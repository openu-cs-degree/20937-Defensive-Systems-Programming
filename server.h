#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <optional>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <cstdint>
#include <memory>

#undef DELETE // the DELETE macro collides with Op::DELETE definition

using boost::asio::ip::tcp;

#ifdef __GNUC__
#define PACK(__Declaration__) __Declaration__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define PACK(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
#endif

namespace
{
  enum class Op : uint8_t
  {
    SAVE = 100,
    RESTORE = 200, // no size or payload
    DELETE = 201,  // no size or payload
    LIST = 202,    // no size, payload, name_len or filename
  };

  enum class Status : uint16_t
  {
    SUCCESS_RESTORE = 210,
    SUCCESS_LIST = 211,
    SUCCESS_SAVE = 212,     // no size or payload
    ERROR_NO_FILE = 1001,   // no size or payload
    ERROR_NO_CLIENT = 1002, // only version and status
    ERROR_GENERAL = 1003,   // only version and status
  };

  PACK(
      struct Payload {
        uint32_t size;
        std::unique_ptr<uint8_t[]> content;
      };

      struct Request {
        uint32_t user_id;
        uint8_t version;
        Op op;
        uint16_t name_len;
        std::unique_ptr<char[]> filename;
        Payload payload;
      };

      struct Response {
        uint8_t version;
        Status status;
        uint16_t name_len;
        std::unique_ptr<char[]> filename;
        Payload payload;
      };)
} // anonymous namespace

namespace maman14
{
  static constexpr inline uint8_t SERVER_VERSION = 2;
  static constexpr inline std::string_view SERVER_DIR_NAME = "my_server";
} // namespace maman14

namespace
{
  std::optional<Request> read_request(tcp::socket &socket)
  {
    std::cout << "read_request\n"
              << "sizeof(Request): " << sizeof(Request) << '\n'
              << "offsetof(Request, filename): " << offsetof(Request, filename) << '\n';

    boost::system::error_code error;

    // Read the fixed-size part of the request
    Request request;
    boost::asio::read(socket, boost::asio::buffer(&request, offsetof(Request, filename)), error);

    if (error)
    {
      std::cout << "Error reading name_len: " << error.message() << '\n';
      return std::nullopt;
    }
    std::cout << "user_id: " << request.user_id << '\n';
    std::cout << "version: " << static_cast<uint16_t>(request.version) << '\n';
    std::cout << "op: " << static_cast<uint16_t>(request.op) << '\n';
    std::cout << "name_len: " << request.name_len << '\n';

    // Read the filename
    request.filename = std::make_unique<char[]>(request.name_len);
    boost::asio::read(socket, boost::asio::buffer(request.filename.get(), request.name_len), error);
    // request.filename[request.name_len] = '\0';

    if (error)
    {
      std::cout << "Error reading filename: " << error.message() << '\n';
      return std::nullopt;
    }
    // std::cout << "filename: " << request.filename.get() << '\n';

    // Read the size of the payload
    boost::asio::read(socket, boost::asio::buffer(&request.payload.size, sizeof(request.payload.size)), error);

    if (error)
    {
      std::cout << "Error: " << error.message() << '\n';
      return std::nullopt;
    }

    // Read the payload
    request.payload.content = std::make_unique<uint8_t[]>(request.payload.size);
    boost::asio::read(socket, boost::asio::buffer(request.payload.content.get(), request.payload.size), error);

    if (error)
    {
      std::cout << "Error: " << error.message() << '\n';
      return std::nullopt;
    }

    return request;
  }

  std::optional<Response> process_request(Request &request)
  {
    std::cout << "process_request\n";
    Response response{maman14::SERVER_VERSION, Status::ERROR_GENERAL, request.name_len, std::move(request.filename), std::move(request.payload)};
    // std::cout << "moved response filename: " << response.filename.get() << '\n';
    // no borrow-checking, beware of using request.filename and request.payload after this point!

    // Construct the directory path
    std::filesystem::path dir_path = std::filesystem::path("C:\\") / maman14::SERVER_DIR_NAME / std::to_string(request.user_id);

    // Create the directory if it doesn't exist
    std::filesystem::create_directories(dir_path);

    // Construct the file path
    std::string null_terminated_filename(response.filename.get(), request.name_len);
    null_terminated_filename += '\0';
    std::cout << "null_terminated_filename: " << null_terminated_filename << '\n';
    std::filesystem::path file_path = dir_path / null_terminated_filename;

    switch (request.op)
    {
    case Op::SAVE:
    {
      // Open the file and write the payload to it
      std::ofstream file(file_path, std::ios::binary);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      file.write(reinterpret_cast<const char *>(response.payload.content.get()), response.payload.size);
      if (!file)
      {
        std::cerr << "Failed to write to file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      response.status = Status::SUCCESS_SAVE;
      break;
    }
    case Op::RESTORE:
    {
      // Open the file and read its contents
      std::ifstream file(file_path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      // Allocate memory for the payload and read the file into it
      response.payload.content = std::make_unique<uint8_t[]>(static_cast<size_t>(size));
      if (!file.read(reinterpret_cast<char *>(response.payload.content.get()), size))
      {
        std::cerr << "Failed to read file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      response.payload.size = static_cast<size_t>(size);

      // std::cout << "Read " << size << " bytes from file: " << file_path << '\n';
      // std::cout << "Payload size: " << std::hex << response.payload.size << '\n';
      // std::cout << "Payload: " << response.payload.content.get() << std::dec << '\n';

      response.status = Status::SUCCESS_RESTORE;
      break;
    }
    case Op::DELETE:
    {
      if (std::error_code ec; !std::filesystem::remove(file_path, ec))
      {
        std::cerr << "Failed to delete file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      response.status = Status::SUCCESS_SAVE;
      break;
    }
    case Op::LIST:
    {
      // Generate a random string of 32 characters
      static constexpr std::string_view characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      static constexpr size_t file_name_length = 32;
      std::string random_string;
      for (size_t i = 0; i < file_name_length; ++i)
      {
        random_string += characters[rand() % characters.size()];
      }
      file_path = dir_path / random_string;

      std::ofstream file(file_path);
      if (!file)
      {
        std::cerr << "Failed to create file: " << file_path << '\n';
        response.status = Status::ERROR_GENERAL;
        break;
      }

      // Iterate over the files in the directory and write their names to the new file
      for (const auto &entry : std::filesystem::directory_iterator(dir_path))
      {
        if (auto filename = entry.path().filename(); filename != random_string)
        {
          file << filename << '\n';
        }
      }

      response.status = Status::SUCCESS_LIST;
      break;
    }
    default:
      response.status = Status::ERROR_GENERAL;
      break;
    }

    return response;
  }

  void write_response(tcp::socket &socket, Response &response)
  {
    std::cout << "write_response\n";
    boost::system::error_code error;

    // Write the fixed-size part of the response
    boost::asio::write(socket, boost::asio::buffer(&response, offsetof(Response, filename)), error);

    if (error)
    {
      std::cout << "Error writing name_len: " << error.message() << '\n';
      return;
    }

    // Write the filename
    // std::cout << "about to write filename: " << response.filename.get() << '\n';
    boost::asio::write(socket, boost::asio::buffer(response.filename.get(), response.name_len), error);

    if (error)
    {
      std::cout << "Error writing filename: " << error.message() << '\n';
      return;
    }

    // Write the size of the payload
    boost::asio::write(socket, boost::asio::buffer(&response.payload.size, sizeof(response.payload.size)), error);

    if (error)
    {
      std::cout << "Error: " << error.message() << '\n';
      return;
    }

    // Write the payload
    boost::asio::write(socket, boost::asio::buffer(response.payload.content.get(), response.payload.size), error);

    if (error)
    {
      std::cout << "Error: " << error.message() << '\n';
      return;
    }

    std::cout << "Response sent\n";
  }

  void handle_client(tcp::socket socket)
  {
    auto request = read_request(socket);
    if (!request)
    {
      std::cout << "Request reading failed!" << '\n';
      return;
    }

    std::cout << "Request received\n";
    // std::cout << "user_id: " << request->user_id << '\n';
    // std::cout << "version: " << request->version << '\n';
    // std::cout << "op: " << static_cast<uint16_t>(request->op) << '\n';
    // std::cout << "name_len: " << request->name_len << '\n';
    // std::cout << "filename: " << request->filename.get() << '\n';
    // std::cout << "payload size: " << request->payload.size << '\n';
    // std::cout << "payload: " << request->payload.content.get() << '\n';

    auto response = process_request(request.value());
    if (!response)
    {
      std::cout << "Request processing failed!" << '\n';
      return;
    }

    std::cout << "Response ready\n";
    std::cout << "version: " << static_cast<uint16_t>(response->version) << '\n';
    std::cout << "status: " << static_cast<uint16_t>(response->status) << '\n';
    std::cout << "name_len: " << response->name_len << '\n';
    std::string null_terminated_filename(response->filename.get(), response->name_len);
    null_terminated_filename += '\0';
    std::cout << "filename: " << null_terminated_filename << '\n';
    std::cout << "payload size: " << response->payload.size << '\n';
    std::cout << "payload: " << response->payload.content.get() << '\n';

    write_response(socket, response.value());
  }
} // anonymous namespace

namespace maman14
{
  static void start_server_on_port(uint16_t port)
  {
    boost::asio::io_context io_context;
    tcp::socket socket(io_context);
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

    try
    {
      while (true)
      {
        acceptor.accept(socket);

        std::thread(handle_client, std::move(socket)).detach();
      }
    }
    catch (std::exception &e)
    {
      std::cerr << e.what() << '\n';
    }
  }

} // namespace maman14