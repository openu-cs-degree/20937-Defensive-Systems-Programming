#include <iostream>
#include <thread>
#include <optional>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <cstdint>
#include <memory>
#include <algorithm>

#pragma warning(push)
#pragma warning(disable : 6001 6031 6101 6255 6258 6313 6387)
#include <boost/asio.hpp>
#pragma warning(pop)

#undef DELETE // the DELETE macro collides with Op::DELETE definition

namespace maman14
{
  static constexpr inline uint8_t SERVER_VERSION = 3;
  static constexpr inline std::string_view SERVER_DIR_NAME = "my_server";
} // namespace maman14

namespace
{
  enum class Op : uint8_t
  {
    SAVE = 100,
    RESTORE = 200, // no size or payload
    DELETE = 201,  // no size or payload
    LIST = 202,    // no size, payload, name_len or filename
  };

  bool is_valid_op(uint8_t value)
  {
    return value == static_cast<uint8_t>(Op::SAVE) ||
           value == static_cast<uint8_t>(Op::RESTORE) ||
           value == static_cast<uint8_t>(Op::DELETE) ||
           value == static_cast<uint8_t>(Op::LIST);
  }

  enum class Status : uint16_t
  {
    SUCCESS_RESTORE = 210,
    SUCCESS_LIST = 211,
    SUCCESS_SAVE = 212,     // no size or payload
    ERROR_NO_FILE = 1001,   // no size or payload
    ERROR_NO_CLIENT = 1002, // only version and status
    ERROR_GENERAL = 1003,   // only version and status
  };
} // anonymous namespace

namespace
{
#pragma pack(push, 1)
  struct Payload
  {
    uint32_t size{};
    std::unique_ptr<uint8_t[]> content{};
  };

  // Requests

  struct Request
  {
  protected:
    Request(uint32_t user_id, uint8_t version, Op op)
        : user_id(user_id), version(version), op(op){};

  public:
    uint32_t user_id;
    uint8_t version;
    Op op;

    static std::optional<std::tuple<uint32_t, uint8_t, Op>> read_user_id_and_version_and_op(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
#pragma pack(push, 1)
      struct RequestData
      {
        uint32_t user_id;
        uint8_t version;
        Op op;
      };
#pragma pack(pop)
      RequestData data;

      boost::asio::read(socket, boost::asio::buffer(&data, sizeof(data)), error);
      if (error)
      {
        std::cerr << "Failed to read request: " << error.message() << '\n';
        return std::nullopt;
      }

      if (!is_valid_op(static_cast<uint8_t>(data.op)))
      {
        std::cerr << "Invalid op: " << static_cast<uint16_t>(data.op) << '\n';
        return std::nullopt;
      }

      return std::make_tuple(data.user_id, data.version, data.op);
    }

    virtual void print(std::ostream &os) const
    {
      os << "user_id: " << user_id << '\n';
      os << "version: " << static_cast<uint16_t>(version) << '\n';
      os << "op: " << static_cast<uint16_t>(op) << '\n';
    }

    friend std::ostream &operator<<(std::ostream &os, const Request &request)
    {
      request.print(os);
      return os;
    }
  };

  struct RequestWithFileName : public Request
  {
  protected:
    RequestWithFileName(uint32_t user_id, uint8_t version, Op op, uint16_t name_len, std::unique_ptr<char[]> filename)
        : Request(user_id, version, op), name_len(name_len), filename(std::move(filename)){};

  public:
    uint16_t name_len;
    std::unique_ptr<char[]> filename;

    virtual void print(std::ostream &os) const
    {
      Request::print(os);
      os << "name_len: " << name_len << '\n';
      os << "filename: " << std::string_view(filename.get(), name_len) << '\n';
    }

    static std::optional<std::pair<uint16_t, std::unique_ptr<char[]>>> read_name_len_and_filename(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      uint16_t name_len;
      boost::asio::read(socket, boost::asio::buffer(&name_len, sizeof(name_len)), error);
      if (error)
      {
        std::cerr << "Failed to read name_len: " << error.message() << '\n';
        return {};
      }

      std::unique_ptr<char[]> filename(new char[name_len]);
      boost::asio::read(socket, boost::asio::buffer(filename.get(), name_len), error);
      if (error)
      {
        std::cerr << "Failed to read filename: " << error.message() << '\n';
        return {};
      }

      return std::make_pair(name_len, std::move(filename));
    };
  };

  struct RequestWithPayload : public RequestWithFileName
  {
  protected:
    RequestWithPayload(uint32_t user_id, uint8_t version, Op op, uint16_t name_len, std::unique_ptr<char[]> filename, Payload payload)
        : RequestWithFileName(user_id, version, op, name_len, std::move(filename)), payload(std::move(payload)){};

  public:
    Payload payload;

    virtual void print(std::ostream &os) const
    {
      RequestWithFileName::print(os);
      os << "payload size: " << payload.size << '\n';
      os << "payload: " << payload.content.get() << '\n';
    }

    static std::optional<Payload> read_payload(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      Payload payload;
      boost::asio::read(socket, boost::asio::buffer(&payload.size, sizeof(payload.size)), error);
      if (error)
      {
        std::cerr << "Failed to read payload size: " << error.message() << '\n';
        return {};
      }
      payload.content = std::make_unique<uint8_t[]>(payload.size);
      boost::asio::read(socket, boost::asio::buffer(payload.content.get(), payload.size), error);
      if (error)
      {
        std::cerr << "Failed to read payload content: " << error.message() << '\n';
        return {};
      }

      return payload;
    };
  };

  struct RequestSave : public RequestWithPayload
  {
    RequestSave(uint32_t user_id, uint8_t version, uint16_t name_len, std::unique_ptr<char[]> filename, Payload payload)
        : RequestWithPayload(user_id, version, Op::SAVE, name_len, std::move(filename), std::move(payload)){};
  };

  struct RequestRestore : public RequestWithFileName
  {
    RequestRestore(uint32_t user_id, uint8_t version, uint16_t name_len, std::unique_ptr<char[]> filename)
        : RequestWithFileName(user_id, version, Op::RESTORE, name_len, std::move(filename)){};
  };

  struct RequestDelete : public RequestWithFileName
  {
    RequestDelete(uint32_t user_id, uint8_t version, uint16_t name_len, std::unique_ptr<char[]> filename)
        : RequestWithFileName(user_id, version, Op::DELETE, name_len, std::move(filename)){};
  };

  struct RequestList : public Request
  {
    RequestList(uint32_t user_id, uint8_t version)
        : Request(user_id, version, Op::LIST){};
  };

  // Responses

  struct Response
  {
  protected:
    Response(uint8_t version, Status status)
        : version(version), status(status){};

  public:
    uint8_t version;
    Status status;

    virtual bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      boost::asio::write(socket, boost::asio::buffer(&this->version, sizeof(version) + sizeof(status)), error);
      if (error)
      {
        std::cerr << "Failed to write response: " << error.message() << '\n';
        return false;
      }

      return true;
    }

    virtual void print(std::ostream &os) const
    {
      os << "version: " << static_cast<uint16_t>(version) << '\n';
      os << "status: " << static_cast<uint16_t>(status) << '\n';
    }

    friend std::ostream &operator<<(std::ostream &os, const Response &response)
    {
      response.print(os);
      return os;
    }
  };

  struct ResponseWithFileName : public Response
  {
  protected:
    ResponseWithFileName(uint8_t version, Status status, uint16_t name_len, std::unique_ptr<char[]> filename)
        : Response(version, status), name_len(name_len), filename(std::move(filename)){};

  public:
    uint16_t name_len;
    std::unique_ptr<char[]> filename;

    virtual bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      if (!Response::write_to_socket(socket, error))
      {
        return false;
      }

      boost::asio::write(socket, boost::asio::buffer(&name_len, sizeof(name_len)), error);
      if (error)
      {
        std::cerr << "Failed to write name_len: " << error.message() << '\n';
        return false;
      }

      boost::asio::write(socket, boost::asio::buffer(filename.get(), name_len), error);
      if (error)
      {
        std::cerr << "Failed to write filename: " << error.message() << '\n';
        return false;
      }

      return true;
    }

    virtual void print(std::ostream &os) const
    {
      Response::print(os);
      os << "name_len: " << name_len << '\n';
      os << "filename: " << std::string_view(filename.get(), name_len) << '\n';
    }
  };

  struct ResponseWithPayload : public ResponseWithFileName
  {
  protected:
    ResponseWithPayload(uint8_t version, Status status, uint16_t name_len, std::unique_ptr<char[]> filename, Payload payload)
        : ResponseWithFileName(version, status, name_len, std::move(filename)), payload(std::move(payload)){};

  public:
    Payload payload;

    virtual bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      if (!ResponseWithFileName::write_to_socket(socket, error))
      {
        return false;
      }

      boost::asio::write(socket, boost::asio::buffer(&payload.size, sizeof(payload.size)), error);
      if (error)
      {
        std::cerr << "Failed to write payload size: " << error.message() << '\n';
        return false;
      }

      boost::asio::write(socket, boost::asio::buffer(payload.content.get(), payload.size), error);
      if (error)
      {
        std::cerr << "Failed to write payload: " << error.message() << '\n';
        return false;
      }

      return true;
    };

    virtual void print(std::ostream &os) const
    {
      ResponseWithFileName::print(os);
      os << "payload size: " << payload.size << '\n';
      os << "payload: " << payload.content.get() << '\n';
    }
  };

  struct ResponseSuccessRestore : public ResponseWithPayload
  {
    ResponseSuccessRestore(uint16_t name_len, std::unique_ptr<char[]> filename, Payload payload)
        : ResponseWithPayload(maman14::SERVER_VERSION, Status::SUCCESS_RESTORE, name_len, std::move(filename), std::move(payload)){};
  };

  struct ResponseSuccessList : public ResponseWithPayload
  {
    ResponseSuccessList(uint16_t name_len, std::unique_ptr<char[]> filename, Payload payload)
        : ResponseWithPayload(maman14::SERVER_VERSION, Status::SUCCESS_LIST, name_len, std::move(filename), std::move(payload)){};
  };

  struct ResponseSuccessSave : public ResponseWithFileName
  {
    ResponseSuccessSave(uint16_t name_len, std::unique_ptr<char[]> filename)
        : ResponseWithFileName(maman14::SERVER_VERSION, Status::SUCCESS_SAVE, name_len, std::move(filename)){};
  };

  struct ResponseErrorNoFile : public ResponseWithFileName
  {
    ResponseErrorNoFile(uint16_t name_len, std::unique_ptr<char[]> filename)
        : ResponseWithFileName(maman14::SERVER_VERSION, Status::ERROR_NO_FILE, name_len, std::move(filename)){};
  };

  struct ResponseErrorNoClient : public Response
  {
    ResponseErrorNoClient()
        : Response(maman14::SERVER_VERSION, Status::ERROR_NO_CLIENT){};
  };

  struct ResponseErrorGeneral : public Response
  {
    ResponseErrorGeneral()
        : Response(maman14::SERVER_VERSION, Status::ERROR_GENERAL){};
  };
#pragma pack(pop)
} // anonymous namespace

namespace
{
  std::unique_ptr<Request> read_request(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
  {
    // Read the common part of the request
    auto user_id_and_version_and_op = Request::read_user_id_and_version_and_op(socket, error);
    if (!user_id_and_version_and_op)
    {
      return {};
    }

    auto &[user_id, version, op] = *user_id_and_version_and_op;

    if (op == Op::LIST)
    {
      return std::make_unique<RequestList>(user_id, version);
    }
    if (op == Op::RESTORE || op == Op::DELETE || op == Op::SAVE)
    {
      auto name_len_and_filename = RequestWithFileName::read_name_len_and_filename(socket, error);
      if (!name_len_and_filename)
      {
        return {};
      }

      auto &[name_len, filename] = *name_len_and_filename;

      if (op == Op::RESTORE)
      {
        return std::make_unique<RequestRestore>(user_id, version, name_len, std::move(filename));
      }
      else if (op == Op::DELETE)
      {
        return std::make_unique<RequestDelete>(user_id, version, name_len, std::move(filename));
      }
      else
      {
        auto payload = RequestWithPayload::read_payload(socket, error);
        if (!payload)
        {
          return {};
        }

        return std::make_unique<RequestSave>(user_id, version, name_len, std::move(filename), std::move(payload.value()));
      }
    }

    return {};
  }

  std::unique_ptr<Response> process_request(Request &request)
  {
    // Construct and create user's directory if it doesn't exist yet
    std::filesystem::path dir_path = std::filesystem::path("C:\\") / maman14::SERVER_DIR_NAME / std::to_string(request.user_id);
    std::filesystem::create_directories(dir_path);

    switch (request.op)
    {
    case Op::SAVE:
    {
      RequestSave &request_as_save = reinterpret_cast<RequestSave &>(request);

      // Construct the file path
      std::string null_terminated_filename(request_as_save.filename.get(), request_as_save.name_len);
      null_terminated_filename += '\0';
      std::cout << "null_terminated_filename: " << null_terminated_filename << '\n';
      std::filesystem::path file_path = dir_path / null_terminated_filename;

      // Open the file and write the payload to it
      std::ofstream file(file_path, std::ios::binary);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      file.write(reinterpret_cast<const char *>(request_as_save.payload.content.get()), request_as_save.payload.size);
      if (!file)
      {
        std::cerr << "Failed to write to file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessSave>(request_as_save.name_len, std::move(request_as_save.filename));
    }
    case Op::RESTORE:
    {
      RequestRestore &request_as_restore = reinterpret_cast<RequestRestore &>(request);

      // Construct the file path
      std::string null_terminated_filename(request_as_restore.filename.get(), request_as_restore.name_len);
      null_terminated_filename += '\0';
      std::cout << "null_terminated_filename: " << null_terminated_filename << '\n';
      std::filesystem::path file_path = dir_path / null_terminated_filename;

      // Open the file and read its contents
      std::ifstream file(file_path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      // Allocate memory for the payload and read the file into it
      Payload payload{static_cast<size_t>(size), std::make_unique<uint8_t[]>(static_cast<size_t>(size))};
      if (!file.read(reinterpret_cast<char *>(payload.content.get()), size))
      {
        std::cerr << "Failed to read file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessRestore>(request_as_restore.name_len, std::move(request_as_restore.filename), std::move(payload));
    }
    case Op::DELETE:
    {
      RequestDelete &request_as_delete = reinterpret_cast<RequestDelete &>(request);

      // Construct the file path
      std::string null_terminated_filename(request_as_delete.filename.get(), request_as_delete.name_len);
      null_terminated_filename += '\0';
      std::cout << "null_terminated_filename: " << null_terminated_filename << '\n';
      std::filesystem::path file_path = dir_path / null_terminated_filename;

      if (std::error_code ec; !std::filesystem::remove(file_path, ec))
      {
        std::cerr << "Failed to delete file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessSave>(request_as_delete.name_len, std::move(request_as_delete.filename));
    }
    case Op::LIST:
    {
      // Generate a random string of 32 characters
      static constexpr uint16_t file_name_length = 32;
      auto generate_random_string = []() -> std::string
      {
        auto generate_random_character = []() -> char
        {
          static constexpr std::string_view characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
          return characters[rand() % characters.size()];
        };
        std::string random_string(file_name_length, 0);
        std::generate_n(random_string.begin(), file_name_length, generate_random_character);
        return random_string;
      };
      const auto list_file_name = generate_random_string();

      // Create a new file with the random string as its name
      std::filesystem::path file_path = dir_path / list_file_name;
      std::fstream file(file_path, std::ios::in | std::ios::out | std::ios::trunc);
      if (!file)
      {
        std::cerr << "Failed to create file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      // Iterate over the files in the directory and write their names to the new file
      std::for_each(std::filesystem::directory_iterator(dir_path),
                    std::filesystem::directory_iterator(),
                    [&](const auto &entry)
                    {
                      if (auto filename = entry.path().filename(); filename != list_file_name)
                      {
                        file << filename << '\n';
                      }
                    });

      // Get the size of the file
      auto file_size = file.tellp();
      if (file_size > std::numeric_limits<uint32_t>::max())
      {
        std::cerr << "File size is too big: " << file_size << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      // Reset the file pointer to the beginning of the file in order to read its contents to the payload
      file.clear();
      file.seekg(0, std::ios::beg);
      std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

      // prepare the response
      auto filename = std::make_unique<char[]>(file_name_length);
      std::move(list_file_name.begin(), list_file_name.end(), filename.get()); // TODO: check null termination
      auto content = std::make_unique<uint8_t[]>(static_cast<uint32_t>(file_size));
      std::move(file_content.begin(), file_content.end(), content.get());
      return std::make_unique<ResponseSuccessList>(file_name_length, std::move(filename), Payload{static_cast<uint32_t>(file_size), std::move(content)});
    }
    }

    // TODO: log something to the user?
    return std::make_unique<ResponseErrorGeneral>();
  }

  void handle_client(boost::asio::ip::tcp::socket socket)
  {
    boost::system::error_code error;

    std::cout << "Receiving request:\n";
    auto request = read_request(socket, error);
    if (!request)
    {
      std::cout << "Request reading failed!" << '\n';
      return;
    }
    std::cout << *request << '\n';

    std::cout << "Generating response:\n";
    auto response = process_request(*request);
    if (!response)
    {
      std::cout << "Request processing failed!" << '\n';
      return;
    }
    std::cout << *response << '\n';

    std::cout << "Sending response:\n";
    response->write_to_socket(socket, error);
    std::cout << "Response sent\n\n";
  }
} // anonymous namespace

namespace maman14
{
  static void start_server_on_port(uint16_t port)
  {
    using boost::asio::ip::tcp;

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