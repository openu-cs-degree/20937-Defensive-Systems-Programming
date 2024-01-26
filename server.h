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

  // classes to be used by both Request and Response

  class Payload
  {
    uint32_t size;
    std::unique_ptr<uint8_t[]> content;

  private:
    Payload() = default;

  public:
    Payload(uint32_t size, std::unique_ptr<uint8_t[]> content)
        : size(size), content(std::move(content)){};

    bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      boost::asio::write(socket, boost::asio::buffer(&size, sizeof(size)), error);
      if (error)
      {
        std::cerr << "Failed to write payload size: " << error.message() << '\n';
        return false;
      }

      boost::asio::write(socket, boost::asio::buffer(content.get(), size), error);
      if (error)
      {
        std::cerr << "Failed to write payload: " << error.message() << '\n';
        return false;
      }

      return true;
    };

    bool write_to_file(const std::filesystem::path &file_path) const
    {
      std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        return false;
      }

      file.write(reinterpret_cast<const char *>(content.get()), size);
      if (!file)
      {
        std::cerr << "Failed to write to file: " << file_path << '\n';
        return false;
      }

      return true;
    }

    static std::optional<Payload> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
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

    static std::optional<Payload> read_from_file(const std::filesystem::path &file_path)
    {
      std::ifstream file(file_path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        std::cerr << "Failed to open file: " << file_path << '\n';
        return {};
      }

      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      std::unique_ptr<uint8_t[]> content(new uint8_t[static_cast<uint32_t>(size)]);
      file.read(reinterpret_cast<char *>(content.get()), size);
      if (!file)
      {
        std::cerr << "Failed to read file: " << file_path << '\n';
        return {};
      }

      return Payload{static_cast<uint32_t>(size), std::move(content)};
    }

    friend std::ostream &operator<<(std::ostream &os, const Payload &payload)
    {
      static constexpr uint32_t MAX_PAYLOAD_PRINT_SIZE = 420;
      os << "payload size: " << payload.size << '\n';
      os << (payload.size > MAX_PAYLOAD_PRINT_SIZE ? "payload (printing limited to 420 bytes):\n" : "payload:\n")
         << std::string_view(reinterpret_cast<const char *>(payload.content.get()), std::min(payload.size, MAX_PAYLOAD_PRINT_SIZE)) << '\n';
      return os;
    }
  };

  class Filename
  {
    uint16_t name_len;
    std::unique_ptr<char[]> filename;

  public:
    Filename(uint16_t name_len, std::unique_ptr<char[]> filename)
        : name_len(name_len), filename(std::move(filename)) {}

    const std::string_view get_name() const
    {
      return std::string_view(filename.get(), name_len);
    }

    bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
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

    static std::optional<Filename> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
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

      return Filename{name_len, std::move(filename)};
    }

    friend std::ostream &operator<<(std::ostream &os, const Filename &filename)
    {
      os << "name_len: " << filename.name_len << '\n';
      os << "filename: " << filename.get_name() << '\n';
      return os;
    }
  };

  // forward declare Response so that it can be used in Request::process()

  class Response;

  // Requests base classes

  class Request
  {
  protected:
    uint32_t user_id;
    uint8_t version;
    Op op;

    Request(uint32_t user_id, uint8_t version, Op op)
        : user_id(user_id), version(version), op(op){};

  public:
    virtual ~Request() = default;

    static std::optional<std::tuple<uint32_t, uint8_t, Op>> read_user_id_and_version_and_op(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      struct RequestData
      {
        uint32_t user_id;
        uint8_t version;
        Op op;
      };
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

    std::filesystem::path create_and_get_user_dir_path() const
    {
      std::filesystem::path dir_path = std::filesystem::path("C:\\") / maman14::SERVER_DIR_NAME / std::to_string(user_id);
      std::filesystem::create_directories(dir_path); // TODO: check return value (and return bool?)
      return dir_path;
    }

    virtual std::unique_ptr<Response> process() = 0;

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

  class RequestWithFileName : public Request
  {
  protected:
    Filename filename;

    RequestWithFileName(uint32_t user_id, uint8_t version, Op op, Filename filename)
        : Request(user_id, version, op), filename(std::move(filename)){};

  public:
    virtual ~RequestWithFileName() = default;

    std::filesystem::path create_and_get_user_file_path() const
    {
      std::filesystem::path dir_path = create_and_get_user_dir_path();
      return dir_path / filename.get_name();
    }

    virtual void print(std::ostream &os) const
    {
      Request::print(os);
      os << filename << '\n';
    }
  };

  class RequestWithPayload : public RequestWithFileName
  {
  protected:
    Payload payload;

    RequestWithPayload(uint32_t user_id, uint8_t version, Op op, Filename filename, Payload payload)
        : RequestWithFileName(user_id, version, op, std::move(filename)), payload(std::move(payload)){};

  public:
    void print(std::ostream &os) const
    {
      RequestWithFileName::print(os);
      os << payload << '\n';
    }
  };

  // Response base classes

  class Response
  {
  protected:
    uint8_t version;
    Status status;

    Response(uint8_t version, Status status)
        : version(version), status(status){};

  public:
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

  class ResponseWithFileName : public Response
  {
  protected:
    Filename filename;

    ResponseWithFileName(uint8_t version, Status status, Filename filename)
        : Response(version, status), filename(std::move(filename)){};

  public:
    virtual bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      if (!Response::write_to_socket(socket, error))
      {
        return false;
      }

      if (!filename.write_to_socket(socket, error))
      {
        return false;
      }

      return true;
    }

    virtual void print(std::ostream &os) const
    {
      Response::print(os);
      os << filename << '\n';
    }
  };

  class ResponseWithPayload : public ResponseWithFileName
  {
  protected:
    Payload payload;

    ResponseWithPayload(uint8_t version, Status status, Filename filename, Payload payload)
        : ResponseWithFileName(version, status, std::move(filename)), payload(std::move(payload)){};

  public:
    bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      if (!ResponseWithFileName::write_to_socket(socket, error))
      {
        return false;
      }

      if (!payload.write_to_socket(socket, error))
      {
        return false;
      }

      return true;
    };

    void print(std::ostream &os) const
    {
      ResponseWithFileName::print(os);
      os << payload << '\n';
    }
  };

  // Response concrete classes (final, non-abstract)

  class ResponseSuccessRestore final : public ResponseWithPayload
  {
  public:
    ResponseSuccessRestore(Filename filename, Payload payload)
        : ResponseWithPayload(maman14::SERVER_VERSION, Status::SUCCESS_RESTORE, std::move(filename), std::move(payload)){};
  };

  class ResponseSuccessList final : public ResponseWithPayload
  {
  public:
    ResponseSuccessList(Filename filename, Payload payload)
        : ResponseWithPayload(maman14::SERVER_VERSION, Status::SUCCESS_LIST, std::move(filename), std::move(payload)){};
  };

  class ResponseSuccessSave final : public ResponseWithFileName
  {
  public:
    ResponseSuccessSave(Filename filename)
        : ResponseWithFileName(maman14::SERVER_VERSION, Status::SUCCESS_SAVE, std::move(filename)){};
  };

  class ResponseErrorNoFile final : public ResponseWithFileName
  {
  public:
    ResponseErrorNoFile(Filename filename)
        : ResponseWithFileName(maman14::SERVER_VERSION, Status::ERROR_NO_FILE, std::move(filename)){};
  };

  class ResponseErrorNoClient final : public Response
  {
  public:
    ResponseErrorNoClient()
        : Response(maman14::SERVER_VERSION, Status::ERROR_NO_CLIENT){};
  };

  class ResponseErrorGeneral final : public Response
  {
  public:
    ResponseErrorGeneral()
        : Response(maman14::SERVER_VERSION, Status::ERROR_GENERAL){};
  };

  // Request concrete classs (final, non-abstract)

  class RequestSave final : public RequestWithPayload
  {
  public:
    RequestSave(uint32_t user_id, uint8_t version, Filename filename, Payload payload)
        : RequestWithPayload(user_id, version, Op::SAVE, std::move(filename), std::move(payload)){};

    std::unique_ptr<Response> process() override
    {
      auto file_path = create_and_get_user_file_path();

      if (!payload.write_to_file(file_path))
      {
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessSave>(std::move(filename));
    }
  };

  class RequestRestore final : public RequestWithFileName
  {
  public:
    RequestRestore(uint32_t user_id, uint8_t version, Filename filename)
        : RequestWithFileName(user_id, version, Op::RESTORE, std::move(filename)){};

    std::unique_ptr<Response> process() override
    {
      auto file_path = create_and_get_user_file_path();

      auto payload = Payload::read_from_file(file_path);
      if (!payload)
      {
        return std::make_unique<ResponseErrorNoFile>(std::move(filename));
      }

      return std::make_unique<ResponseSuccessRestore>(std::move(filename), std::move(payload.value()));
    }
  };

  class RequestDelete final : public RequestWithFileName
  {
  public:
    RequestDelete(uint32_t user_id, uint8_t version, Filename filename)
        : RequestWithFileName(user_id, version, Op::DELETE, std::move(filename)){};

    std::unique_ptr<Response> process() override
    {
      auto file_path = create_and_get_user_file_path();

      if (std::error_code ec; !std::filesystem::remove(file_path, ec))
      {
        std::cerr << "Failed to delete file: " << file_path << '\n';
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessSave>(std::move(filename));
    }
  };

  class RequestList final : public Request
  {
  public:
    RequestList(uint32_t user_id, uint8_t version)
        : Request(user_id, version, Op::LIST){};

    std::unique_ptr<Response> process() override
    {
      std::filesystem::path dir_path = create_and_get_user_dir_path();

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
      return std::make_unique<ResponseSuccessList>(Filename{file_name_length, std::move(filename)}, Payload{static_cast<uint32_t>(file_size), std::move(content)});
    }
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
      auto filename = Filename::read_from_socket(socket, error);
      if (!filename)
      {
        return {};
      }

      if (op == Op::RESTORE)
      {
        return std::make_unique<RequestRestore>(user_id, version, std::move(filename.value()));
      }
      else if (op == Op::DELETE)
      {
        return std::make_unique<RequestDelete>(user_id, version, std::move(filename.value()));
      }
      else
      {
        auto payload = Payload::read_from_socket(socket, error);
        if (!payload)
        {
          return {};
        }

        return std::make_unique<RequestSave>(user_id, version, std::move(filename.value()), std::move(payload.value()));
      }
    }

    return {};
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
    auto response = request->process();
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