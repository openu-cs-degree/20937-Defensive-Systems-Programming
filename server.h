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

#define DEBUG

namespace
{
  template <typename T>
  void print_args(std::ostream &os, const T &t)
  {
    os << t;
  }

  template <typename T, typename... Args>
  void print_args(std::ostream &os, const T &t, Args... args)
  {
    os << t;
    print_args(os, args...);
  }
} // anonymous namespace

#ifdef DEBUG
#define LOG(...)                              \
  do                                          \
  {                                           \
    print_args(std::cerr, __VA_ARGS__, '\n'); \
  } while (0)
#else
#define LOG(...) (void)0
#endif

#define SOCKET_IO(operation, pointer, size, error_value, ...)                                  \
  do                                                                                           \
  {                                                                                            \
    if (auto bytes_transferred = operation(socket, boost::asio::buffer(pointer, size), error); \
        error || bytes_transferred != size)                                                    \
    {                                                                                          \
      LOG(__VA_ARGS__);                                                                        \
      return error_value;                                                                      \
    }                                                                                          \
  } while (0)

#define SOCKET_WRITE(pointer, size, error_value, ...) \
  SOCKET_IO(boost::asio::write, pointer, size, error_value, __VA_ARGS__)

#define SOCKET_READ(pointer, size, error_value, ...) \
  SOCKET_IO(boost::asio::read, pointer, size, error_value, __VA_ARGS__)

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

  const inline bool is_valid_op(uint8_t value)
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
    Payload(const Payload &) = delete;
    Payload &operator=(const Payload &) = delete;
    Payload(Payload &&) = default;
    Payload &operator=(Payload &&) = default;

    Payload(uint32_t size, std::unique_ptr<uint8_t[]> content)
        : size(size), content(std::move(content)){};

    Payload(const std::string &content)
        : size(static_cast<uint32_t>(content.size())), content(std::make_unique<uint8_t[]>(size))
    {
      std::copy(content.begin(), content.end(), this->content.get());
    }

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE(&size, sizeof(size), false, "Failed to write payload size: ", error.message());

      SOCKET_WRITE(content.get(), size, false, "Failed to write payload content: ", error.message());

      return true;
    };

    const bool write_to_file(const std::filesystem::path &file_path) const
    {
      std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
      if (!file)
      {
        LOG("Failed to open file: ", file_path);
        return false;
      }

      file.write(reinterpret_cast<const char *>(content.get()), size);
      if (!file)
      {
        LOG("Failed to write to file: ", file_path);
        return false;
      }

      return true;
    }

    static const std::optional<Payload> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      Payload payload;

      SOCKET_READ(&payload.size, sizeof(payload.size), {}, "Failed to read payload size: ", error.message());

      payload.content = std::make_unique<uint8_t[]>(payload.size);

      SOCKET_READ(payload.content.get(), payload.size, {}, "Failed to read payload content: ", error.message());

      return payload;
    };

    static const std::optional<Payload> read_from_file(const std::filesystem::path &file_path)
    {
      std::ifstream file(file_path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        LOG("Failed to open file: ", file_path);
        return {};
      }

      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      if (size > std::numeric_limits<uint32_t>::max())
      {
        LOG("File size is too big: ", size);
        return {};
      }

      std::unique_ptr<uint8_t[]> content(new uint8_t[static_cast<uint32_t>(size)]);
      file.read(reinterpret_cast<char *>(content.get()), size);
      if (!file)
      {
        LOG("Failed to read file: ", file_path);
        return {};
      }

      return std::make_optional<Payload>(static_cast<uint32_t>(size), std::move(content));
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

  private:
    Filename() = default;

  public:
    Filename(const Filename &) = delete;
    Filename &operator=(const Filename &) = delete;
    Filename(Filename &&) = default;
    Filename &operator=(Filename &&) = default;

    Filename(uint16_t name_len, std::unique_ptr<char[]> filename)
        : name_len(name_len), filename(std::move(filename)) {}

    Filename(const std::string_view &filename)
        : name_len(static_cast<uint16_t>(filename.size())), filename(std::make_unique<char[]>(name_len))
    {
      std::move(filename.begin(), filename.end(), this->filename.get());
    }

    const std::string_view get_name() const
    {
      return std::string_view(filename.get(), name_len);
    }

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE(&name_len, sizeof(name_len), false, "Failed to write name_len: ", error.message());

      SOCKET_WRITE(filename.get(), name_len, false, "Failed to write filename: ", error.message());

      return true;
    }

    static const std::optional<Filename> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      Filename filename;

      SOCKET_READ(&filename.name_len, sizeof(filename.name_len), std::nullopt, "Failed to read name_len: ", error.message());

      filename.filename = std::make_unique<char[]>(filename.name_len);

      SOCKET_READ(filename.filename.get(), filename.name_len, std::nullopt, "Failed to read filename: ", error.message());

      if (!filename.is_filename_valid())
      {
        LOG("Invalid filename: ", filename.get_name());
        return std::nullopt;
      }

      return filename;
    }

    friend std::ostream &operator<<(std::ostream &os, const Filename &filename)
    {
      os << "name_len: " << filename.name_len << '\n';
      os << "filename: " << filename.get_name() << '\n';
      return os;
    }

  private:
    const bool is_filename_valid() const
    {
      return std::all_of(filename.get(), filename.get() + name_len, [](char c) -> bool
                         { return std::isalnum(c) || c == '.' || c == '_' || c == '-'; });
    }
  };

  // forward declare Response so that it can be used in Request::process()

  class Response;

  // Requests base classes

  class Request
  {
  protected:
    const uint32_t user_id;
    const uint8_t version;
    const Op op;

    Request(uint32_t user_id, uint8_t version, Op op)
        : user_id(user_id), version(version), op(op){};

  public:
    Request(const Request &) = delete;
    Request &operator=(const Request &) = delete;
    Request(Request &&) = default;
    Request &operator=(Request &&) = default;

    virtual ~Request() = default;

    static const std::optional<std::tuple<uint32_t, uint8_t, Op>> read_user_id_and_version_and_op(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      struct RequestData
      {
        uint32_t user_id;
        uint8_t version;
        Op op;
      };
      RequestData data;

      SOCKET_READ(&data, sizeof(data), std::nullopt, "Failed to read request: ", error.message());

      if (!is_valid_op(static_cast<uint8_t>(data.op)))
      {
        LOG("Invalid op: ", static_cast<uint16_t>(data.op));
        return std::nullopt;
      }

      return std::make_tuple(data.user_id, data.version, data.op);
    }

    const std::filesystem::path get_user_dir_path() const
    {
      return std::filesystem::path("C:\\") / maman14::SERVER_DIR_NAME / std::to_string(user_id);
    }

    virtual std::unique_ptr<Response> process() = 0; // one day son, I will const process() as well. one day.

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
    Filename filename; // TODO: figure why I can't const it

    RequestWithFileName(uint32_t user_id, uint8_t version, Op op, Filename filename)
        : Request(user_id, version, op), filename(std::move(filename)){};

  public:
    RequestWithFileName(const RequestWithFileName &) = delete;
    RequestWithFileName &operator=(const RequestWithFileName &) = delete;
    RequestWithFileName(RequestWithFileName &&) = default;
    RequestWithFileName &operator=(RequestWithFileName &&) = default;

    virtual ~RequestWithFileName() = default;

    const std::filesystem::path get_user_file_path(const std::filesystem::path &user_dir_path) const
    {
      return user_dir_path / filename.get_name();
    }

    virtual void print(std::ostream &os) const override
    {
      Request::print(os);
      os << filename << '\n';
    }
  };

  class RequestWithPayload : public RequestWithFileName
  {
  protected:
    const Payload payload;

    RequestWithPayload(uint32_t user_id, uint8_t version, Op op, Filename filename, Payload payload)
        : RequestWithFileName(user_id, version, op, std::move(filename)), payload(std::move(payload)){};

  public:
    RequestWithPayload(const RequestWithPayload &) = delete;
    RequestWithPayload &operator=(const RequestWithPayload &) = delete;
    RequestWithPayload(RequestWithPayload &&) = default;
    RequestWithPayload &operator=(RequestWithPayload &&) = default;

    virtual ~RequestWithPayload() = default;

    void print(std::ostream &os) const override
    {
      RequestWithFileName::print(os);
      os << payload << '\n';
    }
  };

  // Response base classes

  class Response
  {
  protected:
    const uint8_t version;
    const Status status;

    Response(uint8_t version, Status status)
        : version(version), status(status){};

  public:
    Response(const Response &) = delete;
    Response &operator=(const Response &) = delete;
    Response(Response &&) = default;
    Response &operator=(Response &&) = default;

    virtual ~Response() = default;

    virtual const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE(&this->version, sizeof(version) + sizeof(status), false, "Failed to write response: ", error.message());

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
    const Filename filename;

    ResponseWithFileName(uint8_t version, Status status, Filename filename)
        : Response(version, status), filename(std::move(filename)){};

  public:
    ResponseWithFileName(const ResponseWithFileName &) = delete;
    ResponseWithFileName &operator=(const ResponseWithFileName &) = delete;
    ResponseWithFileName(ResponseWithFileName &&) = default;
    ResponseWithFileName &operator=(ResponseWithFileName &&) = default;

    virtual ~ResponseWithFileName() = default;

    virtual const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const override
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

    virtual void print(std::ostream &os) const override
    {
      Response::print(os);
      os << filename << '\n';
    }
  };

  class ResponseWithPayload : public ResponseWithFileName
  {
  protected:
    const Payload payload;

    ResponseWithPayload(uint8_t version, Status status, Filename filename, Payload payload)
        : ResponseWithFileName(version, status, std::move(filename)), payload(std::move(payload)){};

  public:
    ResponseWithPayload(const ResponseWithPayload &) = delete;
    ResponseWithPayload &operator=(const ResponseWithPayload &) = delete;
    ResponseWithPayload(ResponseWithPayload &&) = default;
    ResponseWithPayload &operator=(ResponseWithPayload &&) = default;

    virtual ~ResponseWithPayload() = default;

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const override
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

    void print(std::ostream &os) const override
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
      auto dir_path = get_user_dir_path();

      std::filesystem::create_directories(dir_path);

      auto file_path = get_user_file_path(dir_path);
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
      auto dir_path = get_user_dir_path();
      if (!std::filesystem::exists(dir_path) || std::filesystem::is_empty(dir_path))
      {
        return std::make_unique<ResponseErrorNoClient>();
      }

      auto file_path = get_user_file_path(dir_path);
      if (!std::filesystem::exists(file_path))
      {
        return std::make_unique<ResponseErrorNoFile>(std::move(filename));
      }

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
      auto dir_path = get_user_dir_path();
      if (!std::filesystem::exists(dir_path) || std::filesystem::is_empty(dir_path))
      {
        return std::make_unique<ResponseErrorNoClient>();
      }

      auto file_path = get_user_file_path(dir_path);
      if (!std::filesystem::exists(file_path))
      {
        return std::make_unique<ResponseErrorNoFile>(std::move(filename));
      }

      if (std::error_code ec; !std::filesystem::remove(file_path, ec))
      {
        LOG("Failed to delete file: ", file_path);
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
      std::filesystem::path user_dir_path = get_user_dir_path();
      if (!std::filesystem::exists(user_dir_path) || std::filesystem::is_empty(user_dir_path))
      {
        return std::make_unique<ResponseErrorNoClient>();
      }

      const auto user_file_name = generate_random_file_name();
      std::filesystem::path user_file_path = user_dir_path / user_file_name;

      auto file = create_and_get_user_file(user_file_path);
      if (!file)
      {
        return std::make_unique<ResponseErrorGeneral>();
      }

      auto payload = write_directory_to_file(user_dir_path, user_file_name, file.value());
      if (!payload)
      {
        return std::make_unique<ResponseErrorGeneral>();
      }

      return std::make_unique<ResponseSuccessList>(Filename(user_file_name), std::move(payload.value()));
    }

  private:
    const std::string generate_random_file_name() const
    {
      static constexpr uint16_t length = 32;
      auto generate_random_character = []() -> char
      {
        static constexpr std::string_view characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return characters[rand() % characters.size()];
      };
      std::string random_string(length, 0);
      std::generate_n(random_string.begin(), length, generate_random_character);
      return random_string;
    }

    std::optional<std::fstream> create_and_get_user_file(const std::filesystem::path &file_path) const
    {
      std::fstream file(file_path, std::ios::in | std::ios::out | std::ios::trunc);
      if (!file)
      {
        LOG("Failed to create file: ", file_path);
        return std::nullopt;
      }

      return file;
    }

    const std::optional<Payload> write_directory_to_file(const std::filesystem::path &src_path, const std::string_view &ignored_filename, std::fstream &dst_file) const
    {
      std::ostringstream oss;
      std::for_each(std::filesystem::directory_iterator(src_path),
                    std::filesystem::directory_iterator(),
                    [&](const auto &entry)
                    {
                      if (auto filename = entry.path().filename(); filename != ignored_filename)
                      {
                        oss << filename << '\n';
                      }
                    });

      std::string content = oss.str();
      if (auto file_size = content.size(); file_size > std::numeric_limits<uint32_t>::max())
      {
        LOG("File size is too big: ", file_size);
        return std::nullopt;
      }

      dst_file << content;

      return Payload{content};
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

  const bool clear_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
  {
    boost::asio::streambuf discard_buffer;
    while (socket.available())
    {
      socket.read_some(discard_buffer.prepare(socket.available()), error);
      discard_buffer.commit(socket.available());
      if (error)
      {
        return false;
      }
    }
    return true;
  }

  void handle_client(boost::asio::ip::tcp::socket socket)
  {
    boost::system::error_code error;

    LOG("Receiving request :)");
    auto request = read_request(socket, error);
    if (!request)
    {
      LOG("Request reading failed!");
      return;
    }
    LOG(*request);

    if (socket.available())
    {
      LOG("Socket had redundant data. Discarding it.");
      if (!clear_socket(socket, error))
      {
        LOG("Failed to discard extra data: ", error.message());
        return;
      }
    }

    LOG("Request received. Generating response:");
    auto response = request->process();
    if (!response)
    {
      LOG("Request processing failed!");
      return;
    }
    LOG(*response);

    LOG("Sending response:");
    if (!response->write_to_socket(socket, error))
    {
      LOG("Failed to send response: ", error.message());
      return;
    }
    LOG("Response sent successfully :D");
  }
} // anonymous namespace

namespace maman14
{
  static void start_server_on_port(uint16_t port)
  {
    using boost::asio::ip::tcp;

    try
    {
      boost::asio::io_context io_context;
      tcp::socket socket(io_context);
      tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

      while (true)
      {
        acceptor.accept(socket);

        std::thread(handle_client, std::move(socket)).detach();
      }
    }
    catch (std::exception &e)
    {
      LOG("Terminating server because of the following exception: ", e.what());
    }
  }

} // namespace maman14

#define DELETE (0x00010000L)

#undef LOG
#undef SOCKET_IO
#undef SOCKET_WRITE
#undef SOCKET_READ
