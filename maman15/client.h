/**
  @file client.h
  @author Yehonatan Simian
  @date February 2024

  +-----------------------------------------------------------------------------------+
  |                      Defensive System Programming - Maman 15                      |
  |                                                                                   |
  |           "Nothing starts until you take action." - Sonic The Hedgehog            |
  +-----------------------------------------------------------------------------------+

  @section DESCRIPTION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  This header provides a client interface compatible with the requirements of maman 15.
  The client can securely request a compatible server to backup and retrieve files.
  The protocol is over TCP and the data is sent in little endian format.

  The client is capable of sending the following requests:
  - Sign up
  - Send a public key
  - Sign in
  - Send a file
  - CRC valid
  - CRC invalid
  - CRC invalid for the 4th time

  The server can respond with the following responses:
  - Sign up succeeded
  - Sign up failed
  - Public key received, senging AES key
  - CRC valid
  - Message received (responsing to 'CRC valid' or 'CRC invalid for the fourth time')
  - Sign in allowed, sending AES key
  - Sign in rejected (client needs to sign up again)
  - General error

  The client is implemented using Boost.Asio, and uses TCP sockets for communication.

  @note The server doesn't handle endianess, as for most modern systems are assumed to
        be little endian, which is the requested endianess to be used.

  @section REVISIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  @section TODO ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  @section COMPILATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  To compile this project, I have used the following command:

  cl.exe /W4 /WX /analyze /std:c++17 /Zi /EHsc /nologo /D_WIN32_WINNT=0x0A00
         /I C:\path\to\boost "/FeC:\path\to\main.cpp"

  @copyright All rights reserved (c) Yehonatan Simian 2024 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

#pragma once

#pragma region includes
// +----------------------------------------------------------------------------------+
// | Inlcudes: Standard Library and Boost                                             |
// +----------------------------------------------------------------------------------+
#include <string_view>
#include <filesystem>
#include <algorithm>
#include <iostream>
#include <optional>
#include <fstream>
#include <cstdint>
#include <variant>
#include <thread>
#include <memory>

#pragma warning(push)
#pragma warning(disable : 6001 6031 6101 6255 6258 6313 6387)
#include <boost/asio.hpp>
#pragma warning(pop)
#pragma endregion

#pragma region macros
// +----------------------------------------------------------------------------------+
// | Macros & Logging Supplements                                                     |
// +----------------------------------------------------------------------------------+
namespace
{
#ifdef DEBUG
  template <typename T>
  void log(const T &t)
  {
    std::cerr << t << std::endl;
  }

  template <typename T, typename... Args>
  void log(const T &t, const Args &...args)
  {
    std::cerr << t;
    log(args...);
  }
#else
  template <typename... Args>
  void log([[maybe_unused]] const Args &...args) {}
#endif
} // anonymous namespace

#define SOCKET_IO(operation, pointer, size, error_value, ...)                                  \
  do                                                                                           \
  {                                                                                            \
    if (auto bytes_transferred = operation(socket, boost::asio::buffer(pointer, size), error); \
        error || bytes_transferred != size)                                                    \
    {                                                                                          \
      log(__VA_ARGS__);                                                                        \
      return error_value;                                                                      \
    }                                                                                          \
  } while (0)

#define SOCKET_WRITE_OR_RETURN(pointer, size, error_value, ...) \
  SOCKET_IO(boost::asio::write, pointer, size, error_value, __VA_ARGS__)

#define SOCKET_READ_OR_RETURN(pointer, size, error_value, ...) \
  SOCKET_IO(boost::asio::read, pointer, size, error_value, __VA_ARGS__)
#pragma endregion

#pragma region interface
// +----------------------------------------------------------------------------------+
// | Interface: user exposed functions and variables                                  |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  class Client
  {
  public:
    static constexpr inline uint32_t version = 3;

  private:
    static constexpr inline std::string_view instructions_file_name = "transfer.info";
    static constexpr inline std::string_view private_key_file_name = "priv.key";
    static constexpr inline std::string_view identifier_file_name = "me.info";

    using tcp = boost::asio::ip::tcp;

  public:
    Client();

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;
    Client(Client &&) = delete;
    Client &operator=(Client &&) = delete;
    ~Client() = default;

    bool register_to_server();
    bool send_public_key();
    bool send_file(const std::filesystem::path &file_path);
    bool validate_crc();
  };
} // namespace maman15
#pragma endregion

#pragma region enums
// +----------------------------------------------------------------------------------+
// | Enums: protocol enums and relevant functions                                     |
// +----------------------------------------------------------------------------------+
namespace
{
  enum class RequestCode : uint16_t
  {
    sign_up = 1025,
    send_public_key = 1026,
    sign_in = 1027,
    send_file = 1028,
    crc_valid = 1029,
    crc_invalid = 1030,
    crc_invalid_4th_time = 1031,
  };

  enum class ResponseCode : uint16_t
  {
    sign_up_succeeded = 1600,
    sign_up_failed = 1601,
    public_key_received = 1602,
    crc_valid = 1603,
    message_received = 1604,
    sign_in_allowed = 1605, // same table as 1602
    sign_in_rejected = 1606,
    general_error = 1607,
  };

  [[nodiscard]] auto is_valid_response_code(uint16_t value) -> bool
  {
    return value == static_cast<uint16_t>(ResponseCode::sign_up_succeeded) ||
           value == static_cast<uint16_t>(ResponseCode::sign_up_failed) ||
           value == static_cast<uint16_t>(ResponseCode::public_key_received) ||
           value == static_cast<uint16_t>(ResponseCode::crc_valid) ||
           value == static_cast<uint16_t>(ResponseCode::message_received) ||
           value == static_cast<uint16_t>(ResponseCode::sign_in_allowed) ||
           value == static_cast<uint16_t>(ResponseCode::sign_in_rejected) ||
           value == static_cast<uint16_t>(ResponseCode::general_error);
  }
} // anonymous namespace
#pragma endregion

#pragma region implementation_protocol
// +----------------------------------------------------------------------------------+
// | Implementation of the request protocol:                                          |
// | - Request class(es), include request processing implementation.                  |
// | - Response class(es).                                                            |
// | - Common class(es) for Request and Response                                      |
// +----------------------------------------------------------------------------------+
namespace
{
#pragma pack(push, 1)

  // classes to be used by both Request and Response

  class Payload
  {
    std::vector<uint8_t> content;

  private:
    Payload() = default;

  public:
    Payload(const Payload &) = delete;
    Payload &operator=(const Payload &) = delete;
    Payload(Payload &&) = default;
    Payload &operator=(Payload &&) = default;
    ~Payload() = default;

    Payload(std::vector<uint8_t> content)
        : content(std::move(content)){};

    explicit Payload(const std::string &content)
        : content(content.begin(), content.end()){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&size, sizeof(size), false, "Failed to write payload size: ", error.message());

      SOCKET_WRITE_OR_RETURN(content.get(), size, false, "Failed to write payload content: ", error.message());

      return true;
    };

    const bool write_to_file(const std::filesystem::path &file_path) const
    {
      std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
      if (!file)
      {
        log("Failed to open file: ", file_path);
        return false;
      }

      file.write(reinterpret_cast<const char *>(content.get()), size);
      if (!file)
      {
        log("Failed to write to file: ", file_path);
        return false;
      }

      return true;
    }

    static const std::optional<Payload> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      Payload payload;

      SOCKET_READ_OR_RETURN(&payload.size, sizeof(payload.size), {}, "Failed to read payload size: ", error.message());

      payload.content = std::make_unique<uint8_t[]>(payload.size);

      SOCKET_READ_OR_RETURN(payload.content.get(), payload.size, {}, "Failed to read payload content: ", error.message());

      return payload;
    };

    static const std::optional<Payload> read_from_file(const std::filesystem::path &file_path)
    {
      std::ifstream file(file_path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        log("Failed to open file: ", file_path);
        return {};
      }

      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      if (size > std::numeric_limits<uint32_t>::max())
      {
        log("File size is too big: ", size);
        return {};
      }

      std::unique_ptr<uint8_t[]> content(new uint8_t[static_cast<uint32_t>(size)]);
      file.read(reinterpret_cast<char *>(content.get()), size);
      if (!file)
      {
        log("Failed to read file: ", file_path);
        return {};
      }

      return std::make_optional<Payload>(static_cast<uint32_t>(size), std::move(content));
    }

    friend std::ostream &operator<<(std::ostream &os, const Payload &payload)
    {
      static constexpr uint32_t MAX_PAYLOAD_PRINT_SIZE = 69;

      os << "payload size: " << payload.size << '\n';
      os << (payload.size > MAX_PAYLOAD_PRINT_SIZE ? "payload (printing limited to 69 bytes):\n" : "payload:\n")
         << std::string_view(reinterpret_cast<const char *>(payload.content.get()), std::min(payload.size, MAX_PAYLOAD_PRINT_SIZE)) << '\n';

      return os;
    }
  };

  class Filename
  {
    uint16_t name_len;
    std::unique_ptr<char[]> content;

  private:
    Filename() = default;

  public:
    Filename(const Filename &) = delete;
    Filename &operator=(const Filename &) = delete;
    Filename(Filename &&) = default;
    Filename &operator=(Filename &&) = default;
    ~Filename() = default;

    explicit Filename(const std::string_view &filename)
        : name_len(static_cast<uint16_t>(filename.size())), content(std::make_unique<char[]>(name_len))
    {
      std::move(filename.begin(), filename.end(), this->content.get());
    }

    const std::string_view get_name() const
    {
      return std::string_view(content.get(), name_len);
    }

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&name_len, sizeof(name_len), false, "Failed to write name_len: ", error.message());

      SOCKET_WRITE_OR_RETURN(content.get(), name_len, false, "Failed to write filename: ", error.message());

      return true;
    }

    static const std::optional<Filename> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      Filename filename;

      SOCKET_READ_OR_RETURN(&filename.name_len, sizeof(filename.name_len), std::nullopt, "Failed to read name_len: ", error.message());

      if (filename.name_len == 0)
      {
        log("name_len can't be 0");
        return std::nullopt;
      }

      filename.content = std::make_unique<char[]>(filename.name_len);

      SOCKET_READ_OR_RETURN(filename.content.get(), filename.name_len, std::nullopt, "Failed to read filename: ", error.message());

      if (!filename.is_filename_valid())
      {
        log("Invalid filename: ", filename.get_name());
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
      return std::all_of(content.get(), content.get() + name_len, [](char c) -> bool
                         { return std::isalnum(c) || c == '.' || c == '_' || c == '-'; });
    }
  };

  struct ClientID
  {
    uint64_t lower;
    uint64_t upper;
    friend std::ostream &operator<<(std::ostream &os, const ClientID &client_id)
    {
      os << "client_id: " << client_id.upper << client_id.lower;
      return os;
    }
  };

  // forward declare Response so that it can be used in Request::process()

  class Response;

  // Requests base class

  class Request
  {
  protected:
    const ClientID client_id;
    const uint8_t version;
    const RequestCode code;
    const uint32_t payload_size;

    Request(ClientID client_id, RequestCode code, uint32_t payload_size)
        : client_id(client_id), version(maman15::Client::version), code(code), payload_size(payload_size){};

  public:
    Request(const Request &) = delete;
    Request &operator=(const Request &) = delete;
    Request(Request &&) = default;
    Request &operator=(Request &&) = default;

    virtual ~Request() = default;

    virtual const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->version, sizeof(version) + sizeof(code), false, "Failed to write response: ", error.message());

      return true;
    }

    virtual void print(std::ostream &os) const
    {
      os << client_id << '\n';
      os << "version: " << static_cast<uint16_t>(version) << '\n';
      os << "code: " << static_cast<uint16_t>(code) << '\n';
    }

    friend std::ostream &operator<<(std::ostream &os, const Request &request)
    {
      request.print(os);
      return os;
    }
  };

  // Response base class

  class Response
  {
  protected:
    const uint8_t server_version;
    const ResponseCode code;
    const uint32_t payload_size;

    Response(uint8_t server_version, ResponseCode code, uint32_t payload_size)
        : server_version(server_version), code(code), payload_size(payload_size){};

  public:
    Response(const Response &) = delete;
    Response &operator=(const Response &) = delete;
    Response(Response &&) = default;
    Response &operator=(Response &&) = default;

    virtual ~Response() = default;

    static const std::optional<Response> read_response_header(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      struct ResponseData
      {
        uint8_t server_version;
        ResponseCode code;
        uint32_t payload_size;
      };
      ResponseData data;

      SOCKET_READ_OR_RETURN(&data, sizeof(data), std::nullopt, "Failed to read request: ", error.message());

      if (!is_valid_response_code(static_cast<uint16_t>(data.code)))
      {
        log("Invalid code: ", static_cast<uint16_t>(data.code));
        return std::nullopt;
      }

      /// TODO: std::tuple?
      return Response(data.server_version, data.code, data.payload_size);
    }

    virtual void print(std::ostream &os) const
    {
      os << "version: " << static_cast<uint16_t>(server_version) << '\n';
      os << "code: " << static_cast<uint16_t>(code) << '\n';
    }

    friend std::ostream &operator<<(std::ostream &os, const Response &response)
    {
      response.print(os);
      return os;
    }
  };

  // Response concrete classes (final, non-abstract)

  class ResponseSuccessSignUp final : public Response
  {
    const ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseSuccessSignUp(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_up_succeeded, payload_size), client_id(client_id){};
  };

  class ResponseFailureSignUp final : public Response
  {
    static constexpr uint32_t payload_size = 0;

  public:
    explicit ResponseFailureSignUp(uint8_t server_version)
        : Response(server_version, ResponseCode::sign_up_failed, payload_size){};
  };

  class ResponseSuccessPublicKey final : public Response
  {
    ClientID client_id;
    std::array<uint8_t, 256> aes_key; // TODO: replace with AES key class
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

  public:
    explicit ResponseSuccessPublicKey(uint8_t server_version, ClientID client_id, std::array<uint8_t, 256> aes_key)
        : Response(server_version, ResponseCode::public_key_received, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};
  };

  class ResponseSuccessCRCValid final : public Response
  {
    ClientID client_id;
    uint32_t content_size;
    std::array<uint8_t, 255> filename; //  TODO: replace with Filename class
    uint32_t ckcsum;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(content_size) + sizeof(filename) + sizeof(ckcsum);

  public:
    explicit ResponseSuccessCRCValid(uint8_t server_version, ClientID client_id, uint32_t content_size, std::array<uint8_t, 255> filename, uint32_t ckcsum)
        : Response(server_version, ResponseCode::crc_valid, payload_size), client_id(client_id), content_size(content_size), filename(std::move(filename)), ckcsum(ckcsum){};
  };

  class ResponseSuccessMessageReceived final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseSuccessMessageReceived(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::message_received, payload_size), client_id(client_id){};
  };

  class ResponseSuccessSignInAllowed final : public Response
  {
    ClientID client_id;
    std::array<uint8_t, 256> aes_key; // TODO: replace with AES key class, merge with ResponseSuccessPublicKey
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

  public:
    explicit ResponseSuccessSignInAllowed(uint8_t server_version, ClientID client_id, std::array<uint8_t, 256> aes_key)
        : Response(server_version, ResponseCode::sign_in_allowed, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};
  };

  class ResponseFailureSignInRejected final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseFailureSignInRejected(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_in_rejected, payload_size), client_id(client_id){};
  };

  class ResponseErrorGeneral final : public Response
  {
    static constexpr uint32_t payload_size = 0;

  public:
    explicit ResponseErrorGeneral(uint8_t server_version)
        : Response(server_version, ResponseCode::general_error, payload_size){};
  };

  // Request concrete classs (final, non-abstract)

  class RequestSignUp final : public Request
  {
    std::array<uint8_t, 255> name; // TODO: replace with Name class
    static constexpr uint32_t payload_size = sizeof(name);

  public:
    explicit RequestSignUp(ClientID client_id, std::array<uint8_t, 255> name)
        : Request(client_id, RequestCode::sign_up, payload_size), name(std::move(name)){};
  };

  class RequestSendPublicKey final : public Request
  {
    std::array<uint8_t, 255> name;       // TODO: replace with Name class
    std::array<uint8_t, 160> public_key; // TODO: replace with public key class
    static constexpr uint32_t payload_size = sizeof(name) + sizeof(public_key);

  public:
    explicit RequestSendPublicKey(ClientID client_id, std::array<uint8_t, 255> name, std::array<uint8_t, 160> public_key)
        : Request(client_id, RequestCode::send_public_key, payload_size), name(std::move(name)), public_key(std::move(public_key)){};
  };

  class RequestSignIn final : public Request
  {
    std::array<uint8_t, 255> name; // TODO: replace with Name class
    static constexpr uint32_t payload_size = sizeof(name);

  public:
    explicit RequestSignIn(ClientID client_id, std::array<uint8_t, 255> name)
        : Request(client_id, RequestCode::sign_in, payload_size), name(name){};
  };

  class RequestSendFile final : public Request
  {
    uint32_t content_size;
    uint32_t orig_file_size;
    uint32_t packet_number_and_total_packets; // TODO: replace with Packet class
    std::array<uint8_t, 255> filename;        // TODO: replace with Filename class
    std::vector<uint8_t> content;
    static constexpr uint32_t payload_size_without_content = sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number_and_total_packets) + sizeof(filename);

  public:
    explicit RequestSendFile(ClientID client_id, uint32_t content_size, uint32_t orig_file_size, uint32_t packet_number_and_total_packets, std::array<uint8_t, 255> filename, std::vector<uint8_t> content)
        : Request(client_id, RequestCode::send_file, payload_size_without_content + content_size), content_size(content_size), orig_file_size(orig_file_size), packet_number_and_total_packets(packet_number_and_total_packets), filename(std::move(filename)), content(std::move(content)){};
  };

  class RequestCRCValid final : public Request
  {
    std::array<uint8_t, 255> filename; // TODO: replace with Filename class
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCValid(ClientID client_id, std::array<uint8_t, 255> filename)
        : Request(client_id, RequestCode::crc_valid, payload_size), filename(std::move(filename)){};
  };

  class RequestCRCInvalid final : public Request
  {
    std::array<uint8_t, 255> filename; // TODO: replace with Filename class
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCInvalid(ClientID client_id, std::array<uint8_t, 255> filename)
        : Request(client_id, RequestCode::crc_invalid, payload_size), filename(std::move(filename)){};
  };

  class RequestCRCInvalid4thTime final : public Request
  {
    std::array<uint8_t, 255> filename; // TODO: replace with Filename class
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCInvalid4thTime(ClientID client_id, std::array<uint8_t, 255> filename)
        : Request(client_id, RequestCode::crc_invalid_4th_time, payload_size), filename(std::move(filename)){};
  };

  // Sending requests

  const bool send_request(const Request &request, const boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
  {
    struct Visitor
    {
      bool operator()(const RequestSignUp &request)
      {
        log("Sending sign up request");
        return true;
      }
      bool operator()(const RequestSendPublicKey &request)
      {
        log("Sending public key request");
        return true;
      }
      bool operator()(const RequestSignIn &request)
      {
        log("Sending sign in request");
        return true;
      }
      bool operator()(const RequestSendFile &request)
      {
        log("Sending file request");
        return true;
      }
      bool operator()(const RequestCRCValid &request)
      {
        log("Sending CRC valid request");
        return true;
      }
      bool operator()(const RequestCRCInvalid &request)
      {
        log("Sending CRC invalid request");
        return true;
      }
      bool operator()(const RequestCRCInvalid4thTime &request)
      {
        log("Sending CRC invalid for the 4th time request");
        return true;
      }
      bool operator()(const Request &request) = delete;
    };

    std::variant<
        std::reference_wrapper<const RequestSignUp>,
        std::reference_wrapper<const RequestSendPublicKey>,
        std::reference_wrapper<const RequestSignIn>,
        std::reference_wrapper<const RequestSendFile>,
        std::reference_wrapper<const RequestCRCValid>,
        std::reference_wrapper<const RequestCRCInvalid>,
        std::reference_wrapper<const RequestCRCInvalid4thTime>,
        std::reference_wrapper<const Request>>
        variant = request;
    return std::visit(Visitor{}, variant);
  }
#pragma pack(pop)
} // anonymous namespace
#pragma endregion

#pragma region implementation_client
// +----------------------------------------------------------------------------------+
// | Implementation of the slient, which should not be protocol dependent             |
// +----------------------------------------------------------------------------------+
namespace
{
  std::unique_ptr<Request> read_request(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
  {
    // Read the common part of the request
    auto user_id_and_version_and_code = Request::read_user_id_and_version_and_code(socket, error);
    if (!user_id_and_version_and_code)
    {
      return {};
    }

    auto &[user_id, version, code] = *user_id_and_version_and_code;

    // Interpret each request type according to the code
    if (code == RequestCode::list)
    {
      return std::make_unique<RequestList>(user_id, version);
    }
    if (code == RequestCode::restore || code == RequestCode::remove || code == RequestCode::save)
    {
      auto filename = Filename::read_from_socket(socket, error);
      if (!filename)
      {
        return {};
      }

      if (code == RequestCode::restore)
      {
        return std::make_unique<RequestRestore>(user_id, version, std::move(filename.value()));
      }
      else if (code == RequestCode::remove)
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

  bool handle_request(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
  {
    log("Receiving request :)");
    auto request = read_request(socket, error);
    if (!request)
    {
      log("Request reading failed!");
      clear_socket(socket, error);
      return false;
    }
    log(*request);

    if (socket.available())
    {
      log("Socket had redundant data. Discarding it.");
      if (!clear_socket(socket, error))
      {
        log("Failed to discard extra data: ", error.message());
      }
    }

    log("Request received. Generating response:");
    auto response = request->process();
    if (!response)
    {
      log("Request processing failed!");
      return false;
    }
    log(*response);

    log("Sending response:");
    if (!response->write_to_socket(socket, error))
    {
      log("Failed to send response: ", error.message());
      return false;
    }
    log("Response sent successfully :D");

    return true;
  }

  void handle_client(boost::asio::ip::tcp::socket socket)
  {
    boost::system::error_code error;

    try
    {
      if (!handle_request(socket, error))
      {
        send_general_error(socket, error);
      }
    }
    catch ([[maybe_unused]] std::exception &e)
    {
      log("Exception caught: ", e.what());
      send_general_error(socket, error);
    }
  }
} // anonymous namespace
#pragma endregion

#pragma region implementation_interface
// +----------------------------------------------------------------------------------+
// | Implementation of the functions that were declared on #pragma interface          |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  Client::Client()
  {
    log("Client created");
  }

  bool Client::register_to_server()
  {
    log("Registering to server");
    return true;
  }

  bool Client::send_public_key()
  {
    log("Sending public key");
    return true;
  }

  bool Client::send_file(const std::filesystem::path &file_path)
  {
    log("Sending file: ", file_path);
    return true;
  }

  bool Client::validate_crc()
  {
    log("Validating CRC");
    return true;
  }

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
    catch ([[maybe_unused]] std::exception &e)
    {
      log("Terminating server because of the following exception: ", e.what());
    }
  }
} // namespace maman15
#pragma endregion

#pragma region cleanup
// +----------------------------------------------------------------------------------+
// | Cleanup: undefine macros and re-define logging                                   |
// +----------------------------------------------------------------------------------+
#undef SOCKET_IO
#undef SOCKET_WRITE_OR_RETURN
#undef SOCKET_READ_OR_RETURN
#pragma endregion