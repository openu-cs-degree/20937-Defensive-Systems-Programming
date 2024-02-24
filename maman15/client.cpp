#pragma region includes
// +----------------------------------------------------------------------------------+
// | Inlcudes: Standard Library and Boost                                             |
// +----------------------------------------------------------------------------------+
#include "client.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <type_traits>
#include <variant>

#include <base64.h>
#include <osrng.h>
#include <rsa.h>
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
  void log([[maybe_unused]] const Args &...args)
  {
  }
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

#pragma region protocol
// +----------------------------------------------------------------------------------+
// | Definition of this project's protocol:                                           |
// | - Request class(es), include request processing implementation.                  |
// | - Response class(es).                                                            |
// | - Common class(es) for Request and Response                                      |
// +----------------------------------------------------------------------------------+
namespace
{
#pragma pack(push, 1)

  // classes to be used by both Request and Response

  template <typename Trait>
  class NameBase
  {
    static constexpr size_t name_len = 255;
    std::array<char, name_len> name;
    // TODO: name_len and max_name_len?

  private:
  public:
    NameBase() = default; // TODO: make private
    NameBase(const NameBase &) = default;
    NameBase &operator=(const NameBase &) = default;
    NameBase(NameBase &&) = default;
    NameBase &operator=(NameBase &&) = default;
    ~NameBase() = default;

    const std::string get_name() const
    {
      return std::string(name.data(), name.size());
    }

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&name, name_len, false, "Failed to write " + Trait::type_name + ": ", error.message());

      return true;
    }

    // TODO: return std::optional<NameBase> or std::optional<NameBase<Trait>>?
    static const std::optional<NameBase> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      NameBase name{};

      SOCKET_READ_OR_RETURN(&name, name_len, std::nullopt, "Failed to read " + Trait::type_name + ": ", error.message());

      if (!Trait::is_valid(name))
      {
        log("Invalid " + Trait::type_name + ": ", name.get_name());
        return std::nullopt;
      }

      return name;
    }

    static const std::optional<NameBase<Trait>> from_string(const std::string &str)
    {
      NameBase name{};

      if (!Trait::is_valid(str))
      {
        log("Invalid ", Trait::type_name, ": ", str);
        return std::nullopt;
      }

      std::copy(str.begin(), str.end(), name.name.begin());

      return name;
    }

    friend std::ostream &operator<<(std::ostream &os, const NameBase &name)
    {
      os << Trait::type_name << ": " << name.get_name() << '\n';
      return os;
    }

    // TODO: make private is_valid(const std::string &str), check that len <= 255
  };

  struct ClientNameTrait
  {
    static constexpr char type_name[] = "name";
    static constexpr size_t min_name_len = 1;
    static constexpr size_t max_name_len = 100;

    // TODO: check more characters? \n etc.?
    static bool is_valid(const std::string &name)
    {
      return name.size() >= min_name_len &&
             name.size() <= max_name_len &&
             std::none_of(name.begin(), name.end() - 1, [](char c) { return c == '\0'; }) &&
             *(name.end() - 1) == '\0';
    }
  };

  struct FilenameTrait
  {
    static constexpr char type_name[] = "filename";
    static constexpr size_t min_filename_len = 1;
    static constexpr size_t max_filename_len = 255;

    static bool is_valid(const std::string &filename)
    {
      static constexpr std::array forbidden_start_char = {' '};
      static constexpr std::array forbidden_middle_chars = {'\0', '/', '\\', ':', '*', '?', '"', '<', '>', '|'};
      static constexpr std::array forbidden_end_char = {' ', '.'};

      return filename.size() >= min_filename_len &&
             filename.size() <= max_filename_len &&
             std::none_of(forbidden_start_char.begin(), forbidden_start_char.end(), [&](char c) { return filename.front() == c; }) &&
             std::none_of(forbidden_end_char.begin(), forbidden_end_char.end(), [&](char c) { return filename.back() == c; }) &&
             std::none_of(filename.begin(), filename.end(), [&](char c) { return std::any_of(forbidden_middle_chars.begin(), forbidden_middle_chars.end(), [&](char f) { return f == c; }); });
    }
  };

  using ClientName = NameBase<ClientNameTrait>;
  using Filename = NameBase<FilenameTrait>;

  struct ClientID
  {
    uint64_t lower;
    uint64_t upper;
    static std::optional<ClientID> from_string(const std::string_view &str)
    {
      ClientID client_id;
      auto res = std::from_chars(str.data(), str.data() + str.size(), client_id.lower, 16);
      if (res.ec != std::errc())
      {
        return std::nullopt;
      }
      res = std::from_chars(str.data() + 16, str.data() + 16 + str.size(), client_id.upper, 16);
      if (res.ec != std::errc())
      {
        return std::nullopt;
      }
      return client_id;
    }
    friend std::ostream &operator<<(std::ostream &os, const ClientID &client_id)
    {
      os << client_id.upper << client_id.lower;
      return os;
    }
  };

  struct AESKey
  {
    std::array<uint8_t, 256> key;
    friend std::ostream &operator<<(std::ostream &os, const AESKey &aes_key)
    {
      os << aes_key.key.data();
      return os;
    }
  };

  struct PublicKey
  {
    std::array<uint8_t, 160> key;
    friend std::ostream &operator<<(std::ostream &os, const PublicKey &public_key)
    {
      os << public_key.key.data();
      return os;
    }
  };

  struct PacketNumber
  {
    uint32_t data;

    uint16_t getPacketNumber() const
    {
      return data >> 16;
    }

    uint16_t getTotalPackets() const
    {
      return data & 0xFFFF;
    }

    void setPacketNumber(uint16_t packetNumber)
    {
      data = (data & 0xFFFF) | (packetNumber << 16);
    }

    void setTotalPackets(uint16_t totalPackets)
    {
      data = (data & 0xFFFF0000) | totalPackets;
    }

    friend std::ostream &operator<<(std::ostream &os, const PacketNumber &packet)
    {
      os << "packet number " << packet.getPacketNumber() << " out of " << packet.getTotalPackets();
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
    static constexpr size_t header_size = sizeof(client_id) + sizeof(version) + sizeof(code) + sizeof(payload_size);

    Request(ClientID client_id, RequestCode code, uint32_t payload_size)
        : client_id(client_id), version(maman15::Client::version), code(code), payload_size(payload_size){};

  public:
    Request(const Request &) = delete;
    Request &operator=(const Request &) = delete;
    Request(Request &&) = default;
    Request &operator=(Request &&) = default;
    ~Request() = default;

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->client_id, header_size, false, "Failed to write response: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const Request &request)
    {
      os << '\t' << request.client_id << '\n'
         << '\t' << "version: " << static_cast<uint16_t>(request.version) << '\n'
         << '\t' << "code: " << static_cast<uint16_t>(request.code) << '\n'
         << '\t' << "payload_size: " << request.payload_size << '\n';
      return os;
    }
  };

  // Response base class

  class Response // TODO: change to ResponseHeader?
  {
  public:
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
    ~Response() = default;

    static const std::optional<std::tuple<uint8_t, ResponseCode, uint32_t>> read_response_header(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
    {
      // TODO: replace with ResponseHeader and send instead of tuple
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

      return std::make_tuple(data.server_version, data.code, data.payload_size);
    }

    friend std::ostream &operator<<(std::ostream &os, const Response &response)
    {
      os << '\t' << "version: " << static_cast<uint16_t>(response.server_version) << '\n'
         << '\t' << "code: " << static_cast<uint16_t>(response.code) << '\n'
         << '\t' << "payload_size: " << response.payload_size << '\n';
      return os;
    }
  };

  // Response concrete classes (final, non-abstract)

  class ResponseSuccessSignUp final : public Response
  {
  public: // TODO: either make private or make it a struct
    const ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseSuccessSignUp(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_up_succeeded, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessSignUp &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  class ResponseFailureSignUp final : public Response
  {
    static constexpr uint32_t payload_size = 0;

  public:
    explicit ResponseFailureSignUp(uint8_t server_version)
        : Response(server_version, ResponseCode::sign_up_failed, payload_size){};

    friend std::ostream &operator<<(std::ostream &os, [[maybe_unused]] const ResponseFailureSignUp &response)
    {
      return os;
    }
  };

  class ResponseSuccessPublicKey final : public Response
  {
    ClientID client_id;
    AESKey aes_key;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

  public:
    explicit ResponseSuccessPublicKey(uint8_t server_version, ClientID client_id, AESKey aes_key)
        : Response(server_version, ResponseCode::public_key_received, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessPublicKey &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n'
         << '\t' << "aes_key: " << response.aes_key << '\n';
      return os;
    }
  };

  class ResponseSuccessCRCValid final : public Response
  {
    ClientID client_id;
    uint32_t content_size;
    Filename filename;
    uint32_t ckcsum;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(content_size) + sizeof(filename) + sizeof(ckcsum);

  public:
    explicit ResponseSuccessCRCValid(uint8_t server_version, ClientID client_id, uint32_t content_size, Filename filename, uint32_t ckcsum)
        : Response(server_version, ResponseCode::crc_valid, payload_size), client_id(client_id), content_size(content_size), filename(std::move(filename)), ckcsum(ckcsum){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessCRCValid &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n'
         << '\t' << "content_size: " << response.content_size << '\n'
         << '\t' << "filename: " << response.filename << '\n'
         << '\t' << "ckcsum: " << response.ckcsum << '\n';
      return os;
    }
  };

  class ResponseSuccessMessageReceived final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseSuccessMessageReceived(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::message_received, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessMessageReceived &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  class ResponseSuccessSignInAllowed final : public Response
  {
    ClientID client_id;
    AESKey aes_key;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

  public:
    explicit ResponseSuccessSignInAllowed(uint8_t server_version, ClientID client_id, AESKey aes_key)
        : Response(server_version, ResponseCode::sign_in_allowed, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessSignInAllowed &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n'
         << '\t' << "aes_key: " << response.aes_key << '\n';
      return os;
    }
  };

  class ResponseFailureSignInRejected final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

  public:
    explicit ResponseFailureSignInRejected(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_in_rejected, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseFailureSignInRejected &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  class ResponseErrorGeneral final : public Response
  {
    static constexpr uint32_t payload_size = 0;

  public:
    explicit ResponseErrorGeneral(uint8_t server_version)
        : Response(server_version, ResponseCode::general_error, payload_size){};

    friend std::ostream &operator<<(std::ostream &os, [[maybe_unused]] const ResponseErrorGeneral &response)
    {
      return os;
    }
  };

  using ResponseVariant = std::variant<
      ResponseSuccessSignUp,
      ResponseFailureSignUp,
      ResponseSuccessPublicKey,
      ResponseSuccessCRCValid,
      ResponseSuccessMessageReceived,
      ResponseSuccessSignInAllowed,
      ResponseFailureSignInRejected,
      ResponseErrorGeneral>;

  // Request concrete classs (final, non-abstract)

  class RequestSignUp final : public Request
  {
    ClientName &name;
    static constexpr uint32_t payload_size = sizeof(name);

  public:
    explicit RequestSignUp(ClientName &name)
        : Request(ClientID{}, RequestCode::sign_up, payload_size), name(name){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->name, sizeof(name), false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestSignUp &request)
    {
      os << '\t' << "name: " << request.name << '\n';
      return os;
    }
  };

  class RequestSendPublicKey final : public Request
  {
    ClientName name;
    PublicKey public_key;
    static constexpr uint32_t payload_size = sizeof(name) + sizeof(public_key);

  public:
    explicit RequestSendPublicKey(ClientID client_id, ClientName name, PublicKey public_key)
        : Request(client_id, RequestCode::send_public_key, payload_size), name(std::move(name)), public_key(std::move(public_key)){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->name, payload_size, false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestSendPublicKey &request)
    {
      os << '\t' << "name: " << request.name << '\n'
         << '\t' << "public_key: " << request.public_key << '\n';
      return os;
    }
  };

  class RequestSignIn final : public Request
  {
    const ClientName &name;
    static constexpr uint32_t payload_size = sizeof(name);

  public:
    explicit RequestSignIn(ClientID client_id, const ClientName &name)
        : Request(client_id, RequestCode::sign_in, payload_size), name(name){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->name, payload_size, false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestSignIn &request)
    {
      os << '\t' << "name: " << request.name << '\n';
      return os;
    }
  };

  class RequestSendFile final : public Request
  {
    uint32_t content_size;
    uint32_t orig_file_size;
    PacketNumber packet_number_and_total_packets;
    Filename filename;
    std::vector<uint8_t> content;
    static constexpr uint32_t payload_size_without_content = sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number_and_total_packets) + sizeof(filename);

  public:
    explicit RequestSendFile(ClientID client_id, uint32_t content_size, uint32_t orig_file_size, PacketNumber packet_number_and_total_packets, Filename filename, std::vector<uint8_t> content)
        : Request(client_id, RequestCode::send_file, payload_size_without_content + content_size), content_size(content_size), orig_file_size(orig_file_size), packet_number_and_total_packets(packet_number_and_total_packets), filename(std::move(filename)), content(std::move(content)){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->content_size, payload_size_without_content, false, "Failed to write request's payload: ", error.message());

      SOCKET_WRITE_OR_RETURN(this->content.data(), this->content.size(), false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestSendFile &request)
    {
      os << '\t' << "content_size: " << request.content_size << '\n'
         << '\t' << "orig_file_size: " << request.orig_file_size << '\n'
         << '\t' << "packet_number_and_total_packets: " << request.packet_number_and_total_packets << '\n'
         << '\t' << "filename: " << request.filename << '\n'
         << '\t' << "content: " << request.content.data() << '\n';
      return os;
    }
  };

  class RequestCRCValid final : public Request
  {
    Filename filename;
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCValid(ClientID client_id, Filename filename)
        : Request(client_id, RequestCode::crc_valid, payload_size), filename(std::move(filename)){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->filename, payload_size, false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestCRCValid &request)
    {
      os << '\t' << "filename: " << request.filename << '\n';
      return os;
    }
  };

  class RequestCRCInvalid final : public Request
  {
    Filename filename;
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCInvalid(ClientID client_id, Filename filename)
        : Request(client_id, RequestCode::crc_invalid, payload_size), filename(std::move(filename)){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->filename, payload_size, false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestCRCInvalid &request)
    {
      os << '\t' << "filename: " << request.filename << '\n';
      return os;
    }
  };

  class RequestCRCInvalid4thTime final : public Request
  {
    Filename filename;
    static constexpr uint32_t payload_size = sizeof(filename);

  public:
    explicit RequestCRCInvalid4thTime(ClientID client_id, Filename filename)
        : Request(client_id, RequestCode::crc_invalid_4th_time, payload_size), filename(std::move(filename)){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->filename, payload_size, false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestCRCInvalid4thTime &request)
    {
      os << '\t' << "filename: " << request.filename << '\n';
      return os;
    }
  };

  // Requests & Responses IO

  template <typename FullRequest>
  typename std::enable_if<std::is_base_of<Request, FullRequest>::value && !std::is_same<Request, FullRequest>::value, bool>::type
  send_request(const FullRequest &request, boost::asio::ip::tcp::socket &socket)
  {
    boost::system::error_code error;

    if (!request.Request::write_to_socket(socket, error))
    {
      return false;
    }

    if (!request.write_to_socket(socket, error))
    {
      return false;
    }

    return true;
  }

  template <typename FullRequest>
  typename std::enable_if<std::is_base_of<Request, FullRequest>::value && !std::is_same<Request, FullRequest>::value, std::ostream &>::type
  operator<<(std::ostream &os, const FullRequest &request)
  {
    os << "Header:\n"
       << static_cast<const Request &>(request)
       << "Payload:\n"
       << static_cast<const FullRequest &>(request);

    return os;
  }

  const std::optional<ResponseVariant> receive_response(boost::asio::ip::tcp::socket &socket)
  {
    boost::system::error_code error;

    auto response = Response::read_response_header(socket, error);
    if (!response)
    {
      return std::nullopt;
    }

    auto &[server_version, code, payload_size] = *response;

    if (code == ResponseCode::sign_up_succeeded)
    {
      return ResponseSuccessSignUp(server_version, ClientID{});
    }
    if (code == ResponseCode::sign_up_failed)
    {
      return ResponseFailureSignUp(server_version);
    }
    if (code == ResponseCode::public_key_received)
    {
      return ResponseSuccessPublicKey(server_version, ClientID{}, AESKey{});
    }
    if (code == ResponseCode::crc_valid)
    {
      return ResponseSuccessCRCValid(server_version, ClientID{}, 0, Filename{}, 0);
    }
    if (code == ResponseCode::message_received)
    {
      return ResponseSuccessMessageReceived(server_version, ClientID{});
    }
    if (code == ResponseCode::sign_in_allowed)
    {
      return ResponseSuccessSignInAllowed(server_version, ClientID{}, AESKey{});
    }
    if (code == ResponseCode::sign_in_rejected)
    {
      return ResponseFailureSignInRejected(server_version, ClientID{});
    }
    if (code == ResponseCode::general_error)
    {
      return ResponseErrorGeneral(server_version);
    }

    return std::nullopt;
  }
#pragma pack(pop)
} // anonymous namespace
#pragma endregion

#pragma region crypt
// +----------------------------------------------------------------------------------+
// | Crypt: encryption and decryption utilities                                       |
// +----------------------------------------------------------------------------------+
namespace
{
  CryptoPP::AutoSeededRandomPool rng{};

  // std::vector<uint8_t> generate_key();
  void encrypt([[maybe_unused]] const std::vector<uint8_t> &data)
  {
    // ...
  }

  void decrypt([[maybe_unused]] const std::vector<uint8_t> &data)
  {
    // ...
  }

  struct PrivateKey
  {
    const CryptoPP::RSA::PrivateKey key;

  public:
    PrivateKey() = delete;
    PrivateKey(const PrivateKey &) = delete;
    PrivateKey &operator=(const PrivateKey &) = delete;
    PrivateKey(PrivateKey &&) = default;
    PrivateKey &operator=(PrivateKey &&) = default;

    PrivateKey(const CryptoPP::RSA::PrivateKey &&key)
        : key(key){};

    static std::optional<PrivateKey> from_string(const std::string &str)
    {
      CryptoPP::RSA::PrivateKey private_key;
      std::string decoded_key;
      CryptoPP::StringSource ss(str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_key)));
      private_key.Load(CryptoPP::StringSource(decoded_key, true).Ref());
      if (!private_key.Validate(rng, 3))
      {
        return std::nullopt;
      }
      return std::make_optional<PrivateKey>(std::move(private_key));
    }

    friend std::ostream &operator<<(std::ostream &os, const PrivateKey &private_key)
    {
      std::string encoded_key;
      private_key.key.Save(CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded_key)).Ref());

      os << encoded_key;
      return os;
    }
  };
} // namespace
#pragma endregion

#pragma region file_management
// +----------------------------------------------------------------------------------+
// | FileManagement: utilities for the client files' reading and writing              |
// +----------------------------------------------------------------------------------+
namespace
{
  struct InstructionsFileContent
  {
    boost::asio::ip::address ip;
    uint16_t port;
    ClientName client_name;
    std::filesystem::path file_path;

  private:
    InstructionsFileContent() = default; // TODO: delete, use std::move instead, then const all member variables

  public:
    static std::optional<InstructionsFileContent> from_file(const std::filesystem::path &info_file_path)
    {
      std::ifstream file(info_file_path);
      if (!file.is_open())
      {
        return std::nullopt;
      }

      InstructionsFileContent content;
      std::string line;

      // Read IP and port
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      std::stringstream ss(line);
      std::string ipStr;
      if (!std::getline(ss, ipStr, ':') || !(ss >> content.port))
      {
        return std::nullopt;
      }
      content.ip = boost::asio::ip::address::from_string(ipStr);

      // Read client name
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      auto client_name = ClientName::from_string(line);
      if (!client_name)
      {
        return std::nullopt;
      }
      content.client_name = std::move(client_name.value());

      // Read file path
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      content.file_path = line;

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return std::nullopt;
      }

      return content;
    }
  };

  struct IdentifierFileContent
  {
    const ClientName client_name;
    const ClientID client_id;
    const PrivateKey private_key;

  public:
    IdentifierFileContent() = delete;
    IdentifierFileContent(const IdentifierFileContent &) = delete;
    IdentifierFileContent &operator=(const IdentifierFileContent &) = delete;
    IdentifierFileContent(IdentifierFileContent &&) = delete;
    IdentifierFileContent &operator=(IdentifierFileContent &&) = delete;

    IdentifierFileContent(ClientName client_name, ClientID client_id)
        // TODO: this c'tor is temporary, and it here due to the unclear step #2 of the sign-up instruction.
        : client_name(client_name), client_id(client_id), private_key(PrivateKey{CryptoPP::RSA::PrivateKey{}}){};
    IdentifierFileContent(ClientName &&client_name, ClientID &&client_id, PrivateKey &&private_key)
        : client_name(std::move(client_name)), client_id(std::move(client_id)), private_key(std::move(private_key)){};

    static std::optional<IdentifierFileContent> from_file(const std::filesystem::path &info_file_path)
    {
      std::ifstream file(info_file_path);
      if (!file.is_open())
      {
        return std::nullopt;
      }

      std::string line;

      // Read client name
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      auto client_name = ClientName::from_string(line);
      if (!client_name)
      {
        return std::nullopt;
      }

      // Read client uid
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      if (line.size() != 32) // TODO: constexpr. 16 bytes = 128 bits = 32 hex characters. also, move to ClientID::from_string
      {
        return std::nullopt;
      }
      auto id = ClientID::from_string(line);
      if (!id)
      {
        return std::nullopt;
      }

      // Read client's private key
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      auto private_key = PrivateKey::from_string(line);
      if (!private_key)
      {
        return std::nullopt;
      }

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return std::nullopt;
      }

      return std::make_optional<IdentifierFileContent>(std::move(client_name.value()), std::move(id.value()), std::move(private_key.value()));
    }

    const bool to_file(const std::filesystem::path &info_file_path) const
    {
      std::ofstream file(info_file_path);
      if (!file.is_open())
      {
        return false;
      }

      file << client_name << '\n'
           << client_id << '\n'
           << private_key;

      return true;
    }
  };

  struct PrivateKeyFileContent
  {
    const PrivateKey private_key;

  public:
    PrivateKeyFileContent() = delete;
    PrivateKeyFileContent(const PrivateKeyFileContent &) = delete;
    PrivateKeyFileContent &operator=(const PrivateKeyFileContent &) = delete;
    PrivateKeyFileContent(IdentifierFileContent &&) = delete;
    PrivateKeyFileContent &operator=(IdentifierFileContent &&) = delete;

    PrivateKeyFileContent(PrivateKey &&private_key)
        : private_key(std::move(private_key)){};

    static std::optional<PrivateKeyFileContent> from_file(const std::filesystem::path &info_file_path)
    {
      std::ifstream file(info_file_path);
      if (!file.is_open())
      {
        return std::nullopt;
      }

      std::string line;

      // Read client's private key
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      auto private_key = PrivateKey::from_string(line);
      if (!private_key)
      {
        return std::nullopt;
      }

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return std::nullopt;
      }

      return std::make_optional<PrivateKeyFileContent>(std::move(private_key.value()));
    }
  };
} // namespace
#pragma endregion

#pragma region client
// +----------------------------------------------------------------------------------+
// | Client: implementation of Client class                                           |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  Client::Client()
      : socket(io_context)
  {
    log("Client created");
  }

  bool Client::register_to_server()
  {
    log("Registering to server");

    // Read instructions file
    if (!std::filesystem::exists(instructions_file_name)) // TODO: into InstructionsFileContent::from_file
    {
      log("Instructions file (", instructions_file_name, ") does not exist.");
      return false;
    }
    auto instructions_file_content = InstructionsFileContent::from_file(instructions_file_name);
    if (!instructions_file_content)
    {
      log("Failed to read transfer file");
      return false;
    }

    // Connect to server
    // TODO: move connection to... c'tor? factory? I don't like factory in this case...
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::endpoint endpoint(instructions_file_content->ip, instructions_file_content->port);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(endpoint);
    boost::asio::connect(socket, endpoints);

    // if identifier exists, sign in
    if (std::filesystem::exists(identifier_file_name))
    {
      auto identifier_file_content = IdentifierFileContent::from_file(identifier_file_name);
      if (!identifier_file_content)
      {
        log("Failed to read me file");
        return false;
      }

      if (!send_request(RequestSignIn{identifier_file_content->client_id, identifier_file_content->client_name}, socket))
      {
        log("Failed to send client id");
        return false;
      }
      if (auto response = receive_response(socket))
      {
        log("Received reponse: ", response);
        // TODO: handle response
        return true;
      }
      else
      {
        log("Failed to receive client id");
        return false;
      }
    }
    else // sign up
    {
      if (!send_request(RequestSignUp{instructions_file_content->client_name}, socket))
      {
        log("Failed to send client name");
        return false;
      }
      if (auto response = receive_response(socket))
      {
        log("Received reponse: ", response);
        // handle response
        bool result = std::visit(
            [&](auto &&arg) -> bool {
              using T = std::decay_t<decltype(arg)>;
              if constexpr (std::is_same_v<T, ResponseSuccessSignUp>)
              {
                log("Received sign up response: ", arg);
                IdentifierFileContent identifier_file_content{instructions_file_content->client_name, arg.client_id};
                if (!identifier_file_content.to_file(identifier_file_name))
                {
                  log("Failed to write me file");
                  return false;
                }
                return true;
              }
              else if constexpr (std::is_same_v<T, ResponseFailureSignUp>)
              {
                log("Received sign up failed response: ", arg);
                return false;
              }
              else if constexpr (std::is_same_v<T, ResponseErrorGeneral>)
              {
                log("Received general error: ", arg);
                return false;
              }
              else
              {
                log("Received unexpected response: ", arg);
                return false;
              }
            },
            response.value());

        return result;
      }
      else
      {
        log("Failed to receive client id");
        return false;
      }
    }

    // TODO: move sign_in and sign_up to separate functions?
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

  bool Client::clear_socket()
  {
    boost::system::error_code error;
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
} // namespace maman15
#pragma endregion

#pragma region macros_cleanup
// +----------------------------------------------------------------------------------+
// | Cleanup: undefine macros                                                         |
// +----------------------------------------------------------------------------------+
#undef SOCKET_IO
#undef SOCKET_WRITE_OR_RETURN
#undef SOCKET_READ_OR_RETURN
#pragma endregion