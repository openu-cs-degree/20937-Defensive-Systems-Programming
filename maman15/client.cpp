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

#include <aes.h>
#include <base64.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>

#pragma warning(push)
#pragma warning(disable : 4242 4266 6001 6031 6101 6255 6258 6313 6387)
#include <boost/asio.hpp>
#pragma warning(pop)
#pragma endregion

#define DEBUG 1

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

#pragma region crypt
// +----------------------------------------------------------------------------------+
// | Crypt: encryption and decryption utilities                                       |
// +----------------------------------------------------------------------------------+
namespace
{
  CryptoPP::AutoSeededRandomPool rng{}; // TODO: not global?

  // std::vector<uint8_t> generate_key();
  void encrypt([[maybe_unused]] const std::vector<uint8_t> &data)
  {
    // ...
  }

  void decrypt([[maybe_unused]] const std::vector<uint8_t> &data)
  {
    // ...
  }

  struct AESKey
  {
    static constexpr size_t key_len = 32; // 256 bits
    std::array<uint8_t, key_len> key;

    std::string encrypt(const std::vector<uint8_t> &data) const
    {
      CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};
      CryptoPP::AES::Encryption aesEncryption(key.data(), key.size());
      CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

      std::string encrypted;
      CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encrypted));
      stfEncryptor.Put(data.data(), data.size());
      stfEncryptor.MessageEnd();

      return encrypted;
    }

    friend std::ostream &operator<<(std::ostream &os, const AESKey &aes_key)
    {
      os << aes_key.key.data();
      return os;
    }
  }; // class AESKey

  class PrivateKey
  {
  public:
    struct Raw
    {
      static constexpr size_t key_len = 160;
      std::array<uint8_t, key_len> key;
      const inline uint8_t *data() const
      {
        return key.data();
      }
      friend std::ostream &operator<<(std::ostream &os, const PrivateKey::Raw &key)
      {
        os << key.data();
        return os;
      }
    };

  private:
    static constexpr unsigned int modulus_bits = 1024;

    CryptoPP::RSA::PrivateKey key;

  public:
    PrivateKey(const PrivateKey &) = delete;
    PrivateKey &operator=(const PrivateKey &) = delete;
    PrivateKey(PrivateKey &&) = default;
    PrivateKey &operator=(PrivateKey &&) = default;

    PrivateKey()
    {
      key.Initialize(rng, modulus_bits);
    };

    PrivateKey(CryptoPP::RSA::PrivateKey &&key)
        : key(std::move(key)){};

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

    explicit operator std::string() const
    {
      CryptoPP::RSAFunction public_key{key};
      std::string encoded_key;
      CryptoPP::StringSink ss{encoded_key};
      public_key.Save(ss);
      return encoded_key;
    }

    const void decrypt(AESKey &aes_key) const
    {
      CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
      std::string decrypted;
      CryptoPP::ArraySource{aes_key.key.data(), aes_key.key.size(), true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decrypted))};
      std::copy(decrypted.begin(), decrypted.end(), aes_key.key.begin());
    }

    friend std::ostream &operator<<(std::ostream &os, const PrivateKey &private_key)
    {
      std::string encoded_key;
      private_key.key.Save(CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded_key)).Ref());

      os << encoded_key;
      return os;
    }
  }; // class PrivateKey

  class PublicKey
  {
  public:
    struct Raw
    {
      static constexpr size_t key_len = 160;
      std::array<uint8_t, key_len> key;
      Raw(const PublicKey &public_key)
      {
        const CryptoPP::Integer &n = public_key.key.GetModulus();
        const CryptoPP::Integer &e = public_key.key.GetPublicExponent();

        CryptoPP::ArraySink key_sink{key.data(), key.size()};
        n.Encode(key_sink, key.size());
        e.Encode(key_sink, key.size());
      }
      const uint8_t *data() const
      {
        return key.data();
      }
      friend std::ostream &operator<<(std::ostream &os, const PublicKey::Raw &key)
      {
        os << key.data();
        return os;
      }
    };

  private:
    CryptoPP::RSA::PublicKey key;

  public:
    PublicKey() = delete;
    PublicKey(const PublicKey &) = delete;
    PublicKey &operator=(const PublicKey &) = delete;
    PublicKey(PublicKey &&) = default;
    PublicKey &operator=(PublicKey &&) = default;

    PublicKey(const std::string &str)
    {
      CryptoPP::StringSource ss(str, true);
      key.Load(ss);
    }

    PublicKey(const CryptoPP::RSA::PublicKey &&key)
        : key(key){};

    static std::optional<PublicKey> from_string(const std::string &str)
    {
      CryptoPP::RSA::PublicKey public_key;
      std::string decoded_key;
      CryptoPP::StringSource ss(str, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_key)));
      public_key.Load(CryptoPP::StringSource(decoded_key, true).Ref());
      if (!public_key.Validate(rng, 3))
      {
        return std::nullopt;
      }
      return std::make_optional<PublicKey>(std::move(public_key));
    }

    const PublicKey::Raw get_raw() const
    {
      return PublicKey::Raw{*this};
    }

    friend std::ostream &operator<<(std::ostream &os, const PublicKey &public_key)
    {
      std::string encoded_key;
      public_key.key.Save(CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded_key)).Ref());

      os << encoded_key;
      return os;
    }
  }; // class PublicKey
} // namespace
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
    NameBase() = default;

  public:
    NameBase(const NameBase &) = default;
    NameBase &operator=(const NameBase &) = default;
    NameBase(NameBase &&) = default;
    NameBase &operator=(NameBase &&) = default;
    ~NameBase() = default;

    const std::string_view get_name() const
    {
      return std::string_view(name.data());
    }

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&name, name_len, false, "Failed to write " + Trait::type_name + ": ", error.message());

      return true;
    }

    static const std::optional<NameBase<Trait>> read_from_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error)
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
             std::none_of(name.begin(), name.end(), [](char c) { return c == '\0'; });
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
    uint64_t upper;
    uint64_t lower;

    bool operator==(const ClientID &other) const
    {
      return upper == other.upper && lower == other.lower;
    }

    bool operator!=(const ClientID &other) const
    {
      return !(*this == other);
    }

    static std::optional<ClientID> from_string(const std::string &str)
    {
      static constexpr auto max_len = 32; // 128 bits = 16 bytes = 32 hex characters
      if (str.size() > max_len)
      {
        return std::nullopt;
      }
      std::array<char, max_len> arr{};
      std::fill(arr.begin(), arr.end(), '0');
      std::copy(str.begin(), str.end(), arr.end() - str.size());

      ClientID client_id;
      static constexpr auto half_arr = 16;
      auto res = std::from_chars(arr.data(), arr.data() + arr.size(), client_id.upper, half_arr);
      if (res.ec != std::errc())
      {
        return std::nullopt;
      }
      res = std::from_chars(arr.data() + half_arr, arr.data() + half_arr + arr.size(), client_id.lower, half_arr);
      if (res.ec != std::errc())
      {
        return std::nullopt;
      }
      return client_id;
    }

    friend std::ostream &operator<<(std::ostream &os, const ClientID &client_id)
    {
      os << "0x" << std::hex;
      if (client_id.upper > 0)
      {
        os << client_id.upper << std::setfill('0') << std::setw(16);
      }
      os << client_id.lower << std::dec;
      return os;
    }
  };

  struct PacketNumber
  {
    uint32_t data;

    PacketNumber(uint16_t packetNumber, uint16_t totalPackets)
        : data((packetNumber << 16) | totalPackets){};

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
      os << '\t' << "client_id: " << request.client_id << '\n'
         << '\t' << "version: " << static_cast<uint16_t>(request.version) << '\n'
         << '\t' << "code: " << static_cast<uint16_t>(request.code) << '\n'
         << '\t' << "payload_size: " << request.payload_size;
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

  struct ResponseSuccessSignUp final : public Response
  {
    const ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

    explicit ResponseSuccessSignUp(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_up_succeeded, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessSignUp &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  struct ResponseFailureSignUp final : public Response
  {
    static constexpr uint32_t payload_size = 0;

    explicit ResponseFailureSignUp(uint8_t server_version)
        : Response(server_version, ResponseCode::sign_up_failed, payload_size){};

    friend std::ostream &operator<<(std::ostream &os, [[maybe_unused]] const ResponseFailureSignUp &response)
    {
      return os;
    }
  };

  struct ResponseSuccessPublicKey final : public Response
  {
    ClientID client_id;
    AESKey aes_key;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

    explicit ResponseSuccessPublicKey(uint8_t server_version, ClientID client_id, AESKey aes_key)
        : Response(server_version, ResponseCode::public_key_received, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessPublicKey &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n'
         << '\t' << "aes_key: " << response.aes_key << '\n';
      return os;
    }
  };

  struct ResponseSuccessCRCValid final : public Response
  {
    ClientID client_id;
    uint32_t content_size;
    Filename filename;
    uint32_t ckcsum;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(content_size) + sizeof(filename) + sizeof(ckcsum);

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

  struct ResponseSuccessMessageReceived final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

    explicit ResponseSuccessMessageReceived(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::message_received, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessMessageReceived &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  struct ResponseSuccessSignInAllowed final : public Response
  {
    ClientID client_id;
    AESKey aes_key;
    static constexpr uint32_t payload_size = sizeof(client_id) + sizeof(aes_key);

    explicit ResponseSuccessSignInAllowed(uint8_t server_version, ClientID client_id, AESKey aes_key)
        : Response(server_version, ResponseCode::sign_in_allowed, payload_size), client_id(client_id), aes_key(std::move(aes_key)){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseSuccessSignInAllowed &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n'
         << '\t' << "aes_key: " << response.aes_key << '\n';
      return os;
    }
  };

  struct ResponseFailureSignInRejected final : public Response
  {
    ClientID client_id;
    static constexpr uint32_t payload_size = sizeof(client_id);

    explicit ResponseFailureSignInRejected(uint8_t server_version, ClientID client_id)
        : Response(server_version, ResponseCode::sign_in_rejected, payload_size), client_id(client_id){};

    friend std::ostream &operator<<(std::ostream &os, const ResponseFailureSignInRejected &response)
    {
      os << '\t' << "client_id: " << response.client_id << '\n';
      return os;
    }
  };

  struct ResponseErrorGeneral final : public Response
  {
    static constexpr uint32_t payload_size = 0;

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
    const ClientName &name;
    static constexpr uint32_t payload_size = sizeof(name);

  public:
    explicit RequestSignUp(const ClientName &name)
        : Request(ClientID{}, RequestCode::sign_up, payload_size), name(name){};

    const bool write_to_socket(boost::asio::ip::tcp::socket &socket, boost::system::error_code &error) const
    {
      SOCKET_WRITE_OR_RETURN(&this->name, sizeof(name), false, "Failed to write request's payload: ", error.message());

      return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const RequestSignUp &request)
    {
      os << '\t' << request.name << '\n';
      return os;
    }
  };

  class RequestSendPublicKey final : public Request
  {
    ClientName name;
    PublicKey::Raw public_key;
    static constexpr uint32_t payload_size = sizeof(name) + sizeof(public_key);

  public:
    explicit RequestSendPublicKey(ClientID client_id, ClientName name, PublicKey::Raw public_key)
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
    std::string content;
    static constexpr uint32_t payload_size_without_content = sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number_and_total_packets) + sizeof(filename);

  public:
    explicit RequestSendFile(ClientID client_id, uint32_t content_size, uint32_t orig_file_size, PacketNumber packet_number_and_total_packets, Filename filename, std::string content)
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

  using RequestVariant = std::variant<
      RequestSignUp,
      RequestSendPublicKey,
      RequestSignIn,
      RequestSendFile,
      RequestCRCValid,
      RequestCRCInvalid,
      RequestCRCInvalid4thTime>;

  // Requests & Responses IO

  bool send_request(const RequestVariant &request, boost::asio::ip::tcp::socket &socket)
  {
    boost::system::error_code error;

    bool success = std::visit([&](auto &&req) {
      if (!req.Request::write_to_socket(socket, error))
      {
        return false;
      }
      return req.write_to_socket(socket, error);
    },
                              request);

    return success && !error;
  }

  void log_request(const RequestVariant &request)
  {
    std::visit([&](auto &&req) {
      log("Header:");
      log(static_cast<const Request &>(req));
      log("Payload:");
      log(req);
    },
               request);
  }

  void log_response(const ResponseVariant &response)
  {
    std::visit([&](auto &&res) {
      log("Header:");
      log(static_cast<const Response &>(res));
      log("Payload:");
      log(res);
    },
               response);
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
      return ResponseSuccessCRCValid(server_version, ClientID{}, 0, Filename::from_string("temp").value(), 0);
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

#pragma region file_management
// +----------------------------------------------------------------------------------+
// | FileManagement: utilities for the client files' reading and writing              |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  struct InstructionsFileContent
  {
    static constexpr inline std::string_view instructions_file_name = "transfer.info";

    const boost::asio::ip::address ip;
    const uint16_t port;
    const ClientName client_name;
    const std::filesystem::path file_path;

  public:
    InstructionsFileContent() = delete;
    InstructionsFileContent(const InstructionsFileContent &) = delete;
    InstructionsFileContent &operator=(const InstructionsFileContent &) = delete;
    InstructionsFileContent(InstructionsFileContent &&) = default;
    InstructionsFileContent &operator=(InstructionsFileContent &&) = default;

    InstructionsFileContent(boost::asio::ip::address ip, uint16_t port, ClientName &&client_name, std::filesystem::path file_path)
        : ip(ip), port(port), client_name(std::move(client_name)), file_path(file_path){};

    static std::unique_ptr<InstructionsFileContent> load()
    {
      std::filesystem::path instructions_file_path{instructions_file_name};
      if (!std::filesystem::exists(instructions_file_path))
      {
        log("Instructions file (", instructions_file_name, ") does not exist.");
        return {};
      }
      std::ifstream file(instructions_file_path);
      if (!file.is_open())
      {
        return {};
      }

      std::string line;

      // Read IP and port
      if (!std::getline(file, line))
      {
        return {};
      }
      std::stringstream ss(line);
      std::string ipStr;
      uint16_t port;
      if (!std::getline(ss, ipStr, ':') || !(ss >> port))
      {
        return {};
      }
      auto ip = boost::asio::ip::address::from_string(ipStr);

      // Read client name
      if (!std::getline(file, line))
      {
        return {};
      }
      auto client_name = ClientName::from_string(line);
      if (!client_name)
      {
        return {};
      }

      // Read file path
      if (!std::getline(file, line))
      {
        return {};
      }
      std::filesystem::path file_path{line};

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return {};
      }

      return std::make_unique<InstructionsFileContent>(ip, port, std::move(client_name.value()), file_path);
    }

    friend std::ostream &operator<<(std::ostream &os, const InstructionsFileContent &instructions)
    {
      os << "ip: " << instructions.ip << '\n'
         << "port: " << instructions.port << '\n'
         << "client_name: " << instructions.client_name.get_name() << '\n'
         << "file_path: " << instructions.file_path << '\n';
      return os;
    }
  };

  struct IdentifierFileContent
  {
    static constexpr inline std::string_view identifier_file_name = "me.info";

    const ClientName client_name;
    const ClientID client_id;
    const PrivateKey private_key;

  public:
    IdentifierFileContent() = delete;
    IdentifierFileContent(const IdentifierFileContent &) = delete;
    IdentifierFileContent &operator=(const IdentifierFileContent &) = delete;
    IdentifierFileContent(IdentifierFileContent &&) = default;
    IdentifierFileContent &operator=(IdentifierFileContent &&) = default;

    IdentifierFileContent(ClientName client_name, ClientID client_id)
        // TODO: this c'tor is temporary, and it here due to the unclear step #2 of the sign-up instruction.
        : client_name(client_name), client_id(client_id), private_key(PrivateKey{CryptoPP::RSA::PrivateKey{}}){};
    IdentifierFileContent(ClientName &&client_name, ClientID &&client_id, PrivateKey &&private_key)
        : client_name(std::move(client_name)), client_id(std::move(client_id)), private_key(std::move(private_key)){};

    static const bool exists()
    {
      std::filesystem::path identifier_file_path{identifier_file_name};
      return std::filesystem::exists(identifier_file_path);
    }

    static std::unique_ptr<IdentifierFileContent> load()
    {
      std::filesystem::path identifier_file_path{identifier_file_name};
      std::ifstream file(identifier_file_path);
      if (!file.is_open())
      {
        return {};
      }

      std::string line;

      // Read client name
      if (!std::getline(file, line))
      {
        return {};
      }
      auto client_name = ClientName::from_string(line);
      if (!client_name)
      {
        return {};
      }

      // Read client uid
      if (!std::getline(file, line))
      {
        return {};
      }
      auto id = ClientID::from_string(line);
      if (!id)
      {
        return {};
      }

      // Read client's private key
      if (!std::getline(file, line))
      {
        return {};
      }
      auto private_key = PrivateKey::from_string(line);
      if (!private_key)
      {
        return {};
      }

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return {};
      }

      return std::make_unique<IdentifierFileContent>(std::move(client_name.value()), std::move(id.value()), std::move(private_key.value()));
    }

    const bool save() const
    {
      std::filesystem::path identifier_file_path{identifier_file_name};
      std::ofstream file(identifier_file_path);
      if (!file.is_open())
      {
        return false;
      }

      file << client_name.get_name() << '\n'
           << client_id << '\n'
           << private_key;

      return true;
    }
  };

  struct PrivateKeyFileContent
  {
    static constexpr inline std::string_view private_key_file_name = "priv.key";

    const PrivateKey private_key;

  public:
    PrivateKeyFileContent() = delete;
    PrivateKeyFileContent(const PrivateKeyFileContent &) = delete;
    PrivateKeyFileContent &operator=(const PrivateKeyFileContent &) = delete;
    PrivateKeyFileContent(PrivateKeyFileContent &&) = default;
    PrivateKeyFileContent &operator=(PrivateKeyFileContent &&) = default;

    PrivateKeyFileContent(PrivateKey &&private_key)
        : private_key(std::move(private_key)){};

    static std::unique_ptr<PrivateKeyFileContent> load()
    {
      std::filesystem::path private_key_file_path{private_key_file_name};
      std::ifstream file(private_key_file_path);
      if (!file.is_open())
      {
        return {};
      }

      std::string line;

      // Read client's private key
      if (!std::getline(file, line))
      {
        return {};
      }
      auto private_key = PrivateKey::from_string(line);
      if (!private_key)
      {
        return {};
      }

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return {};
      }

      return std::make_unique<PrivateKeyFileContent>(std::move(private_key.value()));
    }

    const bool save() const
    {
      std::filesystem::path private_key_file_path{private_key_file_name};
      std::ofstream file(private_key_file_path);
      if (!file.is_open())
      {
        return false;
      }

      file << private_key;

      return true;
    }
  };
} // namespace maman15
#pragma endregion

#pragma region client_impl
// +----------------------------------------------------------------------------------+
// | Client: implementation of Client::Impl class                                     |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  class Client::Impl
  {
    using tcp = boost::asio::ip::tcp;

  public:
    Impl(std::unique_ptr<InstructionsFileContent> &&instructions_file_content)
        : socket(io_context),
          instructions_file_content(std::move(instructions_file_content)){
              // TODO: uncomment when the server is ready
              // boost::asio::ip::tcp::resolver resolver(io_context);
              // boost::asio::ip::tcp::endpoint endpoint(instructions_file_content->ip, instructions_file_content->port);
              // boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(endpoint);
              // boost::asio::connect(socket, endpoints);
          };

    ~Impl() = default;

    bool register_to_server()
    {
      log("Registering to server");

      if (!instructions_file_content)
      {
        log("Client is corrupted. Try creating a new Client object.");
        return false;
      }

      if (IdentifierFileContent::exists())
      {
        return sign_in();
      }
      else
      {
        return sign_up();
      }
    }

    const bool send_public_key()
    {
      if (!is_connected)
      {
        log("Client is not connected to the server. Please register first.");
        return false;
      }

      PrivateKey private_key{};
      PublicKey public_key{static_cast<std::string>(private_key)};

      private_key_file_content = std::make_unique<PrivateKeyFileContent>(std::move(private_key));
      if (!private_key_file_content)
      {
        log("Failed to create ", PrivateKeyFileContent::private_key_file_name, " file");
        return false;
      }
      if (!private_key_file_content->save())
      {
        log("Failed to save ", PrivateKeyFileContent::private_key_file_name, " file");
        return false;
      }

      if (!send_request(RequestSendPublicKey{identifier_file_content->client_id, instructions_file_content->client_name, public_key.get_raw()}, socket))
      {
        log("Failed to send public key request");
        return false;
      }

      if (auto response = receive_response(socket); !response)
      {
        log("Failed to receive response from the server");
        return false;
      }
      else
      {
        log("Received reponse");
        bool public_key_sent_successfully = std::visit(
            [&](auto &&res) -> bool {
              using T = std::decay_t<decltype(res)>;
              if constexpr (std::is_same_v<T, ResponseSuccessPublicKey>)
              {
                log("Received public key response");
                if (res.client_id != identifier_file_content->client_id)
                {
                  log("Received client_id does not match the one in the identifier file");
                  return false;
                }
                aes_key.emplace(std::move(res.aes_key));
                private_key.decrypt(*aes_key);
                return true;
              }
              else
              {
                log("Did not receive public key response");
                return false;
              }
            },
            response.value());

        return public_key_sent_successfully;
      }
    }

    const bool send_file(const std::filesystem::path &file_path)
    {
      if (!is_connected)
      {
        log("Client is not connected to the server. Please register first.");
        return false;
      }
      if (!aes_key)
      {
        log("AES key is not available. Please send public key first.");
        return false;
      }
      if (!identifier_file_content || !private_key_file_content)
      {
        log("Client is corrupted. Try creating a new Client object.");
        return false;
      }

      auto request = Impl::create_request_send_file(identifier_file_content->client_id, file_path, *aes_key);
      if (!request)
      {
        log("Failed to create send-file request");
        return false;
      }

      if (!send_request(*request, socket))
      {
        log("Failed to send send-file request");
        return false;
      }

      if (auto response = receive_response(socket); !response)
      {
        log("Failed to receive response from the server");
        return false;
      }
      else
      {
        log("Received reponse");
        bool file_sent_successfully = std::visit(
            [&](auto &&res) -> bool {
              using T = std::decay_t<decltype(res)>;
              if constexpr (std::is_same_v<T, ResponseSuccessMessageReceived>)
              {
                log("Received file response");
                if (res.client_id != identifier_file_content->client_id)
                {
                  log("Received client_id does not match the one in the identifier file");
                  return false;
                }
                return true;
              }
              else
              {
                log("Did not receive success response");
                return false;
              }
            },
            response.value());

        return file_sent_successfully;
      }
    }

    const bool validate_crc()
    {
      log("TODO: validate CRC");

      return false;
    }

  private:
    bool clear_socket()
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

    bool sign_up()
    {
      if (!send_request(RequestSignUp{instructions_file_content->client_name}, socket))
      {
        log("Failed to send sign up request");
        return false;
      }

      if (auto response = receive_response(socket); !response)
      {
        log("Failed to receive response from the server");
        return false;
      }
      else
      {
        log("Received reponse");
        is_connected = std::visit(
            [&](auto &&res) -> bool {
              using T = std::decay_t<decltype(res)>;
              if constexpr (std::is_same_v<T, ResponseSuccessSignUp>)
              {
                log("Received sign up response");
                identifier_file_content = std::make_unique<IdentifierFileContent>(instructions_file_content->client_name, res.client_id);
                if (!identifier_file_content)
                {
                  log("Failed to create ", IdentifierFileContent::identifier_file_name, " file");
                  return false;
                }
                if (!identifier_file_content->save())
                {
                  log("Failed to save ", IdentifierFileContent::identifier_file_name, " file");
                  return false;
                }
                return true;
              }
              else
              {
                log("Did not receive sign up response");
                return false;
              }
            },
            response.value());

        return is_connected;
      }
    }

    bool sign_in()
    {
      identifier_file_content = IdentifierFileContent::load(); // technically, I could just use the pre-loaded member variable
      if (!identifier_file_content)
      {
        log("Failed to read ", IdentifierFileContent::identifier_file_name, " file");
        return false;
      }
      private_key_file_content = PrivateKeyFileContent::load();
      if (!private_key_file_content)
      {
        log("Failed to read ", PrivateKeyFileContent::private_key_file_name, " file");
        return false;
      }

      if (!send_request(RequestSignIn{identifier_file_content->client_id, identifier_file_content->client_name}, socket))
      {
        log("Failed to send sign-in request");
        return false;
      }

      if (auto response = receive_response(socket); !response)
      {
        log("Failed to receive response from the server");
        return false;
      }
      else
      {
        log("Received reponse");
        is_connected = std::visit(
            [&](auto &&res) -> bool {
              using T = std::decay_t<decltype(res)>;
              if constexpr (std::is_same_v<T, ResponseSuccessSignInAllowed>)
              {
                log("Received sign in allowed response");
                if (res.client_id != identifier_file_content->client_id)
                {
                  log("Received client_id does not match the one in the identifier file");
                  return false;
                }
                aes_key.emplace(std::move(res.aes_key));
                private_key_file_content->private_key.decrypt(*aes_key);
                return true;
              }
              else
              {
                log("Did not receive sign in allowed response");
                return false;
              }
            },
            response.value());

        return is_connected;
      }
    }

    static const std::optional<RequestVariant> create_request_send_file(ClientID client_id, const std::filesystem::path &file_path, const AESKey &aes_key)
    {
      if (!std::filesystem::exists(file_path))
      {
        log("File does not exist: ", file_path);
        return std::nullopt;
      }
      if (!std::filesystem::is_regular_file(file_path))
      {
        log("File is not a regular file: ", file_path);
        return std::nullopt;
      }
      if (std::filesystem::file_size(file_path) > static_cast<uintmax_t>(std::numeric_limits<uint32_t>::max()))
      {
        log("File is too large: ", file_path);
        return std::nullopt;
      }
      std::ifstream file(file_path, std::ios::binary);
      if (!file.is_open())
      {
        log("Failed to open file: ", file_path);
        return std::nullopt;
      }

      std::vector<uint8_t> content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
      std::string encrypted_content = aes_key.encrypt(content);
      const uint32_t encrypted_content_size = encrypted_content.size();
      const uint32_t orig_file_size = static_cast<uint32_t>(std::filesystem::file_size(file_path));
      const PacketNumber packet_number_and_total_packets{1, 1}; // TODO: implement packetization
      const auto filename = Filename::from_string(file_path.filename().string());
      if (!filename)
      {
        log("Failed to create filename from file path: ", file_path);
        return std::nullopt;
      }

      return RequestSendFile{client_id, encrypted_content_size, orig_file_size, packet_number_and_total_packets, Filename::from_string(file_path.filename().string()).value(), std::move(encrypted_content)};
    }

  public:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;

    // TODO: std::optional instead?
    std::unique_ptr<InstructionsFileContent> instructions_file_content;
    std::unique_ptr<PrivateKeyFileContent> private_key_file_content;
    std::unique_ptr<IdentifierFileContent> identifier_file_content;

    std::optional<AESKey> aes_key;

    bool is_connected = false;
  };
} // namespace maman15
#pragma endregion

#pragma region client
// +----------------------------------------------------------------------------------+
// | Client: implementation of Client class                                           |
// +----------------------------------------------------------------------------------+
namespace maman15
{
  Client::Client(std::unique_ptr<Impl> &&pImpl)
      : pImpl(std::move(pImpl))
  {
    log("Client created successfully");
  }

  std::shared_ptr<Client> Client::create()
  {
    struct ConcreteClient : public Client
    {
      ConcreteClient(std::unique_ptr<Impl> &&pImpl)
          : Client(std::move(pImpl)){};
    }; // to make std::make_shared stfu

    try
    {
      auto instructions_file = InstructionsFileContent::load();
      if (!instructions_file)
      {
        log("Failed to read transfer file");
        return {};
      }
      log(*instructions_file);

      std::unique_ptr<Impl> pImpl = std::make_unique<Impl>(std::move(instructions_file));
      return std::make_shared<ConcreteClient>(std::move(pImpl));
    }
    catch (const std::exception &e)
    {
      log("Failed to create client: ", e.what());
      return {};
    }
  }

  // TODO: wrap pImpl->whatever() with if (!pImpl) log and then return false;

  const bool Client::register_to_server()
  {
    return pImpl->register_to_server();
  }

  void Client::temp()
  {
    log("temp");
    auto instructions_file = InstructionsFileContent::load();
    if (!instructions_file)
    {
      log("Failed to read instructions file");
      return;
    }
    log(instructions_file->ip, ":", instructions_file->port, "\n", instructions_file->client_name, instructions_file->file_path.string());

    RequestVariant request{RequestSignUp{instructions_file->client_name}};
    log("RequestSignUp:");
    log_request(request);

    ResponseVariant response{ResponseSuccessSignUp{1, ClientID{0, 69}}};
    log("ResponseSuccessSignUp:");
    log_response(response);

    if (std::holds_alternative<ResponseSuccessSignUp>(response))
    {
      ResponseSuccessSignUp &success_response = std::get<ResponseSuccessSignUp>(response);
      IdentifierFileContent identifier_file{instructions_file->client_name, success_response.client_id};
      if (!identifier_file.save())
      {
        log("Failed to write me.info file");
      }
      else
      {
        log("Wrote me.info file successfully");
      }
    }
  }

  const bool Client::send_public_key()
  {
    return pImpl->send_public_key();
  }

  const bool Client::send_file(const std::filesystem::path &file_path)
  {
    return pImpl->send_file(file_path);
  }

  const bool Client::validate_crc()
  {
    return pImpl->validate_crc();
  }

  Client::~Client() = default;
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