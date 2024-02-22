#include "client.h"

#include <charconv>
#include <fstream>
#include <optional>
#include <sstream>

#include <base64.h>
#include <osrng.h>
#include <rsa.h>

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
} // namespace
#pragma endregion

#pragma region client_utils
// +----------------------------------------------------------------------------------+
// | ClientUtils: utilities for the client                                            |
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
    InstructionsFileContent() = default;

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
    std::string client_name;
    ClientID client_id;
    CryptoPP::RSA::PrivateKey private_key;

  private:
    IdentifierFileContent() = default;

  public:
    static std::optional<IdentifierFileContent> from_file(const std::filesystem::path &info_file_path)
    {
      std::ifstream file(info_file_path);
      if (!file.is_open())
      {
        return std::nullopt;
      }

      IdentifierFileContent content;
      std::string line;

      // Read client' name
      if (!std::getline(file, content.client_name) || content.client_name.length() > 100)
      {
        return std::nullopt;
      }

      // Read client' uid
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      if (line.size() != 32) // TODO: constexpr. 16 bytes = 128 bits = 32 hex characters
      {
        return std::nullopt;
      }
      auto id = ClientID::from_string(line);
      if (!id)
      {
        return std::nullopt;
      }
      content.client_id = id.value();

      // Read client's private key
      if (!std::getline(file, line))
      {
        return std::nullopt;
      }
      std::string decoded_key;
      CryptoPP::StringSource ss(line, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded_key)));
      content.private_key.Load(CryptoPP::StringSource(decoded_key, true).Ref());
      if (!content.private_key.Validate(rng, 3))
      {
        return std::nullopt;
      }

      // Make sure there are no more lines
      if (std::getline(file, line))
      {
        return std::nullopt;
      }

      return content;
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
      : socket(io_context), acceptor(io_context)
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