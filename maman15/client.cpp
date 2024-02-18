#include "client.h"

#pragma region crypt
// +----------------------------------------------------------------------------------+
// | Crypt: encryption and decryption utilities                                       |
// +----------------------------------------------------------------------------------+
namespace
{
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