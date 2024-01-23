#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <optional>

#include "common.h"

using boost::asio::ip::tcp;

namespace maman14
{

  class Server
  {
  public:
    Server(uint16_t port)
        : acceptor(io_context, tcp::endpoint(tcp::v4(), port))
    {
    }

    void start()
    {
      try
      {
        while (true)
        {
          std::cout << "Waiting for connection\n";
          tcp::socket socket(io_context);
          acceptor.accept(socket);
          std::cout << "Accepted for connection\n";

          std::thread(Server::handle_client, std::move(socket)).detach();
        }
      }
      catch (std::exception &e)
      {
        std::cerr << e.what() << '\n';
      }
    }

  private:
    boost::asio::io_context io_context;
    tcp::acceptor acceptor;

    static std::optional<Request> read_request(tcp::socket &socket)
    {
      std::cout << "read_request\n";
      boost::system::error_code error;

      // Read the fixed-size part of the request
      Request request;
      boost::asio::read(socket, boost::asio::buffer(&request, offsetof(Request, filename)), error);

      if (error)
      {
        std::cout << "Error reading name_len: " << error.message() << '\n';
        return std::nullopt;
      }
      request.name_len -= 11567; // TEMP: putty's connection sets name_len to 11568

      // Read the filename
      request.filename = std::make_unique<char[]>(request.name_len);
      boost::asio::read(socket, boost::asio::buffer(request.filename.get(), request.name_len), error);

      if (error)
      {
        std::cout << "Error reading filename: " << error.message() << '\n';
        return std::nullopt;
      }

      // Read the size of the payload
      boost::asio::read(socket, boost::asio::buffer(&request.payload.size, sizeof(request.payload.size)), error);

      if (error)
      {
        std::cout << "Error: " << error.message() << '\n';
        return std::nullopt;
      }
      request.payload.size -= 1498698868; // TEMP: putty's connection sets name_len to 1498698869

      // Read the payload
      request.payload.payload = std::make_unique<uint8_t[]>(request.payload.size);
      boost::asio::read(socket, boost::asio::buffer(request.payload.payload.get(), request.payload.size), error);

      if (error)
      {
        std::cout << "Error: " << error.message() << '\n';
        return std::nullopt;
      }

      return request;
    }

    static void handle_client(tcp::socket socket)
    {
      if (auto request = read_request(socket))
      {
        std::cout << "Request received\n";
        // std::cout << "user_id: " << request->user_id << '\n';
        // std::cout << "version: " << request->version << '\n';
        // std::cout << "op: " << static_cast<uint16_t>(request->op) << '\n';
        // std::cout << "name_len: " << request->name_len << '\n';
        // std::cout << "filename: " << request->filename.get() << '\n';
        // std::cout << "payload size: " << request->payload.size << '\n';
        // std::cout << "payload: " << request->payload.payload.get() << '\n';
      }
      else
      {
        std::cout << "Request reading failed!" << '\n';
      }

      boost::asio::write(socket, boost::asio::buffer("Response from server"));
    }
  };

} // namespace maman14