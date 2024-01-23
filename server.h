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
    static constexpr uint8_t VERSION = 1;

  public:
    Server(uint16_t port)
        : acceptor(io_context, tcp::endpoint(tcp::v4(), port))
    {
    }
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;
    Server(Server &&) = delete;
    Server &operator=(Server &&) = delete;

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

    static std::optional<Response> process_request(Request &request)
    {
      std::cout << "process_request\n";
      Response response{Server::VERSION, Status::ERROR_GENERAL, request.name_len, std::move(request.filename), std::move(request.payload)};

      switch (request.op)
      {
      case Op::SAVE:
        response.status = Status::SUCCESS_SAVE;
        break;
      case Op::RESTORE:
        response.status = Status::SUCCESS_RESTORE;
        break;
      case Op::DELETE:
        response.status = Status::SUCCESS_RESTORE;
        break;
      case Op::LIST:
        response.status = Status::SUCCESS_LIST;
        break;
      default:
        response.status = Status::ERROR_GENERAL;
        break;
      }

      return response;
    }

    static void write_response(tcp::socket &socket, Response &response)
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
      boost::asio::write(socket, boost::asio::buffer(response.payload.payload.get(), response.payload.size), error);

      if (error)
      {
        std::cout << "Error: " << error.message() << '\n';
        return;
      }

      std::cout << "Response sent\n";
    }

    static void handle_client(tcp::socket socket)
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
      // std::cout << "payload: " << request->payload.payload.get() << '\n';

      auto respone = process_request(request.value());
      if (!respone)
      {
        std::cout << "Request processing failed!" << '\n';
        return;
      }

      std::cout << "Response ready\n";
      // std::cout << "version: " << respone->version << '\n';
      // std::cout << "status: " << static_cast<uint16_t>(respone->status) << '\n';
      // std::cout << "name_len: " << respone->name_len << '\n';
      // std::cout << "filename: " << respone->filename.get() << '\n';
      // std::cout << "payload size: " << respone->payload.size << '\n';
      // std::cout << "payload: " << respone->payload.payload.get() << '\n';

      write_response(socket, respone.value());
    }
  };

} // namespace maman14