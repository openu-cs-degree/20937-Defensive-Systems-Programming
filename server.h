#include <iostream>
#include <boost/asio.hpp>
#include <thread>

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

    static void handle_client(tcp::socket socket)
    {
      std::array<char, 128> buf;
      boost::system::error_code error;

      [[maybe_unused]] size_t len = socket.read_some(boost::asio::buffer(buf), error);

      if (!error)
      {
        std::cout << "Deciphered!" << std::endl;
        boost::asio::write(socket, boost::asio::buffer("Response from server"));
      }
      else
      {
        std::cout << "Error: " << error.message() << std::endl;
      }
    }
  };

}