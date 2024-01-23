#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#pragma warning(push)
#pragma warning(disable : 6001 6031 6101 6255 6258 6313 6387)
#include <boost/asio.hpp>
#pragma warning(pop)

#include "server.h"

int main()
{
  maman14::Server server(60000);
  server.start();

  std::vector<std::string> msg{"Hello", "C++", "World", "from", "VS Code", "and the C++ extension!"};

  std::for_each(msg.begin(), msg.end(), [](std::string &word)
                { std::cout << word << " "; });

  std::cout << "\n\n";
}