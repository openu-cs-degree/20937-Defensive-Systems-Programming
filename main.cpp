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
  maman14::start_server_on_port(60000);
}