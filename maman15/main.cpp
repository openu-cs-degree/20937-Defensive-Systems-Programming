#include "client.h"

#include <iostream>

int main()
{
  auto client = maman15::Client::create();
  if (!client)
  {
    std::cout << "Failed to create client\n";
  }
  client->temp();
}