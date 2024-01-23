#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

int main()
{
  std::vector<std::string> msg{"Hello", "C++", "World", "from", "VS Code", "and the C++ extension!"};

  std::for_each(msg.begin(), msg.end(), [](std::string &word)
                { std::cout << word << " "; });

  std::cout << "\n\n";
}