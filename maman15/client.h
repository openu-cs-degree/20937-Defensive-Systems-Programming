/**
  @file client.h
  @author Yehonatan Simian
  @date February 2024

  +-----------------------------------------------------------------------------------+
  |                      Defensive System Programming - Maman 15                      |
  |                                                                                   |
  |           "Nothing starts until you take action." - Sonic The Hedgehog            |
  +-----------------------------------------------------------------------------------+

  @section DESCRIPTION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  This header provides a client interface compatible with the requirements of maman 15.
  The client can securely request a compatible server to backup and retrieve files.
  The protocol is over TCP and the data is sent in little endian format.

  The client is capable of sending the following requests:
  - Sign up
  - Send a public key
  - Sign in
  - Send a file
  - CRC valid
  - CRC invalid
  - CRC invalid for the 4th time

  The server can respond with the following responses:
  - Sign up succeeded
  - Sign up failed
  - Public key received, senging AES key
  - CRC valid
  - Message received (responsing to 'CRC valid' or 'CRC invalid for the fourth time')
  - Sign in allowed, sending AES key
  - Sign in rejected (client needs to sign up again)
  - General error

  The client is implemented using Boost 1.84.0 and Crypto++ 8.9.0.

  @note The server doesn't handle endianess, as for most modern systems are assumed to
        be little endian, which is the requested endianess to be used.

  @section REVISIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  @section TODO ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  @section COMPILATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  To compile this project, I have used the following command:

  cl.exe /W4 /WX /analyze /std:c++17 /Zi /EHsc /nologo /D_WIN32_WINNT=0x0A00
         /I C:\path\to\boost "/FeC:\path\to\main.cpp"

  @copyright All rights reserved (c) Yehonatan Simian 2024 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

#pragma once

#include <filesystem>
#include <memory>

namespace maman15
{
  class Client
  {
  public:
    static constexpr inline uint32_t version = 3;

  private:
    class Impl;
    Client(std::unique_ptr<Impl> &&impl);

  public:
    static std::shared_ptr<Client> create();

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;
    Client(Client &&) = default;
    Client &operator=(Client &&) = default;
    ~Client();

    const bool register_to_server();
    const bool send_public_key();
    const bool send_file(const std::filesystem::path &file_path);
    void temp();

  private:
    std::unique_ptr<Impl> pImpl;
  };
} // namespace maman15