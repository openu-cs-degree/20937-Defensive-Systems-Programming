#include <gtest/gtest.h>
#include <boost/asio.hpp>

#include <initializer_list>
#include <thread>
#include <vector>
#include <array>

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

/*
 * ~~~~~~~~~~~~~~~~~~~~~~~~~ Maman 14 - Server Test ~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Instructions:
 *
 * 1. Replace #include "server.h" below with your own server header.
 * 2. Replace the `start_server` function with your own implementation.
 * 3. Replace the `VRSN` constant with your own server version number.
 * 4. Ensure to empty the server backup folder before you start the tests(!)
 * 5. Uncomment `#define DEBUG` to enable see each response (raw) from the server.
 * 6. Run the tests, and good luck!
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~ Yoni HaMelech (c) 2024 ~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include "server.h"

void start_server()
{
  maman14::start_server_on_port(60000);
}

#define VRSN 0x06
// #define DEBUG

namespace
{
  // ------------------- Requests: -------------||------- user_id ------||ver || op || name_len ||  filename   ||-------- size --------||pay ||
  static const std::vector<uint8_t> request_sav_1{0x04, 0xD2, 0x00, 0x00, 0x01, 0x64, 0x03, 0x00, 'a', ' ', 'c', 0x01, 0x00, 0x00, 0x00, 0x61};
  static const std::vector<uint8_t> request_sav_2{0x04, 0xD2, 0x00, 0x00, 0x01, 0x64, 0x03, 0x00, 'b', '.', 'c', 0x01, 0x00, 0x00, 0x00, 0x61};
  static const std::vector<uint8_t> request_res_1{0x04, 0xD2, 0x00, 0x00, 0x01, 0xC8, 0x03, 0x00, 'a', ' ', 'c'};
  static const std::vector<uint8_t> request_res_2{0x04, 0xD2, 0x00, 0x00, 0x01, 0xC8, 0x03, 0x00, 'b', '.', 'c'};
  static const std::vector<uint8_t> request_del_1{0x04, 0xD2, 0x00, 0x00, 0x01, 0xC9, 0x03, 0x00, 'a', ' ', 'c'};
  static const std::vector<uint8_t> request_del_2{0x04, 0xD2, 0x00, 0x00, 0x01, 0xC9, 0x03, 0x00, 'b', '.', 'c'};
  static const std::vector<uint8_t> request_lst_0{0x04, 0xD2, 0x00, 0x00, 0x01, 0xCA};
  // ------------ Invalid Requests: ------------||------- user_id ------||ver || op || name_len ||    filename    ||-------- size --------||      pay       ||
  static const std::vector<uint8_t> request_inv_1{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x03, 0x00, 0x61, 0x00, 0x62, 0x03, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63};
  static const std::vector<uint8_t> request_inv_2{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x03, 0x00, 0x61, 0x20, 0x63, 0x03, 0x00, 0x00, 0x00, 0x61, 0x00, 0x63}; // this one's valid
  static const std::vector<uint8_t> request_inv_3{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x03, 0x00, 0x61, 0x00, 0x63, 0x03, 0x00, 0x00, 0x00, 0x61, 0x00, 0x63};
  static const std::vector<uint8_t> request_inv_4{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x03, 0x00, 0x61, 0x2F, 0x63, 0x00, 0x00, 0x00, 0x00};
  static const std::vector<uint8_t> request_inv_5{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x03, 0x00, 0x61, 0x5C, 0x63, 0x00, 0x00, 0x00, 0x00};
  static const std::vector<uint8_t> request_inv_6{0x04, 0xD2, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x61, 0x2E, 0x63, 0x00, 0x00, 0x00, 0x00};
  // ------------- Fuzzed Requests: ------------||------- user_id ------||ver || op || ----------------- garbage -------------------------------||
  static const std::vector<uint8_t> request_fuz_1{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const std::vector<uint8_t> request_fuz_2{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  static const std::vector<uint8_t> request_fuz_3{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const std::vector<uint8_t> request_fuz_4{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  // static const std::vector<uint8_t> request_fuz_5{0x00, 0x00, 0x00, 0x00, 0x00}; // Not taking care of short requests for now.

  // ------------- Responses: -------------------||ver ||- status -|| name_len ||  filename   ||-------- size --------||pay ||
  static const std::vector<uint8_t> response_res_1{VRSN, 0xD2, 0x00, 0x03, 0x00, 'a', ' ', 'c', 0x01, 0x00, 0x00, 0x00, 0x61};
  static const std::vector<uint8_t> response_res_2{VRSN, 0xD2, 0x00, 0x03, 0x00, 'b', '.', 'c', 0x01, 0x00, 0x00, 0x00, 0x61};
  static const std::vector<uint8_t> response_sav_1{VRSN, 0xD4, 0x00, 0x03, 0x00, 'a', ' ', 'c'};
  static const std::vector<uint8_t> response_sav_2{VRSN, 0xD4, 0x00, 0x03, 0x00, 'b', '.', 'c'};
  static const std::vector<uint8_t> response_del_1{VRSN, 0xD4, 0x00, 0x03, 0x00, 'a', ' ', 'c'};
  static const std::vector<uint8_t> response_del_2{VRSN, 0xD4, 0x00, 0x03, 0x00, 'b', '.', 'c'};
  static const std::vector<uint8_t> resp_no_file_1{VRSN, 0xE9, 0x03, 0x03, 0x00, 'a', ' ', 'c'};
  static const std::vector<uint8_t> resp_no_file_2{VRSN, 0xE9, 0x03, 0x03, 0x00, 'b', '.', 'c'};
  static const std::vector<uint8_t> resp_no_client{VRSN, 0xEA, 0x03};
  static const std::vector<uint8_t> resp_gen_error{VRSN, 0xEB, 0x03};

  // ------------- ListReponse Payloads: -------------------
  static const std::vector<uint8_t> response_list_payload_0{};
  static const std::vector<uint8_t> response_list_payload_1{'a', ' ', 'c', '\n'};
  static const std::vector<uint8_t> response_list_payload_2{'b', '.', 'c', '\n'};
  static const std::vector<uint8_t> response_list_payload_12{'a', ' ', 'c', '\n', 'b', '.', 'c', '\n'};

  std::vector<uint8_t> send_request(const std::vector<uint8_t> &request)
  {
    using boost::asio::ip::tcp;

    boost::asio::io_context io_context;

    tcp::socket socket(io_context);
    tcp::endpoint endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 60000);
    socket.connect(endpoint);

    boost::asio::write(socket, boost::asio::buffer(request, request.size()));

    std::vector<uint8_t> recv_data;
    boost::system::error_code error;
    do
    {
      std::array<uint8_t, 128> buffer;
      size_t len = socket.read_some(boost::asio::buffer(buffer), error);
      if (error && error != boost::asio::error::eof)
      {
        throw boost::system::system_error(error); // Handle error appropriately.
      }
      recv_data.insert(recv_data.end(), buffer.begin(), buffer.begin() + len);
    } while (!error);

#ifdef DEBUG
    std::for_each(recv_data.begin(), recv_data.end(), [](uint8_t &c)
                  { std::cout << std::hex << static_cast<int>(c) << " "; });
    std::cout << std::endl;
#endif

    return recv_data;
  }

#define VALIDATE_RESPONSE(response, expected)                                                                                                          \
  do                                                                                                                                                   \
  {                                                                                                                                                    \
    EXPECT_EQ(response.size(), expected.size()) << "Response size does not match expected size.";                                                      \
    auto pair = std::mismatch(response.begin(), response.end(), expected.begin());                                                                     \
    EXPECT_TRUE(pair.first == response.end() && pair.second == expected.end()) << "Mismatch at index " << std::distance(response.begin(), pair.first); \
  } while (0)

#define SEND_REQUEST_AND_EXPECT_RESPONSE(request, expected) \
  do                                                        \
  {                                                         \
    auto response = send_request(request);                  \
    VALIDATE_RESPONSE(response, expected);                  \
  } while (0)

#define SEND_AND_VALIDATE_LIST_REQUEST(list_request, payload)                                                                    \
  do                                                                                                                             \
  {                                                                                                                              \
    auto response = send_request(list_request);                                                                                  \
    ASSERT_EQ(response.size(), 41 + payload.size()) << "Response size does not match expected size.";                            \
    std::vector<uint8_t> expected_start = {VRSN, 0xD3, 0x00, 0x20, 0x00};                                                        \
    EXPECT_TRUE(std::equal(response.begin(), response.begin() + 5, expected_start.begin())) << "Mismatch in the first 5 bytes."; \
    for (size_t i = 5; i < 37; ++i)                                                                                              \
    {                                                                                                                            \
      EXPECT_TRUE(std::isalnum(response[i])) << "Non-alphanumeric character at index " << i;                                     \
    }                                                                                                                            \
    uint32_t payload_size = *reinterpret_cast<const uint32_t *>(&response[37]);                                                  \
    EXPECT_EQ(payload_size, payload.size()) << "Payload size does not match expected size.";                                     \
    EXPECT_TRUE(std::equal(response.begin() + 41, response.end(), payload.begin())) << "Mismatch in payload content.";           \
  } while (0)
} // namespace

class ServerTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    std::thread(start_server).detach();

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
};

TEST_F(ServerTest, RequestSave)
{
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_2, response_sav_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_2, response_sav_2);
}

TEST_F(ServerTest, RequestRestore)
{
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, response_res_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, response_res_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, response_res_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, response_res_2);
}

TEST_F(ServerTest, RequestDelete)
{
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, response_del_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, response_del_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, resp_no_client);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, resp_no_client);
}

TEST_F(ServerTest, RequestsMixed)
{
  // no files
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_lst_0, resp_no_client);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, resp_no_client);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, resp_no_client);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, resp_no_client);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, resp_no_client);

  // one file
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_1);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, response_res_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, resp_no_file_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, resp_no_file_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, response_del_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, resp_no_file_1);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_0);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, resp_no_file_1);

  // two files
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_2, response_sav_2);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_12);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, response_res_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, response_res_2);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_12);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, response_del_1);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, response_del_2);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_0);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, resp_no_file_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_2, resp_no_file_2);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, resp_no_file_1);
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, resp_no_file_2);
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_0);

  // maman example
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_0);  // step 4
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_1, response_sav_1);         // step 5
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_sav_2, response_sav_2);         // step 6
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_12); // step 7
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, response_res_1);         // step 8
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, response_del_1);         // step 9
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_res_1, resp_no_file_1);         // step 10
  SEND_AND_VALIDATE_LIST_REQUEST(request_lst_0, response_list_payload_2);  // just to make sure

  // cleanup
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_2, response_del_2);
}

TEST_F(ServerTest, InvalidInput)
{
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_1, resp_gen_error); // null terminator inside filename
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_2, response_sav_1); // null terminator inside payload
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_3, resp_gen_error); // null terminator inside filename and payload
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_4, resp_gen_error); // invalid filename #1
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_5, resp_gen_error); // invalid filename #2
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_inv_6, resp_gen_error); // zero length filename

  // cleanup
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_del_1, response_del_1);
}

TEST_F(ServerTest, FuzzedRequests)
{
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_fuz_1, resp_gen_error); // all zeros
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_fuz_2, resp_gen_error); // all ones
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_fuz_3, resp_gen_error); // zeros + extra byte
  SEND_REQUEST_AND_EXPECT_RESPONSE(request_fuz_4, resp_gen_error); // zeros without extra bytes
  // SEND_REQUEST_AND_EXPECT_RESPONSE(request_fuz_5, resp_gen_error); // short message, not taking care of this for now
}

int main(int argc, char **argv)
{
  _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}