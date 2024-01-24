#pragma once
#include <cstdint>
#include <memory>
#undef DELETE // the DELETE macro collides with Op::DELETE definition

#ifdef __GNUC__
#define PACK(__Declaration__) __Declaration__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define PACK(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
#endif

namespace maman14
{
  enum class Op : uint8_t
  {
    SAVE = 100,
    RESTORE = 200, // no size or payload
    DELETE = 201,  // no size or payload
    LIST = 202,    // no size, payload, name_len or filename
  };

  enum class Status : uint16_t
  {
    SUCCESS_RESTORE = 210,
    SUCCESS_LIST = 211,
    SUCCESS_SAVE = 212,     // no size or payload
    ERROR_NO_FILE = 1001,   // no size or payload
    ERROR_NO_CLIENT = 1002, // only version and status
    ERROR_GENERAL = 1003,   // only version and status
  };

  PACK(
      struct Payload {
        uint32_t size;
        std::unique_ptr<uint8_t[]> payload;
      };

      struct Request {
        uint32_t user_id;
        uint8_t version;
        Op op;
        uint16_t name_len;
        std::unique_ptr<char[]> filename;
        Payload payload;
      };

      struct Response {
        uint8_t version;
        Status status;
        uint16_t name_len;
        std::unique_ptr<char[]> filename;
        Payload payload;
      };)
}
