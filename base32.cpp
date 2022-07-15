// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "base32.h"

#include <cctype>
#include <cstdint>
#include <stdexcept>

static const char* b32hex_map = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
static const size_t b32hex_map_sz = 32;

std::string base32hex_encode(const std::vector<uint8_t>& raw)
{
  std::string r;

  uint8_t a = 0;
  uint8_t bits_in_a = 0;

  for (size_t j = 0; j < raw.size(); j++)
  {
    for (size_t i = 0; i < 8; i++)
    {
      a = (a << 1) | ((raw[j] >> (7 - i)) & 0x01);
      bits_in_a++;
      if (bits_in_a == 5)
      {
        r.push_back(b32hex_map[a]);
        a = bits_in_a = 0;
      }
    }
  }

  if (bits_in_a)
  {
    a = a << (5 - bits_in_a);
    r.push_back(b32hex_map[a]);
  }

  return r;
}

std::vector<uint8_t> base32hex_decode(const std::string& b32)
{
  std::vector<uint8_t> r;
  uint16_t a = 0;
  size_t bits_in_a = 0;
  for (size_t i = 0; i < b32.size(); i++)
  {
    char c = std::toupper(b32[i]);
    size_t ci = 0;
    for (; ci < b32hex_map_sz; ci++)
      if (c == b32hex_map[ci])
        break;
    if (ci >= b32hex_map_sz)
      throw std::runtime_error("invalid base32 string");
    a = a << 5 | ci;
    bits_in_a += 5;
    if (bits_in_a >= 8)
    {
      r.push_back(a >> (bits_in_a - 8));
      bits_in_a -= 8;
    }
  }
  return r;
}
