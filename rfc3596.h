// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"

namespace RFC3596 // https://www.rfc-editor.org/rfc/rfc3596.html
{
  enum class Type
  {
    AAAA = 28
  };

  inline std::map<Type, std::string> type_string_map = {{Type::AAAA, "AAAA"}};

  class AAAA : public RFC1035::RDataFormat
  {
  public:
    std::array<uint16_t, 8> address;

    AAAA(const std::string& data)
    {
      // Data format RFC 3513: https://www.rfc-editor.org/rfc/rfc3513.html
      std::vector<std::string> tokens;
      std::istringstream f(data);
      std::string tmp;
      size_t total_size = 0;
      int i = 0;
      while (std::getline(f, tmp, ':'))
      {
        auto st = std::stoi(tmp, 0, 16);
        if (st > 0xFFFF)
          throw std::runtime_error("invalid IPv6 address");
        address[i++] = st;
        if (i > 8)
          throw std::runtime_error("excess tokens in IPv6 address");
      }
    }

    AAAA(const small_vector<uint16_t>& data)
    {
      if (data.size() != 16)
        throw std::runtime_error("invalid rdata for AAAA record");
      for (size_t i = 0; i < address.size(); i++)
        address[i] = data[i];
    }

    virtual ~AAAA() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      small_vector<uint16_t> r(2 * address.size());
      for (size_t i = 0; i < address.size(); i++)
      {
        auto& n = address[i];
        r[2 * i] = n >> 8;
        r[2 * i + 1] = n & 0xFF;
      }
      return r;
    }

    virtual operator std::string() const override
    {
      std::string r = std::to_string(address[0]);
      for (size_t i = 1; i < 8; i++)
        r += ":" + std::to_string(address[i]);
      return r;
    }
  };
}
