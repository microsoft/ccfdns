// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/ds/hex.h"
#include "rfc1035.h"
#include "serialization.h"
#include "small_vector.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace RFC6891 // https://datatracker.ietf.org/doc/html/rfc6891
{
  enum class Type : uint16_t
  {
    OPT = 41
  };

  inline std::map<Type, std::string> type_string_map = {{Type::OPT, "OPT"}};

  class OPT : public RFC1035::RDataFormat
  {
    struct Option
    {
      uint16_t code;
      small_vector<uint16_t> data;
    };

    std::vector<Option> options;

  public:
    OPT() = default;

    OPT(const std::string& s)
    {
      std::istringstream f(s);
      std::string tmp;
      while (std::getline(f, tmp, ' '))
      {
        auto eqpos = tmp.find('=');
        auto k = tmp.substr(0, eqpos);
        auto v = tmp.substr(eqpos + 1);
        auto code_int = stoi(k);
        if (code_int >= 1 << 16)
          throw std::runtime_error("OPT code too large");
        uint16_t code = code_int & 0xFFFF;
        options.push_back({.code = code, .data = small_vector<uint16_t>(v)});
      }
    }

    OPT(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      while (pos < data.size())
      {
        Option o;
        o.code = get<uint16_t>(data, pos);
        o.data = small_vector<uint16_t>(data, pos);
        options.push_back(o);
      }
    }

    virtual ~OPT() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      for (const auto& opt : options)
      {
        put(opt.code, r);
        opt.data.put(r);
      }
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      for (const auto& [k, v] : options)
      {
        if (r.size() > 0)
          r += " ";
        r += std::to_string(k) + "=" + ccf::ds::to_hex(v);
      }
      return r;
    }
  };

  struct TTL
  {
    uint8_t extended_rcode = 0;
    uint8_t version = 0;
    bool dnssec_ok = false;
    uint16_t z : 15;

    TTL(uint32_t ttl = 0)
    {
      extended_rcode = (ttl & 0xFF000000) >> 24;
      version = (ttl & 0x00FF0000) >> 16;
      dnssec_ok = (ttl & 0x00008000) != 0;
      z = ttl & 0x00007FFF;
    }

    operator uint32_t() const
    {
      uint32_t r = extended_rcode << 8 | version;
      r |= r << 16 | ((uint8_t)dnssec_ok) << 15 | z;
      return r;
    }

    operator std::string() const
    {
      std::string r;
      r += fmt::format(
        "extended-rcode={:02x} version={:02x} do={:b} z={:04x}",
        extended_rcode,
        version,
        dnssec_ok,
        z);
      return r;
    }
  };
}
