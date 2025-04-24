// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "small_vector.h"

#include <ccf/ds/hex.h>

// DNS Certification Authority Authorization (CAA) Resource Record
// https://datatracker.ietf.org/doc/html/rfc8659
namespace RFC8659
{
  enum class Type
  {
    CAA = 257
  };

  inline std::map<Type, std::string> type_string_map = {{Type::CAA, "CAA"}};

  inline bool is_alphanum_lower(char c)
  {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
  }

  class CAA : public RFC1035::RDataFormat
  {
  public:
    uint8_t flags;
    small_vector<uint8_t> tag;
    std::string value;

    CAA(uint8_t flags, const std::string& tag, const std::string& value) :
      flags(flags),
      tag(tag),
      value(value)
    {}

    CAA(const std::string& data)
    {
      std::stringstream s(data);
      uint8_t t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid flags in CAA rdata");

      char c = 0;
      while (s.peek() == ' ')
        s >> c;

      std::string tmp;
      for (s >> c; is_alphanum_lower(c) && !s.eof(); s >> c)
      {
        tmp += c;
        s >> c;
      }

      tag = small_vector<uint8_t>(tmp);
      if (tag.empty())
        throw std::runtime_error("empty tag in CAA rdata");

      s >> c;
      while (c == ' ')
        s >> c;
      for (; !s.eof(); s >> c)
        value += c;

      if (value.empty())
        throw std::runtime_error("empty value in CAA rdata");
    }

    CAA(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      flags = get<uint8_t>(data, pos);
      tag = small_vector<uint8_t>(data, pos);

      if (tag.empty())
        throw std::runtime_error("empty tag in CAA rdata");

      while (pos < data.size())
        value += data[pos++];

      if (value.empty())
        throw std::runtime_error("empty value in CAA rdata");
    }

    virtual ~CAA() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(flags, r);
      tag.put(r);
      for (const char c : value)
        put(static_cast<uint8_t>(c), r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r += " " + std::to_string(flags);
      r += " ";
      for (size_t i = 0; i < tag.size(); i++)
        r += tag[i];
      r += " \"" + value + "\"";
      return r;
    }
  };
}
