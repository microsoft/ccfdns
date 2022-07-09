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
    OPT(const std::string& data)
    {
      // TODO
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
      // TODO
      return "";
    }
  };
}
