// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/ds/hex.h"
#include "rfc1035.h"
#include "serialization.h"

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

  class OPT : public RFC1035::RDataFormat
  {
    struct Option
    {
      uint16_t code;
      uint16_t length;
      std::vector<uint8_t> data;
    };

    std::vector<Option> options;

  public:
    OPT(const std::string& data)
    {
      // TODO
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      for (const auto& opt : options)
      {
        put(opt.code, r);
        put(opt.length, r);
        put(opt.data, r);
      }
      return r;
    }

    virtual operator std::string() const override
    {
      // TODO
      return "";
    }
  };
}
