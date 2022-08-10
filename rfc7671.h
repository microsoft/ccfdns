// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "small_vector.h"

#include <ccf/ds/hex.h>

namespace RFC7671
// https://www.rfc-editor.org/rfc/rfc7671
// based on https://www.rfc-editor.org/rfc/rfc6698
{
  enum class Type
  {
    TLSA = 52
  };

  inline std::map<Type, std::string> type_string_map = {{Type::TLSA, "TLSA"}};

  class TLSA : public RFC1035::RDataFormat
  {
  public:
    uint8_t certificate_usage;
    uint8_t selector;
    uint8_t matching_type;
    std::vector<uint8_t> certificate_association_data;

    TLSA(const std::string& data)
    {
      std::stringstream s(data);
      uint8_t t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid certificate_usage in TLSA rdata");
      certificate_usage = t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid selector in TLSA rdata");
      selector = t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid matching_type in TLSA rdata");
      matching_type = t;
      std::string signature_b64;
      s >> signature_b64;
      certificate_association_data = crypto::raw_from_b64(signature_b64);
    }

    TLSA(const small_vector<uint16_t>& data)
    {
      if (data.size() < 8)
        throw std::runtime_error("DNSKEY rdata too short");
      size_t pos = 0;
      certificate_usage = get<decltype(certificate_usage)>(data, pos);
      selector = get<decltype(selector)>(data, pos);
      matching_type = get<decltype(matching_type)>(data, pos);
      certificate_association_data =
        std::vector<uint8_t>(&data[pos], &data[pos] + data.size() - pos);
    }

    virtual ~TLSA() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(certificate_usage, r);
      put(selector, r);
      put(matching_type, r);
      put_n(
        certificate_association_data, r, certificate_association_data.size());
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r += " " + std::to_string(certificate_usage);
      r += " " + std::to_string(selector);
      r += " " + std::to_string(matching_type);
      r += " " + ds::to_hex(certificate_association_data);
      return r;
    }
  };
}
