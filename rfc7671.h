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

  enum CertificateUsage : uint8_t
  {
    PKIX_TA = 0,
    PKIX_EE = 1,
    DANE_TA = 2,
    DANE__EE = 3,
    PRIV_CERT = 255
  };

  enum Selector : uint8_t
  {
    CERT = 0,
    SPKI = 1
  };

  enum MatchingType : uint8_t
  {
    Full = 0,
    SHA2_256 = 1,
    SHA2_512 = 2,
    PRIV_MATCH = 255
  };

  class TLSA : public RFC1035::RDataFormat
  {
  public:
    CertificateUsage certificate_usage;
    Selector selector;
    MatchingType matching_type;
    std::vector<uint8_t> certificate_association_data;

    TLSA(const std::string& data)
    {
      std::stringstream s(data);
      uint8_t t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid certificate_usage in TLSA rdata");
      certificate_usage = static_cast<CertificateUsage>(t);
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid selector in TLSA rdata");
      selector = static_cast<Selector>(t);
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid matching_type in TLSA rdata");
      matching_type = static_cast<MatchingType>(t);
      std::string signature_b64;
      s >> signature_b64;
      certificate_association_data = crypto::raw_from_b64(signature_b64);
    }

    TLSA(const small_vector<uint16_t>& data)
    {
      if (data.size() < 8)
        throw std::runtime_error("DNSKEY rdata too short");
      size_t pos = 0;
      certificate_usage =
        static_cast<CertificateUsage>(get<uint8_t>(data, pos));
      selector = static_cast<Selector>(get<uint8_t>(data, pos));
      matching_type = static_cast<MatchingType>(get<uint8_t>(data, pos));
      certificate_association_data =
        std::vector<uint8_t>(&data[pos], &data[pos] + data.size() - pos);
    }

    virtual ~TLSA() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(static_cast<uint8_t>(certificate_usage), r);
      put(static_cast<uint8_t>(selector), r);
      put(static_cast<uint8_t>(matching_type), r);
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
