// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "qvl.h"
#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/crypto/base64.h>
#include <ccf/ds/hex.h>

namespace aDNS::Types
{
  enum class Type : uint16_t
  {
    TLSKEY = 32770,
    ATTEST = 32771
  };

  inline std::map<Type, std::string> type_string_map = {
    {Type::ATTEST, "ATTEST"}, {Type::TLSKEY, "TLSKEY"}};

  class ATTEST : public RFC1035::RDataFormat
  {
  public:
    QVL::Attestation attestation;

    ATTEST(const QVL::Attestation& attestation) : attestation(attestation) {}

    ATTEST(const std::string& data)
    {
      std::stringstream s(data);
      uint8_t format;
      s >> format;
      attestation.format = static_cast<QVL::Format>(format);
      std::string t;
      s >> t;
      attestation.evidence = crypto::raw_from_b64(t);
      s >> t;
      attestation.endorsements = crypto::raw_from_b64(t);
    }

    ATTEST(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      attestation.format = static_cast<QVL::Format>(get<uint8_t>(data, pos));
      attestation.evidence = get<uint8_t, size_t>(data, pos);
      attestation.evidence = get<uint8_t, size_t>(data, pos);
    }

    virtual ~ATTEST() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(static_cast<uint8_t>(attestation.format), r);
      put(attestation.evidence, r);
      put(attestation.endorsements, r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      return std::to_string(static_cast<uint8_t>(attestation.format)) + " " +
        crypto::b64_from_raw(attestation.evidence) + " " +
        crypto::b64_from_raw(attestation.endorsements);
    }

    static QVL::Attestation generate_quote_info(
      const std::vector<uint8_t>& node_public_key_der);
  };

  class TLSKEY : public RFC4034::DNSKEY
  {
  public:
    using DNSKEY::DNSKEY;
    virtual ~TLSKEY() = default;

    using RFC4034::DNSKEY::operator small_vector<uint16_t>;
    using RFC4034::DNSKEY::operator std::string;
  };
}
