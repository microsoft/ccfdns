// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/crypto/base64.h>
#include <ravl/attestation.h>

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
    std::shared_ptr<ravl::Attestation> attestation;

    ATTEST(std::shared_ptr<ravl::Attestation>& attestation) :
      attestation(attestation)
    {}

    ATTEST(const std::string& data)
    {
      attestation = ravl::parse_attestation(data);
    }

    ATTEST(const small_vector<uint16_t>& data)
    {
      attestation =
        ravl::parse_attestation({data.raw(), data.raw() + data.size()});
    }

    virtual ~ATTEST() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::string s = *attestation;
      return small_vector<uint16_t>(s.size(), (unsigned char*)s.data());
    }

    virtual operator std::string() const override
    {
      return ds::to_hex((std::string)*attestation);
    }

    static ravl::Attestation generate_quote_info(
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
