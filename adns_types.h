// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "compression.h"
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
      auto d = ds::from_hex(data);
      attestation = ravl::parse_attestation_cbor({d.begin(), d.end()});
    }

    ATTEST(const small_vector<uint16_t>& data)
    {
      auto ud = decompress(data.raw(), data.size());
      attestation =
        ravl::parse_attestation_cbor({ud.data(), ud.data() + ud.size()});
    }

    virtual ~ATTEST() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> s = attestation->cbor();
      std::vector<uint8_t> cs = compress(s, 9);
      return small_vector<uint16_t>(cs.size(), (unsigned char*)cs.data());
    }

    virtual operator std::string() const override
    {
      return ds::to_hex(attestation->cbor());
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
