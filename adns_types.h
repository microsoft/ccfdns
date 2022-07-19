// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/ds/hex.h>

namespace aDNSTypes
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
    small_vector<uint16_t> evidence;

    ATTEST(const std::string& s)
    {
      evidence = small_vector<uint16_t>::from_hex(s);
    }

    ATTEST(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      evidence = small_vector<uint16_t>(data, pos);
    }

    virtual ~ATTEST() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      evidence.put(r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      return ds::to_hex(evidence);
    }
  };

  class TLSKEY : public RFC4034::DNSKEY
  {
  public:
    TLSKEY(const std::string& data) : RFC4034::DNSKEY(data) {}
    TLSKEY(const small_vector<uint16_t>& data) : RFC4034::DNSKEY(data) {}
    virtual ~TLSKEY() = default;

    using RFC4034::DNSKEY::operator small_vector<uint16_t>;
    using RFC4034::DNSKEY::operator std::string;
  };
}
