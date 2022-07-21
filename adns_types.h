// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/ds/hex.h>
#include <ccf/quote_info.h>

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
    ccf::QuoteInfo quote_info;

    ATTEST(const ccf::QuoteInfo& quote_info) : quote_info(quote_info) {}

    ATTEST(const std::string& s)
    {
      auto sj = nlohmann::json::parse(s);
      quote_info = sj.get<ccf::QuoteInfo>();
    }

    ATTEST(const small_vector<uint16_t>& data)
    {
      auto j = nlohmann::json::parse(&data[0], &data[0] + data.size());
      quote_info = j.get<ccf::QuoteInfo>();
    }

    virtual ~ATTEST() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      nlohmann::json j = quote_info;
      auto sj = j.dump();
      if (sj.size() >= 65535)
        throw std::runtime_error("quote info too large for rdata");
      return sj;
    }

    virtual operator std::string() const override
    {
      nlohmann::json j = quote_info;
      return j.dump();
    }

    static ccf::QuoteInfo generate_quote_info(
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
