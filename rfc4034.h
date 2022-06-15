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

namespace RFC4034 // https://datatracker.ietf.org/doc/html/rfc4034
{
  enum class Type : uint16_t
  {
    DNSKEY = 48,
    RRSIG = 46,
    NSEC = 47,
    DS = 43,
  };

  class DNSKEY : public RFC1035::RDataFormat
  {
  public:
    uint16_t flags;
    uint8_t protocol;
    uint8_t algorithm;
    std::vector<uint8_t> public_key;

    DNSKEY(const std::string& data)
    {
      std::stringstream s(data);
      unsigned t;
      s >> flags;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid protocol in DNSKEY rdata");
      protocol = t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid algorithm in DNSKEY rdata");
      algorithm = t;
      std::string public_key_b64;
      s >> public_key_b64;
      public_key = crypto::raw_from_b64(public_key_b64);
    }

    DNSKEY(const std::vector<uint8_t>& data)
    {
      if (data.size() < 5)
        throw std::runtime_error("DNSKEY rdata too short");
      flags = data[0] << 8 | data[1];
      protocol = data[2];
      algorithm = data[3];
      public_key = std::vector<uint8_t>(data.begin() + 4, data.end());
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      r.push_back(flags >> 8);
      r.push_back(flags & 0x00FF);
      r.push_back(protocol);
      r.push_back(algorithm);
      r.insert(r.end(), public_key.begin(), public_key.end());
      return r;
    }

    virtual operator std::string() const override
    {
      return std::to_string(flags) + " " + std::to_string(protocol) + " " +
        std::to_string(algorithm) + " " + crypto::b64_from_raw(public_key);
    }
  };

  class RRSIG : public RFC1035::RDataFormat
  {
  public:
    uint16_t type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t original_ttl;
    uint32_t signature_expiration;
    uint32_t signature_inception;
    uint16_t key_tag;
    RFC1035::Name signer_name;
    std::vector<uint8_t> signature;

    RRSIG(const std::string& data)
    {
      std::stringstream s(data);
      unsigned t;
      s >> type_covered;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid algorithm in DNSKEY rdata");
      algorithm = t;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid labels in DNSKEY rdata");
      labels = t;
      s >> original_ttl;
      s >> signature_expiration;
      s >> signature_inception;
      s >> key_tag;
      std::string signer_name_raw;
      s >> signer_name_raw;
      signer_name = RFC1035::Name(signer_name_raw);
      std::string signature_b64;
      s >> signature_b64;
      signature = crypto::raw_from_b64(signature_b64);
    }

    RRSIG(const std::vector<uint8_t>& data)
    {
      if (data.size() < 8)
        throw std::runtime_error("DNSKEY rdata too short");
      size_t pos = 0;
      type_covered = get<decltype(type_covered)>(data, pos);
      algorithm = get<decltype(algorithm)>(data, pos);
      labels = get<decltype(labels)>(data, pos);
      original_ttl = get<decltype(original_ttl)>(data, pos);
      signature_expiration = get<decltype(signature_expiration)>(data, pos);
      signature_inception = get<decltype(signature_inception)>(data, pos);
      key_tag = get<decltype(key_tag)>(data, pos);
      signer_name = RFC1035::Name(data, pos, labels);
      signature = get_n<uint8_t>(data, pos, data.size() - pos);
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      put(type_covered, r);
      put(algorithm, r);
      put(labels, r);
      put(original_ttl, r);
      put(signature_expiration, r);
      put(signature_inception, r);
      put(key_tag, r);
      put(signer_name, r);
      put(signature, r);
      return r;
    }

    virtual operator std::string() const override
    {
      return std::to_string(type_covered) + " " + std::to_string(algorithm) +
        " " + std::to_string(labels) + " " + std::to_string(original_ttl) +
        " " + std::to_string(signature_expiration) + " " +
        std::to_string(signature_inception) + " " + std::to_string(key_tag) +
        " " + (std::string)signer_name + " " + crypto::b64_from_raw(signature);
    }
  };

  class NSEC : public RFC1035::RDataFormat
  {
  public:
    struct TypeBitMap
    {
      uint8_t window_block_no;
      uint8_t bitmap_length;
      std::vector<uint8_t> bitmap;
    };
    RFC1035::Name next_domain_name;
    std::vector<TypeBitMap> type_bit_maps;

    NSEC(
      const std::string& data,
      const std::function<uint16_t(const std::string&)>& str2type)
    {
      std::stringstream s(data);
      std::string t;
      s >> t;
      next_domain_name = RFC1035::Name(t);
      std::vector<uint16_t> types;
      while (s)
      {
        s >> t;
        types.push_back(str2type(t));
      }
      std::sort(types.begin(), types.end());
      throw std::runtime_error("NIY");
    }

    NSEC(const std::vector<uint8_t>& data)
    {
      throw std::runtime_error("NIY");
    }

    virtual operator std::vector<uint8_t>() const override
    {
      throw std::runtime_error("NIY");
    }

    virtual operator std::string() const override
    {
      throw std::runtime_error("NIY");
    }
  };

  class DS : public RFC1035::RDataFormat
  {
  public:
    uint16_t key_tag;
    uint8_t algorithm;
    uint8_t digest_type;
    std::vector<uint8_t> digest;

    DS(const std::string& data)
    {
      std::stringstream s(data);
      s >> key_tag;
      s >> algorithm;
      s >> digest_type;
      std::string t;
      s >> t;
      digest = ds::from_hex(t);
    }

    DS(const std::vector<uint8_t>& data)
    {
      size_t pos = 0;
      key_tag = get<decltype(key_tag)>(data, pos);
      algorithm = get<decltype(algorithm)>(data, pos);
      digest_type = get<decltype(digest_type)>(data, pos);
      digest = {data.begin() + pos, data.end()};
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      put(key_tag, r);
      put(algorithm, r);
      put(digest_type, r);
      put(digest, r);
      return r;
    }

    virtual operator std::string() const override
    {
      return std::to_string(key_tag) + " " + std::to_string(algorithm) + " " +
        std::to_string(digest_type) + " " + ds::to_hex(digest);
    }
  };
}
