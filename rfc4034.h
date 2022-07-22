// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/crypto/base64.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/logger.h>
#include <cstdint>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto
{
  class KeyPair;
}

namespace RFC4034 // https://datatracker.ietf.org/doc/html/rfc4034
{
  enum class Type : uint16_t
  {
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
  };

  inline std::map<Type, std::string> type_string_map = {
    {Type::DNSKEY, "DNSKEY"},
    {Type::RRSIG, "RRSIG"},
    {Type::NSEC, "NSEC"},
    {Type::DS, "DS"}};

  // https://datatracker.ietf.org/doc/html/rfc4034#appendix-A.1
  // https://datatracker.ietf.org/doc/html/rfc6944
  /// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
  enum class Algorithm : uint8_t
  {
    DELETE = 0, // Not for zone signing.
    RSAMD5 = 1, // Must not implement.
    DH = 2, // Not for zone signing.
    DSA = 3,
    RESERVED1 = 4,
    RSASHA1 = 5, // Technically mandatory.
    DSA_NSEC3_SHA1 = 6,
    RSASHA1_NSEC3_SHA1 = 7,
    RSASHA256 = 8,
    RESERVED2 = 9,
    RSASHA512 = 10,
    RESERVED3 = 11,
    ECC_GOST = 12,
    ECDSAP256SHA256 = 13,
    ECDSAP384SHA384 = 14,
    ED25519 = 15,
    ED448 = 16,

    // 17-122 Unassigned
    // 123-251 Reserved

    INDIRECT = 252, // Not for zone signing.
    PRIVATE_DNS = 253,
    PRIVATE_OID = 254,
    RESERVED4 = 255,
  };

  static std::map<Algorithm, std::string> algorithm_mnemonic_map = {
    {Algorithm::DELETE, "DELETE"},
    {Algorithm::RSAMD5, "RSAMD5"},
    {Algorithm::DH, "DH"},
    {Algorithm::DSA, "DSA"},
    {Algorithm::RESERVED1, "RESERVED1"},
    {Algorithm::RSASHA1, "RSASHA1"},
    {Algorithm::DSA_NSEC3_SHA1, "DSA_NSEC3_SHA1"},
    {Algorithm::RSASHA1_NSEC3_SHA1, "RSASHA1_NSEC3_SHA1"},
    {Algorithm::RSASHA256, "RSASHA256"},
    {Algorithm::RESERVED2, "RESERVED2"},
    {Algorithm::RSASHA512, "RSASHA512"},
    {Algorithm::RESERVED3, "RESERVED3"},
    {Algorithm::ECC_GOST, "ECC_GOST"},
    {Algorithm::ECDSAP256SHA256, "ECDSAP256SHA256"},
    {Algorithm::ECDSAP384SHA384, "ECDSAP384SHA384"},
    {Algorithm::ED25519, "ED25519"},
    {Algorithm::ED448, "ED448"},
    {Algorithm::INDIRECT, "INDIRECT"},
    {Algorithm::PRIVATE_DNS, "PRIVATEDNS"},
    {Algorithm::PRIVATE_OID, "PRIVATEOID"},
  };

  inline std::string algorithm_mnemonic(Algorithm a)
  {
    auto mit = algorithm_mnemonic_map.find(a);
    if (mit == algorithm_mnemonic_map.end())
      throw std::runtime_error("unknown algorithm");
    return mit->second;
  }

  inline Algorithm algorithm_id(const std::string& mnemonic)
  {
    for (const auto& [id, m] : algorithm_mnemonic_map)
    {
      if (m == mnemonic)
        return id;
    }

    throw std::runtime_error("unknown algorithm mnemonic");
  }

  // https://datatracker.ietf.org/doc/html/rfc4034#appendix-A.2
  enum class DigestType : uint8_t
  {
    RESERVED = 0,
    SHA1 = 1,
    SHA256 = 2, // RFC 4509
    GOST_R = 3, // RFC 5933
    SHA384 = 4 // RFC 6605
  };

  typedef std::function<std::vector<uint8_t>(
    Algorithm, const std::vector<uint8_t>&)>
    SigningFunction;

  // https://datatracker.ietf.org/doc/html/rfc4034#section-6.1

  inline bool operator<(const RFC1035::Label& x, const RFC1035::Label& y)
  {
    size_t i = 0;
    do
    {
      if (i >= x.size() && i < y.size())
        return true;
      if (i >= y.size())
        return false;
      uint8_t lx = std::tolower(x[i]);
      uint8_t ly = std::tolower(y[i]);
      if (lx == ly)
        i++;
      else
        return lx < ly;
    } while (i < x.size() || i < y.size());

    return false;
  }

  inline bool operator<(const RFC1035::Name& x, const RFC1035::Name& y)
  {
    auto xit = x.labels.rbegin();
    auto yit = y.labels.rbegin();

    do
    {
      if (xit == x.labels.rend() && yit != y.labels.rend())
        return true;
      if (yit == y.labels.rend())
        return false;
      if (*xit == *yit)
      {
        xit++;
        yit++;
      }
      else
        return *xit < *yit;
    } while (xit != x.labels.rend() || yit != y.labels.rend());

    return false;
  }

  struct CanonicalNameOrdering
  {
    bool operator()(const RFC1035::Name& x, const RFC1035::Name& y) const
    {
      return operator<(x, y);
    }
  };

  inline bool operator<(
    const RFC1035::ResourceRecord& x, const RFC1035::ResourceRecord& y)
  {
    if (CanonicalNameOrdering()(x.name, y.name))
      return true;

    if (x.name != y.name)
      return false;

    if (x.class_ < y.class_)
      return true;
    else if (x.class_ > y.class_)
      return false;

    if (x.type < y.type)
      return true;
    else if (x.type > y.type)
      return false;

    for (size_t i = 0; i < x.rdata.size(); i++)
    {
      if (i >= y.rdata.size())
        return false;
      if (x.rdata[i] < y.rdata[i])
        return true;
      else if (x.rdata[i] > y.rdata[i])
        return false;
      else
        assert(x.rdata[i] == y.rdata[i]);
    }

    return false;
  }

  struct CanonicalRROrdering
  {
    bool operator()(
      const RFC1035::ResourceRecord& x, const RFC1035::ResourceRecord& y) const
    {
      return operator<(x, y);
    }
  };

  typedef std::set<RFC1035::ResourceRecord, RFC4034::CanonicalRROrdering>
    CanonicalRRSet;

  inline CanonicalRRSet& operator+=(CanonicalRRSet& x, CanonicalRRSet&& y)
  {
    x.merge(y);
    return x;
  }

  inline CanonicalRRSet& operator+=(CanonicalRRSet& x, CanonicalRRSet& y)
  {
    x.merge(y);
    return x;
  }

  inline CanonicalRRSet& operator+=(
    CanonicalRRSet& x, const RFC1035::ResourceRecord& rr)
  {
    x.insert(rr);
    return x;
  }

  inline CanonicalRRSet& operator+=(
    CanonicalRRSet& x, RFC1035::ResourceRecord&& rr)
  {
    x.insert(rr);
    return x;
  }

  class CRRS
  {
  public:
    CRRS(
      const RFC1035::Name& name, uint16_t class_, uint16_t type, uint32_t ttl) :
      name(name),
      class_(class_),
      type(type),
      ttl(ttl)
    {}

    CRRS(
      const RFC1035::Name& name,
      uint16_t class_,
      uint16_t type,
      uint32_t ttl,
      small_vector<uint16_t>&& rdata_) :
      name(name),
      class_(class_),
      type(type),
      ttl(ttl)
    {
      rdata.emplace(std::move(rdata_));
    }

    CRRS(
      const RFC1035::Name& name,
      uint16_t class_,
      uint16_t type,
      uint32_t ttl,
      const small_vector<uint16_t>& rdata_) :
      name(name),
      class_(class_),
      type(type),
      ttl(ttl)
    {
      rdata.insert(rdata_);
    }

    virtual ~CRRS() = default;

    RFC1035::Name name;
    uint16_t class_;
    uint16_t type;
    uint32_t ttl;
    std::set<small_vector<uint16_t>> rdata;

    // bool operator<(const CRRS& other) const
    // {
    //   if (name != other.name)
    //     return name < other.name;
    //   if (class_ != other.class_)
    //     return class_ < other.class_;
    //   if (type != other.type)
    //     return type < other.type;
    //   if (ttl != other.ttl)
    //     return ttl < other.ttl;
    //   for (size_t i = 0; i < rdata.size(); i++)
    //   {
    //     if (i >= other.rdata.size())
    //       return false;
    //     if (rdata[i] != other.rdata[i])
    //       return rdata[i] < other.rdata[i];
    //   }
    //   return true;
    // }
  };

  // https://datatracker.ietf.org/doc/html/rfc4034#section-2
  class DNSKEY : public RFC1035::RDataFormat
  {
  public:
    uint16_t flags;
    uint8_t protocol;
    Algorithm algorithm;
    small_vector<uint16_t> public_key;

    DNSKEY(const std::string& data)
    {
      std::stringstream s(data);
      uint64_t t;
      s >> flags;
      s >> t;
      if (t > 0xFF)
        throw std::runtime_error("invalid protocol in DNSKEY protocol");
      protocol = t;
      std::string ts;
      s >> ts;
      try
      {
        algorithm = static_cast<Algorithm>(std::stoi(ts));
      }
      catch (...)
      {
        algorithm = algorithm_id(ts);
      }
      std::string public_key_b64;
      s >> public_key_b64;
      public_key = small_vector<uint16_t>::from_base64(public_key_b64, false);
      enforce_invariants();
    }

    DNSKEY(const small_vector<uint16_t>& data)
    {
      if (data.size() < 5)
        throw std::runtime_error("DNSKEY rdata too short");
      flags = data[0] << 8 | data[1];
      protocol = data[2];
      algorithm = static_cast<Algorithm>(data[3]);
      public_key = small_vector<uint16_t>(data.size() - 4, &data[4]);
      enforce_invariants();
    }

    DNSKEY(
      uint16_t flags,
      Algorithm algorithm,
      const small_vector<uint16_t>& public_key) :
      flags(flags),
      protocol(3),
      algorithm(algorithm),
      public_key(public_key)
    {
      enforce_invariants();
    }

    virtual ~DNSKEY() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      small_vector<uint16_t> r(
        sizeof(flags) + sizeof(protocol) + sizeof(algorithm) +
        public_key.size());
      uint16_t pos = 0;
      r[pos++] = flags >> 8;
      r[pos++] = flags & 0x00FF;
      r[pos++] = protocol;
      r[pos++] = static_cast<uint8_t>(algorithm);
      for (uint16_t i = 0; i < public_key.size(); i++)
        r[pos++] = public_key[i];
      return r;
    }

    virtual operator std::string() const override
    {
      return std::to_string(flags) + " " + std::to_string(protocol) + " " +
        std::to_string(static_cast<uint8_t>(algorithm)) + " " +
        public_key.to_base64(false);
    }

    bool is_zone_key() const
    {
      return flags & 0x0100;
    }

    bool is_secure_entry_point() const
    {
      return flags & 0x0001;
    }

    bool is_key_signing_key() const
    {
      return (flags & 0x0101) == 0x0101;
    }

  protected:
    void enforce_invariants()
    {
      flags &= 0x0101; // ... must be ignored
      if (protocol != 3)
        throw std::runtime_error("invalid DNSKEY protocol");
    }
  };

  class DNSKEYRR : public RFC1035::ResourceRecord
  {
  public:
    DNSKEYRR(
      const RFC1035::Name& owner,
      RFC1035::Class class_,
      uint32_t ttl,
      uint16_t flags,
      Algorithm algorithm,
      const small_vector<uint16_t>& public_key);

    virtual ~DNSKEYRR() = default;

    DNSKEY rdata;
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

    std::function<std::string(const Type&)> type2str;

    RRSIG(
      const std::string& data,
      const std::function<Type(const std::string&)>& str2type,
      const std::function<std::string(const Type&)>& type2str) :
      type2str(type2str)
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

    RRSIG(
      const small_vector<uint16_t>& data,
      const std::function<std::string(const Type&)>& type2str) :
      type2str(type2str)
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
      signer_name = RFC1035::Name(data, pos);
      signature =
        std::vector<uint8_t>(&data[pos], &data[pos] + data.size() - pos);
    }

    RRSIG(
      uint16_t type_covered,
      uint8_t algorithm,
      uint8_t labels,
      uint32_t original_ttl,
      uint32_t signature_expiration,
      uint32_t signature_inception,
      uint16_t key_tag,
      const RFC1035::Name& signer_name,
      const std::vector<uint8_t>& signature,
      const std::function<std::string(const Type&)>& type2str) :
      type_covered(type_covered),
      algorithm(algorithm),
      labels(labels),
      original_ttl(original_ttl),
      signature_expiration(signature_expiration),
      signature_inception(signature_inception),
      key_tag(key_tag),
      signer_name(signer_name),
      signature(signature),
      type2str(type2str)
    {}

    virtual ~RRSIG() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r = all_but_signature();
      put_n(signature, r, signature.size());
      if (r.size() > 255)
        throw std::runtime_error("RRSIG rdata too large");
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r += type2str(static_cast<Type>(type_covered));
      r += " " + std::to_string(algorithm);
      r += " " + std::to_string(labels);
      r += " " + std::to_string(original_ttl);
      r += " " + std::to_string(signature_expiration);
      r += " " + std::to_string(signature_inception);
      r += " " + std::to_string(key_tag);
      r += " " + (std::string)signer_name;
      r += " " + crypto::b64_from_raw(signature);
      return r;
    }

    virtual std::vector<uint8_t> all_but_signature() const
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
      return r;
    }
  };

  class RRSIGRR : public RFC1035::ResourceRecord
  {
  public:
    RRSIGRR(
      const SigningFunction& signing_function,
      uint16_t key_tag,
      Algorithm algorithm,
      const RFC1035::Name& signer,
      const RFC4034::CRRS& crrs,
      const std::function<std::string(const Type&)>& type2str);

    virtual ~RRSIGRR() = default;

    RRSIG rdata;
  };

  class NSEC : public RFC1035::RDataFormat
  {
  public:
    class TypeBitMaps
    {
    public:
      struct Window
      {
        uint8_t window_block_no;
        small_vector<uint8_t> bitmap;
      };

      std::vector<Window> windows;
      std::function<std::string(const Type&)> type2str;

      TypeBitMaps(const std::function<std::string(const Type&)>& type2str) :
        type2str(type2str)
      {}

      TypeBitMaps(
        const std::string& data,
        const std::function<Type(const std::string&)>& str2type,
        const std::function<std::string(const Type&)>& type2str);

      TypeBitMaps(
        const small_vector<uint16_t>& data,
        size_t& pos,
        const std::function<std::string(const Type&)>& type2str);

      virtual ~TypeBitMaps() = default;

      virtual operator small_vector<uint16_t>() const;

      virtual operator std::string() const;

      void put(std::vector<uint8_t>& r) const;

      void insert(uint16_t type);
    };

    RFC1035::Name next_domain_name;
    TypeBitMaps type_bit_maps;

    NSEC(
      const RFC1035::Name& next_domain_name,
      const std::set<Type>& types,
      const std::function<std::string(const Type&)>& type2str) :
      next_domain_name(next_domain_name),
      type_bit_maps(type2str)
    {
      for (const auto& type : types)
        type_bit_maps.insert(static_cast<uint16_t>(type));
    }

    NSEC(
      const std::string& data,
      const std::function<Type(const std::string&)>& str2type,
      const std::function<std::string(const Type&)>& type2str) :
      type_bit_maps(type2str)
    {
      auto spos = data.find(" ");
      next_domain_name = RFC1035::Name(data.substr(0, spos));
      type_bit_maps = TypeBitMaps(data.substr(spos + 1), str2type, type2str);
    }

    NSEC(
      const small_vector<uint16_t>& data,
      const std::function<std::string(const Type&)>& type2str) :
      type_bit_maps(type2str)
    {
      size_t pos = 0;
      next_domain_name = RFC1035::Name(data, pos);
      type_bit_maps = TypeBitMaps(data, pos, type2str);
    }

    virtual ~NSEC() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      next_domain_name.put(r);
      type_bit_maps.put(r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r = next_domain_name;
      r += " " + (std::string)type_bit_maps;
      return r;
    }
  };

  class NSECRR : public RFC1035::ResourceRecord
  {
  public:
    NSECRR(
      const RFC1035::Name& owner,
      RFC1035::Class class_,
      uint32_t ttl,
      const RFC1035::Name& next_domain_name,
      const std::set<Type>& types,
      const std::function<std::string(const Type&)>& type2str);

    virtual ~NSECRR() = default;

    NSEC rdata;
  };

  class DS : public RFC1035::RDataFormat
  {
  public:
    uint16_t key_tag;
    Algorithm algorithm;
    DigestType digest_type;
    std::vector<uint8_t> digest;

    DS(
      uint16_t key_tag,
      Algorithm algorithm,
      DigestType digest_type,
      const std::vector<uint8_t>& digest) :
      key_tag(key_tag),
      algorithm(algorithm),
      digest_type(digest_type),
      digest(digest)
    {}

    DS(const std::string& data)
    {
      std::stringstream s(data);
      uint8_t tmp;
      s >> key_tag;
      s >> tmp;
      algorithm = static_cast<Algorithm>(tmp);
      s >> tmp;
      digest_type = static_cast<DigestType>(tmp);
      std::string t;
      s >> t;
      digest = ds::from_hex(t);
    }

    DS(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      key_tag = get<decltype(key_tag)>(data, pos);
      algorithm = static_cast<Algorithm>(get<uint8_t>(data, pos));
      digest_type = static_cast<DigestType>(get<uint8_t>(data, pos));
      digest.reserve(data.size() - pos);
      while (pos < data.size())
        digest.push_back(data[pos++]);
    }

    virtual ~DS() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(key_tag, r);
      put(static_cast<uint8_t>(algorithm), r);
      put(static_cast<uint8_t>(digest_type), r);
      put_n(digest, r, digest.size());
      if (r.size() > 65535)
        throw std::runtime_error("DS rdata size too large");
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      return std::to_string(key_tag) + " " +
        std::to_string(static_cast<uint8_t>(algorithm)) + " " +
        std::to_string(static_cast<uint8_t>(digest_type)) + " " +
        ds::to_hex(digest);
    }
  };

  class DSRR : public RFC1035::ResourceRecord
  {
  public:
    DSRR(
      const RFC1035::Name& owner,
      RFC1035::Class class_,
      uint32_t ttl,
      uint16_t tag,
      Algorithm algorithm,
      DigestType digest_type,
      const small_vector<uint16_t>& dnskey_rdata);

    ~DSRR() = default;

    DS rdata;
  };

  // Appendix B
  inline uint16_t keytag(
    const unsigned char dnskey_rdata[], uint16_t dnskey_rdata_size)
  {
    uint32_t ac;
    uint16_t i;

    for (ac = 0, i = 0; i < dnskey_rdata_size; ++i)
      ac += (i & 1) ? dnskey_rdata[i] : dnskey_rdata[i] << 8;

    ac += (ac >> 16) & 0xFFFF;

    return ac & 0xFFFF;
  }

  RFC1035::ResourceRecord canonicalize(
    const RFC1035::Name& origin,
    const RFC1035::ResourceRecord& rr,
    const std::function<std::string(const Type&)>& type2str);

  CanonicalRRSet canonicalize(
    const RFC1035::Name& origin,
    const std::vector<RFC1035::ResourceRecord>& records,
    const std::function<std::string(const Type&)>& type2str);

  RFC4034::RRSIG sign(
    const SigningFunction& signing_function,
    uint16_t keytag,
    Algorithm algorithm,
    uint32_t original_ttl,
    const RFC1035::Name& origin,
    uint16_t class_,
    uint16_t type_,
    const CanonicalRRSet& crrs_to_sign,
    const std::function<std::string(const Type&)>& type2str);

  bool verify_rrsigs(
    const RFC4034::CanonicalRRSet& rrset,
    const RFC4034::CanonicalRRSet& dnskey_rrset,
    const std::function<std::string(const Type&)>& type2str);
}
