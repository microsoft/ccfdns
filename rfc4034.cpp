// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rfc4034.h"

#include "resolver.h"
#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc5155.h"

#include <cassert>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/ds/logger.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <set>
#include <stdexcept>
#include <tuple>
#include <vector>

using namespace RFC1035;

namespace RFC4034
{
  static void lower_and_expand(const Name& origin, Name& name)
  {
    if (!name.is_absolute())
      name += origin;
  }

  ResourceRecord canonicalize(
    const Name& origin,
    const ResourceRecord& rr,
    const std::function<std::string(const Type&)>& type2str)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.2

    ResourceRecord cr;
    cr.name = rr.name;
    lower_and_expand(origin, cr.name);
    cr.class_ = rr.class_;
    cr.type = rr.type;
    cr.ttl = rr.ttl;

    // if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, HINFO,
    // MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6,
    // RRSIG, or NSEC, all uppercase US-ASCII letters in the DNS names contained
    // within the RDATA are replaced by the corresponding lowercase US-ASCII
    // letters;

#define U(X) static_cast<uint16_t>(X)

    switch (cr.type)
    {
      case U(RFC1035::Type::NS):
      {
        auto rdata = NS(rr.rdata);
        lower_and_expand(origin, rdata.nsdname);
        cr.rdata = rdata;
        break;
      }
      case U(RFC1035::Type::CNAME):
      {
        auto rdata = CNAME(rr.rdata);
        rdata.cname.lower();
        cr.rdata = rdata;
        break;
      }
      case U(RFC1035::Type::SOA):
      {
        auto rdata = SOA(rr.rdata);
        lower_and_expand(origin, rdata.mname);
        lower_and_expand(origin, rdata.rname);
        cr.rdata = rdata;
        break;
      }
      case U(RFC1035::Type::MX):
      {
        auto rdata = MX(rr.rdata);
        lower_and_expand(origin, rdata.exchange);
        cr.rdata = rdata;
        break;
      }
      case U(RFC4034::Type::RRSIG):
      {
        auto rdata = RFC4034::RRSIG(rr.rdata, type2str);
        lower_and_expand(origin, rdata.signer_name);
        cr.rdata = rdata;
        break;
      }
      case U(RFC4034::Type::NSEC):
      {
        auto rdata = RFC4034::NSEC(rr.rdata, type2str);
        lower_and_expand(origin, rdata.next_domain_name);
        cr.rdata = rdata;
        break;
      }
      case U(RFC1035::Type::A):
      case U(RFC1035::Type::TXT):
      case U(RFC3596::Type::AAAA):
      case U(RFC4034::Type::DS):
      case U(RFC4034::Type::DNSKEY):
      case U(RFC5155::Type::NSEC3):
      case U(RFC5155::Type::NSEC3PARAM):
      case U(aDNS::Types::Type::ATTEST):
      case U(aDNS::Types::Type::TLSKEY):
        cr.rdata = rr.rdata;
        break;
      default:
        throw std::runtime_error(
          fmt::format("canonicalization for type {} not supported", cr.type));
    }
    return cr;
  }

  CanonicalRRSet canonicalize(
    const Name& origin,
    const std::vector<ResourceRecord>& records,
    const std::function<std::string(const Type&)>& type2str)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.3
    CanonicalRRSet r;
    for (const auto& rr : records)
      r += canonicalize(origin, rr, type2str);
    return r;
  }

  static std::vector<uint8_t> compute_rrset_signature(
    SigningFunction signing_function,
    uint16_t t,
    RFC4034::Algorithm algorithm,
    uint8_t num_labels,
    uint32_t original_ttl,
    uint32_t sig_expiration,
    uint32_t sig_inception,
    uint16_t keytag,
    const Name& signer_name,
    const CanonicalRRSet::iterator& begin,
    const CanonicalRRSet::iterator& end)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1

    std::vector<uint8_t> data_to_sign;
    put(static_cast<uint16_t>(t), data_to_sign);
    put(static_cast<uint8_t>(algorithm), data_to_sign);
    put(num_labels, data_to_sign);
    put(original_ttl, data_to_sign);
    put(sig_expiration, data_to_sign);
    put(sig_inception, data_to_sign);
    put(keytag, data_to_sign);
    signer_name.put(data_to_sign);

    for (auto it = begin; it != end; it++)
    {
      const auto& rr = *it;
      LOG_DEBUG_FMT(
        "ADNS: SIGN: record set: {}", aDNS::string_from_resource_record(rr));
      put(rr.name, data_to_sign);
      put(rr.type, data_to_sign);
      put(rr.class_, data_to_sign);
      put(original_ttl, data_to_sign);
      rr.rdata.put(data_to_sign);
    }

    return signing_function(algorithm, data_to_sign);
  }

  static uint8_t num_labels(const Name& name)
  {
    // https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.3
    auto n = name.labels.size();
    if (name.is_absolute())
      n--;
    for (const auto& l : name.labels)
      if (l.is_wildcard())
        n--;
    return n;
  }

  RFC4034::RRSIG sign(
    const SigningFunction& signing_function,
    uint16_t keytag,
    Algorithm algorithm,
    uint32_t original_ttl,
    const RFC1035::Name& signer,
    uint16_t class_,
    uint16_t type,
    const CanonicalRRSet::iterator& begin,
    const CanonicalRRSet::iterator& end,
    const std::function<std::string(const Type&)>& type2str)
  {
    assert(begin != end);

    const Name& owner = begin->name;

    assert(owner.is_absolute());
    assert(signer.is_absolute());

    uint8_t nl = num_labels(owner);

    auto now = std::chrono::system_clock::now();
    auto tp = now.time_since_epoch();
    uint32_t sig_inception = duration_cast<std::chrono::seconds>(tp).count();
    uint32_t sig_expiration =
      duration_cast<std::chrono::seconds>(tp + std::chrono::days(90)).count();

    std::vector<uint8_t> signature = compute_rrset_signature(
      signing_function,
      type,
      algorithm,
      nl,
      original_ttl,
      sig_expiration,
      sig_inception,
      keytag,
      signer,
      begin,
      end);

    return RRSIG(
      type,
      static_cast<uint8_t>(algorithm),
      nl,
      original_ttl,
      sig_expiration,
      sig_inception,
      keytag,
      signer,
      signature,
      type2str);
  }

  NSEC::TypeBitMaps::TypeBitMaps(
    const std::string& data,
    const std::function<Type(const std::string&)>& str2type,
    const std::function<std::string(const Type&)>& type2str) :
    type2str(type2str)
  {
    std::stringstream s(data);
    std::string t;
    while (s)
    {
      s >> t;
      insert(static_cast<uint16_t>(str2type(t)));
    }
  }

  NSEC::TypeBitMaps::TypeBitMaps(
    const small_vector<uint16_t>& data,
    size_t& pos,
    const std::function<std::string(const Type&)>& type2str) :
    type2str(type2str)
  {
    while (pos < data.size())
    {
      uint8_t wndw = get<uint8_t>(data, pos);
      auto bitmap = small_vector<uint8_t>(data, pos);
      windows.push_back({wndw, bitmap});
    }
  }

  NSEC::TypeBitMaps::operator small_vector<uint16_t>() const
  {
    std::vector<uint8_t> t;
    put(t);
    return small_vector<uint16_t>(t.size(), t.data());
  }

  NSEC::TypeBitMaps::operator std::string() const
  {
    bool first = true;
    std::string r;
    for (const auto& w : windows)
    {
      for (uint8_t i = 0; i < w.bitmap.size(); i++)
      {
        uint8_t bi = w.bitmap[i];
        uint8_t type_no = i << 3;
        while (bi != 0)
        {
          if (bi & 0x80)
          {
            if (first)
              first = false;
            else
              r += " ";
            Type t = static_cast<Type>(w.window_block_no << 8 | type_no);
            r += type2str(t);
          }
          bi <<= 1;
          type_no++;
        }
      }
    }
    return r;
  }

  void NSEC::TypeBitMaps::insert(uint16_t type)
  {
    uint8_t window = type >> 8;
    uint8_t lower = type & 0xFF;

    uint8_t window_index = 0;
    for (; window_index < windows.size(); window_index++)
    {
      if (windows[window_index].window_block_no == window)
      {
        break;
      }
    }
    if (window_index >= windows.size())
    {
      windows.push_back({window, {}});
      window_index = windows.size() - 1;
    }

    auto& entry = windows[window_index];
    uint8_t oct_inx = lower >> 3;
    if (entry.bitmap.size() <= oct_inx)
      entry.bitmap.resize(oct_inx + 1, 0);
    entry.bitmap[oct_inx] |= 0x80 >> (lower & 0x07);
  }

  void NSEC::TypeBitMaps::put(std::vector<uint8_t>& r) const
  {
    for (const auto& w : windows)
    {
      ::put(w.window_block_no, r);
      w.bitmap.put(r);
    }
  }

  static std::vector<uint8_t> der_from_coord(
    const uint8_t* x, const uint8_t* y, size_t csz)
  {
    BIGNUM* xbn = BN_new();
    BIGNUM* ybn = BN_new();
    BN_bin2bn(x, csz, xbn);
    BN_bin2bn(y, csz, ybn);
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT* p = EC_POINT_new(g);
    BN_CTX* bnctx = BN_CTX_new();
    if (EC_POINT_set_affine_coordinates(g, p, xbn, ybn, bnctx) != 1)
      throw std::runtime_error("could not set EC point coordinates");
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (EC_KEY_set_public_key(ec_key, p) != 1)
      throw std::runtime_error("could not create EC key");
    auto size = i2d_EC_PUBKEY(ec_key, NULL);
    std::vector<uint8_t> der(size, 0);
    unsigned char* derptr = (unsigned char*)&der[0];
    i2d_EC_PUBKEY(ec_key, &derptr);
    EC_KEY_free(ec_key);
    BN_CTX_free(bnctx);
    EC_POINT_free(p);
    EC_GROUP_free(g);
    BN_free(xbn);
    BN_free(ybn);
    return der;
  };

  static std::vector<uint8_t> der_from_coord(
    const small_vector<uint16_t>& coordinates)
  {
    auto csz = coordinates.size() / 2;
    const uint8_t* x = &coordinates[0];
    const uint8_t* y = &coordinates[csz];
    return der_from_coord(x, y, csz);
  };

  static void convert_signature_to_asn1(std::vector<uint8_t>& sig)
  {
    auto csz = sig.size() / 2;
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_bin2bn(sig.data(), csz, r);
    BN_bin2bn(sig.data() + csz, csz, s);
    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(ecdsa_sig, r, s);
    auto outsz = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    sig.resize(outsz, 0);
    unsigned char* outp = sig.data();
    i2d_ECDSA_SIG(ecdsa_sig, &outp);
  }

  bool verify_rrsigs(
    const RFC4034::CanonicalRRSet& rrset,
    const RFC4034::CanonicalRRSet& dnskey_rrset,
    const std::function<std::string(const Type&)>& type2str)
  {
    std::vector<std::tuple<crypto::PublicKeyPtr, uint16_t, bool>> pks;

    LOG_DEBUG_FMT("ADNS: VERIFY: Public keys:");
    for (const auto& rr : dnskey_rrset)
    {
      if (rr.type == static_cast<uint16_t>(Type::DNSKEY))
      {
        LOG_DEBUG_FMT("ADNS:  - {}", aDNS::string_from_resource_record(rr));
        RFC4034::DNSKEY rdata(rr.rdata);
        small_vector<uint16_t> rdata_bytes = rdata;
        auto tag = keytag(&rdata_bytes[0], rdata_bytes.size());
        LOG_DEBUG_FMT(
          "ADNS:    tag: {} x/y: {}", tag, ds::to_hex(rdata.public_key));
        auto pk = crypto::make_public_key(der_from_coord(rdata.public_key));
        pks.push_back(std::make_tuple(pk, tag, rdata.is_zone_key()));
      }
    }

    RFC4034::CanonicalRRSet rrs;
    RFC4034::CanonicalRRSet rrsigs;

    for (const auto& rr : rrset)
    {
      if (rr.type == static_cast<uint16_t>(Type::RRSIG))
        rrsigs.insert(rr);
      else
        rrs.insert(rr);
    }

    LOG_DEBUG_FMT("ADNS: VERIFY: record set:");
    for (const auto& rr : rrs)
      LOG_DEBUG_FMT("ADNS:  - {}", aDNS::string_from_resource_record(rr));

    if (rrs.empty())
      throw std::runtime_error("no records to verify");

    for (const auto& rrsig : rrsigs)
    {
      RFC4034::RRSIG rrsig_rdata(rrsig.rdata, type2str);

      if (!rrsig_rdata.signer_name.is_absolute())
        throw std::runtime_error("relative signer name");

      std::vector<uint8_t> data_to_sign = rrsig_rdata.all_but_signature();

      for (const auto& rr : rrs)
      {
        rr.name.put(data_to_sign);
        put(rr.type, data_to_sign);
        put(rr.class_, data_to_sign);
        put(rrsig_rdata.original_ttl, data_to_sign);
        rr.rdata.put(data_to_sign);
      }

      LOG_DEBUG_FMT("ADNS: VERIFY: data={}", ds::to_hex(data_to_sign));
      auto sig = rrsig_rdata.signature;
      LOG_DEBUG_FMT("ADNS: VERIFY: r/s sig={}", ds::to_hex(sig));
      convert_signature_to_asn1(sig);
      LOG_DEBUG_FMT("ADNS: VERIFY: sig={}", ds::to_hex(sig));

      LOG_DEBUG_FMT(
        "ADNS: VERIFY: try rrsig: {}",
        aDNS::string_from_resource_record(rrsig));

      for (const auto& [key, tag, zone_key] : pks)
      {
        LOG_DEBUG_FMT("ADNS: VERIFY: trying key with tag {}", tag);
        if (rrsig_rdata.key_tag == tag && key->verify(data_to_sign, sig))
        {
          return true;
        }
      }
    }

    // No signature matched
    return false;
  }

  DNSKEYRR::DNSKEYRR(
    const RFC1035::Name& owner,
    RFC1035::Class class_,
    uint32_t ttl,
    uint16_t flags,
    Algorithm algorithm,
    const small_vector<uint16_t>& public_key) :
    RFC1035::ResourceRecord(
      owner,
      static_cast<uint16_t>(Type::DNSKEY),
      static_cast<uint16_t>(class_),
      ttl,
      {}),
    rdata(flags, algorithm, public_key)
  {
    RFC1035::ResourceRecord::rdata = rdata;
  }

  RRSIGRR::RRSIGRR(
    const RFC1035::Name& owner,
    RFC1035::Class class_,
    uint32_t ttl,
    const SigningFunction& signing_function,
    uint16_t key_tag,
    Algorithm algorithm,
    uint32_t original_ttl,
    const RFC1035::Name& signer,
    uint16_t type_covered,
    const RFC4034::CanonicalRRSet::iterator& begin,
    const RFC4034::CanonicalRRSet::iterator& end,
    const std::function<std::string(const Type&)>& type2str) :
    RFC1035::ResourceRecord(owner, U(Type::RRSIG), U(class_), ttl, {}),
    rdata(RFC4034::sign(
      signing_function,
      key_tag,
      algorithm,
      original_ttl,
      signer,
      class_,
      type_covered,
      begin,
      end,
      type2str))
  {
    RFC1035::ResourceRecord::rdata = rdata;
  }

  DSRR::DSRR(
    const RFC1035::Name& owner,
    RFC1035::Class class_,
    uint32_t ttl,
    uint16_t tag,
    Algorithm algorithm,
    DigestType digest_type,
    const small_vector<uint16_t>& dnskey_rdata) :
    RFC1035::ResourceRecord(
      owner,
      static_cast<uint16_t>(Type::DS),
      static_cast<uint16_t>(class_),
      ttl,
      {}),
    rdata(tag, algorithm, digest_type, {})
  {
    std::vector<uint8_t> t;
    owner.put(t);
    put_n(dnskey_rdata, t, dnskey_rdata.size());

    if (digest_type != RFC4034::DigestType::SHA384)
      throw std::runtime_error("digest type not supported");

    auto hp = crypto::make_hash_provider();
    rdata.digest = hp->Hash(t.data(), t.size(), crypto::MDType::SHA384);

    RFC1035::ResourceRecord::rdata = rdata;
  }
}
