// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"

#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"
#include "rfc6891.h"
#include "small_vector.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/md_type.h>
#include <ccf/crypto/sha256_hash.h>
#include <ccf/ds/logger.h>
#include <ccf/kv/map.h>
#include <ccf/tx.h>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace RFC1035;

namespace aDNS
{
  static const std::map<uint16_t, aDNS::Type> supported_types = {
    {static_cast<uint16_t>(RFC1035::Type::A), aDNS::Type::A},
    {static_cast<uint16_t>(RFC1035::Type::NS), aDNS::Type::NS},
    {static_cast<uint16_t>(RFC1035::Type::CNAME), aDNS::Type::CNAME},
    {static_cast<uint16_t>(RFC1035::Type::SOA), aDNS::Type::SOA},
    {static_cast<uint16_t>(RFC1035::Type::MX), aDNS::Type::MX},
    {static_cast<uint16_t>(RFC1035::Type::TXT), aDNS::Type::TXT},

    {static_cast<uint16_t>(RFC3596::Type::AAAA), aDNS::Type::AAAA},

    {static_cast<uint16_t>(RFC4034::Type::DNSKEY), aDNS::Type::DNSKEY},
    {static_cast<uint16_t>(RFC4034::Type::DS), aDNS::Type::DS},
    {static_cast<uint16_t>(RFC4034::Type::RRSIG), aDNS::Type::RRSIG},
    {static_cast<uint16_t>(RFC4034::Type::NSEC), aDNS::Type::NSEC},

    {static_cast<uint16_t>(RFC6891::Type::OPT), aDNS::Type::OPT}};

  static const std::map<uint16_t, aDNS::QType> supported_qtypes = {
    {static_cast<uint16_t>(RFC1035::QType::ASTERISK), aDNS::QType::ASTERISK},
  };

  static const std::map<uint16_t, Class> supported_classes = {
    {static_cast<uint16_t>(RFC1035::Class::IN), Class::IN}};

  static const std::map<uint16_t, aDNS::QClass> supported_qclasses = {
    {static_cast<uint16_t>(RFC1035::QClass::ASTERISK), aDNS::QClass::ASTERISK}};

  static const std::map<std::string, aDNS::Class> string_to_class_map = {
    {"IN", aDNS::Class::IN},
  };

  static inline aDNS::Type get_supported_type(uint16_t t)
  {
    auto mit = supported_types.find(t);
    if (mit == supported_types.end())
      throw std::runtime_error(fmt::format("unsupported type {}", t));
    return mit->second;
  };

  static inline bool is_supported_type(uint16_t t)
  {
    return supported_types.find(t) != supported_types.end();
  }

  static inline aDNS::QType get_supported_qtype(uint16_t t)
  {
    auto mit = supported_qtypes.find(t);
    if (mit == supported_qtypes.end())
      return static_cast<aDNS::QType>(get_supported_type(t));
    return mit->second;
  };

  static inline bool is_supported_qtype(uint16_t t)
  {
    return supported_qtypes.find(t) != supported_qtypes.end() ||
      is_supported_type(t);
  }

  static inline Class get_supported_class(uint16_t t)
  {
    auto mit = supported_classes.find(t);
    if (mit == supported_classes.end())
      throw std::runtime_error("unsupported class");
    return mit->second;
  };

  static inline bool is_supported_class(uint16_t t)
  {
    return supported_classes.find(t) != supported_classes.end();
  }

  static inline aDNS::QClass get_supported_qclass(uint16_t t)
  {
    auto mit = supported_qclasses.find(t);
    if (mit == supported_qclasses.end())
      return static_cast<aDNS::QClass>(get_supported_class(t));
    return mit->second;
  };

  static inline bool is_supported_qclass(uint16_t t)
  {
    return supported_qclasses.find(t) != supported_qclasses.end() ||
      is_supported_class(t);
  }

  aDNS::Type type_from_string(const std::string& type_string)
  {
#define TFSF(RFC) \
  { \
    for (const auto& [t, s] : RFC::type_string_map) \
    { \
      if (s == type_string) \
        return static_cast<aDNS::Type>(t); \
    } \
  }

    TFSF(RFC1035);
    TFSF(RFC3596);
    TFSF(RFC4034);
    TFSF(RFC6891);

    throw std::runtime_error(
      fmt::format("unknown type string '{}'", type_string));
  }

  std::string string_from_type(const aDNS::Type& t)
  {
#define SFTF(RFC) \
  { \
    auto mit = RFC::type_string_map.find(static_cast<RFC::Type>(t)); \
    if (mit != RFC::type_string_map.end()) \
      return mit->second; \
  }

    SFTF(RFC1035);
    SFTF(RFC3596);
    SFTF(RFC4034);
    SFTF(RFC6891);

    // https://datatracker.ietf.org/doc/html/rfc3597#section-5
    return "TYPE" + std::to_string(static_cast<uint16_t>(t));
  };

  std::string string_from_qtype(const aDNS::QType& t)
  {
    return t == QType::ASTERISK ? "*" : string_from_type(static_cast<Type>(t));
  }

  aDNS::QType qtype_from_string(const std::string& s)
  {
    static const std::map<std::string, aDNS::QType> smap = {
      {"*", aDNS::QType::ASTERISK},
    };
    auto mit = smap.find(s);
    if (mit == smap.end())
      return static_cast<aDNS::QType>(type_from_string(s));
    return mit->second;
  };

  static inline Class class_from_string(const std::string& s)
  {
    static const std::map<std::string, Class> smap = {{"IN", Class::IN}};
    auto mit = smap.find(s);
    if (mit == smap.end())
      throw std::runtime_error("unknown class");
    return mit->second;
  }

  static inline QClass qclass_from_string(const std::string& s)
  {
    static const std::map<std::string, QClass> smap = {{"*", QClass::ASTERISK}};
    auto mit = smap.find(s);
    if (mit == smap.end())
      return static_cast<QClass>(class_from_string(s));
    return mit->second;
  }

  std::string string_from_class(const Class& class_)
  {
    for (const auto& [name, c] : string_to_class_map)
    {
      if (c == class_)
      {
        return name;
      }
    }

    // https://datatracker.ietf.org/doc/html/rfc3597#section-5
    return "CLASS" + std::to_string(static_cast<uint16_t>(class_));
  };

  std::string string_from_qclass(const aDNS::QClass& c)
  {
    return c == QClass::ASTERISK ? "*" :
                                   string_from_class(static_cast<Class>(c));
  }

  auto type2str = [](const auto& x) {
    return aDNS::string_from_type(static_cast<aDNS::Type>(x));
  };

  std::shared_ptr<RDataFormat> mk_rdata(
    Type t, const small_vector<uint16_t>& rdata)
  {
    // clang-format off
    switch (t)
    {
      case Type::A: return std::make_shared<RFC1035::A>(rdata); break;
      case Type::NS: return std::make_shared<RFC1035::NS>(rdata); break;
      case Type::CNAME: return std::make_shared<RFC1035::CNAME>(rdata); break;
      case Type::SOA: return std::make_shared<RFC1035::SOA>(rdata); break;
      case Type::MX: return std::make_shared<RFC1035::MX>(rdata); break;
      case Type::TXT: return std::make_shared<RFC1035::TXT>(rdata); break;

      case Type::AAAA: return std::make_shared<RFC3596::AAAA>(rdata); break;

      case Type::DNSKEY: return std::make_shared<RFC4034::DNSKEY>(rdata); break;
      case Type::DS: return std::make_shared<RFC4034::DS>(rdata); break;
      case Type::RRSIG: return std::make_shared<RFC4034::RRSIG>(rdata, type2str); break;
      case Type::NSEC: return std::make_shared<RFC4034::NSEC>(rdata, type2str); break;

      case Type::OPT: return std::make_shared<RFC6891::OPT>(rdata); break;

      default: throw std::runtime_error("unsupported rdata format");
    }
    // clang-format on
  }

  std::string string_from_resource_record(const ResourceRecord& rr)
  {
    std::string r = rr.name;

    if (rr.type == static_cast<uint16_t>(aDNS::Type::OPT))
    {
      // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
      r += " udp-payload-size=" + std::to_string(rr.class_);
      r += " " + (std::string)RFC6891::TTL(rr.ttl);
    }
    else
    {
      r += " " + string_from_class(static_cast<Class>(rr.class_));
      r += " " + std::to_string(rr.ttl);
    }
    r += " " + string_from_type(static_cast<Type>(rr.type));
    r += " " + (std::string)*mk_rdata(static_cast<Type>(rr.type), rr.rdata);
    return r;
  }

  Resolver::Resolver()
  {
    // TODO: install (public) key for root?
  }

  Resolver::~Resolver() {}

  Message Resolver::reply(const Message& msg)
  {
    Message r;

    r.header.id = msg.header.id;
    r.header.qr = true;
    r.header.opcode = msg.header.opcode;
    r.header.aa = true;
    r.header.tc = false;
    r.header.rd = false;
    r.header.ra = false;
    r.header.rcode = ResponseCode::NO_ERROR;

    for (const auto& q : msg.questions)
    {
      auto resolution = resolve(
        q.qname,
        get_supported_qtype(static_cast<uint16_t>(q.qtype)),
        get_supported_qclass(static_cast<uint16_t>(q.qclass)));

      r.header.rcode = resolution.response_code;

      r.questions.push_back(q);

      r.answers.insert(
        r.answers.end(), resolution.answers.begin(), resolution.answers.end());

      r.authorities.insert(
        r.authorities.end(),
        resolution.authorities.begin(),
        resolution.authorities.end());
    }

    for (const auto& rr : msg.additionals)
    {
      bool have_opt = false;
      if (rr.type == static_cast<uint16_t>(aDNS::Type::OPT))
      {
        LOG_DEBUG_FMT("EDNS(0): {}", string_from_resource_record(rr));
        if (have_opt)
        {
          // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.1
          r.header.rcode = ResponseCode::FORMAT;
          break;
        }

        RFC6891::TTL ttl(rr.ttl);
        ttl.version = 0;
        ttl.dnssec_ok = true;
        ttl.extended_rcode = 0;
        ttl.z = 0;

        uint16_t udp_payload_size = 4096;
        ResourceRecord opt_reply(
          Name("."),
          static_cast<uint16_t>(aDNS::Type::OPT),
          udp_payload_size,
          (uint32_t)ttl,
          {});
        LOG_DEBUG_FMT(
          "EDNS(0) OPT reply: {}", string_from_resource_record(opt_reply));
        r.additionals.push_back(opt_reply);
        have_opt = true;
      }
    }

    r.header.qdcount = r.questions.size();
    r.header.ancount = r.answers.size();
    r.header.nscount = r.authorities.size();
    r.header.arcount = r.additionals.size();

    return r;
  }

  RFC4034::CanonicalRRSet Resolver::find_records(
    const Name& origin, const Name& name, QType qtype, QClass qclass)
  {
    LOG_DEBUG_FMT("Find: {} {} {} {}", (std::string)origin, (std::string)name, string_from_qtype(qtype), string_from_qclass(qclass));
    RFC4034::CanonicalRRSet records;
    for_each(
      origin,
      qclass,
      qtype,
      [this, &origin, &name, &qclass, &records](const auto& rr) {
        LOG_DEBUG_FMT(" - {}", string_from_resource_record(rr));
        if (rr.name == name)
          records.insert(rr);
        return true;
      });
    return records;
  }

  Resolver::Resolution Resolver::resolve(
    const Name& qname, QType qtype, QClass qclass)
  {
    Resolution result;    

    if (
      !is_supported_qtype(static_cast<uint16_t>(qtype)) ||
      !is_supported_qclass(static_cast<uint16_t>(qclass)))
    {
      throw std::runtime_error("unsupported question type or class");
    }

    if (qtype == QType::ASTERISK || qclass == QClass::ASTERISK)
      return {ResponseCode::NOT_IMPLEMENTED, {}, {}};
    
    if (!qname.is_absolute())
      throw std::runtime_error("cannot resolve relative names");

    Name origin;
    for (size_t i = 1; i <= qname.labels.size(); i++)
    {
      origin = Name(std::span(qname.labels).last(i));

      RFC4034::CanonicalRRSet records =
        find_records(origin, qname, qtype, qclass);

      if (records.size() > 0)
      {
        auto& result_set =
          qtype == aDNS::QType::SOA ? result.authorities : result.answers;

        for (const auto& rr : records)
        {
          for_each(
            origin,
            static_cast<QClass>(rr.class_),
            QType::RRSIG,
            [&qname, &rrtype = rr.type, &result_set](const auto& rr) {
              if (rr.name == qname)
              {
                auto rdata = RFC4034::RRSIG(rr.rdata, type2str);
                if (rdata.type_covered == rrtype)
                  result_set.insert(rr);
              }
              return true;
            });
        }

        result_set += records;
        break; // Keep walking down the tree?
      }
    }

    if (result.answers.empty())
    {      
      result.authorities += find_records(origin, qname, QType::NSEC, qclass);
      
      if (qtype != QType::SOA)
      {
        auto soa_records = find_records(origin, origin, QType::SOA, qclass);
        if (soa_records.size() > 0)
          result.authorities += *soa_records.begin();
      }

      for (const auto& rr : find_records(origin, qname, QType::RRSIG, qclass))
      {
        RFC4034::RRSIG rd(rr.rdata, type2str);
        if (
          rd.type_covered == static_cast<uint16_t>(Type::NSEC) ||
          (qtype != aDNS::QType::SOA && rd.type_covered == static_cast<uint16_t>(Type::SOA)))
          result.authorities += rr;
      }

      if (result.response_code == NO_ERROR && result.authorities.empty()) {
        LOG_DEBUG_FMT("NXDOMAIN!");
        result.response_code = NAME_ERROR; // NXDOMAIN
      }
    }

    LOG_TRACE_FMT(
      "Resolve: {} type {} class {}:{}",
      (std::string)qname,
      string_from_qtype(static_cast<QType>(qtype)),
      string_from_qclass(static_cast<QClass>(qclass)),
      result.answers.empty() ? " <nothing>" : "");
    for (const auto& rr : result.answers)
      LOG_TRACE_FMT(" {}", string_from_resource_record(rr));

    return result;
  }

  static void convert_signature_to_ieee_p1363(
    std::vector<uint8_t>& sig,
    std::shared_ptr<const crypto::KeyPair> signing_key)
  {
    // Convert signature from ASN.1 format to IEEE P1363
    const unsigned char* pp = sig.data();
    ECDSA_SIG* sig_r_s = d2i_ECDSA_SIG(NULL, &pp, sig.size());
    const BIGNUM* r = ECDSA_SIG_get0_r(sig_r_s);
    const BIGNUM* s = ECDSA_SIG_get0_s(sig_r_s);
    int r_n = BN_num_bytes(r);
    int s_n = BN_num_bytes(s);
    size_t sz = signing_key->coordinates().x.size();
    assert(signing_key->coordinates().y.size() == sz);
    sig = std::vector<uint8_t>(2 * sz, 0);
    BN_bn2binpad(r, sig.data(), sz);
    BN_bn2binpad(s, sig.data() + sz, sz);
    ECDSA_SIG_free(sig_r_s);
  }

  static small_vector<uint16_t> encode_public_key(
    std::shared_ptr<const crypto::KeyPair> key)
  {
    auto coords = key->coordinates();
    small_vector<uint16_t> r(coords.x.size() + coords.y.size());
    for (size_t i = 0; i < coords.x.size(); i++)
      r[i] = coords.x[i];
    for (size_t i = 0; i < coords.y.size(); i++)
      r[coords.x.size() + i] = coords.y[i];
    return r;
  }

  static RFC4034::SigningFunction make_signing_function(
    std::shared_ptr<const crypto::KeyPair> signing_key)
  {
    RFC4034::SigningFunction r = [signing_key](
                                   RFC4034::Algorithm algorithm,
                                   const std::vector<uint8_t>& data_to_sign) {
      if (algorithm != RFC4034::Algorithm::ECDSAP384SHA384)
        throw std::runtime_error(
          fmt::format("algorithm {} not supported", algorithm));
      auto pem = signing_key->public_key_pem();
      LOG_DEBUG_FMT("SIGNING public key pem: {}", pem.str());
      auto xy_pk = encode_public_key(signing_key);
      LOG_DEBUG_FMT("SIGNING x/y public key: {}", ds::to_hex(xy_pk));
      LOG_DEBUG_FMT("SIGNING data={}", ds::to_hex(data_to_sign));
      auto sig = signing_key->sign(data_to_sign, crypto::MDType::SHA384);
      LOG_DEBUG_FMT("SIGNING sig={}", ds::to_hex(sig));
      convert_signature_to_ieee_p1363(sig, signing_key);
      LOG_DEBUG_FMT("SIGNING r/s sig={}", ds::to_hex(sig));
      return sig;
    };
    return r;
  }

  RFC4034::CanonicalRRSet Resolver::order_records(
    const Name& origin, QClass c) const
  {
    RFC4034::CanonicalRRSet r;

    for (const auto& [_, t] : supported_types)
    {
      std::vector<ResourceRecord> records;

      for_each(
        origin, c, static_cast<aDNS::QType>(t), [&records](const auto& rr) {          
          records.push_back(rr);
          return true;
        });

      r += RFC4034::canonicalize(origin, records, type2str);
    }

    return r;
  }

  void Resolver::sign(const Name& origin)
  {
    LOG_DEBUG_FMT("(Re)signing {}", (std::string)origin);

    assert(origin.is_absolute());

    auto kit = zone_signing_keys.find(origin);
    if (kit == zone_signing_keys.end())
    {
      auto [ekit, ok] =
        zone_signing_keys.emplace(origin, crypto::make_key_pair());
      if (!ok)
        throw std::runtime_error("error creating zone signing key");
      kit = ekit;
    }
    auto zone_signing_key = kit->second;

    auto dnskey_rrs = find_records(origin, origin, QType::DNSKEY, QClass::IN);

    if (dnskey_rrs.empty())
    {
      auto key_vec = encode_public_key(zone_signing_key);
      auto key_tag = RFC4034::keytag(&key_vec[0], key_vec.size());

      ResourceRecord dnskey_rr(
        origin,
        static_cast<uint16_t>(Type::DNSKEY),
        static_cast<uint16_t>(Class::IN),
        default_ttl,
        RFC4034::DNSKEY(0x0100, RFC4034::Algorithm::ECDSAP384SHA384, key_vec));

      LOG_DEBUG_FMT("NEW KEY: {}", string_from_resource_record(dnskey_rr));

      ignore_on_add = true;
      add(origin, dnskey_rr);
      dnskey_rrs += dnskey_rr;
    }

    if (dnskey_rrs.size() > 1)
      throw std::runtime_error("too many DNSKEY records");

    auto dnskey_rdata_raw = dnskey_rrs.begin()->rdata;
    RFC4034::DNSKEY dnskey_rdata(dnskey_rdata_raw);

    auto key_tag =
      RFC4034::keytag(&dnskey_rdata_raw[0], dnskey_rdata_raw.size());

    if (!origin.is_root())
    {
      Name parent = origin.parent();

      auto ds_rrs = find_records(parent, origin, QType::DS, QClass::IN);

      if (ds_rrs.empty())
      {
        auto hp = crypto::make_hash_provider();

        std::vector<uint8_t> t;
        origin.put(t);
        dnskey_rdata_raw.put(t);

        auto digest = hp->Hash(t.data(), t.size(), crypto::MDType::SHA384);

        ResourceRecord ds_rr(
          parent,
          static_cast<uint16_t>(Type::DS),
          static_cast<uint16_t>(Class::IN),
          default_ttl,
          RFC4034::DS(
            key_tag,
            RFC4034::Algorithm::ECDSAP384SHA384,
            RFC4034::DigestType::SHA384,
            digest));

        ignore_on_add = true;
        add(parent, ds_rr);
        ds_rrs += ds_rr;
      }

      if (ds_rrs.size() > 1)
        throw std::runtime_error("too many DS records");

      RFC4034::DS ds_rdata(ds_rrs.begin()->rdata);

      {
        // Check that we're using the right key
        if (ds_rdata.key_tag != key_tag)
          throw std::runtime_error("key tag mismatch");

        auto zspk = encode_public_key(zone_signing_key);
        if (dnskey_rdata.public_key.size() != zspk.size())
          throw std::runtime_error("public key size mismatch");
        for (size_t i = 0; i < zspk.size(); i++)
          if (dnskey_rdata.public_key[i] != zspk[i])
            throw std::runtime_error("public key mismatch");
      }
    }

    for (const auto& [_, c] : supported_classes)
    {
      auto soa_records =
        find_records(origin, origin, QType::SOA, static_cast<QClass>(c));

      if (soa_records.size() > 1)
        throw std::runtime_error("too many SOA records");

      bool is_authoritative = soa_records.size() == 1;

      RFC4034::CanonicalRRSet crecords =
        order_records(origin, static_cast<QClass>(c));

      LOG_DEBUG_FMT("Records to sign at {}:", (std::string)origin);
      for (const auto& rr : crecords)
        LOG_DEBUG_FMT(" {}", string_from_resource_record(rr));

      {
        // Remove existing RRSIGs and NSECs
        // Check: do we want deterministic signatures to avoid unnecessary
        // noise?
        std::set<Name, RFC4034::CanonicalNameOrdering> names;
        for (const auto& rr : crecords)
          names.insert(rr.name);

        for (const auto& name : names)
        {
          remove(origin, name, Type::RRSIG);
          remove(origin, name, Type::NSEC);
        }
      }

      for (auto it = crecords.begin(); it != crecords.end(); it++)
      {
        RFC4034::CanonicalRRSet n_crrset; // all records of name and type
        uint32_t ttl = it->ttl;

        for (auto nit = it; nit != crecords.end() && nit->name == it->name &&
             nit->type == it->type;
             nit++)
        {
          n_crrset += *nit;

          if (nit->ttl != ttl)
            LOG_INFO_FMT(
              "warning: TTL mismatch in record set for {}",
              (std::string)nit->name);
        }

        // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
        if (
          static_cast<Type>(it->type) == Type::RRSIG ||
          (static_cast<Type>(it->type) == Type::NS && it->name != origin))
          continue;

        auto rrsig_rdata = RFC4034::sign(
          make_signing_function(zone_signing_key),
          key_tag,
          RFC4034::Algorithm::ECDSAP384SHA384,
          ttl,
          origin,
          static_cast<uint16_t>(c),
          static_cast<uint16_t>(it->type),
          n_crrset,
          type2str);

        ignore_on_add = true;
        add(
          origin,
          ResourceRecord(
            it->name,
            static_cast<uint16_t>(Type::RRSIG),
            static_cast<uint16_t>(c),
            ttl,
            rrsig_rdata));
      }

      // https://datatracker.ietf.org/doc/html/rfc4034#section-4
      // the next owner name (in the canonical ordering of the zone) that
      // contains authoritative data or a delegation point NS RRset
      auto next = crecords.begin();

      for (auto it = crecords.begin(); it != crecords.end();)
      {
        bool is_delegation_point = false;
        while (next != crecords.end() &&
               (next->name == it->name ||
                (!is_authoritative && !is_delegation_point)))
        {
          next++;
          if (next != crecords.end())
          {
            auto nsrs = find_records(
              origin, next->name, QType::NS, static_cast<QClass>(c));
            is_delegation_point = !nsrs.empty();
          }
        }

        Name next_owner_name = next != crecords.end() ?
          next->name :
          (is_authoritative ? soa_records.begin()->name : origin);

        RFC4034::NSEC nsec_rdata(next_owner_name, type2str);

        for (auto nit = it; nit != crecords.end() && nit->name == it->name;
             nit++)
          nsec_rdata.type_bit_maps.insert(static_cast<uint16_t>(nit->type));

        uint32_t ttl = default_ttl;
        if (is_authoritative)
        {
          SOA soa_rdata(soa_records.begin()->rdata);
          ttl = soa_rdata.minimum;
        }

        ResourceRecord nsec(
          it->name,
          static_cast<uint16_t>(Type::NSEC),
          static_cast<uint16_t>(c),
          ttl,
          nsec_rdata);

        ignore_on_add = true;
        add(origin, nsec);

        it = next;
      }
    }
  }

  void Resolver::on_add(const Name& origin, const ResourceRecord& rr)
  {
    if (ignore_on_add)
    {
      ignore_on_add = false;
      return;
    }

    auto t = static_cast<Type>(rr.type);
    LOG_DEBUG_FMT(
      "{}: on_add: {}", (std::string)origin, string_from_resource_record(rr));
    switch (t)
    {
      case Type::A:
      case Type::NS:
      case Type::CNAME:
      case Type::SOA:
      case Type::MX:
      case Type::TXT:
      case Type::AAAA:
      case Type::RRSIG:
      case Type::NSEC:
      case Type::OPT:
        sign(origin);
        break;
      default:
      {
        LOG_DEBUG_FMT("Ignoring update to {} record", string_from_type(t));
        break;
      }
    }
  }
}
