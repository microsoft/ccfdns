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
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

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

    throw std::runtime_error(
      fmt::format("unknown type {}", std::to_string(static_cast<uint16_t>(t))));
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

  std::string string_from_class(const uint16_t& class_)
  {
    for (const auto& [name, c] : string_to_class_map)
    {
      if (static_cast<uint16_t>(c) == class_)
      {
        return name;
      }
    }

    throw std::runtime_error(
      fmt::format("unknown class '{}'", std::to_string((uint16_t)class_)));
  };

  std::shared_ptr<RDataFormat> rdata(
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
      case Type::RRSIG: return std::make_shared<RFC4034::RRSIG>(rdata); break;
      case Type::NSEC: return std::make_shared<RFC4034::NSEC>(rdata); break;

      case Type::OPT: return std::make_shared<RFC6891::OPT>(rdata); break;

      default: throw std::runtime_error("unsupported rdata format");
    }
    // clang-format on
  }

  static std::string string_from_resource_record(const ResourceRecord& rr)
  {
    std::string r = rr.owner;
    r += " " + string_from_class(rr.class_);
    r += " " + std::to_string(rr.ttl);
    r += " " + string_from_type(static_cast<Type>(rr.type));
    r += " " + (std::string)*rdata(static_cast<Type>(rr.type), rr.rdata);
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

    for (const auto& q : msg.questions)
    {
      auto a = resolve(
        q.qname,
        get_supported_qtype(static_cast<uint16_t>(q.qtype)),
        get_supported_qclass(static_cast<uint16_t>(q.qclass)));
      r.answers.insert(r.answers.end(), a.begin(), a.end());
      r.questions.push_back(q);
    }

    r.header.id = msg.header.id;
    r.header.qr = true;
    r.header.opcode = msg.header.opcode;
    r.header.aa = true;

    r.header.qdcount = r.questions.size();
    r.header.ancount = r.answers.size();
    r.header.nscount = r.authorities.size();
    r.header.arcount = r.additionals.size();

    return r;
  }

  std::vector<ResourceRecord> Resolver::resolve(
    const Name& qname, QType qtype, QClass qclass)
  {
    std::vector<ResourceRecord> rrs;

    LOG_TRACE_FMT("resolve: {}", (std::string)qname);

    if (
      !is_supported_qtype(static_cast<uint16_t>(qtype)) ||
      !is_supported_qclass(static_cast<uint16_t>(qclass)))
    {
      throw std::runtime_error("unsupported question type or class");
    }

    if (qtype == QType::ASTERISK || qclass == QClass::ASTERISK)
    {
      throw std::runtime_error("wildcard queries not implemented yet");
    }

    Name origin = qname;
    Name entry;
    bool done = false;
    for (size_t i = 0; i < qname.labels.size() && !done; i++)
    {
      LOG_DEBUG_FMT(
        "Looking for '{}' type '{}' in '{}'",
        (std::string)entry,
        string_from_qtype(static_cast<QType>(qtype)),
        (std::string)origin);

      for_each(origin, qclass, qtype, [&origin, &entry, &rrs](const auto& rr) {
        if (rr.owner == entry)
        {
          LOG_DEBUG_FMT("found match");
          rrs.push_back(rr);
          rrs.back().owner += origin;
        }
        return true;
      });

      if (rrs.size() > 0)
        break; // Continue collecting matches in longer origins?

      entry.labels.push_back(origin.labels.front());
      origin.labels.erase(origin.labels.begin());
    }

    return rrs;
  }

  static RFC4034::SigningFunction make_signing_function(
    std::shared_ptr<crypto::KeyPair> signing_key)
  {
    RFC4034::SigningFunction r = [signing_key](
                                   RFC4034::Algorithm algorithm,
                                   const std::vector<uint8_t>& data_to_sign) {
      if (algorithm != RFC4034::Algorithm::ECDSAP384SHA384)
        throw std::runtime_error(
          fmt::format("algorithm {} not supported", algorithm));
      return signing_key->sign(data_to_sign, crypto::MDType::SHA384);
    };
    return r;
  }

  void Resolver::sign(const Name& origin)
  {
    LOG_DEBUG_FMT("(Re)signing {}", (std::string)origin);

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

    std::vector<ResourceRecord> dnskey_rrs =
      resolve(origin, QType::DNSKEY, QClass::IN);

    if (dnskey_rrs.empty())
    {
      auto zspk = zone_signing_key->public_key_der();
      auto key_tag = RFC4034::keytag(zspk.data(), zspk.size());

      ResourceRecord dnskey_rr(
        origin,
        static_cast<uint16_t>(Type::DNSKEY),
        static_cast<uint16_t>(Class::IN),
        default_ttl,
        RFC4034::DNSKEY(
          0x0100,
          RFC4034::Algorithm::ECDSAP384SHA384,
          small_vector<uint16_t>(zspk.size(), zspk.data())));
      ignore_on_add = true;
      add(origin, dnskey_rr);
      dnskey_rrs.push_back(dnskey_rr);
    }

    if (dnskey_rrs.size() > 1)
      throw std::runtime_error("too many DNSKEY records");

    RFC4034::DNSKEY dnskey_rdata(dnskey_rrs[0].rdata);

    std::vector<ResourceRecord> ds_rrs = resolve(origin, QType::DS, QClass::IN);

    if (ds_rrs.empty())
    {
      auto hp = crypto::make_hash_provider();

      auto key_tag = RFC4034::keytag(
        &dnskey_rdata.public_key[0], dnskey_rdata.public_key.size());
      auto pk_digest = hp->Hash(
        &dnskey_rdata.public_key[0],
        dnskey_rdata.public_key.size(),
        crypto::MDType::SHA384);

      ResourceRecord ds_rr(
        origin,
        static_cast<uint16_t>(Type::DS),
        static_cast<uint16_t>(Class::IN),
        default_ttl,
        RFC4034::DS(
          key_tag,
          RFC4034::Algorithm::ECDSAP384SHA384,
          RFC4034::DigestType::SHA384,
          pk_digest));

      ignore_on_add = true;
      add(origin, ds_rr);
      ds_rrs.push_back(ds_rr);
    }

    if (ds_rrs.size() > 1)
      throw std::runtime_error("too many DS records");

    RFC4034::DS ds_rdata(ds_rrs[0].rdata);

    {
      // Check that we're using the right key
      auto zspk = zone_signing_key->public_key_der();
      auto key_tag = RFC4034::keytag(zspk.data(), zspk.size());
      if (ds_rdata.key_tag != key_tag)
        throw std::runtime_error("key tag mismatch");
      if (dnskey_rdata.public_key.size() != zspk.size())
        throw std::runtime_error("public key size mismatch");
      for (size_t i = 0; i < zspk.size(); i++)
        if (dnskey_rdata.public_key[i] != zspk[i])
          throw std::runtime_error("public key mismatch");
    }

    for (const auto& [_, c] : supported_classes)
    {
      for (const auto& [_, t] : supported_types)
      {
        if (
          t == Type::SOA || t == Type::DNSKEY || t == Type::RRSIG ||
          t == Type::NSEC || t == Type::DS)
          continue;

        std::vector<ResourceRecord> records;

        for_each(
          origin,
          static_cast<QClass>(c),
          static_cast<QType>(t),
          [&records](const auto& rr) {
            // Check: TTL must be the same for all in rrset?
            records.push_back(rr);
            return true;
          });

        LOG_DEBUG_FMT(
          "Sign {} {} {}: {} records",
          (std::string)origin,
          string_from_class(static_cast<uint16_t>(c)),
          string_from_type(t),
          records.size());

        auto rrsig_rdata = RFC4034::sign(
          make_signing_function(zone_signing_key),
          ds_rdata.key_tag,
          RFC4034::Algorithm::ECDSAP384SHA384,
          68400,
          origin,
          static_cast<uint16_t>(c),
          static_cast<uint16_t>(t),
          records);

        ignore_on_add = true;
        add(
          origin,
          ResourceRecord(
            origin,
            static_cast<uint16_t>(Type::RRSIG),
            static_cast<uint16_t>(c),
            default_ttl,
            rrsig_rdata));
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
