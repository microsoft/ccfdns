// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"

#include "adns_types.h"
#include "base32.h"
#include "formatting.h"
#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"
#include "rfc5155.h"
#include "rfc6891.h"
#include "rfc7671.h"
#include "small_vector.h"

#include <ccf/crypto/entropy.h>
#include <ccf/crypto/hash_bytes.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/md_type.h>
#include <ccf/crypto/san.h>
#include <ccf/crypto/sha256_hash.h>
#include <ccf/ds/logger.h>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <ravl/oe.h> // TODO: abstract details away
#include <ravl/openssl.hpp>
#include <ravl/ravl.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>

using namespace RFC1035;

namespace ravl
{
  HTTPResponse SynchronousHTTPClient::execute_synchronous(
    const HTTPRequest&, size_t, size_t, bool)
  {
    throw std::runtime_error("fresh endorsement download not supported");
  }
}

namespace aDNS
{
  static const std::map<uint16_t, Type> supported_types = {
    {static_cast<uint16_t>(RFC1035::Type::A), Type::A},
    {static_cast<uint16_t>(RFC1035::Type::NS), Type::NS},
    {static_cast<uint16_t>(RFC1035::Type::CNAME), Type::CNAME},
    {static_cast<uint16_t>(RFC1035::Type::SOA), Type::SOA},
    {static_cast<uint16_t>(RFC1035::Type::MX), Type::MX},
    {static_cast<uint16_t>(RFC1035::Type::TXT), Type::TXT},

    {static_cast<uint16_t>(RFC3596::Type::AAAA), Type::AAAA},

    {static_cast<uint16_t>(RFC4034::Type::DNSKEY), Type::DNSKEY},
    {static_cast<uint16_t>(RFC4034::Type::DS), Type::DS},
    {static_cast<uint16_t>(RFC4034::Type::RRSIG), Type::RRSIG},
    {static_cast<uint16_t>(RFC4034::Type::NSEC), Type::NSEC},

    {static_cast<uint16_t>(RFC6891::Type::OPT), Type::OPT},

    {static_cast<uint16_t>(RFC5155::Type::NSEC3), Type::NSEC3},
    {static_cast<uint16_t>(RFC5155::Type::NSEC3PARAM), Type::NSEC3PARAM},

    {static_cast<uint16_t>(RFC7671::Type::TLSA), Type::TLSA},

    // {static_cast<uint16_t>(aDNS::Types::Type::TLSKEY), Type::TLSKEY},
    {static_cast<uint16_t>(aDNS::Types::Type::ATTEST), Type::ATTEST},
  };

  static const std::map<uint16_t, QType> supported_qtypes = {
    {static_cast<uint16_t>(RFC1035::QType::ASTERISK), QType::ASTERISK},
  };

  static const std::map<uint16_t, Class> supported_classes = {
    {static_cast<uint16_t>(RFC1035::Class::IN), Class::IN}};

  static const std::map<uint16_t, QClass> supported_qclasses = {
    {static_cast<uint16_t>(RFC1035::QClass::ASTERISK), QClass::ASTERISK}};

  static const std::map<std::string, Class> string_to_class_map = {
    {"IN", Class::IN},
  };

  Type type_from_string(const std::string& type_string)
  {
#define TFSF(RFC) \
  { \
    for (const auto& [t, s] : RFC::type_string_map) \
    { \
      if (s == type_string) \
        return static_cast<Type>(t); \
    } \
  }

    TFSF(RFC1035);
    TFSF(RFC3596);
    TFSF(RFC4034);
    TFSF(RFC6891);
    TFSF(RFC5155);
    TFSF(RFC7671);
    TFSF(RFC8659);
    TFSF(aDNS::Types);

    throw std::runtime_error(
      fmt::format("unknown type string '{}'", type_string));
  }

  std::string string_from_type(const Type& t)
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
    SFTF(RFC5155);
    SFTF(RFC7671);
    SFTF(RFC8659);
    SFTF(aDNS::Types);

    // https://datatracker.ietf.org/doc/html/rfc3597#section-5
    return "TYPE" + std::to_string(static_cast<uint16_t>(t));
  };

  std::string string_from_qtype(const QType& t)
  {
    return t == QType::ASTERISK ? "*" : string_from_type(static_cast<Type>(t));
  }

  QType qtype_from_string(const std::string& s)
  {
    static const std::map<std::string, QType> smap = {
      {"*", QType::ASTERISK},
    };
    auto mit = smap.find(s);
    if (mit == smap.end())
      return static_cast<QType>(type_from_string(s));
    return mit->second;
  };

  Class class_from_string(const std::string& s)
  {
    static const std::map<std::string, Class> smap = {{"IN", Class::IN}};
    auto mit = smap.find(s);
    if (mit == smap.end())
      throw std::runtime_error("unknown class");
    return mit->second;
  }

  QClass qclass_from_string(const std::string& s)
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

  std::string string_from_qclass(const QClass& c)
  {
    return c == QClass::ASTERISK ? "*" :
                                   string_from_class(static_cast<Class>(c));
  }

  auto type2str = [](const auto& x) {
    return string_from_type(static_cast<Type>(x));
  };

  std::shared_ptr<RDataFormat> mk_rdata_format(
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

      case Type::NSEC3: return std::make_shared<RFC5155::NSEC3>(rdata, type2str); break;
      case Type::NSEC3PARAM: return std::make_shared<RFC5155::NSEC3PARAM>(rdata); break;

      case Type::OPT: return std::make_shared<RFC6891::OPT>(rdata); break;

      case Type::TLSA: return std::make_shared<RFC7671::TLSA>(rdata); break;

      case Type::CAA: return std::make_shared<RFC8659::CAA>(rdata); break;

      // case Type::TLSKEY: return std::make_shared<aDNS::Types::TLSKEY>(rdata); break;
      case Type::ATTEST: return std::make_shared<aDNS::Types::ATTEST>(rdata); break;

      default: throw std::runtime_error("unsupported rdata format");
    }
    // clang-format on
  }

  std::string string_from_resource_record(const ResourceRecord& rr)
  {
    std::string r = rr.name;

    if (rr.type == static_cast<uint16_t>(Type::OPT))
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
    r +=
      " " + (std::string)*mk_rdata_format(static_cast<Type>(rr.type), rr.rdata);
    return r;
  }

  static void convert_ec_signature_to_ieee_p1363(
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
    std::shared_ptr<crypto::KeyPair> signing_key)
  {
    RFC4034::SigningFunction r = [signing_key](
                                   RFC4034::Algorithm algorithm,
                                   const std::vector<uint8_t>& data_to_sign) {
      if (algorithm != RFC4034::Algorithm::ECDSAP384SHA384)
        throw std::runtime_error(
          fmt::format("algorithm {} not supported", algorithm));
      auto coords = signing_key->coordinates();
      // CCF_APP_TRACE(
      //   "ADNS: SIGN: key x/y {}{}", ds::to_hex(coords.x),
      //   ds::to_hex(coords.y));
      // CCF_APP_TRACE("SIGN: data={}", ds::to_hex(data_to_sign));
      auto sig = signing_key->sign(data_to_sign, crypto::MDType::SHA384);
      // CCF_APP_TRACE("ADNS: SIGN: sig={}", ds::to_hex(sig));
      convert_ec_signature_to_ieee_p1363(sig, signing_key);
      // CCF_APP_TRACE("ADNS: SIGN: r/s sig={}", ds::to_hex(sig));
      return sig;
    };
    return r;
  }

  Resolver::Resolver() : nsec3_salt(8)
  {
    auto e = crypto::create_entropy();
    e->random(&nsec3_salt[0], nsec3_salt.size());
  }

  Resolver::~Resolver() {}

  uint16_t get_key_tag(const RFC4034::DNSKEY& dnskey_rdata)
  {
    small_vector<uint16_t> bytes = dnskey_rdata;
    return RFC4034::keytag(&bytes[0], bytes.size());
  }

  Message Resolver::reply(const Message& msg)
  {
    try
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
          static_cast<aDNS::QType>(q.qtype),
          static_cast<aDNS::QClass>(q.qclass));

        r.header.rcode = resolution.response_code;

        r.questions.push_back(q);

        r.answers.insert(
          r.answers.end(),
          resolution.answers.begin(),
          resolution.answers.end());

        r.authorities.insert(
          r.authorities.end(),
          resolution.authorities.begin(),
          resolution.authorities.end());

        r.additionals.insert(
          r.additionals.end(),
          resolution.additionals.begin(),
          resolution.additionals.end());
      }

      for (const auto& rr : msg.additionals)
      {
        bool have_opt = false;
        if (rr.type == static_cast<uint16_t>(Type::OPT))
        {
          CCF_APP_TRACE("ADNS: EDNS(0): {}", string_from_resource_record(rr));
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
            static_cast<uint16_t>(Type::OPT),
            udp_payload_size,
            (uint32_t)ttl,
            {});
          CCF_APP_TRACE(
            "ADNS: EDNS(0) reply: {}", string_from_resource_record(opt_reply));
          r.additionals.push_back(opt_reply);
          have_opt = true;
        }
      }

      r.header.qdcount = r.questions.size();
      r.header.ancount = r.answers.size();
      r.header.nscount = r.authorities.size();
      r.header.arcount = r.additionals.size();

      r.header.aa = r.header.ancount > 0;

      return r;
    }
    catch (std::exception& ex)
    {
      CCF_APP_FAIL("ADNS: Exception: {}", ex.what());
    }
    catch (...)
    {
      CCF_APP_FAIL("ADNS: Unknown exception");
    }

    Message r;
    r.header.id = msg.header.id;
    r.header.qr = true;
    r.header.rcode = SERVER_FAILURE;
    return r;
  }

  RFC4034::CanonicalRRSet Resolver::find_records(
    const Name& origin,
    const Name& name,
    QType qtype,
    QClass qclass,
    std::optional<std::function<bool(const ResourceRecord&)>> condition)
  {
    CCF_APP_TRACE(
      "ADNS: Find: {} {} {} {}",
      origin,
      name,
      string_from_qtype(qtype),
      string_from_qclass(qclass));
    RFC4034::CanonicalRRSet records;
    for_each(
      origin,
      qclass,
      qtype,
      [this, &origin, &name, &qclass, &records, &condition](const auto& rr) {
        // CCF_APP_TRACE("ADNS:  - {}", string_from_resource_record(rr));
        if (rr.name == name && (!condition || (*condition)(rr)))
          records.insert(rr);
        return true;
      });
    return records;
  }

  Resolver::Resolution Resolver::resolve(
    const Name& qname, QType qtype, QClass qclass)
  {
    Resolution result;

    if (qtype == QType::ASTERISK || qclass == QClass::ASTERISK)
      return {ResponseCode::NOT_IMPLEMENTED, {}, {}, {}};

    if (!qname.is_absolute())
      throw std::runtime_error("cannot resolve relative names");

    // Find an origin
    Name origin;
    for (size_t i = 0; i < qname.labels.size(); i++)
    {
      Name po = Name(std::span(qname.labels).last(i + 1));
      if (origin_exists(po))
      {
        origin = po;
        break; // Keep walking down the tree?
      }
    }

    auto& result_set = result.answers;

    if (origin.is_absolute())
    {
      RFC4034::CanonicalRRSet records =
        find_records(origin, qname, qtype, qclass);

      if (records.size() > 0)
      {
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
      }

      if (result_set.empty())
      {
        auto configuration = get_configuration();

        if (configuration.use_nsec3)
        {
          auto name_hash = RFC5155::NSEC3::hash(
            origin, qname, configuration.nsec3_hash_iterations, nsec3_salt);
          std::string nameb32 =
            base32hex_encode(&name_hash[0], name_hash.size());
          assert(nameb32.size() <= 63);
          RFC1035::Name name(nameb32);
          const RFC1035::Name& suffix = qname;
          name += suffix;
          result.authorities +=
            find_records(origin, name, static_cast<QType>(Type::NSEC3), qclass);
        }
        else
          result.authorities +=
            find_records(origin, qname, static_cast<QType>(Type::NSEC), qclass);

        if (qtype != QType::SOA)
        {
          auto soa_records = find_records(origin, origin, QType::SOA, qclass);
          if (soa_records.size() > 0)
            result.authorities += *soa_records.begin();
        }

        if (!qname.is_root())
        {
          for (Name n = qname; n != origin && !n.is_root(); n = n.parent())
          {
            // Delegation records
            result.authorities +=
              find_records(origin, n, static_cast<QType>(Type::NS), qclass);

            // Glue records
            for (const auto& rr : result.authorities)
              if (rr.type == static_cast<uint16_t>(Type::NS))
              {
                result.additionals += find_records(
                  origin,
                  NS(rr.rdata).nsdname,
                  static_cast<QType>(Type::A),
                  qclass);
              }
          }
        }

        result.authorities += find_records(
          origin,
          qname,
          QType::RRSIG,
          qclass,
          [&cfg = configuration, &qtype](const auto& rr) {
            RFC4034::RRSIG rd(rr.rdata, type2str);
            return (!cfg.use_nsec3 &&
                    rd.type_covered == static_cast<uint16_t>(Type::NSEC)) ||
              (cfg.use_nsec3 &&
               rd.type_covered == static_cast<uint16_t>(Type::NSEC3)) ||
              (qtype != QType::SOA &&
               rd.type_covered == static_cast<uint16_t>(Type::SOA));
          });

        if (result.response_code == NO_ERROR && result.authorities.empty())
          result.response_code = NAME_ERROR; // NXDOMAIN
      }
    }

    CCF_APP_TRACE(
      "ADNS: Resolve: {} type {} class {}:{}",
      qname,
      string_from_qtype(static_cast<QType>(qtype)),
      string_from_qclass(static_cast<QClass>(qclass)),
      result_set.empty() ? " <nothing>" : "");
    for (const auto& rr : result_set)
      CCF_APP_TRACE("ADNS:  - {}", string_from_resource_record(rr));

    return result;
  }

  std::pair<RFC4034::CanonicalRRSet, Resolver::Names> Resolver::order_records(
    const Name& origin, QClass c) const
  {
    RFC4034::CanonicalRRSet r;
    Names names;

    for (const auto& [_, t] : supported_types)
    {
      if (t == Type::RRSIG)
        continue; // signatures are not signed but recreated

      std::vector<ResourceRecord> records;

      for_each(
        origin,
        c,
        static_cast<QType>(t),
        [&origin, &records, &names](const auto& rr) {
          // delegation points/glue entries are not signed
          // (https://datatracker.ietf.org/doc/html/rfc4035#section-2.2)
          if (rr.type != static_cast<uint16_t>(Type::NS) || rr.name == origin)
          {
            records.push_back(rr);
            names.insert(rr.name);
          }
          return true;
        });

      r += RFC4034::canonicalize(origin, records, type2str);
    }

    return std::make_pair(r, names);
  }

  Resolver::KeyAndTag Resolver::add_new_signing_key(
    const Name& origin, Class class_, bool key_signing)
  {
    const auto& configuration = get_configuration();

    std::shared_ptr<crypto::KeyPair> new_zsk;

    if (configuration.fixed_zsk)
      new_zsk = crypto::make_key_pair(*configuration.fixed_zsk);
    else
      new_zsk = crypto::make_key_pair();

    small_vector<uint16_t> new_zsk_pk = encode_public_key(new_zsk);

    RFC4034::DNSKEYRR dnskey_rr =
      add_dnskey(origin, class_, new_zsk_pk, key_signing);
    auto new_zsk_tag = get_key_tag(dnskey_rr.rdata);

    CCF_APP_DEBUG(
      "ADNS: NEW KEY for {}, class={}, tag={}:", origin, class_, new_zsk_tag);
    CCF_APP_DEBUG("ADNS: - {}", string_from_resource_record(dnskey_rr));
    CCF_APP_DEBUG("ADNS:   - xy={}", ds::to_hex(new_zsk_pk));

    if (
      origin_exists(origin.parent()) &&
      (!configuration.use_key_signing_key || key_signing))
      add_ds(origin, class_, new_zsk, new_zsk_tag, dnskey_rr.rdata);

    on_new_signing_key(
      origin,
      new_zsk_tag,
      new_zsk->private_key_pem(),
      configuration.use_key_signing_key && key_signing);

    return std::make_pair(new_zsk, new_zsk_tag);
  }

  Resolver::KeyAndTag Resolver::get_signing_key(
    const Name& origin, Class class_, bool key_signing)
  {
    const auto& configuration = get_configuration();

    bool find_ksk = configuration.use_key_signing_key && key_signing;

    RFC4034::CanonicalRRSet suitable_keys = find_records(
      origin,
      origin,
      QType::DNSKEY,
      static_cast<QClass>(class_),
      [&find_ksk](const auto& rr) {
        return find_ksk == RFC4034::DNSKEY(rr.rdata).is_key_signing_key();
      });

    if (suitable_keys.empty())
      return add_new_signing_key(origin, class_, key_signing);
    else
    {
      auto chosen_key = suitable_keys.begin(); // TODO: which key do we pick?

      RFC4034::DNSKEY dnskey(chosen_key->rdata);
      uint16_t key_tag = get_key_tag(dnskey);

      auto pem = get_private_key(origin, key_tag, dnskey.public_key, find_ksk);
      auto key = crypto::make_key_pair(pem);
      return std::make_pair(key, key_tag);
    }
  }

  RFC4034::DNSKEYRR Resolver::add_dnskey(
    const Name& origin,
    Class class_,
    const small_vector<uint16_t>& public_key,
    bool key_signing)
  {
    auto configuration = get_configuration();

    uint16_t flags = 0x0000;

    if (!configuration.use_key_signing_key || !key_signing)
      flags |= 0x0100;

    if (configuration.use_key_signing_key && key_signing)
      flags |= 0x0101;

    RFC4034::DNSKEYRR rr(
      origin,
      static_cast<RFC1035::Class>(class_),
      configuration.default_ttl,
      flags,
      configuration.signing_algorithm,
      public_key);

    add(origin, rr);

    return rr;
  }

  void Resolver::add_ds(
    const Name& origin,
    Class class_,
    std::shared_ptr<crypto::KeyPair> key,
    uint16_t tag,
    const small_vector<uint16_t>& dnskey_rdata)
  {
    if (origin.is_root())
      return;

    auto configuration = get_configuration();

    Name parent = origin.parent();
    auto ds_rrs = find_records(parent, origin, QType::DS, QClass::IN);

    if (!ds_rrs.empty())
      throw std::runtime_error("too many DS records");

    add(
      parent,
      RFC4034::DSRR(
        origin,
        static_cast<RFC1035::Class>(class_),
        configuration.default_ttl,
        tag,
        configuration.signing_algorithm,
        configuration.digest_type,
        dnskey_rdata));
  }

  ResourceRecord Resolver::add_nsec3(
    Class c,
    const Name& origin,
    uint32_t ttl,
    const small_vector<uint8_t>& name_hash,
    const small_vector<uint8_t>& next_hashed_owner_name,
    std::vector<RFC4034::CanonicalRRSet::iterator>& rrs)
  {
    assert(!rrs.empty());
    auto configuration = get_configuration();

    std::string nameb32 = base32hex_encode(&name_hash[0], name_hash.size());
    assert(nameb32.size() <= 63);
    RFC1035::Name name(nameb32);
    const RFC1035::Name& suffix = rrs.front()->name;
    name += suffix;

    uint8_t flags = 0;
    uint16_t iterations = 2;
    small_vector<uint8_t> salt;

    RFC5155::NSEC3 rdata(
      configuration.nsec3_hash_algorithm,
      flags,
      configuration.nsec3_hash_iterations,
      salt,
      next_hashed_owner_name,
      type2str);

    for (const auto& rec : rrs)
      rdata.type_bit_maps.insert(static_cast<uint16_t>(rec->type));

    rdata.type_bit_maps.insert(static_cast<uint16_t>(Type::RRSIG));
    rdata.type_bit_maps.insert(static_cast<uint16_t>(Type::NSEC3));

    ResourceRecord rr(
      name,
      static_cast<uint16_t>(Type::NSEC3),
      static_cast<uint16_t>(c),
      ttl,
      rdata);

    add(origin, rr);

    return rr;
  }

  void Resolver::sign(const Name& origin)
  {
    CCF_APP_DEBUG("ADNS: (Re)signing {}", origin);

    if (!origin.is_absolute())
      throw std::runtime_error("origin is not absolute");

    const auto& configuration = get_configuration();

    for (const auto& [_, c] : supported_classes)
    {
      // Note: the following may trigger addition of RRs
      auto ksk_and_tag = get_signing_key(origin, c, true);
      auto zsk_and_tag = get_signing_key(origin, c, false);

      if (!ksk_and_tag.first || !zsk_and_tag.first)
        throw std::runtime_error("missing signing key");

      auto soa_records =
        find_records(origin, origin, QType::SOA, static_cast<QClass>(c));

      if (soa_records.size() > 1)
        throw std::runtime_error("too many SOA records");

      bool is_authoritative = soa_records.size() == 1;

      auto [crecords, names] = order_records(origin, static_cast<QClass>(c));

      // CCF_APP_TRACE("ADNS: Records to sign at {}:", origin);
      // for (const auto& rr : crecords)
      //   CCF_APP_TRACE("ADNS:  {}", string_from_resource_record(rr));

      {
        // Remove existing RRSIGs and NSECs (could be avoided)
        for (const auto& name : names)
        {
          CCF_APP_DEBUG("ADNS: Remove {}", name);
          remove(origin, name, c, Type::RRSIG);
          remove(origin, name, c, Type::NSEC);
          remove(origin, c, Type::NSEC3);
          remove(origin, c, Type::NSEC3PARAM);
        }
      }

      // Add RRSIGs
      for (auto it = crecords.begin(); it != crecords.end();)
      {
        uint32_t ttl = it->ttl;
        const auto& name = it->name;
        const auto& type = it->type;
        const auto& class_ = it->class_;

        RFC4034::CanonicalRRSet::iterator next = std::next(it);
        while (next != crecords.end() && next->name == name &&
               next->type == type && next->class_ == class_)
        {
          if (next->ttl != ttl)
            CCF_APP_INFO(
              "ADNS: warning: TTL mismatch in record set for {}", name);
          next++;
        }

        // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
        auto tt = static_cast<Type>(type);
        if (
          tt == Type::RRSIG || (tt == Type::NS && name != origin) ||
          tt == Type::NSEC || tt == Type::NSEC3)
        {
          it = next;
          continue;
        }

        bool is_dnskey = tt == Type::DNSKEY;
        auto [key, key_tag] = is_dnskey ? ksk_and_tag : zsk_and_tag;

        RFC4034::CRRS crrs(name, class_, type, ttl);
        for (auto rit = it; rit != next; rit++)
          crrs.rdata.insert(rit->rdata);

        add(
          origin,
          RFC4034::RRSIGRR(
            make_signing_function(key),
            key_tag,
            configuration.signing_algorithm,
            origin,
            crrs,
            type2str));

        it = next;
      }

      uint32_t ttl = configuration.default_ttl;
      if (is_authoritative)
      {
        SOA soa_rdata(soa_records.begin()->rdata);
        ttl = soa_rdata.minimum;
      }

      if (configuration.use_nsec3)
      {
        // https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7

        HashedNamesMap hashed_names_map;
        while (!crecords.empty() && hashed_names_map.empty())
        {
          for (auto it = crecords.begin(); it != crecords.end();)
          {
            auto hashed_owner = RFC5155::NSEC3::hash(
              origin,
              it->name,
              configuration.nsec3_hash_iterations,
              nsec3_salt);

            if (hashed_names_map.find(hashed_owner) != hashed_names_map.end())
            {
              // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
              // hash collision, restart with new salt
              auto e = crypto::create_entropy();
              e->random(&nsec3_salt[0], nsec3_salt.size());
              hashed_names_map.clear();
              break;
            }

            std::vector<RFC4034::CanonicalRRSet::iterator> entries;
            auto next = it;
            for (; next != crecords.end() && next->name == it->name; next++)
              entries.push_back(next);

            hashed_names_map[hashed_owner] = entries;

            it = next;
          }
        }

        // for (auto it = hashed_names_map.begin(); it !=
        // hashed_names_map.end();
        //      it++)
        // {
        //   CCF_APP_TRACE("ADNS:  - {}: ", ds::to_hex(it->first));
        //   for (size_t i = 0; i < it->second.size(); i++)
        //   {
        //     CCF_APP_TRACE(
        //       "ADNS:    - {}",
        //       string_from_resource_record(*(it->second)[i]));
        //   }
        // }

        for (auto it = hashed_names_map.begin(); it != hashed_names_map.end();
             it++)
        {
          if (it->second.front()->type == static_cast<uint16_t>(Type::NSEC3))
            continue;

          auto next = std::next(it);

          auto first = *it->second.begin();
          const Name& owner = first->name;
          small_vector<uint8_t> next_hashed_owner_name =
            next != hashed_names_map.end() ? next->first :
                                             hashed_names_map.begin()->first;

          auto rr = add_nsec3(
            c, origin, ttl, it->first, next_hashed_owner_name, it->second);

          RFC4034::CRRS crrs(
            owner,
            static_cast<RFC1035::Class>(c),
            static_cast<uint16_t>(Type::NSEC3),
            ttl,
            rr.rdata);

          auto [key, key_tag] = zsk_and_tag;
          add(
            origin,
            RFC4034::RRSIGRR(
              make_signing_function(key),
              key_tag,
              configuration.signing_algorithm,
              origin,
              crrs,
              type2str));
        }

        if (is_authoritative)
        {
          add(
            origin,
            RFC5155::NSEC3PARAMRR(
              origin,
              static_cast<RFC1035::Class>(c),
              ttl,
              configuration.nsec3_hash_algorithm,
              0x00,
              configuration.nsec3_hash_iterations,
              nsec3_salt));
        }
      }
      else
      {
        auto next = std::next(crecords.begin());
        for (auto it = crecords.begin(); it != crecords.end();)
        {
          Name next_domain_name = next != crecords.end() ?
            next->name :
            (is_authoritative ? soa_records.begin()->name : origin);

          std::set<RFC4034::Type> types = {
            static_cast<RFC4034::Type>(it->type),
            RFC4034::Type::RRSIG,
            RFC4034::Type::NSEC};

          while (next != crecords.end() && next->name == it->name &&
                 next->class_ == it->class_)
          {
            types.insert(static_cast<RFC4034::Type>(next->type));
            next++;
          }

          RFC4034::NSECRR rr(
            it->name,
            static_cast<RFC1035::Class>(c),
            ttl,
            next_domain_name,
            types,
            type2str);
          add(origin, rr);

          RFC4034::CRRS crrs(
            it->name,
            static_cast<RFC1035::Class>(c),
            static_cast<uint16_t>(Type::NSEC),
            ttl,
            rr.rdata);

          auto [key, key_tag] = zsk_and_tag;
          add(
            origin,
            RFC4034::RRSIGRR(
              make_signing_function(key),
              key_tag,
              configuration.signing_algorithm,
              origin,
              crrs,
              type2str));

          it = next;
        }
      }
    }
  }

  std::shared_ptr<crypto::KeyPair> Resolver::get_tls_key()
  {
    // The CCF resolver uses the network key, but we could also use the zone or
    // key signing key.
    const auto& cfg = get_configuration();
    return get_signing_key(cfg.origin, Class::IN, true).first;
  }

  ResourceRecord Resolver::mk_rr(
    const Name& name,
    aDNS::Type type,
    aDNS::Class class_,
    uint32_t ttl,
    const small_vector<uint16_t>& rdata)
  {
    return ResourceRecord(
      name,
      static_cast<uint16_t>(type),
      static_cast<uint16_t>(class_),
      ttl,
      rdata);
  }

  Resolver::RegistrationInformation Resolver::configure(
    const Configuration& cfg)
  {
    using namespace RFC8659;

    set_configuration(cfg);

    if (cfg.node_addresses.empty())
      throw std::runtime_error("missing node information");

    if (cfg.contact.empty())
      throw std::runtime_error("at least one contact is required");

    auto tls_key = get_tls_key();

    RegistrationInformation out;

    out.public_key = tls_key->public_key_pem().str();
    out.node_information = get_node_information();

    for (const auto& [id, addr] : cfg.node_addresses)
    {
      if (!addr.name.ends_with(cfg.origin))
        throw std::runtime_error(fmt::format(
          "invalid node name; '{}' is outside the zone", addr.name));

      add(
        cfg.origin,
        mk_rr(cfg.origin, Type::NS, Class::IN, cfg.default_ttl, NS(addr.name)));

      add(
        cfg.origin,
        mk_rr(addr.name, Type::A, Class::IN, cfg.default_ttl, A(addr.ip)));

      add(cfg.origin, mk_rr(cfg.origin, Type::A, Class::IN, 1, A(addr.ip)));
    }

    add(
      cfg.origin,
      mk_rr(
        cfg.origin,
        aDNS::Type::CAA,
        Class::IN,
        60,
        CAA(0, "issue", cfg.service_ca.name)));

    for (const auto &email : cfg.contact)
      add(
        cfg.origin,
        mk_rr(
          cfg.origin,
          aDNS::Type::CAA,
          Class::IN,
          60,
          CAA(0, "iodef", "mailto:" + email)));

    sign(cfg.origin);

    std::string cn;
    std::vector<crypto::SubjectAltName> sans;

    cn = cfg.origin.unterminated();
    sans.push_back({cn, false});
    for (const auto& [id, addr] : cfg.node_addresses)
      sans.push_back({addr.name.unterminated(), false});

    if (cfg.alternative_names)
      for (const auto& san : *cfg.alternative_names)
        sans.push_back({san, false});

    out.csr =
      tls_key->create_csr_der("CN=" + cn, sans, tls_key->public_key_pem());

    auto dnskeys = resolve(cfg.origin, QType::DNSKEY, QClass::IN);

    if (dnskeys.answers.size() > 0)
    {
      out.dnskey_records = std::vector<ResourceRecord>();
      for (const auto& keyrr : dnskeys.answers)
        if (keyrr.type == static_cast<uint16_t>(aDNS::Type::DNSKEY))
          out.dnskey_records->push_back(keyrr);
    }

    return out;
  }

  void Resolver::add_fragmented(
    const Name& origin, const Name& name, const ResourceRecord& rr)
  {
    auto configuration = get_configuration();

    remove(origin, name, Class::IN, Type::AAAA);

    uint16_t rsz = rr.rdata.size();
    size_t num_rrs = rsz / 14;

    if ((rsz % 14) != 0)
      num_rrs++;

    small_vector<uint16_t> data(16);

    for (uint16_t i = 0; i < num_rrs; i++)
    {
      data[0] = i >> 8;
      data[1] = i & 0xFF;

      for (size_t j = 0; j < 14; j++)
      {
        auto inx = 14 * i + j;
        data[2 + j] = inx >= rsz ? 0 : rr.rdata[inx];
      }

      add(
        origin,
        mk_rr(
          name,
          Type::AAAA,
          Class::IN,
          configuration.default_ttl,
          RFC3596::AAAA(data)));
    }
  }

  Name Resolver::find_zone(const Name& name)
  {
    for (Name t = name.parent(); !t.is_root(); t = t.parent())
      if (origin_exists(t))
        return t;
    throw std::runtime_error(
      fmt::format("no suitable zone found for {}", name));
  }

  void Resolver::register_service(const RegistrationRequest& rr)
  {
    using namespace RFC7671;
    using namespace RFC8659;

    auto configuration = get_configuration();

    OpenSSL::UqX509_REQ req(rr.csr, false);
    auto public_key = req.get_pubkey();
    auto public_key_pem = public_key.pem_pubkey();

    auto subject_name = req.get_subject_name().get_common_name();
    Name service_name(subject_name);

    if (!service_name.is_absolute())
      service_name += std::vector<Label>{Label()};

    auto origin = find_zone(service_name);

    CCF_APP_INFO("ADNS: Register service {} in {}", service_name, origin);

    save_service_registration_request(rr);

    if (!req.verify(public_key))
      throw std::runtime_error("CSR signature validation failed");

    bool policy_ok = false;
    std::vector<std::shared_ptr<ravl::Claims>> claims;
#ifdef ATTESTATION_VERIFICATION_FAILURE_OK
    try
#endif
    {
      std::string policy_data = "var data = { claims: {";

      for (const auto& [id, info] : rr.node_information)
      {
        std::shared_ptr<ravl::Attestation> att =
          ravl::parse_attestation(info.attestation);
        auto c = ravl::verify_synchronous(att);
        if (!c)
          throw std::runtime_error(
            "attestation verification failed: no claims");
        claims.push_back(c);
        policy_data +=
          "\"" + (std::string)info.address.name + "\": " + c->to_json() + ",";
      }

      policy_data += "  }};";
      policy_ok = evaluate_service_registration_policy(policy_data);
    }
#ifdef ATTESTATION_VERIFICATION_FAILURE_OK
    catch (...)
    {
      policy_ok = true;
    }
#endif

    if (!policy_ok)
      throw std::runtime_error("service registration policy evaluation failed");

    // TODO: Check we're not overwriting existing registrations? Part of policy?

    uint16_t flags = 0x0000;
    auto pk_der = public_key.der_pubkey();
    small_vector<uint16_t> public_key_sv(pk_der.size(), pk_der.data());

    for (const auto& [id, info] : rr.node_information)
    {
      const auto& name = info.address.name.terminated();

      if (!name.ends_with(service_name))
        throw std::runtime_error(fmt::format(
          "node name '{}' outside of service sub-zone '{}'",
          name,
          service_name));

      // ATTEST RR
      ResourceRecord att_rr = mk_rr(
        name,
        Type::ATTEST,
        Class::IN,
        configuration.default_ttl,
        Types::ATTEST(info.attestation));

      remove(origin, name, Class::IN, Type::ATTEST);
      add(origin, att_rr);

      // Fragmented ATTEST RR
      remove(origin, Name("attest") + name, Class::IN, Type::ATTEST);
      add_fragmented(origin, Name("attest") + name, att_rr);

      add(
        origin,
        mk_rr(
          name,
          Type::A,
          Class::IN,
          configuration.default_ttl,
          RFC1035::A(info.address.ip)));

      // A records for the service name, one for each node.
      add(
        origin,
        mk_rr(
          service_name,
          Type::A,
          Class::IN,
          configuration.default_ttl,
          RFC1035::A(info.address.ip)));

      // TLSA RR for node
      std::string prolow = info.address.protocol;
      std::transform(prolow.begin(), prolow.end(), prolow.begin(), ::tolower);
      auto tlsa_name = Name("_" + std::to_string(info.address.port)) +
        Name(std::string("_") + prolow) + name;

      ResourceRecord tlsa_rr = mk_rr(
        tlsa_name,
        Type::TLSA,
        Class::IN,
        configuration.default_ttl,
        TLSA(
          CertificateUsage::DANE_EE,
          Selector::CERT,
          MatchingType::Full,
          public_key_sv));

      remove(origin, tlsa_name, Class::IN, Type::TLSA);
      add(origin, tlsa_rr);
    }

    auto it = rr.node_information.begin();
    std::string tlsa_prolow = it->second.address.protocol;
    uint16_t tlsa_port = it->second.address.port;
    for (it++; it != rr.node_information.end(); it++)
    {
      if (it->second.address.protocol != tlsa_prolow)
        throw std::runtime_error("node protocol mismatch");
      if (it->second.address.port != tlsa_port)
        throw std::runtime_error("node port mismatch");
    }

    // TLSA RR for service
    std::transform(
      tlsa_prolow.begin(), tlsa_prolow.end(), tlsa_prolow.begin(), ::tolower);
    auto tlsa_name = Name("_" + std::to_string(tlsa_port)) +
      Name(std::string("_") + tlsa_prolow) + service_name;
    remove(origin, service_name, Class::IN, Type::TLSA);
    add(
      origin,
      mk_rr(
        service_name,
        Type::TLSA,
        Class::IN,
        configuration.default_ttl,
        TLSA(
          CertificateUsage::DANE_EE,
          Selector::CERT,
          MatchingType::Full,
          public_key_sv)));

    // CAA RR
    remove(origin, service_name, Class::IN, Type::CAA);
    add(
      origin,
      mk_rr(
        service_name,
        aDNS::Type::CAA,
        Class::IN,
        configuration.default_ttl,
        CAA(0, "issue", configuration.service_ca.name)));

    for (const auto& contact : rr.contact)
      add(
        origin,
        mk_rr(
          service_name,
          aDNS::Type::CAA,
          Class::IN,
          configuration.default_ttl,
          CAA(0, "iodef", "mailto:" + contact)));

    sign(origin);

    start_service_acme(origin, service_name, rr.csr, rr.contact);
  }

  void Resolver::install_acme_response(
    const Name& origin,
    const Name& name,
    const std::vector<Name>& alternative_names,
    const std::string& key_authorization)
  {
    auto configuration = get_configuration();

    if (!origin_exists(origin))
      throw std::runtime_error("invalid origin");

    if (!name.ends_with(origin))
      throw std::runtime_error("name outside of zone");

    // Note: does not necessarily have to be installed on the same DNS server;
    // we can delegate the challenge to someone else, e.g. a non-DNSSEC
    // server.

    add(
      origin,
      mk_rr(
        Name("_acme-challenge") + name,
        Type::TXT,
        Class::IN,
        1,
        TXT(key_authorization)));

    for (const auto& n : alternative_names)
      if (n != name)
        add(
          origin,
          mk_rr(
            Name("_acme-challenge") + n,
            Type::TXT,
            Class::IN,
            1,
            TXT(key_authorization)));

    sign(origin);
  }

  void Resolver::remove_acme_response(const Name& origin, const Name& name)
  {
    if (!origin_exists(origin))
      throw std::runtime_error("invalid origin");

    if (!name.ends_with(origin))
      throw std::runtime_error("name outside of zone");

    remove(origin, Name("_acme-challenge") + name, Class::IN, Type::TXT);
  }

  void Resolver::register_delegation(const DelegationRequest& dr)
  {
    auto cfg = get_configuration();

    auto origin = find_zone(dr.subdomain);

    OpenSSL::UqX509_REQ req(dr.csr, false);
    auto public_key = req.get_pubkey();
    auto public_key_pem = public_key.pem_pubkey();

    auto subject_name = req.get_subject_name().get_common_name();
    Name name(subject_name);

    if (!name.is_absolute())
      name += std::vector<Label>{Label()};

    CCF_APP_INFO("ADNS: Register delegation {} in {}", name, origin);

    save_delegation_registration_request(dr);

    if (!name.ends_with(origin))
      throw std::runtime_error("name outside of origin");

    if (!req.verify(public_key))
      throw std::runtime_error("CSR signature validation failed");

    bool policy_ok = false;
    std::vector<std::shared_ptr<ravl::Claims>> claims;
#ifdef ATTESTATION_VERIFICATION_FAILURE_OK
    try
#endif
    {
      std::string policy_data = "var data = { claims: {";

      for (const auto& [id, info] : dr.node_information)
      {
        std::shared_ptr<ravl::Attestation> att =
          ravl::parse_attestation(info.attestation);
        auto c = ravl::verify_synchronous(att);
        if (!c)
          throw std::runtime_error(
            "attestation verification failed: no claims");
        claims.push_back(c);
        policy_data +=
          "\"" + (std::string)info.address.name + "\": " + c->to_json() + ",";
      }

      policy_data += "  }};";
      policy_ok = evaluate_delegation_registration_policy(policy_data);
    }
#ifdef ATTESTATION_VERIFICATION_FAILURE_OK
    catch (...)
    {
      policy_ok = true;
    }
#endif

    if (!policy_ok)
      throw std::runtime_error(
        "delegation registration policy evaluation failed");

    remove(origin, dr.subdomain, Class::IN, Type::NS);

    for (const auto& [id, info] : dr.node_information)
    {
      add(
        origin,
        mk_rr(
          dr.subdomain,
          Type::NS,
          Class::IN,
          cfg.default_ttl,
          NS(info.address.name)));
    }

    for (const auto& dnskey_rr : dr.dnskey_records)
      remove(origin, dnskey_rr.name, Class::IN, Type::DS);

    for (const auto& dnskey_rr : dr.dnskey_records)
    {
      if (!dnskey_rr.name.ends_with(origin))
        throw std::runtime_error("DNSKEY record name not within the zone");

      RFC4034::DNSKEY dnskey(dnskey_rr.rdata);
      auto key_tag = get_key_tag(dnskey);

      add(
        origin,
        RFC4034::DSRR(
          dnskey_rr.name,
          static_cast<RFC1035::Class>(dnskey_rr.class_),
          dnskey_rr.ttl,
          key_tag,
          dnskey.algorithm,
          cfg.digest_type,
          dnskey_rr.rdata));
    }

    sign(origin);

    // Glue records are not signed
    // (https://datatracker.ietf.org/doc/html/rfc4035#section-2.2)

    for (const auto& [id, info] : dr.node_information)
      remove(origin, info.address.name, Class::IN, Type::DS);

    for (const auto& [id, info] : dr.node_information)
    {
      add(
        origin,
        mk_rr(
          info.address.name,
          Type::A,
          Class::IN,
          cfg.default_ttl,
          RFC1035::A(info.address.ip)));
    }
  }
}
