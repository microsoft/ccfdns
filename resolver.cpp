// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"

#include "adns_types.h"
#include "base32.h"
#include "compression.h"
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
#include <mutex>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <ravl/json.h>
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

    {static_cast<uint16_t>(RFC8659::Type::CAA), Type::CAA},

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

  Resolver::Resolver() {}

  Resolver::~Resolver() {}

  uint16_t get_key_tag(const RFC4034::DNSKEY& dnskey_rdata)
  {
    small_vector<uint16_t> bytes = dnskey_rdata;
    return RFC4034::keytag(&bytes[0], bytes.size());
  }

  Resolver::Reply Resolver::reply(const Message& msg)
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

        r.header.aa &= resolution.is_authoritative;
      }

      size_t peer_udp_payload_size = 0;

      bool have_client_opt = false;
      for (const auto& rr : msg.additionals)
      {
        if (rr.type == static_cast<uint16_t>(Type::OPT))
        {
          CCF_APP_TRACE("ADNS: EDNS(0): {}", string_from_resource_record(rr));

          if (have_client_opt)
          {
            // More than one OPT record is a format violation
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
          have_client_opt = true;
        }
      }

      r.header.qdcount = r.questions.size();
      r.header.ancount = r.answers.size();
      r.header.nscount = r.authorities.size();
      r.header.arcount = r.additionals.size();

      return {r, peer_udp_payload_size};
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
    return {r, 0};
  }

  RFC4034::CanonicalRRSet Resolver::find_records(
    const Name& origin,
    const Name& qname,
    QType qtype,
    QClass qclass,
    std::optional<std::function<bool(const ResourceRecord&)>> condition)
  {
    CCF_APP_TRACE(
      "ADNS: Find: {} {} {} {}",
      origin,
      qname,
      string_from_qtype(qtype),
      string_from_qclass(qclass));
    RFC4034::CanonicalRRSet records;
    for_each(
      origin,
      qname,
      qclass,
      qtype,
      [this, &origin, &records, &condition](const auto& rr) {
        // CCF_APP_TRACE("ADNS:  - {}", string_from_resource_record(rr));
        if ((!condition || (*condition)(rr)))
          records.insert(rr);
        return true;
      });
    return records;
  }

  RFC4034::CanonicalRRSet Resolver::find_rrsigs(
    const Name& origin, const Name& name, QClass qclass, Type type_covered)
  {
    return find_records(
      origin,
      name,
      static_cast<QType>(Type::RRSIG),
      qclass,
      [type_covered](const auto& rr) {
        RFC4034::RRSIG rd(rr.rdata, type2str);
        return rd.type_covered == static_cast<uint16_t>(type_covered);
      });
  }

  RFC1035::ResponseCode Resolver::find_nsec3_records(
    const Name& origin,
    QClass qclass,
    const Name& qname,
    RFC4034::CanonicalRRSet& r)
  {
    auto configuration = get_configuration();

    auto nsec3params = find_records(origin, origin, QType::NSEC3PARAM, qclass);
    if (nsec3params.empty())
      return RFC1035::SERVER_FAILURE;

    RFC5155::NSEC3PARAM p(nsec3params.begin()->rdata);
    auto name_hash = RFC5155::NSEC3::hash(
      origin, qname, configuration.nsec3_hash_iterations, p.salt);
    std::string nameb32 = base32hex_encode(&name_hash[0], name_hash.size());
    assert(nameb32.size() <= 63);
    RFC1035::Name name(nameb32);
    const RFC1035::Name& suffix = qname;
    name += suffix;
    name.lower();

    auto nsec3 = find_records(origin, name, QType::NSEC3, qclass);

    if (!nsec3.empty())
    {
      CCF_APP_DEBUG("ADNS: Found NSEC3: {}", name);
      r += nsec3;
      r += find_rrsigs(origin, name, qclass, Type::NSEC3);
      return RFC1035::NO_ERROR;
    }

    // TODO: This is wrong. We need to find the closest encloser. See
    // https://www.rfc-editor.org/rfc/rfc5155#section-7.2.1

    const auto& ns = get_ordered_names(origin, static_cast<Class>(qclass));

    auto preceding = find_preceding(ns, origin, name);

    CCF_APP_DEBUG("ADNS: Preceding: {}", preceding);

    r += find_records(origin, preceding, QType::NSEC3, qclass);
    r += find_rrsigs(origin, preceding, qclass, Type::NSEC3);

    return RFC1035::NAME_ERROR; // NXDOMAIN
  }

  Name Resolver::find_preceding(
    const Names& ns, const Name& origin, const Name& sname)
  {
    for (auto it = ns.rbegin(); it != ns.rend();)
    {
      auto next = it;
      next++;

      if (
        RFC4034::operator<(*it, sname) &&
        (next == ns.rend() || !RFC4034::operator<(sname, *next)))
        return *it;

      it = next;
    }

    return origin;
  }

  RFC1035::ResponseCode Resolver::find_nsec_records(
    const Name& origin,
    QClass sclass,
    const Name& sname,
    RFC4034::CanonicalRRSet& r)
  {
    // NODATA:

    // If the zone contains RRsets matching <SNAME, SCLASS> but contains no
    // RRset matching <SNAME, SCLASS, STYPE>, then the name server MUST include
    // the NSEC RR for <SNAME, SCLASS> along with its associated RRSIG RR(s) in
    // the Authority section of the response (see Section 3.1.1).  If space
    // does not permit inclusion of the NSEC RR or its associated RRSIG RR(s),
    // the name server MUST set the TC bit (see Section 3.1.1).

    // Since the search name exists, wildcard name expansion does not apply to
    // this query, and a single signed NSEC RR suffices to prove that the
    // requested RR type does not exist.

    // For NODATA, we would find an NSEC record for sname
    auto nsec = find_records(origin, sname, QType::NSEC, sclass);

    if (!nsec.empty())
    {
      r += nsec;
      r += find_rrsigs(origin, sname, sclass, Type::NSEC);
      return RFC1035::ResponseCode::NO_ERROR;
    }

    // NXDOMAIN:

    // If the zone does not contain any RRsets matching <SNAME, SCLASS> either
    // exactly or via wildcard name expansion, then the name server MUST include
    // the following NSEC RRs in the Authority section, along with their
    // associated RRSIG RRs:

    // o  An NSEC RR proving that there is no exact match for <SNAME, SCLASS>.

    // o  An NSEC RR proving that the zone contains no RRsets that would match
    // <SNAME, SCLASS> via wildcard name expansion.

    const auto& ns = get_ordered_names(origin, static_cast<Class>(sclass));

    auto preceding = find_preceding(ns, origin, sname);

    r += find_records(origin, preceding, QType::NSEC, sclass);
    r += find_rrsigs(origin, preceding, sclass, Type::NSEC);

    // TODO: Wildcard expansion. Since we don't support wildcards, we can't
    // easily search for one.

    return RFC1035::ResponseCode::NAME_ERROR;
  }

  Resolver::Resolution Resolver::resolve(
    const Name& qnameu, QType qtype, QClass qclass)
  {
    Resolution result;

    if (qtype == QType::ASTERISK || qclass == QClass::ASTERISK)
      return {ResponseCode::NOT_IMPLEMENTED, {}, {}, {}};

    if (!qnameu.is_absolute())
      throw std::runtime_error("cannot resolve relative names");

    Name qname = qnameu.lowered();

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

    if (!origin.is_absolute())
      return result;

    auto& result_set = result.answers;

    RFC4034::CanonicalRRSet records;

    bool delegated = is_delegated(origin, qname);

    if (!delegated || qtype == QType::DS)
    {
      records = find_records(origin, qname, qtype, qclass);
      result.is_authoritative = true;
    }
    else if (qtype == QType::A || qtype == QType::AAAA)
    {
      // Direct query for glue records. Not sure queries of this form are
      // standards compliant.
      records = find_records(origin + Name("glue."), qname, qtype, qclass);
      result.is_authoritative = true;
    }

    for (const auto& rr : records)
      if (rr.name == qname)
        result_set +=
          find_rrsigs(origin, rr.name, qclass, static_cast<Type>(rr.type));

    result_set += records;

    if (result_set.empty())
    {
      auto cfg = get_configuration();
      auto& ra = result.authorities;

      if (delegated)
      {
        for (Name n = qname; n != origin && !n.is_root(); n = n.parent())
        {
          // Delegation records
          ra += find_records(origin, n, QType::NS, qclass);

          ra += find_records(origin, n, QType::DS, qclass);
          ra += find_rrsigs(origin, n, qclass, Type::DS);

          // Glue records
          for (const auto& rr : ra)
            if (rr.type == static_cast<uint16_t>(Type::NS))
            {
              result.additionals += find_records(
                origin + Name("glue."),
                NS(rr.rdata).nsdname,
                static_cast<QType>(Type::A),
                qclass);
            }
        }

        result.response_code = ResponseCode::NO_ERROR;
      }
      else
      {
        ra += find_records(origin, origin, QType::SOA, qclass);
        ra += find_rrsigs(origin, origin, qclass, Type::SOA);

        if (cfg.use_nsec3)
          result.response_code = find_nsec3_records(origin, qclass, qname, ra);
        else
          result.response_code = find_nsec_records(origin, qclass, qname, ra);
      }
    }

    CCF_APP_TRACE(
      "ADNS: Resolve: {} type {} class {}:{}",
      qname,
      string_from_qtype(qtype),
      string_from_qclass(qclass),
      std::to_string(result_set.size()));
    for (const auto& rr : result_set)
      CCF_APP_TRACE("ADNS:  - {}", string_from_resource_record(rr));

    return result;
  }

  RFC4034::CanonicalRRSet Resolver::get_ordered_records(
    const Name& origin, QClass c, QType t, const Name& name) const
  {
    RFC4034::CanonicalRRSet r;

    for_each(origin, name, c, t, [&origin, &r](const auto& rr) {
      r += RFC4034::canonicalize(origin, rr, type2str);
      return true;
    });

    return r;
  }

  const Resolver::Names& Resolver::get_ordered_names(
    const Name& origin, Class c)
  {
    if (name_cache_dirty)
    {
      name_cache.clear();

      for (const auto& [_, t] : supported_types)
      {
        for_each(
          origin,
          static_cast<QClass>(c),
          static_cast<QType>(t),
          [this, &origin](const auto& rr) {
            name_cache.insert(rr.name);
            return true;
          });
      }

      name_cache_dirty = false;
    }

    return name_cache;
  }

  Resolver::Names Resolver::get_ordered_names(
    const Name& origin, Class c, Type t)
  {
    Names r;
    for_each(
      origin,
      static_cast<QClass>(c),
      static_cast<QType>(t),
      [&origin, &r](const auto& rr) {
        r.insert(rr.name);
        return true;
      });

    return r;
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
    const RFC1035::Name& suffix,
    std::set<Type> types,
    uint32_t nsec_ttl,
    const KeyAndTag& key_and_tag)
  {
    assert(!types.empty());
    auto configuration = get_configuration();

    std::string nameb32 = base32hex_encode(&name_hash[0], name_hash.size());
    assert(nameb32.size() <= 63);
    RFC1035::Name name(nameb32);
    name += suffix;
    name.lower();

    uint8_t flags = 0;
    uint16_t iterations = 2;

    RFC5155::NSEC3 rdata(
      configuration.nsec3_hash_algorithm,
      flags,
      configuration.nsec3_hash_iterations,
      get_nsec3_salt(origin, static_cast<QClass>(c)),
      next_hashed_owner_name,
      type2str);

    for (const auto& t : types)
      if (t != Type::NSEC3)
        rdata.type_bit_maps.insert(static_cast<uint16_t>(t));

    rdata.type_bit_maps.insert(static_cast<uint16_t>(Type::RRSIG));

    ResourceRecord rr(
      name,
      static_cast<uint16_t>(Type::NSEC3),
      static_cast<uint16_t>(c),
      ttl,
      rdata);

    add(origin, rr);

    // Add RRSIG for NSEC3
    RFC4034::CRRS crrs(
      rr.name,
      static_cast<RFC1035::Class>(c),
      static_cast<uint16_t>(Type::NSEC3),
      nsec_ttl,
      rr.rdata);

    auto [key, key_tag] = key_and_tag;
    add(
      origin,
      RFC4034::RRSIGRR(
        make_signing_function(key),
        key_tag,
        configuration.signing_algorithm,
        origin,
        crrs,
        type2str));

    return rr;
  }

  size_t Resolver::sign_rrset(
    const Name& origin,
    QClass c,
    QType t,
    const Name& name,
    std::shared_ptr<crypto::KeyPair> key,
    uint16_t key_tag,
    RFC4034::Algorithm signing_algorithm)
  {
    CCF_APP_DEBUG(
      "ADNS: Signing {} class {} type {}",
      name,
      string_from_qclass(c),
      string_from_qtype(t));

    auto crecords = get_ordered_records(origin, c, t, name);

    if (!crecords.empty())
    {
      RFC4034::CRRS crrs(
        name,
        crecords.begin()->class_,
        crecords.begin()->type,
        crecords.begin()->ttl);

      for (const auto& rr : crecords)
      {
        if (rr.ttl != crrs.ttl)
          CCF_APP_INFO(
            "ADNS: warning: TTL mismatch in record set for {} type {}",
            name,
            type2str(rr.type));

        crrs.rdata.insert(rr.rdata);
      }

      add(
        origin,
        RFC4034::RRSIGRR(
          make_signing_function(key),
          key_tag,
          signing_algorithm,
          origin,
          crrs,
          type2str));
    }

    return crecords.size();
  }

  void Resolver::sign(const Name& origin)
  {
    CCF_APP_INFO("ADNS: (Re)signing {}", origin);

    std::lock_guard<std::mutex> lock(sign_mtx);

    if (!origin.is_absolute())
      throw std::runtime_error("origin is not absolute");

    const auto& cfg = get_configuration();

    name_cache_dirty = true;

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

      uint32_t nsec_ttl = cfg.default_ttl;

      if (is_authoritative)
      {
        SOA soa_rdata(soa_records.begin()->rdata);
        nsec_ttl = soa_rdata.minimum;
      }

      remove(origin, c, Type::RRSIG);
      remove(origin, c, Type::NSEC);
      remove(origin, c, Type::NSEC3); // Necessary?

      HashedNameTypesMap nsec3_types;
      NameTypesMap nsec_types;

    restart:
      for (const auto& [_, t] : supported_types)
      {
        if (
          t == Type::RRSIG || t == Type::OPT || t == Type::NSEC ||
          t == Type::NSEC3)
          continue; // These are not signed but recreated

        auto names = get_ordered_names(origin, c, t);

        for (auto it = names.begin(); it != names.end(); it++)
        {
          const auto& name = *it;

          // delegation points/glue records are not signed
          // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
          if (t == Type::NS && name != origin)
            continue;

          auto [key, key_tag] = t == Type::DNSKEY && cfg.use_key_signing_key ?
            ksk_and_tag :
            zsk_and_tag;

          auto num_records = sign_rrset(
            origin,
            static_cast<QClass>(c),
            static_cast<QType>(t),
            name,
            key,
            key_tag,
            cfg.signing_algorithm);

          if (cfg.use_nsec3 && num_records > 0)
          {
            auto hashed_owner = RFC5155::NSEC3::hash(
              origin,
              name,
              cfg.nsec3_hash_iterations,
              get_nsec3_salt(origin, static_cast<aDNS::QClass>(c)));

            auto hit = nsec3_types.find(hashed_owner);
            if (hit != nsec3_types.end() && hit->second.name != name)
            {
              // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
              // hash collision, restart with new salt
              update_nsec3_param(
                origin,
                c,
                nsec_ttl,
                cfg.nsec3_hash_algorithm,
                cfg.nsec3_hash_iterations,
                cfg.nsec3_salt_length);
              nsec3_types.clear();
              CCF_APP_INFO(
                "ADNS: Restarting zone signing after NSEC3 hash collision");
              goto restart;
            }

            if (hit == nsec3_types.end())
            {
              nsec3_types[hashed_owner].name = name;
              nsec3_types[hashed_owner].types = {t, Type::RRSIG};
            }
            else
              hit->second.types.insert({t, Type::RRSIG});
          }
          else
          {
            nsec_types[name].insert(static_cast<Type>(t));
            nsec_types[name].insert(Type::RRSIG);
          }
        }
      }

      if (cfg.use_nsec3)
      {
        // https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7
        for (auto it = nsec3_types.begin(); it != nsec3_types.end(); it++)
        {
          auto next = std::next(it);

          const Name& owner = it->second.name;
          small_vector<uint8_t> next_hashed_owner_name =
            next != nsec3_types.end() ? next->first :
                                        nsec3_types.begin()->first;

          auto rr = add_nsec3(
            c,
            origin,
            nsec_ttl,
            it->first,
            next_hashed_owner_name,
            owner,
            it->second.types,
            nsec_ttl,
            zsk_and_tag);
        }
      }
      else
      {
        for (auto it = nsec_types.begin(); it != nsec_types.end();)
        {
          auto next = std::next(it);
          Name next_domain_name = next != nsec_types.end() ?
            next->first :
            (is_authoritative ? soa_records.begin()->name : origin);

          std::set<RFC4034::Type> types;
          types.insert(RFC4034::Type::RRSIG);
          types.insert(RFC4034::Type::NSEC);
          for (const auto t : it->second)
            types.insert(static_cast<RFC4034::Type>(t));

          RFC4034::NSECRR rr(
            it->first,
            static_cast<RFC1035::Class>(c),
            nsec_ttl,
            next_domain_name,
            types,
            type2str);
          add(origin, rr);

          RFC4034::CRRS crrs(
            it->first,
            static_cast<RFC1035::Class>(c),
            static_cast<uint16_t>(Type::NSEC),
            nsec_ttl,
            rr.rdata);

          auto [key, key_tag] = zsk_and_tag;
          add(
            origin,
            RFC4034::RRSIGRR(
              make_signing_function(key),
              key_tag,
              cfg.signing_algorithm,
              origin,
              crrs,
              type2str));

          it = next;
        }
      }
    }

    CCF_APP_INFO("ADNS: (Re)signing {} done", origin);
  }

  std::shared_ptr<crypto::KeyPair> Resolver::get_tls_key()
  {
    // The CCF resolver uses the network key, but we could also use the zone
    // or key signing key.
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

  void Resolver::add_caa_records(
    const Name& origin,
    const Name& name,
    const std::string& ca_name,
    const std::vector<std::string>& contact)
  {
    using namespace RFC8659;

    add(
      origin,
      mk_rr(name, aDNS::Type::CAA, Class::IN, 3600, CAA(0, "issue", ca_name)));

    for (const auto& email : contact)
      add(
        origin,
        mk_rr(
          name,
          aDNS::Type::CAA,
          Class::IN,
          3600,
          CAA(0, "iodef", "mailto:" + email)));
  }

  small_vector<uint8_t> Resolver::get_nsec3_salt(
    const Name& origin, aDNS::QClass class_)
  {
    auto params_rrs = find_records(origin, origin, QType::NSEC3PARAM, class_);

    if (params_rrs.empty())
    {
      auto cfg = get_configuration();

      update_nsec3_param(
        origin,
        static_cast<Class>(class_),
        cfg.default_ttl,
        cfg.nsec3_hash_algorithm,
        cfg.nsec3_hash_iterations,
        cfg.nsec3_salt_length);

      params_rrs = find_records(origin, origin, QType::NSEC3PARAM, class_);

      if (params_rrs.empty())
        throw std::runtime_error(
          fmt::format("failed to add NSEC3PARAM record for {}", origin));
    }

    return RFC5155::NSEC3PARAM(params_rrs.begin()->rdata).salt;
  }

  small_vector<uint8_t> Resolver::generate_nsec3_salt(uint8_t length)
  {
    small_vector<uint8_t> salt(length);
    auto e = crypto::create_entropy();
    e->random(&salt[0], salt.size());
    return salt;
  }

  void Resolver::update_nsec3_param(
    const Name& origin,
    aDNS::Class class_,
    uint16_t ttl,
    RFC5155::HashAlgorithm hash_algorithm,
    uint16_t hash_iterations,
    uint8_t salt_length)
  {
    remove(origin, origin, class_, Type::NSEC3PARAM);

    auto r = generate_nsec3_salt(salt_length);

    CCF_APP_TRACE("CCFDNS: new nsec3 salt: {}", ds::to_hex(r));

    add(
      origin,
      RFC5155::NSEC3PARAMRR(
        origin,
        static_cast<RFC1035::Class>(class_),
        ttl,
        hash_algorithm,
        0x00,
        hash_iterations,
        r));
  }

  static std::shared_ptr<ravl::Attestation> der_compress(
    const std::shared_ptr<ravl::Attestation>& att)
  {
#ifdef ATTESTATION_VERIFICATION_FAILURE_OK
    return att;
#else
    switch (att->source)
    {
      case ravl::Source::SGX:
      {
        auto sgx_att = dynamic_pointer_cast<ravl::sgx::Attestation>(att);
        sgx_att->compress_pck_certificate_chain();
        return sgx_att;
      }
      case ravl::Source::OPEN_ENCLAVE:
      {
        auto oe_att = dynamic_pointer_cast<ravl::oe::Attestation>(att);
        oe_att->compress_pck_certificate_chain();
        return oe_att;
      }
      default:
        return att;
    }
#endif
  }

  void Resolver::add_attestation_records(
    const Name& origin,
    const Name& service_name,
    const std::map<std::string, NodeInfo>& node_info)
  {
    auto cfg = get_configuration();
    ravl::json j_att_set = ravl::json::array(); // JSON array of attestations

    remove(origin, service_name, Class::IN, Type::ATTEST);

    for (const auto& [id, info] : node_info)
    {
      // Compress attestation
      auto att = ravl::parse_attestation(info.attestation);
      att->endorsements.clear();
      att = der_compress(att);
      j_att_set.push_back(ravl::json::from_cbor(att->cbor()));

      // ATTEST record for each node
      small_vector<uint16_t> attest_rdata = Types::ATTEST(att);
      ResourceRecord att_rr = mk_rr(
        info.address.name,
        Type::ATTEST,
        Class::IN,
        cfg.default_ttl,
        attest_rdata);
      remove(origin, info.address.name, Class::IN, Type::ATTEST);
      add(origin, att_rr);

      // Fragmented version
      auto attest_name = Name("attest") + info.address.name;
      remove(origin, attest_name, Class::IN, Type::AAAA);
      add_fragmented(origin, attest_name, att_rr);

      // Service name/subdomain ATTEST record for each node
      auto service_att_rr = mk_rr(
        service_name, Type::ATTEST, Class::IN, cfg.default_ttl, attest_rdata);
      add(origin, service_att_rr);
    }

    // Fragmented ATTEST RR set for service
    auto att_set_name = Name("attest") + service_name;
    remove(origin, att_set_name, Class::IN, Type::AAAA);
    add_fragmented(
      origin,
      att_set_name,
      cfg.default_ttl,
      Class::IN,
      ravl::json::to_cbor(j_att_set),
      true);
  }

  Resolver::RegistrationInformation Resolver::configure(
    const Configuration& cfg)
  {
    set_configuration(cfg);

    update_nsec3_param(
      cfg.origin,
      aDNS::Class::IN,
      cfg.default_ttl,
      cfg.nsec3_hash_algorithm,
      cfg.nsec3_hash_iterations,
      cfg.nsec3_salt_length);

    if (cfg.node_addresses.empty())
      throw std::runtime_error("missing node information");

    if (cfg.contact.empty())
      throw std::runtime_error("at least one contact is required");

    auto tls_key = get_tls_key();

    RegistrationInformation out;

    out.public_key = tls_key->public_key_pem().str();
    out.node_information = get_node_information();

    remove(cfg.origin, cfg.origin, Class::IN, Type::SOA);
    add(
      cfg.origin,
      mk_rr(cfg.origin, aDNS::Type::SOA, Class::IN, 60, SOA(cfg.soa)));

    remove(cfg.origin, cfg.origin, Class::IN, Type::NS);
    remove(cfg.origin, cfg.origin, Class::IN, Type::A);

    add_caa_records(cfg.origin, cfg.origin, cfg.service_ca.name, cfg.contact);

    for (const auto& [id, addr] : cfg.node_addresses)
    {
      if (!addr.name.ends_with(cfg.origin))
        throw std::runtime_error(fmt::format(
          "invalid node name; '{}' is outside the zone", addr.name));

      add(
        cfg.origin,
        mk_rr(cfg.origin, Type::NS, Class::IN, cfg.default_ttl, NS(addr.name)));

      remove(cfg.origin, addr.name, Class::IN, Type::A);
      add(
        cfg.origin,
        mk_rr(addr.name, Type::A, Class::IN, cfg.default_ttl, A(addr.ip)));

      add(
        cfg.origin,
        mk_rr(cfg.origin, Type::A, Class::IN, cfg.default_ttl, A(addr.ip)));

      remove(cfg.origin, addr.name, Class::IN, Type::CAA);
      add_caa_records(cfg.origin, addr.name, cfg.service_ca.name, cfg.contact);
    }

    add_attestation_records(cfg.origin, cfg.origin, out.node_information);

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

    // get_signing_key(cfg.origin, Class::IN, cfg.use_key_signing_key);

    auto dnskeys = resolve(cfg.origin, QType::DNSKEY, QClass::IN);

    if (dnskeys.answers.size() > 0)
    {
      out.dnskey_records = std::vector<ResourceRecord>();
      for (const auto& keyrr : dnskeys.answers)
        if (keyrr.type == static_cast<uint16_t>(aDNS::Type::DNSKEY))
        {
          if (cfg.use_key_signing_key)
          {
            RFC4034::DNSKEY rd(keyrr.rdata);
            if (rd.is_key_signing_key())
              out.dnskey_records->push_back(keyrr);
          }
          else
            out.dnskey_records->push_back(keyrr);
        }
    }

    return out;
  }

  void Resolver::add_fragmented(
    const Name& origin,
    const Name& name,
    uint32_t ttl,
    aDNS::Class class_,
    const small_vector<uint16_t>& rrdata,
    bool compress,
    uint8_t records_per_name)
  {
    // TODO: remove old records?

    std::vector<uint8_t> tmp;

    uint16_t rsz = rrdata.size();
    const uint8_t* crrdata = rrdata.raw();

    if (compress)
    {
      tmp = aDNS::compress(rrdata, 9);
      crrdata = tmp.data();
      rsz = tmp.size();
    }

    size_t num_rrs = rsz / 15;

    if ((rsz % 15) != 0)
      num_rrs++;

    size_t num_names = num_rrs / records_per_name;

    if ((num_rrs % records_per_name) != 0)
      num_names++;

    if (num_names > 65535)
      throw std::runtime_error(
        "too many names/record for AAAA fragmented record");

    small_vector<uint16_t> tdata(16);

    size_t bytes_encoded = 0;
    for (size_t n = 0; n < num_names; n++)
    {
      Name fname = Name("_" + std::to_string(n)) + name;

      remove(origin, fname, Class::IN, Type::AAAA);

      for (size_t i = 0; i < records_per_name; i++)
      {
        tdata[0] = i;

        size_t bytes_per_fragment = records_per_name * 15;

        if (n == 0 && i == 0)
        {
          tdata[1] = rsz >> 8;
          tdata[2] = rsz & 0xFF;

          for (size_t j = 3; j < 16; j++)
            tdata[j] = bytes_encoded >= rsz ? 0 : crrdata[bytes_encoded++];
        }
        else
        {
          for (size_t j = 1; j < 16; j++)
            tdata[j] = bytes_encoded >= rsz ? 0 : crrdata[bytes_encoded++];
        }

        add(
          origin, mk_rr(fname, Type::AAAA, class_, ttl, RFC3596::AAAA(tdata)));

        if (bytes_encoded >= rsz)
          break;
      }
    }
  }

  void Resolver::add_fragmented(
    const Name& origin,
    const Name& name,
    const ResourceRecord& rr,
    bool compress,
    uint8_t records_per_name)
  {
    add_fragmented(
      origin,
      name,
      rr.ttl,
      static_cast<aDNS::Class>(rr.class_),
      rr.rdata,
      compress,
      records_per_name);
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

    save_service_registration_request(service_name, rr);

    if (!req.verify(public_key))
      throw std::runtime_error("CSR signature validation failed");

    bool policy_ok = false;
    std::vector<std::shared_ptr<ravl::Claims>> claims;
    std::optional<std::vector<uint8_t>> endorsements;
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

        if (!endorsements)
          endorsements = att->endorsements;
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

    // TODO: Check we're not overwriting existing registrations? Part of
    // policy?

    uint16_t flags = 0x0000;
    auto pk_der = public_key.der_pubkey();
    small_vector<uint16_t> public_key_sv(pk_der.size(), pk_der.data());

    auto service_protocol =
      rr.node_information.begin()->second.address.protocol;
    auto service_port = rr.node_information.begin()->second.address.port;
    bool protocol_port_same_forall = true;

    for (const auto& [id, info] : rr.node_information)
    {
      const auto& name = info.address.name.terminated();

      if (
        info.address.protocol != service_protocol ||
        info.address.port != service_port)
        protocol_port_same_forall = false;

      if (!name.ends_with(service_name))
        throw std::runtime_error(fmt::format(
          "node name '{}' outside of service sub-zone '{}'",
          name,
          service_name));

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
          Selector::SPKI,
          MatchingType::Full,
          public_key_sv));

      remove(origin, tlsa_name, Class::IN, Type::TLSA);
      add(origin, tlsa_rr);

      remove(origin, tlsa_name, Class::IN, Type::AAAA);
      add_fragmented(origin, tlsa_name, tlsa_rr);

      // CAA RR for node
      remove(origin, name, Class::IN, Type::CAA);
      add_caa_records(origin, name, configuration.service_ca.name, rr.contact);
    }

    add_attestation_records(origin, service_name, rr.node_information);

    if (protocol_port_same_forall)
    {
      // TLSA RR for service
      std::string prolow = service_protocol;
      std::transform(prolow.begin(), prolow.end(), prolow.begin(), ::tolower);
      auto service_tlsa_name = Name("_" + std::to_string(service_port)) +
        Name(std::string("_") + prolow) + service_name;

      auto tlsa_rr = mk_rr(
        service_tlsa_name,
        Type::TLSA,
        Class::IN,
        configuration.default_ttl,
        TLSA(
          CertificateUsage::DANE_EE,
          Selector::SPKI,
          MatchingType::Full,
          public_key_sv));

      remove(origin, service_tlsa_name, Class::IN, Type::TLSA);
      add(origin, tlsa_rr);

      // Fragmented version
      remove(origin, service_tlsa_name, Class::IN, Type::AAAA);
      add_fragmented(origin, service_tlsa_name, tlsa_rr);
    }

    // CAA RR for service
    remove(origin, service_name, Class::IN, Type::CAA);
    add_caa_records(
      origin, service_name, configuration.service_ca.name, rr.contact);

    sign(origin);

    if (endorsements)
      save_endorsements(service_name, compress(*endorsements, 9));

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

    add(
      origin,
      mk_rr(
        Name("_acme-challenge") + name,
        Type::TXT,
        Class::IN,
        60,
        TXT(key_authorization)));

    for (const auto& n : alternative_names)
      if (n != name)
        add(
          origin,
          mk_rr(
            Name("_acme-challenge") + n,
            Type::TXT,
            Class::IN,
            60,
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

    save_delegation_request(name, dr);

    if (!name.ends_with(origin))
      throw std::runtime_error("name outside of origin");

    if (!req.verify(public_key))
      throw std::runtime_error("CSR signature validation failed");

    bool policy_ok = false;
    std::vector<std::shared_ptr<ravl::Claims>> claims;
    std::optional<std::vector<uint8_t>> endorsements;
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

        if (!endorsements)
          endorsements = att->endorsements;
      }

      policy_data += "  }};";
      policy_ok = evaluate_delegation_policy(policy_data);
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

    add_attestation_records(dr.subdomain, dr.subdomain, dr.node_information);

    sign(origin);

    // Glue records are not signed
    // (https://datatracker.ietf.org/doc/html/rfc4035#section-2.2)
    // Note: we shouldn't answer direct queries for glue records, so we put
    // them into a special origin.

    for (const auto& [id, info] : dr.node_information)
      remove(origin + Name("glue."), info.address.name, Class::IN, Type::A);

    for (const auto& [id, info] : dr.node_information)
    {
      add(
        origin + Name("glue."),
        mk_rr(
          info.address.name,
          Type::A,
          Class::IN,
          cfg.default_ttl,
          RFC1035::A(info.address.ip)));
    }

    if (endorsements)
      save_endorsements(dr.subdomain, compress(*endorsements, 9));
  }

  const std::map<uint16_t, Type>& Resolver::get_supported_types() const
  {
    return supported_types;
  }

  const std::map<uint16_t, Class>& Resolver::get_supported_classes() const
  {
    return supported_classes;
  }
}
