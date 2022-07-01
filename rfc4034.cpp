// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rfc4034.h"

#include "rfc1035.h"
#include "rfc3596.h"

#include <ccf/crypto/key_pair.h>
#include <set>
#include <stdexcept>
#include <vector>

using namespace RFC1035;

namespace RFC4034
{
  static void lower_and_expand(const Name& origin, Name& name)
  {
    if (!name.is_absolute())
      name += origin;
  }

  static ResourceRecord canonicalize(
    const Name& origin, const ResourceRecord& rr)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.2

    ResourceRecord cr;
    cr.owner = rr.owner;
    lower_and_expand(origin, cr.owner);
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
        auto rdata = RFC4034::RRSIG(rr.rdata);
        lower_and_expand(origin, rdata.signer_name);
        cr.rdata = rdata;
        break;
      }
      case U(RFC4034::Type::NSEC):
      {
        auto rdata = RFC4034::NSEC(rr.rdata);
        lower_and_expand(origin, rdata.next_domain_name);
        cr.rdata = rdata;
        break;
      }
      case U(RFC1035::Type::A):
      case U(RFC3596::Type::AAAA):
        /* Nothing to do */
        break;
      default:
        throw std::runtime_error(
          fmt::format("canonicalization for type {} not supported", cr.type));
    }
    return cr;
  }

  typedef std::set<ResourceRecord, RFC4034::CanonicalRROrdering> CanonicalRRSet;

  static CanonicalRRSet canonicalize(
    const Name& origin, const std::vector<ResourceRecord>& records)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.3
    CanonicalRRSet r;
    for (const auto& rr : records)
      r.insert(canonicalize(origin, rr));
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
    uint32_t keytag,
    const Name& owner,
    const CanonicalRRSet& rrset)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1

    std::vector<uint8_t> data_to_sign;
    put(static_cast<uint16_t>(t), data_to_sign);
    put(static_cast<uint8_t>(algorithm), data_to_sign);
    put((uint8_t)owner.labels.size(), data_to_sign);
    put(original_ttl, data_to_sign);
    put(sig_expiration, data_to_sign);
    put(sig_inception, data_to_sign);
    put(keytag, data_to_sign);
    put(owner, data_to_sign);

    for (const auto& rr : rrset)
    {
      std::vector<uint8_t> rr_i;
      put(rr.owner, rr_i);
      put(rr.type, rr_i);
      put(rr.class_, rr_i);
      put(rr.ttl, rr_i);
      rr.rdata.put(rr_i);
    }

    return signing_function(algorithm, data_to_sign);
  }

  RFC4034::RRSIG sign(
    const SigningFunction& signing_function,
    unsigned int keytag,
    Algorithm algorithm,
    uint32_t original_ttl,
    const RFC1035::Name& origin,
    uint16_t class_,
    uint16_t type,
    const std::vector<RFC1035::ResourceRecord>& records)
  {
    auto& owner = origin; // Correct if we are authoritative?

    auto now = std::chrono::system_clock::now();
    auto tp = now.time_since_epoch();
    uint32_t sig_inception = duration_cast<std::chrono::seconds>(tp).count();
    uint32_t sig_expiration =
      duration_cast<std::chrono::seconds>(tp + std::chrono::days(90)).count();

    auto crrset = RFC4034::canonicalize(origin, records);

    std::vector<uint8_t> signature = compute_rrset_signature(
      signing_function,
      type,
      algorithm,
      owner.labels.size(),
      original_ttl,
      sig_expiration,
      sig_expiration,
      keytag,
      owner,
      crrset);

    return RRSIG(
      type,
      static_cast<uint8_t>(algorithm),
      owner.labels.size(),
      original_ttl,
      sig_expiration,
      sig_inception,
      keytag,
      owner,
      signature);
  }
}
