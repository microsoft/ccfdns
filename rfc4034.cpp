// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rfc4034.h"

#include "resolver.h"
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
      case U(RFC3596::Type::AAAA):
        cr.rdata = rr.rdata;
        break;
      default:
        throw std::runtime_error(
          fmt::format("canonicalization for type {} not supported", cr.type));
    }
    return cr;
  }

  typedef std::set<ResourceRecord, RFC4034::CanonicalRROrdering> CanonicalRRSet;

  CanonicalRRSet canonicalize(
    const Name& origin,
    const std::vector<ResourceRecord>& records,
    const std::function<std::string(const Type&)>& type2str)
  {
    // https://datatracker.ietf.org/doc/html/rfc4034#section-6.3
    CanonicalRRSet r;
    for (const auto& rr : records)
      r.insert(canonicalize(origin, rr, type2str));
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
      put(rr.name, rr_i);
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
    const CanonicalRRSet& rrset,
    const std::function<std::string(const Type&)>& type2str)
  {
    auto& owner = origin; // Correct if we are authoritative?

    auto now = std::chrono::system_clock::now();
    auto tp = now.time_since_epoch();
    uint32_t sig_inception = duration_cast<std::chrono::seconds>(tp).count();
    uint32_t sig_expiration =
      duration_cast<std::chrono::seconds>(tp + std::chrono::days(90)).count();

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
      rrset);

    return RRSIG(
      type,
      static_cast<uint8_t>(algorithm),
      owner.labels.size(),
      original_ttl,
      sig_expiration,
      sig_inception,
      keytag,
      owner,
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
          if (bi & 0x01)
          {
            if (first)
              first = false;
            else
              r += " ";
            Type t = static_cast<Type>(w.window_block_no << 8 | type_no);
            r += type2str(t);
          }
          bi >>= 1;
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
    entry.bitmap[oct_inx] |= 1 << (lower & 0x07);
  }

  void NSEC::TypeBitMaps::put(std::vector<uint8_t>& r) const
  {
    for (const auto& w : windows)
    {
      ::put(w.window_block_no, r);
      w.bitmap.put(r);
    }
  }
}
