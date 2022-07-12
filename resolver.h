// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"
#include "rfc6891.h"

#include <functional>
#include <memory>
#include <stdexcept>

namespace crypto
{
  class KeyPair;
}

namespace aDNS
{
  using Name = RFC1035::Name;
  using Message = RFC1035::Message;
  using ResourceRecord = RFC1035::ResourceRecord;

  enum class Type : uint16_t
  {
    A = static_cast<uint16_t>(RFC1035::Type::A),
    NS = static_cast<uint16_t>(RFC1035::Type::NS),
    CNAME = static_cast<uint16_t>(RFC1035::Type::CNAME),
    SOA = static_cast<uint16_t>(RFC1035::Type::SOA),
    MX = static_cast<uint16_t>(RFC1035::Type::MX),
    TXT = static_cast<uint16_t>(RFC1035::Type::TXT),
    AAAA = static_cast<uint16_t>(RFC3596::Type::AAAA),
    DNSKEY = static_cast<uint16_t>(RFC4034::Type::DNSKEY),
    RRSIG = static_cast<uint16_t>(RFC4034::Type::RRSIG),
    NSEC = static_cast<uint16_t>(RFC4034::Type::NSEC),
    DS = static_cast<uint16_t>(RFC4034::Type::DS),
    OPT = static_cast<uint16_t>(RFC6891::Type::OPT),
  };

  enum class QType : uint16_t
  {
    A = static_cast<uint16_t>(RFC1035::Type::A),
    NS = static_cast<uint16_t>(RFC1035::Type::NS),
    CNAME = static_cast<uint16_t>(RFC1035::Type::CNAME),
    SOA = static_cast<uint16_t>(RFC1035::Type::SOA),
    MX = static_cast<uint16_t>(RFC1035::Type::MX),
    TXT = static_cast<uint16_t>(RFC1035::Type::TXT),
    AAAA = static_cast<uint16_t>(RFC3596::Type::AAAA),
    DNSKEY = static_cast<uint16_t>(RFC4034::Type::DNSKEY),
    RRSIG = static_cast<uint16_t>(RFC4034::Type::RRSIG),
    NSEC = static_cast<uint16_t>(RFC4034::Type::NSEC),
    DS = static_cast<uint16_t>(RFC4034::Type::DS),
    OPT = static_cast<uint16_t>(RFC6891::Type::OPT),
    ASTERISK = static_cast<uint16_t>(RFC1035::QType::ASTERISK),
  };

  std::string string_from_type(const Type& type);
  std::string string_from_qtype(const QType& type);
  std::string string_from_resource_record(const ResourceRecord& rr);

  Type type_from_string(const std::string& s);
  QType qtype_from_string(const std::string& s);

  enum class Class : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
  };

  enum class QClass : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
    ASTERISK = static_cast<uint16_t>(RFC1035::QClass::ASTERISK),
  };

  inline bool is_type_in_qtype(uint16_t t, QType qt)
  {
    return qt == QType::ASTERISK || t == static_cast<uint16_t>(qt);
  }

  inline bool is_class_in_qclass(uint16_t c, QClass qc)
  {
    return qc == QClass::ASTERISK || c == static_cast<uint16_t>(qc);
  }

  class Resolver
  {
  public:
    struct Resolution
    {
      RFC1035::ResponseCode response_code = RFC1035::ResponseCode::NO_ERROR;
      RFC4034::CanonicalRRSet answers;
      RFC4034::CanonicalRRSet authorities;
    };

    Resolver();
    virtual ~Resolver();

    virtual Message reply(const Message& msg);

    virtual Resolution resolve(
      const Name& qname, QType qtype, QClass qclass, bool with_extras = false);

    virtual RFC4034::CanonicalRRSet find_records(
      const Name& origin, const Name& name, QType qtype, QClass qclass);

    virtual void for_each(
      const Name& origin,
      QClass qclass,
      QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const = 0;

    virtual void sign(const Name& origin);

    virtual void on_add(const Name& origin, const ResourceRecord& rr);

    virtual void add(const Name& origin, const ResourceRecord& rr) = 0;

    virtual void remove(
      const Name& origin, const Name& name, const Type& t) = 0;

  protected:
    uint32_t default_ttl = 86400;
    bool ignore_on_add = false;
    std::map<
      Name,
      std::shared_ptr<crypto::KeyPair>,
      RFC4034::CanonicalNameOrdering>
      zone_signing_keys;

    RFC4034::CanonicalRRSet order_records(const Name& origin, QClass c) const;
  };
}
