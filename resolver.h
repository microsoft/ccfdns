// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"

#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <ccf/kv/map.h>
#include <memory>
#include <stdexcept>

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
    ASTERISK = static_cast<uint16_t>(RFC1035::QType::ASTERISK),
  };

  enum class Class : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
  };

  enum class QClass : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
    ASTERISK = static_cast<uint16_t>(RFC1035::QClass::ASTERISK),
  };

  // A string representation of zone files
  struct Zone
  {
    struct Record
    {
      std::string name;
      std::optional<std::string> ttl;
      std::optional<std::string> class_;
      std::string type;
      std::string data;
    };

    std::vector<Record> records;
  };

  class Resolver
  {
  public:
    Resolver();
    virtual ~Resolver();

    virtual void update(const Name& origin, const Zone& zone);

    virtual Zone zone(const Name& origin);

    virtual Message reply(const Message& msg);

    virtual std::vector<ResourceRecord> resolve(
      const Name& qname, QType qtype, QClass qclass) const;

  protected:
    struct DomainTree;
    std::shared_ptr<DomainTree> root;

    std::shared_ptr<DomainTree> find(const Name& origin) const;
    std::shared_ptr<DomainTree> find_or_create(const Name& origin);
  };
}
