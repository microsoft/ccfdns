// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"

#include "ccf/ds/logger.h"
#include "rfc1035.h"
#include "rfc3596.h"

#include <cstddef>
#include <memory>
#include <sstream>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace RFC1035;

namespace aDNS
{
  static inline aDNS::Type get_supported_type(uint16_t t)
  {
    static const std::map<uint16_t, aDNS::Type> smap = {
      {static_cast<uint16_t>(RFC1035::Type::A), aDNS::Type::A},
      {static_cast<uint16_t>(RFC1035::Type::NS), aDNS::Type::NS},
      {static_cast<uint16_t>(RFC1035::Type::CNAME), aDNS::Type::CNAME},
      {static_cast<uint16_t>(RFC1035::Type::SOA), aDNS::Type::SOA},
      {static_cast<uint16_t>(RFC1035::Type::MX), aDNS::Type::MX},
      {static_cast<uint16_t>(RFC1035::Type::TXT), aDNS::Type::TXT},

      {static_cast<uint16_t>(RFC3596::Type::AAAA), aDNS::Type::AAAA},

      {static_cast<uint16_t>(RFC4034::Type::DNSKEY), aDNS::Type::DNSKEY}};
    auto mit = smap.find(t);
    if (mit == smap.end())
      throw std::runtime_error("unsupported type");
    return mit->second;
  };

  static inline aDNS::QType get_supported_qtype(uint16_t t)
  {
    static const std::map<uint16_t, aDNS::QType> smap = {
      {static_cast<uint16_t>(RFC1035::QType::ASTERISK), aDNS::QType::ASTERISK},
    };
    auto mit = smap.find(t);
    if (mit == smap.end())
      return static_cast<aDNS::QType>(get_supported_type(t));
    return mit->second;
  };

  static inline Class get_supported_class(uint16_t t)
  {
    static const std::map<uint16_t, Class> smap = {
      {static_cast<uint16_t>(RFC1035::Class::IN), Class::IN}};
    auto mit = smap.find(t);
    if (mit == smap.end())
      throw std::runtime_error("unsupported class");
    return mit->second;
  };

  static inline aDNS::QClass get_supported_qclass(uint16_t t)
  {
    static const std::map<uint16_t, aDNS::QClass> smap = {
      {static_cast<uint16_t>(RFC1035::QClass::ASTERISK),
       aDNS::QClass::ASTERISK}};
    auto mit = smap.find(t);
    if (mit == smap.end())
      return static_cast<aDNS::QClass>(get_supported_class(t));
    return mit->second;
  };

  static inline aDNS::Type type_from_string(const std::string& s)
  {
    static const std::map<std::string, aDNS::Type> smap = {
      {"A", aDNS::Type::A},
      {"NS", aDNS::Type::NS},
      {"CNAME", aDNS::Type::CNAME},
      {"SOA", aDNS::Type::SOA},
      {"MX", aDNS::Type::MX},
      {"TXT", aDNS::Type::TXT},

      {"AAAA", aDNS::Type::AAAA},

      {"DNSKEY", aDNS::Type::DNSKEY},
    };
    auto mit = smap.find(s);
    if (mit == smap.end())
      throw std::runtime_error("unknown type");
    return mit->second;
  };

  static inline aDNS::QType qtype_from_string(const std::string& s)
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

  struct Resolver::DomainTree
  {
    DomainTree() {}
    DomainTree(const Label& l) : label(l) {}

    Label label;
    std::vector<ResourceRecord> resource_records;
    std::vector<std::shared_ptr<DomainTree>> subdomains;

    std::string to_string(size_t indent) const
    {
      std::stringstream ss;
      ss << std::string(indent, ' ') << "- " << (std::string)label << ":";
      for (const auto& rr : resource_records)
        ss << " " << (unsigned)rr.type;
      ss << std::endl;
      for (const auto& sd : subdomains)
        ss << sd->to_string(indent + 1);
      return ss.str();
    }
  };

  Resolver::Resolver()
  {
    root = std::make_shared<DomainTree>();
  }

  Resolver::~Resolver() {}

  std::shared_ptr<Resolver::DomainTree> Resolver::find(const Name& name) const
  {
    if (!name.is_absolute())
      throw std::runtime_error(fmt::format(
        "invalid name '{}'(required to be absolute; i.e. ends in '.').",
        (std::string)name));

    std::shared_ptr<DomainTree> subtree = nullptr;

    for (auto it = name.labels.rbegin(); it != name.labels.rend(); it++)
    {
      std::cout << "@: " << (std::string)*it << std::endl;

      if (!subtree)
      {
        subtree = root;
      }
      else
      {
        auto& children = subtree->subdomains;

        auto next = std::find_if(
          children.begin(), children.end(), [&label = *it](auto x) {
            return label == x->label;
          });

        if (next == children.end())
          throw std::runtime_error("Bug: name could not be found");

        subtree = *next;
      }
    }

    return subtree;
  }

  std::shared_ptr<Resolver::DomainTree> Resolver::find_or_create(
    const Name& name)
  {
    if (!name.is_absolute())
      throw std::runtime_error(fmt::format(
        "invalid name '{}' (required to be absolute; i.e. ends in '.').",
        (std::string)name));

    std::shared_ptr<DomainTree> subtree = nullptr;

    std::cout << "Looking for " << (std::string)name << std::endl;

    for (auto it = name.labels.rbegin(); it != name.labels.rend(); it++)
    {
      std::cout << "@+: " << (std::string)*it << std::endl;

      if (!subtree)
      {
        subtree = root;
      }
      else
      {
        auto& children = subtree->subdomains;

        auto next = std::find_if(
          children.begin(), children.end(), [&label = *it](auto x) {
            return label == x->label;
          });

        subtree = next != children.end() ?
          *next :
          children.emplace_back(std::make_shared<DomainTree>(*it));
      }
    }

    if (!subtree)
      throw std::runtime_error("Bug: name could not be found or created");

    return subtree;
  }

  void Resolver::update(const Name& origin, const Zone& zone)
  {
    std::cout << "Update: " << (std::string)origin << std::endl;

    auto subtree = find_or_create(origin);

    subtree->resource_records.clear();
    subtree->subdomains.clear();

    auto& children = subtree->subdomains;
    children.clear();

    for (auto& e : zone.records)
    {
      Name name(e.name);
      Type type = type_from_string(e.type);
      Class class_ = Class::IN; // TODO: defaults to "last explicitly stated"
      uint32_t ttl = 0; // TODO: defaults to "last explicitly stated"

      name.strip_suffix(origin);

      if (name.labels.size() > 1)
        throw std::runtime_error("multi-label zone entries not supported");

      if (e.class_)
        class_ = static_cast<Class>(std::stoi(*e.class_));

      if (e.ttl)
        ttl = std::stoi(*e.ttl);

      std::cout << "+ " << (std::string)name << std::endl;
      std::cout << "e.data: " << e.data << std::endl;

      auto child_it = std::find_if(
        children.begin(), children.end(), [&label = name.labels[0]](auto x) {
          return label == x->label;
        });

      std::shared_ptr<DomainTree> child = child_it != children.end() ?
        *child_it :
        children.emplace_back(std::make_shared<DomainTree>(name.labels[0]));

      std::vector<uint8_t> rdata;

      switch (type)
      {
        case Type::A:
          rdata = RFC1035::A(e.data);
          break;
        case Type::NS:
          rdata = RFC1035::NS(e.data);
          subtree->subdomains.emplace_back(std::make_shared<DomainTree>(
            name.labels[0])); // TODO: Multi-label scopes?
          break;
        case Type::CNAME:
          rdata = RFC1035::CNAME(e.data);
          break;
        case Type::TXT:
          rdata = RFC1035::TXT(e.data);
          break;

        case Type::AAAA:
          rdata = RFC3596::AAAA(e.data);
          break;

        case Type::DNSKEY:
          rdata = RFC4034::DNSKEY(e.data);
          break;
        case Type::RRSIG:
          rdata = RFC4034::RRSIG(e.data);
          break;
        case Type::NSEC:
          rdata = RFC4034::NSEC(e.data, [](const std::string& x) {
            return static_cast<uint16_t>(type_from_string(x));
          });
          break;
        case Type::DS:
          rdata = RFC4034::DS(e.data);
          break;

        default:
          rdata = {e.data.begin(), e.data.end()};
      }

      child->resource_records.emplace_back(
        name,
        static_cast<RFC1035::Type>(type),
        static_cast<RFC1035::Class>(class_),
        ttl,
        rdata);
    }

    std::cout << "Updated tree: " << std::endl;
    std::cout << root->to_string(0) << std::endl;
  }

  Zone Resolver::zone(const Name& origin)
  {
    return Zone();
  }

  Message Resolver::reply(const Message& msg)
  {
    if (msg.questions.size() == 0)
      throw std::runtime_error("No questions.");

    Message r;
    for (const auto& q : msg.questions)
    {
      auto a = resolve(
        q.qname,
        get_supported_qtype(static_cast<uint16_t>(q.qtype)),
        get_supported_qclass(static_cast<uint16_t>(q.qclass)));
      r.answers.insert(r.answers.end(), a.begin(), a.end());
    }

    r.header.qdcount = r.questions.size();
    r.header.ancount = r.answers.size();
    r.header.nscount = r.authorities.size();
    r.header.arcount = r.additionals.size();

    return r;
  }

  std::vector<ResourceRecord> Resolver::resolve(
    const Name& qname, QType qtype, QClass qclass) const
  {
    std::vector<ResourceRecord> r;

    auto subtree = find(qname);

    // TODO: check for qtypes that are not in Type
    // TODO: check if qclass not in Class

    for (const auto& rec : subtree->resource_records)
    {
      if (
        static_cast<uint16_t>(rec.class_) == static_cast<uint16_t>(qclass) &&
        static_cast<uint16_t>(rec.type) == static_cast<uint16_t>(qtype))
      {
        r.push_back(rec);
      }
    }

    return r;
  }
}
