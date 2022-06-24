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
  static const std::map<uint16_t, aDNS::Type> supported_types = {
    {static_cast<uint16_t>(RFC1035::Type::A), aDNS::Type::A},
    {static_cast<uint16_t>(RFC1035::Type::NS), aDNS::Type::NS},
    {static_cast<uint16_t>(RFC1035::Type::CNAME), aDNS::Type::CNAME},
    {static_cast<uint16_t>(RFC1035::Type::SOA), aDNS::Type::SOA},
    {static_cast<uint16_t>(RFC1035::Type::MX), aDNS::Type::MX},
    {static_cast<uint16_t>(RFC1035::Type::TXT), aDNS::Type::TXT},

    {static_cast<uint16_t>(RFC3596::Type::AAAA), aDNS::Type::AAAA},

    {static_cast<uint16_t>(RFC4034::Type::DNSKEY), aDNS::Type::DNSKEY}};

  static const std::map<uint16_t, aDNS::QType> supported_qtypes = {
    {static_cast<uint16_t>(RFC1035::QType::ASTERISK), aDNS::QType::ASTERISK},
  };

  static const std::map<uint16_t, Class> supported_classes = {
    {static_cast<uint16_t>(RFC1035::Class::IN), Class::IN}};

  static const std::map<uint16_t, aDNS::QClass> supported_qclasses = {
    {static_cast<uint16_t>(RFC1035::QClass::ASTERISK), aDNS::QClass::ASTERISK}};

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

  static const std::map<std::string, aDNS::Type> string_to_type_map = {
    {"A", aDNS::Type::A},
    {"NS", aDNS::Type::NS},
    {"CNAME", aDNS::Type::CNAME},
    {"SOA", aDNS::Type::SOA},
    {"MX", aDNS::Type::MX},
    {"TXT", aDNS::Type::TXT},

    {"AAAA", aDNS::Type::AAAA},

    {"DNSKEY", aDNS::Type::DNSKEY},
  };

  static inline aDNS::Type type_from_string(const std::string& s)
  {
    auto mit = string_to_type_map.find(s);
    if (mit == string_to_type_map.end())
    {
      throw std::runtime_error(fmt::format("unknown type '{}'", s));
    }
    return mit->second;
  };

  static inline std::string string_from_type(const uint16_t& t)
  {
    for (const auto& [name, type] : string_to_type_map)
    {
      if (static_cast<uint16_t>(type) == t)
      {
        return name;
      }
    }

    throw std::runtime_error(
      fmt::format("unknown type '{}'", std::to_string((uint16_t)t)));
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

  Resolver::Resolver() {}

  Resolver::~Resolver() {}

  void Resolver::add(const Name& origin, const ResourceRecord& record)
  {
    LOG_TRACE_FMT(
      "Add '{}' type '{}' to '{}'",
      (std::string)record.name,
      string_from_type(record.type),
      (std::string)origin);

    auto oit = cache.find(origin);
    if (oit == cache.end())
    {
      oit = cache.insert(cache.end(), {origin, std::vector<ResourceRecord>()});
    }

    ResourceRecord rs(record);
    rs.name.strip_suffix(origin);
    oit->second.push_back(rs);
  }

  void Resolver::remove(const Name& origin, const ResourceRecord& record)
  {
    LOG_TRACE_FMT(
      "Remove '{}' type '{}' from '{}'",
      (std::string)record.name,
      string_from_type(record.type),
      (std::string)origin);

    auto oit = cache.find(origin);
    if (oit == cache.end())
    {
      return;
    }

    ResourceRecord rs(record);
    rs.name.strip_suffix(origin);

    std::erase_if(oit->second, [&rs](const auto& r) { return r == rs; });
  }

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

  static bool type_in_qtype(uint16_t t, QType qt)
  {
    return qt == QType::ASTERISK || t == static_cast<uint16_t>(qt);
  }

  static bool class_in_qclass(uint16_t c, QClass qc)
  {
    return qc == QClass::ASTERISK || c == static_cast<uint16_t>(qc);
  }

  std::vector<ResourceRecord> Resolver::resolve(
    const Name& qname, QType qtype, QClass qclass) const
  {
    std::vector<ResourceRecord> r;

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
    for (size_t i = 0; i < qname.labels.size(); i++)
    {
      LOG_DEBUG_FMT(
        "Looking for '{}' type '{}' in '{}'",
        (std::string)entry,
        string_from_type(static_cast<uint16_t>(qtype)),
        (std::string)origin);

      auto cit = cache.find(origin);
      if (cit != cache.end())
      {
        for (const auto& rr : cit->second)
        {
          LOG_TRACE_FMT(
            "{} =?= {} : {}",
            (std::string)rr.name,
            (std::string)entry,
            rr.name == entry);
          if (
            type_in_qtype(rr.type, qtype) &&
            class_in_qclass(rr.class_, qclass) && rr.name == entry)
          {
            LOG_DEBUG_FMT("Found a match!");
            r.push_back(rr);
            r.back().name += origin;
          }
        }
        break; // Continue collecting matches in longer origins?
      }

      entry.labels.push_back(origin.labels.front());
      origin.labels.erase(origin.labels.begin());
    }

    return r;
  }
}
