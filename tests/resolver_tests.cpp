// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <ccf/ds/logger.h>
#include <doctest/doctest.h>

using namespace aDNS;
using namespace RFC1035;

static uint32_t default_ttl = 3600;

class TestResolver : public Resolver
{
public:
  TestResolver() : Resolver() {}
  virtual ~TestResolver() {}

  std::map<Name, std::vector<ResourceRecord>> zones;

  virtual void add(const Name& origin, const ResourceRecord& r)
  {
    zones[origin].push_back(r);
  }

  virtual void for_each(
    const Name& origin,
    aDNS::QType qtype,
    aDNS::QClass qclass,
    const std::function<bool(const ResourceRecord&)>& f) override
  {
    auto oit = zones.find(origin);
    if (oit != zones.end())
    {
      for (const auto& rr : oit->second)
      {
        if (type_in_qtype(rr.type, qtype) && class_in_qclass(rr.class_, qclass))
          if (!f(rr))
            break;
      }
    }
  };
};

RFC1035::Message mk_question(const std::string& name, aDNS::QType type)
{
  RFC1035::Question q;
  q.qname = Name(name);
  q.qclass = static_cast<RFC1035::QClass>(RFC1035::Class::IN);
  q.qtype = static_cast<RFC1035::QType>(type);

  RFC1035::Message r;
  r.questions.push_back(q);
  r.header.qdcount = 1;
  return r;
}

ResourceRecord RR(
  const Name& name,
  aDNS::Type type,
  aDNS::Class class_,
  std::vector<uint8_t>&& data)
{
  return ResourceRecord(
    name,
    static_cast<uint16_t>(type),
    static_cast<uint16_t>(class_),
    default_ttl,
    data);
}

TEST_CASE("Basic lookups")
{
  TestResolver s;

  Name origin("example.com.");

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("www"),
      aDNS::Type::A,
      aDNS::Class::IN,
      RFC1035::A("93.184.216.34"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("wwwv6"),
      aDNS::Type::AAAA,
      aDNS::Class::IN,
      RFC3596::AAAA("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("www"),
      aDNS::Type::AAAA,
      aDNS::Class::IN,
      RFC3596::AAAA("FEDC:BA98:7654:3210:FEDC:BA98:7654:3211"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("sub"),
      aDNS::Type::NS,
      aDNS::Class::IN,
      RFC1035::NS("ns1.elsewhere.com."))));

  {
    RFC1035::Message msg = mk_question("www.example.com.", aDNS::QType::A);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    REQUIRE(
      response.answers[0].rdata == std::vector<uint8_t>{93, 184, 216, 34});
  }

  {
    RFC1035::Message msg = mk_question("wwwv6.example.com.", aDNS::QType::AAAA);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    /* clang-format off */
    REQUIRE(
      response.answers[0].rdata ==
      std::vector<uint8_t>{
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10});
    /* clang-format on */
  }

  {
    RFC1035::Message msg = mk_question("www.example.com.", aDNS::QType::AAAA);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    /* clang-format off */
    REQUIRE(
      response.answers[0].rdata ==
      std::vector<uint8_t>{
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11});
    /* clang-format on */
  }

  {
    RFC1035::Message msg = mk_question("sub.example.com.", aDNS::QType::NS);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    NS ns(response.answers[0].rdata);
    std::cout << (std::string)ns.nsdname << std::endl;
    REQUIRE(Name(response.answers[0].rdata) == Name("ns1.elsewhere.com."));
  }
}

TEST_CASE("DNSSEC RRs")
{
  TestResolver s;

  REQUIRE_NOTHROW(s.add(
    Name("example.com."),
    RR(
      Name("mykey"),
      aDNS::Type::DNSKEY,
      aDNS::Class::IN,
      RFC4034::DNSKEY("256 3 5 "
                      "AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/"
                      "0PY1kxkmvHjcZc8nokfzj31GajIQKY+"
                      "5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6"
                      "ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="))));

  {
    RFC1035::Message msg =
      mk_question("mykey.example.com.", aDNS::QType::DNSKEY);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    RFC4034::DNSKEY dnskey(response.answers[0].rdata);
    std::string sd = dnskey;
    std::cout << sd << std::endl;
    REQUIRE(sd.starts_with("256 3 5 AQPSK"));
  }
}

int main(int argc, char** argv)
{
  logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}