// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"
#include "rfc1035.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace aDNS;
using namespace RFC1035;

std::vector<uint8_t> str2vec(const std::string& s)
{
  return {s.data(), s.data() + s.size()};
}

class TestResolver : public Resolver
{
public:
  TestResolver() : Resolver() {}
  virtual ~TestResolver() {}

  std::map<Name, Zone> zones;

  virtual void update(const Name& origin, const Zone& zone) override
  {
    zones[origin] = zone;
    Resolver::update(origin, zone);
  }

  virtual Zone zone(const Name& name) override
  {
    return zones[name];
  }
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

TEST_CASE("Basic lookups")
{
  TestResolver s;

  Zone d;
  d.records.push_back({.name = "www", .type = "A", .data = "93.184.216.34"});
  d.records.push_back(
    {.name = "wwwv6",
     .type = "AAAA",
     .data = "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"});
  d.records.push_back(
    {.name = "www",
     .type = "AAAA",
     .data = "FEDC:BA98:7654:3210:FEDC:BA98:7654:3211"});
  d.records.push_back(
    {.name = "sub", .type = "NS", .data = "ns1.elsewhere.com."});

  {
    REQUIRE_NOTHROW(s.update(Name("example.com."), d));
  }

  {
    auto z = s.zone(Name("example.com."));
    REQUIRE(z.records.size() == d.records.size());
  }

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
    REQUIRE(
      Name(response.answers[0].rdata, SIZE_MAX) == Name("ns1.elsewhere.com."));
  }
}

TEST_CASE("DNSSEC RRs")
{
  TestResolver s;

  Zone d;
  d.records.push_back(
    {.name = "mykey",
     .type = "DNSKEY",
     .data = "256 3 5 "
             "AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/"
             "0PY1kxkmvHjcZc8nokfzj31GajIQKY+"
             "5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOzt"
             "yvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="});

  REQUIRE_NOTHROW(s.update(Name("example.com."), d));

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