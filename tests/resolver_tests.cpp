// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_pair.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/ds/logger.h>
#include <openenclave/3rdparty/openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <random>

using namespace aDNS;
using namespace RFC1035;

static uint32_t default_ttl = 3600;

auto type2str = [](const auto& x) {
  return aDNS::string_from_type(static_cast<aDNS::Type>(x));
};

class TestResolver : public Resolver
{
public:
  TestResolver() : Resolver() {}
  virtual ~TestResolver() {}

  std::map<
    Name,
    std::set<ResourceRecord, RFC4034::CanonicalRROrdering>,
    RFC4034::CanonicalNameOrdering>
    zones;

  virtual void add(const Name& origin, const ResourceRecord& rr) override
  {
    ResourceRecord rs(rr);
    if (!rs.name.is_absolute())
      rs.name += origin;

    LOG_DEBUG_FMT("Add: {}", string_from_resource_record(rs));

    zones[origin].insert(rs);
    Resolver::on_add(origin, rs);
  }

  virtual void remove(const Name& origin, const ResourceRecord& rr)
  {
    ResourceRecord rs(rr);
    if (!rs.name.is_absolute())
      rs.name += origin;

    LOG_DEBUG_FMT("Remove: {}", string_from_resource_record(rs));

    zones[origin].erase(rs);
  }

  virtual void remove(
    const Name& origin, const Name& name, const aDNS::Type& t) override
  {
    Name aname = name;
    if (!aname.is_absolute())
      aname += origin;

    auto& zone = zones[origin];
    std::erase_if(zone, [&aname, &t](const ResourceRecord& rr) {
      bool r = rr.type == static_cast<uint16_t>(t) && rr.name == aname;
      if (r)
        LOG_DEBUG_FMT("Remove: {}", string_from_resource_record(rr));
      return r;
    });
  }

  virtual void for_each(
    const Name& origin,
    aDNS::QClass qclass,
    aDNS::QType qtype,
    const std::function<bool(const ResourceRecord&)>& f) const override
  {
    auto oit = zones.find(origin);
    if (oit != zones.end())
    {
      for (const auto& rr : oit->second)
      {
        if (
          is_type_in_qtype(rr.type, qtype) &&
          is_class_in_qclass(rr.class_, qclass))
          if (!f(rr))
            break;
      }
    }
  };

  virtual void show(const Name& origin) const
  {
    LOG_DEBUG_FMT("Current entries at {}:", (std::string)origin);
    auto oit = zones.find(origin);
    if (oit != zones.end())
    {
      for (const auto& rr : oit->second)
        LOG_DEBUG_FMT(" {}", string_from_resource_record(rr));
    }
    else
      LOG_DEBUG_FMT("<empty>");
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

ResourceRecord RR(
  const Name& name,
  aDNS::Type type,
  aDNS::Class class_,
  small_vector<uint16_t>&& data)
{
  return ResourceRecord(
    name,
    static_cast<uint16_t>(type),
    static_cast<uint16_t>(class_),
    default_ttl,
    data);
}

TEST_CASE("Name ordering")
{
  // https://datatracker.ietf.org/doc/html/rfc4034#section-6.1

  REQUIRE(RFC4034::operator<(Name("a.example"), Name("z.example")));
  REQUIRE(RFC4034::operator<(Name("yljkjljk.a.example"), Name("*.z.example")));
  REQUIRE(RFC4034::operator<(Name("yljkjljk.a.example"), Name("Z.a.example")));
  REQUIRE(RFC4034::operator<(Name("example.com."), Name("www.example.com.")));
  REQUIRE(RFC4034::operator<(Name("example.com."), Name("wwwv6.example.com.")));
  REQUIRE(
    !RFC4034::operator<(Name("wwwv6.example.com."), Name("www.example.com.")));

  std::vector<Name> names = {
    Name("example"),
    Name("a.example"),
    Name("yljkjljk.a.example"),
    Name("Z.a.example"),
    Name("zABC.a.EXAMPLE"),
    Name("z.example"),
    Name("\001.z.example"),
    Name("*.z.example"),
    Name("\200.z.example")};

  std::vector<Name> shuffled = names;
  auto rng = std::default_random_engine{};
  std::shuffle(std::begin(shuffled), std::end(shuffled), rng);

  std::sort(shuffled.begin(), shuffled.end(), RFC4034::CanonicalNameOrdering());

  REQUIRE(names.size() == shuffled.size());
  for (size_t i = 0; i < names.size(); i++)
    REQUIRE(names[i] == shuffled[i]);
}

TEST_CASE("Basic lookups")
{
  TestResolver s;

  Name origin("example.com.");

  std::string soa_rdata =
    "ns1.example.com. joe.example.com. 4 604800 86400 2419200 604800";

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(origin, aDNS::Type::SOA, aDNS::Class::IN, RFC1035::SOA(soa_rdata))));

  {
    RFC1035::Message msg = mk_question("example.com.", aDNS::QType::SOA);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    SOA soa(response.answers[0].rdata);
    REQUIRE((std::string)soa == soa_rdata);
  }

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
      response.answers[0].rdata == small_vector<uint16_t>{93, 184, 216, 34});
  }

  {
    RFC1035::Message msg = mk_question("wwwv6.example.com.", aDNS::QType::AAAA);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    /* clang-format off */
    REQUIRE(
      response.answers[0].rdata ==
      small_vector<uint16_t>{
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
      small_vector<uint16_t>{
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11});
    /* clang-format on */
  }

  {
    RFC1035::Message msg = mk_question("sub.example.com.", aDNS::QType::NS);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    NS ns(response.answers[0].rdata);
    REQUIRE(Name(response.answers[0].rdata) == Name("ns1.elsewhere.com."));
  }

  s.show(origin);
}

TEST_CASE("DNSKEY RR Example")
{
  TestResolver s;

  Name origin("example.com.");

  std::string demo_key_b64 =
    "AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+"
    "5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742i"
    "U/TpPSEDhm2SNKLijfUppn1UaNvv4w==";

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("mykey"),
      aDNS::Type::DNSKEY,
      aDNS::Class::IN,
      RFC4034::DNSKEY("256 3 5 " + demo_key_b64))));

  {
    RFC1035::Message msg =
      mk_question("mykey.example.com.", aDNS::QType::DNSKEY);
    auto response = s.reply(msg);
    REQUIRE(response.answers.size() > 0);
    RFC4034::DNSKEY dnskey(response.answers[0].rdata);
    std::string sd = dnskey;
    REQUIRE(sd == "256 3 5 " + demo_key_b64);
  }
}

std::vector<uint8_t> der_from_coord(const small_vector<uint16_t>& coordinates)
{
  auto csz = coordinates.size() / 2;
  const uint8_t* x = &coordinates[0];
  const uint8_t* y = &coordinates[csz];
  BIGNUM* xbn = BN_new();
  BIGNUM* ybn = BN_new();
  BN_bin2bn(x, csz, xbn);
  BN_bin2bn(y, csz, ybn);
  EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp384r1);
  EC_POINT* p = EC_POINT_new(g);
  BN_CTX* bnctx = BN_CTX_new();
  if (EC_POINT_set_affine_coordinates(g, p, xbn, ybn, bnctx) != 1)
    throw std::runtime_error("could not set EC point coordinates");
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  if (EC_KEY_set_public_key(ec_key, p) != 1)
    throw std::runtime_error("could not create EC key");
  auto size = i2d_EC_PUBKEY(ec_key, NULL);
  std::vector<uint8_t> der(size, 0);
  unsigned char* derptr = (unsigned char*)&der[0];
  i2d_EC_PUBKEY(ec_key, &derptr);
  LOG_DEBUG_FMT("VERIFY: der={}", ds::to_hex(der));
  EC_KEY_free(ec_key);
  BN_CTX_free(bnctx);
  EC_POINT_free(p);
  EC_GROUP_free(g);
  BN_free(xbn);
  BN_free(ybn);
  return der;
};

static void convert_signature_to_asn1(std::vector<uint8_t>& sig)
{
  auto csz = sig.size() / 2;
  BIGNUM* r = BN_new();
  BIGNUM* s = BN_new();
  BN_bin2bn(sig.data(), csz, r);
  BN_bin2bn(sig.data() + csz, csz, s);
  ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
  ECDSA_SIG_set0(ecdsa_sig, r, s);
  auto outsz = i2d_ECDSA_SIG(ecdsa_sig, NULL);
  sig.resize(outsz, 0);
  unsigned char* outp = sig.data();
  i2d_ECDSA_SIG(ecdsa_sig, &outp);
}

static bool verify(
  const RFC4034::CanonicalRRSet& rrset,
  const RFC4034::CanonicalRRSet& rrsigset,
  const small_vector<uint16_t>& public_key)
{
  auto pk = crypto::make_public_key(der_from_coord(public_key));

  for (const auto& rrsig : rrsigset)
  {
    RFC4034::RRSIG rrsig_rdata(rrsig.rdata, type2str);
    REQUIRE(rrsig_rdata.signer_name.is_absolute());
    LOG_DEBUG_FMT("VERIFY: rrsig: {}", string_from_resource_record(rrsig));

    std::vector<uint8_t> data_to_sign = rrsig_rdata.all_but_signature();
    for (const auto& rr : rrset)
    {
      LOG_DEBUG_FMT("VERIFY: rr: {}", string_from_resource_record(rr));
      rr.name.put(data_to_sign);
      put(rr.type, data_to_sign);
      put(rr.class_, data_to_sign);
      put(rrsig_rdata.original_ttl, data_to_sign);
      rr.rdata.put(data_to_sign);
    }

    LOG_DEBUG_FMT("VERIFY: data={}", ds::to_hex(data_to_sign));
    auto sig = rrsig_rdata.signature;
    convert_signature_to_asn1(sig);
    LOG_DEBUG_FMT("VERIFY: sig={}", ds::to_hex(sig));
    auto r = pk->verify(data_to_sign, sig);
    LOG_DEBUG_FMT("VERIFY: r={}", r);
    if (!r)
      return false;
  }

  return true;
}

TEST_CASE("RRSIG tests")
{
  TestResolver s;

  Name origin("example.com.");
  {
    REQUIRE_NOTHROW(s.add(
      origin,
      RR(
        origin,
        aDNS::Type::SOA,
        aDNS::Class::IN,
        RFC1035::SOA(
          "ns1.example.com. joe.example.com. 4 604800 86400 2419200 604800"))));

    REQUIRE_NOTHROW(s.add(
      origin,
      RR(Name("www"), aDNS::Type::A, aDNS::Class::IN, RFC1035::A("1.2.3.4"))));

    REQUIRE_NOTHROW(s.add(
      origin,
      RR(
        Name("www"),
        aDNS::Type::TXT,
        aDNS::Class::IN,
        RFC1035::TXT("some text"))));

    auto r =
      s.resolve(origin, aDNS::QType::DNSKEY, aDNS::QClass::IN, true).answers;
    ResourceRecord key, key_rrsig;
    for (const auto& rr : r)
    {
      LOG_DEBUG_FMT("A: {}", string_from_resource_record(rr));
      if (rr.type == static_cast<uint16_t>(aDNS::Type::RRSIG))
        key_rrsig = rr;
      else if (rr.type == static_cast<uint16_t>(aDNS::Type::DNSKEY))
        key = rr;
    }
    RFC4034::DNSKEY dnskey_rdata(key.rdata);
    RFC4034::RRSIG rrsig_rdata(key_rrsig.rdata, type2str);
    REQUIRE(dnskey_rdata.is_zone_key());
    REQUIRE(verify({key}, {key_rrsig}, dnskey_rdata.public_key));

    s.show(origin);
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