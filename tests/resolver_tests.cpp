// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "base32.h"
#include "formatting.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/_private/crypto/openssl/hash.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/sha256.h>
#include <ccf/ds/logger.h>
#include <ccf/ds/quote_info.h>
#include <ccf/pal/snp_ioctl.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <random>

using namespace aDNS;
using namespace RFC1035;
using namespace ccf::crypto::OpenSSL;

static uint32_t default_ttl = 86400;

auto type2str = [](const auto& x) {
  return aDNS::string_from_type(static_cast<aDNS::Type>(x));
};

static std::vector<uint8_t> slurp_file(const std::string& file)
{
  std::ifstream f(file, std::ios::binary | std::ios::ate);
  assert(f);

  auto size = f.tellg();
  f.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(size);
  f.read((char*)data.data(), size);

  std::cout << "Read " << size << " bytes from file: " << file << std::endl;

  assert(f);
  return data;
}

static std::string slurp_file_string(const std::string& file)
{
  auto v = slurp_file(file);
  return {v.begin(), v.end()};
}

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
  std::set<Name, RFC4034::CanonicalNameOrdering> origins;

  std::map<Name, ccf::crypto::Pem, RFC4034::CanonicalNameOrdering>
    key_signing_keys;
  std::map<Name, ccf::crypto::Pem, RFC4034::CanonicalNameOrdering>
    zone_signing_keys;

  std::string service_registration_policy_str;

  Resolver::Configuration configuration;

  ccf::crypto::KeyPairPtr service_key{};

  virtual Configuration get_configuration() const override
  {
    return configuration;
  }

  virtual void set_configuration(const Configuration& cfg) override
  {
    configuration = cfg;
  }

  virtual void add(const Name& origin, const ResourceRecord& rr) override
  {
    ResourceRecord rs(rr);
    if (!rs.name.is_absolute())
      rs.name += origin;

    CCF_APP_DEBUG(
      "Add: {} to {}", string_from_resource_record(rs), std::string(origin));

    origins.insert(origin.lowered());
    zones[origin].insert(rs);
  }

  virtual void remove(const Name& origin, const ResourceRecord& rr)
  {
    ResourceRecord rs(rr);
    if (!rs.name.is_absolute())
      rs.name += origin;

    CCF_APP_DEBUG("Remove: {}", string_from_resource_record(rs));

    zones[origin].erase(rs);
  }

  virtual void remove(
    const Name& origin, const Name& name, aDNS::Class c, aDNS::Type t) override
  {
    auto& zone = zones[origin];
    std::erase_if(zone, [&name, &c, &t](const ResourceRecord& rr) {
      bool r = rr.type == static_cast<uint16_t>(t) && rr.name == name &&
        rr.class_ == static_cast<uint16_t>(c);
      if (r)
        CCF_APP_DEBUG("Remove: {}", string_from_resource_record(rr));
      return r;
    });
  }

  virtual void remove(const Name& origin, aDNS::Class c, aDNS::Type t) override
  {
    auto& zone = zones[origin];
    std::erase_if(zone, [&c, &t](const ResourceRecord& rr) {
      bool r = rr.type == static_cast<uint16_t>(t) &&
        rr.class_ == static_cast<uint16_t>(c);
      if (r)
        CCF_APP_DEBUG("Remove: {}", string_from_resource_record(rr));
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
  }

  virtual void for_each(
    const Name& origin,
    const Name& qname,
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
          rr.name == qname && is_type_in_qtype(rr.type, qtype) &&
          is_class_in_qclass(rr.class_, qclass))
          if (!f(rr))
            break;
      }
    }
  }

  virtual bool origin_exists(const Name& origin) const override
  {
    return origins.contains(origin.lowered());
  }

  virtual ccf::crypto::Pem get_private_key(
    const Name& origin,
    uint16_t tag,
    const small_vector<uint16_t>& public_key,
    bool key_signing) override
  {
    auto configuration = get_configuration();

    if (configuration.use_key_signing_key && key_signing)
      return key_signing_keys[origin];
    else
      return zone_signing_keys[origin];
  }

  virtual void on_new_signing_key(
    const Name& origin,
    uint16_t tag,
    const ccf::crypto::Pem& pem,
    bool key_signing) override
  {
    auto configuration = get_configuration();

    if (configuration.use_key_signing_key && key_signing)
      key_signing_keys[origin] = pem;
    else
      zone_signing_keys[origin] = pem;
  }

  virtual void show(const Name& origin) const
  {
    CCF_APP_DEBUG("Current entries at {}:", std::string(origin));
    auto oit = zones.find(origin);
    if (oit != zones.end())
    {
      for (const auto& rr : oit->second)
        CCF_APP_DEBUG(" {}", string_from_resource_record(rr));
    }
    else
      CCF_APP_DEBUG("<empty>");
  }

  virtual std::string service_registration_policy() const override
  {
    return service_registration_policy_str;
  }

  virtual void set_service_registration_policy(
    const std::string& new_policy) override
  {
    service_registration_policy_str = new_policy;
  }

  virtual bool evaluate_service_registration_policy(
    const std::string& data) const override
  {
    return true;
  }

  uint32_t get_fresh_time() override
  {
    return 0;
  }

  virtual void save_service_registration_request(
    const Name& name, const RegistrationRequest& rr) override
  {}

  virtual std::map<std::string, Resolver::NodeInfo> get_node_information()
    override
  {
    std::map<std::string, Resolver::NodeInfo> r;
    for (const auto& [id, addr] : configuration.node_addresses)
      r[id] = {.address = addr, .attestation = get_attestation()};
    return r;
  }

  std::string get_dummy_attestation()
  {
    const std::string measurement_literal =
      "Insecure hard-coded virtual measurement v1";
    const std::string measurement = ccf::crypto::b64_from_raw(
      (uint8_t*)measurement_literal.data(), measurement_literal.size());

    auto key_der = get_service_key()->public_key_der();
    auto key_digest = ccf::crypto::sha256(key_der);
    auto report_data = ccf::crypto::b64_from_raw(key_digest);

    nlohmann::json evidence_json;
    evidence_json["measurement"] = measurement;
    evidence_json["report_data"] = report_data;
    auto evidence_str = evidence_json.dump();
    auto evidence_encoded = ccf::crypto::b64_from_raw(
      (uint8_t*)evidence_str.data(), evidence_str.size());

    nlohmann::json attestation;
    attestation["evidence"] = evidence_encoded;
    attestation["endorsements"] = "";
    attestation["uvm_endorsements"] = "";
    return attestation.dump();
  }

  std::string get_snp_attestation()
  {
    auto key_der = get_service_key()->public_key_der();
    auto key_digest = ccf::crypto::sha256(key_der);
    assert(key_digest.size() == ccf::crypto::Sha256Hash::SIZE);
    const std::span<const uint8_t, ccf::crypto::Sha256Hash::SIZE> as_span(
      key_digest.data(), key_digest.data() + key_digest.size());
    auto snp_attestation = ccf::pal::snp::get_attestation(
      ccf::crypto::Sha256Hash::from_span(as_span));

    // UVM_SECURITY_CONTEXT_DIR is set in cmake, so must be run via ctest (or
    // ./tests.sh), or set it manually.
    const std::string endorsements_path =
      std::getenv("UVM_SECURITY_CONTEXT_DIR");
    assert(!endorsements_path.empty());
    auto endorsements = slurp_file_string(endorsements_path + "/host-amd-cert-base64");

    nlohmann::json attestation;
    attestation["evidence"] =
      ccf::crypto::b64_from_raw(snp_attestation->get_raw());
    attestation["endorsements"] = endorsements;
    attestation["uvm_endorsements"] = "";
    return attestation.dump();
  }

  std::string get_attestation()
  {
#if defined(PLATFORM_VIRTUAL)
    return get_dummy_attestation();
#elif defined(PLATFORM_SNP)
    return get_snp_attestation();
#else
    throw std::exception("Bad platform");
#endif
  }

  ccf::crypto::KeyPairPtr get_service_key(bool refresh = false)
  {
    if (refresh || !service_key)
    {
      service_key = ccf::crypto::make_key_pair(ccf::crypto::CurveID::SECP384R1);
    }
    return service_key;
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
    type == aDNS::Type::SOA ? 0 : default_ttl,
    data);
}

TEST_CASE("base32hex encoding")
{
  std::string s = "A2B3C4D5E4";
  auto raw = base32hex_decode(s);
  auto b32 = base32hex_encode(raw);
  REQUIRE(b32 == s);

  s = "A2B3C4D";
  raw = base32hex_decode(s);
  b32 = base32hex_encode(raw);
  REQUIRE(b32 == "A2B3C48");

  s = "A2";
  raw = base32hex_decode(s);
  b32 = base32hex_encode(raw);
  REQUIRE(b32 == "A0");
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

  Resolver::Names ns;
  for (const auto& n : names)
    ns.insert(n);
  size_t i = 0;
  for (const auto& n : ns)
    REQUIRE(names[i++] == n);
}

TEST_CASE("Name ordering 2")
{
  Resolver::Names names;
  names.insert(Name("adns.ccf.dev."));
  names.insert(Name("_acme-challenge.adns.ccf.dev."));
  names.insert(Name("ns1.adns.ccf.dev."));
  names.insert(Name("_acme-challenge.ns1.adns.ccf.dev."));
  names.insert(Name("_0.attest.ns1.adns.ccf.dev."));

  auto r = Resolver::find_preceding(
    names, Name("adns.ccf.dev."), Name("kr79a5s1m6.adns.ccf.dev."));
  REQUIRE(r == Name("_acme-challenge.adns.ccf.dev."));
}

const ResourceRecord& first(
  const std::vector<ResourceRecord>& rrs, aDNS::Type type)
{
  for (const auto& rr : rrs)
    if (rr.type == static_cast<uint16_t>(type))
      return rr;
  throw std::runtime_error("expected resource record not found");
}

TEST_CASE("Basic lookups")
{
  TestResolver s;

  Name origin("example.com.");

  std::string soa_rdata =
    "ns1.example.com. joe.example.com. 4 604800 86400 2419200 0";

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(origin, aDNS::Type::SOA, aDNS::Class::IN, RFC1035::SOA(soa_rdata))));

  {
    RFC1035::Message msg = mk_question("example.com.", aDNS::QType::SOA);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    size_t num_soa = 0;
    for (const auto& rr : response.answers)
    {
      if (rr.type == static_cast<uint16_t>(aDNS::Type::SOA))
      {
        SOA soa(rr.rdata);
        REQUIRE((std::string)soa == soa_rdata);
        num_soa++;
      }
    }
    REQUIRE(num_soa == 1);
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
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    REQUIRE(
      response.answers[0].rdata == small_vector<uint16_t>{93, 184, 216, 34});
  }

  {
    RFC1035::Message msg = mk_question("WwW.ExAmPlE.CoM.", aDNS::QType::A);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    REQUIRE(
      response.answers[0].rdata == small_vector<uint16_t>{93, 184, 216, 34});
  }

  {
    RFC1035::Message msg = mk_question("wwwv6.example.com.", aDNS::QType::AAAA);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    REQUIRE(
      response.answers[0].rdata ==
      small_vector<uint16_t>{
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10});
  }

  {
    RFC1035::Message msg = mk_question("www.example.com.", aDNS::QType::AAAA);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    REQUIRE(
      response.answers[0].rdata ==
      small_vector<uint16_t>{
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x11});
  }

  {
    RFC1035::Message msg = mk_question("sub.example.com.", aDNS::QType::NS);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() > 0);
    NS ns(response.answers[0].rdata);
    REQUIRE(Name(response.answers[0].rdata) == Name("ns1.elsewhere.com."));
  }

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("_acme-challenge.service42") + origin,
      aDNS::Type::TXT,
      aDNS::Class::IN,
      RFC1035::TXT("some text"))));

  REQUIRE_NOTHROW(s.sign(origin));

  {
    RFC1035::Message msg =
      mk_question("_AcMe-CHAllENGE.sErvice42.eXaMple.com.", aDNS::QType::TXT);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() >= 2);
    auto rr = first(response.answers, aDNS::Type::TXT);
    TXT txt(rr.rdata);
    REQUIRE(txt.strings.size() == 1);
    REQUIRE(txt.strings[0] == small_vector<uint8_t>{"some text"});
  }

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("AnOther") + origin,
      aDNS::Type::TXT,
      aDNS::Class::IN,
      RFC1035::TXT(std::vector<std::string>{"some", "texts"}))));

  REQUIRE_NOTHROW(s.sign(origin));

  {
    RFC1035::Message msg =
      mk_question("AnOther.eXaMple.com.", aDNS::QType::TXT);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() >= 2);
    auto rr = first(response.answers, aDNS::Type::TXT);
    TXT txt(rr.rdata);
    REQUIRE(txt.strings.size() == 2);
    REQUIRE(txt.strings[0] == small_vector<uint8_t>("some"));
    REQUIRE(txt.strings[1] == small_vector<uint8_t>("texts"));
  }

  {
    // Test unsupported type
    RFC1035::Message msg =
      mk_question("www.example.com.", static_cast<aDNS::QType>(9999));
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() == 0);
    REQUIRE(response.header.rcode == ResponseCode::NO_ERROR);
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

  REQUIRE_NOTHROW(s.sign(origin));

  {
    RFC1035::Message msg =
      mk_question("mykey.example.com.", aDNS::QType::DNSKEY);
    auto response = s.reply(msg).message;
    REQUIRE(response.answers.size() == 2);
    auto& a = response.answers;
    auto& key =
      (a[0].type == static_cast<uint16_t>(RFC4034::Type::DNSKEY)) ? a[0] : a[1];
    RFC4034::DNSKEY dnskey(key.rdata);
    std::string sd = dnskey;
    REQUIRE(sd == "256 3 5 " + demo_key_b64);
  }
}

TEST_CASE("Record ordering")
{
  Name origin("example.com.");

  aDNS::ResourceRecord rr1 = RR(
    origin,
    aDNS::Type::DNSKEY,
    aDNS::Class::IN,

    RFC4034::DNSKEY(
      "256 3 14 "
      "IG7n29Kh3trUUZ9qbrqMEA674xv3bGQAqDGhQQt8s0k4Ik3bAmWmh4wMZBGQ9WAUTDg7FL1w"
      "IVP1xH/DL85sEzgk+g65jvEVpLh3U19PWzBRpNZN3yeKeVDzIN6OoKvS"));

  aDNS::ResourceRecord rr2 = RR(
    origin,
    aDNS::Type::DNSKEY,
    aDNS::Class::IN,
    RFC4034::DNSKEY(
      "257 3 14 "
      "RRCiP/"
      "zvumIdsulWz4OjS5Lx7GDeYtu6e+gCRq9ccXsGDCd3RPnR+7nqZgR1Sa0cYpIE2XVIdwCE/"
      "6NEK4cltZLVOHmE30lxc17I4UKlU5PB3C+InEc7FIYn7h7IUUQ6"));

  REQUIRE(RFC4034::operator<(rr1, rr2));
  REQUIRE(!(RFC4034::operator<(rr2, rr1)));
  REQUIRE(rr1 != rr2);
  REQUIRE_FALSE(rr1 == rr2);
}

TEST_CASE("RRSIG tests")
{
  TestResolver s;

  Name origin("example.com.");

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      origin,
      aDNS::Type::SOA,
      aDNS::Class::IN,
      RFC1035::SOA(
        "ns1.example.com. joe.example.com. 4 604800 86400 2419200 0"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(Name("www"), aDNS::Type::A, aDNS::Class::IN, RFC1035::A("1.2.3.4"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(Name("www"), aDNS::Type::A, aDNS::Class::IN, RFC1035::A("1.2.3.5"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("sometext"),
      aDNS::Type::TXT,
      aDNS::Class::IN,
      RFC1035::TXT("some text"))));

  REQUIRE_NOTHROW(s.add(
    origin,
    RR(
      Name("www"),
      aDNS::Type::TXT,
      aDNS::Class::IN,
      RFC1035::TXT("some text"))));

  REQUIRE_NOTHROW(s.sign(origin));

  auto dnskey_rrs =
    s.resolve(origin, aDNS::QType::DNSKEY, aDNS::QClass::IN).answers;
  REQUIRE(RFC4034::verify_rrsigs(dnskey_rrs, dnskey_rrs, type2str));

  auto r = s.resolve(origin, aDNS::QType::SOA, aDNS::QClass::IN);
  REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));

  r = s.resolve(Name("www.example.com."), aDNS::QType::A, aDNS::QClass::IN);
  REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));

  r = s.resolve(
    Name("sometext.example.com."), aDNS::QType::TXT, aDNS::QClass::IN);
  REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));

  s.show(origin);
}

TEST_CASE("Service registration")
{
  TestResolver s;

  Resolver::Configuration cfg;
  cfg = {
    .origin = Name("example.com."),
    .soa = "ns1.example.com. joe.example.com. 4 604800 86400 2419200 0",
    .node_addresses =
      {{"id",
        Resolver::NodeAddress{
          .name = Name("ns1.example.com."),
          .ip = "127.0.0.1",
          .protocol = "tcp",
          .port = 53}}},
  };
  s.configure(cfg);

  Name service_name("service42.example.com.");
  std::string url_name = service_name.unterminated();

  RFC1035::A address("192.168.0.1");

  auto csr = s.get_service_key()->create_csr_der(
    "CN=" + url_name, {{"alt." + url_name, false}});

  s.register_service(
    {csr, {{"id", {{url_name, address, "tcp", 443}, s.get_attestation()}}}});

  auto dnskey_rrs =
    s.resolve(cfg.origin, aDNS::QType::DNSKEY, aDNS::QClass::IN).answers;
  REQUIRE(RFC4034::verify_rrsigs(dnskey_rrs, dnskey_rrs, type2str));

  auto r = s.resolve(
    Name("_443._tcp") + service_name, aDNS::QType::TLSA, aDNS::QClass::IN);
  REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));

  // Not implemented yet
  // r = s.resolve(service_name, aDNS::QType::ATTEST, aDNS::QClass::IN);
  // REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));

  r = s.resolve(service_name, aDNS::QType::A, aDNS::QClass::IN);
  REQUIRE(RFC4034::verify_rrsigs(r.answers, dnskey_rrs, type2str));
}

int main(int argc, char** argv)
{
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}