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

    nlohmann::json attestation;
    attestation["evidence"] =
      ccf::crypto::b64_from_raw(snp_attestation->get_raw());

    // Probably better to use node API to get fetched endorsement, but seems
    // like needs tweaks to be called in a unit test, so slapped a hardcoded
    // chain for the timebeing.
    attestation["endorsements"] =
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZRekNDQXZlZ0F3SUJBZ0lCQURCQkJn"
      "a3Foa2lHOXcwQkFRb3dOS0FQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZj"
      "TkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVEF3ZXpFVU1CSUdBMVVFQ3d3TApSVzVu"
      "YVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJH"
      "RnlZVEVMCk1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmtJRTFwWTNK"
      "dklFUmxkbWxqWlhNeEVqQVEKQmdOVkJBTU1DVk5GVmkxTmFXeGhiakFlRncweU5UQXhNak14"
      "T1RFME5URmFGdzB6TWpBeE1qTXhPVEUwTlRGYQpNSG94RkRBU0JnTlZCQXNNQzBWdVoybHVa"
      "V1Z5YVc1bk1Rc3dDUVlEVlFRR0V3SlZVekVVTUJJR0ExVUVCd3dMClUyRnVkR0VnUTJ4aGNt"
      "RXhDekFKQmdOVkJBZ01Ba05CTVI4d0hRWURWUVFLREJaQlpIWmhibU5sWkNCTmFXTnkKYnlC"
      "RVpYWnBZMlZ6TVJFd0R3WURWUVFEREFoVFJWWXRWa05GU3pCMk1CQUdCeXFHU000OUFnRUdC"
      "U3VCQkFBaQpBMklBQko5TzdiaVM4QzQ1VEEvaWhwVlZBTklQMTlGc0t1UEZyTWtEajI0WlJI"
      "MW9RVHZlZlJ4c1JabDk2UFdrCndZNjRvalAwd0hyRWJhNmt0dndBWWU4YkQyOVNFR1JFWWxG"
      "S3BzNHJSWXV4ZEkrcG5pYVhWNVVJNFlZUXlJb1MKMkNwY1NxT0NBUmN3Z2dFVE1CQUdDU3NH"
      "QVFRQm5IZ0JBUVFEQWdFQU1CY0dDU3NHQVFRQm5IZ0JBZ1FLRmdoTgphV3hoYmkxQ01EQVJC"
      "Z29yQmdFRUFaeDRBUU1CQkFNQ0FRUXdFUVlLS3dZQkJBR2NlQUVEQWdRREFnRUFNQkVHCkNp"
      "c0dBUVFCbkhnQkF3UUVBd0lCQURBUkJnb3JCZ0VFQVp4NEFRTUZCQU1DQVFBd0VRWUtLd1lC"
      "QkFHY2VBRUQKQmdRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdjRUF3SUJBREFSQmdvckJnRUVB"
      "Wng0QVFNREJBTUNBUmd3RWdZSwpLd1lCQkFHY2VBRURDQVFFQWdJQTJ6Qk5CZ2tyQmdFRUFa"
      "eDRBUVFFUUkyRW1EcjczS0VMU2lrNlhPSGJCcVhrCmpTckJmazJ4TWRQczBXUXZqWHZrbXNS"
      "MnZzWE1wemdpTE1lVmdOaTVXS2I1ZW1NeXA2eENndmZFRi92VFQ4NHcKUVFZSktvWklodmNO"
      "QVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTgpC"
      "Z2xnaGtnQlpRTUVBZ0lGQUtJREFnRXdBNElDQVFCcW5xTXhiS0tleW5BdmxHTktwYnYvZUdO"
      "eFlxcWJ0QUpVCk4rT3d3WUZhakYwejIwNXA5eGRmMkJrWFc2UTFhcVg0ekR4czFCbTNqU1hZ"
      "VlVWQ1pKcU5la3ZISDRXK2UyTFoKcUhTMmJiQ0pwRy9EVnBBTEUyWm1MNXdnQW1IdWE5azZ6"
      "TldHY0htS1F2QjJwVC8raVVqOEpLV0wweTN2SEtMZgpHdWRZZnBsSGpwbDRlTm5ueStoM0Fo"
      "SWMyNXhGNjNqdmE2TW1YMUQ4L1RDT25uZTUzZVFTZEZOMXNxS3hmOU5lClZrK0JBYUVDVlV3"
      "alNEOEpwUW0ySzJXSkhQR2hSK2orV1IraXNiZ01WNHRsZGpKb3NnVnNPSGh5bmFxbTk2R24K"
      "ZTdqMjllMWVSSk0wSmdjSEdUZHQxaTFuYlVscFlpRHpINzVwRjF2R283eFZrZ0FYSk1xLytI"
      "R041WHNSSkh5YgpOeC85bURyNmpxR000SW45SU80bmRyemJJd0VqVlB4T29MMkUzM1dxa2VD"
      "citqdUVTUzg1RS9CZlRyQVNjQVR5ClRYWkdnS3ZwRkdpajB6Q0hwTDNiL2V4SnowOTRVUDFI"
      "Qm9XeG94eEdJdVZueTZxV3BKSzBCa3BkeDB2enhZVVQKa2doRTFacjY1enFMRDJSRXhZQzlW"
      "SVVVZUJQaXdBM3FsaGJpUnY3OTdQOC92UktHREFWeXBaOE9VVkkveGIrVAovWGx5NWZLSFpv"
      "dHNkNC9INlFzSGE0K0VSdDlpU2VkYjlSUFp3T1h4UU1YTldBK0RIdzBlc1psekpxZmFENmUy"
      "CjFndFpXbnVwZkdYVDkvTDUrcTl0L0l1MkRFNUZydFYvaWcvbmpFZndqcXNoUTNHbVFNOVJU"
      "aXZzN1RSUHBEdysKemtWam1yNTNPdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0t"
      "LS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdD"
      "U3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3"
      "MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFz"
      "TUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVk"
      "R0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpD"
      "Qk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpB"
      "eE1ESXlNVGd5TkRJd1doY05ORFV4TURJeQpNVGd5TkRJd1dqQjdNUlF3RWdZRFZRUUxEQXRG"
      "Ym1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJ"
      "RU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RX"
      "bGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKVTBWV0xVMXBiR0Z1TUlJQ0lqQU5CZ2tx"
      "aGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBblUyZHJyTlRmYmhOUUlsbGYrVzJ5"
      "K1JPQ2JTeklkMWFLWmZ0CjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpT"
      "ek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXcKS1pYMEptUUV1WWptK1dLa3NMdHhnZExwOUU3"
      "RVpOd05EcVYxcjBxUlA1dEI4T1dreVFiSWRMZXU0YUN6N2ovUwpsMUZrQnl0ZXY5c2JGR3p0"
      "N2N3bmp6aTltN25vcXNrK3VSVkJwMytJbjM1UVBkY2o4WWZsRW1uSEJOdnVVREpoCkxDSk1X"
      "OEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThl"
      "azVFVkwKalpXSDFwdDlFM1RmcFI2WHlmUUtuWTZrbDVhRUlQd2RXM2VGWWFxQ0ZQcklvOXBR"
      "VDZXdURTUDRKQ1lKYlpuZQpLS0liWmp6WGtKdDNOUUczMkV1a1lJbUJiOVNDa205K2ZTNUxa"
      "Rmc5b2p6dWJNWDMrTmtCb1NYSTdPUHZuSE14Cmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9s"
      "bXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGwKQWxKdzVEMENUUlRDMVk1"
      "WVdGREJDckEvdkdubVRucUc4QytqalVBUzdjampSOHE0T1BoeURtSlJQbmFDL1pHNQp1UDBL"
      "MHo2R29PLzN1ZW45d3FzaEN1SGVnTFRwT2VIRUpSS3JRRnI0UFZJd1ZPQjArZWJPNUZnb3lP"
      "dzQzbnlGCkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhV"
      "dHJtUVdWMmhVand6cXd2SEYKZWk4clB4TUNBd0VBQWFPQm96Q0JvREFkQmdOVkhRNEVGZ1FV"
      "TzhadUdDckQvVDFpWkVpYjQ3ZEhMTFQ4di9ndwpId1lEVlIwakJCZ3dGb0FVaGF3YTBVUDN5"
      "S3hWMU1VZFFVaXIxWGhLMUZNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93SUJBREFPQmdOVkhR"
      "OEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXIKWkhO"
      "cGJuUm1MbUZ0WkM1amIyMHZkbU5sYXk5Mk1TOU5hV3hoYmk5amNtd3dSZ1lKS29aSWh2Y05B"
      "UUVLTURtZwpEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJn"
      "bGdoa2dCWlFNRUFnSUZBS0lECkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1Ux"
      "VnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEUKUEkxamgzZ0piTHhMNmdmM0s4anhjdHpP"
      "V25rWWNiZGZNT09yMjhLVDM1SWFBUjIwcmVrS1JGcHRUSGhlK0RGcgozQUZ6WkxERDdjV0sy"
      "OS9HcFBpdFBKREtDdkk3QTRVZzA2cms3SjB6QmUxZnovcWU0aTIvRjEycnZmd0NHWWhjClJ4"
      "UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6"
      "Sys1cGxWR0cKRnNqREp0TXoydWQ5eTBwdk9FNGozZEg1SVc5akd4YVNHU3RxTnJhYm5ucEYy"
      "MzZFVHIxL2E0M2I4RkZLTDVRTgptdDhWcjl4blhScHpucUNSdnFqcitrVnJiNmRsZnVUbGxp"
      "WGVRVE1sQm9SV0ZKT1JMOEFjQkp4R1o0SzJtWGZ0CmwxalU1VExlaDVLWEw5Tlc3YS9xQU9J"
      "VXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnIKRWc2emt4bXZNdWFi"
      "Wk9zZEtmUmtXZmhIMlpLY1RsRGZtSDFIMHpxMFEyYkczdXZhVmRpQ3RGWTFMbFd5QjM4SgpT"
      "MmZOc1IvUHk2dDVickVKQ0ZOdnphRGt5NktlQzRpb24vY1ZnVWFpN3p6UzNiR1FXektES1Uz"
      "NVNxTlUyV2tQCkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0Rnht"
      "V2lTbmZKbDY5MEI5ckpwTlIvZkkKYWp4Q1czU2Vpd3M2cjFabSt0Q3VWYk1pTnRwUzlUaGpO"
      "WDR1dmU1dGh5ZkUyRGdveFJGdlkxQ3NvRjVNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdZekNDQkJLZ0F3SUJBZ0lEQVFBQU1F"
      "WUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtp"
      "Rzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05W"
      "QkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUy"
      "RnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1O"
      "bFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNO"
      "TWpBeE1ESXlNVGN5TXpBMVdoY05ORFV4TURJeQpNVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxE"
      "QXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJu"
      "UmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldR"
      "Z1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKUVZKTExVMXBiR0Z1TUlJQ0lqQU5C"
      "Z2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpk"
      "c1ZtRDdGa3R1b3RXd1gxZk5nClc0MVhZOVh6MUhFaFNVbWhMejlDdTlESFJsdmdKU054YmVZ"
      "WXNuSmZ2eWp4MU1mVTBWNXRrS2lVMUVlc05GdGEKMWtUQTBzek5pc2RZYzlpc3FrN21YVDUr"
      "S2ZHUmJmYzRWLzl6UkljRThqbEhONjFTMWp1OFg5Mys2ZHhEVXJHMgpTenhxSjRCaHF5WW1V"
      "RHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwCjYw"
      "ZDM3alk5TEZldU9QNE1lcmk4cWdmaTJTNWtLcWcvYUY2YVB0dUFaUVZSN3UzS0ZZWFA1OVht"
      "Smd0Y29nMDUKZ21JMFQvT2l0TGh1elZ2cFpjTHBoMG9kaC8xSVBYcXgzK01uakQ5N0E3Zlhw"
      "cUdkL3k4S3hYN2prc1RFekFPZwpiS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5"
      "a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzCitnVkRrdVZQaHNueklSTmdZdk00OFkr"
      "N0xHaUpZbnJtRTh4Y3JleGVrQnhydmEyVjlUSlFxbk4zUTUza3Q1dmkKUWkzK2dDZm1rd0Mw"
      "RjB0aXJJWmJMa1hQclB3elowTTllTnhoSXlTYjJucEpmZ25xejU1STB1MzN3aDRyMFpOUQpl"
      "VEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5p"
      "dDJ1TG85TTE4CmZIejEwbE9NVDhuV0FVdlJaRnp0ZVhDbSs3UEhkWVBsbVF3VXczTHZlbkov"
      "SUxYb1FQSGZia0gwQ3lQZmhsMWoKV2hKRlphc0NBd0VBQWFOK01Id3dEZ1lEVlIwUEFRSC9C"
      "QVFEQWdFR01CMEdBMVVkRGdRV0JCU0ZyQnJSUS9mSQpyRlhVeFIxQlNLdlZlRXJVVXpBUEJn"
      "TlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHCktXaDBkSEJ6T2k4"
      "dmEyUnphVzUwWmk1aGJXUXVZMjl0TDNaalpXc3ZkakV2VFdsc1lXNHZZM0pzTUVZR0NTcUcK"
      "U0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQkFR"
      "Z3dEUVlKWUlaSQpBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9q"
      "Zmd5K3psZWVoc3g2b2wwb2NnVmVsCkVUb2JweCtFdUNzcVZGUlBLMWpaMXNwL2x5ZDkrMGZR"
      "MHI2Nm43a2FnUms0Q2EzOWc2NldHVEpNZUpkcVlyaXcKU1RqakRDS1ZQU2VzV1hZUFZBeURo"
      "bVA1bjJ2K0JZaXBaV2hwdnFwYWlPK0VHSzVJQlArNTc4UWVXL3NTb2tySwpkSGFMQXhHMkxo"
      "WnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0Q1RCMVlx"
      "CnpUNUR1d3ZBZStjbzJDSVZJek1EYW1ZdVNGalBOMEJDZ29qbDdWK2JUb3U3ZE1zcUl1L1RX"
      "L3JQQ1g5L0VVY3AKS0dLcVBRM1ArTjlyMWhqRUZZMXBsQmc5M3Q1M09PbzQ5R05JK1YxenZY"
      "UExJNnhJRlZzaCttdG8yUnRnRVgvZQpwbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2"
      "bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxCkhuSVloeHkwWUtYR3lhVzFOamZV"
      "THhycm14Vlc0d2NuNUU4R2RkbXZOYTZ5WW04c2NKYWdFaTEzbWhHdTRKcWgKM1FVM3NmOGlV"
      "U1VyMDl4UUR3SHRPUVVWSXF4NG1hQlpQQnRTTWYrcVVEdGpYU1NxOGxmV2NkOGJMcjltZHNV"
      "bgpKWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZ"
      "SitUdUJvYTRzK0hICkNWaUF2Z1Q5a2YvckJxMWQraXZqNnNra0h4dXpjeGJrMXh2NlpHeHJ0"
      "ZUp4Vkg3S2xYN1lSZFo2ZUFSS3dMZTQKQUZaRUF3b0tDUT09Ci0tLS0tRU5EIENFUlRJRklD"
      "QVRFLS0tLS0K";
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