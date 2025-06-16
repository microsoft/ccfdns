// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccfdns_rpc_types.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"

#include <ccf/ds/json.h>

#define DECLARE_JSON_STRINGIFIED(TYPE, PATTERN) \
  inline void to_json(nlohmann::json& j, const TYPE& t) \
  { \
    j = nlohmann::json::string_t(t); \
  } \
  inline void from_json(const nlohmann::json& j, TYPE& t) \
  { \
    if (!j.is_string()) \
    { \
      throw ccf::JsonParseError(fmt::format( \
        "Cannot parse " #TYPE ": expected string, got {}", j.dump())); \
    } \
    t = TYPE(j.get<std::string>()); \
  } \
  inline std::string schema_name(const TYPE*) \
  { \
    return #TYPE; \
  } \
  inline void fill_json_schema(nlohmann::json& schema, const TYPE*) \
  { \
    schema["type"] = "string"; \
    schema["pattern"] = PATTERN; \
  }

// small_vector<uint16_t>
inline void to_json(nlohmann::json& j, const small_vector<uint16_t>& t)
{
  j = t.to_base64();
}

inline void from_json(const nlohmann::json& j, small_vector<uint16_t>& t)
{
  if (!j.is_string())
  {
    throw ccf::JsonParseError(fmt::format(
      "Cannot parse small_vector<uint16_t>: expected base64-encoded string, "
      "got {}",
      j.dump()));
  }
  t = small_vector<uint16_t>::from_base64(j.get<std::string>());
}

inline std::string schema_name(const small_vector<uint16_t>*)
{
  return "small_vector<uint16_t>";
}

inline void fill_json_schema(
  nlohmann::json& schema, const small_vector<uint16_t>*)
{
  schema["type"] = "small_vector<uint16_t>";
}

// aDNS::Type
inline void to_json(nlohmann::json& j, const aDNS::Type& t)
{
  j = string_from_type(t);
}

inline void from_json(const nlohmann::json& j, aDNS::Type& t)
{
  if (!j.is_string())
    throw ccf::JsonParseError(
      fmt::format("Cannot parse aDNS::Type: invalid datatype {}", j.dump()));
  t = aDNS::type_from_string(j.get<std::string>());
}

inline std::string schema_name(const aDNS::Type*)
{
  return "aDNS::Type";
}

inline void fill_json_schema(nlohmann::json& schema, const aDNS::Type*)
{
  schema["type"] = "aDNS::Type";
}

namespace RFC1035
{
  DECLARE_JSON_STRINGIFIED(Name, "^[A-Za-z0-9]+(\\.[A-Za-z0-9]+)+$");

  DECLARE_JSON_TYPE(ResourceRecord);
  DECLARE_JSON_REQUIRED_FIELDS(ResourceRecord, name, type, class_, ttl, rdata);
}

namespace RFC4034
{
  DECLARE_JSON_ENUM(
    Algorithm,
    {
      {Algorithm::DELETE, "DELETE"},
      {Algorithm::RSAMD5, "RSAMD5"},
      {Algorithm::DH, "DH"},
      {Algorithm::DSA, "DSA"},
      {Algorithm::RESERVED1, "RESERVED1"},
      {Algorithm::RSASHA1, "RSASHA1"},
      {Algorithm::DSA_NSEC3_SHA1, "DSA_NSEC3_SHA1"},
      {Algorithm::RSASHA1_NSEC3_SHA1, "RSASHA1_NSEC3_SHA1"},
      {Algorithm::RSASHA256, "RSASHA256"},
      {Algorithm::RESERVED2, "RESERVED2"},
      {Algorithm::RSASHA512, "RSASHA512"},
      {Algorithm::RESERVED3, "RESERVED3"},
      {Algorithm::ECC_GOST, "ECC_GOST"},
      {Algorithm::ECDSAP256SHA256, "ECDSAP256SHA256"},
      {Algorithm::ECDSAP384SHA384, "ECDSAP384SHA384"},
      {Algorithm::ED25519, "ED25519"},
      {Algorithm::ED448, "ED448"},
      {Algorithm::INDIRECT, "INDIRECT"},
      {Algorithm::PRIVATE_DNS, "PRIVATE_DNS"},
      {Algorithm::PRIVATE_OID, "PRIVATE_OID"},
      {Algorithm::RESERVED4, "RESERVED4"},
    });

  DECLARE_JSON_ENUM(
    DigestType,
    {{DigestType::RESERVED, "RESERVED"},
     {DigestType::SHA1, "SHA1"},
     {DigestType::SHA256, "SHA256"},
     {DigestType::GOST_R, "GOST_R"},
     {DigestType::SHA384, "SHA384"}});
}

namespace RFC5155
{
  DECLARE_JSON_ENUM(
    HashAlgorithm,
    {{HashAlgorithm::RESERVED, "RESERVED"}, {HashAlgorithm::SHA1, "SHA1"}});
}

namespace aDNS
{
  DECLARE_JSON_TYPE(Resolver::Configuration::ServiceCA);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::Configuration::ServiceCA, name, directory, ca_certificates);

  DECLARE_JSON_TYPE(Resolver::NodeAddress);
  DECLARE_JSON_REQUIRED_FIELDS(Resolver::NodeAddress, name, ip, protocol, port);

  DECLARE_JSON_TYPE(Resolver::NodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(Resolver::NodeInfo, address, attestation);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Resolver::Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::Configuration,
    origin,
    soa,
    default_ttl,
    signing_algorithm,
    digest_type,
    use_key_signing_key,
    use_nsec3,
    nsec3_hash_algorithm,
    nsec3_hash_iterations,
    nsec3_salt_length,
    node_addresses);
  DECLARE_JSON_OPTIONAL_FIELDS(Resolver::Configuration, alternative_names);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Resolver::RegistrationInformation);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::RegistrationInformation, public_key, csr, node_information);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Resolver::RegistrationInformation, dnskey_records);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Resolver::RegistrationRequest);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::RegistrationRequest, csr, node_information);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Resolver::RegistrationRequest, configuration_receipt);
}

namespace ccfdns
{
  DECLARE_JSON_TYPE(ZoneKeyInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    ZoneKeyInfo, key_signing_keys, zone_signing_keys);

  DECLARE_JSON_TYPE(Configure::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Configure::Out, registration_info);

  DECLARE_JSON_TYPE(AddRecord::In);
  DECLARE_JSON_REQUIRED_FIELDS(AddRecord::In, origin, record);

  DECLARE_JSON_TYPE(RemoveAll::In);
  DECLARE_JSON_REQUIRED_FIELDS(RemoveAll::In, origin, name, class_, type);

  DECLARE_JSON_TYPE(Resign::In);
  DECLARE_JSON_REQUIRED_FIELDS(Resign::In, origin);

  DECLARE_JSON_TYPE(SetServiceDefinition::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    SetServiceDefinition::In, service_name, policy, attestation);

  DECLARE_JSON_TYPE(SetPlatformDefinition::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    SetPlatformDefinition::In, platform, policy, attestation);
}
