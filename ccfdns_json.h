// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
      throw JsonParseError(fmt::format( \
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
    throw JsonParseError(fmt::format(
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
    throw JsonParseError(
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
}

namespace ccfdns
{
  DECLARE_JSON_TYPE(ZoneKeyInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    ZoneKeyInfo, key_signing_keys, zone_signing_keys);
}
