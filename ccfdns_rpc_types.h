// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccfdns_json.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/crypto/pem.h>
#include <ccf/ds/json.h>
#include <cstdint>

namespace ccfdns
{

  struct AddRecord
  {
    struct In
    {
      aDNS::Name origin;
      aDNS::ResourceRecord record;
    };
    using Out = void;
  };

  typedef AddRecord RemoveRecord;

  struct InstallACMEToken
  {
    struct In
    {
      aDNS::Name origin;
      aDNS::Name name;
      std::string key_authorization;
    };
    using Out = void;
  };
  
  struct RemoveACMEToken
  {
    struct In {
      aDNS::Name origin; 
      aDNS::Name name;
    };
    using Out = void;
  };

  struct RemoveAll
  {
    struct In
    {
      aDNS::Name origin;
      aDNS::Name name;
      uint16_t class_;
      uint16_t type;
    };
    using Out = void;
  };

  struct RegisterService
  {
    struct In
    {
      std::string origin;
      std::string name;
      std::string address;
      uint16_t port;
      std::string protocol;

      RFC4034::Algorithm algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
      crypto::Pem public_key;
      std::string attestation;
      std::vector<uint8_t> csr;
    };
    using Out = void;
  };
}

namespace ccfdns
{
  DECLARE_JSON_TYPE(AddRecord::In);
  DECLARE_JSON_REQUIRED_FIELDS(AddRecord::In, origin, record);

  DECLARE_JSON_TYPE(RemoveAll::In);
  DECLARE_JSON_REQUIRED_FIELDS(RemoveAll::In, origin, name, class_, type);

  DECLARE_JSON_TYPE(InstallACMEToken::In);
  DECLARE_JSON_REQUIRED_FIELDS(InstallACMEToken::In, origin, name, key_authorization);

  DECLARE_JSON_TYPE(RemoveACMEToken::In);
  DECLARE_JSON_REQUIRED_FIELDS(RemoveACMEToken::In, origin, name);

  DECLARE_JSON_TYPE(RegisterService::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegisterService::In,
    origin,
    name,
    address,
    port,
    protocol,
    attestation,
    algorithm,
    public_key);
}
