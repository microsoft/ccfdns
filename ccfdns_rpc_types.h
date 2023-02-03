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
  struct Configure
  {
    struct In
    {
      aDNS::Resolver::Configuration configuration;
    };
    struct Out
    {
      aDNS::Resolver::RegistrationInformation registration_info;
    };
  };

  struct SetServiceCertificate
  {
    struct In
    {
      std::string certificate;
    };
    using Out = void;
  };

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
      std::vector<aDNS::Name> alternative_names;
      std::string key_authorization;
    };
    using Out = void;
  };

  struct RemoveACMEToken
  {
    struct In
    {
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
    using In = aDNS::Resolver::RegistrationRequest;
    using Out = void;
  };

  struct RegisterDelegation
  {
    using In = aDNS::Resolver::DelegationRequest;
    using Out = void;
  };

  struct SetCertificate
  {
    struct In
    {
      std::string service_dns_name;
      std::string certificate;
    };
    using Out = void;
  };

  struct GetCertificate
  {
    struct In
    {
      std::string service_dns_name;
    };
    struct Out
    {
      std::string certificate;
    };
  };
}

namespace ccfdns
{
  DECLARE_JSON_TYPE(Configure::In);
  DECLARE_JSON_REQUIRED_FIELDS(Configure::In, configuration);

  DECLARE_JSON_TYPE(Configure::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Configure::Out, registration_info);

  DECLARE_JSON_TYPE(SetServiceCertificate::In);
  DECLARE_JSON_REQUIRED_FIELDS(SetServiceCertificate::In, certificate);

  DECLARE_JSON_TYPE(AddRecord::In);
  DECLARE_JSON_REQUIRED_FIELDS(AddRecord::In, origin, record);

  DECLARE_JSON_TYPE(RemoveAll::In);
  DECLARE_JSON_REQUIRED_FIELDS(RemoveAll::In, origin, name, class_, type);

  DECLARE_JSON_TYPE(InstallACMEToken::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    InstallACMEToken::In, origin, name, alternative_names, key_authorization);

  DECLARE_JSON_TYPE(RemoveACMEToken::In);
  DECLARE_JSON_REQUIRED_FIELDS(RemoveACMEToken::In, origin, name);

  DECLARE_JSON_TYPE(SetCertificate::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    SetCertificate::In, service_dns_name, certificate);

  DECLARE_JSON_TYPE(GetCertificate::In);
  DECLARE_JSON_REQUIRED_FIELDS(GetCertificate::In, service_dns_name);
  DECLARE_JSON_TYPE(GetCertificate::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetCertificate::Out, certificate);
}

namespace aDNS
{
  DECLARE_JSON_TYPE(Resolver::RegistrationRequest);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::RegistrationRequest,
    origin,
    name,
    ip,
    port,
    protocol,
    attestation,
    csr,
    contact);

  DECLARE_JSON_TYPE(Resolver::DelegationRequest);
  DECLARE_JSON_REQUIRED_FIELDS(
    Resolver::DelegationRequest,
    origin,
    name,
    subdomain,
    ip,
    port,
    protocol,
    attestation,
    csr,
    contact,
    dnskey_records);
}