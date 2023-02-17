// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
    using In = aDNS::Resolver::Configuration;
    struct Out
    {
      aDNS::Resolver::RegistrationInformation registration_info;
    };
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

  struct InstallACMEResponse
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
