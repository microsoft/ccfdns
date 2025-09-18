// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/crypto/pem.h>
#include <ccf/ds/json.h>
#include <ccf/ds/quote_info.h>
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

  struct Resign
  {
    struct In
    {
      std::string origin;
    };
    using Out = void;
  };

  struct SetServiceDefinition
  {
    struct In
    {
      std::string service_name;
      std::string policy;
      std::string attestation;
    };
    using Out = void;
  };

  struct SetPlatformDefinition
  {
    struct In
    {
      ccf::QuoteFormat platform;
      std::string policy;
      std::string attestation;
    };
    using Out = void;
  };
}
