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

  struct Resign
  {
    struct In
    {
      std::string origin;
    };
    using Out = void;
  };

  struct SetServiceRelyingPartyPolicy
  {
    struct In
    {
      std::string policy;
    };
    using Out = void;
  };
}
