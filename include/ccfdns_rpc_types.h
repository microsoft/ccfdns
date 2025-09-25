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
