// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "resolver.h"
#include "rfc1035.h"

#include <ccf/service/map.h>
#include <cstdint>
#include <vector>

namespace ccfdns
{
  struct ZoneKeyInfo
  {
    std::map<uint16_t, std::vector<crypto::Pem>> key_signing_keys;
    std::map<uint16_t, std::vector<crypto::Pem>> zone_signing_keys;
  };

  using Keys = ccf::ServiceMap<RFC1035::Name, ZoneKeyInfo>;
}
