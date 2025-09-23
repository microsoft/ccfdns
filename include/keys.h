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
  // We keep the public keys in records, for DNS-based discovery and
  // transparency, and share the corresponding private signing keys using
  // encrypted CCF tables.

  struct KeyInfo
  {
    uint16_t tag{};
    ccf::crypto::Pem key{};
  };

  using PrivateDNSKey = ccf::ServiceMap<RFC1035::Name, KeyInfo>;

  const std::string key_signing_key_table = "private:key_signing_keys";
  const std::string zone_signing_key_table = "private:zone_signing_keys";
}
