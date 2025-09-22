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

  struct ZoneKeyInfo
  {
    std::map<uint16_t, std::vector<ccf::crypto::Pem>> key_signing_keys;
    std::map<uint16_t, std::vector<ccf::crypto::Pem>> zone_signing_keys;
  };

  using PrivateDNSKeys = ccf::ServiceMap<RFC1035::Name, ZoneKeyInfo>;
  const std::string private_dnskey_table_name = "private:dnskey_table_name";
}
