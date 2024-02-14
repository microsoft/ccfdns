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
  // We keep the public keys in records, for DNS-based discovery and transparency,
  // and share the corresponding private signing keys using encrypted CCF tables.  

  struct ZoneKeyInfo
  {
    std::map<uint16_t, std::vector<crypto::Pem>> key_signing_keys;
    std::map<uint16_t, std::vector<crypto::Pem>> zone_signing_keys;
  };

  using PrivateDNSKeys = ccf::ServiceMap<RFC1035::Name, ZoneKeyInfo>;
  const std::string private_dnskey_table_name = "private:dnskey_table_name";


  // EAT KEYS 

  // minimal time EAT public keys must be discoverable before issuing tokens (1 day)
  const uint32_t discovery_ttl = 24*3600; 

  // We could also keep the public keys in TLSA records, for DNS-based discovery and transparency
  // but then aDNS clients can already directly fetch the service attestation records.

  struct EATPublicKeyRecord
  {
    // to be fixed; whatever it takes to produce the JWKS.
    crypto::Pem public_key;

    // creation time for first key, creation_time + discovery_ttl for next keys
    uint32_t can_sign_after; 

    // private-key erasure time + upper bound on the expiration of all signed tokens
    uint32_t can_retire_after; 
  };

  // We keep keys in vectors, ordered by creation-time.
  // The private vector keeps only the active signing key [0] and the next ones [1+]
  // The public vector may keep additional old public keys for discoverability 
  
  using EATIssuerKeyInfo = ccf::ServiceValue<std::vector<EATPublicKeyRecord>>;
  const std::string eat_issuer_key_info_table_name = "eat_issuer_key_info_table_name";

  using EATPrivateKeys = ccf::ServiceValue<std::vector<crypto::Pem>>;
  const std::string eat_private_key_table_name = "private:eat_private_key_table_name";
}
