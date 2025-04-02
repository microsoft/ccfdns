// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rfc5155.h"

#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"
#include "small_vector.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/md_type.h>
#include <functional>
#include <span>
#include <vector>

using namespace RFC1035;

namespace RFC5155
{
  NSEC3::NSEC3(
    HashAlgorithm hash_algorithm,
    uint8_t flags,
    uint16_t iterations,
    const small_vector<uint8_t>& salt,
    const small_vector<uint8_t>& next_hashed_owner_name,
    const std::function<std::string(const RFC4034::Type&)>& type2str) :
    hash_algorithm(hash_algorithm),
    flags(flags),
    iterations(iterations),
    salt(salt),
    next_hashed_owner_name(next_hashed_owner_name),
    type_bit_maps(type2str)
  {}

  static std::vector<uint8_t> H(const std::vector<uint8_t>& x)
  {
    auto hp = ccf::crypto::make_hash_provider();
    auto md_type = ccf::crypto::MDType::SHA1;
    return hp->Hash(&x[0], x.size(), md_type);
  }

  // https://datatracker.ietf.org/doc/html/rfc5155#section-5
  small_vector<uint8_t> NSEC3::hash(
    const RFC1035::Name& origin,
    const RFC1035::Name& name,
    uint16_t iterations,
    const small_vector<uint8_t>& salt)
  {
    auto canonical_name = name;
    if (!canonical_name.is_absolute())
      canonical_name += origin;
    canonical_name.lower();

    // IH(salt, x, 0) = H(x || salt), and
    // IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
    // Then the calculated hash of an owner name is
    // IH(salt, owner name, iterations),

    std::vector<uint8_t> a;
    canonical_name.put(a);
    for (size_t i = 0; i < iterations + 1; i++)
    {
      for (size_t j = 0; j < salt.size(); j++)
        a.push_back(salt[j]);
      CCF_APP_TRACE("CCFDNS: nsec3 hash a={}", ccf::ds::to_hex(a));
      a = H(a);
    }
    CCF_APP_TRACE("CCFDNS: nsec3 hash h={}", ccf::ds::to_hex(a));
    return small_vector<uint8_t>(a.size(), a.data());
  }

  NSEC3PARAMRR::NSEC3PARAMRR(
    const RFC1035::Name& owner,
    RFC1035::Class class_,
    uint32_t ttl,
    HashAlgorithm hash_algorithm,
    uint8_t flags,
    uint16_t iterations,
    const small_vector<uint8_t>& salt) :
    RFC1035::ResourceRecord(
      owner,
      static_cast<uint16_t>(Type::NSEC3PARAM),
      static_cast<uint16_t>(class_),
      ttl,
      NSEC3PARAM(hash_algorithm, flags, iterations, salt))
  {}
}