// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "qvl.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/ds/logger.h>

template <typename T, typename R, R (*F)(T*, size_t)>
struct Buffer
{
  T* data = nullptr;
  size_t length = 0;

  ~Buffer()
  {
    F(data, length);
  }
};

namespace QVL
{
  Result verify(
    const Attestation& attestation, const std::string& public_key_pem)
  {
    return Result::Verified;
  }
}