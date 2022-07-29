// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <vector>

namespace QVL
{
  enum class Format : uint8_t
  {
    NONE = 0,
    SGX = 1,
    AMD = 2
  };

  struct Attestation
  {
    Attestation() = default;
    Attestation(const Attestation&) = default;
    Attestation& operator=(const Attestation&) = default;

    Format format = Format::NONE;
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;
  };

  enum class Result
  {
    Verified = 0,
    Failed,
    FailedCodeIdNotFound,
    FailedInvalidQuotedPublicKey,
  };

  Result verify(
    const Attestation& attestation, const std::string& public_key_pem);
};
