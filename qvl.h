// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <ccf/crypto/hash_provider.h>
#include <ccf/quote_info.h>
#include <ccf/service/code_digest.h>

namespace QVL
{
  enum class Result
  {
    Verified = 0,
    Failed,
    FailedCodeIdNotFound,
    FailedInvalidQuotedPublicKey,
  };

  Result verify_quote(
    const ccf::QuoteInfo& quote_info,
    ccf::CodeDigest& unique_id,
    crypto::Sha256Hash& hash_node_public_key);
};
