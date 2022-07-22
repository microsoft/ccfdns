// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "qvl.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/ds/logger.h>
#include <ccf/quote_info.h>
#include <ccf/service/code_digest.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>

static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
static constexpr auto sgx_report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;

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

  Result verify_quote(
    const ccf::QuoteInfo& quote_info,
    ccf::CodeDigest& unique_id,
    crypto::Sha256Hash& hash_node_public_key)
  {
    Buffer<oe_claim_t, oe_result_t, oe_free_claims> claims;

    auto rc = oe_verify_evidence(
      &oe_quote_format,
      quote_info.quote.data(),
      quote_info.quote.size(),
      quote_info.endorsements.data(),
      quote_info.endorsements.size(),
      nullptr,
      0,
      &claims.data,
      &claims.length);

    if (rc != OE_OK)
    {
#ifdef QUOTE_VERIFICATION_FAILURE_OK
      LOG_FAIL_FMT("ignoring failed quote verification");
      return Result::Verified;
#else
      return Result::Failed;
#endif
    }

    bool unique_id_found = false;
    bool sgx_report_data_found = false;
    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      auto claim_name = std::string(claim.name);
      if (claim_name == OE_CLAIM_UNIQUE_ID)
      {
        std::copy(
          claim.value, claim.value + claim.value_size, unique_id.data.begin());
        unique_id_found = true;
      }
      else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        // Find sgx report data in custom claims
        Buffer<oe_claim_t, oe_result_t, oe_free_custom_claims> custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          throw std::logic_error(fmt::format(
            "Failed to deserialise custom claims", oe_result_str(rc)));
        }

        for (size_t j = 0; j < custom_claims.length; j++)
        {
          auto& custom_claim = custom_claims.data[j];
          if (std::string(custom_claim.name) == sgx_report_data_claim_name)
          {
            if (custom_claim.value_size != hash_node_public_key.SIZE)
            {
              throw std::logic_error(fmt::format(
                "Expected {} of size {}, had size {}",
                sgx_report_data_claim_name,
                hash_node_public_key.SIZE,
                custom_claim.value_size));
            }

            std::copy(
              custom_claim.value,
              custom_claim.value + custom_claim.value_size,
              hash_node_public_key.h.begin());
            sgx_report_data_found = true;
            break;
          }
        }
      }
    }

    if (!unique_id_found || !sgx_report_data_found)
    {
#ifdef QUOTE_VERIFICATION_FAILURE_OK
      LOG_FAIL_FMT("ignoring failed quote verification");
      return Result::Verified;
#else
      return Result::Failed;
#endif
    }

    return Result::Verified;
  }

  Result verify_quoted_node_public_key(
    const std::vector<uint8_t>& expected_node_public_key,
    const crypto::Sha256Hash& quoted_hash)
  {
    if (quoted_hash != crypto::Sha256Hash(expected_node_public_key))
    {
      return Result::FailedInvalidQuotedPublicKey;
    }

    return Result::Verified;
  }

}