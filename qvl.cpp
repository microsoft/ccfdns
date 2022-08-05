// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "qvl.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/ds/logger.h>

#ifdef GET_QUOTE
#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>
#endif

template <typename T, typename R, R (*F)(T*)>
struct Buffer
{
  T* data = nullptr;
  size_t size = 0;

  ~Buffer()
  {
    F(data);
  }
};

namespace QVL
{
  Result verify(
    const Attestation& attestation, const std::string& public_key_pem)
  {
    return Result::Verified;
  }

  Attestation get_oe_attestation(const std::vector<uint8_t>& extra)
  {
    Attestation r;

#ifdef GET_QUOTE

    static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
    static constexpr auto sgx_report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;

    r.format = Format::SGX;

    Buffer<uint8_t, oe_result_t, oe_free_evidence> evidence;
    Buffer<uint8_t, oe_result_t, oe_free_endorsements> endorsements;
    Buffer<uint8_t, oe_result_t, oe_free_serialized_custom_claims>
      serialised_custom_claims;

    const size_t custom_claim_length = 0;
    oe_claim_t custom_claim;

    if (!extra.empty())
    {
      crypto::Sha256Hash h(extra);
      const size_t custom_claim_length = 1;
      custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
      custom_claim.value = h.h.data();
      custom_claim.value_size = h.SIZE;

      oe_result_t rc = oe_serialize_custom_claims(
        &custom_claim,
        custom_claim_length,
        &serialised_custom_claims.data,
        &serialised_custom_claims.size);
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Error serialising report data as custom claim: {}",
          oe_result_str(rc)));
      }
    }

    oe_result_t rc = oe_get_evidence(
      &oe_quote_format,
      0,
      serialised_custom_claims.data,
      serialised_custom_claims.size,
      nullptr,
      0,
      &evidence.data,
      &evidence.size,
      &endorsements.data,
      &endorsements.size);
    if (rc != OE_OK)
    {
      throw std::logic_error(
        fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
    }

    r.evidence.assign(evidence.data, evidence.data + evidence.size);
    r.endorsements.assign(
      endorsements.data, endorsements.data + endorsements.size);
#endif

    return r;
  }
}