// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "adns_types.h"

#include "qvl.h"

#include <ccf/crypto/hash_provider.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>

struct Claims
{
  oe_claim_t* data = nullptr;
  size_t length = 0;

  ~Claims()
  {
    oe_free_claims(data, length);
  }
};

struct CustomClaims
{
  oe_claim_t* data = nullptr;
  size_t length = 0;

  ~CustomClaims()
  {
    oe_free_custom_claims(data, length);
  }
};

struct SerialisedClaims
{
  uint8_t* buffer = nullptr;
  size_t size = 0;

  ~SerialisedClaims()
  {
    oe_free_serialized_custom_claims(buffer);
  }
};

struct Evidence
{
  uint8_t* buffer = NULL;
  size_t size = 0;

  ~Evidence()
  {
    oe_free_evidence(buffer);
  }
};

struct Endorsements
{
  uint8_t* buffer = NULL;
  size_t size = 0;

  ~Endorsements()
  {
    oe_free_endorsements(buffer);
  }
};

static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
static constexpr auto sgx_report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;

QVL::Attestation aDNS::Types::ATTEST::generate_quote_info(
  const std::vector<uint8_t>& node_public_key_der)
{
  QVL::Attestation attestation;
  attestation.format = QVL::Format::SGX;

  crypto::Sha256Hash h{node_public_key_der};

  Evidence evidence;
  Endorsements endorsements;
  SerialisedClaims serialised_custom_claims;

  // Serialise hash of node's public key as a custom claim
  const size_t custom_claim_length = 1;
  oe_claim_t custom_claim;
  custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
  custom_claim.value = h.h.data();
  custom_claim.value_size = h.SIZE;

  auto rc = oe_serialize_custom_claims(
    &custom_claim,
    custom_claim_length,
    &serialised_custom_claims.buffer,
    &serialised_custom_claims.size);
  if (rc != OE_OK)
  {
    throw std::logic_error(fmt::format(
      "Could not serialise node's public key as quote custom claim: {}",
      oe_result_str(rc)));
  }

  rc = oe_get_evidence(
    &oe_quote_format,
    0,
    serialised_custom_claims.buffer,
    serialised_custom_claims.size,
    nullptr,
    0,
    &evidence.buffer,
    &evidence.size,
    &endorsements.buffer,
    &endorsements.size);
  if (rc != OE_OK)
  {
    throw std::logic_error(
      fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
  }

  attestation.evidence.assign(evidence.buffer, evidence.buffer + evidence.size);
  attestation.endorsements.assign(
    endorsements.buffer, endorsements.buffer + endorsements.size);

  return attestation;
}