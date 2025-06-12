// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <ccf/ds/quote_info.h>
#include <ccf/pal/attestation.h>
#include <ccf/pal/attestation_sev_snp.h>
#include <ccf/pal/measurement.h>
#include <ccf/pal/report_data.h>
#include <ccf/pal/uvm_endorsements.h>

namespace aDNS
{
  using HostData = ccf::crypto::Sha256Hash;

  static ccf::QuoteInfo parse_and_verify_attestation(
    std::string_view raw_attestation,
    ccf::pal::PlatformAttestationReportData& report_data,
    ccf::pal::UVMEndorsements& uvm_endorsements_descriptor)
  {
    auto attestation =
      nlohmann::json::parse(raw_attestation).get<ccf::QuoteInfo>();

    // Maybe, endorsements are represented in THIM format, as defined in
    // ccf::pal::snp::ACIReportEndorsements.
    try
    {
      const auto aci_endorsements =
        nlohmann::json::parse(attestation.endorsements)
          .get<ccf::pal::snp::ACIReportEndorsements>();

      attestation.endorsements = std::vector<uint8_t>(
        aci_endorsements.vcek_cert.begin(), aci_endorsements.vcek_cert.end());
      attestation.endorsements.insert(
        attestation.endorsements.end(),
        aci_endorsements.certificate_chain.begin(),
        aci_endorsements.certificate_chain.end());
    }
    catch (const nlohmann::json::parse_error& e)
    {
      // If not, fallback to attempt as byte-encoded chain as is.
    }

    ccf::pal::PlatformAttestationMeasurement measurement = {};
    ccf::pal::verify_quote(attestation, measurement, report_data);

    uvm_endorsements_descriptor = ccf::pal::verify_uvm_endorsements_descriptor(
      attestation.uvm_endorsements.value(), measurement);

    return attestation;
  }

  static HostData retrieve_host_data(const ccf::QuoteInfo& attestation)
  {
    HostData::Representation rep{};
    auto typed_attestation =
      *reinterpret_cast<const ccf::pal::snp::Attestation*>(
        attestation.quote.data());
    std::copy(
      std::begin(typed_attestation.host_data),
      std::end(typed_attestation.host_data),
      rep.begin());
    return HostData::from_representation(rep);
  }
}