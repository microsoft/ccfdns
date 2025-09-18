// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <ccf/crypto/base64.h>
#include <ccf/crypto/key_pair.h>
#include <fmt/format.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_common.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace aDNS
{
  namespace cose
  {
    // COSE/CWT constants
    static constexpr int64_t COSE_ALG_LABEL = 1;
    static constexpr int64_t COSE_ALG_ES256 = -7;
    static constexpr int64_t CWT_CLAIMS_LABEL = 15;
    static constexpr int64_t CWT_ISS_LABEL = 1;
    static constexpr int64_t CWT_CNF_LABEL = 8;
    static constexpr auto CWT_ATT_NAME = "att";
    static constexpr auto CWT_SVI_NAME = "svi";

    // CNF claim constants
    static constexpr int64_t CNF_KTY_LABEL = 1;
    static constexpr int64_t CNF_CRV_LABEL = -1;
    static constexpr int64_t CNF_X_LABEL = -2;
    static constexpr int64_t CNF_Y_LABEL = -3;

    // Service info constants
    static constexpr auto SVI_PORT_NAME = "port";
    static constexpr auto SVI_PROTOCOL_NAME = "protocol";
    static constexpr auto SVI_IPV4_NAME = "ipv4";

    static constexpr int64_t UHDR_ENDORSEMENTS = 1;

    // Attestation
    static constexpr auto PLD_ATTESTATION = "att";
    static constexpr auto PLD_UVM_ENDORSEMENTS = "uvm";
    static constexpr auto PLD_ENDORSEMENTS = "eds";

    struct CnfClaim
    {
      int64_t kty{};
      int64_t crv{};
      std::vector<uint8_t> x{};
      std::vector<uint8_t> y{};
    };

    struct ServiceInfo
    {
      std::string port{};
      std::string protocol{};
      std::string ipv4{};
    };

    struct CwtClaim
    {
      std::string iss{};
      CnfClaim cnf{};
      std::string att{};
      ServiceInfo svi{};
    };

    struct ProtectedHeader
    {
      int64_t alg{};
      CwtClaim cwt{};
    };

    struct CoseRequest
    {
      ProtectedHeader protected_header{};
      std::vector<uint8_t> payload{};
    };

    struct Attestation
    {
      std::vector<uint8_t> attestation{};
      std::vector<uint8_t> uvm_endorsements{};
      std::string endorsements{};
    };

    // Helper functions for QCBOR conversions
    inline UsefulBufC from_bytes(std::span<const uint8_t> v)
    {
      return UsefulBufC{v.data(), v.size()};
    }

    inline UsefulBufC from_string(std::string_view v)
    {
      return UsefulBufC{v.data(), v.size()};
    }

    inline std::vector<uint8_t> as_vector(UsefulBufC buf)
    {
      return std::vector<uint8_t>(
        static_cast<const uint8_t*>(buf.ptr),
        static_cast<const uint8_t*>(buf.ptr) + buf.len);
    }

    inline std::span<const uint8_t> as_span(UsefulBufC buf)
    {
      return {static_cast<const uint8_t*>(buf.ptr), buf.len};
    }

    inline std::string_view as_string(UsefulBufC buf)
    {
      return {static_cast<const char*>(buf.ptr), buf.len};
    }

    // COSE parsing function implementations
    inline CnfClaim parse_cnf_claims(QCBORDecodeContext& ctx)
    {
      QCBORDecode_EnterMapFromMapN(&ctx, CWT_CNF_LABEL);
      auto decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw std::runtime_error(
          fmt::format("Failed to decode CNF claims: {}", decode_error));
      }

      enum
      {
        CNF_KTY_INDEX,
        CNF_CRV_INDEX,
        CNF_X_INDEX,
        CNF_Y_INDEX,
        CNF_END_INDEX,
      };
      QCBORItem cnf_items[CNF_END_INDEX + 1];

      cnf_items[CNF_KTY_INDEX].label.int64 = CNF_KTY_LABEL;
      cnf_items[CNF_KTY_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cnf_items[CNF_KTY_INDEX].uDataType = QCBOR_TYPE_INT64;

      cnf_items[CNF_CRV_INDEX].label.int64 = CNF_CRV_LABEL;
      cnf_items[CNF_CRV_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cnf_items[CNF_CRV_INDEX].uDataType = QCBOR_TYPE_INT64;

      cnf_items[CNF_X_INDEX].label.int64 = CNF_X_LABEL;
      cnf_items[CNF_X_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cnf_items[CNF_X_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      cnf_items[CNF_Y_INDEX].label.int64 = CNF_Y_LABEL;
      cnf_items[CNF_Y_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cnf_items[CNF_Y_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      cnf_items[CNF_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, cnf_items);

      auto qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error(fmt::format(
          "Failed to decode CNF claim: {}", qcbor_err_to_str(qcbor_result)));
      }

      QCBORDecode_ExitMap(&ctx);

      CnfClaim cnf{};

      if (cnf_items[CNF_KTY_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'kty' in cnf claim");
      }
      cnf.kty = cnf_items[CNF_KTY_INDEX].val.int64;

      if (cnf_items[CNF_CRV_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'crv' in cnf claim");
      }
      cnf.crv = cnf_items[CNF_CRV_INDEX].val.int64;

      if (cnf_items[CNF_X_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'x' in cnf claim");
      }
      cnf.x = as_vector(cnf_items[CNF_X_INDEX].val.string);

      if (cnf_items[CNF_Y_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'y' in cnf claim");
      }
      cnf.y = as_vector(cnf_items[CNF_Y_INDEX].val.string);

      return cnf;
    }

    inline ServiceInfo parse_service_info(QCBORDecodeContext& ctx)
    {
      QCBORDecode_EnterMapFromMapSZ(&ctx, "svi");
      auto decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw std::runtime_error(
          fmt::format("Failed to decode service info: {}", decode_error));
      }

      enum
      {
        SVI_PORT_INDEX,
        SVI_PROTOCOL_INDEX,
        SVI_IPV4_INDEX,
        SVI_END_INDEX,
      };
      QCBORItem svi_items[SVI_END_INDEX + 1];

      svi_items[SVI_PORT_INDEX].label.string = UsefulBuf_FromSZ(SVI_PORT_NAME);
      svi_items[SVI_PORT_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      svi_items[SVI_PORT_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      svi_items[SVI_PROTOCOL_INDEX].label.string =
        UsefulBuf_FromSZ(SVI_PROTOCOL_NAME);
      svi_items[SVI_PROTOCOL_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      svi_items[SVI_PROTOCOL_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      svi_items[SVI_IPV4_INDEX].label.string = UsefulBuf_FromSZ(SVI_IPV4_NAME);
      svi_items[SVI_IPV4_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      svi_items[SVI_IPV4_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      svi_items[SVI_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, svi_items);

      auto qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error(fmt::format(
          "Failed to decode service info: {}", qcbor_err_to_str(qcbor_result)));
      }

      QCBORDecode_ExitMap(&ctx);

      ServiceInfo svi{};

      if (svi_items[SVI_PORT_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'port' in service info");
      }
      svi.port = as_string(svi_items[SVI_PORT_INDEX].val.string);

      if (svi_items[SVI_PROTOCOL_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error(
          "Missing or invalid 'protocol' in service info");
      }
      svi.protocol = as_string(svi_items[SVI_PROTOCOL_INDEX].val.string);

      if (svi_items[SVI_IPV4_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'ipv4' in service info");
      }
      svi.ipv4 = as_string(svi_items[SVI_IPV4_INDEX].val.string);

      return svi;
    }

    inline CwtClaim parse_cwt_claims(QCBORDecodeContext& ctx)
    {
      QCBORDecode_EnterMapFromMapN(&ctx, CWT_CLAIMS_LABEL);
      auto decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw std::runtime_error(
          fmt::format("Failed to decode CWT claims: {}", decode_error));
      }

      enum
      {
        CWT_ISS_INDEX,
        CWT_CNF_INDEX,
        CWT_ATT_INDEX,
        CWT_SVI_INDEX,
        CWT_END_INDEX,
      };

      QCBORItem cwt_items[CWT_END_INDEX + 1];

      cwt_items[CWT_ISS_INDEX].label.int64 = CWT_ISS_LABEL;
      cwt_items[CWT_ISS_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cwt_items[CWT_ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      cwt_items[CWT_CNF_INDEX].label.int64 = CWT_CNF_LABEL;
      cwt_items[CWT_CNF_INDEX].uLabelType = QCBOR_TYPE_INT64;
      cwt_items[CWT_CNF_INDEX].uDataType = QCBOR_TYPE_MAP;

      cwt_items[CWT_ATT_INDEX].label.string = UsefulBuf_FromSZ(CWT_ATT_NAME);
      cwt_items[CWT_ATT_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      cwt_items[CWT_ATT_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      cwt_items[CWT_SVI_INDEX].label.string = UsefulBuf_FromSZ(CWT_SVI_NAME);
      cwt_items[CWT_SVI_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      cwt_items[CWT_SVI_INDEX].uDataType = QCBOR_TYPE_MAP;

      cwt_items[CWT_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, cwt_items);
      decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw std::runtime_error(
          fmt::format("Failed to decode CWT claim contents: {}", decode_error));
      }

      CwtClaim cwt{};

      if (cwt_items[CWT_ISS_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'iss' in CWT claims");
      }
      cwt.iss = as_string(cwt_items[CWT_ISS_INDEX].val.string);

      if (cwt_items[CWT_CNF_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing 'cnf' in CWT claims");
      }
      cwt.cnf = parse_cnf_claims(ctx);

      if (cwt_items[CWT_ATT_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'att' in CWT claims");
      }
      cwt.att = as_string(cwt_items[CWT_ATT_INDEX].val.string);

      if (cwt_items[CWT_SVI_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing 'svi' in CWT claims");
      }
      cwt.svi = parse_service_info(ctx);

      QCBORDecode_ExitMap(&ctx);

      return cwt;
    }

    inline ProtectedHeader parse_protected_header_items(QCBORDecodeContext& ctx)
    {
      enum
      {
        ALG_INDEX,
        CWT_CLAIMS_INDEX,
        END_INDEX,
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ALG_INDEX].label.int64 = COSE_ALG_LABEL;
      header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

      header_items[CWT_CLAIMS_INDEX].label.int64 = CWT_CLAIMS_LABEL;
      header_items[CWT_CLAIMS_INDEX].uLabelType = QCBOR_TYPE_INT64;
      header_items[CWT_CLAIMS_INDEX].uDataType = QCBOR_TYPE_MAP;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);

      auto qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error(fmt::format(
          "Failed to decode protected header: {}",
          qcbor_err_to_str(qcbor_result)));
      }

      ProtectedHeader phdr{};

      if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error(
          "Missing or invalid algorithm in protected header");
      }
      phdr.alg = header_items[ALG_INDEX].val.int64;

      if (header_items[CWT_CLAIMS_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing CWT claims in protected header");
      }

      phdr.cwt = parse_cwt_claims(ctx);

      return phdr;
    }

    inline CoseRequest decode_cose_request(std::span<const uint8_t> input)
    {
      QCBORError qcbor_result;

      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, from_bytes(input), QCBOR_DECODE_MODE_NORMAL);

      QCBORDecode_EnterArray(&ctx, nullptr);
      qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error("Failed to parse COSE_Sign1 outer array");
      }

      uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
      if (tag != CBOR_TAG_COSE_SIGN1)
      {
        throw std::runtime_error("COSE_Sign1 is not tagged");
      }

      QCBORDecode_EnterBstrWrapped(&ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
      QCBORDecode_EnterMap(&ctx, NULL);

      ProtectedHeader phdr = parse_protected_header_items(ctx);

      QCBORDecode_ExitMap(&ctx);
      QCBORDecode_ExitBstrWrapped(&ctx);

      // uhdr
      QCBORDecode_EnterMap(&ctx, NULL);
      QCBORDecode_ExitMap(&ctx);

      QCBORItem payload_item;
      QCBORDecode_GetNext(&ctx, &payload_item);

      if (payload_item.uDataType != QCBOR_TYPE_BYTE_STRING)
      {
        throw std::runtime_error("Expected payload to be a byte string");
      }
      std::vector<uint8_t> payload = as_vector(payload_item.val.string);

      QCBORDecode_ExitArray(&ctx);

      return CoseRequest{.protected_header = phdr, .payload = payload};
    }

    inline ccf::crypto::PublicKeyPtr reconstruct_public_key_from_cnf(
      const CnfClaim& cnf)
    {
      if (cnf.kty != 2)
      {
        throw std::runtime_error("Unsupported key type, expected EC2");
      }
      if (cnf.crv != 1)
      {
        throw std::runtime_error("Unsupported curve, expected P-256");
      }
      if (cnf.x.size() != 32 || cnf.y.size() != 32)
      {
        throw std::runtime_error("Invalid coordinate size for P-256");
      }

      ccf::crypto::JsonWebKeyECPublic jwk_public;
      jwk_public.kty = ccf::crypto::JsonWebKeyType::EC;
      jwk_public.crv = ccf::crypto::JsonWebKeyECCurve::P256;
      jwk_public.x = ccf::crypto::b64url_from_raw(cnf.x, false);
      jwk_public.y = ccf::crypto::b64url_from_raw(cnf.y, false);

      return ccf::crypto::make_public_key(jwk_public);
    }

    inline Attestation parse_attestation(std::span<const uint8_t> attestation)
    {
      QCBORDecodeContext ctx;
      QCBORDecode_Init(&ctx, from_bytes(attestation), QCBOR_DECODE_MODE_NORMAL);

      QCBORDecode_EnterMap(&ctx, NULL);

      enum
      {
        ATTESTATION_INDEX,
        ENDORSEMENTS_INDEX,
        UVM_ENDORSEMENTS_INDEX,
        END_INDEX,
      };
      QCBORItem header_items[END_INDEX + 1];

      header_items[ATTESTATION_INDEX].label.string =
        UsefulBuf_FromSZ(PLD_ATTESTATION);
      header_items[ATTESTATION_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[ATTESTATION_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      header_items[UVM_ENDORSEMENTS_INDEX].label.string =
        UsefulBuf_FromSZ(PLD_UVM_ENDORSEMENTS);
      header_items[UVM_ENDORSEMENTS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[UVM_ENDORSEMENTS_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

      header_items[ENDORSEMENTS_INDEX].label.string =
        UsefulBuf_FromSZ(PLD_ENDORSEMENTS);
      header_items[ENDORSEMENTS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
      header_items[ENDORSEMENTS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

      header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

      QCBORDecode_GetItemsInMap(&ctx, header_items);

      auto qcbor_result = QCBORDecode_GetError(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error(fmt::format(
          "Failed to decode payload: {}", qcbor_err_to_str(qcbor_result)));
      }

      std::vector<uint8_t> raw_attestation{}, uvm_endorsements{};
      std::string endorsements{};

      if (header_items[UVM_ENDORSEMENTS_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'uvm' in the payload");
      }
      raw_attestation = as_vector(header_items[ATTESTATION_INDEX].val.string);

      if (header_items[UVM_ENDORSEMENTS_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'uvm' in the payload");
      }
      uvm_endorsements =
        as_vector(header_items[UVM_ENDORSEMENTS_INDEX].val.string);

      if (header_items[ENDORSEMENTS_INDEX].uDataType == QCBOR_TYPE_NONE)
      {
        throw std::runtime_error("Missing or invalid 'eds' in the payload");
      }
      endorsements = as_string(header_items[ENDORSEMENTS_INDEX].val.string);

      QCBORDecode_ExitMap(&ctx);

      qcbor_result = QCBORDecode_Finish(&ctx);
      if (qcbor_result != QCBOR_SUCCESS)
      {
        throw std::runtime_error(fmt::format(
          "Decoding attestation finished with error: {}",
          qcbor_err_to_str(qcbor_result)));
      }

      return Attestation{
        .attestation = raw_attestation,
        .uvm_endorsements = uvm_endorsements,
        .endorsements = endorsements};
    }
  } // cose
} // aDNS
