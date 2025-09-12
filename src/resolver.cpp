// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"

#include "attestation.h"
#include "compression.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/crypto/base64.h>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/entropy.h>
#include <ccf/crypto/hash_bytes.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/md_type.h>
#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/crypto/san.h>
#include <ccf/crypto/sha256.h>
#include <ccf/crypto/sha256_hash.h>
#include <ccf/crypto/verifier.h>
#include <ccf/ds/logger.h>
#include <cctype>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <openssl/x509.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <rego/rego.hh>
#include <set>
#include <string>

using namespace RFC1035;

namespace
{
  void verify_service_definition(
    const std::string& host_data, const std::string& policy)
  {
    nlohmann::json rego_input;
    rego_input["host_data"] = host_data;

    rego::Interpreter interpreter(true /* v1 compatible */);
    auto rv = interpreter.add_module("policy", policy);

    auto tv = interpreter.set_input_term(rego_input.dump());
    if (tv != nullptr)
    {
      throw std::runtime_error(
        fmt::format("Invalid policy input: {}", rego_input.dump()));
    }

    auto qv = interpreter.query("data.policy.allow");

    if (qv == "{\"expressions\":[true]}")
    {
      return;
    }
    else if (qv == "{\"expressions\":[false]}")
    {
      throw std::runtime_error(
        fmt::format("Policy not satisfied: {}", rego_input.dump()));
    }
    else
    {
      throw std::runtime_error(
        fmt::format("Error while applying policy: {}", qv));
    }
  }

  void verify_platform_definition(
    const std::string& measurement, const std::string& policy)
  {
    nlohmann::json rego_input;
    rego_input["measurement"] = measurement;

    rego::Interpreter interpreter(true /* v1 compatible */);
    auto rv = interpreter.add_module("policy", policy);

    auto tv = interpreter.set_input_term(rego_input.dump());
    if (tv != nullptr)
    {
      throw std::runtime_error(
        fmt::format("Invalid policy input: {}", rego_input.dump()));
    }

    auto qv = interpreter.query("data.policy.allow");

    if (qv == "{\"expressions\":[true]}")
    {
      return;
    }
    else if (qv == "{\"expressions\":[false]}")
    {
      throw std::runtime_error(
        fmt::format("Policy not satisfied: {}", rego_input.dump()));
    }
    else
    {
      throw std::runtime_error(
        fmt::format("Error while applying policy: {}", qv));
    }
  }
}

namespace
{
  // COSE/CWT constants
  static constexpr int64_t COSE_ALG_LABEL = 1;
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

  CnfClaim parse_cnf_claims(QCBORDecodeContext& ctx)
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

  ServiceInfo parse_service_info(QCBORDecodeContext& ctx)
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
      throw std::runtime_error("Missing or invalid 'protocol' in service info");
    }
    svi.protocol = as_string(svi_items[SVI_PROTOCOL_INDEX].val.string);

    if (svi_items[SVI_IPV4_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw std::runtime_error("Missing or invalid 'ipv4' in service info");
    }
    svi.ipv4 = as_string(svi_items[SVI_IPV4_INDEX].val.string);

    return svi;
  }

  CwtClaim parse_cwt_claims(QCBORDecodeContext& ctx)
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

  ProtectedHeader parse_protected_header_items(QCBORDecodeContext& ctx)
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

  CoseRequest decode_cose_request(std::span<const uint8_t> input)
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

    // Get unprotected header (not used).
    QCBORItem uhdr;
    QCBORDecode_GetNext(&ctx, &uhdr);

    // Get payload
    QCBORItem payload_item;
    QCBORDecode_GetNext(&ctx, &payload_item);
    if (payload_item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::runtime_error("Expected payload to be a byte string");
    }
    std::vector<uint8_t> payload = as_vector(payload_item.val.string);

    QCBORDecode_ExitArray(&ctx);

    return {phdr, payload};
  }

  ccf::crypto::PublicKeyPtr reconstruct_public_key_from_cnf(const CnfClaim& cnf)
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
}

namespace aDNS
{
  static const std::map<uint16_t, Type> supported_types = {
    {static_cast<uint16_t>(RFC1035::Type::A), Type::A},
    {static_cast<uint16_t>(RFC1035::Type::NS), Type::NS},
    {static_cast<uint16_t>(RFC1035::Type::CNAME), Type::CNAME},
    {static_cast<uint16_t>(RFC1035::Type::SOA), Type::SOA},
    {static_cast<uint16_t>(RFC1035::Type::MX), Type::MX},
    {static_cast<uint16_t>(RFC1035::Type::TXT), Type::TXT},

    {static_cast<uint16_t>(RFC3596::Type::AAAA), Type::AAAA},

    {static_cast<uint16_t>(RFC4034::Type::DNSKEY), Type::DNSKEY},
    {static_cast<uint16_t>(RFC4034::Type::DS), Type::DS},
    {static_cast<uint16_t>(RFC4034::Type::RRSIG), Type::RRSIG},
    {static_cast<uint16_t>(RFC4034::Type::NSEC), Type::NSEC},

    {static_cast<uint16_t>(RFC6891::Type::OPT), Type::OPT},

    {static_cast<uint16_t>(RFC5155::Type::NSEC3), Type::NSEC3},
    {static_cast<uint16_t>(RFC5155::Type::NSEC3PARAM), Type::NSEC3PARAM},

    {static_cast<uint16_t>(RFC7671::Type::TLSA), Type::TLSA},
  };

  static const std::map<uint16_t, QType> supported_qtypes = {
    {static_cast<uint16_t>(RFC1035::QType::ASTERISK), QType::ASTERISK},
  };

  static const std::map<uint16_t, Class> supported_classes = {
    {static_cast<uint16_t>(RFC1035::Class::IN), Class::IN}};

  static const std::map<uint16_t, QClass> supported_qclasses = {
    {static_cast<uint16_t>(RFC1035::QClass::ASTERISK), QClass::ASTERISK}};

  static const std::map<std::string, Class> string_to_class_map = {
    {"IN", Class::IN},
  };

  Type type_from_string(const std::string& type_string)
  {
#define TFSF(RFC) \
  { \
    for (const auto& [t, s] : RFC::type_string_map) \
    { \
      if (s == type_string) \
        return static_cast<Type>(t); \
    } \
  }

    TFSF(RFC1035);
    TFSF(RFC3596);
    TFSF(RFC4034);
    TFSF(RFC6891);
    TFSF(RFC5155);
    TFSF(RFC7671);

    throw std::runtime_error(
      fmt::format("unknown type string '{}'", type_string));
  }

  std::string string_from_type(const Type& t)
  {
#define SFTF(RFC) \
  { \
    auto mit = RFC::type_string_map.find(static_cast<RFC::Type>(t)); \
    if (mit != RFC::type_string_map.end()) \
      return mit->second; \
  }

    SFTF(RFC1035);
    SFTF(RFC3596);
    SFTF(RFC4034);
    SFTF(RFC6891);
    SFTF(RFC5155);
    SFTF(RFC7671);

    // https://datatracker.ietf.org/doc/html/rfc3597#section-5
    return "TYPE" + std::to_string(static_cast<uint16_t>(t));
  };

  std::string string_from_qtype(const QType& t)
  {
    return t == QType::ASTERISK ? "*" : string_from_type(static_cast<Type>(t));
  }

  QType qtype_from_string(const std::string& s)
  {
    static const std::map<std::string, QType> smap = {
      {"*", QType::ASTERISK},
    };
    auto mit = smap.find(s);
    if (mit == smap.end())
      return static_cast<QType>(type_from_string(s));
    return mit->second;
  };

  Class class_from_string(const std::string& s)
  {
    static const std::map<std::string, Class> smap = {{"IN", Class::IN}};
    auto mit = smap.find(s);
    if (mit == smap.end())
      throw std::runtime_error("unknown class");
    return mit->second;
  }

  QClass qclass_from_string(const std::string& s)
  {
    static const std::map<std::string, QClass> smap = {{"*", QClass::ASTERISK}};
    auto mit = smap.find(s);
    if (mit == smap.end())
      return static_cast<QClass>(class_from_string(s));
    return mit->second;
  }

  std::string string_from_class(const Class& class_)
  {
    for (const auto& [name, c] : string_to_class_map)
    {
      if (c == class_)
      {
        return name;
      }
    }

    // https://datatracker.ietf.org/doc/html/rfc3597#section-5
    return "CLASS" + std::to_string(static_cast<uint16_t>(class_));
  };

  std::string string_from_qclass(const QClass& c)
  {
    return c == QClass::ASTERISK ? "*" :
                                   string_from_class(static_cast<Class>(c));
  }

  auto type2str = [](const auto& x) {
    return string_from_type(static_cast<Type>(x));
  };

  std::shared_ptr<RDataFormat> mk_rdata_format(
    Type t, const small_vector<uint16_t>& rdata)
  {
    switch (t)
    {
      case Type::A:
        return std::make_shared<RFC1035::A>(rdata);
      case Type::NS:
        return std::make_shared<RFC1035::NS>(rdata);
      case Type::CNAME:
        return std::make_shared<RFC1035::CNAME>(rdata);
      case Type::SOA:
        return std::make_shared<RFC1035::SOA>(rdata);
      case Type::MX:
        return std::make_shared<RFC1035::MX>(rdata);
      case Type::TXT:
        return std::make_shared<RFC1035::TXT>(rdata);
      case Type::AAAA:
        return std::make_shared<RFC3596::AAAA>(rdata);
      case Type::DNSKEY:
        return std::make_shared<RFC4034::DNSKEY>(rdata);
      case Type::DS:
        return std::make_shared<RFC4034::DS>(rdata);
      case Type::RRSIG:
        return std::make_shared<RFC4034::RRSIG>(rdata, type2str);
      case Type::NSEC:
        return std::make_shared<RFC4034::NSEC>(rdata, type2str);
      case Type::NSEC3:
        return std::make_shared<RFC5155::NSEC3>(rdata, type2str);
      case Type::NSEC3PARAM:
        return std::make_shared<RFC5155::NSEC3PARAM>(rdata);
      case Type::OPT:
        return std::make_shared<RFC6891::OPT>(rdata);
      case Type::TLSA:
        return std::make_shared<RFC7671::TLSA>(rdata);
      default:
        throw std::runtime_error("unsupported rdata format");
    }
  }

  std::string string_from_resource_record(const ResourceRecord& rr)
  {
    std::string r = rr.name;

    if (rr.type == static_cast<uint16_t>(Type::OPT))
    {
      // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
      r += " udp-payload-size=" + std::to_string(rr.class_);
      r += " " + (std::string)RFC6891::TTL(rr.ttl);
    }
    else
    {
      r += " " + string_from_class(static_cast<Class>(rr.class_));
      r += " " + std::to_string(rr.ttl);
    }
    r += " " + string_from_type(static_cast<Type>(rr.type));
    r +=
      " " + (std::string)*mk_rdata_format(static_cast<Type>(rr.type), rr.rdata);
    return r;
  }

  static void convert_ec_signature_to_ieee_p1363(
    std::vector<uint8_t>& sig,
    std::shared_ptr<const ccf::crypto::KeyPair> signing_key)
  {
    // Convert signature from ASN.1 format to IEEE P1363
    const unsigned char* pp = sig.data();
    ECDSA_SIG* sig_r_s = d2i_ECDSA_SIG(NULL, &pp, sig.size());
    const BIGNUM* r = ECDSA_SIG_get0_r(sig_r_s);
    const BIGNUM* s = ECDSA_SIG_get0_s(sig_r_s);
    int r_n = BN_num_bytes(r);
    int s_n = BN_num_bytes(s);
    size_t sz = signing_key->coordinates().x.size();
    assert(signing_key->coordinates().y.size() == sz);
    sig = std::vector<uint8_t>(2 * sz, 0);
    BN_bn2binpad(r, sig.data(), sz);
    BN_bn2binpad(s, sig.data() + sz, sz);
    ECDSA_SIG_free(sig_r_s);
  }

  static small_vector<uint16_t> encode_public_key(
    std::shared_ptr<const ccf::crypto::KeyPair> key)
  {
    auto coords = key->coordinates();
    small_vector<uint16_t> r(coords.x.size() + coords.y.size());
    for (size_t i = 0; i < coords.x.size(); i++)
      r[i] = coords.x[i];
    for (size_t i = 0; i < coords.y.size(); i++)
      r[coords.x.size() + i] = coords.y[i];
    return r;
  }

  static RFC4034::SigningFunction make_signing_function(
    std::shared_ptr<ccf::crypto::KeyPair> signing_key)
  {
    RFC4034::SigningFunction r = [signing_key](
                                   RFC4034::Algorithm algorithm,
                                   const std::vector<uint8_t>& data_to_sign) {
      if (algorithm != RFC4034::Algorithm::ECDSAP384SHA384)
        throw std::runtime_error(
          fmt::format("algorithm {} not supported", algorithm));
      auto coords = signing_key->coordinates();
      CCF_APP_TRACE(
        "ADNS: SIGN: key x/y {}{}",
        ccf::ds::to_hex(coords.x),
        ccf::ds::to_hex(coords.y));
      CCF_APP_TRACE("SIGN: data={}", ccf::ds::to_hex(data_to_sign));
      auto sig = signing_key->sign(data_to_sign, ccf::crypto::MDType::SHA384);
      CCF_APP_TRACE("ADNS: SIGN: sig={}", ccf::ds::to_hex(sig));
      convert_ec_signature_to_ieee_p1363(sig, signing_key);
      CCF_APP_TRACE("ADNS: SIGN: r/s sig={}", ccf::ds::to_hex(sig));
      return sig;
    };
    return r;
  }

  Resolver::Resolver() {}

  Resolver::~Resolver() {}

  uint16_t get_key_tag(const RFC4034::DNSKEY& dnskey_rdata)
  {
    small_vector<uint16_t> bytes = dnskey_rdata;
    return RFC4034::keytag(&bytes[0], bytes.size());
  }

  Resolver::Reply Resolver::reply(const Message& msg)
  {
    try
    {
      Message r;

      r.header.id = msg.header.id;
      r.header.qr = true;
      r.header.opcode = msg.header.opcode;
      r.header.aa = true;
      r.header.tc = false;
      r.header.rd = false;
      r.header.ra = false;
      r.header.rcode = ResponseCode::NO_ERROR;

      for (const auto& q : msg.questions)
      {
        auto resolution = resolve(
          q.qname,
          static_cast<aDNS::QType>(q.qtype),
          static_cast<aDNS::QClass>(q.qclass));

        r.header.rcode = resolution.response_code;

        r.questions.push_back(q);

        r.answers.insert(
          r.answers.end(),
          resolution.answers.begin(),
          resolution.answers.end());

        r.authorities.insert(
          r.authorities.end(),
          resolution.authorities.begin(),
          resolution.authorities.end());

        r.additionals.insert(
          r.additionals.end(),
          resolution.additionals.begin(),
          resolution.additionals.end());

        r.header.aa &= resolution.is_authoritative;
      }

      size_t peer_udp_payload_size = 0;

      bool have_client_opt = false;
      for (const auto& rr : msg.additionals)
      {
        if (rr.type == static_cast<uint16_t>(Type::OPT))
        {
          CCF_APP_TRACE("ADNS: EDNS(0): {}", string_from_resource_record(rr));

          if (have_client_opt)
          {
            // More than one OPT record is a format violation
            // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.1
            r.header.rcode = ResponseCode::FORMAT;
            break;
          }

          peer_udp_payload_size = rr.class_;

          RFC6891::TTL ttl(rr.ttl);
          ttl.version = 0;
          ttl.dnssec_ok = true;
          ttl.extended_rcode = 0;
          ttl.z = 0;

          uint16_t udp_payload_size = 512;
          ResourceRecord opt_reply(
            Name("."),
            static_cast<uint16_t>(Type::OPT),
            udp_payload_size,
            (uint32_t)ttl,
            {});
          CCF_APP_TRACE(
            "ADNS: EDNS(0) reply: {}", string_from_resource_record(opt_reply));
          r.additionals.push_back(opt_reply);
          have_client_opt = true;
        }
      }

      r.header.qdcount = r.questions.size();
      r.header.ancount = r.answers.size();
      r.header.nscount = r.authorities.size();
      r.header.arcount = r.additionals.size();

      return {r, peer_udp_payload_size};
    }
    catch (std::exception& ex)
    {
      CCF_APP_FAIL("ADNS: Exception: {}", ex.what());
    }
    catch (...)
    {
      CCF_APP_FAIL("ADNS: Unknown exception");
    }

    Message r;
    r.header.id = msg.header.id;
    r.header.qr = true;
    r.header.rcode = SERVER_FAILURE;
    return {r, 0};
  }

  RFC4034::CanonicalRRSet Resolver::find_records(
    const Name& origin,
    const Name& qname,
    QType qtype,
    QClass qclass,
    std::optional<std::function<bool(const ResourceRecord&)>> condition)
  {
    CCF_APP_TRACE(
      "ADNS: Find: {} {} {} {}",
      std::string(origin),
      std::string(qname),
      string_from_qtype(qtype),
      string_from_qclass(qclass));
    RFC4034::CanonicalRRSet records;
    for_each(
      origin,
      qname,
      qclass,
      qtype,
      [this, &origin, &records, &condition](const auto& rr) {
        if ((!condition || (*condition)(rr)))
          records.insert(rr);
        return true;
      });
    return records;
  }

  RFC4034::CanonicalRRSet Resolver::find_rrsigs(
    const Name& origin, const Name& name, QClass qclass, Type type_covered)
  {
    return find_records(
      origin,
      name,
      static_cast<QType>(Type::RRSIG),
      qclass,
      [type_covered](const auto& rr) {
        RFC4034::RRSIG rd(rr.rdata, type2str);
        return rd.type_covered == static_cast<uint16_t>(type_covered);
      });
  }

  RFC1035::ResponseCode Resolver::find_nsec3_records(
    const Name& origin,
    QClass qclass,
    const Name& qname,
    RFC4034::CanonicalRRSet& r)
  {
    auto configuration = get_configuration();

    auto nsec3params = find_records(origin, origin, QType::NSEC3PARAM, qclass);
    if (nsec3params.empty())
      return RFC1035::SERVER_FAILURE;

    RFC5155::NSEC3PARAM p(nsec3params.begin()->rdata);
    auto name_hash = RFC5155::NSEC3::hash(
      origin, qname, configuration.nsec3_hash_iterations, p.salt);
    std::string nameb32 = base32hex_encode(&name_hash[0], name_hash.size());
    assert(nameb32.size() <= 63);
    RFC1035::Name name(nameb32);
    const RFC1035::Name& suffix = qname;
    name += suffix;
    name.lower();

    auto nsec3 = find_records(origin, name, QType::NSEC3, qclass);

    if (!nsec3.empty())
    {
      CCF_APP_DEBUG("ADNS: Found NSEC3: {}", std::string(name));
      r += nsec3;
      r += find_rrsigs(origin, name, qclass, Type::NSEC3);
      return RFC1035::NO_ERROR;
    }

    // This is wrong. We need to find the closest encloser. See
    // https://www.rfc-editor.org/rfc/rfc5155#section-7.2.1

    const auto& ns = get_ordered_names(origin, static_cast<Class>(qclass));

    auto preceding = find_preceding(ns, origin, name);

    CCF_APP_DEBUG("ADNS: Preceding: {}", std::string(preceding));

    r += find_records(origin, preceding, QType::NSEC3, qclass);
    r += find_rrsigs(origin, preceding, qclass, Type::NSEC3);

    return RFC1035::NAME_ERROR; // NXDOMAIN
  }

  Name Resolver::find_preceding(
    const Names& ns, const Name& origin, const Name& sname)
  {
    for (auto it = ns.rbegin(); it != ns.rend();)
    {
      auto next = it;
      next++;

      if (
        RFC4034::operator<(*it, sname) &&
        (next == ns.rend() || !RFC4034::operator<(sname, *next)))
        return *it;

      it = next;
    }

    return origin;
  }

  RFC1035::ResponseCode Resolver::find_nsec_records(
    const Name& origin,
    QClass sclass,
    const Name& sname,
    RFC4034::CanonicalRRSet& r)
  {
    // NODATA:

    // If the zone contains RRsets matching <SNAME, SCLASS> but contains no
    // RRset matching <SNAME, SCLASS, STYPE>, then the name server MUST include
    // the NSEC RR for <SNAME, SCLASS> along with its associated RRSIG RR(s) in
    // the Authority section of the response (see Section 3.1.1).  If space
    // does not permit inclusion of the NSEC RR or its associated RRSIG RR(s),
    // the name server MUST set the TC bit (see Section 3.1.1).

    // Since the search name exists, wildcard name expansion does not apply to
    // this query, and a single signed NSEC RR suffices to prove that the
    // requested RR type does not exist.

    // For NODATA, we would find an NSEC record for sname
    auto nsec = find_records(origin, sname, QType::NSEC, sclass);

    if (!nsec.empty())
    {
      r += nsec;
      r += find_rrsigs(origin, sname, sclass, Type::NSEC);
      return RFC1035::ResponseCode::NO_ERROR;
    }

    // NXDOMAIN:

    // If the zone does not contain any RRsets matching <SNAME, SCLASS> either
    // exactly or via wildcard name expansion, then the name server MUST include
    // the following NSEC RRs in the Authority section, along with their
    // associated RRSIG RRs:

    // o  An NSEC RR proving that there is no exact match for <SNAME, SCLASS>.

    // o  An NSEC RR proving that the zone contains no RRsets that would match
    // <SNAME, SCLASS> via wildcard name expansion.

    const auto& ns = get_ordered_names(origin, static_cast<Class>(sclass));

    auto preceding = find_preceding(ns, origin, sname);

    r += find_records(origin, preceding, QType::NSEC, sclass);
    r += find_rrsigs(origin, preceding, sclass, Type::NSEC);

    return RFC1035::ResponseCode::NAME_ERROR;
  }

  Resolver::Resolution Resolver::resolve(
    const Name& qnameu, QType qtype, QClass qclass)
  {
    Resolution result;

    if (qtype == QType::ASTERISK || qclass == QClass::ASTERISK)
      return {ResponseCode::NOT_IMPLEMENTED, {}, {}, {}};

    if (!qnameu.is_absolute())
      throw std::runtime_error("cannot resolve relative names");

    Name qname = qnameu.lowered();

    // Find an origin
    Name origin;
    for (size_t i = 0; i < qname.labels.size(); i++)
    {
      Name po = Name(std::span(qname.labels).last(i + 1));
      if (origin_exists(po))
      {
        origin = po;
        break; // Keep walking down the tree?
      }
    }

    if (!origin.is_absolute())
      return result;

    auto& result_set = result.answers;

    RFC4034::CanonicalRRSet records;

    records = find_records(origin, qname, qtype, qclass);
    result.is_authoritative = true;

    for (const auto& rr : records)
      if (rr.name == qname)
        result_set +=
          find_rrsigs(origin, rr.name, qclass, static_cast<Type>(rr.type));

    result_set += records;

    if (result_set.empty())
    {
      auto cfg = get_configuration();
      auto& ra = result.authorities;

      ra += find_records(origin, origin, QType::SOA, qclass);
      ra += find_rrsigs(origin, origin, qclass, Type::SOA);

      if (cfg.use_nsec3)
        result.response_code = find_nsec3_records(origin, qclass, qname, ra);
      else
        result.response_code = find_nsec_records(origin, qclass, qname, ra);
    }

    CCF_APP_DEBUG(
      "ADNS: Resolve: {} type {} class {}: {} records",
      std::string(qname),
      string_from_qtype(qtype),
      string_from_qclass(qclass),
      std::to_string(result_set.size()));
    for (const auto& rr : result_set)
      CCF_APP_TRACE("ADNS:  - {}", string_from_resource_record(rr));

    return result;
  }

  RFC4034::CanonicalRRSet Resolver::get_ordered_records(
    const Name& origin, QClass c, QType t, const Name& name) const
  {
    RFC4034::CanonicalRRSet r;

    for_each(origin, name, c, t, [&origin, &r](const auto& rr) {
      r += RFC4034::canonicalize(origin, rr, type2str);
      return true;
    });

    return r;
  }

  const Resolver::Names& Resolver::get_ordered_names(
    const Name& origin, Class c)
  {
    if (name_cache_dirty)
    {
      name_cache.clear();

      for (const auto& [_, t] : supported_types)
      {
        for_each(
          origin,
          static_cast<QClass>(c),
          static_cast<QType>(t),
          [this, &origin](const auto& rr) {
            name_cache.insert(rr.name);
            return true;
          });
      }

      name_cache_dirty = false;
    }

    return name_cache;
  }

  Resolver::Names Resolver::get_ordered_names(
    const Name& origin, Class c, Type t)
  {
    Names r;
    for_each(
      origin,
      static_cast<QClass>(c),
      static_cast<QType>(t),
      [&origin, &r](const auto& rr) {
        r.insert(rr.name);
        return true;
      });

    return r;
  }

  Resolver::KeyAndTag Resolver::add_new_signing_key(
    const Name& origin, Class class_, bool key_signing)
  {
    const auto& configuration = get_configuration();

    auto new_zsk = ccf::crypto::make_key_pair();

    small_vector<uint16_t> new_zsk_pk = encode_public_key(new_zsk);

    RFC4034::DNSKEYRR dnskey_rr =
      add_dnskey(origin, class_, new_zsk_pk, key_signing);
    auto new_zsk_tag = get_key_tag(dnskey_rr.rdata);

    CCF_APP_DEBUG(
      "ADNS: NEW KEY for {}, class={}, tag={}:",
      std::string(origin),
      class_,
      new_zsk_tag);
    CCF_APP_DEBUG("ADNS: - {}", string_from_resource_record(dnskey_rr));
    CCF_APP_DEBUG("ADNS:   - xy={}", ccf::ds::to_hex(new_zsk_pk));

    if (
      origin_exists(origin.parent()) &&
      (!configuration.use_key_signing_key || key_signing))
      add_ds(origin, class_, new_zsk, new_zsk_tag, dnskey_rr.rdata);

    on_new_signing_key(
      origin,
      new_zsk_tag,
      new_zsk->private_key_pem(),
      configuration.use_key_signing_key && key_signing);

    return std::make_pair(new_zsk, new_zsk_tag);
  }

  // returns keypair and tag for this origin + class + flags;
  // creates a new key if no existing key is found
  Resolver::KeyAndTag Resolver::get_signing_key(
    const Name& origin, Class class_, bool key_signing)
  {
    const auto& configuration = get_configuration();

    bool find_ksk = configuration.use_key_signing_key && key_signing;

    RFC4034::CanonicalRRSet suitable_keys = find_records(
      origin,
      origin,
      QType::DNSKEY,
      static_cast<QClass>(class_),
      [&find_ksk](const auto& rr) {
        return find_ksk == RFC4034::DNSKEY(rr.rdata).is_key_signing_key();
      });

    if (suitable_keys.empty())
      return add_new_signing_key(origin, class_, key_signing);
    else
    {
      auto chosen_key = suitable_keys.begin();

      RFC4034::DNSKEY dnskey(chosen_key->rdata);
      uint16_t key_tag = get_key_tag(dnskey);

      auto pem = get_private_key(origin, key_tag, dnskey.public_key, find_ksk);
      auto key = ccf::crypto::make_key_pair(pem);
      return std::make_pair(key, key_tag);
    }
  }

  RFC4034::DNSKEYRR Resolver::add_dnskey(
    const Name& origin,
    Class class_,
    const small_vector<uint16_t>& public_key,
    bool key_signing)
  {
    auto configuration = get_configuration();

    uint16_t flags = 0x0000;

    if (!configuration.use_key_signing_key || !key_signing)
      flags |= 0x0100;

    if (configuration.use_key_signing_key && key_signing)
      flags |= 0x0101;

    RFC4034::DNSKEYRR rr(
      origin,
      static_cast<RFC1035::Class>(class_),
      configuration.default_ttl,
      flags,
      configuration.signing_algorithm,
      public_key);

    add(origin, rr);

    return rr;
  }

  void Resolver::add_ds(
    const Name& origin,
    Class class_,
    std::shared_ptr<ccf::crypto::KeyPair> key,
    uint16_t tag,
    const small_vector<uint16_t>& dnskey_rdata)
  {
    if (origin.is_root())
      return;

    auto configuration = get_configuration();

    Name parent = origin.parent();
    auto ds_rrs = find_records(parent, origin, QType::DS, QClass::IN);

    if (!ds_rrs.empty())
      throw std::runtime_error("too many DS records");

    add(
      parent,
      RFC4034::DSRR(
        origin,
        static_cast<RFC1035::Class>(class_),
        configuration.default_ttl,
        tag,
        configuration.signing_algorithm,
        configuration.digest_type,
        dnskey_rdata));
  }

  // for RRSIG inception and expiration, we tolerate up to 5 minutes of clock
  // skew
  static const uint32_t acceptable_clock_skew = 300;

  ResourceRecord Resolver::add_nsec3(
    Class c,
    const Name& origin,
    uint32_t ttl,
    const small_vector<uint8_t>& name_hash,
    const small_vector<uint8_t>& next_hashed_owner_name,
    const RFC1035::Name& suffix,
    std::set<Type> types,
    uint32_t nsec_ttl,
    uint32_t sig_time,
    const KeyAndTag& key_and_tag)
  {
    assert(!types.empty());
    auto configuration = get_configuration();

    std::string nameb32 = base32hex_encode(&name_hash[0], name_hash.size());
    assert(nameb32.size() <= 63);
    RFC1035::Name name(nameb32);
    name += suffix;
    name.lower();

    uint8_t flags = 0;
    uint16_t iterations = 2;

    RFC5155::NSEC3 rdata(
      configuration.nsec3_hash_algorithm,
      flags,
      configuration.nsec3_hash_iterations,
      get_nsec3_salt(origin, static_cast<QClass>(c)),
      next_hashed_owner_name,
      type2str);

    for (const auto& t : types)
      if (t != Type::NSEC3)
        rdata.type_bit_maps.insert(static_cast<uint16_t>(t));

    rdata.type_bit_maps.insert(static_cast<uint16_t>(Type::RRSIG));

    ResourceRecord rr(
      name,
      static_cast<uint16_t>(Type::NSEC3),
      static_cast<uint16_t>(c),
      ttl,
      rdata);

    add(origin, rr);

    // Add RRSIG for NSEC3
    RFC4034::CRRS crrs(
      rr.name,
      static_cast<RFC1035::Class>(c),
      static_cast<uint16_t>(Type::NSEC3),
      nsec_ttl,
      rr.rdata);

    auto [key, key_tag] = key_and_tag;
    add(
      origin,
      RFC4034::RRSIGRR(
        make_signing_function(key),
        key_tag,
        configuration.signing_algorithm,
        origin,
        crrs,
        sig_time - acceptable_clock_skew,
        sig_time + acceptable_clock_skew + nsec_ttl,
        type2str));

    return rr;
  }

  size_t Resolver::sign_rrset(
    const Name& origin,
    QClass c,
    QType t,
    const Name& name,
    uint32_t sig_time,
    std::shared_ptr<ccf::crypto::KeyPair> key,
    uint16_t key_tag,
    RFC4034::Algorithm signing_algorithm)
  {
    CCF_APP_DEBUG(
      "ADNS: Signing {} class {} type {}",
      std::string(name),
      string_from_qclass(c),
      string_from_qtype(t));

    auto crecords = get_ordered_records(origin, c, t, name);

    if (!crecords.empty())
    {
      RFC4034::CRRS crrs(
        name,
        crecords.begin()->class_,
        crecords.begin()->type,
        crecords.begin()->ttl);

      for (const auto& rr : crecords)
      {
        if (rr.ttl != crrs.ttl)
          CCF_APP_INFO(
            "ADNS: warning: TTL mismatch in record set for {} type {}",
            std::string(name),
            type2str(rr.type));

        crrs.rdata.insert(rr.rdata);
      }

      add(
        origin,
        RFC4034::RRSIGRR(
          make_signing_function(key),
          key_tag,
          signing_algorithm,
          origin,
          crrs,
          sig_time - acceptable_clock_skew,
          sig_time + acceptable_clock_skew + crrs.ttl,
          type2str));
    }

    return crecords.size();
  }

  void Resolver::sign(const Name& origin)
  {
    std::lock_guard<std::mutex> lock(sign_mtx);

    const auto& cfg = get_configuration();

    const uint32_t sig_time = get_fresh_time();
    CCF_APP_INFO(
      "ADNS: (Re)signing {} at time {}", std::string(origin), sig_time);

    if (!origin.is_absolute())
      throw std::runtime_error("origin is not absolute");

    if (!origin.ends_with(cfg.origin))
      throw std::runtime_error("origin is out of zone");

    name_cache_dirty = true;

    for (const auto& [_, c] : supported_classes)
    {
      // Note: the following may trigger addition of RRs
      auto ksk_and_tag = get_signing_key(origin, c, true);
      auto zsk_and_tag = get_signing_key(origin, c, false);

      if (!ksk_and_tag.first || !zsk_and_tag.first)
        throw std::runtime_error("missing signing key");

      auto soa_records =
        find_records(origin, origin, QType::SOA, static_cast<QClass>(c));

      if (soa_records.size() > 1)
        throw std::runtime_error("too many SOA records");

      bool is_authoritative = soa_records.size() == 1;

      uint32_t nsec_ttl = cfg.default_ttl;

      if (is_authoritative)
      {
        SOA soa_rdata(soa_records.begin()->rdata);
        nsec_ttl = soa_rdata.minimum;
      }

      remove(origin, c, Type::RRSIG);
      remove(origin, c, Type::NSEC);
      remove(origin, c, Type::NSEC3); // Necessary?

      HashedNameTypesMap nsec3_types;
      NameTypesMap nsec_types;

    restart:
      for (const auto& [__, t] : supported_types)
      {
        if (
          t == Type::RRSIG || t == Type::OPT || t == Type::NSEC ||
          t == Type::NSEC3)
          continue; // These are not signed but recreated

        auto names = get_ordered_names(origin, c, t);

        for (auto it = names.begin(); it != names.end(); it++)
        {
          const auto& name = *it;

          // delegation points/glue records are not signed
          // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
          if (t == Type::NS && name != origin)
            continue;

          auto [key, key_tag] = t == Type::DNSKEY && cfg.use_key_signing_key ?
            ksk_and_tag :
            zsk_and_tag;

          auto num_records = sign_rrset(
            origin,
            static_cast<QClass>(c),
            static_cast<QType>(t),
            name,
            sig_time,
            key,
            key_tag,
            cfg.signing_algorithm);

          if (cfg.use_nsec3 && num_records > 0)
          {
            auto hashed_owner = RFC5155::NSEC3::hash(
              origin,
              name,
              cfg.nsec3_hash_iterations,
              get_nsec3_salt(origin, static_cast<aDNS::QClass>(c)));

            auto hit = nsec3_types.find(hashed_owner);
            if (hit != nsec3_types.end() && hit->second.name != name)
            {
              // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
              // hash collision, restart with new salt
              update_nsec3_param(
                origin,
                c,
                nsec_ttl,
                cfg.nsec3_hash_algorithm,
                cfg.nsec3_hash_iterations,
                cfg.nsec3_salt_length);
              nsec3_types.clear();
              CCF_APP_INFO(
                "ADNS: Restarting zone signing after NSEC3 hash collision");
              goto restart;
            }

            if (hit == nsec3_types.end())
            {
              nsec3_types[hashed_owner].name = name;
              nsec3_types[hashed_owner].types = {t, Type::RRSIG};
            }
            else
              hit->second.types.insert({t, Type::RRSIG});
          }
          else
          {
            nsec_types[name].insert(static_cast<Type>(t));
            nsec_types[name].insert(Type::RRSIG);
          }
        }
      }

      if (cfg.use_nsec3)
      {
        // https://datatracker.ietf.org/doc/html/rfc5155#section-3.1.7
        for (auto it = nsec3_types.begin(); it != nsec3_types.end(); it++)
        {
          auto next = std::next(it);

          const Name& owner = it->second.name;
          small_vector<uint8_t> next_hashed_owner_name =
            next != nsec3_types.end() ? next->first :
                                        nsec3_types.begin()->first;

          auto rr = add_nsec3(
            c,
            origin,
            nsec_ttl,
            it->first,
            next_hashed_owner_name,
            owner,
            it->second.types,
            nsec_ttl,
            sig_time,
            zsk_and_tag);
        }
      }
      else
      {
        for (auto it = nsec_types.begin(); it != nsec_types.end();)
        {
          auto next = std::next(it);
          Name next_domain_name = next != nsec_types.end() ?
            next->first :
            (is_authoritative ? soa_records.begin()->name : origin);

          std::set<RFC4034::Type> types;
          types.insert(RFC4034::Type::RRSIG);
          types.insert(RFC4034::Type::NSEC);
          for (const auto t : it->second)
            types.insert(static_cast<RFC4034::Type>(t));

          RFC4034::NSECRR rr(
            it->first,
            static_cast<RFC1035::Class>(c),
            nsec_ttl,
            next_domain_name,
            types,
            type2str);
          add(origin, rr);

          RFC4034::CRRS crrs(
            it->first,
            static_cast<RFC1035::Class>(c),
            static_cast<uint16_t>(Type::NSEC),
            nsec_ttl,
            rr.rdata);

          auto [key, key_tag] = zsk_and_tag;
          add(
            origin,
            RFC4034::RRSIGRR(
              make_signing_function(key),
              key_tag,
              cfg.signing_algorithm,
              origin,
              crrs,
              sig_time - acceptable_clock_skew,
              sig_time + acceptable_clock_skew + crrs.ttl,
              type2str));

          it = next;
        }
      }
    }

    CCF_APP_INFO("ADNS: (Re)signing {} done", std::string(origin));
  }

  std::shared_ptr<ccf::crypto::KeyPair> Resolver::get_tls_key()
  {
    // The CCF resolver uses the network key, but we could also use the zone
    // or key signing key.
    const auto& cfg = get_configuration();
    return get_signing_key(cfg.origin, Class::IN, true).first;
  }

  ResourceRecord Resolver::mk_rr(
    const Name& name,
    aDNS::Type type,
    aDNS::Class class_,
    uint32_t ttl,
    const small_vector<uint16_t>& rdata)
  {
    return ResourceRecord(
      name,
      static_cast<uint16_t>(type),
      static_cast<uint16_t>(class_),
      ttl,
      rdata);
  }

  small_vector<uint8_t> Resolver::get_nsec3_salt(
    const Name& origin, aDNS::QClass class_)
  {
    auto params_rrs = find_records(origin, origin, QType::NSEC3PARAM, class_);

    if (params_rrs.empty())
    {
      auto cfg = get_configuration();

      update_nsec3_param(
        origin,
        static_cast<Class>(class_),
        cfg.default_ttl,
        cfg.nsec3_hash_algorithm,
        cfg.nsec3_hash_iterations,
        cfg.nsec3_salt_length);

      params_rrs = find_records(origin, origin, QType::NSEC3PARAM, class_);

      if (params_rrs.empty())
        throw std::runtime_error(fmt::format(
          "failed to add NSEC3PARAM record for {}", std::string(origin)));
    }

    return RFC5155::NSEC3PARAM(params_rrs.begin()->rdata).salt;
  }

  small_vector<uint8_t> Resolver::generate_nsec3_salt(uint8_t length)
  {
    small_vector<uint8_t> salt(length);
    auto e = ccf::crypto::get_entropy();
    e->random(&salt[0], salt.size());
    return salt;
  }

  void Resolver::update_nsec3_param(
    const Name& origin,
    aDNS::Class class_,
    uint16_t ttl,
    RFC5155::HashAlgorithm hash_algorithm,
    uint16_t hash_iterations,
    uint8_t salt_length)
  {
    remove(origin, origin, class_, Type::NSEC3PARAM);

    auto r = generate_nsec3_salt(salt_length);

    CCF_APP_TRACE("CCFDNS: new nsec3 salt: {}", ccf::ds::to_hex(r));

    add(
      origin,
      RFC5155::NSEC3PARAMRR(
        origin,
        static_cast<RFC1035::Class>(class_),
        ttl,
        hash_algorithm,
        0x00,
        hash_iterations,
        r));
  }

  Resolver::RegistrationInformation Resolver::configure(
    const Configuration& cfg)
  {
    set_configuration(cfg);

    update_nsec3_param(
      cfg.origin,
      aDNS::Class::IN,
      cfg.default_ttl,
      cfg.nsec3_hash_algorithm,
      cfg.nsec3_hash_iterations,
      cfg.nsec3_salt_length);

    if (cfg.node_addresses.empty())
      throw std::runtime_error("missing node information");

    auto tls_key = get_tls_key();

    RegistrationInformation out;

    out.public_key = tls_key->public_key_pem().str();
    out.node_information = get_node_information();

    remove(cfg.origin, cfg.origin, Class::IN, Type::SOA);
    add(cfg.origin, mk_rr(cfg.origin, Type::SOA, Class::IN, 60, SOA(cfg.soa)));

    remove(cfg.origin, cfg.origin, Class::IN, Type::NS);
    remove(cfg.origin, cfg.origin, Class::IN, Type::A);

    for (const auto& [id, addr] : cfg.node_addresses)
    {
      if (!addr.name.ends_with(cfg.origin))
        throw std::runtime_error(fmt::format(
          "invalid node name; '{}' is outside the zone",
          std::string(addr.name)));

      add(
        cfg.origin,
        mk_rr(cfg.origin, Type::NS, Class::IN, cfg.default_ttl, NS(addr.name)));

      remove(cfg.origin, addr.name, Class::IN, Type::A);
      add(
        cfg.origin,
        mk_rr(addr.name, Type::A, Class::IN, cfg.default_ttl, A(addr.ip)));

      add(
        cfg.origin,
        mk_rr(cfg.origin, Type::A, Class::IN, cfg.default_ttl, A(addr.ip)));
    }

    // signs initial records; this triggers the creation of fresh DNSKEY
    // records.
    sign(cfg.origin);

    std::string cn;
    std::vector<ccf::crypto::SubjectAltName> sans;

    cn = cfg.origin.unterminated();
    sans.push_back({cn, false});
    for (const auto& [id, addr] : cfg.node_addresses)
      sans.push_back({addr.name.unterminated(), false});

    if (cfg.alternative_names)
      for (const auto& san : *cfg.alternative_names)
        sans.push_back({san, false});

    CCF_APP_INFO("CCFDNS: Resolver::configure(): CSR");
    out.csr =
      tls_key->create_csr_der("CN=" + cn, sans, tls_key->public_key_pem());

    // get_signing_key(cfg.origin, Class::IN, cfg.use_key_signing_key);

    CCF_APP_INFO("CCFDNS: Resolver::configure(): Resolve DNSKEY");
    auto dnskeys = resolve(cfg.origin, QType::DNSKEY, QClass::IN);

    if (dnskeys.answers.size() > 0)
    {
      out.dnskey_records = std::vector<ResourceRecord>();
      for (const auto& keyrr : dnskeys.answers)
        if (keyrr.type == static_cast<uint16_t>(Type::DNSKEY))
        {
          if (cfg.use_key_signing_key)
          {
            RFC4034::DNSKEY rd(keyrr.rdata);
            if (rd.is_key_signing_key())
              out.dnskey_records->push_back(keyrr);
          }
          else
            out.dnskey_records->push_back(keyrr);
        }
    }
    CCF_APP_INFO(
      "CCFDNS: Resolver::configure(): Added {} records",
      dnskeys.answers.size());

    return out;
  }

  void Resolver::add_fragmented(
    const Name& origin,
    const Name& name,
    uint32_t ttl,
    aDNS::Class class_,
    const small_vector<uint16_t>& rrdata,
    bool compress,
    uint8_t records_per_name)
  {
    std::vector<uint8_t> tmp;

    uint16_t rsz = rrdata.size();
    const uint8_t* crrdata = rrdata.raw();

    if (compress)
    {
      tmp = aDNS::compress(rrdata, 9);
      crrdata = tmp.data();
      rsz = tmp.size();
    }

    size_t num_rrs = rsz / 15;

    if ((rsz % 15) != 0)
      num_rrs++;

    size_t num_names = num_rrs / records_per_name;

    if ((num_rrs % records_per_name) != 0)
      num_names++;

    if (num_names > 65535)
      throw std::runtime_error(
        "too many names/record for AAAA fragmented record");

    small_vector<uint16_t> tdata(16);

    size_t bytes_encoded = 0;
    for (size_t n = 0; n < num_names; n++)
    {
      Name fname = Name("_" + std::to_string(n)) + name;

      remove(origin, fname, Class::IN, Type::AAAA);

      for (size_t i = 0; i < records_per_name; i++)
      {
        tdata[0] = i;

        size_t bytes_per_fragment = records_per_name * 15;

        if (n == 0 && i == 0)
        {
          tdata[1] = rsz >> 8;
          tdata[2] = rsz & 0xFF;

          for (size_t j = 3; j < 16; j++)
            tdata[j] = bytes_encoded >= rsz ? 0 : crrdata[bytes_encoded++];
        }
        else
        {
          for (size_t j = 1; j < 16; j++)
            tdata[j] = bytes_encoded >= rsz ? 0 : crrdata[bytes_encoded++];
        }

        add(
          origin, mk_rr(fname, Type::AAAA, class_, ttl, RFC3596::AAAA(tdata)));

        if (bytes_encoded >= rsz)
          break;
      }
    }
  }

  void Resolver::add_fragmented(
    const Name& origin,
    const Name& name,
    const ResourceRecord& rr,
    bool compress,
    uint8_t records_per_name)
  {
    add_fragmented(
      origin,
      name,
      rr.ttl,
      static_cast<aDNS::Class>(rr.class_),
      rr.rdata,
      compress,
      records_per_name);
  }

  Name Resolver::find_zone(const Name& name)
  {
    for (Name t = name.parent(); !t.is_root(); t = t.parent())
      if (origin_exists(t))
        return t;
    throw std::runtime_error(
      fmt::format("no suitable zone found for {}", std::string(name)));
  }

  void Resolver::register_service(const std::vector<uint8_t>& request)
  {
    using namespace RFC7671;

    auto [phdr, payload] = decode_cose_request(request);
    auto public_key = reconstruct_public_key_from_cnf(phdr.cwt.cnf);

    CCF_APP_INFO(
      "Reconstructed public key DER: {}",
      ccf::ds::to_hex(public_key->public_key_der()));

    auto cose_verifier =
      ccf::crypto::make_cose_verifier_from_key(public_key->public_key_pem());
    std::span<uint8_t> authned_content{};
    cose_verifier->verify(request, authned_content);

    auto public_key_digest = ccf::crypto::sha256(public_key->public_key_der());

    small_vector<uint16_t> public_key_sv(
      public_key_digest.size(), public_key_digest.data());

    ccf::QuoteInfo attestation;
    ccf::pal::PlatformAttestationReportData report_data = {};
    ccf::pal::UVMEndorsements uvm_endorsements_descriptor = {};
    ccf::pal::PlatformAttestationMeasurement measurement = {};
    HostData host_data = {};

    std::string attestation_json(payload.begin(), payload.end());

    try
    {
      attestation = parse_and_verify_attestation(
        attestation_json,
        report_data,
        measurement,
        uvm_endorsements_descriptor);

      if (attestation.format != ccf::QuoteFormat::insecure_virtual)
      {
        host_data = retrieve_host_data(attestation);
      }
    }
    catch (const std::exception& e)
    {
      throw std::runtime_error(
        fmt::format("ADNS: Failed to verify attestation report: {}", e.what()));
    }

    // SNP report data is 64 bytes, key hash is 32, the rest has to be zeroed.
    // Virtual report data is set to 32 bytes in CCF.
    assert(
      report_data.data.size() == ccf::pal::snp_attestation_report_data_size ||
      report_data.data.size() ==
        ccf::pal::virtual_attestation_report_data_size);

    assert(public_key_digest.size() == 32);

    if (!std::equal(
          public_key_digest.begin(),
          public_key_digest.end(),
          report_data.data.begin()))
    {
      throw std::runtime_error(
        "ADNS: Attestation report hash does not match public key");
    }

    if (
      report_data.data.size() == ccf::pal::snp_attestation_report_data_size &&
      !std::all_of(
        report_data.data.begin() + public_key_digest.size(),
        report_data.data.end(),
        [](uint8_t b) { return b == 0; }))
    {
      throw std::runtime_error(
        "ADNS: Attestation report data for {} is not zeroed after key hash");
    }

    Name service_name(phdr.cwt.iss);

    if (!service_name.is_absolute())
      service_name += std::vector<Label>{Label()};

    auto origin = find_zone(service_name);

    CCF_APP_INFO(
      "ADNS: Register service {} in {}",
      std::string(service_name),
      std::string(origin));

    save_service_registration_request(service_name, request);

    if (attestation.format != ccf::QuoteFormat::insecure_virtual)
    {
      try
      {
        auto platform = nlohmann::json(phdr.cwt.att).dump();
        verify_platform_definition(
          ccf::ds::to_hex(measurement.data), platform_definition(platform));

        verify_service_definition(
          ccf::crypto::b64_from_raw(host_data.h.data(), host_data.h.size()),
          service_definition(service_name));
      }
      catch (const std::exception& e)
      {
        throw std::runtime_error(
          fmt::format("ADNS: Failed to register with error {}", e.what()));
      }
    }

    auto configuration = get_configuration();

    const auto& name = service_name.terminated();

    if (!name.ends_with(service_name))
      throw std::runtime_error(fmt::format(
        "node name '{}' outside of service sub-zone '{}'",
        std::string(name),
        std::string(service_name)));

    add(
      origin,
      mk_rr(
        name,
        Type::A,
        Class::IN,
        configuration.default_ttl,
        RFC1035::A(phdr.cwt.svi.ipv4)));

    add(
      origin,
      mk_rr(
        service_name,
        Type::A,
        Class::IN,
        configuration.default_ttl,
        RFC1035::A(phdr.cwt.svi.ipv4)));

    std::string prolow = phdr.cwt.svi.protocol;
    std::transform(prolow.begin(), prolow.end(), prolow.begin(), ::tolower);
    auto tlsa_name =
      Name("_" + phdr.cwt.svi.port) + Name(std::string("_") + prolow) + name;

    ResourceRecord tlsa_rr = mk_rr(
      tlsa_name,
      Type::TLSA,
      Class::IN,
      configuration.default_ttl,
      TLSA(
        CertificateUsage::DANE_EE,
        Selector::SPKI,
        MatchingType::SHA2_256,
        public_key_sv));

    sign(origin);
  }

  const std::map<uint16_t, Type>& Resolver::get_supported_types() const
  {
    return supported_types;
  }

  const std::map<uint16_t, Class>& Resolver::get_supported_classes() const
  {
    return supported_classes;
  }
}
