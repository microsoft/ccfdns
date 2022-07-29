// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "qvl.h"
#include "rfc4034.h"

#include <ccf/crypto/pem.h>
#include <cstdint>
#include <ds/json.h>

namespace ccfdns
{
  struct RegisterService
  {
    struct In
    {
      std::string origin;
      std::string name;
      std::string address;

      QVL::Attestation attestation;

      RFC4034::Algorithm algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
      crypto::Pem public_key;
    };
    using Out = void;
  };
}

namespace QVL
{
  DECLARE_JSON_ENUM(
    Format,
    {{Format::NONE, "NONE"}, {Format::SGX, "SGX"}, {Format::AMD, "AMD"}});

  DECLARE_JSON_TYPE(Attestation);
  DECLARE_JSON_REQUIRED_FIELDS(Attestation, format, evidence, endorsements);
}

namespace ccfdns
{
  DECLARE_JSON_TYPE(RegisterService::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegisterService::In,
    origin,
    name,
    address,
    attestation,
    algorithm,
    public_key);
}
