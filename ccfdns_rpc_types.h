// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccfdns_json.h"
#include "qvl.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/crypto/pem.h>
#include <ccf/ds/json.h>
#include <cstdint>

namespace ccfdns
{

  struct AddRecord
  {
    struct In
    {
      RFC1035::Name origin;
      RFC1035::ResourceRecord record;
    };
  };

  typedef AddRecord RemoveRecord;

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
  DECLARE_JSON_TYPE(AddRecord::In)
  DECLARE_JSON_REQUIRED_FIELDS(AddRecord::In, origin, record)

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
