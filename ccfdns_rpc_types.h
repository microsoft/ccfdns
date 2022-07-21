// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rfc4034.h"

#include <ccf/crypto/pem.h>
#include <ccf/quote_info.h>
#include <cstdint>

namespace ccfdns
{
  struct RegisterService
  {
    struct In
    {
      std::string origin;
      std::string name;
      std::string address;

      ccf::QuoteInfo quote_info;

      RFC4034::Algorithm algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
      crypto::Pem public_key;
    };
    using Out = void;
  };

  DECLARE_JSON_TYPE(RegisterService::In);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegisterService::In,
    origin,
    name,
    address,
    quote_info,
    algorithm,
    public_key);
}
