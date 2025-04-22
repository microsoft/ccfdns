// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "compression.h"
#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"
#include "small_vector.h"

#include <ccf/crypto/base64.h>

namespace aDNS::Types
{
  enum class Type : uint16_t
  {
    TLSKEY = 32770,
    ATTEST = 32771
  };

  inline std::map<Type, std::string> type_string_map = {
    {Type::ATTEST, "ATTEST"}, {Type::TLSKEY, "TLSKEY"}};
}
