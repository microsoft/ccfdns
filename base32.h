// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <vector>

std::string base32hex_encode(const uint8_t* data, size_t size);

inline std::string base32hex_encode(const std::vector<uint8_t>& data)
{
  return base32hex_encode(data.data(), data.size());
}

std::vector<uint8_t> base32hex_decode(const std::string& b32);