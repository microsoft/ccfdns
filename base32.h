// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <vector>

std::string base32hex_encode(const std::vector<uint8_t>& raw);

std::vector<uint8_t> base32hex_decode(const std::string& b32);