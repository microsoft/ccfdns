// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <vector>

template <typename T, typename V = std::vector<uint8_t>>
inline T get(const V& bytes, size_t& pos)
{
  T r = 0;
  for (size_t i = 0; i < sizeof(T); i++)
  {
    if (pos >= bytes.size())
      throw std::runtime_error(
        "deserialization failed: insufficient number of bytes");
    r = r << 8 | bytes[pos++];
  }
  return r;
}

template <typename T, typename V = std::vector<uint8_t>>
inline std::vector<T> get_n(const V& bytes, size_t& pos, size_t n)
{
  std::vector<T> r(n);
  for (size_t i = 0; i < n; i++)
  {
    r[i] = T(bytes, pos);
  }
  return r;
}

template <>
inline std::vector<uint8_t> get_n(
  const std::vector<uint8_t>& bytes, size_t& pos, size_t n)
{
  std::vector<uint8_t> r(n);
  for (size_t i = 0; i < n; i++)
  {
    r[i] = get<uint8_t>(bytes, pos);
  }
  return r;
}

template <typename T, typename SIZE_TYPE>
inline std::vector<T> get(const std::vector<uint8_t>& bytes, size_t& pos)
{
  SIZE_TYPE sz = get<SIZE_TYPE>(bytes, pos);
  std::vector<T> r((size_t)sz);
  for (SIZE_TYPE i = 0; i < sz; i++)
    r[i] = get<T>(bytes, pos);
  return r;
}

template <typename T>
inline void put(const T& x, std::vector<uint8_t>& r)
{
  for (size_t i = 0; i < sizeof(T); i++)
  {
    uint8_t b = (x >> 8 * (sizeof(T) - 1 - i)) & 0xFF;
    r.push_back(b);
  }
}

template <typename T>
inline void put(const std::vector<T>& vec, std::vector<uint8_t>& r)
{
  for (const auto& elem : vec)
  {
    std::vector<uint8_t> t = elem;
    r.insert(std::end(r), std::begin(t), std::end(t));
  }
}

template <>
inline void put(const std::vector<uint8_t>& vec, std::vector<uint8_t>& r)
{
  put((uint16_t)vec.size(), r);
  r.insert(std::end(r), std::begin(vec), std::end(vec));
}
