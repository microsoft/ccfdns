// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "base32.h"
#include "serialization.h"

#include <ccf/crypto/base64.h>
#include <ccf/ds/hex.h>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>

template <typename T, typename E = uint8_t>
class small_vector
{
public:
  small_vector() : size_(0), data(nullptr) {}

  small_vector(const T& size) : size_(size)
  {
    data = size == 0 ? nullptr : new E[size * sizeof(E)];
  }

  small_vector(const T& size, const E* data) : size_(size), data(nullptr)
  {
    if (size_ > 0)
    {
      this->data = new E[size * sizeof(E)];
      for (T i = 0; i < size; i++)
        this->data[i] = data[i];
    }
  }

  small_vector(std::initializer_list<E> init) :
    size_(init.size()),
    data(nullptr)
  {
    if (size_ > 0)
    {
      data = new E[init.size() * sizeof(E)];
      T i = 0;
      for (auto it = init.begin(); it != init.end(); it++)
        data[i++] = *it;
    }
  }

  small_vector(const small_vector<T, E>& other) : size_(0), data(nullptr)
  {
    size_ = other.size_;
    if (size_ > 0)
    {
      data = new E[size_ * sizeof(E)];
      for (T i = 0; i < size_; i++)
        data[i] = other.data[i];
    }
  }

  small_vector(const std::span<const uint8_t>& bytes, size_t& pos) :
    size_(0),
    data(nullptr)
  {
    size_ = get<T>(bytes, pos);
    if (size_ > 0)
    {
      data = new E[size_ * sizeof(E)];
      for (T i = 0; i < size_; i++)
        data[i] = get<E>(bytes, pos);
    }
  }

  small_vector(const std::vector<uint8_t>& bytes, size_t& pos) :
    small_vector(std::span<const uint8_t>(bytes), pos)
  {}

  small_vector(const small_vector<uint16_t>& bytes, size_t& pos) :
    size_(0),
    data(nullptr)
  {
    size_ = get<T>(bytes, pos);
    if (size_ > 0)
    {
      data = new E[size_ * sizeof(E)];
      for (T i = 0; i < size_; i++)
        data[i] = get<E>(bytes, pos);
    }
  }

  small_vector(const std::string& s)
  {
    size_ = s.size();
    if (size_ > 0)
    {
      data = new uint8_t[size_];
      std::memcpy(data, s.data(), size_);
    }
  }

  ~small_vector()
  {
    if (size_ != 0)
      delete[] data;
  }

  E& operator[](const T& index)
  {
    return data[index];
  }

  const E& operator[](const T& index) const
  {
    return data[index];
  }

  E& at(const T& index) const
  {
    if (index >= size())
      throw std::out_of_range("small_vector");
    return data[index];
  }

  bool operator==(const small_vector<T, E>& other) const
  {
    if (size_ != other.size_)
      return false;
    for (T i = 0; i < size_; i++)
      if (data[i] != other.data[i])
        return false;
    return true;
  }

  T size() const
  {
    return size_;
  }

  bool empty() const
  {
    return size_ == 0;
  }

  void resize(const T& size, const E& elem)
  {
    E* new_data = size == 0 ? nullptr : new E[size * sizeof(E)];
    if (data)
    {
      for (T i = 0; i < std::min(size, size_); i++)
        new_data[i] = data[i];
      delete[] data;
    }
    if (size > size_)
    {
      for (T i = size_; i < size; i++)
        new_data[i] = elem;
    }
    size_ = size;
    data = new_data;
  }

  small_vector<T, E>& operator=(const small_vector<T, E>& other)
  {
    if (data)
      delete[] data;
    size_ = other.size_;
    data = nullptr;
    if (size_ > 0)
    {
      data = new E[size_ * sizeof(E)];
      for (T i = 0; i < size_; i++)
        data[i] = other.data[i];
    }
    return *this;
  }

  small_vector<T, E>& operator=(small_vector<T, E>&& other)
  {
    if (data)
      delete[] data;
    size_ = other.size_;
    data = other.data;
    other.size_ = 0;
    other.data = nullptr;
    return *this;
  }

  std::string to_base64(bool urlsafe = true) const
  {
    if (urlsafe)
      return crypto::b64url_from_raw(
        static_cast<uint8_t*>(data), size_ * sizeof(E));
    else
      return crypto::b64_from_raw(
        static_cast<uint8_t*>(data), size_ * sizeof(E));
  }

  static small_vector<T, E> from_base64(
    const std::string& b64, bool url_safe = true)
  {
    auto bytes =
      url_safe ? crypto::raw_from_b64url(b64) : crypto::raw_from_b64(b64);
    if (bytes.size() >= 1 << (sizeof(T) * 8))
      throw std::runtime_error("data too large for small_vector");
    return small_vector<T, E>(
      bytes.size() / sizeof(E), static_cast<E*>(&bytes[0]));
  }

  std::string to_base32hex() const
  {
    return base32hex_encode(data, size_);
  }

  static small_vector<T, E> from_base32hex(const std::string& b32)
  {
    auto bytes = base32hex_decode(b32);
    if (bytes.size() >= 1 << (sizeof(T) * 8))
      throw std::runtime_error("data too large for small_vector");
    return small_vector<T, E>(
      bytes.size() / sizeof(E), static_cast<E*>(&bytes[0]));
  }

  static small_vector<T, E> from_hex(const std::string& s)
  {
    auto sz = s.size() / 2;
    small_vector<T, E> r(sz);
    for (size_t i = 0; i < sz; i++)
      r[i] = (ds::hex_char_to_int(s[2 * i]) << 4) |
        ds::hex_char_to_int(s[2 * i + 1]);
    return r;
  }

  void put(std::vector<uint8_t>& r) const
  {
    ::put(size_, r);
    for (T i = 0; i < size_; i++)
      ::put(data[i], r);
  }

  bool operator<(const small_vector<T, E>& other) const
  {
    for (T i = 0; i < size_; i++)
    {
      if (i > other.size_)
        return false;

      if ((*this)[i] != other[i])
        return (*this)[i] < other[i];
    }
    return size_ < other.size_;
  }

  const E* raw() const
  {
    return data;
  }

protected:
  T size_;
  E* data;
};

template <typename T, typename E>
inline void put_n(
  const small_vector<T, E>& vec, std::vector<uint8_t>& r, size_t n)
{
  for (T i = 0; i < n; i++)
  {
    r.push_back(vec[i]);
  }
}

namespace ds
{
  template <typename T, typename E>
  inline static std::string to_hex(const small_vector<T, E>& data)
  {
    std::string r;
    for (T i = 0; i < data.size(); i++)
    {
      r += fmt::format("{:02x}", data[i]);
    }
    return r;
  }
}