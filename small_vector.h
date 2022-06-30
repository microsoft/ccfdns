// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "serialization.h"

#include <ccf/crypto/base64.h>
#include <cstdint>
#include <initializer_list>
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

  small_vector(const std::vector<uint8_t>& bytes, size_t& pos) :
    size_(0),
    data(nullptr)
  {
    size_ = get<T>(bytes, pos);
    if (size_ > 0)
    {
      data = new E[size_ * sizeof(E)];
      for (uint8_t i = 0; i < size_; i++)
        data[i] = get<E>(bytes, pos);
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

  std::string to_base64() const
  {
    return crypto::b64_from_raw(static_cast<uint8_t*>(data), size_);
  }

  static small_vector<T, E> from_base64(const std::string& b64)
  {
    auto bytes = crypto::raw_from_b64(b64);
    if (bytes.size() >= 1 << (sizeof(T) * 8))
      throw std::runtime_error("data too large for small_vector");
    return small_vector<T, E>(
      bytes.size() / sizeof(E), static_cast<E*>(&bytes[0]));
  }

  void put(std::vector<uint8_t>& r) const
  {
    ::put(size_, r);
    for (T i = 0; i < size_; i++)
      ::put(data[i], r);
  }

protected:
  T size_;
  E* data;
};
