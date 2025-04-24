// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "small_vector.h"

#include <vector>
#include <zlib.h>

namespace aDNS
{
  inline std::vector<uint8_t> decompress(const uint8_t* data, size_t sz)
  {
    static const constexpr size_t CHUNK = 8192;

    int ret;
    z_stream strm;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    strm.total_in = strm.total_out = 0;

    if (inflateInit(&strm) != Z_OK)
      throw std::runtime_error("inflateInit failed");

    std::vector<uint8_t> r;

    strm.avail_in = sz;
    strm.next_in = (unsigned char*)data;

    do
    {
      r.resize(strm.total_out + CHUNK);
      strm.avail_out = CHUNK;
      strm.next_out = &r[strm.total_out];

      ret = inflate(&strm, Z_FINISH);
      if (ret == Z_STREAM_ERROR)
        throw std::runtime_error("zlib Z_STREAM_ERROR error");
      if (ret != 0 && strm.msg)
        throw std::runtime_error(strm.msg);
      switch (ret)
      {
        case Z_NEED_DICT:
          ret = Z_DATA_ERROR;
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
          inflateEnd(&strm);
          throw std::runtime_error("zlib data error");
      }
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    r.resize(strm.total_out);

    return r;
  }

  inline std::vector<uint8_t> decompress(const std::vector<uint8_t>& data)
  {
    return decompress(data.data(), data.size());
  }

  template <typename T>
  inline std::vector<uint8_t> decompress(const small_vector<T>& data)
  {
    return decompress(data.raw(), data.size());
  }

  inline std::vector<uint8_t> compress(
    const uint8_t* data, size_t sz, int level)
  {
    static const constexpr size_t CHUNK = 8192;

    int ret = 0;
    int flush = 0;
    z_stream strm;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    strm.total_in = strm.total_out = 0;

    if (deflateInit(&strm, level) != Z_OK)
      throw std::runtime_error("deflateInit failed");

    std::vector<uint8_t> r;

    strm.avail_in = sz;
    strm.next_in = (unsigned char*)data;

    do
    {
      r.resize(strm.total_out + CHUNK);
      strm.avail_out = CHUNK;
      strm.next_out = &r[strm.total_out];

      ret = deflate(&strm, Z_FINISH);
      if (ret == Z_STREAM_ERROR)
        throw std::runtime_error("zlib Z_STREAM_ERROR error");
      if (ret != Z_OK && ret != Z_STREAM_END && strm.msg)
        throw std::runtime_error(strm.msg);
      switch (ret)
      {
        case Z_NEED_DICT:
          ret = Z_DATA_ERROR;
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
          deflateEnd(&strm);
          throw std::runtime_error("zlib data error");
      }
    } while (ret != Z_STREAM_END);

    deflateEnd(&strm);
    r.resize(strm.total_out);

    return r;
  }

  inline std::vector<uint8_t> compress(
    const std::vector<uint8_t>& data, int level)
  {
    return compress(data.data(), data.size(), level);
  }

  template <typename T>
  inline std::vector<uint8_t> compress(const small_vector<T>& data, int level)
  {
    return compress(data.raw(), data.size(), level);
  }
}
