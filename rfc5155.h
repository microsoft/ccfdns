// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc4034.h"
#include "serialization.h"

#include <ccf/ds/hex.h>

namespace RFC5155 // https://datatracker.ietf.org/doc/html/rfc5155
{
  enum class Type : uint16_t
  {
    NSEC3 = 50,
    NSEC3PARAM = 51
  };

  inline std::map<Type, std::string> type_string_map = {
    {Type::NSEC3, "NSEC3"}, {Type::NSEC3PARAM, "NSEC3PARAM"}};

  enum class HashAlgorithm : uint8_t
  {
    RESERVED = 0,
    SHA1 = 1,
  };

  class NSEC3 : public RFC1035::RDataFormat
  {
  public:
    HashAlgorithm hash_algorithm;
    uint8_t flags;
    uint16_t iterations;
    small_vector<uint8_t> salt;
    small_vector<uint8_t> next_hashed_owner_name;
    RFC4034::NSEC::TypeBitMaps type_bit_maps;

    NSEC3(const std::function<std::string(const RFC4034::Type&)>& type2str) :
      type_bit_maps(type2str)
    {}

    NSEC3(
      HashAlgorithm hash_algorithm,
      uint8_t flags,
      uint16_t iterations,
      const small_vector<uint8_t>& salt,
      const small_vector<uint8_t>& next_hashed_owner_name,
      const std::function<std::string(const RFC4034::Type&)>& type2str);

    NSEC3(
      const std::string& s,
      const std::function<RFC4034::Type(const std::string&)>& str2type,
      const std::function<std::string(const RFC4034::Type&)>& type2str) :
      type_bit_maps(type2str)
    {
      std::istringstream f(s);
      uint8_t tmp;
      f >> tmp;
      hash_algorithm = static_cast<HashAlgorithm>(tmp);
      f >> flags;
      f >> iterations;
      std::string stmp;
      f >> stmp;
      salt = small_vector<uint8_t>::from_hex(stmp);
      f >> stmp;
      next_hashed_owner_name = small_vector<uint8_t>::from_base32hex(stmp);
      stmp = "";
      while (f.good())
      {
        std::string type;
        f >> type;
        stmp += type + " ";
      }
      type_bit_maps = RFC4034::NSEC::TypeBitMaps(stmp, str2type, type2str);
    }

    NSEC3(
      const small_vector<uint16_t>& data,
      const std::function<std::string(const RFC4034::Type&)>& type2str) :
      type_bit_maps(type2str)
    {
      size_t pos = 0;
      hash_algorithm = static_cast<HashAlgorithm>(get<uint8_t>(data, pos));
      flags = get<uint8_t>(data, pos);
      iterations = get<uint16_t>(data, pos);
      salt = small_vector<uint8_t>(data, pos);
      next_hashed_owner_name = small_vector<uint8_t>(data, pos);
      type_bit_maps = RFC4034::NSEC::TypeBitMaps(data, pos, type2str);
    }

    virtual ~NSEC3() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put((uint8_t)hash_algorithm, r);
      put(flags, r);
      put(iterations, r);
      salt.put(r);
      next_hashed_owner_name.put(r);
      type_bit_maps.put(r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r = std::to_string(static_cast<uint8_t>(hash_algorithm));
      r += " " + std::to_string(flags);
      r += " " + std::to_string(iterations);
      r += " " + (salt.size() > 0 ? ds::to_hex(salt) : "-");
      r += " " + next_hashed_owner_name.to_base32hex();
      r += " " + (std::string)type_bit_maps;
      return r;
    }

    static small_vector<uint8_t> hash(
      const RFC1035::Name& origin,
      const RFC1035::Name& name,
      uint16_t iterations,
      const small_vector<uint8_t>& salt);

    bool is_opt_out() const
    {
      return flags & 0x01;
    }
  };

  class NSEC3RR : public RFC1035::ResourceRecord
  {
  public:
    NSEC3RR(
      const RFC1035::Name& owner,
      RFC1035::Class class_,
      uint32_t ttl,
      HashAlgorithm hash_algorithm,
      uint8_t flags,
      uint16_t iterations,
      const small_vector<uint8_t>& salt,
      const small_vector<uint8_t>& next_hashed_owner_name);

    virtual ~NSEC3RR() = default;
  };

  class NSEC3PARAM : public RFC1035::RDataFormat
  {
  public:
    HashAlgorithm hash_algorithm;
    uint8_t flags;
    uint16_t iterations;
    small_vector<uint8_t> salt;

    NSEC3PARAM() = default;

    NSEC3PARAM(
      HashAlgorithm hash_algorithm,
      uint8_t flags,
      uint16_t iterations,
      const small_vector<uint8_t>& salt) :
      hash_algorithm(hash_algorithm),
      flags(flags),
      iterations(iterations),
      salt(salt)
    {}

    NSEC3PARAM(const std::string& s)
    {
      std::istringstream f(s);
      uint8_t tmp;
      f >> tmp;
      hash_algorithm = static_cast<HashAlgorithm>(tmp);
      f >> flags;
      f >> iterations;
      std::string stmp;
      f >> stmp;
      salt = small_vector<uint8_t>::from_hex(stmp);
    }

    NSEC3PARAM(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      hash_algorithm = static_cast<HashAlgorithm>(get<uint8_t>(data, pos));
      flags = get<uint8_t>(data, pos);
      iterations = get<uint16_t>(data, pos);
      salt = small_vector<uint8_t>(data, pos);
    }

    virtual ~NSEC3PARAM() = default;

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put((uint8_t)hash_algorithm, r);
      put(flags, r);
      put(iterations, r);
      salt.put(r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      r = std::to_string(static_cast<uint8_t>(hash_algorithm));
      r += " " + std::to_string(flags);
      r += " " + std::to_string(iterations);
      r += " " + (salt.size() > 0 ? ds::to_hex(salt) : "-");
      return r;
    }
  };

  class NSEC3PARAMRR : public RFC1035::ResourceRecord
  {
  public:
    NSEC3PARAMRR(
      const RFC1035::Name& owner,
      RFC1035::Class class_,
      uint32_t ttl,
      HashAlgorithm hash_algorithm,
      uint8_t flags,
      uint16_t iterations,
      const small_vector<uint8_t>& salt);

    virtual ~NSEC3PARAMRR() = default;
  };
}
