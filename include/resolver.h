// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"
#include "rfc5155.h"
#include "rfc6891.h"
#include "rfc7671.h"

#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/pem.h>
#include <ccf/ds/quote_info.h>
#include <functional>
#include <memory>
#include <stdexcept>

namespace aDNS
{
  using Name = RFC1035::Name;
  using Message = RFC1035::Message;
  using ResourceRecord = RFC1035::ResourceRecord;
  using CRRS = RFC4034::CRRS;

  enum class Type : uint16_t
  {
    A = static_cast<uint16_t>(RFC1035::Type::A),
    NS = static_cast<uint16_t>(RFC1035::Type::NS),
    CNAME = static_cast<uint16_t>(RFC1035::Type::CNAME),
    SOA = static_cast<uint16_t>(RFC1035::Type::SOA),
    MX = static_cast<uint16_t>(RFC1035::Type::MX),
    TXT = static_cast<uint16_t>(RFC1035::Type::TXT),
    AAAA = static_cast<uint16_t>(RFC3596::Type::AAAA),
    DNSKEY = static_cast<uint16_t>(RFC4034::Type::DNSKEY),
    RRSIG = static_cast<uint16_t>(RFC4034::Type::RRSIG),
    NSEC = static_cast<uint16_t>(RFC4034::Type::NSEC),
    DS = static_cast<uint16_t>(RFC4034::Type::DS),
    NSEC3 = static_cast<uint16_t>(RFC5155::Type::NSEC3),
    NSEC3PARAM = static_cast<uint16_t>(RFC5155::Type::NSEC3PARAM),
    TLSA = static_cast<uint16_t>(RFC7671::Type::TLSA),
    OPT = static_cast<uint16_t>(RFC6891::Type::OPT),
  };

  enum class QType : uint16_t
  {
    A = static_cast<uint16_t>(RFC1035::Type::A),
    NS = static_cast<uint16_t>(RFC1035::Type::NS),
    CNAME = static_cast<uint16_t>(RFC1035::Type::CNAME),
    SOA = static_cast<uint16_t>(RFC1035::Type::SOA),
    MX = static_cast<uint16_t>(RFC1035::Type::MX),
    TXT = static_cast<uint16_t>(RFC1035::Type::TXT),
    AAAA = static_cast<uint16_t>(RFC3596::Type::AAAA),
    DNSKEY = static_cast<uint16_t>(RFC4034::Type::DNSKEY),
    RRSIG = static_cast<uint16_t>(RFC4034::Type::RRSIG),
    NSEC = static_cast<uint16_t>(RFC4034::Type::NSEC),
    DS = static_cast<uint16_t>(RFC4034::Type::DS),
    NSEC3 = static_cast<uint16_t>(RFC5155::Type::NSEC3),
    NSEC3PARAM = static_cast<uint16_t>(RFC5155::Type::NSEC3PARAM),
    TLSA = static_cast<uint16_t>(RFC7671::Type::TLSA),
    OPT = static_cast<uint16_t>(RFC6891::Type::OPT),
    ASTERISK = static_cast<uint16_t>(RFC1035::QType::ASTERISK),
  };

  std::string string_from_type(const aDNS::Type& type);
  std::string string_from_qtype(const aDNS::QType& type);
  std::string string_from_resource_record(const ResourceRecord& rr);

  Type type_from_string(const std::string& s);
  QType qtype_from_string(const std::string& s);

  enum class Class : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
  };

  enum class QClass : uint16_t
  {
    IN = static_cast<uint16_t>(RFC1035::Class::IN),
    ASTERISK = static_cast<uint16_t>(RFC1035::QClass::ASTERISK),
  };

  std::string string_from_class(const Class& class_);
  std::string string_from_qclass(const QClass& c);

  Class class_from_string(const std::string& s);
  QClass qclass_from_string(const std::string& s);

  inline bool is_type_in_qtype(uint16_t t, QType qt)
  {
    return qt == QType::ASTERISK || t == static_cast<uint16_t>(qt);
  }

  inline bool is_class_in_qclass(uint16_t c, QClass qc)
  {
    return qc == QClass::ASTERISK || c == static_cast<uint16_t>(qc);
  }

  class Resolver
  {
  public:
    struct NodeAddress
    {
      Name name;
      std::string ip;
      std::string protocol;
      uint16_t port;
    };

    struct NodeInfo
    {
      NodeAddress address;
      std::string attestation;
      ccf::QuoteFormat attestation_type;
    };

    struct Configuration
    {
      Name origin; // domain name suffix of the zone served by this resolver
      std::string soa; // serialized SOA record data for the zone
      std::optional<std::vector<Name>> alternative_names;
      uint32_t default_ttl = 86400;
      RFC4034::Algorithm signing_algorithm =
        RFC4034::Algorithm::ECDSAP384SHA384;
      RFC4034::DigestType digest_type = RFC4034::DigestType::SHA384;
      bool use_key_signing_key = true;
      bool use_nsec3 = true;
      RFC5155::HashAlgorithm nsec3_hash_algorithm =
        RFC5155::HashAlgorithm::SHA1;
      uint16_t nsec3_hash_iterations = 3;
      uint8_t nsec3_salt_length = 8;
      // DNS hosts, indexed by CCF node IDs
      std::map<std::string, NodeAddress> node_addresses;
    };

    struct Resolution
    {
      RFC1035::ResponseCode response_code = RFC1035::ResponseCode::NO_ERROR;
      RFC4034::CanonicalRRSet answers;
      RFC4034::CanonicalRRSet authorities;
      RFC4034::CanonicalRRSet additionals;
      bool is_authoritative = false;
    };

    typedef std::set<Name, RFC4034::CanonicalNameOrdering> Names;

    Resolver();

    virtual ~Resolver();

    virtual void configure();

    struct Reply
    {
      Message message;
      size_t peer_udp_payload_size;
    };

    virtual Reply reply(const Message& msg);

    virtual Resolution resolve(const Name& qname, QType qtype, QClass qclass);

    virtual RFC4034::CanonicalRRSet find_records(
      const Name& origin,
      const Name& qname,
      QType qtype,
      QClass qclass,
      std::optional<std::function<bool(const ResourceRecord&)>> condition =
        std::nullopt);

    RFC4034::CanonicalRRSet find_rrsigs(
      const Name& origin, const Name& name, QClass qclass, Type type_covered);

    RFC1035::ResponseCode find_nsec3_records(
      const Name& origin,
      QClass qclass,
      const Name& qname,
      RFC4034::CanonicalRRSet& r);

    RFC1035::ResponseCode find_nsec_records(
      const Name& origin,
      QClass sclass,
      const Name& sname,
      RFC4034::CanonicalRRSet& r);

    virtual void for_each(
      const Name& origin,
      QClass qclass,
      QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const = 0;

    virtual void for_each(
      const Name& origin,
      const Name& qname,
      QClass qclass,
      QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const = 0;

    virtual bool origin_exists(const Name& name) const = 0;

    virtual void sign(const Name& origin);

    virtual void add(const Name& origin, const ResourceRecord& rr) = 0;

    virtual void remove(
      const Name& origin, const Name& name, Class c, Type t) = 0;

    virtual void remove(const Name& origin, Class c, Type t) = 0;

    virtual ccf::crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) = 0;

    virtual std::shared_ptr<ccf::crypto::KeyPair> get_tls_key();

    virtual void on_new_signing_key(
      const Name& origin,
      uint16_t tag,
      const ccf::crypto::KeyPairPtr& pem,
      bool key_signing) = 0;

    virtual void register_service(const std::vector<uint8_t>& req);

    virtual std::string service_definition_auth() const = 0;

    virtual void set_service_definition_auth(const std::string& new_policy) = 0;

    virtual std::string platform_definition_auth() const = 0;

    virtual void set_platform_definition_auth(
      const std::string& new_policy) = 0;

    virtual std::string service_definition(
      const std::string& service_name) const = 0;

    virtual void set_service_definition(
      const std::string& service_name, const std::string& new_policy) = 0;

    virtual std::string platform_definition(
      const std::string& platform) const = 0;

    virtual void set_platform_definition(
      const std::string& platform, const std::string& new_policy) = 0;

    virtual Configuration get_configuration() const = 0;
    virtual void set_configuration(const Configuration& cfg) = 0;

    virtual uint32_t get_fresh_time() = 0;

    virtual void save_service_registration_request(
      const Name& name, const std::vector<uint8_t>& rr) = 0;

    virtual std::map<std::string, NodeInfo> get_node_information() = 0;

    const std::map<uint16_t, Type>& get_supported_types() const;

    const std::map<uint16_t, Class>& get_supported_classes() const;

    static Name find_preceding(
      const Names& ns, const Name& origin, const Name& sname);

  protected:
    Names name_cache;
    bool name_cache_dirty = true;
    std::mutex sign_mtx;

    small_vector<uint8_t> generate_nsec3_salt(uint8_t length);

    small_vector<uint8_t> get_nsec3_salt(
      const Name& origin, aDNS::QClass class_);

    void update_nsec3_param(
      const Name& origin,
      aDNS::Class class_,
      uint16_t ttl,
      RFC5155::HashAlgorithm hash_algorithm,
      uint16_t hash_iterations,
      uint8_t salt_length);

    RFC4034::CanonicalRRSet get_ordered_records(
      const Name& origin, QClass c, QType t, const Name& name) const;

    const Resolver::Names& get_ordered_names(const Name& origin, Class c);

    Names get_ordered_names(const Name& origin, Class c, Type t);

    RFC4034::CanonicalRRSet get_record_set(
      const Name& origin, const Name& name, QClass c, QType t) const;

    typedef std::pair<std::shared_ptr<ccf::crypto::KeyPair>, uint16_t>
      KeyAndTag;

    KeyAndTag get_signing_key(
      const Name& origin, Class class_, bool key_signing);

    KeyAndTag add_new_signing_key(
      const Name& origin, Class class_, bool key_signing);

    RFC4034::DNSKEYRR add_dnskey(
      const Name& origin,
      Class class_,
      const small_vector<uint16_t>& public_key,
      bool key_signing);

    void add_ds(
      const Name& origin,
      Class class_,
      std::shared_ptr<ccf::crypto::KeyPair> key,
      uint16_t tag,
      const small_vector<uint16_t>& dnskey_rdata);

    struct NameTypes
    {
      Name name;
      std::set<Type> types;
    };

    typedef std::map<small_vector<uint8_t>, NameTypes> HashedNameTypesMap;
    typedef std::map<Name, std::set<Type>, RFC4034::CanonicalNameOrdering>
      NameTypesMap;

    ResourceRecord add_nsec3(
      Class c,
      const Name& origin,
      uint32_t ttl,
      const small_vector<uint8_t>& hashed_name,
      const small_vector<uint8_t>& next_hashed_owner_name,
      const RFC1035::Name& suffix,
      std::set<Type> types,
      uint32_t nsec_ttl,
      uint32_t sig_inception,
      const KeyAndTag& key_and_tag);

    void add_fragmented(
      const Name& origin,
      const Name& name,
      uint32_t ttl,
      aDNS::Class class_,
      const small_vector<uint16_t>& rrdata,
      bool compress = false,
      uint8_t records_per_name = 64);

    void add_fragmented(
      const Name& origin,
      const Name& name,
      const ResourceRecord& rr,
      bool compress = false,
      uint8_t records_per_name = 64);

    ResourceRecord mk_rr(
      const Name& name,
      aDNS::Type type,
      aDNS::Class class_,
      uint32_t ttl,
      const small_vector<uint16_t>& rdata);

    Name find_zone(const Name& name);

    size_t sign_rrset(
      const Name& origin,
      QClass c,
      QType t,
      const Name& name,
      uint32_t sig_time,
      std::shared_ptr<ccf::crypto::KeyPair> key,
      uint16_t key_tag,
      RFC4034::Algorithm signing_algorithm);
  };

  uint16_t get_key_tag(const RFC4034::DNSKEY& dnskey_rdata);
}
