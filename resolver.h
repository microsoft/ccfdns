// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "adns_types.h"
#include "rfc1035.h"
#include "rfc3596.h"
#include "rfc4034.h"
#include "rfc5155.h"
#include "rfc6891.h"
#include "rfc7671.h"
#include "rfc8659.h"

#include <ccf/crypto/pem.h>
#include <functional>
#include <memory>
#include <stdexcept>

namespace crypto
{
  class KeyPair;
}

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
    CAA = static_cast<uint16_t>(RFC8659::Type::CAA),
    // TLSKEY = static_cast<uint16_t>(aDNS::Types::Type::TLSKEY),
    ATTEST = static_cast<uint16_t>(aDNS::Types::Type::ATTEST),
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
    CAA = static_cast<uint16_t>(RFC8659::Type::CAA),
    // TLSKEY = static_cast<uint16_t>(aDNS::Types::Type::TLSKEY),
    ATTEST = static_cast<uint16_t>(aDNS::Types::Type::ATTEST),

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
    };

    struct Configuration
    {
      Name origin;
      std::string soa;

      std::optional<std::vector<Name>> alternative_names;
      std::optional<std::string> parent_base_url;
      std::vector<std::string> contact;

      uint32_t default_ttl = 86400;
      RFC4034::Algorithm signing_algorithm =
        RFC4034::Algorithm::ECDSAP384SHA384;
      RFC4034::DigestType digest_type = RFC4034::DigestType::SHA384;
      bool use_key_signing_key = true;

      bool use_nsec3 = true;
      RFC5155::HashAlgorithm nsec3_hash_algorithm =
        RFC5155::HashAlgorithm::SHA1;
      uint16_t nsec3_hash_iterations = 3;

      std::optional<std::string> fixed_zsk; // TODO: Debug-only?

      struct ServiceCA
      {
        std::string name;
        std::string directory;
        std::vector<std::string> ca_certificates;
      };

      ServiceCA service_ca;

      std::map<std::string, NodeAddress> node_addresses;
    };

    struct RegistrationInformation
    {
      std::string public_key;
      std::vector<uint8_t> csr;
      std::map<std::string, NodeInfo> node_information;
      std::optional<std::vector<aDNS::ResourceRecord>> dnskey_records;
    };

    struct RegistrationRequest
    {
      std::vector<uint8_t> csr;
      std::vector<std::string> contact;
      std::map<std::string, NodeInfo> node_information;
      std::optional<std::string> configuration_receipt;
    };

    struct DelegationRequest
    {
      Name subdomain;
      std::vector<uint8_t> csr;
      std::vector<std::string> contact;
      std::map<std::string, NodeInfo> node_information;
      std::vector<aDNS::ResourceRecord> dnskey_records;
      std::optional<std::string> configuration_receipt;
    };

    struct Resolution
    {
      RFC1035::ResponseCode response_code = RFC1035::ResponseCode::NO_ERROR;
      RFC4034::CanonicalRRSet answers;
      RFC4034::CanonicalRRSet authorities;
      RFC4034::CanonicalRRSet additionals;
    };

    Resolver();

    virtual ~Resolver();

    virtual RegistrationInformation configure(const Configuration& cfg);

    virtual Message reply(const Message& msg);

    virtual Resolution resolve(const Name& qname, QType qtype, QClass qclass);

    virtual RFC4034::CanonicalRRSet find_records(
      const Name& origin,
      const Name& name,
      QType qtype,
      QClass qclass,
      std::optional<std::function<bool(const ResourceRecord&)>> condition =
        std::nullopt);

    RFC4034::CanonicalRRSet find_rrsigs(
      const Name& origin, const Name& name, QClass qclass, Type type_covered);

    virtual void for_each(
      const Name& origin,
      QClass qclass,
      QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const = 0;

    virtual bool origin_exists(const Name& name) const = 0;

    virtual void sign(const Name& origin);

    virtual void add(const Name& origin, const ResourceRecord& rr) = 0;

    virtual void remove(
      const Name& origin, const Name& name, Class c, Type t) = 0;

    virtual void remove(const Name& origin, Class c, Type t) = 0;

    virtual crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) = 0;

    virtual std::shared_ptr<crypto::KeyPair> get_tls_key();

    virtual void on_new_signing_key(
      const Name& origin,
      uint16_t tag,
      const crypto::Pem& pem,
      bool key_signing) = 0;

    virtual void start_service_acme(
      const Name& origin,
      const Name& name,
      const std::vector<uint8_t>& csr,
      const std::vector<std::string>& contact,
      const std::optional<std::string>& service_url = std::nullopt,
      const std::optional<std::vector<std::string>>& service_ca_certs = {}) = 0;

    virtual void install_acme_response(
      const Name& origin,
      const Name& name,
      const std::vector<Name>& alternative_names,
      const std::string& key_authorization);

    virtual void remove_acme_response(const Name& origin, const Name& name);

    virtual void register_service(const RegistrationRequest& req);

    virtual std::string service_registration_policy() const = 0;

    virtual void set_service_registration_policy(
      const std::string& new_policy) = 0;

    virtual bool evaluate_service_registration_policy(
      const std::string& data) const = 0;

    virtual void register_delegation(const DelegationRequest& req);

    virtual std::string delegation_registration_policy() const = 0;

    virtual void set_delegation_registration_policy(
      const std::string& new_policy) = 0;

    virtual bool evaluate_delegation_registration_policy(
      const std::string& data) const = 0;

    virtual Configuration get_configuration() const = 0;
    virtual void set_configuration(const Configuration& cfg) = 0;

    virtual void set_service_certificate(
      const std::string& service_dns_name,
      const std::string& certificate_pem) = 0;

    virtual std::string get_service_certificate(
      const std::string& service_dns_name) = 0;

    virtual void save_service_registration_request(
      const RegistrationRequest& rr) = 0;

    virtual void save_delegation_registration_request(
      const DelegationRequest& rr) = 0;

    virtual std::map<std::string, NodeInfo> get_node_information() = 0;

  protected:
    small_vector<uint8_t> nsec3_salt;

    typedef std::set<Name, RFC4034::CanonicalNameOrdering> Names;

    std::pair<RFC4034::CanonicalRRSet, Names> order_records(
      const Name& origin,
      QClass c,
      std::optional<Name> match_name = std::nullopt) const;

    Names names(const Name& origin, QClass c) const;

    RFC4034::CanonicalRRSet get_record_set(
      const Name& origin, const Name& name, QClass c, QType t) const;

    typedef std::pair<std::shared_ptr<crypto::KeyPair>, uint16_t>
      KeyAndTag; // TODO: Should use OpenSSL type instead of KeyPair

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
      std::shared_ptr<crypto::KeyPair> key,
      uint16_t tag,
      const small_vector<uint16_t>& dnskey_rdata);

    typedef std::
      map<small_vector<uint8_t>, std::vector<RFC4034::CanonicalRRSet::iterator>>
        HashedNamesMap;

    ResourceRecord add_nsec3(
      Class c,
      const Name& origin,
      uint32_t ttl,
      const small_vector<uint8_t>& hashed_name,
      const small_vector<uint8_t>& next_hashed_owner_name,
      std::vector<RFC4034::CanonicalRRSet::iterator>& rrs);

    void add_fragmented(
      const Name& origin,
      const Name& name,
      const ResourceRecord& rr,
      uint8_t records_per_name = 64);

    ResourceRecord mk_rr(
      const Name& name,
      aDNS::Type type,
      aDNS::Class class_,
      uint32_t ttl,
      const small_vector<uint16_t>& rdata);

    Name find_zone(const Name& name);

    void add_caa_records(
      const Name& origin,
      const Name& name,
      const std::string& ca_name,
      const std::vector<std::string>& contact);
  };

  uint16_t get_key_tag(const RFC4034::DNSKEY& dnskey_rdata);
}
