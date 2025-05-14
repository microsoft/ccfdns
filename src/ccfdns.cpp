// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccfdns_json.h"
#include "ccfdns_rpc_types.h"
#include "formatting.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <arpa/inet.h>
#include <ccf/_private/ds/thread_messaging.h>
#include <ccf/_private/enclave/enclave_time.h>
#include <ccf/_private/node/acme_client.h>
#include <ccf/_private/node/identity.h>
#include <ccf/_private/udp/msg_types.h>
#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/curve.h>
#include <ccf/crypto/eddsa_key_pair.h>
#include <ccf/crypto/jwk.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <ccf/endpoint_context.h>
#include <ccf/endpoints/authentication/cert_auth.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/http_header_map.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/indexing/strategies/visit_each_entry_in_map.h>
#include <ccf/json_handler.h>
#include <ccf/kv/version.h>
#include <ccf/network_identity_interface.h>
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/node/node_configuration_interface.h>
#include <ccf/pal/attestation.h>
#include <ccf/research/custom_protocol_subsystem_interface.h>
#include <ccf/service/acme_client_config.h>
#include <ccf/service/node_info.h>
#include <ccf/service/tables/acme_certificates.h>
#include <ccf/service/tables/nodes.h>
#include <ccf/tx.h>
#include <ccf/tx_id.h>
#include <ccf/version.h>
#include <llhttp/llhttp.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <optional>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <regex>
#include <stdexcept>

// Could be merged with CCF's ccf::http::JwtVerifier

using namespace aDNS;
using namespace RFC1035;

namespace ccf::kv::serialisers
{
  template <>
  struct BlitSerialiser<Name>
  {
    static SerialisedEntry to_serialised(const Name& name)
    {
      const auto data = (std::vector<uint8_t>)name;
      return SerialisedEntry(data.begin(), data.end());
    }

    static Name from_serialised(const SerialisedEntry& data)
    {
      return Name(std::vector<uint8_t>{data.data(), data.data() + data.size()});
    }
  };

  template <>
  struct BlitSerialiser<ResourceRecord>
  {
    static SerialisedEntry to_serialised(const ResourceRecord& record)
    {
      const auto data = (std::vector<uint8_t>)record;
      return SerialisedEntry(data.begin(), data.end());
    }

    static ResourceRecord from_serialised(const SerialisedEntry& data)
    {
      size_t pos = 0;
      return ResourceRecord(std::span<const uint8_t>(data), pos);
    }
  };
}

namespace ccfdns
{
  template <typename T>
  std::vector<uint8_t> to_json_bytes(const T& x)
  {
    nlohmann::json jin;
    to_json(jin, x);
    std::string s = jin.dump();
    return std::vector<uint8_t>(s.data(), s.data() + s.size());
  }

  struct RegisterServiceWithPreviousVersion
  {
    RegisterService::In request;
    std::optional<ccf::kv::Version> previous_version;
  };

  DECLARE_JSON_TYPE(RegisterServiceWithPreviousVersion);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegisterServiceWithPreviousVersion, request, previous_version);

  struct RegisterDelegationWithPreviousVersion
  {
    RegisterDelegation::In request;
    std::optional<ccf::kv::Version> previous_version;
  };

  DECLARE_JSON_TYPE(RegisterDelegationWithPreviousVersion);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegisterDelegationWithPreviousVersion, request, previous_version);

  class HTTPClient
  {
  public:
    HTTPClient(std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss) :
      acme_ss(acme_ss)
    {}

    struct HTTPRetryMsg
    {
      HTTPRetryMsg(
        HTTPClient* client,
        std::string&& method,
        std::string&& url,
        ccf::http::HeaderMap&& headers,
        std::string&& body,
        const std::vector<std::string>& ca_certs,
        const std::function<bool(
          ccf::http_status, ccf::http::HeaderMap&&, std::vector<uint8_t>&&)>&
          callback,
        bool use_node_client_cert) :
        client(client),
        method(std::move(method)),
        url(std::move(url)),
        headers(std::move(headers)),
        body(body),
        ca_certs(ca_certs),
        callback(callback),
        use_node_client_cert(use_node_client_cert)
      {}

      HTTPClient* client;
      std::string method;
      std::string url;
      ccf::http::HeaderMap headers;
      std::string body;
      std::vector<std::string> ca_certs;
      std::function<bool(
        ccf::http_status, ccf::http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback;
      bool use_node_client_cert;
    };

    static void msg_cb(std::unique_ptr<threading::Tmsg<HTTPRetryMsg>> msg)
    {
      auto vbody =
        std::vector<uint8_t>(msg->data.body.begin(), msg->data.body.end());
      CCF_APP_TRACE("CCFDNS: HTTP: {} {}", msg->data.method, msg->data.url);
      CCF_APP_TRACE(
        "CCFDNS: {} CA certificates configures", msg->data.ca_certs.size());
      msg->data.client->acme_ss->make_http_request(
        msg->data.method,
        msg->data.url,
        msg->data.headers,
        vbody,
        [msgdata = msg->data](
          const ccf::http_status& status,
          const ccf::http::HeaderMap& headers,
          const std::vector<uint8_t>& data) {
          ccf::http::HeaderMap hdrs = headers;
          if (
            status == HTTP_STATUS_SERVICE_UNAVAILABLE ||
            status == HTTP_STATUS_REQUEST_TIMEOUT)
          {
            size_t wait_seconds = 5;
            auto rait = hdrs.find("retry-after");
            if (rait != hdrs.end())
              wait_seconds = std::atoi(rait->second.c_str());

            CCF_APP_DEBUG(
              "CCFDNS: ACME: Retrying failed HTTP request in {} sec",
              wait_seconds);

            auto nmsg =
              std::make_unique<threading::Tmsg<HTTPRetryMsg>>(msg_cb, msgdata);

            threading::ThreadMessaging::instance().add_task_after(
              std::move(nmsg), std::chrono::seconds(wait_seconds));

            return false;
          }
          else
          {
            std::vector<uint8_t> cdata = data;
            return msgdata.callback(status, std::move(hdrs), std::move(cdata));
          }
        },
        msg->data.ca_certs,
        "HTTP1",
        true);
    };

    void request(
      std::string&& method,
      std::string&& url,
      ccf::http::HeaderMap&& headers,
      std::string&& body,
      const std::vector<std::string>& ca_certs,
      const std::function<
        bool(ccf::http_status, ccf::http::HeaderMap&&, std::vector<uint8_t>&&)>&
        callback,
      bool use_node_client_cert = false)
    {
      auto msg = std::make_unique<threading::Tmsg<HTTPRetryMsg>>(
        msg_cb,
        this,
        std::move(method),
        std::move(url),
        std::move(headers),
        std::move(body),
        ca_certs,
        callback,
        use_node_client_cert);

      threading::ThreadMessaging::instance().add_task_after(
        std::move(msg), std::chrono::seconds(0));
    }

  protected:
    std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss;
  };

  using namespace ccf::indexing::strategies;

  class LastWriteTxIDByKey : public VisitEachEntryInMap
  {
  public:
    LastWriteTxIDByKey(const std::string& map_name) :
      VisitEachEntryInMap(map_name, "TxIDByKey")
    {}

    virtual void visit_entry(
      const ccf::TxID& txid,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      txids_by_key[k] = txid;
    }

    std::optional<ccf::TxID> last_write(const ccf::ByteVector& k)
    {
      auto it = txids_by_key.find(k);
      if (it == txids_by_key.end())
        return std::nullopt;
      else
        return it->second;
    }

  protected:
    ccf::pal::Mutex lock;
    std::unordered_map<ccf::ByteVector, ccf::TxID> txids_by_key;
  };

  class CCFDNS : public Resolver
  {
  public:
    CCFDNS(
      const std::string& node_id,
      std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss,
      std::shared_ptr<ccf::NetworkIdentitySubsystemInterface> nwid_ss,
      std::shared_ptr<ccf::NodeConfigurationInterface> nci_ss,
      std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss,
      ccf::indexing::IndexingStrategies& istrats) :
      Resolver(),
      node_id(node_id),
      acme_ss(acme_ss),
      nwid_ss(nwid_ss),
      nci_ss(nci_ss),
      cp_ss(cp_ss),
      http_client(acme_ss)
    {
      registration_index_strategy = std::make_shared<RegistrationRequestsIndex>(
        registration_requests_table_name);
      istrats.install_strategy(registration_index_strategy);
      delegation_index_strategy = std::make_shared<DelegationRequestsIndex>(
        delegation_requests_table_name);
      istrats.install_strategy(delegation_index_strategy);
    }

    virtual ~CCFDNS() {}

    void find_internal_interface()
    {
      // Find an interface for internal RPC calls and the ACME config name
      auto ncs = nci_ss->get();

      for (const auto& iface : ncs.node_config.network.rpc_interfaces)
      {
        const auto& e = iface.second.endorsement;
        if (
          iface.second.app_protocol != "DNSTCP" &&
          iface.second.app_protocol != "DNSUDP")
          internal_node_address = "https://" + iface.second.published_address;
      }
    }

    std::string node_id;
    std::string my_name; // Certifiable FQDN for this node of the DNS service

    // Declaring CCF Table types and names

    // "keys.h" also defines a private table for DNSKEYs.

    using TConfigurationTable =
      ccf::ServiceValue<aDNS::Resolver::Configuration>;
    const std::string configuration_table_name = "public:adns_configuration";

    using TTimeTable = ccf::ServiceValue<uint32_t>;
    const std::string time_table_name = "public:ccfdns.time";

    using Names = ccf::ServiceSet<Name>;

    using Records = ccf::ServiceSet<ResourceRecord>;
    using Origins = ccf::ServiceSet<Name>;
    const std::string origins_table_name = "public:ccfdns.origins";

    using ServiceCertificates = ccf::ServiceMap<std::string, std::string>;
    const std::string service_certificates_table_name =
      "public:service_certificates";

    using ServiceRegistrationPolicy = ccf::ServiceValue<std::string>;
    const std::string service_registration_policy_table_name =
      "public:ccf.gov.ccfdns.service_registration_policy";

    using RegistrationRequests =
      ccf::ServiceMap<Name, RegisterServiceWithPreviousVersion>;
    const std::string registration_requests_table_name =
      "public:service_registration_requests";
    using RegistrationRequestsIndex = LastWriteTxIDByKey;
    std::shared_ptr<RegistrationRequestsIndex> registration_index_strategy =
      nullptr;

    /*
      Records a vector of policies for delegating subzones out of this service's
      zone. The policies consist of a fixed policy copied from each attested
      parent along the delegation chain, followed by the local delegation
      policy, which is updatable via service governance.

      All policies must agree to authorize /register-delegation of subzones.

      The vector is initialized with a local policy (via governance) at the
      start of the service. If its parent zone is attested, it is then prepended
      with the attested parent policies at the end of /configure. The policies
      are made available (via /delegation-receipt) for the parent to review
      before authorizing /register-delegation.

      TBC!
    */
    using DelegationPolicies = ccf::ServiceValue<std::vector<std::string>>;
    const std::string delegation_policy_table_name =
      "public:ccf.gov.ccfdns.delegation_policy";

    // Records a map of subzones currently delegated by this service.
    // TODO commit consistency
    using DelegationRequests =
      ccf::ServiceMap<Name, RegisterDelegationWithPreviousVersion>;
    const std::string delegation_requests_table_name =
      "public:delegation_requests";
    using DelegationRequestsIndex = LastWriteTxIDByKey;
    std::shared_ptr<DelegationRequestsIndex> delegation_index_strategy =
      nullptr;

    using Endorsements = ccf::ServiceMap<Name, std::vector<uint8_t>>;
    const std::string endorsements_table_name = "public:service_endorsements";

    void set_endpoint_context(
      ccf::endpoints::CommandEndpointContext* c, bool writable = true)
    {
      ctx = c;
      ctx_writable = c == nullptr ? false : writable;
    }

    ccf::kv::Tx& rwtx() const
    {
      if (!ctx_writable)
        throw std::runtime_error("read-write context required");
      return static_cast<ccf::endpoints::EndpointContext*>(ctx)->tx;
    }

    ccf::kv::ReadOnlyTx& rotx() const
    {
      if (!ctx_writable)
        return static_cast<ccf::endpoints::ReadOnlyEndpointContext*>(ctx)->tx;
      else
        return static_cast<ccf::endpoints::EndpointContext*>(ctx)->tx;
    }

    virtual Configuration get_configuration() const override
    {
      CCF_APP_TRACE("CCFDNS: Get configuration");
      check_context();
      auto t = rotx().template ro<CCFDNS::TConfigurationTable>(
        configuration_table_name);
      if (!t)
        throw std::runtime_error("empty configuration table");
      auto cfg = t->get();
      if (!cfg)
        throw std::runtime_error(
          "get_configuration(): no configuration available");
      return *cfg;
    }

    virtual void set_configuration(const Configuration& cfg) override
    {
      CCF_APP_TRACE("ADNS: Set configuration");
      check_context();
      CCF_APP_TRACE("CCFDNS: setting configuration");
      auto t = rwtx().template rw<CCFDNS::TConfigurationTable>(
        configuration_table_name);
      t->put(cfg);
      CCF_APP_TRACE("CCFDNS: configuration set");
    }

    // returns the persisted, monotonic system time, since 1970,
    // in seconds represented as uint32, as in e.g. RFC4034,
    // advancing it based on the local host time if need be
    virtual uint32_t get_fresh_time() override
    {
      // TODO: consider adding time quantum to the configuration
      uint32_t quantum = 5;

      check_context();
      auto table = rwtx().template rw<CCFDNS::TTimeTable>(time_table_name);
      auto v = table->get();
      uint32_t time = v.has_value() ? v.value() : 0;

      // refreshed by the host, every 10ms by default (see node config)
      // we use an internal call instead of
      // UserEndpointRegistry.get_untrusted_host_time_v1 because it is not in
      // scope
      const uint32_t node_time =
        std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

      // does *not* support 32-bit rollover, tricky with untrusted host time.
      if (time + quantum < node_time)
      {
        CCF_APP_TRACE("CCFDNS: Advance time to {}", node_time);
        time = node_time;
        table->put(time);
      }
      return time;
    };

    virtual std::shared_ptr<ccf::crypto::KeyPair> get_tls_key() override
    {
      check_context();
      auto ni = nwid_ss->get().get();
      return ccf::crypto::make_key_pair(ni->priv_key);
    }

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      check_context();
      if (
        rr.type !=
        static_cast<uint16_t>(RFC3596::Type::AAAA)) // skip
                                                    // AAAA-fragmented
                                                    // payloads
        // CCF_APP_TRACE("CCFDNS: Add: {}", string_from_resource_record(rr));

        if (!origin.is_absolute())
          throw std::runtime_error("origin not absolute");

      auto origins = rwtx().rw<Origins>(origins_table_name);
      if (!origins->contains(origin))
        origins->insert(origin);

      auto c = static_cast<aDNS::Class>(rr.class_);
      auto t = static_cast<aDNS::Type>(rr.type);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = rwtx().rw<Records>(table_name(origin, rr.name, c, t));
      records->insert(rs);

      // could be conditioned on the name not existing
      auto names = rwtx().rw<Names>(names_table_name(origin));
      names->insert(rs.name);
      name_cache_dirty = true;
    }

    bool name_exists(const Name& origin, const Name& name) const
    {
      check_context();

      // TODO: keep a map of name -> class/type?
      for (const auto& [_, c] : get_supported_classes())
        for (const auto& [__, t] : get_supported_types())
        {
          auto rrs = rwtx().rw<Records>(table_name(origin, name, c, t));
          if (rrs && rrs->size() != 0)
            return true;
        }

      return false;
    }

    void remove_name_if_unused(const Name& origin, const Name& name)
    {
      if (!name_exists(origin, name))
      {
        auto names = rwtx().rw<Names>(names_table_name(origin));
        names->remove(name);
      }
    }

    virtual void remove(const Name& origin, const ResourceRecord& rr)
    {
      check_context();
      CCF_APP_TRACE("CCFDNS: Remove: {}", string_from_resource_record(rr));

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      auto c = static_cast<aDNS::Class>(rr.class_);
      auto t = static_cast<aDNS::Type>(rr.type);

      CCF_APP_TRACE(
        "CCFDNS: Remove {} type {} at {}",
        std::string(rr.name),
        string_from_type(t),
        std::string(origin));

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = rwtx().rw<Records>(table_name(origin, rs.name, c, t));
      if (records)
      {
        records->remove(rs);
        remove_name_if_unused(origin, rs.name);
      }

      name_cache_dirty = true;
    }

    virtual void remove(
      const Name& origin,
      const Name& name,
      aDNS::Class c,
      aDNS::Type t) override
    {
      check_context();

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      Name aname = name;
      if (!aname.is_absolute())
        aname += origin;

      auto records = rwtx().rw<Records>(table_name(origin, aname, c, t));
      if (records)
      {
        records->foreach([this, origin, t, &records](const ResourceRecord& rr) {
          CCF_APP_TRACE("CCFDNS: Remove {}", string_from_resource_record(rr));
          records->remove(rr);
          remove_name_if_unused(origin, rr.name);
          return true;
        });
      }

      name_cache_dirty = true;
    }

    virtual void remove(
      const Name& origin, aDNS::Class c, aDNS::Type t) override
    {
      check_context();

      CCF_APP_TRACE(
        "CCFDNS: Remove type {} at {}",
        string_from_type(t),
        std::string(origin));

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      auto names = rwtx().rw<Names>(names_table_name(origin));
      names->foreach([this, c, t, &origin](const Name& name) {
        auto records = rwtx().rw<Records>(table_name(origin, name, c, t));
        if (records)
          records->clear();
        remove_name_if_unused(origin, name);
        return true;
      });

      name_cache_dirty = true;
    }

    using Resolver::reply;

    virtual Reply reply(const Message& msg) override
    {
      std::lock_guard<std::mutex> lock(reply_mtx);
      check_context();
      return Resolver::reply(msg);
    }

    virtual void for_each(
      const Name& origin,
      aDNS::QClass qclass,
      aDNS::QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const override
    {
      check_context();

      if (qtype == aDNS::QType::ASTERISK || qclass == aDNS::QClass::ASTERISK)
        throw std::runtime_error("for_each cannot handle wildcards");

      auto c = static_cast<aDNS::Class>(qclass);
      auto t = static_cast<aDNS::Type>(qtype);

      auto names = rotx().ro<Names>(names_table_name(origin));
      names->foreach([this, &origin, c, t, &f](const Name& name) {
        std::string tn = table_name(origin, name, c, t);
        auto records = rotx().ro<Records>(tn);
        if (records)
          records->foreach([&f](const auto& rr) { return f(rr); });
        return true;
      });
    }

    virtual void for_each(
      const Name& origin,
      const Name& qname,
      aDNS::QClass qclass,
      aDNS::QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const override
    {
      check_context();

      if (qtype == aDNS::QType::ASTERISK || qclass == aDNS::QClass::ASTERISK)
        throw std::runtime_error("for_each cannot handle wildcards");

      auto c = static_cast<aDNS::Class>(qclass);
      auto t = static_cast<aDNS::Type>(qtype);
      std::string tn = table_name(origin, qname, c, t);

      auto records = rotx().ro<Records>(tn);
      records->foreach(
        [&qclass, &qname, &qtype, &f](const auto& rr) { return f(rr); });
    }

    virtual bool origin_exists(const Name& name) const override
    {
      check_context();
      auto origins = rotx().ro<Origins>(origins_table_name);
      auto lowername = name.lowered();
      return origins->contains(lowername);
      // TODO commit consistency
      // && origins->get_globally_committed(lowername) ==
      // origins->get(lowername);
    };

    // review explicit origin?
    virtual bool is_delegated(
      const Name& origin, const Name& name) const override
    {
      if (!name.ends_with(origin))
        return false;

      auto delegations =
        rotx().ro<DelegationRequests>(delegation_requests_table_name);

      if (!delegations)
        return false;

      for (Name tmp = name; tmp != origin; tmp = tmp.parent())
      {
        if (delegations->has(tmp))
          return true;
      }

      return false;
    }

    virtual ccf::crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) override
    {
      check_context();

      auto origin_lowered = origin.lowered();
      auto table = rotx().ro<PrivateDNSKeys>(private_dnskey_table_name);
      if (!table)
        return {};
      auto key_maps = table->get(origin_lowered);
      if (key_maps)
      {
        auto& key_map = key_signing ? key_maps->key_signing_keys :
                                      key_maps->zone_signing_keys;
        auto kit = key_map.find(tag);
        if (kit != key_map.end())
        {
          for (const auto& pem : kit->second)
          {
            auto kp = ccf::crypto::make_key_pair(pem);
            auto coord = kp->coordinates();
            if (coord.x.size() + coord.y.size() == public_key.size())
            {
              bool matches = true;
              for (size_t i = 0; i < coord.x.size() && matches; i++)
                if (public_key[i] != coord.x[i])
                  matches = false;
              for (size_t i = 0; i < coord.y.size() && matches; i++)
                if (public_key[coord.x.size() + i] != coord.y[i])
                  matches = false;
              if (matches)
                return pem;
            }
          }
        }
      }

      throw std::runtime_error(fmt::format(
        "private {} signing key not found", key_signing ? "key" : "zone"));
    }

    virtual void on_new_signing_key(
      const Name& origin,
      uint16_t tag,
      const ccf::crypto::Pem& pem,
      bool key_signing) override
    {
      check_context();

      auto origin_lowered = origin.lowered();
      auto table = rwtx().rw<PrivateDNSKeys>(private_dnskey_table_name);
      if (!table)
        throw std::runtime_error("could not get keys table");
      auto value = table->get(origin_lowered);
      if (!value)
        value = ZoneKeyInfo();
      auto& key_map =
        key_signing ? value->key_signing_keys : value->zone_signing_keys;
      auto kit = key_map.find(tag);
      if (kit == key_map.end())
        key_map[tag] = {pem};
      else
        kit->second.push_back(pem);
      table->put(origin_lowered, *value);
    }

    virtual std::string service_registration_policy() const override
    {
      check_context();

      auto policy_table = rotx().ro<ServiceRegistrationPolicy>(
        service_registration_policy_table_name);
      const std::optional<std::string> policy = policy_table->get();
      if (!policy)
        throw std::runtime_error("no service registration policy");
      return *policy;
    }

    virtual void set_service_registration_policy(
      const std::string& new_policy) override
    {
      check_context();

      auto policy = rwtx().rw<ServiceRegistrationPolicy>(
        service_registration_policy_table_name);

      if (!policy)
        throw std::runtime_error(
          "error accessing service registration policy table");

      policy->put(new_policy);
    }

    virtual std::vector<std::string> delegation_policy() const override
    {
      check_context();

      auto tbl = rotx().ro<DelegationPolicies>(delegation_policy_table_name);

      if (!tbl)
        throw std::runtime_error(
          "error accessing parent delegation policy table");

      auto policies = tbl->get();

      if (!policies)
        throw std::runtime_error("no delegation registration policies");

      return *policies;

      /*
          if (parent.empty())
            throw std::runtime_error("no parent delegation policy");
          if (local.empty())
            throw std::runtime_error("no local delegation policy");

          return "function parent() {\n" + parent +
            "\n}\n\n"
            "function local() {\n" +
            local + "\n" + "return r == true;" + "\n" +
            "}\n\n"
            "parent() && local()"; */
    }

    virtual void set_parent_delegation_policy(
      std::vector<std::string>& policies)
    {
      check_context();

      const auto& cfg = get_configuration();

      if (!cfg.parent_base_url)
        throw std::runtime_error(
          "no updatable parent policies in the top attested zone");

      auto tbl = rwtx().rw<DelegationPolicies>(delegation_policy_table_name);

      if (!tbl)
        throw std::runtime_error(
          "cannot set parent policies in uninitialized policy table");

      auto local_policy = tbl->get();

      if (!local_policy || local_policy->size() != 1)
        throw std::runtime_error("cannot overwrite existing parent policies");

      policies.push_back(local_policy->at(0));
      tbl->put(policies);
    }

    // sets or updates the local delegation policy (also accessible via
    // governance)
    virtual void set_delegation_policy(const std::string& new_policy) override
    {
      check_context();

      auto tbl = rwtx().rw<DelegationPolicies>(delegation_policy_table_name);

      if (!tbl)
        throw std::runtime_error("error accessing delegation policy table");

      auto policies = tbl->get();

      if (!policies || policies->size() < 1)
        throw std::runtime_error("error accessing delegation policy");

      policies->back() = new_policy;
      tbl->put(*policies);
    }

    static constexpr const size_t default_stack_size = 1024 * 1024;
    static constexpr const size_t default_heap_size = 100 * 1024 * 1024;

    class RPJSRuntime
    {
    public:
      RPJSRuntime()
      {
        rt = JS_NewRuntime();
        if (!rt)
          throw std::runtime_error("JS runtime creation failed");
        JS_SetMaxStackSize(rt, default_stack_size);
        JS_SetMemoryLimit(rt, default_heap_size);
        ctx = JS_NewContext(rt);
        if (!ctx)
          throw std::runtime_error("JS context creation failed");
      }

      virtual ~RPJSRuntime()
      {
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
      }

      bool eval(const std::string& program)
      {
        static const JSValue jnull = {JSValueUnion{0}, JS_TAG_NULL};

        CCF_APP_TRACE("CCFDNS: Policy evaluation program:\n{}", program);

        JSValue val = JS_Eval(
          ctx,
          program.c_str(),
          program.size(),
          "program.js",
          JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT);

        if (!JS_IsBool(val))
        {
          const char* cstr = "";
          if (JS_IsException(val))
          {
            auto exval = JS_GetException(ctx);
            bool is_error = JS_IsError(ctx, exval);
            if (!is_error && JS_IsObject(exval))
              exval = JS_JSONStringify(ctx, exval, jnull, jnull);
            cstr = JS_ToCString(ctx, exval);
            JS_FreeValue(ctx, exval);
          }
          else
          {
            auto jval = JS_JSONStringify(ctx, val, jnull, jnull);
            cstr = JS_ToCString(ctx, jval);
            JS_FreeValue(ctx, jval);
          }
          if (!cstr)
            throw std::runtime_error(
              "JS policy evaluation produced non-Boolean, non-convertible "
              "result");
          std::string r(cstr);
          JS_FreeCString(ctx, cstr);
          JS_FreeValue(ctx, val);
          throw std::runtime_error(
            "JS policy evaluation produced non-Boolean result: " + r);
        }

        {
          auto jval = JS_JSONStringify(ctx, val, jnull, jnull);
          const char* cstr = JS_ToCString(ctx, jval);
          CCF_APP_DEBUG("CCFDNS: Policy evaluation result: {}", cstr);
          JS_FreeCString(ctx, cstr);
          JS_FreeValue(ctx, jval);
        }

        bool r = JS_VALUE_GET_BOOL(val);
        JS_FreeValue(ctx, val);
        return r;
      }

      JSRuntime* rt = nullptr;
      JSContext* ctx = nullptr;
    };

    virtual bool evaluate_service_registration_policy(
      const std::string& data) const override
    {
      RPJSRuntime rt;
      std::string program = data + "\n\n" + service_registration_policy();
      return rt.eval(program);
    }

    virtual bool evaluate_delegation_policy(
      const std::string& data) const override
    {
      RPJSRuntime rt;

      for (const auto& policy : delegation_policy())
      {
        std::string program = data + "\n\n" + policy;
        if (!rt.eval(program))
          return false;
      }
      return true;
    }

    using Resolver::register_delegation;
    using Resolver::register_service;

    virtual std::map<std::string, NodeInfo> get_node_information() override
    {
      check_context();

      const auto& cfg = get_configuration();

      std::map<std::string, NodeInfo> r;

      auto nodes_table = rotx().template ro<ccf::Nodes>(ccf::Tables::NODES);
      if (!nodes_table)
        throw std::runtime_error("error accessing nodes table");

      for (const auto& [id, addr] : cfg.node_addresses)
      {
        auto entry = nodes_table->get(id);

        // TODO attestation
        auto attestation = "";
        r[id] = {.address = addr, .attestation = attestation};
      }

      return r;
    }

    virtual RegistrationInformation configure(const Configuration& cfg) override
    {
      check_context();
      auto reginfo = Resolver::configure(cfg);

      if (reginfo.dnskey_records)
      {
        CCF_APP_INFO("CCFDNS: : Our DNSKEY records: ");
        for (const auto& dnskey_rr : *reginfo.dnskey_records)
          CCF_APP_INFO(
            "CCFDNS: : - {}", string_from_resource_record(dnskey_rr));

        CCF_APP_INFO("CCFDNS: : Our proposed DS records: ");
        for (const auto& dnskey_rr : *reginfo.dnskey_records)
        {
          auto key_tag = get_key_tag(dnskey_rr.rdata);
          RFC4034::DNSKEY dnskey_rdata(dnskey_rr.rdata);

          RFC4034::DSRR ds(
            dnskey_rr.name,
            static_cast<RFC1035::Class>(dnskey_rr.class_),
            dnskey_rr.ttl,
            key_tag,
            dnskey_rdata.algorithm,
            cfg.digest_type,
            dnskey_rdata);

          CCF_APP_INFO("CCFDNS: : - {}", string_from_resource_record(ds));
        }
      }

      if (my_name.empty())
      {
        auto it = cfg.node_addresses.find(node_id);
        if (it == cfg.node_addresses.end())
          throw std::runtime_error("bug: own node address not found");
        my_name = it->second.name;
        while (my_name.back() == '.')
          my_name.pop_back();
      }

      if (!cfg.parent_base_url)
      {
        create_certificate_signing_key("");
        CCF_APP_INFO("CCFDNS: ACME Client started");
      }
      else
      {
        // When delegating, we now wait until start-delegation-acme-client is
        // called, before starting the ACME client. Alternatively, we could
        // also poll via DNS until we see ourselves.

        // Download the parent's delegation policy
        http_client.request(
          "GET",
          *cfg.parent_base_url + "/app/delegation-policy",
          {},
          {},
          cfg.service_ca.ca_certificates,
          [this](
            ccf::http_status status,
            ccf::http::HeaderMap&&,
            std::vector<uint8_t>&& body) {
            if (status != HTTP_STATUS_OK)
            {
              CCF_APP_FAIL("CCFDNS: Failed to get parent delegation policy");
              return false;
            }

            std::string sbody(body.begin(), body.end());
            http_client.request(
              "POST",
              internal_node_address + "/internal/set-parent-delegation-policy",
              {},
              std::move(sbody),
              {nwid_ss->get()->cert.str()},
              [](
                ccf::http_status status,
                ccf::http::HeaderMap&&,
                std::vector<uint8_t>&& body) {
                if (status != HTTP_STATUS_OK)
                  CCF_APP_FAIL("CCFDNS: Failed to set delegation policy");
                return true;
              },
              true);
            return true;
          });
      }

      return reginfo;
    }

    std::string configuration_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx_,
      ccf::historical::StatePtr historical_state)
    {
      std::string r;
      auto historical_tx = historical_state->store->create_read_only_tx();
      auto tbl = historical_tx.template ro<TConfigurationTable>(
        configuration_table_name);
      if (!tbl)
        throw std::runtime_error("configuration table not found");
      const auto cfg = tbl->get();
      if (!cfg)
        throw std::runtime_error("configuration not found");
      const auto txid = tbl->get_version_of_previous_write();
      if (!txid)
        throw std::runtime_error("configuration TX ID not found");
      auto receipt = ccf::describe_receipt_v1(*historical_state->receipt);

      CCF_APP_INFO(
        "CCFDNS: Configuration receipt size: {}", receipt.dump().size());

      nlohmann::json j;
      j["txid"] = txid.value();
      j["configuration"] = cfg.value();
      j["receipt"] = receipt;
      return j.dump();
    }

    std::string registration_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx_,
      ccf::historical::StatePtr historical_state,
      const std::string& service_name)
    {
      auto historical_tx = historical_state->store->create_read_only_tx();
      auto tbl = historical_tx.template ro<RegistrationRequests>(
        registration_requests_table_name);
      if (!tbl)
        throw std::runtime_error("service registration table not found");
      auto prev = tbl->get_version_of_previous_write(service_name);
      const auto reg = tbl->get(service_name);
      if (!reg)
        throw std::runtime_error("service registration not found");
      auto receipt = ccf::describe_receipt_v1(*historical_state->receipt);

      CCF_APP_INFO(
        "CCFDNS: Registration receipt size: {}", receipt.dump().size());

      nlohmann::json j;
      j["registration"] = reg->request;
      j["receipt"] = receipt;
      if (reg->previous_version)
        j["previous_version"] = *reg->previous_version;
      return j.dump();
    }

    std::string delegation_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx_,
      ccf::historical::StatePtr historical_state,
      const std::string& subdomain)
    {
      CCF_APP_DEBUG("CCFDNS: delegation_receipt: {} ", subdomain);
      auto historical_tx = historical_state->store->create_read_only_tx();
      auto tbl = historical_tx.template ro<DelegationRequests>(
        delegation_requests_table_name);
      if (!tbl)
        throw std::runtime_error("delegation requests table not found");
      const auto dr = tbl->get(subdomain);
      if (!dr)
        throw std::runtime_error("delegation request not found");
      auto receipt = ccf::describe_receipt_v1(*historical_state->receipt);

      CCF_APP_INFO(
        "CCFDNS: Delegation receipt size: {}", receipt.dump().size());

      nlohmann::json j;
      j["delegation"] = dr->request;
      j["receipt"] = receipt;
      if (dr->previous_version)
        j["previous_version"] = *dr->previous_version;
      return j.dump();
    }

    virtual void save_service_registration_request(
      const Name& name, const RegistrationRequest& rr) override
    {
      check_context();

      auto rrtbl = rwtx().template rw<CCFDNS::RegistrationRequests>(
        registration_requests_table_name);
      if (!rrtbl)
        throw std::runtime_error(
          "could not access service registration request table");

      rrtbl->put(name, {rr, rrtbl->get_version_of_previous_write(name)});
    }

    virtual void save_delegation_request(
      const Name& name, const DelegationRequest& dr) override
    {
      check_context();

      auto drtbl = rwtx().template rw<CCFDNS::DelegationRequests>(
        delegation_requests_table_name);
      if (!drtbl)
        throw std::runtime_error(
          "could not access delegation registration request table");
      drtbl->put(name, {dr, drtbl->get_version_of_previous_write(name)});
    }

    std::string dump()
    {
      const auto& cfg = get_configuration();
      std::string r;

      auto origins = rotx().ro<CCFDNS::Origins>(origins_table_name);
      origins->foreach([this, &r, &cfg](const Name& origin) {
        r += "$ORIGIN " + (std::string)origin + "\n";
        r += "$TTL " + std::to_string(cfg.default_ttl) + "\n\n";

        for (const auto& [_, cls] : get_supported_classes())
          for (const auto& [__, type] : get_supported_types())
          {
            auto names = rotx().ro<CCFDNS::Names>(names_table_name(origin));
            names->foreach([this, &r, &origin, c = cls, t = type](
                             const Name& name) {
              auto records = rotx().ro<Records>(table_name(origin, name, c, t));
              records->foreach([&r](const ResourceRecord& rr) {
                if (static_cast<aDNS::Type>(rr.type) == aDNS::Type::ATTEST)
                  r += "; ";
                auto tmp = string_from_resource_record(rr) + "\n";
                if (static_cast<aDNS::Type>(rr.type) == aDNS::Type::NSEC3)
                  r += std::regex_replace(tmp, std::regex("ATTEST"), "");
                else if (static_cast<aDNS::Type>(rr.type) == aDNS::Type::RRSIG)
                {
                  auto type2str = [](const auto& x) {
                    return string_from_type(static_cast<aDNS::Type>(x));
                  };
                  RFC4034::RRSIG sd(rr.rdata, type2str);
                  if (
                    sd.type_covered ==
                    static_cast<uint16_t>(aDNS::Type::ATTEST))
                    r += "; ";
                  r += tmp;
                }
                else
                  r += tmp;
                return true;
              });
              return true;
            });
          }
        r += "\n";
        return true;
      });

      return r;
    }

    virtual void save_endorsements(
      const Name& service_name,
      const std::vector<uint8_t>& endorsements) override
    {
      check_context();

      CCF_APP_INFO(
        "CCFDNS: Saving endorsements for {} ({} bytes)",
        std::string(service_name),
        endorsements.size());

      auto tbl =
        rwtx().template rw<CCFDNS::Endorsements>(endorsements_table_name);
      if (!tbl)
        throw std::runtime_error("could not access endorsements table");
      tbl->put(service_name, endorsements);
    }

    virtual std::vector<uint8_t> get_endorsements(
      const Name& service_name) override
    {
      check_context();

      auto tbl =
        rotx().template ro<CCFDNS::Endorsements>(endorsements_table_name);
      if (!tbl)
        throw std::runtime_error("could not access endorsements table");
      auto r = tbl->get(service_name);
      if (!r)
        throw std::runtime_error("no endorsements found for service");
      return *r;
    }

    static std::string b64url_from_string(std::string s)
    {
      const std::vector<uint8_t> v(s.begin(), s.end());
      return ccf::crypto::b64url_from_raw(v, false); // without padding
    }

    EVP_PKEY* create_private_key()
    {
      EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
      if (!key_ctx)
      {
        return nullptr;
      }

      if (EVP_PKEY_keygen_init(key_ctx) <= 0)
      {
        EVP_PKEY_CTX_free(key_ctx);
        return nullptr;
      }

      if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0)
      {
        EVP_PKEY_CTX_free(key_ctx);
        return nullptr;
      }

      EVP_PKEY* pkey = nullptr;
      if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0)
      {
        EVP_PKEY_CTX_free(key_ctx);
        return nullptr;
      }

      EVP_PKEY_CTX_free(key_ctx);
      return pkey;
    }

    std::string private_key_to_pem(EVP_PKEY* pkey)
    {
      BIO* bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_PrivateKey(
            bio, pkey, nullptr, nullptr, 0, nullptr, nullptr))
      {
        BIO_free(bio);
        return "";
      }

      char* pem_data;
      long pem_length = BIO_get_mem_data(bio, &pem_data);
      std::string pem_str(pem_data, pem_length);
      BIO_free(bio);
      return pem_str;
    }

    X509* create_root_certificate(EVP_PKEY* pkey)
    {
      X509* x509 = X509_new();
      if (!x509)
      {
        return nullptr;
      }

      // Set the serial number
      ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

      // Set the validity period
      X509_gmtime_adj(X509_get_notBefore(x509), 0);
      X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for 1 year

      // Set the public key for the certificate
      X509_set_pubkey(x509, pkey);

      // Set the issuer name (self-signed, so same as subject)
      X509_NAME* name = X509_get_subject_name(x509);
      X509_NAME_add_entry_by_txt(
        name, "C", MBSTRING_ASC, (unsigned char*)"UK", -1, -1, 0);
      X509_NAME_add_entry_by_txt(
        name,
        "O",
        MBSTRING_ASC,
        (unsigned char*)"aDNS Organization",
        -1,
        -1,
        0);
      X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (unsigned char*)"aDNS root CA", -1, -1, 0);
      X509_set_issuer_name(x509, name);

      // Add SANs
      X509_EXTENSION* ext;
      X509V3_CTX san_ctx;
      X509V3_set_ctx_nodb(&san_ctx);
      X509V3_set_ctx(&san_ctx, x509, x509, nullptr, nullptr, 0);

      // Include multiple DNS entries
      ext = X509V3_EXT_conf_nid(
        nullptr,
        &san_ctx,
        NID_subject_alt_name,
        "DNS:acidns10.attested.name,DNS:localhost");
      if (!ext)
      {
        X509_free(x509);
        return nullptr;
      }
      X509_add_ext(x509, ext, -1);
      X509_EXTENSION_free(ext);

      // Sign the certificate with the private key
      if (!X509_sign(x509, pkey, EVP_sha256()))
      {
        X509_free(x509);
        return nullptr;
      }

      return x509;
    }

    std::string certificate_to_pem(X509* x509)
    {
      BIO* bio = BIO_new(BIO_s_mem());
      if (!PEM_write_bio_X509(bio, x509))
      {
        BIO_free(bio);
        return "";
      }

      char* pem_data;
      long pem_length = BIO_get_mem_data(bio, &pem_data);
      std::string pem_str(pem_data, pem_length);
      BIO_free(bio);
      return pem_str;
    }

    void create_certificate_signing_key(std::string alg)
    {
      try
      {
        check_context();
        uint32_t now = get_fresh_time();

        EVP_PKEY* pkey = create_private_key();
        std::string pem_str = private_key_to_pem(pkey);

        auto private_key_table = rwtx().template rw<CertificatePrivateKeys>(
          certificate_private_key_table_name);
        auto private_keys =
          private_key_table->get().value_or(std::vector<std::string>());
        private_keys.push_back(pem_str);
        private_key_table->put(private_keys);

        X509* x509 = create_root_certificate(pkey);
        std::string pem_str_cert = certificate_to_pem(x509);

        auto root_certificate_table =
          rwtx().template rw<RootCertificates>(root_certificate_table_name);
        auto root_certificates =
          root_certificate_table->get().value_or(std::vector<std::string>());
        root_certificates.push_back(pem_str_cert);
        root_certificate_table->put(root_certificates);

        CCF_APP_INFO("aDNS: Create root certificate\n{}", pem_str_cert);

        return;
      }
      catch (std::exception& ex)
      {
        CCF_APP_INFO("Certificate signing key gen fails with {}", ex.what());
        return;
      }
    }

  protected:
    ccf::endpoints::CommandEndpointContext* ctx = nullptr;
    bool ctx_writable = false;
    std::mutex reply_mtx;

    std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss;
    std::shared_ptr<ccf::NetworkIdentitySubsystemInterface> nwid_ss;
    std::shared_ptr<ccf::NodeConfigurationInterface> nci_ss;
    std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss;
    HTTPClient http_client;

    std::string internal_node_address = "https://127.0.0.1";

    std::string names_table_name(const Name& origin) const
    {
      return "public:names:" + (std::string)origin.lowered();
    }

    std::string table_name(
      const Name& origin,
      const Name& name,
      aDNS::Class class_,
      aDNS::Type type) const
    {
      return "public:records:" + (std::string)origin.lowered() + ":" +
        (std::string)name.lowered() + "-" + string_from_type(type) + "-" +
        string_from_class(class_);
    }

    void check_context() const
    {
      if (!ctx)
        std::runtime_error("bug: no endpoint context");
    }
  };

  std::shared_ptr<CCFDNS> ccfdns;

  class ContextContext
  {
  public:
    ContextContext(
      std::shared_ptr<CCFDNS> ccfdns_, ccf::endpoints::EndpointContext& ctx_)
    {
      if (!ccfdns)
        throw std::runtime_error("node initialization failed");
      ccfdns->set_endpoint_context(&ctx_, true);
    }

    ContextContext(
      std::shared_ptr<CCFDNS> ccfdns_,
      ccf::endpoints::ReadOnlyEndpointContext& ctx_)
    {
      if (!ccfdns)
        throw std::runtime_error("node initialization failed");
      ccfdns->set_endpoint_context(&ctx_, false);
    }

    ~ContextContext()
    {
      if (ccfdns)
        ccfdns->set_endpoint_context(nullptr, false);
    }
  };

  class DNSQuerySession : public ccf::Session
  {
  protected:
    uint16_t message_length = 0;
    std::vector<uint8_t> bytes;
    int64_t session_id = 0;
    std::shared_ptr<CCFDNS> ccfdns;
    std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss;
    std::shared_ptr<ccf::CustomProtocolSubsystemInterface::Essentials> cp_ess;
    std::mutex mtx;

  public:
    DNSQuerySession(
      std::shared_ptr<CCFDNS> ccfdns,
      std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss) :
      ccfdns(ccfdns),
      cp_ss(cp_ss)
    {
      cp_ess = cp_ss->get_essentials();
    }

    virtual ~DNSQuerySession()
    {
      // Let the host know that we're done and that it can destroy the
      // associated TCPImpl. Without this, file/socket descriptors will not be
      // closed.
      RINGBUFFER_WRITE_MESSAGE(
        tcp::tcp_stop,
        cp_ess->writer,
        session_id,
        std::string("DNS/TCP Session closed"));
    }

    virtual void handle_incoming_data(std::span<const uint8_t> data) override
    {
      if (data.empty())
        return;

      std::lock_guard<std::mutex> lock(mtx);

      try
      {
        bytes.insert(bytes.end(), data.begin(), data.end());

        while (bytes.size() >= 8)
        {
          session_id = *(int64_t*)bytes.data();
          bytes.erase(bytes.begin(), bytes.begin() + 8);

          do
          {
            if (message_length == 0 && bytes.size() >= 2)
            {
              size_t pos = 0;
              message_length = get<uint16_t>(bytes, pos);

              if (message_length == 0)
                bytes.erase(bytes.begin(), bytes.begin() + 1);
            }

            if (message_length > 0 && bytes.size() >= message_length + 2)
            {
              size_t pos = 2;
              RFC1035::Message msg(bytes, pos);
              bytes.erase(bytes.begin(), bytes.begin() + pos);
              message_length = 0;
              auto reply = handle_message(msg);
              send_data((std::vector<uint8_t>)reply.message);
            }
          } while (bytes.size() >= message_length + 2);
        }
      }
      catch (const std::exception& ex)
      {
        CCF_APP_FAIL(
          "CCFDNS: Caught exception in TCP {}: {}", __func__, ex.what());
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(data));
        bytes.clear();
        close_session();
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Caught unknown exception in TCP {}", __func__);
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(data));
        bytes.clear();
        close_session();
      }
    }

    Resolver::Reply handle_message(const Message& msg)
    {
      try
      {
        // Note: not sure we can re-use cp_ess->tx, so we create a new one.

        cp_ess = cp_ss->get_essentials();
        ContextContext cc(ccfdns, *cp_ess->ctx);
        auto r = ccfdns->reply(msg);
        cp_ess->ctx = nullptr;
        cp_ess->tx = nullptr;
        return r;
      }
      catch (const std::exception& ex)
      {
        CCF_APP_FAIL("CCFDNS: Caught exception in {}: {}", __func__, ex.what());
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Caught unknown exception in {}", __func__);
      }

      return {};
    }

    virtual void send_data(std::span<const uint8_t> data) override
    {
      try
      {
        if (data.size() < 1024)
          CCF_APP_TRACE("CCFDNS: TCP reply: {}", ccf::ds::to_hex(data));
        else
          CCF_APP_TRACE("CCFDNS: TCP reply of size {}", data.size());

        uint8_t size[2] = {(uint8_t)(data.size() >> 8), (uint8_t)(data.size())};

        RINGBUFFER_TRY_WRITE_MESSAGE(
          tcp::tcp_outbound,
          cp_ess->writer,
          session_id,
          serializer::ByteRange{size, 2});

        size_t fragment_size = data.size();

        for (size_t i = 0; i < data.size();)
        {
          bool ok = false;
          size_t n = std::min(data.size() - i, fragment_size);

          try
          {
            ok = RINGBUFFER_TRY_WRITE_MESSAGE(
              tcp::tcp_outbound,
              cp_ess->writer,
              session_id,
              serializer::ByteRange{&data.data()[i], n});
          }
          catch (const std::exception& ex)
          {
            CCF_APP_FAIL(
              "CCFDNS: Caught exception in {}: {}", __func__, ex.what());
          }
          catch (...)
          {
            CCF_APP_FAIL("CCFDNS: Caught unknown exception in {}", __func__);
          }

          if (ok)
            i += n;
          else if (fragment_size == 1)
            throw std::runtime_error("TCP send error with fragment_size == 1");
          else
            fragment_size = std::max(fragment_size / 2, 1ul);
        }
      }
      catch (const std::exception& ex)
      {
        CCF_APP_FAIL("CCFDNS: Caught exception in {}: {}", __func__, ex.what());
        bytes.clear();
        close_session();
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Caught unknown exception in {}", __func__);
        bytes.clear();
        close_session();
      }
    }

    virtual void close_session() override
    {
      // RFC 1035:
      // If the server needs to close a dormant connection to reclaim
      // resources, it should wait until the connection has been idle for a
      // period on the order of two minutes.  In particular, the server should
      // allow the SOA and AXFR request sequence (which begins a refresh
      // operation) to be made on a single connection. Since the server would
      // be unable to answer queries anyway, a unilateral close or reset may
      // be used instead of a graceful close.

      CCF_APP_TRACE("CCFDNS: TCP session {} closed", session_id);
      session_id = 0;
    }
  };

  class UDPDNSQuerySession : public DNSQuerySession
  {
  public:
    UDPDNSQuerySession(
      std::shared_ptr<CCFDNS> ccfdns_,
      std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss) :
      DNSQuerySession(ccfdns_, cp_ss)
    {}

    virtual ~UDPDNSQuerySession() = default;

    virtual void handle_incoming_data(std::span<const uint8_t> data) override
    {
      // TODO: separate addr for each request? Fork off?
      std::lock_guard<std::mutex> lock(mtx);

      std::vector<uint8_t> payload;

      try
      {
        auto [sid, family, addr, msg_payload] =
          ringbuffer::read_message<udp::udp_inbound>(data);

        session_id = sid;
        addr_family = family;
        addr_data = addr;
        payload = {msg_payload.data, msg_payload.data + msg_payload.size};
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Failed to read UDP ringbuffer message");
        return;
      }

      try
      {
#ifndef NDEBUG
        char buf[64];
        inet_ntop(addr_family, &addr_data, buf, sizeof(buf));
        CCF_APP_DEBUG("CCFDNS: UDP request from {}", buf);
#endif

        size_t num_read = 0;
        RFC1035::Message msg(
          std::span<const uint8_t>(payload.data(), payload.size()), num_read);

        std::vector<uint8_t> outbuf;

#ifdef ALWAYS_USE_TCP
        uint16_t id = 0;
        if (payload.size() >= 2)
          id = payload.data()[0] << 8 | payload.data()[1];

        RFC1035::Message tc_reply;
        tc_reply.header.id = id;
        tc_reply.header.qr = true;
        tc_reply.header.tc = true;
        tc_reply.header.aa = true;

#  ifdef CCFDNS_STATIC_ANSWER
        RFC1035::Message reply;
        reply.header.id = id;
        reply.header.qr = true;
        reply.header.tc = false;
        reply.header.aa = true;
        static auto rr = ResourceRecord(
          Name("test.adns.ccf.dev."),
          static_cast<uint16_t>(RFC1035::Type::A),
          RFC1035::Class::IN,
          60,
          RFC1035::A("192.168.0.1"));
        reply.answers.push_back(rr);
        reply.questions = msg.questions;
        reply.header.qdcount = msg.questions.size();
        reply.header.ancount = 1;
        outbuf = (std::vector<uint8_t>)reply;

        send_data(outbuf);
        return;
#  endif

        tc_reply.questions = msg.questions;
        tc_reply.header.qdcount = msg.questions.size();

        static const uint16_t udp_payload_size = 512;

        RFC6891::TTL ttl;
        ttl.dnssec_ok = true;

        tc_reply.additionals.push_back(ResourceRecord(
          Name("."),
          static_cast<uint16_t>(aDNS::Type::OPT),
          udp_payload_size,
          ttl,
          {}));
        tc_reply.header.arcount++;

        outbuf = (std::vector<uint8_t>)tc_reply;
#else
        auto reply = DNSQuerySession::handle_message(msg);
        auto reply_data = (std::vector<uint8_t>)reply.message;
        outbuf.insert(outbuf.end(), reply_data.begin(), reply_data.end());

        size_t udp_payload_size = std::max(reply.peer_udp_payload_size, 512UL);

        if (outbuf.size() > udp_payload_size)
        {
          CCF_APP_TRACE(
            "CCFDNS: UDP reply too large, sending truncated reply for a "
            "retry over TCP.");
          RFC1035::Message tc_reply;
          tc_reply.header.id = reply.message.header.id;
          tc_reply.header.qr = true;
          tc_reply.header.tc = true;
          tc_reply.questions = msg.questions;
          tc_reply.header.qdcount = msg.questions.size();
          // TODO: Add OPT?
          outbuf = (std::vector<uint8_t>)tc_reply;
        }
#endif

        send_data(outbuf);

        if (num_read < payload.size())
        {
          CCF_APP_DEBUG(
            "CCFNDS: Excess data in UDP packet: {} bytes",
            payload.size() - num_read);
          CCF_APP_TRACE("CCFDNS: ecxess data={}", ccf::ds::to_hex(data));
        }
      }
      catch (const std::exception& ex)
      {
        CCF_APP_FAIL(
          "CCFDNS: Caught exception in UDP {}: {}", __func__, ex.what());
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(data));
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Caught unknown exception in UDP {}", __func__);
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(data));
      }
    }

    virtual void send_data(std::span<const uint8_t> payload) override
    {
      CCF_APP_TRACE("CCFDNS: UDP reply: {}", ccf::ds::to_hex(payload));

      try
      {
        auto ok = RINGBUFFER_TRY_WRITE_MESSAGE(
          udp::udp_outbound,
          cp_ess->writer,
          session_id,
          addr_family,
          addr_data,
          serializer::ByteRange{payload.data(), payload.size()});

        if (!ok)
          CCF_APP_DEBUG("CCFDNS: UDP write failed.");

        addr_family = 0;
        addr_data.clear();
      }
      catch (const std::exception& ex)
      {
        CCF_APP_FAIL(
          "CCFDNS: Caught exception in UDP {}: {}", __func__, ex.what());
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(payload));
      }
      catch (...)
      {
        CCF_APP_FAIL("CCFDNS: Caught unknown exception in UDP {}", __func__);
        CCF_APP_TRACE("CCFDNS: data={}", ccf::ds::to_hex(payload));
      }
    }

  protected:
    std::mutex mtx;
    short addr_family;
    std::vector<uint8_t> addr_data;
  };

  class Handlers : public ccf::UserEndpointRegistry
  {
  protected:
    std::string node_id;

    std::string get_param(
      const ccf::http::ParsedQuery& parsed_query, const std::string& name)
    {
      std::string r, error_reason;
      if (!ccf::http::get_query_value(parsed_query, name, r, error_reason))
        throw std::runtime_error(fmt::format("parameter '{}' missing.", name));
      return r;
    }

    std::optional<ccf::TxID> txid_from_query(ccf::http::ParsedQuery pq)
    {
      if (!pq.contains("version"))
        return std::nullopt;

      ccf::View view;
      ccf::SeqNo seqno = stol(get_param(pq, "version"));
      if (get_view_for_seqno_v1(seqno, view) == ccf::ApiResult::OK)
        return ccf::TxID{view, seqno};
      return std::nullopt;
    }

  public:
    Handlers(ccf::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF aDNS";
      openapi_info.description =
        "This application implements an attested DNS-over-HTTPS server.";
      openapi_info.document_version = "0.0.0";

      node_id = context.get_node_id();

      auto acme_ss = context.get_subsystem<ccf::ACMESubsystemInterface>();
      auto nwid_ss =
        context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
      auto nci_ss = context.get_subsystem<ccf::NodeConfigurationInterface>();
      auto cp_ss =
        context.get_subsystem<ccf::CustomProtocolSubsystemInterface>();
      auto& istrats = context.get_indexing_strategies();

      ccfdns = std::make_shared<CCFDNS>(
        node_id, acme_ss, nwid_ss, nci_ss, cp_ss, istrats);

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      auto configure = [this](auto& ctx, nlohmann::json&& params) {
        CCF_APP_TRACE("CCFDNS: call /configure");
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<Configure::In>();
          CCF_APP_INFO(
            "CCFDNS: Configuration request size: {}",
            ctx.rpc_ctx->get_request_body().size());
          Configure::Out out = {.registration_info = ccfdns->configure(in)};

          auto log = nlohmann::json{
            {"request", "/configure"}, {"input", in}, {"output", out}};

          CCF_APP_INFO("CCFDNS: Out configuration");
          ctx.rpc_ctx->set_claims_digest(ccf::ClaimsDigest::Digest(log.dump()));
          CCF_APP_INFO("CCFDNS: Set claims digest");

          return ccf::make_success(out);
        }
        catch (std::exception& ex)
        {
          CCF_APP_INFO("CCFDNS: Configure exception {}", ex.what());
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/configure",
        HTTP_POST,
        ccf::json_adapter(configure),
        {std::make_shared<ccf::UserCertAuthnPolicy>()})
        .set_auto_schema<Configure::In, Configure::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto configuration_receipt =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          try
          {
            auto r = ccfdns->configuration_receipt(ctx, historical_state);
            ctx.rpc_ctx->set_response_body(std::move(r));
          }
          catch (std::exception& ex)
          {
            ctx.rpc_ctx->set_response_body(ex.what());
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          }
        };

      auto config_txid_extractor =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        auto tbl = ctx.tx.ro<CCFDNS::TConfigurationTable>(
          ccfdns->configuration_table_name);
        if (!tbl)
          throw std::runtime_error("configuration table not found");
        const auto cfg = tbl->get();
        if (!cfg)
          throw std::runtime_error("configuration not found");
        auto version = tbl->get_version_of_previous_write();
        if (!version || *version == ccf::kv::NoVersion)
          return std::nullopt;
        ccf::View view;
        if (get_view_for_seqno_v1(*version, view) != ccf::ApiResult::OK)
          return std::nullopt;
        return ccf::TxID{.view = view, .seqno = *version};
      };

      make_read_only_endpoint(
        "/configuration-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          configuration_receipt,
          context,
          is_tx_committed,
          config_txid_extractor),
        ccf::no_auth_required)
        .set_auto_schema<void, std::string>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto registration_receipt =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          try
          {
            const auto parsed_query =
              ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
            Name service_name =
              Name(get_param(parsed_query, "service-name")).terminated();
            CCF_APP_DEBUG(
              "CCFDNS: registration_receipt: {}", std::string(service_name));
            auto r =
              ccfdns->registration_receipt(ctx, historical_state, service_name);
            ctx.rpc_ctx->set_response_body(std::move(r));
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          }
          catch (std::exception& ex)
          {
            ctx.rpc_ctx->set_response_body(ex.what());
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          }
        };

      auto registration_txid_extractor =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
        auto txid = txid_from_query(parsed_query);
        if (txid)
          return *txid;
        Name service_name =
          Name(get_param(parsed_query, "service-name")).terminated();
        auto sn = CCFDNS::RegistrationRequests::KeySerialiser::to_serialised(
          service_name);
        auto r = ccfdns->registration_index_strategy->last_write(sn);
        CCF_APP_DEBUG(
          "CCFDNS: registration_txid_extractor: {} {}",
          std::string(service_name),
          r.has_value());
        return r;
      };

      make_read_only_endpoint(
        "/registration-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          registration_receipt,
          context,
          is_tx_committed,
          registration_txid_extractor),
        ccf::no_auth_required)
        .set_auto_schema<std::string, std::string>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto delegation_receipt = [this](
                                  ccf::endpoints::ReadOnlyEndpointContext& ctx,
                                  ccf::historical::StatePtr historical_state) {
        try
        {
          const auto parsed_query =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
          Name subdomain =
            Name(get_param(parsed_query, "subdomain")).terminated();
          auto r = ccfdns->delegation_receipt(ctx, historical_state, subdomain);
          ctx.rpc_ctx->set_response_body(std::move(r));
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
        }
      };

      auto delegation_txid_extractor =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
        auto txid = txid_from_query(parsed_query);
        if (txid)
          return *txid;
        Name subdomain =
          Name(get_param(parsed_query, "subdomain")).terminated();
        auto ssub =
          CCFDNS::DelegationRequests::KeySerialiser::to_serialised(subdomain);
        auto r = ccfdns->delegation_index_strategy->last_write(ssub);
        CCF_APP_DEBUG(
          "CCFDNS: delegation_txid_extractor: {} {}",
          std::string(subdomain),
          r.has_value());
        return r;
      };

      make_read_only_endpoint(
        "/delegation-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          delegation_receipt,
          context,
          is_tx_committed,
          delegation_txid_extractor),
        ccf::no_auth_required)
        .set_auto_schema<std::string, std::string>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto set_parent_delegation_policy = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          auto body = ctx.rpc_ctx->get_request_body();
          auto policies = nlohmann::json::parse(body)
                            .template get<std::vector<std::string>>();
          ccfdns->set_parent_delegation_policy(policies);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/set-parent-delegation-policy",
        HTTP_POST,
        set_parent_delegation_policy,
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto add = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<AddRecord::In>();
          ccfdns->add(in.origin, in.record);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/add",
        HTTP_POST,
        ccf::json_adapter(add),
        {std::make_shared<ccf::MemberCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto dns_query = [this](auto& ctx_) {
        try
        {
          ContextContext cc(ccfdns, ctx_);
          std::vector<uint8_t> bytes;
          auto verb = ctx_.rpc_ctx->get_request_verb();

          if (verb == HTTP_GET)
          {
            const auto parsed_query =
              ccf::http::parse_query(ctx_.rpc_ctx->get_request_query());
            std::string query_b64 = get_param(parsed_query, "dns");
            bytes = ccf::crypto::raw_from_b64url(query_b64);
          }
          else if (verb == HTTP_POST)
          {
            auto headers = ctx_.rpc_ctx->get_request_headers();

            auto ctit = headers.find("content-type");
            if (ctit == headers.end())
              throw std::runtime_error("missing content type header");
            if (ctit->second != "application/dns-message")
              throw std::runtime_error(
                fmt::format("unknown content type {}", ctit->second));

            bytes = ctx_.rpc_ctx->get_request_body();
          }
          else
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "unsupported HTTP verb; use GET or POST");
          }

          CCF_APP_INFO("CCFDNS: Query: {}", ccf::ds::to_hex(bytes));

          auto reply = ccfdns->reply(Message(bytes));

          ctx_.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx_.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE, "application/dns-message");
          std::vector<uint8_t> out = reply.message;
          CCF_APP_INFO("CCFDNS: response: {}", ccf::ds::to_hex(out));

          ctx_.rpc_ctx->set_response_body(out);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_read_only_endpoint(
        "/dns-query", HTTP_GET, dns_query, ccf::no_auth_required)
        .set_auto_schema<void, std::vector<uint8_t>>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      make_read_only_endpoint(
        "/dns-query", HTTP_POST, dns_query, ccf::no_auth_required)
        .set_auto_schema<void, std::vector<uint8_t>>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto register_service = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          CCF_APP_INFO(
            "CCFDNS: Registration request size: {}",
            ctx.rpc_ctx->get_request_body().size());
          const auto in = params.get<RegisterService::In>();
          ccfdns->register_service(in);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/register-service",
        HTTP_POST,
        ccf::json_adapter(register_service),
        ccf::no_auth_required)
        .set_auto_schema<RegisterService::In, RegisterService::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto register_delegation = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          CCF_APP_INFO(
            "CCFDNS: Delegation request size: {}",
            ctx.rpc_ctx->get_request_body().size());
          const auto in = params.get<RegisterDelegation::In>();
          ccfdns->register_delegation(in);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/register-delegation",
        HTTP_POST,
        ccf::json_adapter(register_delegation),
        {std::make_shared<ccf::MemberCertAuthnPolicy>()})
        .set_auto_schema<RegisterDelegation::In, RegisterDelegation::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto resign = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<Resign::In>();
          ccfdns->sign(in.origin);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/resign",
        HTTP_POST,
        ccf::json_adapter(resign),
        {std::make_shared<ccf::UserCertAuthnPolicy>()})
        .set_auto_schema<Resign::In, Resign::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto dump = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(ccfdns->dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint("/dump", HTTP_GET, dump, ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto registration_policy = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(ccfdns->service_registration_policy());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/registration-policy",
        HTTP_GET,
        registration_policy,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto delegation_policy = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::JSON);

          auto policies = ccfdns->delegation_policy();
          nlohmann::json j = policies;
          ctx.rpc_ctx->set_response_body(j.dump(4));
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/delegation-policy",
        HTTP_GET,
        delegation_policy,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_endorsements = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto parsed_query =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
          Name service_name =
            Name(get_param(parsed_query, "service_name")).terminated();
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE, "application/zlib");
          ctx.rpc_ctx->set_response_body(
            ccfdns->get_endorsements(service_name));
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/endorsements", HTTP_GET, get_endorsements, ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();

      ccfdns->find_internal_interface();

      auto cp_ss =
        context.get_subsystem<ccf::CustomProtocolSubsystemInterface>();

      cp_ss->install(
        "DNSTCP",
        [cp_ss](ccf::tls::ConnID, const std::unique_ptr<ccf::tls::Context>&&) {
          return std::static_pointer_cast<ccf::Session>(
            std::make_shared<DNSQuerySession>(ccfdns, cp_ss));
        });

      cp_ss->install(
        "DNSUDP",
        [cp_ss](ccf::tls::ConnID, const std::unique_ptr<ccf::tls::Context>&&) {
          return std::static_pointer_cast<ccf::Session>(
            std::make_shared<UDPDNSQuerySession>(ccfdns, cp_ss));
        });

      CCF_APP_DEBUG("Custom protocol handlers installed.");
    }
  };
}

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
#if defined(TRACE_LOGGING)
    logger::config::level() = TRACE;
#elif defined(VERBOSE_LOGGING)
    logger::config::level() = DEBUG;
#else
    logger::config::level() = INFO;
#endif
    return std::make_unique<ccfdns::Handlers>(context);
  }
}
