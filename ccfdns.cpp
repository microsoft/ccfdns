// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccfdns_json.h"
#include "ccfdns_rpc_types.h"
#include "formatting.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/_private/ds/thread_messaging.h>
#include <ccf/_private/http/http_parser.h>
#include <ccf/_private/node/acme_client.h>
#include <ccf/_private/node/rpc/network_identity_interface.h>
#include <ccf/_private/node/rpc/network_identity_subsystem.h>
#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/curve.h>
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
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/node/node_configuration_interface.h>
#include <ccf/pal/attestation.h>
#include <ccf/service/acme_client_config.h>
#include <ccf/service/node_info.h>
#include <ccf/service/tables/acme_certificates.h>
#include <ccf/service/tables/nodes.h>
#include <ccf/version.h>
#include <kv/version.h>
#include <llhttp/llhttp.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <ravl/oe.h>
#include <ravl/openssl.hpp>
#include <regex>
#include <stdexcept>
#include <tx.h>
#include <tx_id.h>

using namespace aDNS;
using namespace RFC1035;

namespace kv::serialisers
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
        http::HeaderMap&& headers,
        std::string&& body,
        const std::vector<std::string>& ca_certs,
        const std::function<bool(
          http_status, http::HeaderMap&&, std::vector<uint8_t>&&)>& callback,
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
      http::HeaderMap headers;
      std::string body;
      std::vector<std::string> ca_certs;
      std::function<bool(
        http_status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback;
      bool use_node_client_cert;
    };

    static void msg_cb(std::unique_ptr<threading::Tmsg<HTTPRetryMsg>> msg)
    {
      auto vbody =
        std::vector<uint8_t>(msg->data.body.begin(), msg->data.body.end());
      CCF_APP_TRACE("CCFDNS: HTTP: {} {}", msg->data.method, msg->data.url);
      msg->data.client->acme_ss->make_http_request(
        msg->data.method,
        msg->data.url,
        msg->data.headers,
        vbody,
        [msgdata = msg->data](
          const http_status& status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& data) {
          http::HeaderMap hdrs = headers;
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
        ccf::ApplicationProtocol::HTTP1,
        true);
    };

    void request(
      std::string&& method,
      std::string&& url,
      http::HeaderMap&& headers,
      std::string&& body,
      const std::vector<std::string>& ca_certs,
      const std::function<
        bool(http_status, http::HeaderMap&&, std::vector<uint8_t>&&)>& callback,
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

  class ACMEClient : public ACME::Client
  {
  public:
    ACMEClient(
      Resolver& resolver,
      const std::string& origin,
      const ACME::ClientConfig& config,
      const std::vector<uint8_t>& service_csr,
      const std::string& node_address,
      std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss,
      std::shared_ptr<crypto::KeyPair> account_key_pair = nullptr) :
      ACME::Client(config, account_key_pair),
      acme_ss(acme_ss),
      http_client(acme_ss),
      resolver(resolver),
      node_address(node_address),
      origin(origin),
      service_csr(service_csr)
    {}

    virtual ~ACMEClient() = default;

    void reconfigure(
      const std::string& origin,
      const ACME::ClientConfig& config,
      const std::vector<uint8_t>& service_csr,
      const std::string& node_address,
      std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss,
      std::shared_ptr<crypto::KeyPair> account_key_pair = nullptr)
    {
      this->origin = origin;
      this->service_csr = service_csr;
      this->node_address = node_address;
      this->acme_ss = acme_ss;

      this->config = config;
      this->account_key_pair = account_key_pair;

      active_orders.clear();
      this->challenges_todo.clear();
      num_failed_attempts = 0;
    }

    static std::string key_authorization_digest(
      const std::string& token, const std::string& response)
    {
      auto key_authorization = token + "." + response;
      auto digest = crypto::sha256(
        (uint8_t*)key_authorization.data(), key_authorization.size());
      return crypto::b64url_from_raw(
        (uint8_t*)digest.data(), digest.size(), false);
    }

    virtual void on_challenge(
      const std::string& token, const std::string& response) override
    {
      auto sn = config.service_dns_name;
      CCF_APP_DEBUG("CCFDNS: ACME: on_challenge for {}", sn);

      auto digest_b64 = key_authorization_digest(token, response);

      std::vector<Name> sans;
      for (const auto& n : config.alternative_names)
        sans.push_back(n + ".");

      {
        std::lock_guard<std::mutex> lock(challenges_todo_mtx);
        challenges_todo[sn].insert(token);
      }

      acme_ss->make_http_request(
        "POST",
        node_address + "/app/internal/install-acme-response",
        {},
        to_json_bytes(InstallACMEResponse::In{
          origin, config.service_dns_name + ".", sans, digest_b64}),
        [this, sn, token, sz = sans.size()](
          const http_status& http_status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& body) {
          if (
            http_status == HTTP_STATUS_OK ||
            http_status == HTTP_STATUS_NO_CONTENT)
          {
            std::lock_guard<std::mutex> lock(challenges_todo_mtx);
            auto it = challenges_todo.find(sn);
            if (it == challenges_todo.end() || it->second.size() == sz)
              for (auto& t : it->second)
                start_challenge(t);
          }
          else
          {
            std::string sbody(body.begin(), body.end());
            CCF_APP_FAIL(
              "CCFDNS: ACME: error http_status={} body:\n{}",
              http_status,
              sbody);
          }
          return true;
        },
        config.ca_certs,
        ccf::ApplicationProtocol::HTTP1,
        true);
    }

    virtual void on_challenge_finished(const std::string& token) override
    {
      CCF_APP_DEBUG("CCFDNS: ACME: on_challenge_finished");

      {
        std::lock_guard<std::mutex> lock(challenges_todo_mtx);
        auto it = challenges_todo.find(config.service_dns_name);
        if (it != challenges_todo.end())
          it->second.erase(token);
      }

      return; // TODO: Remove

      acme_ss->make_http_request(
        "POST",
        node_address + "/app/internal/remove-acme-response",
        {},
        to_json_bytes(
          RemoveACMEToken::In{origin, config.service_dns_name + "."}),
        [](
          const http_status& http_status,
          const http::HeaderMap&,
          const std::vector<uint8_t>&) { return true; },
        config.ca_certs,
        ccf::ApplicationProtocol::HTTP1,
        true);
    }

    virtual void on_certificate(const std::string& certificate) override
    {
      CCF_APP_DEBUG("CCFDNS: ACME: on_certificate");

      acme_ss->make_http_request(
        "POST",
        node_address + "/app/internal/set-certificate",
        {},
        to_json_bytes(SetCertificate::In{config.service_dns_name, certificate}),
        [](
          const http_status& http_status,
          const http::HeaderMap&,
          const std::vector<uint8_t>&) { return true; },
        config.ca_certs,
        ccf::ApplicationProtocol::HTTP1,
        true);
    }

    virtual std::vector<uint8_t> get_service_csr() override
    {
      return service_csr;
    }

    virtual void on_http_request(
      const http::URL& url,
      http::Request&& req,
      std::function<
        bool(http_status, http::HeaderMap&&, std::vector<uint8_t>&&)> callback)
      override
    {
      std::string method = req.get_method() == HTTP_GET ? "GET" : "POST";
      std::string body(
        req.get_content_data(),
        req.get_content_data() + req.get_content_length());
      auto url_str = url.scheme + "://" + url.host + ":" + url.port + url.path;
      http::HeaderMap headers = req.get_headers();
      http_client.request(
        std::move(method),
        std::move(url_str),
        std::move(headers),
        std::move(body),
        config.ca_certs,
        callback);
    }

  private:
    std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss;
    HTTPClient http_client;
    Resolver& resolver;
    std::string node_address;
    std::string origin;
    std::vector<uint8_t> service_csr;
    std::map<std::string, std::set<std::string>> challenges_todo;
    std::mutex challenges_todo_mtx;
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
      CCF_APP_DEBUG("CCFDNS: visit_entry {}", k);
      txids_by_key[k] = txid;
    }

    std::optional<ccf::TxID> last_write(const ccf::ByteVector& k)
    {
      CCF_APP_DEBUG("CCFDNS: last_write {}", k);
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
      std::shared_ptr<ccf::NetworkIdentitySubsystem> nwid_ss,
      std::shared_ptr<ccf::NodeConfigurationInterface> nci_ss,
      ccf::indexing::IndexingStrategies& istrats) :
      Resolver(),
      node_id(node_id),
      acme_ss(acme_ss),
      nwid_ss(nwid_ss),
      nci_ss(nci_ss),
      http_client(acme_ss)
    {
      acme_account_key_pair = crypto::make_key_pair(crypto::CurveID::SECP384R1);
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
        if (e->authority == ccf::Authority::ACME && e->acme_configuration)
          acme_config_name = *iface.second.endorsement->acme_configuration;
        else
          internal_node_address = "https://" + iface.second.published_address;
      }
    }

    std::string node_id;
    std::string my_name;
    std::vector<uint8_t> my_acme_csr;

    using TConfigurationTable =
      ccf::ServiceValue<aDNS::Resolver::Configuration>;
    const std::string configuration_table_name = "public:adns_configuration";

    using Records = ccf::ServiceSet<ResourceRecord>;
    using Origins = ccf::ServiceSet<RFC1035::Name>;
    const std::string origins_table_name = "public:ccfdns.origins";

    using ServiceCertificates = ccf::ServiceMap<std::string, std::string>;
    const std::string service_certifificates_table_name =
      "public:service_certificates";

    using ServiceRegistrationPolicy = ccf::ServiceValue<std::string>;
    const std::string service_registration_policy_table_name =
      "public:ccf.gov.ccfdns.service_registration_policy";

    using RegistrationRequests = ccf::ServiceMap<Name, RegisterService::In>;
    const std::string registration_requests_table_name =
      "public:service_registration_requests";
    using RegistrationRequestsIndex = LastWriteTxIDByKey;
    std::shared_ptr<RegistrationRequestsIndex> registration_index_strategy =
      nullptr;

    using DelegationPolicies =
      ccf::ServiceValue<std::pair<std::string, std::string>>;
    const std::string delegation_policy_table_name =
      "public:ccf.gov.ccfdns.delegation_policy";

    using DelegationRequests = ccf::ServiceMap<Name, RegisterDelegation::In>;
    const std::string delegation_requests_table_name =
      "public:delegation_requests";
    using DelegationRequestsIndex = LastWriteTxIDByKey;
    std::shared_ptr<DelegationRequestsIndex> delegation_index_strategy =
      nullptr;

    void set_endpoint_context(ccf::endpoints::EndpointContext* c)
    {
      ctx = c;
    }

    virtual Configuration get_configuration() const override
    {
      check_context();
      auto t = ctx->tx.template ro<CCFDNS::TConfigurationTable>(
        configuration_table_name);
      if (!t)
        throw std::runtime_error("empty configuration table");
      auto cfg = t->get();
      if (!cfg)
        throw std::runtime_error("no configuration available");
      return *cfg;
    }

    virtual void set_configuration(const Configuration& cfg) override
    {
      check_context();
      auto t = ctx->tx.template rw<CCFDNS::TConfigurationTable>(
        configuration_table_name);
      t->put(cfg);
    }

    virtual std::shared_ptr<crypto::KeyPair> get_tls_key() override
    {
      check_context();
      auto ni = nwid_ss->get().get();
      return crypto::make_key_pair(ni->priv_key);
    }

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      check_context();
      CCF_APP_TRACE("CCFDNS: Add: {}", string_from_resource_record(rr));

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      auto origins = ctx->tx.rw<Origins>(origins_table_name);
      if (!origins->contains(origin))
        origins->insert(origin);

      auto c = static_cast<aDNS::Class>(rr.class_);
      auto t = static_cast<aDNS::Type>(rr.type);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      records->insert(rs);
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
        rr.name,
        string_from_type(t),
        origin);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      if (records)
        records->remove(rs);
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

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      if (records)
      {
        records->foreach([origin, t, &aname, &records](
                           const ResourceRecord& rr) {
          if (rr.type == static_cast<uint16_t>(t) && rr.name == aname)
          {
            CCF_APP_TRACE("CCFDNS: Remove {}", string_from_resource_record(rr));
            records->remove(rr);
          }
          return true;
        });
      }
    }

    virtual void remove(
      const Name& origin, aDNS::Class c, aDNS::Type t) override
    {
      check_context();

      CCF_APP_TRACE(
        "CCFDNS: Remove type {} at {}", string_from_type(t), origin);

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      if (records)
        records->clear();
    }

    using Resolver::reply;

    virtual Reply reply(const Message& msg) override
    {
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
      std::string tn = table_name(origin, c, t);

      auto records = ctx->tx.ro<Records>(tn);
      records->foreach([&qclass, &qtype, &f](const auto& rr) {
        if (
          !is_type_in_qtype(rr.type, qtype) ||
          !is_class_in_qclass(rr.class_, qclass))
        {
          return true;
        }
        return f(rr);
      });
    }

    virtual bool origin_exists(const Name& name) const override
    {
      check_context();
      auto origins = ctx->tx.ro<Origins>(origins_table_name);
      return origins->contains(name.lowered());
    }

    virtual crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) override
    {
      check_context();

      auto originl = origin.lowered();
      auto table_name = "private:signing_keys";
      auto table = ctx->tx.ro<Keys>(table_name);
      if (!table)
        return {};
      auto key_maps = table->get(originl);
      if (key_maps)
      {
        auto& key_map = key_signing ? key_maps->key_signing_keys :
                                      key_maps->zone_signing_keys;
        auto kit = key_map.find(tag);
        if (kit != key_map.end())
        {
          for (const auto& pem : kit->second)
          {
            auto kp = crypto::make_key_pair(pem);
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
      const crypto::Pem& pem,
      bool key_signing) override
    {
      check_context();

      auto origin_lowered = origin.lowered();
      auto table_name = "private:signing_keys";
      auto table = ctx->tx.rw<Keys>(table_name);
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

      auto policy_table = ctx->tx.ro<ServiceRegistrationPolicy>(
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

      auto policy = ctx->tx.rw<ServiceRegistrationPolicy>(
        service_registration_policy_table_name);

      if (!policy)
        throw std::runtime_error(
          "error accessing service registration policy table");

      policy->put(new_policy);
    }

    virtual std::string delegation_policy() const override
    {
      check_context();

      auto tbl = ctx->tx.ro<DelegationPolicies>(delegation_policy_table_name);
      const auto policies = tbl->get();
      if (!policies)
        throw std::runtime_error("no delegation registration policies");

      auto [parent, local] = *policies;

      if (parent.empty())
        throw std::runtime_error("no parent delegation policy");
      if (local.empty())
        throw std::runtime_error("no local delegation policy");

      return "function parent() {\n" + parent +
        "\n}\n\n"
        "function local() {\n" +
        local + "\n" + "return r == true;" + "\n" +
        "}\n\n"
        "parent() && local()";
    }

    virtual void set_parent_delegation_policy(const std::string& new_policy)
    {
      check_context();

      auto tbl = ctx->tx.rw<DelegationPolicies>(delegation_policy_table_name);

      if (!tbl)
        throw std::runtime_error(
          "error accessing parent delegation policy table");

      const auto old_policies = tbl->get();

      if (!old_policies)
        throw std::runtime_error("error accessing parent delegation policy");

      tbl->put(std::make_pair(new_policy, old_policies->second));
    }

    virtual void set_delegation_policy(const std::string& new_policy) override
    {
      check_context();

      auto tbl = ctx->tx.rw<DelegationPolicies>(delegation_policy_table_name);

      if (!tbl)
        throw std::runtime_error("error accessing delegation policy table");

      const auto old_policies = tbl->get();

      if (!old_policies)
        throw std::runtime_error("error accessing delegation policy");

      tbl->put({old_policies->first, new_policy});
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
      std::string program = data + "\n\n" + delegation_policy();
      return rt.eval(program);
    }

    using Resolver::register_delegation;
    using Resolver::register_service;

    virtual void set_service_certificate(
      const std::string& service_name,
      const std::string& certificate_pem) override
    {
      check_context();

      if (
        service_name == get_configuration().origin ||
        service_name + "." == get_configuration().origin)
      {
        auto tbl = ctx->tx.template rw<ccf::ACMECertificates>(
          ccf::Tables::ACME_CERTIFICATES);
        if (!tbl)
          throw std::runtime_error("missing ACME certificate table");
        tbl->put(acme_config_name, certificate_pem);
      }
      else
      {
        auto tbl =
          ctx->tx.rw<ServiceCertificates>(service_certifificates_table_name);
        tbl->put(service_name, certificate_pem);
        acme_clients.erase(service_name);
      }
    }

    virtual std::string get_service_certificate(
      const std::string& service_name) override
    {
      check_context();

      const auto& cfg = get_configuration();

      if (
        service_name == my_name || service_name == cfg.origin ||
        service_name == my_name + "." ||
        service_name == cfg.origin.unterminated())
      {
        auto t = ctx->tx.template rw<ccf::ACMECertificates>(
          ccf::Tables::ACME_CERTIFICATES);
        if (!t)
          throw std::runtime_error("service certificate table empty");
        auto v = t->get(acme_config_name);
        if (!v)
          throw std::runtime_error("service certificate not available");
        return v->str();
      }
      else
      {
        auto tbl =
          ctx->tx.ro<ServiceCertificates>(service_certifificates_table_name);
        auto r = tbl->get(service_name);
        if (!r)
          throw std::runtime_error("no such certificate");
        return *r;
      }
    }

    virtual std::map<std::string, NodeInfo> get_node_information() override
    {
      check_context();

      const auto& cfg = get_configuration();

      std::map<std::string, NodeInfo> r;

      auto nodes_table = ctx->tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
      if (!nodes_table)
        throw std::runtime_error("error accessing nodes table");

      for (const auto& [id, addr] : cfg.node_addresses)
      {
        auto entry = nodes_table->get(id);
        auto attestation = ravl::oe::Attestation(
          entry->quote_info.quote, entry->quote_info.endorsements);
        r[id] = {.address = addr, .attestation = attestation};
      }

      return r;
    }

    virtual RegistrationInformation configure(const Configuration& cfg) override
    {
      check_context();
      auto reginfo = Resolver::configure(cfg);
      my_acme_csr = reginfo.csr;

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
        CCF_APP_DEBUG("MY NAME: {}", my_name);
      }

      if (cfg.parent_base_url)
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
            http_status status,
            http::HeaderMap&&,
            std::vector<uint8_t>&& body) {
            if (status != HTTP_STATUS_OK)
            {
              CCF_APP_FAIL("CCFDNS: Failed to get parent delegation policy");
              return false;
            }

            std::string sbody(body.begin(), body.end());
            http_client.request(
              "POST",
              internal_node_address + "/app/set-parent-delegation-policy",
              {},
              std::move(sbody),
              {nwid_ss->get()->cert.str()},
              [](
                http_status status,
                http::HeaderMap&&,
                std::vector<uint8_t>&& body) {
                if (status != HTTP_STATUS_OK)
                  CCF_APP_FAIL("CCFDNS: Failed to set delegation policy");
                return true;
              },
              true);
            return true;
          });
      }
      else
      {
        // No parent, i.e. we are a TLD and need to get our TLS certificate
        // directly from the CA, instead of a parent aDNS instance.

        set_parent_delegation_policy("return true;");

        auto cn = cfg.origin.unterminated();

        std::vector<std::string> acme_contact;
        for (const auto& email : cfg.contact)
          acme_contact.push_back("mailto:" + email);

        ACME::ClientConfig acme_client_config = {
          .ca_certs = cfg.service_ca.ca_certificates,
          .directory_url = cfg.service_ca.directory,
          .service_dns_name = cn,
          .alternative_names = {cn},
          .contact = acme_contact,
          .terms_of_service_agreed = true,
          .challenge_type = "dns-01"};

        acme_client_config.ca_certs.push_back(nwid_ss->get()->cert.str());

        std::vector<crypto::SubjectAltName> sans;
        sans.push_back({cn, false});

        for (const auto& [id, addr] : cfg.node_addresses)
        {
          auto name = addr.name.unterminated();
          acme_client_config.alternative_names.push_back(name);
          sans.push_back({name, false});
        }

        auto tls_key = get_tls_key();
        auto csr =
          tls_key->create_csr_der("CN=" + cn, sans, tls_key->public_key_pem());

        auto acme_client = std::make_shared<ccfdns::ACMEClient>(
          *this,
          cfg.origin,
          acme_client_config,
          csr,
          internal_node_address,
          acme_ss,
          acme_account_key_pair);

        acme_client->get_certificate(acme_account_key_pair);

        acme_clients[cn] = acme_client;
      }

      return reginfo;
    }

    std::string configuration_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx,
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

      nlohmann::json j;
      j["txid"] = txid.value();
      j["configuration"] = cfg.value();
      j["receipt"] = receipt;
      return j.dump();
    }

    std::string registration_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx,
      ccf::historical::StatePtr historical_state,
      const std::string& service_name)
    {
      auto historical_tx = historical_state->store->create_read_only_tx();
      auto tbl = historical_tx.template ro<RegistrationRequests>(
        registration_requests_table_name);
      if (!tbl)
        throw std::runtime_error("service registration table not found");
      const auto reg = tbl->get(service_name);
      if (!reg)
        throw std::runtime_error("service registration not found");
      auto receipt = ccf::describe_receipt_v1(*historical_state->receipt);

      nlohmann::json j;
      j["registration"] = reg.value();
      j["receipt"] = receipt;
      return j.dump();
    }

    std::string delegation_receipt(
      ccf::endpoints::ReadOnlyEndpointContext& ctx,
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

      nlohmann::json j;
      j["delegation"] = dr.value();
      j["receipt"] = receipt;
      return j.dump();
    }

    virtual void start_delegation_acme_client()
    {
      check_context();

      const auto& cfg = get_configuration();

      if (cfg.parent_base_url)
      {
        std::vector<std::string> acme_contact;
        for (const auto& c : cfg.contact)
          acme_contact.push_back("mailto:" + c);
        start_service_acme(cfg.origin, cfg.origin, my_acme_csr, acme_contact);
      }
    }

    virtual void save_service_registration_request(
      const Name& name, const RegistrationRequest& rr) override
    {
      check_context();

      auto lrr = ctx->tx.template rw<CCFDNS::RegistrationRequests>(
        registration_requests_table_name);
      if (!lrr)
        throw std::runtime_error(
          "could not access service registration request table");
      lrr->put(name, rr);
    }

    virtual void save_delegation_request(
      const Name& name, const DelegationRequest& dr) override
    {
      check_context();

      auto lrr = ctx->tx.template rw<CCFDNS::DelegationRequests>(
        delegation_requests_table_name);
      if (!lrr)
        throw std::runtime_error(
          "could not access delegation registration request table");
      lrr->put(name, dr);
    }

    virtual void start_service_acme(
      const Name& origin,
      const Name& name,
      const std::vector<uint8_t>& csr,
      const std::vector<std::string>& contact,
      const std::optional<std::string>& service_url = std::nullopt,
      const std::optional<std::vector<std::string>>& service_ca_certs = {})
      override
    {
      const auto& cfg = get_configuration();

      CCF_APP_DEBUG("CCFDNS: Set up ACME client for {}", name);

      std::string subject_name = name.unterminated();

      OpenSSL::UqX509_REQ req(csr, false);

      CCF_APP_DEBUG("CCFDNS: CSR:\n{}", (std::string)req);

      auto sans = req.get_subject_alternative_names();
      std::vector<std::string> ssans;
      for (size_t i = 0; i < sans.size(); i++)
      {
        auto san = sans.at(i);
        if (san.is_dns())
          ssans.push_back((std::string)san.string());
      }

      ACME::ClientConfig acme_client_config = {
        .ca_certs = cfg.service_ca.ca_certificates,
        .directory_url = cfg.service_ca.directory,
        .service_dns_name = subject_name,
        .alternative_names = ssans,
        .contact = contact,
        .terms_of_service_agreed = true,
        .challenge_type = "dns-01"};

      acme_client_config.ca_certs.push_back(nwid_ss->get()->cert.str());

      if (service_ca_certs)
        for (const auto& c : *service_ca_certs)
          acme_client_config.ca_certs.push_back(c);

      std::shared_ptr<ccfdns::ACMEClient> acme_client;

      auto ait = acme_clients.find(name);
      if (ait != acme_clients.end())
      {
        CCF_APP_DEBUG("CCFDNS: re-using existing ACME client");
        acme_client = ait->second;
        acme_client->reconfigure(
          origin,
          acme_client_config,
          csr,
          service_url.value_or(internal_node_address),
          acme_ss,
          acme_account_key_pair);
      }
      else
      {
        acme_client = std::make_shared<ccfdns::ACMEClient>(
          *this,
          origin,
          acme_client_config,
          csr,
          service_url.value_or(internal_node_address),
          acme_ss,
          acme_account_key_pair);
        acme_clients[name] = acme_client;
      }

      acme_client->get_certificate(acme_account_key_pair);
    }

    bool have_acme_client(const std::string& name) const
    {
      return acme_clients.find(name) != acme_clients.end();
    }

    std::string dump()
    {
      const auto& cfg = get_configuration();
      std::string r;

      auto origins = ctx->tx.ro<CCFDNS::Origins>(origins_table_name);
      origins->foreach([this, &r, &cfg](const Name& origin) {
        r += "$ORIGIN " + (std::string)origin + "\n";
        r += "$TTL " + std::to_string(cfg.default_ttl) + "\n\n";
        for (const auto& [_, c] : get_supported_classes())
          for (const auto& [_, t] : get_supported_types())
          {
            auto records = ctx->tx.ro<Records>(table_name(origin, c, t));
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
                  sd.type_covered == static_cast<uint16_t>(aDNS::Type::ATTEST))
                  r += "; ";
                r += tmp;
              }
              else
                r += tmp;
              return true;
            });
          }
        r += "\n";
        return true;
      });

      return r;
    }

  protected:
    ccf::endpoints::EndpointContext* ctx = nullptr;
    std::map<std::string, std::shared_ptr<ccfdns::ACMEClient>> acme_clients;

    std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss;
    std::shared_ptr<ccf::NetworkIdentitySubsystemInterface> nwid_ss;
    std::shared_ptr<ccf::NodeConfigurationInterface> nci_ss;
    HTTPClient http_client;

    crypto::KeyPairPtr acme_account_key_pair;
    std::string internal_node_address = "https://127.0.0.1";
    std::string acme_config_name;

    std::string table_name(
      const Name& origin, aDNS::Class class_, aDNS::Type type) const
    {
      return "public:" + (std::string)origin.lowered() + "-" +
        string_from_type(type) + "-" + string_from_class(class_);
    }

    void check_context() const
    {
      if (!ctx)
        std::runtime_error("bug: no endpoint context");
    }
  };

  std::shared_ptr<CCFDNS> ccfdns;

  class Handlers : public ccf::UserEndpointRegistry
  {
  protected:
    std::string node_id;

    std::string get_param(
      const http::ParsedQuery& parsed_query, const std::string& name)
    {
      std::string r, error_reason;
      if (!http::get_query_value(parsed_query, name, r, error_reason))
        throw std::runtime_error(fmt::format("parameter '{}' missing.", name));
      return r;
    }

    class ContextContext
    {
    public:
      ContextContext(
        std::shared_ptr<CCFDNS> ccfdns, ccf::endpoints::EndpointContext& ctx)
      {
        if (!ccfdns)
          throw std::runtime_error("node initialization failed");
        ccfdns->set_endpoint_context(&ctx);
      }

      ~ContextContext()
      {
        if (ccfdns)
          ccfdns->set_endpoint_context(nullptr);
      }
    };

  public:
    Handlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF aDNS";
      openapi_info.description =
        "This application implements an attested DNS-over-HTTPS server.";
      openapi_info.document_version = "0.0.0";

      node_id = context.get_node_id();

      auto acme_ss = context.get_subsystem<ccf::ACMESubsystemInterface>();
      auto nwid_ss = context.get_subsystem<ccf::NetworkIdentitySubsystem>();
      auto nci_ss = context.get_subsystem<ccf::NodeConfigurationInterface>();
      auto& istrats = context.get_indexing_strategies();

      ccfdns =
        std::make_shared<CCFDNS>(node_id, acme_ss, nwid_ss, nci_ss, istrats);

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      auto configure = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<Configure::In>();
          Configure::Out out = {ccfdns->configure(in)};
          return ccf::make_success(out);
        }
        catch (std::exception& ex)
        {
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
        if (!version || *version == kv::NoVersion)
          return std::nullopt;
        return ccf::TxID{.view = consensus->get_view(), .seqno = *version};
      };

      make_read_only_endpoint(
        "/configuration-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v3(
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
              http::parse_query(ctx.rpc_ctx->get_request_query());
            Name service_name =
              Name(get_param(parsed_query, "service-name")).terminated();
            CCF_APP_DEBUG("CCFDNS: registration_receipt: {}", service_name);
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
          http::parse_query(ctx.rpc_ctx->get_request_query());
        Name service_name =
          Name(get_param(parsed_query, "service-name")).terminated();
        auto sn = CCFDNS::RegistrationRequests::KeySerialiser::to_serialised(
          service_name);
        auto r = ccfdns->registration_index_strategy->last_write(sn);
        CCF_APP_DEBUG(
          "CCFDNS: registration_txid_extractor: {} {}",
          service_name,
          r.has_value());
        return r;
      };

      make_read_only_endpoint(
        "/registration-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v3(
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
            http::parse_query(ctx.rpc_ctx->get_request_query());
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
          http::parse_query(ctx.rpc_ctx->get_request_query());
        Name subdomain =
          Name(get_param(parsed_query, "subdomain")).terminated();
        auto ssub =
          CCFDNS::DelegationRequests::KeySerialiser::to_serialised(subdomain);
        auto r = ccfdns->delegation_index_strategy->last_write(ssub);
        CCF_APP_DEBUG(
          "CCFDNS: delegation_txid_extractor: {} {}", subdomain, r.has_value());
        return r;
      };

      make_read_only_endpoint(
        "/delegation-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v3(
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
          auto new_policy = ctx.rpc_ctx->get_request_body();
          ccfdns->set_parent_delegation_policy(
            {new_policy.begin(), new_policy.end()});
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/set-parent-delegation-policy",
        HTTP_POST,
        set_parent_delegation_policy,
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto start_acme_client = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          ccfdns->start_delegation_acme_client();
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/start-delegation-acme-client",
        HTTP_POST,
        ccf::json_adapter(start_acme_client),
        {std::make_shared<ccf::UserCertAuthnPolicy>()})
        .set_auto_schema<void, void>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto install_acme_response = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<InstallACMEResponse::In>();
          CCF_APP_DEBUG(
            "ADNS: install ACME response for {}: {}",
            in.name,
            in.key_authorization);
          ccfdns->install_acme_response(
            in.origin, in.name, in.alternative_names, in.key_authorization);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/install-acme-response",
        HTTP_POST,
        ccf::json_adapter(install_acme_response),
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto remove_acme_response = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<RemoveACMEToken::In>();
          ccfdns->remove_acme_response(in.origin, in.name);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/remove-acme-response",
        HTTP_POST,
        ccf::json_adapter(remove_acme_response),
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
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
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto dns_query = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          std::vector<uint8_t> bytes;
          auto verb = ctx.rpc_ctx->get_request_verb();

          if (verb == HTTP_GET)
          {
            const auto parsed_query =
              http::parse_query(ctx.rpc_ctx->get_request_query());
            std::string query_b64 = get_param(parsed_query, "dns");
            bytes = crypto::raw_from_b64url(query_b64);
          }
          else if (verb == HTTP_POST)
          {
            auto headers = ctx.rpc_ctx->get_request_headers();

            auto ctit = headers.find("content-type");
            if (ctit == headers.end())
              throw std::runtime_error("missing content type header");
            if (ctit->second != "application/dns-message")
              throw std::runtime_error(
                fmt::format("unknown content type {}", ctit->second));

            bytes = ctx.rpc_ctx->get_request_body();
          }
          else
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "unsupported HTTP verb; use GET or POST");
          }
          CCF_APP_INFO("CCFDNS: query: {}", ds::to_hex(bytes));

          auto reply = ccfdns->reply(Message(bytes));

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, "application/dns-message");
          std::vector<uint8_t> out = reply.message;
          CCF_APP_INFO("CCFDNS: response: {}", ds::to_hex(out));

          ctx.rpc_ctx->set_response_body(out);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint("/dns-query", HTTP_GET, dns_query, ccf::no_auth_required)
        .set_auto_schema<void, std::vector<uint8_t>>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      make_endpoint("/dns-query", HTTP_POST, dns_query, ccf::no_auth_required)
        .set_auto_schema<void, std::vector<uint8_t>>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto register_service = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
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
        {std::make_shared<ccf::MemberCertAuthnPolicy>()})
        .set_auto_schema<RegisterService::In, RegisterService::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto register_delegation = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
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

      auto set_certificate = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<SetCertificate::In>();
          ccfdns->set_service_certificate(in.service_dns_name, in.certificate);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/set-certificate",
        HTTP_POST,
        ccf::json_adapter(set_certificate),
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto get_certificate = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto in = params.get<GetCertificate::In>();
          GetCertificate::Out out;
          out.certificate =
            ccfdns->get_service_certificate(in.service_dns_name);
          return ccf::make_success(out);
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/get-certificate",
        HTTP_POST,
        ccf::json_adapter(get_certificate),
        ccf::no_auth_required)
        .set_auto_schema<GetCertificate::In, GetCertificate::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
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
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
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
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
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
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(ccfdns->delegation_policy());
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
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();
      ccfdns->find_internal_interface();
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
#if defined(TRACE_LOGGING)
    logger::config::level() = logger::TRACE;
#elif defined(VERBOSE_LOGGING)
    logger::config::level() = logger::DEBUG;
#else
    logger::config::level() = logger::INFO;
#endif
    return std::make_unique<ccfdns::Handlers>(context);
  }
}
