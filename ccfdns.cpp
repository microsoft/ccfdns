// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccfdns_rpc_types.h"
#include "formatting.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/_private/http/http_parser.h>
#include <ccf/_private/node/acme_client.h>
#include <ccf/_private/node/rpc/network_identity_interface.h>
#include <ccf/_private/node/rpc/network_identity_subsystem.h>
#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <ccf/http_header_map.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/node/node_configuration_interface.h>
#include <ccf/pal/attestation.h>
#include <ccf/service/tables/acme_certificates.h>
#include <ccf/version.h>
#include <charconv>
#include <crypto/curve.h>
#include <endpoint_context.h>
#include <nlohmann/json.hpp>
#include <odata_error.h>
#include <optional>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <ravl/oe.h>
#include <ravl/openssl.hpp>
#include <service/acme_client_config.h>
#include <stdexcept>

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
      return ResourceRecord({data.data(), data.data() + data.size()}, pos);
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

  class ACMEClient : public ACME::Client
  {
  public:
    ACMEClient(
      Resolver& resolver,
      const std::string& origin,
      const ACME::ClientConfig& config,
      const std::vector<uint8_t>& service_csr,
      const std::string& node_address,
      std::shared_ptr<ccf::ACMESubsystemInterface> subsys,
      std::shared_ptr<crypto::KeyPair> account_key_pair = nullptr) :
      ACME::Client(config, account_key_pair),
      subsys(subsys),
      resolver(resolver),
      node_address(node_address),
      origin(origin),
      service_csr(service_csr)
    {}

    virtual ~ACMEClient() = default;

    virtual void on_challenge(
      const std::string& token, const std::string& response) override
    {
      CCF_APP_DEBUG("ADNS ACME: on_challenge");

      auto key_authorization = token + "." + response;
      auto digest = crypto::sha256(
        (uint8_t*)key_authorization.data(), key_authorization.size());
      auto digest_b64 =
        crypto::b64url_from_raw((uint8_t*)digest.data(), digest.size(), false);

      InstallACMEToken::In in = {
        origin, config.service_dns_name + ".", digest_b64};
      std::string url =
        "https://" + node_address + "/app/internal/install_acme_response";

      for (const auto& c : config.ca_certs)
        CCF_APP_DEBUG("CA certificate: {}", c);

      subsys->make_http_request(
        "POST",
        url,
        {},
        to_json_bytes(in),
        [this, token](
          const http_status& http_status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& body) {
          if (
            http_status == HTTP_STATUS_OK ||
            http_status == HTTP_STATUS_NO_CONTENT)
            start_challenge(token);
          else
            CCF_APP_FAIL("ADNS ACME: error http_status={}", http_status);
          return true;
        },
        config.ca_certs);
    }

    virtual void on_challenge_finished(const std::string& token) override
    {
      CCF_APP_DEBUG("ADNS ACME: on_challenge_finished");

      RemoveACMEToken::In in = {origin, config.service_dns_name + "."};
      std::string url =
        "https://" + node_address + "/app/internal/remove_acme_response";
      subsys->make_http_request(
        "POST",
        url,
        {},
        to_json_bytes(in),
        [](
          const http_status& http_status,
          const http::HeaderMap&,
          const std::vector<uint8_t>&) { return true; },
        config.ca_certs);
    }

    virtual void on_certificate(const std::string& certificate) override
    {
      CCF_APP_DEBUG("ADNS ACME: on_certificate");

      SetCertificate::In in = {config.service_dns_name, certificate};
      std::string url =
        "https://" + node_address + "/app/internal/set-certificate";
      subsys->make_http_request(
        "POST",
        url,
        {},
        to_json_bytes(in),
        [](
          const http_status& http_status,
          const http::HeaderMap&,
          const std::vector<uint8_t>&) { return true; },
        config.ca_certs);
    }

    virtual std::vector<uint8_t> get_service_csr() override
    {
      return service_csr;
    }

    virtual void on_http_request(
      const http::URL& url,
      http::Request&& req,
      std::function<
        bool(http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback) override
    {
      auto method =
        req.get_method() == llhttp_method::HTTP_POST ? "POST" : "GET";

      auto url_str = url.scheme + "://" + url.host + ":" + url.port + url.path;

      CCF_APP_DEBUG("ADNS ACME: on_http_request: {}", url_str);

      std::vector<uint8_t> body(
        req.get_content_data(),
        req.get_content_data() + req.get_content_length());

      subsys->make_http_request(
        method,
        url_str,
        req.get_headers(),
        body,
        [callback](
          const http_status& status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& data) {
          http::HeaderMap hdrs = headers;
          std::vector<uint8_t> cdata = data;
          return callback(status, std::move(hdrs), std::move(cdata));
        },
        config.ca_certs);
    }

  private:
    std::shared_ptr<ccf::ACMESubsystemInterface> subsys;
    Resolver& resolver;
    std::string node_address;
    std::string origin;
    std::vector<uint8_t> service_csr;
  };

  class CCFDNS : public Resolver
  {
  public:
    CCFDNS() : Resolver() {}

    virtual ~CCFDNS() {}

    using TConfigurationTable =
      ccf::ServiceValue<aDNS::Resolver::Configuration>;
    const std::string configuration_table_name = "public:adns_configuration";

    using Records = ccf::ServiceSet<ResourceRecord>;
    using Origins = ccf::ServiceSet<RFC1035::Name>;
    const std::string origins_table_name = "public:ccfdns.origins";

    using RegistrationPolicy = ccf::ServiceValue<std::string>;
    const std::string registration_policy_table_name =
      "public:ccf.gov.ccfdns.registration_policy";

    using ServiceCertificates = ccf::ServiceMap<std::string, std::string>;
    const std::string service_certifificates_table_name =
      "public:service_certificates";

    void set_endpoint_context(ccf::endpoints::EndpointContext& ctx)
    {
      this->ctx = &ctx;
    }

    virtual void configure(const Configuration& cfg) override
    {
      Resolver::configure(cfg);

      // TODO: Add table hook to re-configure upon changes.

      auto t = ctx->tx.template rw<CCFDNS::TConfigurationTable>(
        configuration_table_name);
      t->put(cfg);

      add(
        cfg.origin,
        ResourceRecord(
          cfg.name,
          static_cast<uint16_t>(aDNS::Type::NS),
          static_cast<uint16_t>(aDNS::Class::IN),
          cfg.default_ttl,
          NS(cfg.name)));

      add(
        cfg.origin,
        ResourceRecord(
          cfg.name,
          static_cast<uint16_t>(aDNS::Type::A),
          static_cast<uint16_t>(aDNS::Class::IN),
          cfg.default_ttl,
          A(cfg.ip)));

      // Add our own attestation; may not be required.
      std::shared_ptr<ravl::Attestation> attestation;
      ccf::pal::attestation_report_data ard = {0};
      ccf::pal::generate_quote(
        ard,
        [&attestation](
          const ccf::QuoteInfo& quote_info,
          const ccf::pal::snp::EndorsementEndpointsConfiguration&) {
          attestation = std::make_shared<ravl::oe::Attestation>(
            quote_info.quote, quote_info.endorsements);
        });

      add(
        cfg.origin,
        ResourceRecord(
          cfg.name,
          static_cast<uint16_t>(aDNS::Types::Type::ATTEST),
          static_cast<uint16_t>(aDNS::Class::IN),
          configuration.default_ttl,
          aDNS::Types::ATTEST(attestation)));
    }

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      CCF_APP_DEBUG("CCFDNS: Add: {}", string_from_resource_record(rr));

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
        throw std::runtime_error("origin not absolute");

      auto origins = ctx->tx.rw<Origins>(origins_table_name);
      if (!origins->contains(origin))
        origins->insert(origin);

      auto c = static_cast<aDNS::Class>(rr.class_);
      auto t = static_cast<aDNS::Type>(rr.type);

      CCF_APP_TRACE(
        "CCFDNS: Add {} type {} to {}", rr.name, string_from_type(t), origin);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      records->insert(rs);

      Resolver::on_add(origin, rs);
    }

    virtual void remove(const Name& origin, const ResourceRecord& rr)
    {
      CCF_APP_DEBUG("CCFDNS: Remove: {}", string_from_resource_record(rr));

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("origin not absolute");
      }

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

      Resolver::on_remove(origin, rs);
    }

    virtual void remove(
      const Name& origin,
      const Name& name,
      aDNS::Class c,
      aDNS::Type t) override
    {
      CCF_APP_DEBUG(
        "CCFDNS: Remove {} type {} at {}", name, string_from_type(t), origin);

      if (!ctx)
        std::runtime_error("missing endpoint context");

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
            CCF_APP_TRACE("CCFDNS: remove {}", string_from_resource_record(rr));
            records->remove(rr);
          }
          return true;
        });
      }
    }

    virtual void remove(
      const Name& origin, aDNS::Class c, aDNS::Type t) override
    {
      CCF_APP_DEBUG(
        "CCFDNS: Remove type {} at {}", string_from_type(t), origin);

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("origin not absolute");
      }

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      if (records)
        records->clear();
    }

    using Resolver::reply;

    virtual Message reply(const Message& msg) override
    {
      if (!ctx)
        std::runtime_error("missing endpoint context");

      return Resolver::reply(msg);
    }

    virtual void for_each(
      const Name& origin,
      aDNS::QClass qclass,
      aDNS::QType qtype,
      const std::function<bool(const ResourceRecord&)>& f) const override
    {
      if (!ctx)
        std::runtime_error("missing endpoint context");

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
      CCF_APP_DEBUG("Looking for origin: {}", name);
      auto origins = ctx->tx.ro<Origins>(origins_table_name);
      return origins->contains(name.lowered());
    }

    virtual crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) override
    {
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

    virtual std::string registration_policy() const override
    {
      auto policy_table =
        ctx->tx.ro<RegistrationPolicy>(registration_policy_table_name);
      const std::optional<std::string> policy = policy_table->get();
      if (!policy)
        throw std::runtime_error("no registration policy");
      return *policy;
    }

    virtual void set_registration_policy(const std::string& new_policy) override
    {
      auto policy =
        ctx->tx.rw<RegistrationPolicy>(registration_policy_table_name)->get();
      policy = new_policy;
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

        CCF_APP_TRACE("Policy evaluation program:\n{}", program);

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
          CCF_APP_DEBUG("Policy evaluation result: {}", cstr);
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

    virtual bool evaluate_registration_policy(
      const std::string& data) const override
    {
      RPJSRuntime rt;
      std::string program = data + "\n\n" + registration_policy();
      return rt.eval(program);
    }

    using Resolver::register_service;

    virtual void set_service_certificate(
      const std::string& service_dns_name,
      const std::string& certificate_pem) override
    {
      auto tbl =
        ctx->tx.rw<ServiceCertificates>(service_certifificates_table_name);
      tbl->put(service_dns_name, certificate_pem);

      acme_clients.erase(service_dns_name);
    }

    virtual std::string get_service_certificate(
      const std::string& service_dns_name) override
    {
      auto tbl =
        ctx->tx.ro<ServiceCertificates>(service_certifificates_table_name);
      auto r = tbl->get(service_dns_name);
      if (!r)
        throw std::runtime_error("no such certificate");
      return *r;
    }

    bool have_acme_client(const std::string& name) const
    {
      return acme_clients.find(name) != acme_clients.end();
    }

    void add_acme_client(
      const std::string& name, std::shared_ptr<ccfdns::ACMEClient> client)
    {
      acme_clients[name] = client;
    }

    void remove_acme_client(const std::string& name)
    {
      acme_clients.erase(name);
    }

  protected:
    ccf::endpoints::EndpointContext* ctx = nullptr;
    std::map<std::string, std::shared_ptr<ccfdns::ACMEClient>> acme_clients;

    std::string table_name(
      const Name& origin, aDNS::Class class_, aDNS::Type type) const
    {
      return "public:" + (std::string)origin.lowered() + "-" +
        string_from_type(type) + "-" + string_from_class(class_);
    }
  };

  CCFDNS ccfdns;

  class Handlers : public ccf::UserEndpointRegistry
  {
  protected:
    std::string get_param(
      const http::ParsedQuery& parsed_query, const std::string& name)
    {
      std::string r, error_reason;
      if (!http::get_query_value(parsed_query, name, r, error_reason))
        throw std::runtime_error(fmt::format("parameter '{}' missing.", name));
      return r;
    }

    std::shared_ptr<ccf::ACMESubsystemInterface> acme_ss;
    std::string acme_config_name;
    ccf::ACMEClientConfig acme_config;
    crypto::KeyPairPtr acme_account_key_pair;
    std::string internal_node_address = "127.0.0.1";

  public:
    Handlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF aDNS";
      openapi_info.description =
        "This application implements an attested DNS-over-HTTPS server.";
      openapi_info.document_version = "0.0.0";

      acme_account_key_pair = crypto::make_key_pair(crypto::CurveID::SECP384R1);

      auto configure = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<Configure::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.configure(in.configuration);
          return ccf::make_success();
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
        ccf::no_auth_required)
        .set_auto_schema<Configure::In, Configure::Out>()
        .install();

      auto install_acme_response = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<InstallACMEToken::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.install_acme_response(
            in.origin, in.name, in.key_authorization);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/install_acme_response",
        HTTP_POST,
        ccf::json_adapter(install_acme_response),
        ccf::no_auth_required)
        .set_auto_schema<InstallACMEToken::In, InstallACMEToken::Out>()
        .install();

      auto remove_acme_response = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RemoveACMEToken::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.remove_acme_response(in.origin, in.name);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/remove_acme_response",
        HTTP_POST,
        ccf::json_adapter(remove_acme_response),
        ccf::no_auth_required)
        .set_auto_schema<RemoveACMEToken::In, RemoveACMEToken::Out>()
        .install();

      auto add = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<AddRecord::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.add(in.origin, in.record);
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
        ccf::no_auth_required)
        .set_auto_schema<AddRecord::In, AddRecord::Out>()
        .install();

      auto remove = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RemoveRecord::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.remove(in.origin, in.record);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/remove",
        HTTP_POST,
        ccf::json_adapter(remove),
        ccf::no_auth_required)
        .set_auto_schema<RemoveRecord::In, RemoveRecord::Out>()
        .install();

      auto remove_all = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RemoveAll::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.remove(
            in.origin,
            static_cast<aDNS::Class>(in.class_),
            static_cast<aDNS::Type>(in.type));
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/internal/remove_all",
        HTTP_POST,
        ccf::json_adapter(remove_all),
        ccf::no_auth_required)
        .set_auto_schema<RemoveAll::In, RemoveAll::Out>()
        .install();

      auto dns_query = [this](auto& ctx) {
        try
        {
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

          ccfdns.set_endpoint_context(ctx);
          auto reply = ccfdns.reply(Message(bytes));

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, "application/dns-message");
          std::vector<uint8_t> out = reply;
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
        .install();

      make_endpoint("/dns-query", HTTP_POST, dns_query, ccf::no_auth_required)
        .set_auto_schema<void, std::vector<uint8_t>>()
        .install();

      auto register_service = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RegisterService::In>();
          ccfdns.set_endpoint_context(ctx);

          // TODO: Save entire request including `in` in a special audit table.

          OpenSSL::UqX509_REQ req(in.csr, false);
          auto public_key = req.get_pubkey();
          auto public_key_pem = public_key.pem_pubkey();

          if (!req.verify(public_key))
            throw std::runtime_error("CSR signature validation failed");

          auto subject_name = req.get_subject_name().get_common_name();
          Name absolute_name(subject_name, std::vector<Label>{Label()});

          ccfdns.register_service(
            Name(in.origin),
            absolute_name,
            RFC1035::A(in.address),
            in.port,
            in.protocol,
            in.attestation,
            public_key_pem);

          if (ccfdns.have_acme_client(absolute_name))
            throw std::runtime_error("registration in process");

          CCF_APP_DEBUG("Set up ACME client for {}", subject_name);
          ACME::ClientConfig acme_client_config = {
            .ca_certs = acme_config.ca_certs,
            .directory_url = acme_config.directory_url,
            .service_dns_name =
              subject_name, // TODO: could be multiple names, including service
                            // name, get from CSR
            .contact = {},
            .terms_of_service_agreed = true,
            .challenge_type = "dns-01"};

          auto nwidss =
            this->context.get_subsystem<ccf::NetworkIdentitySubsystem>();
          acme_client_config.ca_certs.push_back(nwidss->get()->cert.str());

          auto acme_client = std::make_shared<ccfdns::ACMEClient>(
            ccfdns,
            in.origin,
            acme_client_config,
            in.csr,
            internal_node_address,
            acme_ss,
            acme_account_key_pair);

          acme_client->get_certificate(acme_account_key_pair);

          ccfdns.add_acme_client(absolute_name, acme_client);

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
        "/register",
        HTTP_POST,
        ccf::json_adapter(register_service),
        ccf::no_auth_required)
        .set_auto_schema<RegisterService::In, RegisterService::Out>()
        .install();

      auto set_certificate = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<SetCertificate::In>();
          ccfdns.set_endpoint_context(ctx);
          ccfdns.set_service_certificate(in.service_dns_name, in.certificate);
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
        ccf::no_auth_required)
        .set_auto_schema<SetCertificate::In, SetCertificate::Out>()
        .install();

      auto get_certificate = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<GetCertificate::In>();
          ccfdns.set_endpoint_context(ctx);
          GetCertificate::Out out;

          if (in.service_dns_name == ccfdns.get_configuration().name)
          {
            auto t = ctx.tx.template rw<ccf::ACMECertificates>(
              ccf::Tables::ACME_CERTIFICATES);
            if (!t)
              throw std::runtime_error("ACME service certificate table empty");
            auto v = t->get(acme_config_name);
            if (!v)
              throw std::runtime_error(
                "ACME service certificate not available");
            out.certificate = v->str();
          }
          else
            out.certificate =
              ccfdns.get_service_certificate(in.service_dns_name);
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
        .install();
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();

      acme_ss = context.get_subsystem<ccf::ACMESubsystemInterface>();

      // Get ACME config
      {
        auto interface_id = "acme_endorsed_interface";
        auto nci = context.get_subsystem<ccf::NodeConfigurationInterface>();
        auto ncs = nci->get();
        auto iit = ncs.node_config.network.rpc_interfaces.find(interface_id);
        if (iit == ncs.node_config.network.rpc_interfaces.end())
          CCF_APP_FAIL("Interface '{}' not found", interface_id);
        else
        {
          auto endo = iit->second.endorsement;
          if (
            endo->authority == ccf::Authority::ACME && endo->acme_configuration)
            acme_config_name = *endo->acme_configuration;
          if (acme_config_name.empty())
            CCF_APP_FAIL("Empty ACME configuration");
          acme_config = **acme_ss->config(acme_config_name);
        }
      }

      {
        // Interface for internal RPC calls
        auto interface_id = "primary_rpc_interface";
        auto nci = context.get_subsystem<ccf::NodeConfigurationInterface>();
        auto ncs = nci->get();
        auto iit = ncs.node_config.network.rpc_interfaces.find(interface_id);
        if (iit == ncs.node_config.network.rpc_interfaces.end())
          CCF_APP_FAIL("Interface '{}' not found", interface_id);
        else
          internal_node_address = iit->second.published_address;
      }
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    logger::config::level() = logger::TRACE;
    return std::make_unique<ccfdns::Handlers>(context);
  }
}
