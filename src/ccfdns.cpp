// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "attestation.h"
#include "ccfdns_json.h"
#include "ccfdns_rpc_types.h"
#include "cose.h"
#include "didx509cpp/didx509cpp.h"
#include "formatting.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <arpa/inet.h>
#include <ccf/_private/tcp/msg_types.h>
#include <ccf/_private/udp/msg_types.h>
#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/cose_verifier.h>
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
#include <ccf/node/node_configuration_interface.h>
#include <ccf/pal/attestation.h>
#include <ccf/research/custom_protocol_subsystem_interface.h>
#include <ccf/service/node_info.h>
#include <ccf/service/tables/nodes.h>
#include <ccf/tx.h>
#include <ccf/tx_id.h>
#include <ccf/version.h>
#include <llhttp/llhttp.h>
#include <memory>
#include <mutex>
#include <optional>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <regex>
#include <rego/rego.hh>
#include <stdexcept>

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

namespace
{
  void verify_against_service_registration_policy(
    std::string_view policy, ccf::pal::UVMEndorsements& uvm_descriptor)
  {
    nlohmann::json rego_input;
    rego_input["iss"] = uvm_descriptor.did;
    rego_input["sub"] = uvm_descriptor.feed;
    rego_input["svn"] = std::stoi(uvm_descriptor.svn);

    rego::Interpreter interpreter(true /* v1 compatible */);
    auto rv = interpreter.add_module("policy", std::string(policy));

    auto tv = interpreter.set_input_term(rego_input.dump());
    if (tv != nullptr)
    {
      throw std::runtime_error(
        fmt::format("Invalid policy input: {}", rego_input.dump()));
    }

    auto qv = interpreter.query("data.policy.allow");

    if (qv == "{\"expressions\":[true]}")
    {
      return;
    }
    else if (qv == "{\"expressions\":[false]}")
    {
      throw std::runtime_error(
        fmt::format("Policy not satisfied: {}", rego_input.dump()));
    }
    else
    {
      throw std::runtime_error(
        fmt::format("Error while applying policy: {}", qv));
    }
  }

  void verify_against_platform_registration_policy(
    std::string_view policy, ccf::pal::UVMEndorsements& uvm_descriptor)
  {
    // Currently reuse service relying party logic, because input is the same.
    verify_against_service_registration_policy(policy, uvm_descriptor);
  }

  void verify_against_auth_policy(
    std::string_view policy, const std::string& verified_did)
  {
    CCF_APP_INFO("Verifying DID {} against policy {}", verified_did, policy);

    nlohmann::json rego_input;
    rego_input["iss"] = verified_did;

    rego::Interpreter interpreter(true /* v1 compatible */);
    auto rv = interpreter.add_module("policy", std::string(policy));

    auto tv = interpreter.set_input_term(rego_input.dump());
    if (tv != nullptr)
    {
      throw std::runtime_error(
        fmt::format("Invalid policy input: {}", rego_input.dump()));
    }

    auto qv = interpreter.query("data.policy.allow");

    if (qv == "{\"expressions\":[true]}")
    {
      return;
    }
    else if (qv == "{\"expressions\":[false]}")
    {
      throw std::runtime_error(
        fmt::format("Policy not satisfied: {}", rego_input.dump()));
    }
    else
    {
      throw std::runtime_error(
        fmt::format("Error while applying policy: {}", qv));
    }
  }

  std::string get_verified_did(const cose::CoseRequest& as_cose)
  {
    std::string pem_chain;
    for (auto const& c : as_cose.protected_header.x5chain)
    {
      pem_chain += ccf::crypto::cert_der_to_pem(c).str();
    }

    auto did_document_str = didx509::resolve(
      pem_chain,
      as_cose.protected_header.cwt.iss,
      true /* Do not validate time */);

    CCF_APP_INFO("Resolved DID document: {}", did_document_str);

    auto as_json = nlohmann::json::parse(did_document_str);
    return as_json["verificationMethod"][0]["controller"];
  }

  cose::CoseRequest get_verified_cose(const std::vector<uint8_t>& body)
  {
    auto as_cose = cose::decode_cose_request(body);
    const auto& x5chain = as_cose.protected_header.x5chain;
    if (x5chain.empty())
    {
      throw std::runtime_error("expected a valid x5chain entry, got empty one");
    }

    auto cose_verifier = ccf::crypto::make_cose_verifier_from_cert(x5chain[0]);
    std::span<uint8_t> authned_content{};
    cose_verifier->verify(body, authned_content);

    return as_cose;
  }
}

namespace ccfdns
{
  class CCFDNS : public Resolver
  {
  public:
    CCFDNS(std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss) :
      Resolver(),
      cp_ss(cp_ss)
    {}

    virtual ~CCFDNS() {}

    std::string my_name; // Certifiable FQDN for this node of the DNS service

    using TConfigurationTable =
      ccf::ServiceValue<aDNS::Resolver::Configuration>;
    const std::string configuration_table_name =
      "public:ccf.gov.ccfdns.adns_configuration";

    using TTimeTable = ccf::ServiceValue<uint32_t>;
    const std::string time_table_name = "public:ccfdns.time";

    using Names = ccf::ServiceSet<Name>;

    using Records = ccf::ServiceSet<ResourceRecord>;
    using Origins = ccf::ServiceSet<Name>;
    const std::string origins_table_name = "public:ccfdns.origins";

    using ServiceCertificates = ccf::ServiceMap<std::string, std::string>;
    const std::string service_certificates_table_name =
      "public:service_certificates";

    using ServiceDefinitionAuth = ccf::ServiceValue<std::string>;
    const std::string service_definition_auth_table_name =
      "public:ccf.gov.ccfdns.service_definition_auth";

    using ServiceDefinition = ccf::ServiceMap<std::string, std::string>;
    const std::string service_definition_table_name =
      "public:ccf.gov.ccfdns.service_definition";

    using PlatformDefinitionAuth = ccf::ServiceValue<std::string>;
    const std::string platform_definition_auth_table_name =
      "public:ccf.gov.ccfdns.platform_definition_auth";

    using PlatformDefinition = ccf::ServiceMap<std::string, std::string>;
    const std::string platform_definition_table_name =
      "public:ccf.gov.ccfdns.platform_definition";

    using RegistrationRequests = ccf::ServiceMap<Name, std::vector<uint8_t>>;
    const std::string registration_requests_table_name =
      "public:service_registration_requests";

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

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      check_context();
      if (
        rr.type !=
        static_cast<uint16_t>(RFC3596::Type::AAAA)) // skip
                                                    // AAAA-fragmented
                                                    // payloads

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
    };

    virtual ccf::crypto::Pem get_private_key(
      const Name& origin,
      uint16_t tag,
      const small_vector<uint16_t>& public_key,
      bool key_signing) override
    {
      check_context();

      auto origin_lowered = origin.lowered();

      auto table = key_signing ?
        rotx().ro<PrivateDNSKey>(key_signing_key_table) :
        rotx().ro<PrivateDNSKey>(zone_signing_key_table);
      if (!table)
        return {};

      auto value = table->get(origin_lowered);
      if (value)
      {
        auto kp = ccf::crypto::make_key_pair(value->key);
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
            return value->key;
        }
      }

      throw std::runtime_error(fmt::format(
        "private {} signing key not found", key_signing ? "key" : "zone"));
    }

    virtual void on_new_signing_key(
      const Name& origin,
      uint16_t tag,
      const ccf::crypto::KeyPairPtr& kp,
      bool key_signing) override
    {
      check_context();
      auto pem = kp->private_key_pem();

      auto origin_lowered = origin.lowered();
      auto table = key_signing ?
        rwtx().rw<PrivateDNSKey>(key_signing_key_table) :
        rwtx().rw<PrivateDNSKey>(zone_signing_key_table);
      if (!table)
        throw std::runtime_error("could not get keys table");

      table->put(origin_lowered, KeyInfo{tag, pem});
      if (key_signing)
      {
        ctx->rpc_ctx->set_claims_digest(
          ccf::ClaimsDigest::Digest(kp->public_key_der()));
      }
    }

    virtual std::string service_definition_auth() const override
    {
      check_context();

      auto policy_table =
        rotx().ro<ServiceDefinitionAuth>(service_definition_auth_table_name);
      const std::optional<std::string> policy = policy_table->get();
      if (!policy)
        throw std::runtime_error("no service definition auth");
      return *policy;
    }

    virtual void set_service_definition_auth(
      const std::string& new_policy) override
    {
      check_context();

      auto policy =
        rwtx().rw<ServiceDefinitionAuth>(service_definition_auth_table_name);

      if (!policy)
        throw std::runtime_error(
          "error accessing service definition auth table");

      policy->put(new_policy);
    }

    virtual std::string service_definition(
      const std::string& service_name) const override
    {
      check_context();

      auto policy_table =
        rotx().ro<ServiceDefinition>(service_definition_table_name);
      const std::optional<std::string> policy = policy_table->get(service_name);
      if (!policy)
        throw std::runtime_error("no service definition");
      return *policy;
    }

    virtual void set_service_definition(
      const std::string& service_name, const std::string& new_policy) override
    {
      check_context();

      auto policy = rwtx().rw<ServiceDefinition>(service_definition_table_name);

      if (!policy)
        throw std::runtime_error("error accessing service definition table");

      policy->put(service_name, new_policy);
    }

    virtual std::string platform_definition_auth() const override
    {
      check_context();

      auto policy_table =
        rotx().ro<PlatformDefinitionAuth>(platform_definition_auth_table_name);
      const std::optional<std::string> policy = policy_table->get();
      if (!policy)
        throw std::runtime_error("no platform defintion auth policy");
      return *policy;
    }

    virtual void set_platform_definition_auth(
      const std::string& new_policy) override
    {
      check_context();

      auto policy =
        rwtx().rw<PlatformDefinitionAuth>(platform_definition_auth_table_name);

      if (!policy)
        throw std::runtime_error(
          "error accessing platform definition auth table");

      policy->put(new_policy);
    }

    virtual std::string platform_definition(
      const std::string& platform) const override
    {
      check_context();

      auto policy_table =
        rotx().ro<PlatformDefinition>(platform_definition_table_name);
      const std::optional<std::string> policy = policy_table->get(platform);
      if (!policy)
        throw std::runtime_error("no platform definition");

      return *policy;
    }

    virtual void set_platform_definition(
      const std::string& platform, const std::string& new_policy) override
    {
      check_context();

      auto policy =
        rwtx().rw<PlatformDefinition>(platform_definition_table_name);

      if (!policy)
        throw std::runtime_error("error accessing platform definition table");

      policy->put(platform, new_policy);
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

        // Not implemented
        auto attestation = "";

        r[id] = {
          .address = addr,
          .attestation = attestation,
          .attestation_type = ccf::QuoteFormat::amd_sev_snp_v1};
      }

      return r;
    }

    virtual void configure() override
    {
      check_context();

      Resolver::configure();
    }

    virtual void save_service_registration_request(
      const Name& name, const std::vector<uint8_t>& rr) override
    {
      check_context();

      auto rrtbl = rwtx().template rw<CCFDNS::RegistrationRequests>(
        registration_requests_table_name);
      if (!rrtbl)
        throw std::runtime_error(
          "could not access service registration request table");

      rrtbl->put(name, rr);
    }

  protected:
    ccf::endpoints::CommandEndpointContext* ctx = nullptr;
    bool ctx_writable = false;
    std::mutex reply_mtx;

    std::shared_ptr<ccf::CustomProtocolSubsystemInterface> cp_ss;

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

      auto cp_ss =
        context.get_subsystem<ccf::CustomProtocolSubsystemInterface>();

      ccfdns = std::make_shared<CCFDNS>(cp_ss);

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      auto configure = [this](auto& ctx) {
        CCF_APP_TRACE("CCFDNS: call /configure");
        try
        {
          ContextContext cc(ccfdns, ctx);
          ccfdns->configure();
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint("/configure", HTTP_POST, configure, ccf::no_auth_required)
        .set_auto_schema<void, void>()
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

      auto register_service = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto& body = ctx.rpc_ctx->get_request_body();
          ccfdns->register_service(body);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/register-service", HTTP_POST, register_service, ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto set_service_definition = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto& body = ctx.rpc_ctx->get_request_body();

          auto as_cose = cose::decode_cose_request(body);
          auto did = get_verified_did(as_cose);
          auto policy = ccfdns->service_definition_auth();

          verify_against_auth_policy(policy, did);

          const auto& service_name = as_cose.protected_header.cwt.sub;
          if (service_name.empty())
          {
            throw std::runtime_error("Missing service name (sub)");
          }

          auto new_policy =
            std::string(as_cose.payload.begin(), as_cose.payload.end());
          CCF_APP_INFO("New policy is: {}", new_policy);

          ccfdns->set_service_definition(service_name, new_policy);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/set-service-definition",
        HTTP_POST,
        set_service_definition,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto set_platform_definition = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto& body = ctx.rpc_ctx->get_request_body();

          auto as_cose = cose::decode_cose_request(body);
          auto did = get_verified_did(as_cose);
          auto policy = ccfdns->platform_definition_auth();

          verify_against_auth_policy(policy, did);

          auto new_policy =
            std::string(as_cose.payload.begin(), as_cose.payload.end());
          CCF_APP_INFO("New policy is: {}", new_policy);

          const auto& platform = as_cose.protected_header.cwt.sub;
          if (platform.empty())
          {
            throw std::runtime_error("Missing platform name (sub)");
          }

          ccfdns->set_platform_definition(platform, new_policy);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/set-platform-definition",
        HTTP_POST,
        set_platform_definition,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto set_service_definition_auth = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto& body = ctx.rpc_ctx->get_request_body();

          auto as_cose = cose::decode_cose_request(body);
          auto did = get_verified_did(as_cose);
          auto policy = ccfdns->service_definition_auth();

          verify_against_auth_policy(policy, did);

          auto new_policy =
            std::string(as_cose.payload.begin(), as_cose.payload.end());
          CCF_APP_INFO("New policy is: {}", new_policy);

          ccfdns->set_service_definition_auth(new_policy);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/set-service-definition-auth",
        HTTP_POST,
        set_service_definition_auth,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto set_platform_definition_auth = [this](auto& ctx) {
        try
        {
          ContextContext cc(ccfdns, ctx);
          const auto& body = ctx.rpc_ctx->get_request_body();

          auto as_cose = cose::decode_cose_request(body);
          auto did = get_verified_did(as_cose);
          auto policy = ccfdns->platform_definition_auth();

          verify_against_auth_policy(policy, did);

          auto new_policy =
            std::string(as_cose.payload.begin(), as_cose.payload.end());
          CCF_APP_INFO("New policy is: {}", new_policy);

          ccfdns->set_platform_definition_auth(new_policy);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
      };

      make_endpoint(
        "/set-platform-definition-auth",
        HTTP_POST,
        set_platform_definition_auth,
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();

      auto ksk_txid_extractor =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx)
        -> std::optional<ccf::TxID> {
        auto tbl = ctx.tx.ro<PrivateDNSKey>(key_signing_key_table);
        if (!tbl)
          throw std::runtime_error("KSK table not found");

        auto req = ctx.rpc_ctx->get_request_body();
        nlohmann::json j = nlohmann::json::parse(req);

        auto zone = j.value("zone", "");
        auto version = tbl->get_version_of_previous_write(RFC1035::Name(zone));

        if (!version || *version == ccf::kv::NoVersion)
          return std::nullopt;

        ccf::View view;
        if (get_view_for_seqno_v1(*version, view) != ccf::ApiResult::OK)
          return std::nullopt;

        return ccf::TxID{.view = view, .seqno = *version};
      };

      auto get_ksk_receipt = [this](
                               ccf::endpoints::ReadOnlyEndpointContext& ctx,
                               ccf::historical::StatePtr historical_state) {
        try
        {
          auto historical_tx = historical_state->store->create_read_only_tx();
          auto receipt = ccf::describe_receipt_v1(*historical_state->receipt);
          ctx.rpc_ctx->set_response_body(receipt.dump());
        }
        catch (const std::exception& ex)
        {
          ctx.rpc_ctx->set_response_body(ex.what());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
        }
      };

      make_read_only_endpoint(
        "/ksk-receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_ksk_receipt, context, is_tx_committed, ksk_txid_extractor),
        ccf::no_auth_required)
        .set_auto_schema<std::string, std::string>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();

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
