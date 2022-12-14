// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccfdns_rpc_types.h"
#include "formatting.h"
#include "keys.h"
#include "resolver.h"
#include "rfc1035.h"
#include "rfc4034.h"

#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <ccf/version.h>
#include <charconv>
#include <endpoint_context.h>
#include <nlohmann/json.hpp>
#include <odata_error.h>
#include <optional>
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
  class CCFDNS : public Resolver
  {
  public:
    CCFDNS() : Resolver() {}
    virtual ~CCFDNS() {}

    using Records = ccf::ServiceSet<ResourceRecord>;
    using Origins = ccf::ServiceSet<RFC1035::Name>;
    std::string origins_table_name = "public:origins";

    void set_endpoint_context(ccf::endpoints::EndpointContext& ctx)
    {
      this->ctx = &ctx;
    }

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      CCF_APP_DEBUG("CCFDNS: Add: {}", string_from_resource_record(rr));

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("Origin not absolute");
      }

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
        throw std::runtime_error("Origin not absolute");
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
        "Remove {} type {} at {}", name, string_from_type(t), origin);

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("Origin not absolute");
      }

      Name aname = name;
      if (!aname.is_absolute())
        aname += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, c, t));
      if (records)
      {
        records->foreach(
          [origin, t, &aname, &records](const ResourceRecord& rr) {
            if (rr.type == static_cast<uint16_t>(t) && rr.name == aname)
            {
              CCF_APP_TRACE(
                "CCFDNS:  remove {}", string_from_resource_record(rr));
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
        throw std::runtime_error("Origin not absolute");
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

  protected:
    ccf::endpoints::EndpointContext* ctx;

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

  public:
    Handlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF aDNS";
      openapi_info.description =
        "This application implements an attested DNS-over-HTTPS server.";
      openapi_info.document_version = "0.0.0";

      auto add = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<AddRecord::In>();
          ccfdns.set_endpoint_context(ctx);

          // if policy checks pass...
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
        "/add", HTTP_POST, ccf::json_adapter(add), ccf::no_auth_required)
        .set_auto_schema<AddRecord::In, AddRecord::Out>()
        .install();

      auto remove = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RemoveRecord::In>();
          ccfdns.set_endpoint_context(ctx);

          // if policy checks pass...
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
        "/remove", HTTP_POST, ccf::json_adapter(remove), ccf::no_auth_required)
        .set_auto_schema<RemoveRecord::In, RemoveRecord::Out>()
        .install();

      auto remove_all = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<RemoveAll::In>();
          ccfdns.set_endpoint_context(ctx);

          // if policy checks pass...
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
        "/remove_all",
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

          ccfdns.register_service(
            Name(in.origin),
            Name(in.name),
            RFC1035::A(in.address),
            in.port,
            in.protocol,
            in.attestation,
            in.algorithm,
            in.public_key);

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
