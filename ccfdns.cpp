// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "resolver.h"
#include "rfc1035.h"

#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/logger.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <ccf/version.h>
#include <charconv>
#include <ds/json.h>
#include <endpoint_context.h>
#include <nlohmann/json.hpp>
#include <optional>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace aDNS;
using namespace RFC1035;

namespace RFC1025
{
  DECLARE_JSON_TYPE(Name);
  DECLARE_JSON_REQUIRED_FIELDS(Name, labels)
}

namespace aDNS
{
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Zone::Record)
  DECLARE_JSON_REQUIRED_FIELDS(Zone::Record, name, type, data)
  DECLARE_JSON_OPTIONAL_FIELDS(Zone::Record, ttl, class_)

  DECLARE_JSON_TYPE(Zone)
  DECLARE_JSON_REQUIRED_FIELDS(Zone, records)
}

namespace ccfdns
{
  struct Update
  {
    struct In
    {
      std::string name;
      Zone zone;
    };
  };

  DECLARE_JSON_TYPE(Update::In)
  DECLARE_JSON_REQUIRED_FIELDS(Update::In, name, zone)

  struct ZoneRequest
  {
    struct Out
    {
      std::string name;
      Zone zone;
    };
  };

  DECLARE_JSON_TYPE(ZoneRequest::Out)
  DECLARE_JSON_REQUIRED_FIELDS(ZoneRequest::Out, name, zone)

  using ZoneMap = kv::Map<Name, Zone>;
  static constexpr auto ZONES = "zones";

  class CCFDNS : public Resolver
  {
  protected:
    ccf::endpoints::EndpointContext* ctx;

  public:
    CCFDNS() : Resolver() {}
    virtual ~CCFDNS() {}

    void set_endpoint_context(ccf::endpoints::EndpointContext* ctx)
    {
      this->ctx = ctx;
    }

    virtual void update(const Name& origin, const Zone& zone) override
    {
      auto tbl = ctx->tx.template rw<ZoneMap>(ZONES);
      tbl->put(origin, zone);

      Resolver::update(origin, zone);
    }

    virtual Zone zone(const Name& origin) override
    {
      auto tbl = ctx->tx.template ro<ZoneMap>(ZONES);
      auto z = tbl->get(origin);
      if (!z)
      {
        throw std::runtime_error("No such zone");
      }
      return *z;
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
      {
        throw ccf::make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format("Value '{}' missing.", name));
      }
      return r;
    }

  public:
    Handlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF DNS";
      openapi_info.description =
        "This CCF sample app implements a simple DNS over HTTPS server.";
      openapi_info.document_version = "0.0.0";

      auto update = [this](auto& ctx, nlohmann::json&& params) {
        const auto in = params.get<Update::In>();
        try
        {
          ccfdns.set_endpoint_context(&ctx);
          ccfdns.update(in.name, in.zone);
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/update", HTTP_POST, ccf::json_adapter(update), ccf::no_auth_required)
        .set_auto_schema<Update::In, void>()
        .install();

      auto zone = [this](auto& ctx) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());
        std::string name, error_reason;
        if (!http::get_query_value(parsed_query, "name", name, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            "Value 'name' missing.");
        }

        try
        {
          ccfdns.set_endpoint_context(&ctx);
          Zone z = ccfdns.zone(name);
          return ccf::make_success(ZoneRequest::Out{.name = name, .zone = z});
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint("/zone", HTTP_GET, zone, ccf::no_auth_required)
        .set_auto_schema<void, ZoneRequest::Out>()
        .install();

      auto dns_query = [this](auto& ctx) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());
        std::string p = get_param(parsed_query, "dns");
        auto bytes = crypto::raw_from_b64url(p);
        LOG_INFO_FMT("query: {}", ds::to_hex(bytes));

        try
        {
          ccfdns.set_endpoint_context(&ctx);
          auto reply = ccfdns.reply(Message(bytes));

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, "application/dns-query");
          std::vector<uint8_t> out = reply;
          LOG_INFO_FMT("response: {}", ds::to_hex(out));

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
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    logger::config::level() = logger::MOST_VERBOSE;
    return std::make_unique<ccfdns::Handlers>(context);
  }
}
