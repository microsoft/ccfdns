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
#include <odata_error.h>
#include <optional>
#include <stdexcept>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace aDNS;
using namespace RFC1035;

#define DECLARE_JSON_STRINGIFIED(TYPE, PATTERN) \
  inline void to_json(nlohmann::json& j, const TYPE& t) \
  { \
    j = nlohmann::json::string_t(t); \
  } \
  inline void from_json(const nlohmann::json& j, TYPE& t) \
  { \
    if (!j.is_string()) \
    { \
      throw JsonParseError(fmt::format( \
        "Cannot parse " #TYPE ": expected string, got {}", j.dump())); \
    } \
    t = TYPE(j.get<std::string>()); \
  } \
  inline std::string schema_name(const TYPE*) \
  { \
    return #TYPE; \
  } \
  inline void fill_json_schema(nlohmann::json& schema, const TYPE*) \
  { \
    schema["type"] = "string"; \
    schema["pattern"] = PATTERN; \
  }

inline void to_json(nlohmann::json& j, const small_vector<uint16_t>& t)
{
  j = t.to_base64();
}

inline void from_json(const nlohmann::json& j, small_vector<uint16_t>& t)
{
  if (!j.is_string())
  {
    throw JsonParseError(fmt::format(
      "Cannot parse small_vector<uint16_t>: expected base64-encoded string, "
      "got {}",
      j.dump()));
  }
  t = small_vector<uint16_t>::from_base64(j.get<std::string>());
}

inline std::string schema_name(const small_vector<uint16_t>*)
{
  return "small_vector<uint16_t>";
}

inline void fill_json_schema(
  nlohmann::json& schema, const small_vector<uint16_t>*)
{
  schema["type"] = "small_vector<uint16_t>";
}

namespace RFC1035
{
  DECLARE_JSON_ENUM(aDNS::Type, {{aDNS::Type::A, "A"}});
  DECLARE_JSON_STRINGIFIED(Name, "^[A-Za-z0-9]+(\\.[A-Za-z0-9]+)+$");

  DECLARE_JSON_TYPE(ResourceRecord);
  DECLARE_JSON_REQUIRED_FIELDS(ResourceRecord, name, type, class_, ttl, rdata);
}

namespace kv::serialisers
{
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
  struct AddRecord
  {
    struct In
    {
      Name origin;
      ResourceRecord record;
    };
  };

  DECLARE_JSON_TYPE(AddRecord::In)
  DECLARE_JSON_REQUIRED_FIELDS(AddRecord::In, origin, record)

  class CCFDNS : public Resolver
  {
  public:
    CCFDNS() : Resolver() {}
    virtual ~CCFDNS() {}

    using Records = ccf::ServiceSet<ResourceRecord>;

    void set_endpoint_context(ccf::endpoints::EndpointContext& ctx)
    {
      this->ctx = &ctx;
    }

    virtual void add(const Name& origin, const ResourceRecord& rr) override
    {
      LOG_DEBUG_FMT("Add: {}", string_from_resource_record(rr));

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("Origin not absolute");
      }

      nlohmann::json rj;
      to_json(rj, rr);
      LOG_DEBUG_FMT("Add: {}: {}", (std::string)origin, rj.dump());

      auto t = static_cast<aDNS::Type>(rr.type);

      LOG_TRACE_FMT(
        "Add {} type {} to {}",
        (std::string)rr.name,
        string_from_type(t),
        (std::string)origin);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, t));
      records->insert(rs);

      Resolver::on_add(origin, rs);
    }

    virtual void remove(const Name& origin, const ResourceRecord& rr)
    {
      LOG_DEBUG_FMT("Remove: {}", string_from_resource_record(rr));

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("Origin not absolute");
      }

      auto t = static_cast<aDNS::Type>(rr.type);

      LOG_TRACE_FMT(
        "Remove {} type {} at {}",
        (std::string)rr.name,
        string_from_type(t),
        (std::string)origin);

      ResourceRecord rs(rr);

      if (!rs.name.is_absolute())
        rs.name += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, t));
      records->remove(rs);
    }

    virtual void remove(
      const Name& origin, const Name& name, const aDNS::Type& t) override
    {
      LOG_DEBUG_FMT(
        "Remove {} type {} at {}",
        (std::string)name,
        string_from_type(t),
        (std::string)origin);

      if (!ctx)
        std::runtime_error("missing endpoint context");

      if (!origin.is_absolute())
      {
        throw std::runtime_error("Origin not absolute");
      }

      Name aname = name;
      if (!aname.is_absolute())
        aname += origin;

      auto records = ctx->tx.rw<Records>(table_name(origin, t));
      records->foreach([origin, t, &aname, &records](const ResourceRecord& rr) {
        if (rr.type == static_cast<uint16_t>(t) && rr.name == aname)
        {
          LOG_TRACE_FMT(" remove {}", string_from_resource_record(rr));
          records->remove(rr);
        }
        return true;
      });
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

      std::string tn = table_name(origin, static_cast<aDNS::Type>(qtype));

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

  protected:
    ccf::endpoints::EndpointContext* ctx;

    std::string table_name(const Name& origin, aDNS::Type type) const
    {
      return (std::string)origin.lowered() + "-" + string_from_type(type);
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
        "This CCF sample app implements a simple DNS-over-HTTPS server.";
      openapi_info.document_version = "0.0.0";

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
        "/add", HTTP_POST, ccf::json_adapter(add), ccf::no_auth_required)
        .set_auto_schema<AddRecord::In, void>()
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
          LOG_INFO_FMT("query: {}", ds::to_hex(bytes));

          ccfdns.set_endpoint_context(ctx);
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

      make_endpoint("/dns-query", HTTP_POST, dns_query, ccf::no_auth_required)
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
    logger::config::level() = logger::TRACE;
    return std::make_unique<ccfdns::Handlers>(context);
  }
}
