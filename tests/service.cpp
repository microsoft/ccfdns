// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/ds/logger.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <stdexcept>
#include <thread>

namespace service
{
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
      openapi_info.title = "Attested Test Service";
      openapi_info.description =
        "This application is a test service, attested via aDNS.";
      openapi_info.document_version = "0.0.0";

      auto poke = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          return ccf::make_success();
        }
        catch (std::exception& ex)
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

      make_endpoint(
        "/poke", HTTP_POST, ccf::json_adapter(poke), ccf::no_auth_required)
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
    return std::make_unique<service::Handlers>(context);
  }
}
