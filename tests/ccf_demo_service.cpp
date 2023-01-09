// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <cstdint>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "../ccfdns_rpc_types.h"
#include "adns_acme_challenge_handler.h"

#include <ccf/_private/http/http_builder.h>
#include <ccf/_private/http/http_parser.h>
#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/verifier.h>
#include <ccf/ds/logger.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/node/node_configuration_interface.h>
#include <ccf/pal/attestation.h>
#include <ravl/oe.h>
#include <ravl/ravl.h>
#include <stdexcept>
#include <thread>

namespace ravl
{
  HTTPResponse SynchronousHTTPClient::execute_synchronous(
    const HTTPRequest&, size_t, size_t, bool)
  {
    throw std::runtime_error("fresh endorsement download not supported");
  }
}

namespace ccfapp
{
  struct Configuration
  {
    std::string interface_id = "endorsed_interface";
    std::string adns_base_url = "https://adns.ccf.dev:8080/app";
    std::string origin = "adns.ccf.dev.";
    std::string service_name = "service43.adns.ccf.dev.";
    std::string ip = "51.143.161.224";
    uint16_t default_port = 443;
  } configuration;

  std::vector<std::string> ca_certs;

  void register_service(
    ccfapp::AbstractNodeContext& context,
    const std::string& protocol,
    uint16_t port)
  {
    CCF_APP_DEBUG("DEMO: submitting app registration");

    auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
    auto public_key_pem =
      crypto::public_key_pem_from_cert(acmess->network_cert().raw());

    ccfdns::RegisterService::In regopts;
    regopts.origin = configuration.origin;
    regopts.name = configuration.service_name;
    regopts.address = configuration.ip;
    regopts.protocol = protocol;
    regopts.port = port;
    regopts.algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
    regopts.public_key = public_key_pem;

    ccf::pal::attestation_report_data ard = {0};
    ccf::pal::generate_quote(
      ard,
      [&regopts](
        const ccf::QuoteInfo& quote_info,
        const ccf::pal::snp::EndorsementEndpointsConfiguration&) {
        regopts.attestation =
          ravl::oe::Attestation(quote_info.quote, quote_info.endorsements);
      });

    nlohmann::json jbody = regopts;
    auto body = serdes::pack(jbody, serdes::Pack::Text);

    acmess->make_http_request(
      "POST",
      configuration.adns_base_url + "/register",
      {{"content-type", "application/json"}},
      body,
      [](
        const enum http_status& http_status,
        const http::HeaderMap& headers,
        const std::vector<uint8_t>& reply_body) {
        if (
          http_status != HTTP_STATUS_OK &&
          http_status != HTTP_STATUS_NO_CONTENT)
        {
          std::string tmp = {
            reply_body.data(), reply_body.data() + reply_body.size()};
          CCF_APP_DEBUG(
            "DEMO: app registration failed with status={} and "
            "body={}",
            http_status,
            tmp);
          return false;
        }
        CCF_APP_TRACE("DEMO: App registered (status={})", http_status);
        return true;
      },
      ca_certs);
  }
}

namespace service
{
  class Handlers : public ccf::UserEndpointRegistry
  {
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

      auto index = [this](auto& ctx) {
        try
        {
          std::stringstream response;
          response << "<html>";
          response << "This is <a href=\"https://"
                   << ccfapp::configuration.service_name << "\">"
                   << ccfapp::configuration.service_name << "</a>";
          response << "</html>";
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(response.str());
        }
        catch (std::exception& ex)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx.rpc_ctx->set_response_body(ex.what());
        }
      };

      make_endpoint("/", HTTP_GET, index, ccf::no_auth_required).install();
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();

      auto interface_id = ccfapp::configuration.interface_id;
      auto nci = context.get_subsystem<ccf::NodeConfigurationInterface>();
      auto ncs = nci->get();
      auto iit = ncs.node_config.network.rpc_interfaces.find(interface_id);
      if (iit == ncs.node_config.network.rpc_interfaces.end())
        CCF_APP_FAIL(
          "Interface '{}' not found; cannot register service", interface_id);
      else
      {
        std::string acme_config_name;
        auto endo = iit->second.endorsement;
        if (endo->authority == ccf::Authority::ACME && endo->acme_configuration)
          acme_config_name = *endo->acme_configuration;
        if (acme_config_name.empty())
          CCF_APP_FAIL("Empty ACME configuration; cannot register service");

        auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
        const auto& acmecfg = acmess->config(acme_config_name);
        if (acmecfg)
          ccfapp::ca_certs = (*acmecfg)->ca_certs;

        acmess->install_challenge_handler(
          ccfapp::configuration.interface_id,
          std::make_shared<ccfapp::ADNSChallengeHandler>(
            context,
            ccfapp::configuration.adns_base_url,
            ccfapp::configuration.origin,
            ccfapp::configuration.service_name,
            ccfapp::ca_certs));

        auto protocol = iit->second.protocol;
        if (protocol.empty())
          protocol = "tcp";
        uint16_t port = ccfapp::configuration.default_port;
        const auto& address = iit->second.bind_address;
        auto cpos = address.find(':');
        if (cpos != std::string::npos)
          port = atoi(&address[cpos + 1]);
        ccfapp::register_service(context, protocol, port);
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

    auto endpoint_registry = std::make_unique<service::Handlers>(context);

    return endpoint_registry;
  }
}
