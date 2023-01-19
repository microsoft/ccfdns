// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ravl/sgx.h"

#include <cstdint>
#include <ds/json.h>
#include <service/consensus_config.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "../ccfdns_rpc_types.h"

#include <ccf/_private/http/http_builder.h>
#include <ccf/_private/http/http_parser.h>
#include <ccf/_private/node/rpc/network_identity_subsystem.h>
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
    std::string name = "service43.adns.ccf.dev.";
    std::string ip = "51.143.161.224";
    uint16_t port = 443;
    std::string protocol = "tcp";

    std::optional<std::string> adns_base_url;
    std::optional<std::vector<std::string>> ca_certs;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration, name, ip, port, protocol);
  DECLARE_JSON_OPTIONAL_FIELDS(Configuration, adns_base_url, ca_certs);

  struct RegistrationInfo
  {
    // auto algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
    std::string public_key;
    std::string attestation;
    std::vector<uint8_t> csr;
  };

  DECLARE_JSON_TYPE(RegistrationInfo);
  DECLARE_JSON_REQUIRED_FIELDS(RegistrationInfo, public_key, attestation, csr);
}

using namespace ccfapp;

namespace service
{

  using TConfigurationTable = ccf::ServiceValue<Configuration>;
  std::string configuration_table_name = "public:service_config";

  struct ConfigurationRPC
  {
    using In = Configuration;
    using Out = RegistrationInfo;
  };

  class Handlers : public ccf::UserEndpointRegistry
  {
  protected:
    std::shared_ptr<ccf::ACMESubsystemInterface> acmess;
    std::shared_ptr<ccf::NetworkIdentitySubsystemInterface> niss;

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
          auto t =
            ctx.tx.template ro<TConfigurationTable>(configuration_table_name);
          auto opt_cfg = t->get();

          std::stringstream response;
          response << "<html>";
          if (!opt_cfg)
            response << "No service config.";
          else
            response << "This is <a href=\"https://" << opt_cfg->name << "\">"
                     << opt_cfg->name << "</a>";

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

      auto configure = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto in = params.get<ConfigurationRPC::In>();

          auto t =
            ctx.tx.template rw<TConfigurationTable>(configuration_table_name);
          t->put(in);

          ConfigurationRPC::Out out;

          auto public_key =
            crypto::public_key_pem_from_cert(acmess->network_cert().raw());

          out.public_key = public_key.str();

          ccf::pal::attestation_report_data ard = {0};
          ccf::pal::generate_quote(
            ard,
            [&out](
              const ccf::QuoteInfo& quote_info,
              const ccf::pal::snp::EndorsementEndpointsConfiguration&) {
              out.attestation = ravl::oe::Attestation(
                quote_info.quote, quote_info.endorsements);
            });

          if (!niss)
            throw std::runtime_error("No network identity subsystem");

          const auto& ni = niss->get();
          auto kp = make_key_pair(ni->priv_key);

          if (!kp)
            throw std::runtime_error("Invalid network key");

          auto n = in.name;
          while (n.back() == '.')
            n.pop_back();

          out.csr = kp->create_csr_der("CN=" + n, {{n, false}}, public_key);

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
        ccf::no_auth_required)
        .set_auto_schema<ConfigurationRPC::In, ConfigurationRPC::Out>()
        .install();
    }

    virtual void init_handlers() override
    {
      ccf::UserEndpointRegistry::init_handlers();
      acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
      niss = context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
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
