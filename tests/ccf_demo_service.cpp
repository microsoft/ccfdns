// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ravl/sgx.h"

#include <cstdint>
#include <ds/json.h>
#include <llhttp/llhttp.h>
#include <service/consensus_config.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "../ccfdns_rpc_types.h"

#include <ccf/_private/ds/thread_messaging.h>
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
#include <chrono>
#include <ravl/oe.h>
#include <ravl/ravl.h>
#include <stdexcept>

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
    std::string name;
    std::string ip;
    uint16_t port;

    std::string adns_base_url;
    std::vector<std::string> ca_certs;
  };

  DECLARE_JSON_TYPE(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(
    Configuration, name, ip, port, adns_base_url, ca_certs);

  struct RegistrationInfo
  {
    std::string protocol;
    std::string public_key;
    std::string attestation;
    std::vector<uint8_t> csr;
  };

  DECLARE_JSON_TYPE(RegistrationInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegistrationInfo, protocol, public_key, attestation, csr);

  std::string service_cert;
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
    Configuration configuration;

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

          configuration.name = in.name;
          configuration.ip = in.ip;
          configuration.port = in.port;
          configuration.adns_base_url = in.adns_base_url;
          configuration.ca_certs = in.ca_certs;

          ConfigurationRPC::Out out;

          out.protocol = "tcp";

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

          auto sn = in.name;
          while (sn.back() == '.')
            sn.pop_back();

          out.csr = kp->create_csr_der("CN=" + sn, {{sn, false}}, public_key);

          auto unterminated_name = configuration.name;
          while (unterminated_name.size() > 0 &&
                 unterminated_name.back() == '.')
            unterminated_name.pop_back();

          std::string body =
            "{\"service_dns_name\": \"" + unterminated_name + "\"}";
          std::vector<uint8_t> vbody(body.begin(), body.end());
          std::vector<std::string> ca_certs;

          struct CertThreadMsg
          {
            CertThreadMsg(
              std::shared_ptr<ccf::ACMESubsystemInterface> acmess,
              const std::string& adns_base_url,
              const std::vector<uint8_t>& body,
              const std::vector<std::string>& ca_certs) :
              acmess(acmess),
              adns_base_url(adns_base_url),
              body(body),
              ca_certs(ca_certs)
            {}

            std::shared_ptr<ccf::ACMESubsystemInterface> acmess;
            std::string adns_base_url;
            std::vector<uint8_t> body;
            std::vector<std::string> ca_certs;
          };

          auto msg = std::make_unique<threading::Tmsg<CertThreadMsg>>(
            [](std::unique_ptr<threading::Tmsg<CertThreadMsg>> msg) {
              if (!service_cert.empty())
                return;

              msg->data.acmess->make_http_request(
                "POST",
                msg->data.adns_base_url + "/app/get-certificate",
                {{"content-type", "application/json"}},
                msg->data.body,
                [](
                  const http_status& status,
                  const http::HeaderMap&,
                  const std::vector<uint8_t>& body) {
                  CCF_APP_DEBUG("CALLBACK: status={}", status);
                  if (status == HTTP_STATUS_OK)
                  {
                    auto j = nlohmann::json::parse(body);
                    service_cert = j["certificate"].get<std::string>();
                    CCF_APP_DEBUG("SERVICE CERTIFICATE: {}", service_cert);
                  }
                  return true;
                },
                msg->data.ca_certs);

              threading::ThreadMessaging::thread_messaging.add_task_after(
                std::move(msg), std::chrono::seconds(1));
            },
            acmess,
            configuration.adns_base_url,
            vbody,
            configuration.ca_certs);

          threading::ThreadMessaging::thread_messaging.add_task_after(
            std::move(msg), std::chrono::seconds(1));

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
