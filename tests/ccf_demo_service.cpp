// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "../ccfdns_rpc_types.h"

#include <ccf/_private/http/http_builder.h>
#include <ccf/_private/http/http_parser.h>
#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/ds/logger.h>
#include <ccf/http_query.h>
#include <ccf/http_status.h>
#include <ccf/json_handler.h>
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/serdes.h>
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

    struct Opts
    {
      std::string interface_id = "endorsed_interface";
      std::string config_name = "my_acme_config";
      std::string adns_base_url = "https://adns.ccf.dev:8000/app";
      std::string origin = "adns.ccf.dev.";
      std::string service_name = "service43.adns.ccf.dev.";
      std::string ip = "51.143.161.224";
    } opts;

    auto endpoint_registry = std::make_unique<service::Handlers>(context);

    auto acme_subsystem = context.get_subsystem<ccf::ACMESubsystemInterface>();
    if (acme_subsystem)
    {
      volatile bool keep_waiting = true;

      acme_subsystem->install_challenge_handler(
        opts.interface_id,
        [context, opts](const std::string& token, const std::string& response) {
          CCF_APP_DEBUG("DO SOMETHING ABOUT IT");

          auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
          std::vector<std::string> ca_certs = {};
          const auto& acme_cfgs = acmess->configurations();
          const auto& acmecfgit = acme_cfgs.find(opts.config_name);
          if (acmecfgit != acme_cfgs.end())
          {
            ca_certs = acmecfgit->second.ca_certs;
          }

          http::HeaderMap headers = {{"content-type", "application/json"}};

          ccfdns::RegisterService::In regopts;
          regopts.origin = opts.origin;
          regopts.name = opts.service_name;
          regopts.address = opts.ip;
          regopts.algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
          regopts.public_key = acmess->get_public_key();
          regopts.attestation = QVL::get_oe_attestation(
            crypto::make_public_key(regopts.public_key)->public_key_der());

          nlohmann::json jbody = regopts;
          auto body = serdes::pack(jbody, serdes::Pack::Text);

          acmess->make_http_request(
            "POST",
            opts.adns_base_url + "/register",
            headers,
            body,
            [context, opts, ca_certs, response](
              const enum http_status& http_status,
              const http::HeaderMap& headers,
              const std::vector<uint8_t>& reply_body) {
              CCF_APP_DEBUG("CALLBACK FROM REGISTER");

              auto acmess =
                context.get_subsystem<ccf::ACMESubsystemInterface>();

              auto b64_validation = crypto::b64_from_raw(
                (uint8_t*)response.data(), response.size());

              ccfdns::AddRecord::In addopts;
              addopts.origin = opts.origin;
              addopts.record = RFC1035::ResourceRecord(
                RFC1035::Name("_acme-challenge." + opts.service_name),
                static_cast<uint16_t>(aDNS::Type::TXT),
                static_cast<uint16_t>(aDNS::Class::IN),
                0,
                b64_validation);

              nlohmann::json jbody = addopts;
              auto body = serdes::pack(jbody, serdes::Pack::Text);

              acmess->make_http_request(
                "POST",
                opts.adns_base_url + "/add",
                headers,
                body,
                [](
                  const enum http_status& http_status,
                  const http::HeaderMap& headers,
                  const std::vector<uint8_t>& reply_body) {
                  CCF_APP_DEBUG("CALLBACK FROM ADD");
                  return true;
                },
                ca_certs);

              CCF_APP_DEBUG("Add request submitted");

              return true;
            },
            ca_certs);

          return true;
        });
    }

    // TODO: remove challenge TXT record at some later point in time

    return endpoint_registry;
  }
}
