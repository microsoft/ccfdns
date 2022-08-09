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
#include <ccf/service/acme_client_config.h>
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
  struct Configuration
  {
    std::string interface_id = "endorsed_interface";
    std::string acme_config_name = "my_acme_config";
    std::string adns_base_url = "https://adns.ccf.dev:8000/app";
    std::string origin = "adns.ccf.dev.";
    std::string service_name = "service43.adns.ccf.dev.";
    std::string ip = "51.143.161.224";
  } configuration;

  class ADNSChallengeHandler : public ccf::ACMEChallengeHandler
  {
  public:
    ADNSChallengeHandler(ccfapp::AbstractNodeContext& context) :
      ccf::ACMEChallengeHandler(),
      context(context)
    {}
    virtual ~ADNSChallengeHandler() = default;

    enum class ChallengeStatus
    {
      INITIATED = 0,
      REGISTERED,
      ADDED,
      DONE
    };

    std::map<std::string, ChallengeStatus> challenges;
    ccfapp::AbstractNodeContext& context;

    std::vector<std::string> ca_certs() const
    {
      auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
      const auto& acmecfg = acmess->config(configuration.acme_config_name);
      if (acmecfg)
      {
        return (*acmecfg)->ca_certs;
      }
      return {};
    }

    void register_app(const std::string& token)
    {
      CCF_APP_DEBUG("ACME: Registering app with token '{}'", token);

      auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();

      ccfdns::RegisterService::In regopts;
      regopts.origin = configuration.origin;
      regopts.name = configuration.service_name;
      regopts.address = configuration.ip;
      regopts.algorithm = RFC4034::Algorithm::ECDSAP384SHA384;
      regopts.public_key = acmess->node_public_key();
      regopts.attestation = QVL::get_oe_attestation(
        crypto::make_public_key(regopts.public_key)->public_key_der());

      nlohmann::json jbody = regopts;
      auto body = serdes::pack(jbody, serdes::Pack::Text);

      acmess->make_http_request(
        "POST",
        configuration.adns_base_url + "/register",
        {{"content-type", "application/json"}},
        body,
        [this, token](
          const enum http_status& http_status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& reply_body) {
          CCF_APP_DEBUG("ACME: CALLBACK FROM REGISTER {}", token);
          if (
            http_status != HTTP_STATUS_OK &&
            http_status != HTTP_STATUS_NO_CONTENT)
          {
            std::string tmp = {
              reply_body.data(), reply_body.data() + reply_body.size()};
            CCF_APP_DEBUG(
              "ACME: registration request for '{}' failed with status={} and "
              "body={}",
              token,
              http_status,
              tmp);
            return false;
          }

          challenges[token] = ChallengeStatus::REGISTERED;
          add_challenge_response(token);
          return true;
        },
        ca_certs());
    }

    void add_challenge_response(const std::string& token)
    {
      CCF_APP_DEBUG("ACME: Adding challenge response for token '{}'", token);

      auto rit = token_responses.find(token);
      if (rit == token_responses.end())
      {
        throw std::runtime_error(
          fmt::format("challenge response for token '{}' not found", token));
      }
      else
      {
        auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
        const auto& response = rit->second;

        CCF_APP_DEBUG("ACME: response for token '{}' is '{}'", token, response);

        ccfdns::AddRecord::In addopts;
        addopts.origin = configuration.origin;
        addopts.record = RFC1035::ResourceRecord(
          RFC1035::Name("_acme-challenge." + configuration.service_name),
          static_cast<uint16_t>(aDNS::Type::TXT),
          static_cast<uint16_t>(aDNS::Class::IN),
          0,
          RFC1035::TXT(response));

        nlohmann::json jbody = addopts;
        auto body = serdes::pack(jbody, serdes::Pack::Text);

        acmess->make_http_request(
          "POST",
          configuration.adns_base_url + "/add",
          {{"content-type", "application/json"}},
          body,
          [this, token](
            const enum http_status& http_status,
            const http::HeaderMap& headers,
            const std::vector<uint8_t>& reply_body) {
            CCF_APP_DEBUG(
              "ACME: CALLBACK FROM ADD {} with status={}", token, http_status);
            if (
              http_status != HTTP_STATUS_OK &&
              http_status != HTTP_STATUS_NO_CONTENT)
            {
              std::string tmp = {
                reply_body.data(), reply_body.data() + reply_body.size()};
              CCF_APP_DEBUG(
                "ACME: add request for '{}' failed with status={} and body={}",
                token,
                http_status,
                tmp);
              return false;
            }
            challenges[token] = ChallengeStatus::ADDED;
            return true;
          },
          ca_certs());

        CCF_APP_DEBUG("ACME: Add request submitted for {}", token);
      }
    }

    virtual bool ready(const std::string& token) override
    {
      CCF_APP_DEBUG("ACME: ready check for token '{}'", token);

      auto cit = challenges.find(token);
      if (cit == challenges.end())
      {
        auto rit = token_responses.find(token);
        if (rit == token_responses.end())
        {
          throw std::runtime_error(
            fmt::format("challenge response for token '{}' not found", token));
        }
        else
        {
          auto response = rit->second;
          register_app(token);
          challenges[token] = ChallengeStatus::INITIATED;
        }
      }
      else
      {
        CCF_APP_DEBUG("ACME: status={}", cit->second);
        switch (cit->second)
        {
          case ChallengeStatus::INITIATED:
          case ChallengeStatus::REGISTERED:
            break;
          case ChallengeStatus::ADDED:
            return true;
            break;
          default:
            throw std::runtime_error("unknown challenge status");
        }
      }

      return false;
    }

    virtual void remove(const std::string& token) override
    {
      CCF_APP_DEBUG("ACME: remove token '{}'", token);

      auto rit = token_responses.find(token);
      if (rit == token_responses.end())
        return;

      auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
      const auto& response = rit->second;

      ccfdns::AddRecord::In remopts;
      remopts.origin = configuration.origin;
      remopts.record = RFC1035::ResourceRecord(
        RFC1035::Name("_acme-challenge." + configuration.service_name),
        static_cast<uint16_t>(aDNS::Type::TXT),
        static_cast<uint16_t>(aDNS::Class::IN),
        0,
        RFC1035::TXT(response));

      nlohmann::json jbody = remopts;
      auto body = serdes::pack(jbody, serdes::Pack::Text);

      acmess->make_http_request(
        "POST",
        configuration.adns_base_url + "/add",
        {{"content-type", "application/json"}},
        body,
        [this, token](
          const enum http_status& http_status,
          const http::HeaderMap& headers,
          const std::vector<uint8_t>& reply_body) {
          CCF_APP_DEBUG(
            "ACME: CALLBACK FROM ADD {} with status={}", token, http_status);
          if (
            http_status != HTTP_STATUS_OK &&
            http_status != HTTP_STATUS_NO_CONTENT)
          {
            std::string tmp = {
              reply_body.data(), reply_body.data() + reply_body.size()};
            CCF_APP_DEBUG(
              "ACME: add request for '{}' failed with status={} and body={}",
              token,
              http_status,
              tmp);
            return false;
          }
          challenges[token] = ChallengeStatus::ADDED;
          return true;
        },
        ca_certs());

      token_responses.erase(token);
      challenges.erase(token);
    }
  };

  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    logger::config::level() = logger::TRACE;

    auto endpoint_registry = std::make_unique<service::Handlers>(context);

    auto acme_subsystem = context.get_subsystem<ccf::ACMESubsystemInterface>();
    if (acme_subsystem)
    {
      acme_subsystem->install_challenge_handler(
        configuration.interface_id,
        std::make_shared<ADNSChallengeHandler>(context));
    }

    return endpoint_registry;
  }
}
