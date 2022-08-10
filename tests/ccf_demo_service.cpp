// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <cstdint>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "../ccfdns_rpc_types.h"

#include <ccf/_private/http/http_builder.h>
#include <ccf/_private/http/http_parser.h>
#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/sha256.h>
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

  std::vector<std::string> ca_certs(ccfapp::AbstractNodeContext& context)
  {
    auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();
    const auto& acmecfg = acmess->config(configuration.acme_config_name);
    if (acmecfg)
    {
      return (*acmecfg)->ca_certs;
    }
    return {};
  }

  void register_app(ccfapp::AbstractNodeContext& context)
  {
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
      [](
        const enum http_status& http_status,
        const http::HeaderMap& headers,
        const std::vector<uint8_t>& reply_body) {
        CCF_APP_DEBUG("ACME: CALLBACK FROM REGISTER");
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
      ca_certs(context));
  }

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
      TXT_RR_REQUESTED = 0,
      TXT_RR_ADDED
    };

    ccfapp::AbstractNodeContext& context;
    std::map<std::string, ChallengeStatus> challenges;
    std::map<std::string, aDNS::ResourceRecord> challenge_rrs;

    void add_challenge_response(const std::string& token)
    {
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
        auto challenge_name =
          aDNS::Name("_acme-challenge." + configuration.service_name);

        // First clear old records, just in case.
        ccfdns::RemoveAll::In remopts;
        remopts.origin = configuration.origin;
        remopts.name = challenge_name;
        remopts.class_ = static_cast<uint16_t>(aDNS::Class::IN);
        remopts.type = static_cast<uint16_t>(aDNS::Type::TXT);

        auto rembody =
          serdes::pack(nlohmann::json(remopts), serdes::Pack::Text);

        acmess->make_http_request(
          "POST",
          configuration.adns_base_url + "/remove_all",
          {{"content-type", "application/json"}},
          rembody,
          [](
            const enum http_status&,
            const http::HeaderMap&,
            const std::vector<uint8_t>&) { return true; });

        CCF_APP_TRACE("ACME: response for token '{}' is '{}'", token, response);

        auto key_authorization = token + "." + response;
        auto digest = crypto::sha256(
          (uint8_t*)key_authorization.data(), key_authorization.size());
        auto digest_b64 = crypto::b64url_from_raw(
          (uint8_t*)digest.data(), digest.size(), false);
        CCF_APP_TRACE(
          "ACME: b64_digest for token '{}' is '{}'", token, digest_b64);

        ccfdns::AddRecord::In addopts;
        addopts.origin = configuration.origin;
        addopts.record = RFC1035::ResourceRecord(
          challenge_name,
          static_cast<uint16_t>(aDNS::Type::TXT),
          static_cast<uint16_t>(aDNS::Class::IN),
          0,
          RFC1035::TXT(digest_b64));

        auto body = serdes::pack(nlohmann::json(addopts), serdes::Pack::Text);
        challenge_rrs[token] = addopts.record;

        acmess->make_http_request(
          "POST",
          configuration.adns_base_url + "/add",
          {{"content-type", "application/json"}},
          body,
          [this, token](
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
                "ACME: TXT entry add request for '{}' failed with status={} "
                "and body={}",
                token,
                http_status,
                tmp);
              return false;
            }
            CCF_APP_TRACE(
              "ACME: TXT entry for '{}' added (status={})", token, http_status);
            challenges[token] = ChallengeStatus::TXT_RR_ADDED;
            return true;
          },
          ca_certs(context));

        CCF_APP_DEBUG("ACME: Add request submitted for {}", token);
      }
    }

    virtual bool ready(const std::string& token) override
    {
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
          add_challenge_response(token);
          challenges[token] = ChallengeStatus::TXT_RR_REQUESTED;
        }
      }
      else
      {
        CCF_APP_DEBUG("ACME: status={}", cit->second);
        switch (cit->second)
        {
          case ChallengeStatus::TXT_RR_REQUESTED:
            break;
          case ChallengeStatus::TXT_RR_ADDED:
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
      auto rrit = challenge_rrs.find(token);
      if (rrit != challenge_rrs.end())
      {
        auto acmess = context.get_subsystem<ccf::ACMESubsystemInterface>();

        ccfdns::RemoveRecord::In remopts;
        remopts.origin = configuration.origin;
        remopts.record = rrit->second;

        auto body = serdes::pack(nlohmann::json(remopts), serdes::Pack::Text);

        acmess->make_http_request(
          "POST",
          configuration.adns_base_url + "/remove",
          {{"content-type", "application/json"}},
          body,
          [this, token](
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
                "ACME: TXT entry remove request for '{}' failed with status={} "
                "and body={}",
                token,
                http_status,
                tmp);
              return false;
            }
            CCF_APP_TRACE(
              "ACME: TXT entry for '{}' removed (status={})",
              token,
              http_status);
            return true;
          },
          ca_certs(context));
      }

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
