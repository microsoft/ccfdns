// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ccfdns_rpc_types.h"

#include <ccf/crypto/sha256.h>
#include <ccf/node/acme_subsystem_interface.h>
#include <ccf/node/node_configuration_interface.h>
#include <ccf/node_context.h>
#include <ccf/serdes.h>
#include <ccf/service/acme_client_config.h>
#include <map>
#include <string>
#include <vector>

namespace ccfapp
{
  class ADNSChallengeHandler : public ccf::ACMEChallengeHandler
  {
  public:
    ADNSChallengeHandler(
      ccfapp::AbstractNodeContext& context,
      const std::string& adns_base_url,
      const std::string& origin,
      const std::string& service_name,
      const std::vector<std::string>& ca_certs) :
      ccf::ACMEChallengeHandler(),
      context(context),
      adns_base_url(adns_base_url),
      origin(origin),
      service_name(service_name),
      ca_certs(ca_certs)
    {}
    virtual ~ADNSChallengeHandler() = default;

    enum class ChallengeStatus
    {
      TXT_RR_REQUESTED = 0,
      TXT_RR_ADDED
    };

    AbstractNodeContext& context;
    std::string adns_base_url;
    std::string origin;
    std::string service_name;
    std::vector<std::string> ca_certs;
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
        auto challenge_name = aDNS::Name("_acme-challenge." + service_name);

        // First clear old records, just in case.
        ccfdns::RemoveAll::In remopts;
        remopts.origin = origin;
        remopts.name = challenge_name;
        remopts.class_ = static_cast<uint16_t>(aDNS::Class::IN);
        remopts.type = static_cast<uint16_t>(aDNS::Type::TXT);

        auto rembody =
          serdes::pack(nlohmann::json(remopts), serdes::Pack::Text);

        acmess->make_http_request(
          "POST",
          adns_base_url + "/remove_all",
          {{"content-type", "application/json"}},
          rembody,
          [](
            const enum http_status&,
            const http::HeaderMap&,
            const std::vector<uint8_t>&) { return true; },
          ca_certs);

        CCF_APP_TRACE(
          "ACME-DNS: response for token '{}' is '{}'", token, response);

        auto key_authorization = token + "." + response;
        auto digest = crypto::sha256(
          (uint8_t*)key_authorization.data(), key_authorization.size());
        auto digest_b64 = crypto::b64url_from_raw(
          (uint8_t*)digest.data(), digest.size(), false);
        CCF_APP_TRACE(
          "ACME-DNS: b64_digest for token '{}' is '{}'", token, digest_b64);

        ccfdns::AddRecord::In addopts;
        addopts.origin = origin;
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
          adns_base_url + "/add",
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
                "ACME-DNS: TXT entry add request for '{}' failed with "
                "status={} and body={}",
                token,
                http_status,
                tmp);
              return false;
            }
            CCF_APP_TRACE(
              "ACME-DNS: TXT entry for '{}' added (status={})",
              token,
              http_status);
            challenges[token] = ChallengeStatus::TXT_RR_ADDED;
            return true;
          },
          ca_certs);

        CCF_APP_DEBUG("ACME-DNS: Add request submitted for {}", token);
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
        CCF_APP_DEBUG("ACME-DNS: status={}", cit->second);
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
        remopts.origin = origin;
        remopts.record = rrit->second;

        auto body = serdes::pack(nlohmann::json(remopts), serdes::Pack::Text);

        acmess->make_http_request(
          "POST",
          adns_base_url + "/remove",
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
                "ACME-DNS: TXT entry remove request for '{}' failed with "
                "status={} and body={}",
                token,
                http_status,
                tmp);
              return false;
            }
            CCF_APP_TRACE(
              "ACME-DNS: TXT entry for '{}' removed (status={})",
              token,
              http_status);
            return true;
          },
          ca_certs);
      }

      token_responses.erase(token);
      challenges.erase(token);
    }
  };

}