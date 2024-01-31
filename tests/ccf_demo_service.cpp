// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ravl/sgx.h"

#include <ccf/crypto/san.h>
#include <ccf/ds/json.h>
#include <ccf/endpoints/authentication/cert_auth.h>
#include <ccf/service/tables/acme_certificates.h>
#include <cstdint>
#include <llhttp/llhttp.h>
#include <service/tables/nodes.h>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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
#include <ccf/service/consensus_config.h>
#include <ccf/service/node_info_network.h>
#include <ccf/service/tables/service.h>
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
  struct NodeAddress
  {
    std::string name;
    std::string ip;
    std::string protocol;
    uint16_t port;
  };

  struct NodeInfo
  {
    NodeAddress address;
    std::string attestation;
  };

  struct Configuration
  {
    std::string service_name;

    std::string adns_base_url;
    std::vector<std::string> ca_certs;
    std::map<std::string, NodeAddress> node_addresses;
  };

  DECLARE_JSON_TYPE(NodeAddress);
  DECLARE_JSON_REQUIRED_FIELDS(NodeAddress, name, ip, port, protocol);

  DECLARE_JSON_TYPE(NodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfo, address, attestation);

  DECLARE_JSON_TYPE(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(
    Configuration, service_name, adns_base_url, ca_certs, node_addresses);

  struct RegistrationInfo
  {
    std::string public_key;
    std::vector<uint8_t> csr;
    std::map<std::string, NodeInfo> node_information;
  };

  DECLARE_JSON_TYPE(RegistrationInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RegistrationInfo, public_key, csr, node_information);

  struct SetServiceCertificateIn
  {
    std::string certificate;
  };

  DECLARE_JSON_TYPE(SetServiceCertificateIn);
  DECLARE_JSON_REQUIRED_FIELDS(SetServiceCertificateIn, certificate);

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

  struct SetServiceCertificate
  {
    using In = SetServiceCertificateIn;
    using Out = void;
  };

  class Handlers : public ccf::UserEndpointRegistry
  {
  protected:
    std::shared_ptr<ccf::ACMESubsystemInterface> acmess;
    std::shared_ptr<ccf::NetworkIdentitySubsystem> niss;
    Configuration configuration;
    std::string internal_node_address;

  public:
    Handlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "Attested Test Service";
      openapi_info.description =
        "This application is a test service, attested via aDNS.";
      openapi_info.document_version = "0.0.0";

      auto set_service_certificate =
        [this](auto& ctx, nlohmann::json&& params) {
          try
          {
            const auto in = params.get<SetServiceCertificate::In>();
            auto tbl = ctx.tx.template rw<ccf::ACMECertificates>(
              ccf::Tables::ACME_CERTIFICATES);
            if (!tbl)
              throw std::runtime_error("missing ACME certificate table");
            tbl->put("custom", in.certificate);
            return ccf::make_success();
          }
          catch (std::exception& ex)
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
          }
        };

      make_endpoint(
        "/internal/set-service-certificate",
        HTTP_POST,
        ccf::json_adapter(set_service_certificate),
        {std::make_shared<ccf::NodeCertAuthnPolicy>()})
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
            response << "This is <a href=\"https://" << opt_cfg->service_name
                     << "\">" << opt_cfg->service_name << "</a>";

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

      make_endpoint("/", HTTP_GET, index, ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto configure = [this](auto& ctx, nlohmann::json&& params) {
        try
        {
          const auto cfg = params.get<ConfigurationRPC::In>();

          auto cfg_table =
            ctx.tx.template rw<TConfigurationTable>(configuration_table_name);
          if (!cfg_table)
            throw std::runtime_error("error accessing configuration table");

          cfg_table->put(cfg);

          configuration = cfg;

          ConfigurationRPC::Out out;

          auto nodes_table = ctx.tx.template ro<ccf::Nodes>(ccf::Tables::NODES);
          if (!nodes_table)
            throw std::runtime_error("error accessing nodes table");

          for (const auto& [id, addr] : cfg.node_addresses)
          {
            auto entry = nodes_table->get(id);
            auto attestation = ravl::oe::Attestation(
              entry->quote_info.quote, entry->quote_info.endorsements);
            out.node_information[id] = {
              .address = addr, .attestation = attestation};
          }

          auto nwk_public_key =
            crypto::public_key_pem_from_cert(acmess->network_cert().raw());

          out.public_key = nwk_public_key.str();

          if (!niss)
            throw std::runtime_error("no network identity subsystem");

          const auto& ni = niss->get();
          auto kp = make_key_pair(ni->priv_key);

          if (!kp)
            throw std::runtime_error("invalid network key");

          auto sn = cfg.service_name;
          while (sn.back() == '.')
            sn.pop_back();

          std::vector<crypto::SubjectAltName> sans;
          sans.push_back({sn, false});
          for (const auto& [id, addr] : cfg.node_addresses)
          {
            auto n = addr.name;
            while (n.back() == '.')
              n.pop_back();
            sans.push_back({n, false});
            // sans.push_back({addr.ip, true});
          }

          out.csr = kp->create_csr_der("CN=" + sn, sans, nwk_public_key);

          if (!cfg.adns_base_url.empty())
          {
            auto unterminated_name = cfg.service_name;
            while (unterminated_name.size() > 0 &&
                   unterminated_name.back() == '.')
              unterminated_name.pop_back();

            std::string body =
              "{\"service_dns_name\": \"" + unterminated_name + "\"}";
            std::vector<uint8_t> vbody(body.begin(), body.end());
            std::vector<std::string> ca_certs = cfg.ca_certs;
            ca_certs.push_back(niss->get()->cert.str());

            struct CertThreadMsg
            {
              CertThreadMsg(
                std::shared_ptr<ccf::ACMESubsystemInterface> acmess,
                std::shared_ptr<ccf::NetworkIdentitySubsystem> niss,
                const std::string& adns_base_url,
                const std::vector<uint8_t>& body,
                const std::vector<std::string>& ca_certs,
                const std::string& rpc_address) :
                acmess(acmess),
                niss(niss),
                adns_base_url(adns_base_url),
                body(body),
                ca_certs(ca_certs),
                rpc_address(rpc_address)
              {}

              std::shared_ptr<ccf::ACMESubsystemInterface> acmess;
              std::shared_ptr<ccf::NetworkIdentitySubsystem> niss;
              std::string adns_base_url;
              std::vector<uint8_t> body;
              std::vector<std::string> ca_certs;
              std::string rpc_address;
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
                  [data = msg->data](
                    const http_status& status,
                    const http::HeaderMap&,
                    const std::vector<uint8_t>& body) {
                    if (status != HTTP_STATUS_OK)
                      return false;
                    else
                    {
                      try
                      {
                        auto j = nlohmann::json::parse(body);
                        service_cert = j["certificate"].get<std::string>();

                        SetServiceCertificate::In robj = {service_cert};
                        nlohmann::json jin;
                        to_json(jin, robj);
                        std::string s = jin.dump();
                        auto rbody =
                          std::vector<uint8_t>(s.data(), s.data() + s.size());

                        data.acmess->make_http_request(
                          "POST",
                          "https://" + data.rpc_address +
                            "/app/internal/set-service-certificate",
                          {},
                          rbody,
                          [](
                            const http_status& http_status,
                            const http::HeaderMap&,
                            const std::vector<uint8_t>&) {
                            if (http_status != 200)
                              CCF_APP_FAIL("Internal RPC call failed.");
                            return true;
                          },
                          data.ca_certs,
                          "HTTP1",
                          true);
                      }
                      catch (...)
                      {
                        CCF_APP_DEBUG("caught unknown exception");
                      }
                      return true;
                    }
                  },
                  msg->data.ca_certs,
                  "HTTP1");

                threading::ThreadMessaging::instance().add_task_after(
                  std::move(msg), std::chrono::seconds(1));
              },
              acmess,
              niss,
              configuration.adns_base_url,
              vbody,
              ca_certs,
              internal_node_address);

            threading::ThreadMessaging::instance().add_task_after(
              std::move(msg), std::chrono::seconds(1));
          }

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
      niss = context.get_subsystem<ccf::NetworkIdentitySubsystem>();

      {
        // Interface for internal RPC calls
        auto interface_id = "primary_rpc_interface";
        auto nci = context.get_subsystem<ccf::NodeConfigurationInterface>();
        auto ncs = nci->get();
        auto iit = ncs.node_config.network.rpc_interfaces.find(interface_id);
        if (iit == ncs.node_config.network.rpc_interfaces.end())
          CCF_APP_FAIL("Interface '{}' not found", interface_id);
        else
          internal_node_address = iit->second.published_address;
      }
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    logger::config::level() = TRACE;
    return std::make_unique<service::Handlers>(context);
  }
}
