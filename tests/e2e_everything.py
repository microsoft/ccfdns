# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import logging
import time
import os

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import infra.interfaces

from loguru import logger as LOG

import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

import adns_service
from adns_service import aDNSConfig, ServiceCAConfig
import ccf_demo_service
import pebble
from adns_tools import cert_to_pem, poll_for_receipt, NoReceiptException


nonzero_mrenclave_policy = """
    let r = true;
    for (const [name, claims] of Object.entries(data.claims)) {
        r &= claims.sgx_claims.report_body.mr_enclave.length == 32 &&
            JSON.stringify(claims.custom_claims.sgx_report_data) != JSON.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
    r == true
"""


def register_service(network, service_info, registration_info, num_retries=10):
    """Register the service"""
    while num_retries > 0:
        try:
            primary, _ = network.find_primary()
            with primary.client() as client:
                r = client.post(
                    "/app/register-service",
                    {
                        "contact": service_info["contact"],
                        "csr": registration_info["csr"],
                        "node_information": registration_info["node_information"],
                        "configuration_receipt": str(
                            registration_info["configuration_receipt"]
                        ),
                    },
                )
                assert (
                    r.status_code == http.HTTPStatus.OK
                    or r.status_code == http.HTTPStatus.NO_CONTENT
                )
                assert "x-ms-ccf-transaction-id" in r.headers
                return poll_for_receipt(network, r.headers["x-ms-ccf-transaction-id"])
        except Exception as ex:
            num_retries = num_retries - 1
            if num_retries == 0:
                raise ex
            else:
                n = 5
                LOG.error(f"Registration failed; retrying in {n} seconds.")
                time.sleep(n)


def register_delegation(
    adns_network, sub_adns_network, delegation_info, registration_info, num_retries=10
):
    """Register delegation of a subdomain"""

    while num_retries > 0:
        try:
            primary, _ = adns_network.find_primary()
            r = None
            with primary.client() as client:
                r = client.post(
                    "/app/register-delegation",
                    {
                        "subdomain": delegation_info["subdomain"],
                        "contact": delegation_info["contact"],
                        #
                        "csr": registration_info["csr"],
                        "dnskey_records": registration_info["dnskey_records"],
                        "node_information": registration_info["node_information"],
                        "configuration_receipt": str(
                            registration_info["configuration_receipt"]
                        ),
                    },
                )
            assert (
                r.status_code == http.HTTPStatus.OK
                or r.status_code == http.HTTPStatus.NO_CONTENT
            )
            assert "x-ms-ccf-transaction-id" in r.headers
            receipt = poll_for_receipt(
                adns_network, r.headers["x-ms-ccf-transaction-id"]
            )

            sub_primary, _ = sub_adns_network.find_primary()
            with sub_primary.client() as client:
                r = client.post("/app/start-delegation-acme-client", {})

            return receipt
        except Exception as ex:
            num_retries = num_retries - 1
            if num_retries == 0:
                raise ex
            else:
                n = 5
                LOG.error(f"Registration failed; retrying in {n} seconds.")
                time.sleep(n)


def run_server(args, wait_for_endorsed_cert=False, with_proxies=True):
    """Run an aDNS server (network)"""
    adns_endorsed_certs = None

    adns_nw, procs, adns_endorsed_certs, reginfo = adns_service.run(
        args, wait_for_endorsed_cert, with_proxies
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    return adns_nw, procs, adns_endorsed_certs, reginfo


def start_and_register_service(adns_nw, service_args, adns_endorsed_certs):
    """Start, configure, and register service"""

    service_nw = ccf_demo_service.run(service_args)

    if not service_nw:
        raise Exception("Failed to start service network")

    node_addr = adns_service.assign_node_addresses(
        service_nw, service_args.node_addresses, False
    )

    service_cfg = {
        "service_name": service_args.service_name,
        "contact": ["mailto:" + service_args.email],
        "adns_base_url": service_args.adns_base_url,
        "ca_certs": [cert_to_pem(adns_nw.cert)] + adns_endorsed_certs,
        "node_addresses": node_addr,
    }

    registered = False
    while not registered:
        try:
            reginfo = ccf_demo_service.configure(service_nw, service_cfg)
            registration_receipt = register_service(adns_nw, service_cfg, reginfo)
            registered = True
        except Exception as ex:
            if hasattr(ex, "message"):
                LOG.info(f"Exception: {ex.message}")
            else:
                LOG.info(f"Exception: {ex}")
            logging.exception("caught exception")

    assert registration_receipt is not None

    return registration_receipt


def run(pebble_args, adns_args, service_args, sub_adns_args, sub_service_args):
    """Run everything"""

    adns_nw = service_nw = sub_adns_nw = None
    procs = []

    try:
        # Start CA
        pebble_proc, _, _ = pebble.run_pebble(pebble_args)
        procs += [pebble_proc]
        while not os.path.exists(pebble_args.ca_cert_filename):
            time.sleep(0.25)
        pebble_certs = pebble.ca_certs(pebble_args.mgmt_address)
        pebble_certs += pebble.ca_certs_from_file(pebble_args.ca_cert_filename)
        adns_args.adns.service_ca.ca_certificates += pebble_certs
        sub_adns_args.adns.service_ca.ca_certificates += pebble_certs

        # Start top-level aDNS
        adns_args.adns.ca_certs += pebble_certs
        adns_nw, adns_procs, adns_certs, _ = run_server(adns_args, True)
        procs += adns_procs

        start_and_register_service(adns_nw, service_args, adns_certs)

        # Start a sub-domain aDNS
        adns_args.adns.ca_certs += pebble_certs
        sub_adns_nw, sub_procs, _, sub_adns_reginfo = run_server(
            sub_adns_args, False, True
        )
        procs += sub_procs

        # Register the delegation
        delegation_info = {
            "subdomain": sub_adns_args.adns.origin,
            "contact": ["mailto:" + sub_adns_args.email],
        }

        register_delegation(adns_nw, sub_adns_nw, delegation_info, sub_adns_reginfo)

        sub_endorsed_cert = adns_service.wait_for_endorsed_certs(
            sub_adns_nw, delegation_info["subdomain"], num_retries=10000
        )

        start_and_register_service(
            sub_adns_nw,
            sub_service_args,
            sub_endorsed_cert,
        )

        LOG.info("Waiting forever...")
        while True:
            pass

    except Exception as ex:
        if hasattr(ex, "message"):
            LOG.info(f"Exception: {ex.message}")
        else:
            LOG.info(f"Exception: {ex}")
        logging.exception("caught exception")
    finally:
        if service_nw:
            service_nw.stop_all_nodes()
        if adns_nw:
            adns_nw.stop_all_nodes()
        if procs:
            for p in procs:
                if p:
                    p.kill()


def main():
    """Entry point"""

    def cliparser(parser):
        """CLI option parser"""
        parser.description = "Run a CCF-based demo service"

    # Pebble CA
    pebble_args = pebble.Arguments(
        # dns_address="ns1.adns.ccf.dev:53",
        wait_forever=False,
        http_port=8080,
        ca_cert_filename="pebble-ca-cert.pem",
        config_filename="pebble.config.json",
    )

    # First, an aDNS server for adns.ccf.dev.

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.node_addresses = [
        (
            "local://10.1.0.4:1443",  # primary/internal
            "local://10.1.0.4:8443",  # external/endorsed
            "ns1.adns.ccf.dev",  # public name
            "51.143.161.224",  # public IP
        ),
        (
            "local://10.1.0.5:1443",
            "local://10.1.0.5:8443",
            "ns2.adns.ccf.dev",
            "20.108.155.64",
        ),
        (
            "local://10.1.0.6:1443",
            "local://10.1.0.6:8443",
            "ns3.adns.ccf.dev",
            "20.0.255.182",
        ),
    ]
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"
    adns_args.label = "demo_adns"
    adns_args.acme_config_name = "custom"
    adns_args.email = "some-dev@example.com"
    adns_args.wait_forever = False
    adns_args.http2 = False
    adns_args.ca_certs = []

    adns_args.adns = aDNSConfig(
        origin="adns.ccf.dev.",
        service_name="adns.ccf.dev.",
        node_addresses={},
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.adns.ccf.dev.",
                rname="some-dev.example.com",
                serial=4,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=21600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=3,
        ca_certs=adns_args.ca_certs,
        parent_base_url=None,
        service_ca=ServiceCAConfig(  # CA for service certificates
            directory="https://127.0.0.1:1024/dir",
            ca_certificates=[],
        ),
        registration_policy=nonzero_mrenclave_policy,
        delegation_policy=nonzero_mrenclave_policy,
        fixed_zsk="""-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDApoJlA4ykORqLIJQNq
rpE/KtX8WlGRmFj13deg1pLu2uazeeMKf4ccPOa4sH7oQWqhZANiAATe2J/4MjjS
++0PMLpmgTxVqQgKG64siqKM1BBZjaex5TdxLKLVLPu6QAHKIRKtVeprL0KgkdNl
XIiPf1pGst9TyaEfzTi/XxVqK/CGdZFct9r9eYMjWm01P6HLQi22SjI=
-----END PRIVATE KEY-----
""",
    )

    # A service that registers for adns.ccf.dev.

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.service_name = "service43." + adns_args.adns.origin.rstrip(".")
    service_args.node_addresses = [
        (
            "local://10.1.0.4:3443",
            "local://10.1.0.4:9443",
            "node1." + service_args.service_name,
            "51.143.161.224",
        ),
        (
            "local://10.1.0.5:3443",
            "local://10.1.0.5:9443",
            "node2." + service_args.service_name,
            "20.108.155.64",
        ),
    ]
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"
    service_args.label = "demo_service"
    service_args.email = "bill@example.com"
    service_args.acme_config_name = "custom"
    service_args.wait_forever = False
    service_args.http2 = False
    service_args.adns_base_url = "https://ns1.adns.ccf.dev:8443"

    # Then, a second aDNS server for sub.adns.ccf.dev.

    sub_adns_args = infra.e2e_args.cli_args(cliparser)
    sub_adns_args.node_addresses = [
        (
            "local://10.1.0.7:1443",
            "local://10.1.0.7:8443",
            "ns4.sub.adns.ccf.dev",
            "20.108.16.154",
        ),
        (
            "local://10.1.0.8:1443",
            "local://10.1.0.8:8443",
            "ns5.sub.adns.ccf.dev",
            "20.108.16.23",
        ),
        (
            "local://10.1.0.9:1443",
            "local://10.1.0.9:8443",
            "ns6.sub.adns.ccf.dev",
            "20.108.18.43",
        ),
    ]
    sub_adns_args.constitution = glob.glob("../tests/constitution/*")
    sub_adns_args.package = "libccfdns"
    sub_adns_args.label = "demo_sub_adns"
    sub_adns_args.email = "some-dev@sub.example.com"
    sub_adns_args.acme_config_name = "custom"
    sub_adns_args.wait_forever = False
    sub_adns_args.http2 = False
    sub_adns_args.ca_certs = []

    sub_adns_args.adns = aDNSConfig(
        origin="sub.adns.ccf.dev.",
        service_name="sub.adns.ccf.dev.",
        node_addresses=[],
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.sub.adns.ccf.dev.",
                rname="some-dev.sub.example.com",
                serial=4,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=21600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=3,
        ca_certs=adns_args.ca_certs,
        parent_base_url="https://ns1.adns.ccf.dev:8443",
        service_ca=ServiceCAConfig(
            directory="https://127.0.0.1:1024/dir", ca_certificates=[]
        ),
        registration_policy=nonzero_mrenclave_policy,
        delegation_policy=nonzero_mrenclave_policy,
    )

    # A service that registers for sub.adns.ccf.dev.

    sub_service_args = infra.e2e_args.cli_args(cliparser)
    sub_service_args.service_name = "service45." + sub_adns_args.adns.origin.rstrip(".")
    sub_service_args.node_addresses = [
        (
            "local://10.1.0.7:3443",
            "local://10.1.0.7:9443",
            "node1." + sub_service_args.service_name,
            "20.108.16.154",
        ),
        (
            "local://10.1.0.9:3443",
            "local://10.1.0.9:9443",
            "node2." + sub_service_args.service_name,
            "20.108.18.43",
        ),
    ]
    sub_service_args.constitution = glob.glob("../tests/constitution/*")
    sub_service_args.package = "libccf_demo_service"
    sub_service_args.label = "demo_sub_service"
    sub_service_args.acme_config_name = "custom"
    sub_service_args.wait_forever = False
    sub_service_args.email = "joe@example.com"
    sub_service_args.http2 = False
    sub_service_args.adns_base_url = "https://ns4.sub.adns.ccf.dev:8443"

    run(pebble_args, adns_args, service_args, sub_adns_args, sub_service_args)


if __name__ == "__main__":
    main()
