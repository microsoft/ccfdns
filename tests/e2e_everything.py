# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import json
import logging
import time
import os

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

from loguru import logger as LOG

import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

import adns_service
from adns_service import cert_to_pem
import ccf_demo_service
import pebble


def register_service(network, origin, service_info, reginfo):
    """Register the service"""
    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/register-service",
            {
                "origin": origin,  # Chose origin to be registered in (no origin creation)
                "name": service_info["name"],
                "alternative_names": service_info["alternative_names"],
                "ip": service_info["ip"],
                "port": service_info["port"],
                "contact": service_info["contact"],
                "protocol": reginfo["protocol"],
                "attestation": reginfo["attestation"],
                "csr": reginfo["csr"],
            },
        )
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    return True


def register_delegation(network, origin, delegation_info, registration_info):
    """Register delegation of a subdomain"""
    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/register-delegation",
            {
                "origin": origin,
                "subdomain": delegation_info["origin"],
                "name": delegation_info["name"],
                "ip": delegation_info["ip"],
                "port": delegation_info["port"],
                "contact": delegation_info["contact"],
                "protocol": registration_info["protocol"],
                "attestation": registration_info["attestation"],
                "csr": registration_info["csr"],
                "dnskey_records": registration_info["dnskey_records"],
            },
        )
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    return True


def run_server(args):
    """Run an aDNS server (network)"""
    adns_endorsed_cert = None

    adns_config = {
        "configuration": {
            "name": str(args.soa.mname),
            "ip": args.ip,
            "origin": args.origin,
            "default_ttl": args.default_ttl,
            "signing_algorithm": "ECDSAP384SHA384",
            "digest_type": "SHA384",
            "use_key_signing_key": True,
            "use_nsec3": True,
            "nsec3_hash_algorithm": "SHA1",
            "nsec3_hash_iterations": 3,
            "ca_certs": [],
        }
    }

    if args.fixed_zsk:
        adns_config["configuration"][
            "fixed_zsk"
        ] = """-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDApoJlA4ykORqLIJQNq
rpE/KtX8WlGRmFj13deg1pLu2uazeeMKf4ccPOa4sH7oQWqhZANiAATe2J/4MjjS
++0PMLpmgTxVqQgKG64siqKM1BBZjaex5TdxLKLVLPu6QAHKIRKtVeprL0KgkdNl
XIiPf1pGst9TyaEfzTi/XxVqK/CGdZFct9r9eYMjWm01P6HLQi22SjI=
-----END PRIVATE KEY-----
"""

    adns_nw, proc, adns_endorsed_cert, reginfo = adns_service.run(args, adns_config)

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    return adns_nw, proc, adns_endorsed_cert, reginfo


def run_service(args):
    """Run a service"""
    service_nw = ccf_demo_service.run(args)

    if not service_nw:
        raise Exception("Failed to start service network")

    return service_nw


def run(pebble_args, adns_args, service_args, sub_adns_args):
    """Run everything"""

    adns_nw = service_nw = sub_adns_nw = None
    procs = []
    mname_nodot = str(adns_args.soa.mname).rstrip(".")

    try:
        # Start CA
        pebble_proc, _, _ = pebble.run_pebble(pebble_args)
        procs += [pebble_proc]
        while not os.path.exists(pebble_args.ca_cert_filename):
            time.sleep(0.25)

        # Start top-level aDNS
        adns_nw, adns_proc, adns_endorsed_cert, _ = run_server(adns_args)
        procs += [adns_proc]

        # # Start a service
        # service_nw = run_service(service_args)

        # service_info = {
        #     "name": "service43." + adns_args.origin,
        #     "alternative_names": ["www.service43.adns.ccf.dev"],
        #     "ip": service_args.ip,
        #     "port": 9443,
        #     "contact": ["mailto:joe@example.com"],
        # }

        # # Configure the service & get registration info
        # reginfo = ccf_demo_service.configure(
        #     service_nw,
        #     service_info,
        #     "https://" + mname_nodot + ":" + str(adns_args.service_port),
        #     [cert_to_pem(adns_nw.cert)],  # , adns_endorsed_cert
        # )

        # # Register the service with aDNS
        # register_service(adns_nw, adns_args.origin, service_info, reginfo)

        # Start a sub-domain aDNS
        sub_adns_nw, sub_proc, _, sub_adns_reginfo = run_server(sub_adns_args)
        procs += [sub_proc]

        # Register the delegation
        delegation_info = {
            "name": str(sub_adns_args.soa.mname),
            "origin": sub_adns_args.origin,
            "ip": sub_adns_args.ip,
            "port": 8443,
            "contact": ["mailto:bob@example.com"],
        }

        register_delegation(
            adns_nw, adns_args.origin, delegation_info, sub_adns_reginfo
        )

        if not sub_adns_nw:
            raise Exception("Failed to start aDNS network")

        LOG.info("Waiting forever...")
        while True:
            pass

    except Exception:
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
        dns_address="ns1.adns.ccf.dev:53",
        wait_forever=False,
        http_port=8080,
        ca_cert_filename="pebble-ca-cert.pem",
        config_filename="pebble.config.json",
    )

    # First, an aDNS server for adns.ccf.dev.

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.node = ["local://10.1.0.4"]
    adns_args.nodes = infra.e2e_args.min_nodes(adns_args, f=0)
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"
    adns_args.label = "demo_adns"
    adns_args.acme_config_name = "custom"
    adns_args.acme_directory = ""
    adns_args.ca_cert_filename = pebble_args.ca_cert_filename
    adns_args.email = "some-dev@example.com"
    adns_args.wait_forever = False
    adns_args.acme_http_port = pebble_args.http_port
    adns_args.service_port = 8443
    adns_args.populate = False
    adns_args.start_proxy = True
    adns_args.wait_for_endorsed_cert = False
    adns_args.fixed_zsk = True
    adns_args.http2 = True

    adns_args.registration_policy = """
        data.claims.sgx_claims.report_body.mr_enclave.length == 32 &&
        JSON.stringify(data.claims.custom_claims.sgx_report_data) == JSON.stringify([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    """
    adns_args.delegation_policy = """
        data.claims.sgx_claims.report_body.mr_enclave.length == 32 &&
        JSON.stringify(data.claims.custom_claims.sgx_report_data) == JSON.stringify([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    """

    adns_args.origin = "adns.ccf.dev."
    adns_args.ip = "51.143.161.224"
    adns_args.default_ttl = 86400
    adns_args.soa = SOA.SOA(
        rdc.IN,
        rdt.SOA,
        mname="ns1.adns.ccf.dev.",
        rname="joe.example.com",
        serial=4,
        refresh=604800,
        retry=86400,
        expire=2419200,
        minimum=0,
    )

    # A service that registers for adns.ccf.dev.

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.node = ["local://10.1.0.4:9443"]  # < 1024 requires root or setcap
    service_args.nodes = infra.e2e_args.min_nodes(service_args, f=0)
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"
    service_args.label = "demo_service"
    service_args.acme_config_name = "custom"
    service_args.wait_forever = False
    service_args.ip = "51.143.161.224"
    service_args.service_port = 9443
    service_args.dns_name = "service43." + adns_args.origin.rstrip(".")
    service_args.ca_cert_filename = pebble_args.ca_cert_filename
    service_args.http2 = True

    # Then, a second aDNS server for sub.adns.ccf.dev.

    sub_adns_args = infra.e2e_args.cli_args(cliparser)
    sub_adns_args.node = ["local://10.1.0.5"]
    sub_adns_args.nodes = infra.e2e_args.min_nodes(sub_adns_args, f=0)
    sub_adns_args.constitution = glob.glob("../tests/constitution/*")
    sub_adns_args.package = "libccfdns"
    sub_adns_args.label = "demo_sub_adns"
    sub_adns_args.acme_config_name = "custom"
    sub_adns_args.acme_directory = ""
    sub_adns_args.ca_cert_filename = pebble_args.ca_cert_filename
    sub_adns_args.email = "some-dev@sub.example.com"
    sub_adns_args.wait_forever = False
    sub_adns_args.acme_http_port = None
    sub_adns_args.service_port = 8443
    sub_adns_args.start_proxy = True
    sub_adns_args.wait_for_endorsed_cert = False
    sub_adns_args.http2 = True
    sub_adns_args.fixed_zsk = False

    sub_adns_args.populate = False
    sub_adns_args.registration_policy = """
        data.claims.sgx_claims.report_body.mr_enclave.length == 32 &&
        JSON.stringify(data.claims.custom_claims.sgx_report_data) == JSON.stringify([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    """
    sub_adns_args.delegation_policy = """
        data.claims.sgx_claims.report_body.mr_enclave.length == 32 &&
        JSON.stringify(data.claims.custom_claims.sgx_report_data) == JSON.stringify([ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    """

    sub_adns_args.origin = "sub.adns.ccf.dev."
    sub_adns_args.ip = "20.108.155.64"
    sub_adns_args.default_ttl = 86400
    sub_adns_args.soa = SOA.SOA(
        rdc.IN,
        rdt.SOA,
        mname="ns1.sub.adns.ccf.dev.",
        rname="joe.example.com",
        serial=4,
        refresh=604800,
        retry=86400,
        expire=2419200,
        minimum=0,
    )

    run(pebble_args, adns_args, service_args, sub_adns_args)


if __name__ == "__main__":
    main()
