# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import json

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

# from cryptography.x509 import Certificate,
from cryptography.hazmat.primitives import serialization
from loguru import logger as LOG

import adns_ccf_dev
import ccf_demo_service


def pk_to_pem(x):
    return x.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def cert_to_pem(x):
    return x.public_bytes(serialization.Encoding.PEM).decode("ascii")


def configure_service(network, service_info, adns_base_url, ca_certs):
    """Configure the service"""

    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/configure",
            {
                "name": service_info["name"],
                "ip": service_info["ip"],
                "port": service_info["port"],
                "protocol": service_info["protocol"],
                "adns_base_url": adns_base_url,
                "ca_certs": ca_certs,
            },
        )

    assert r.status_code == http.HTTPStatus.OK
    return json.loads(str(r.body))


def register_service(network, service_info, attestation, public_key):
    """Register the service ="""
    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/register",
            {
                "origin": "adns.ccf.dev.",
                "name": service_info["name"],
                "address": service_info["ip"],
                "port": service_info["port"],
                "protocol": service_info["protocol"],
                "attestation": attestation,
                "algorithm": "ECDSAP384SHA384",
                "public_key": public_key,
            },
        )
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    # jbody = json.loads(str(r.body))
    # return jbody
    return True


def run(adns_args, service_args):
    """Run everything"""

    adns_nw = service_nw = None
    procs = []

    try:
        # Start ADNS server for adns.ccf.dev, including a pebble CA and the DOH proxy
        adns_nw, procs = adns_ccf_dev.run(adns_args)

        if not adns_nw:
            raise Exception("Failed to start aDNS network")

        input("Press Enter to continue...")

        # Start a demo service that registers with the ADNS server
        service_nw = ccf_demo_service.run(service_args)

        if not service_nw:
            raise Exception("Failed to start service network")

        input("Press Enter to continue...")

        service_info = {
            "name": "service43.adns.ccf.dev.",
            "ip": "51.143.161.224",
            "port": 9443,
            "protocol": "tcp",
        }

        # Configure the service & get registration info
        reginfo = configure_service(
            service_nw,
            service_info,
            "adns.ccf.dev",
            [
                cert_to_pem(adns_nw.cert),
                open(adns_args.ca_cert_filename, "r", encoding="ascii").read(),
            ],
        )

        input("Press Enter to continue...")

        # Register the service with aDNS
        register_service(
            adns_nw,
            service_info,
            reginfo["attestation"],
            reginfo["public_key"],
        )

        LOG.info("Waiting forever...")
        while True:
            pass
    except Exception as ex:
        LOG.error("exception: " + str(ex))
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

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.node = ["local://10.1.0.4"]
    adns_args.nodes = infra.e2e_args.min_nodes(adns_args, f=0)
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"
    adns_args.label = "demo_adns"
    adns_args.acme_config_name = "pebble"
    adns_args.wait_forever = False
    adns_args.acme_http_port = 8080
    adns_args.service_port = 8443
    # adns_args.environment += "UBSAN_OPTIONS=print_stacktrace=1"

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.node = ["local://10.1.0.4:443"]  # < 1024 requires root or setcap
    service_args.nodes = infra.e2e_args.min_nodes(service_args, f=0)
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"
    service_args.label = "demo_service"
    service_args.acme_config_name = None
    service_args.wait_forever = False

    run(adns_args, service_args)


if __name__ == "__main__":
    main()
