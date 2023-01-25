# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import json
import time
import logging

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

# from cryptography.x509 import Certificate,
from cryptography.hazmat.primitives import serialization
from loguru import logger as LOG

import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

import adns_ccf_dev
import ccf_demo_service


def pk_to_pem(x):
    return x.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def cert_to_pem(x):
    return x.public_bytes(serialization.Encoding.PEM).decode("ascii")


def get_endorsed_cert(network, name):
    """Get the endorsed network certificate"""

    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/get-certificate",
            {"service_dns_name": name},
        )

    assert r.status_code == http.HTTPStatus.OK
    return json.loads(str(r.body))["certificate"]


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
                "adns_base_url": adns_base_url,
                "ca_certs": ca_certs,
            },
        )

    assert r.status_code == http.HTTPStatus.OK
    return json.loads(str(r.body))


def register_service(network, origin, service_info, reginfo):
    """Register the service"""
    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/register",
            {
                "origin": origin,  # Chose origin to be registered in (no origin creation)
                "address": service_info["ip"],
                "port": service_info["port"],
                "protocol": reginfo["protocol"],
                "attestation": reginfo["attestation"],
                "csr": reginfo["csr"],
            },
        )
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    # jbody = json.loads(str(r.body))
    # return jbody
    return True


def wait_for_endorsed_cert(network, name):
    """Wait until an endorsed network certificate is available"""
    num_retries = 20
    while num_retries > 0:
        try:
            r = get_endorsed_cert(network, name)
            return r
        except Exception:
            num_retries = num_retries - 1
        time.sleep(1)
    if num_retries == 0:
        raise Exception("Failed to obtain endorsed network certificate")


def run(adns_args, service_args):
    """Run everything"""

    adns_nw = service_nw = None
    procs = []
    mname_nodot = str(adns_args.soa.mname).rstrip(".")

    try:
        # Start ADNS server, including a pebble CA and the DOH proxy
        adns_nw, procs = adns_ccf_dev.run(adns_args)

        if not adns_nw:
            raise Exception("Failed to start aDNS network")

        # Configure aDNS
        adns_config = {
            "configuration": {
                "name": str(adns_args.soa.mname),
                "ip": adns_args.ip,
                "origin": adns_args.origin,
                "default_ttl": adns_args.default_ttl,
                "signing_algorithm": "ECDSAP384SHA384",
                "digest_type": "SHA384",
                "use_key_signing_key": True,
                "use_nsec3": True,
                "nsec3_hash_algorithm": "SHA1",
                "nsec3_hash_iterations": 3,
                "ca_certs": [
                    cert_to_pem(adns_nw.cert),
                    open(adns_args.ca_cert_filename, "r", encoding="ascii").read(),
                ],
                "fixed_zsk": """-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDApoJlA4ykORqLIJQNq
rpE/KtX8WlGRmFj13deg1pLu2uazeeMKf4ccPOa4sH7oQWqhZANiAATe2J/4MjjS
++0PMLpmgTxVqQgKG64siqKM1BBZjaex5TdxLKLVLPu6QAHKIRKtVeprL0KgkdNl
XIiPf1pGst9TyaEfzTi/XxVqK/CGdZFct9r9eYMjWm01P6HLQi22SjI=
-----END PRIVATE KEY-----
""",
            }
        }

        adns_ccf_dev.configure(adns_nw, adns_config)

        adns_endorsed_cert = wait_for_endorsed_cert(adns_nw, str(adns_args.soa.mname))

        input("Press Enter to continue...")

        # Start a demo service that registers with the ADNS server
        service_nw = ccf_demo_service.run(service_args)

        if not service_nw:
            raise Exception("Failed to start service network")

        input("Press Enter to continue...")

        service_info = {
            "name": "service43." + adns_args.origin,
            "ip": service_args.ip,
            "port": 9443,
        }

        # Configure the service & get registration info
        reginfo = configure_service(
            service_nw,
            service_info,
            "https://" + mname_nodot + ":" + str(adns_args.service_port),
            [cert_to_pem(adns_nw.cert), adns_endorsed_cert],
        )

        input("Press Enter to continue...")

        # Register the service with aDNS
        register_service(adns_nw, adns_args.origin, service_info, reginfo)

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

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.node = ["local://10.1.0.4"]
    adns_args.nodes = infra.e2e_args.min_nodes(adns_args, f=0)
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"
    adns_args.label = "demo_adns"
    adns_args.acme_config_name = "pebble"
    adns_args.email = "cwinter@microsoft.com"
    adns_args.wait_forever = False
    adns_args.acme_http_port = 8080
    adns_args.service_port = 8443
    adns_args.populate = False
    # adns_args.udp_service_port = 54
    adns_args.regpol = """
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
        rname="some-dev.microsoft.com.",
        serial=4,
        refresh=604800,
        retry=86400,
        expire=2419200,
        minimum=0,
    )

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.node = ["local://10.1.0.4:443"]  # < 1024 requires root or setcap
    service_args.nodes = infra.e2e_args.min_nodes(service_args, f=0)
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"
    service_args.label = "demo_service"
    service_args.acme_config_name = None
    service_args.wait_forever = False
    service_args.ip = "51.143.161.224"
    service_args.dns_name = "service43." + adns_args.origin.rstrip(".")

    run(adns_args, service_args)


if __name__ == "__main__":
    main()
