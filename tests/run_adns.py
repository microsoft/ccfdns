# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# To be run purely by demo/adns/adns.sh. Placed here for dependecies sake.

import glob
import base64
import socket
import infra.e2e_args
import adns_service
import dns
from e2e_basic import (
    create_issuer,
    get_attestation_format,
    set_service_definition_auth_successfully,
    set_platform_definition_auth_successfully,
    set_service_definition_successfully,
    set_platform_definition_successfully,
)
import dns.rdtypes.ANY.SOA as SOA
from hashlib import sha256
from adns_service import aDNSConfig

rdc = dns.rdataclass
rdt = dns.rdatatype


def get_host_data_base64():
    security_policy = infra.snp.get_container_group_security_policy()
    return base64.b64encode(sha256(security_policy.encode()).digest()).decode()


def get_security_policy(enclave):
    """Get the security policy for the enclave"""
    if enclave == "snp":
        return get_host_data_base64()
    elif enclave == "virtual":
        return "Insecure hard-coded virtual security policy v1"
    else:
        raise ValueError(f"Unexpected enclave platform: {enclave}")


def set_policies(network, args):
    enclave = args.enclave_platform

    issuer = create_issuer()

    set_service_definition_auth_successfully(
        network, issuer, "test.e2e.acidns10.attested.name."
    )
    set_platform_definition_auth_successfully(
        network, issuer, get_attestation_format(enclave)
    )

    set_service_definition_successfully(
        network,
        enclave,
        issuer,
        service_name="test.e2e.acidns10.attested.name.",
        permissive=True,
    )
    set_platform_definition_successfully(
        network,
        enclave,
        issuer,
        platform=get_attestation_format(enclave),
        permissive=True,
    )


def run(args):
    """Run tests"""

    adns_nw = adns_service.run(
        args,
        tcp_port=5353,
        udp_port=5353,
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    set_policies(adns_nw, args)

    print("ADNS network is running. Press Ctrl+C to stop.")
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down ADNS network...")
        pass


def main():
    """Entry point"""

    def cliparser(parser):
        """Add parser"""
        parser.description = "DNS tests"

        parser.add_argument(
            "--service-type",
            help="Type of service",
            action="store",
            dest="service_type",
            default="CCF",
        )

    targs = infra.e2e_args.cli_args(cliparser)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

    print("Bringing up network on {}", my_ip)

    targs.nodes = infra.e2e_args.min_nodes(targs, f=0)
    targs.node_addresses = [
        (
            "local://0.0.0.0:1443",  # primary/internal
            "local://0.0.0.0:8443",  # external/endorsed
            "ns1.acidns10.attested.name",  # public name
            "20.160.110.47",  # public IP
        )
    ]
    # Localhost has to be replaced with the external IP for distributed demo.
    targs.subject_alt_names = ["iPAddress:0.0.0.0", "iPAddress:127.0.0.1"]
    targs.constitution = glob.glob("../../tests/constitution/*")
    targs.package = "libccfdns"
    targs.enclave_platform = "snp" if glob.glob("/security-context-*") else "virtual"
    targs.acme_config_name = "custom"

    targs.http2 = False
    targs.initial_node_cert_validity_days = 365
    targs.initial_service_cert_validity_days = 365
    targs.message_timeout_ms = 5000
    targs.election_timeout_ms = 60000

    # Don't shut down the socket which is semi-manually managed via custom
    # ccf::Session implementations for UDP/TCP.
    targs.idle_connection_timeout_s = 3600 * 3600

    targs.adns = aDNSConfig(
        origin="acidns10.attested.name.",
        service_name="acidns10.attested.name.",
        node_addresses={},
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.acidns10.attested.name.",
                rname="some-dev.acidns10.attested.name.",
                serial=8,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=3600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=0,
        nsec3_salt_length=8,
    )

    run(targs)


if __name__ == "__main__":
    main()
