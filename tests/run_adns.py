# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import base64
import socket
import json
import infra.e2e_args
import os
import subprocess
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
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
from adns_service import aDNSConfig
from pycose.messages import Sign1Message  # type: ignore

rdc = dns.rdataclass
rdt = dns.rdatatype

SERVICE_REGISTRATION_AUTH_ALLOW_ALL = """
package policy
default allow := true
"""

PLATFORM_DEFINITION_AUTH_ALLOW_ALL = """
package policy
default allow := true
"""

SEV_SNP_CONTAINERPLAT_AMD_UVM = "SEV-SNP:ContainerPlat-AMD-UVM"


def get_container_group_snp_endorsements_base64():
    security_context_dir = infra.snp.get_security_context_dir()
    return open(
        os.path.join(
            security_context_dir, infra.snp.ACI_SEV_SNP_FILENAME_REPORT_ENDORSEMENTS
        ),
        "r",
        encoding="utf-8",
    ).read()


def gen_csr(domain, key):
    """Generate CSR for registration request"""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(domain),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr


def get_dummy_attestation(report_data):
    measurement = base64.b64encode(
        b"Insecure hard-coded virtual measurement v1"
    ).decode()
    attestation = {
        "measurement": measurement,
        "report_data": base64.b64encode(report_data).decode(),
    }
    return base64.b64encode(json.dumps(attestation).encode()).decode()


def get_host_data_base64():
    security_policy = infra.snp.get_container_group_security_policy()
    return base64.b64encode(sha256(security_policy.encode()).digest()).decode()


def get_snp_attestation(report_data):
    result = subprocess.run(
        [os.environ.get("SNP_REPORT_BINARY"), report_data.hex()],
        check=True,
        capture_output=True,
    )

    # hex(str) -> raw(b) -> b64(b) -> b64(str)
    return base64.b64encode(bytes.fromhex(result.stdout.decode())).decode()


def get_attestation(report_data, enclave):
    if enclave == "snp":
        attestation = get_snp_attestation(report_data)
        endorsements = get_container_group_snp_endorsements_base64()
        uvm_endorsements = infra.snp.get_container_group_uvm_endorsements_base64()
    elif enclave == "virtual":
        attestation = get_dummy_attestation(report_data)
        endorsements = ""
        uvm_endorsements = ""
    else:
        raise ValueError(f"Unknown enclave platform: {enclave}")

    attestation_format = (
        "Insecure_Virtual" if enclave == "virtual" else "AMD_SEV_SNP_v1"
    )
    dummy_attestation = {
        "format": attestation_format,
        "quote": attestation,
        "endorsements": endorsements,
        "uvm_endorsements": uvm_endorsements,
    }
    return json.dumps(dummy_attestation)


def get_security_policy(enclave):
    """Get the security policy for the enclave"""
    if enclave == "snp":
        return get_host_data_base64()
    elif enclave == "virtual":
        return "Insecure hard-coded virtual security policy v1"
    else:
        raise ValueError(f"Unexpected enclave platform: {enclave}")


def corrupted(some_str):
    return "0000" + some_str[4:]


def get_service_definition(enclave, permissive):
    policy = (
        get_security_policy(enclave)
        if permissive
        else corrupted(get_security_policy(enclave))
    )
    return f"""
package policy

default allow := false

allowed_security_policy if {{
    input.host_data == "{policy}"
}}

allow if {{
    allowed_security_policy
}}
"""


def get_platform_definition(enclave, permissive):
    if enclave == "snp":
        uvm_endorsements = infra.snp.get_container_group_uvm_endorsements_base64()
        cose_envelope = Sign1Message.decode(base64.b64decode(uvm_endorsements))
        payload = cose_envelope.payload.decode()
        allowed_measurement = json.loads(payload)["x-ms-sevsnpvm-launchmeasurement"]
    elif enclave == "virtual":
        allowed_measurement = "Insecure hard-coded virtual measurement v1"
    else:
        raise ValueError(f"Unexpected enclave platform: {enclave}")

    if not permissive:
        allowed_measurement = corrupted(allowed_measurement)

    return f"""
package policy

default allow := false

allowed_measurements := ["{allowed_measurement}"]

allowed_measurement if {{
    input.measurement in allowed_measurements
}}

allow if {{
    allowed_measurement
}}
"""


def set_service_definition(network, enclave, service_name, permissive=True):
    policy = get_service_definition(enclave=enclave, permissive=permissive)
    primary, _ = network.find_primary()

    # Let's hash policy as report data for now.
    report_data = sha256(policy.encode()).digest()

    with primary.client(identity="member0") as client:
        r = client.post(
            "/app/set-service-definition",
            {
                "service_name": service_name,
                "policy": policy,
                "attestation": get_attestation(
                    report_data=report_data, enclave=enclave
                ),
            },
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT, r


def set_platform_definition(network, enclave, platform, permissive=True):
    policy = get_platform_definition(enclave=enclave, permissive=permissive)
    primary, _ = network.find_primary()

    # Let's hash policy as report data for now.
    report_data = sha256(policy.encode()).digest()

    with primary.client(identity="member0") as client:
        r = client.post(
            "/app/set-platform-definition",
            {
                "platform": platform,
                "policy": policy,
                "attestation": get_attestation(
                    report_data=report_data, enclave=enclave
                ),
            },
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT, r


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
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns"
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
