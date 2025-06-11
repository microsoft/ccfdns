# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import base64
import socket
import requests
import json
import infra.e2e_args
import os
import subprocess
import adns_service
import dns
import dns.message
import dns.query
import dns.dnssec
import dns.rdtypes.ANY.SOA as SOA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import sha256
from adns_service import aDNSConfig, set_policy

rdc = dns.rdataclass
rdt = dns.rdatatype

SERVICE_REGISTRATION_ALLOW_ALL = """
package policy
default allow := true
"""

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


def get_attestation(service_key, enclave_platform):
    public_key = service_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    report_data = sha256(public_key).digest()

    if enclave_platform == "snp":
        attestation = get_snp_attestation(report_data)
        endorsements = get_container_group_snp_endorsements_base64()
        uvm_endorsements = infra.snp.get_container_group_uvm_endorsements_base64()
    elif enclave_platform == "virtual":
        attestation = get_dummy_attestation(report_data)
        endorsements = ""
        uvm_endorsements = ""
    else:
        raise ValueError(f"Unknown enclave platform: {enclave_platform}")

    attestation_format = (
        "Insecure_Virtual" if enclave_platform == "virtual" else "AMD_SEV_SNP_v1"
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
        raise ValueError(f"Unknown enclave platform: {enclave}")


def corrupted(some_str):
    return "0000" + some_str[4:]


def get_service_relying_party_policy(enclave, good):
    policy = get_security_policy(enclave) if good else corrupted(get_security_policy(enclave))
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


def submit_service_registration(client, name, address, port, protocol, service_key, enclave_platform, attestation):
    """Submit a service registration request"""
    csr = gen_csr(name, service_key)
    with open(f"{enclave_platform}_attestation.json", "w") as f:
        f.write(attestation)

    r = client.post(
        "/app/register-service",
        {
            "csr": base64.b64encode(
                csr.public_bytes(serialization.Encoding.DER)
            ).decode(),
            "node_information": {
                # Possible to register multiple instances in one call
                "default": {
                    "address": {
                        "name": name,
                        "ip": address,
                        "protocol": protocol,
                        "port": port,
                    },
                    "attestation": attestation,
                }
            },
        },
    )
    if r.status_code != http.HTTPStatus.NO_CONTENT:
        raise Exception(f"Failed to register service {name}: {r.status_code} {r.body}")
    return r


def check_record(host, port, ca, name, stype, expected_data=None):
    """Checks for existence of a specific DNS record"""
    qname = dns.name.from_text(name)
    qtype = rdt.from_text(stype)
    with requests.sessions.Session() as session:
        q = dns.message.make_query(qname, qtype)
        r = dns.query.https(
            q,
            "https://" + host + ":" + str(port) + "/app/dns-query",
            session=session,
            verify=ca,
            post=False,
        )
        print(f"Check record: query=\n{q}\nresponse =\n{r.answer}")
        assert r.answer
        for a in r.answer:
            assert a.name == qname
            saw_expected = False
            for item in a.items:
                assert item.rdclass == rdc.IN
                assert item.rdtype in [
                    qtype,
                    rdt.RRSIG,
                    rdt.NSEC,
                    rdt.NSEC3,
                ]
                if expected_data:
                    if (
                        item.rdtype != qtype
                        or item.to_wire() == expected_data.to_wire()
                    ):
                        saw_expected = True
            assert not expected_data or saw_expected


def validate_rrsigs(response: dns.message.Message, qtype, keys):
    """Validate RRSIG records"""
    name = response.question[0].name
    rrs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, qtype)
    rrsigs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, rdt.RRSIG, qtype)
    if keys is not None:
        dns.dnssec.validate(rrs, rrsigs, keys)


def get_records(host, port, ca, qname, stype, keys=None):
    """Get a set of DNS records"""
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
    qtype = rdt.from_text(stype)
    with requests.sessions.Session() as session:
        q = dns.message.make_query(qname, qtype)
        r = dns.query.https(
            q,
            "https://" + host + ":" + str(port) + "/app/dns-query",
            session=session,
            verify=ca,
            post=False,
        )
        if keys:
            validate_rrsigs(r, qtype, keys)
        return r
    return None


def get_keys(host, port, ca, origin):
    """Get DNSKEY records"""
    r = get_records(host, port, ca, origin, "DNSKEY", None)
    try:
        key_rrs = r.find_rrset(r.answer, origin, rdc.IN, rdt.DNSKEY)
    except KeyError:
        print("No DNSKEY records found")
    keys = {origin: key_rrs}
    validate_rrsigs(r, rdt.DNSKEY, keys)
    return keys


def ARecord(s):
    """Parse an A record"""
    return dns.rdata.from_text(rdc.IN, rdt.A, s)


def register_and_ensure(primary, enclave, with_key, with_attestation=None):
    with primary.client(identity="member0") as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("acidns10.attested.name.")
        print("Getting DNSSEC key")
        keys = get_keys(host, port, ca, origin)

        service_name = "test.acidns10.attested.name"
        
        submit_service_registration(
            client,
            service_name,
            "127.0.0.1",
            port,
            "tcp",
            with_key,
            enclave,
            attestation=with_attestation or get_attestation(with_key, enclave),
        )

        print("Checking record is installed")
        check_record(host, port, ca, service_name, "A", ARecord("127.0.0.1"))
        r = get_records(host, port, ca, service_name, "A", keys)
        print(r)


def register_successfully(*args, **kwargs):
    """Expect a function to succeed"""
    try:
        register_and_ensure(*args, **kwargs)
    except Exception as e:
        raise AssertionError(f"FAIL: {e}")

def register_failed(with_error, *args, **kwargs):
    try:
        register_and_ensure(*args, **kwargs)
    except Exception as e:
        if with_error not in str(e):
            raise AssertionError(f"Expected error '{with_error}' but got: {e}")
    else:
        raise AssertionError(f"Expected failure with error '{with_error}' but succeeded")
    

def set_service_registration_policy(network, policy):
    set_policy(network, "set_registration_policy", policy)

def set_service_relying_party_policy(network, enclave, good=True):
    policy = get_service_relying_party_policy(enclave=enclave, good=good)
    print("PATTERN Applying RP policy:\n", policy)
    primary, _ = network.find_primary()
    with primary.client(identity="member0") as client:
        r = client.post(
            "/app/set-service-relying-party-policy",
            {
                "policy": policy,
            },
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT, r

def test_service_reg(network, args):
    """Service registration tests"""
    primary, _ = network.find_primary()

    enclave = args.enclave_platform
    service_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    set_service_registration_policy(network, SERVICE_REGISTRATION_ALLOW_ALL)
    set_service_relying_party_policy(network, enclave, good=True)
    register_successfully(primary, enclave=enclave, with_key=service_key)

    if enclave == "virtual":
        return  # Can't easily manipulate the attestation in a virtual enclave
    
    set_service_relying_party_policy(network, enclave, good=False)
    register_failed("Policy not satisfied", primary, enclave=enclave, with_key=service_key)


def run(args):
    """Run tests"""

    adns_nw, _ = adns_service.run(
        args,
        tcp_port=53,
        udp_port=53,
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    test_service_reg(adns_nw, args)


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
