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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import sha256
from adns_service import aDNSConfig, set_policy
from pycose.messages import Sign1Message  # type: ignore
import cbor2
from cwt import COSE, COSEKey

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


def get_container_group_snp_endorsements_base64():
    security_context_dir = infra.snp.get_security_context_dir()
    return open(
        os.path.join(
            security_context_dir, infra.snp.ACI_SEV_SNP_FILENAME_REPORT_ENDORSEMENTS
        ),
        "r",
        encoding="utf-8",
    ).read()


def get_attestation_format(enclave):
    return "Insecure_Virtual" if enclave == "virtual" else "AMD_SEV_SNP_v1"


def get_dummy_attestation(report_data):
    measurement = base64.b64encode(
        b"Insecure hard-coded virtual measurement v1"
    ).decode()
    attestation = {
        "measurement": measurement,
        "report_data": base64.b64encode(report_data).decode(),
    }
    return bytes(json.dumps(attestation).encode())


def get_host_data_base64():
    security_policy = infra.snp.get_container_group_security_policy()
    return base64.b64encode(sha256(security_policy.encode()).digest()).decode()


def get_snp_attestation(report_data):
    result = subprocess.run(
        [os.environ.get("SNP_REPORT_BINARY"), report_data.hex()],
        check=True,
        capture_output=True,
    )

    return bytes.fromhex(result.stdout.decode())


def get_attestation(report_data, enclave, as_json=True):
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

    if as_json:
        attestation = base64.b64encode(attestation).decode()
        return json.dumps(
            {
                "quote": attestation,
                "uvm_endorsements": uvm_endorsements,
                "endorsements": endorsements,
                "format": get_attestation_format(enclave),
            }
        )

    uvm_endorsements = base64.b64decode(uvm_endorsements)

    return cbor2.dumps(
        {
            "att": attestation,
            "eds": endorsements,
            "uvm": uvm_endorsements,
        }
    )


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


PHDR_ALG = 1
ALG_ES256 = -7

# CWT Claims (RFC9597) defined in https://www.iana.org/assignments/cwt/cwt.xhtml
PHDR_CWT = 15

CWT_ISS = 1
CWT_SUB = 2
CWT_CNF = 8

# Key representation for CNF https://www.rfc-editor.org/rfc/rfc8747.html#section-3.2
CNF_KTY = 1
CNF_CRV = -1
CNF_X = -2
CNF_Y = -3

# Other claims
CWT_ATT = "att"  # (AT)testation (T)ype
CWT_SVI = "svi"  # (S)er(V)ice (I)nformation


def cose_register_service_request(
    name, address, port, protocol, service_key, enclave, attestation
):
    pkey_data = service_key.public_key().public_numbers()
    assert pkey_data.curve.name == "secp256r1", "Only supporting secp256r1 keys"

    phdr = {
        PHDR_ALG: ALG_ES256,
        PHDR_CWT: {
            CWT_ISS: name,
            CWT_CNF: {
                CNF_KTY: 2,  # EC2 key type
                CNF_CRV: 1,  # P-256 curve
                CNF_X: pkey_data.x.to_bytes(32, "big"),
                CNF_Y: pkey_data.y.to_bytes(32, "big"),
            },
            CWT_ATT: get_attestation_format(enclave),
            CWT_SVI: {
                "ipv4": address,
                "port": str(port),
                "protocol": protocol,
            },
        },
    }

    pem_key = service_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cose_key = COSEKey.from_pem(pem_key)

    cose = COSE.new()
    return cose.encode_and_sign(
        protected=phdr, unprotected={}, payload=attestation, key=cose_key
    )


def submit_service_registration(
    client, name, address, port, protocol, service_key, enclave_platform, attestation
):
    """Submit a service registration request"""

    reg_request = cose_register_service_request(
        name, address, port, protocol, service_key, enclave_platform, attestation
    )

    r = client.post(
        "/app/register-service",
        body=reg_request,
        headers={"Content-Type": "application/cose"},
    )

    if r.status_code != http.HTTPStatus.OK:
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


def get_uvm_endorsements(network):
    primary, _ = network.find_primary()
    with primary.api_versioned_client(
        identity="member0", api_version="2024-07-01"
    ) as client:
        r = client.get("/gov/service/join-policy")
        assert r.status_code == http.HTTPStatus.OK, r

        uvm_endorsements = r.body.json()["snp"]["uvmEndorsements"]
        assert (
            len(uvm_endorsements) == 1
        ), f"Expected one UVM endorsement, {uvm_endorsements}"

        did, value = next(iter(uvm_endorsements.items()))
        feed, data = next(iter(value.items()))
        svn = data["svn"]

        return did, feed, svn


def register_and_ensure(
    primary, enclave, service_name, with_key, with_attestation=None
):
    with primary.client(identity="member0") as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("acidns10.attested.name.")
        print("Getting DNSSEC key")
        keys = get_keys(host, port, ca, origin)

        public_key = with_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        report_data = sha256(public_key).digest()

        submit_service_registration(
            client,
            service_name,
            "127.0.0.1",
            port,
            "tcp",
            with_key,
            enclave,
            attestation=with_attestation
            or get_attestation(report_data, enclave, as_json=False),
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
        raise AssertionError(
            f"Expected failure with error '{with_error}' but succeeded"
        )


def create_service_definition_auth(network, permissive=True):
    did, feed, svn = get_uvm_endorsements(network)
    if not permissive:
        svn = int(svn) + 1

    return f"""
package policy

default allow := false

allow_iss if {{
    input.iss == "{did}"
}}

allow_sub if {{
    input.sub == "{feed}"
}}

allow_svn if {{
    input.svn
    input.svn >= {svn}
}}

allow if {{
    allow_iss
    allow_sub
    allow_svn
}}
"""


def create_platform_definition_auth(network, permissive=True):
    did, feed, svn = get_uvm_endorsements(network)
    if not permissive:
        svn = int(svn) + 1

    return f"""
package policy

default allow := false

allow_iss if {{
    input.iss == "{did}"
}}

allow_sub if {{
    input.sub == "{feed}"
}}

allow_svn if {{
    input.svn
    input.svn >= {svn}
}}

allow if {{
    allow_iss
    allow_sub
    allow_svn
}}
"""


def set_service_definition_auth(network, policy):
    set_policy(network, "set_service_definition_auth", policy)


def set_platform_definition_auth(network, policy):
    set_policy(network, "set_platform_definition_auth", policy)


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


def set_service_definition_successfully(*args, **kwargs):
    set_service_definition(*args, **kwargs)


def set_service_definition_failed(with_error, *args, **kwargs):
    try:
        set_service_definition(*args, **kwargs)
    except Exception as e:
        if with_error not in str(e):
            raise AssertionError(f"Expected error '{with_error}' but got: {e}")
    else:
        raise AssertionError(
            f"Expected failure with error '{with_error}' but succeeded"
        )


def set_platform_definition_successfully(*args, **kwargs):
    set_platform_definition(*args, **kwargs)


def set_platform_definition_failed(with_error, *args, **kwargs):
    try:
        set_platform_definition(*args, **kwargs)
    except Exception as e:
        if with_error not in str(e):
            raise AssertionError(f"Expected error '{with_error}' but got: {e}")
    else:
        raise AssertionError(
            f"Expected failure with error '{with_error}' but succeeded"
        )


def test_service_registration(network, args):
    """Service registration tests"""
    primary, _ = network.find_primary()

    enclave = args.enclave_platform
    service_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    set_service_definition_auth(network, SERVICE_REGISTRATION_AUTH_ALLOW_ALL)
    set_platform_definition_auth(network, PLATFORM_DEFINITION_AUTH_ALLOW_ALL)

    set_service_definition_successfully(
        network, enclave, service_name="test.acidns10.attested.name.", permissive=True
    )
    set_platform_definition_successfully(
        network, enclave, platform=get_attestation_format(enclave), permissive=True
    )

    register_successfully(
        primary,
        enclave=enclave,
        service_name="test.acidns10.attested.name.",
        with_key=service_key,
    )

    if args.enclave_platform == "virtual":
        return

    # Different service name should fail, no policy for it.
    register_failed(
        "no service relying party policy",
        primary,
        enclave=enclave,
        service_name="another.acidns10.attested.name.",
        with_key=service_key,
    )

    # Register under wrong service registration policy (modified host data, aka security policy).
    set_service_definition_successfully(
        network, enclave, service_name="test.acidns10.attested.name.", permissive=False
    )
    set_platform_definition_successfully(
        network, enclave, platform=get_attestation_format(enclave), permissive=True
    )
    register_failed(
        "Policy not satisfied",
        primary,
        enclave=enclave,
        service_name="test.acidns10.attested.name.",
        with_key=service_key,
    )

    # Register under wrong platform registration policy (modified host data, aka security policy).
    set_service_definition_successfully(
        network, enclave, service_name="test.acidns10.attested.name.", permissive=True
    )
    set_platform_definition_successfully(
        network, enclave, platform=get_attestation_format(enclave), permissive=False
    )
    register_failed(
        "Policy not satisfied",
        primary,
        enclave=enclave,
        service_name="test.acidns10.attested.name.",
        with_key=service_key,
    )


def test_policy_registration(network, args):
    # Test with a proper service registration policy which checks UVM endorsements.
    set_service_definition_auth(
        network, create_service_definition_auth(network, permissive=True)
    )
    set_service_definition_successfully(
        network,
        enclave=args.enclave_platform,
        service_name="test.acidns10.attested.name.",
    )

    # Test with incremented SVN to ensure current UVM endorsements are not accepted when setting new relying party policy.
    set_service_definition_auth(
        network, create_service_definition_auth(network, permissive=False)
    )
    set_service_definition_failed(
        "Policy not satisfied",
        network,
        enclave=args.enclave_platform,
        service_name="test.acidns10.attested.name.",
    )

    # Same for platform relying party policy.
    set_platform_definition_auth(
        network, create_platform_definition_auth(network, permissive=True)
    )

    set_platform_definition_successfully(
        network,
        enclave=args.enclave_platform,
        platform=get_attestation_format(args.enclave_platform),
    )

    set_platform_definition_auth(
        network, create_platform_definition_auth(network, permissive=False)
    )
    set_platform_definition_failed(
        "Policy not satisfied",
        network,
        enclave=args.enclave_platform,
        platform=get_attestation_format(args.enclave_platform),
    )


def run(args):
    """Run tests"""

    adns_nw, _ = adns_service.run(
        args,
        tcp_port=53,
        udp_port=53,
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    test_service_registration(adns_nw, args)

    if args.enclave_platform != "virtual":
        test_policy_registration(adns_nw, args)


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
