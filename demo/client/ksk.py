import argparse
import requests
import base64
import time
import json
import tempfile
from http import HTTPStatus
from tools.attestation import verify_snp_attestation
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from hashlib import sha256
import dns
from regopy import Interpreter
import struct
import subprocess
from ccf.receipt import root as reconstruct_root
from ccf.receipt import verify as verify_receipt_ccf


def poll_ksk_dns(host, dns_name):
    import dns.query
    import dns.message

    q = dns.message.make_query(dns_name, "DNSKEY")
    return dns.query.https(
        q,
        f"https://{host}/app/dns-query",
        verify=False,
        post=False,
    )


def poll_receipt(cb, num_retries=10):
    r = cb()
    while r.status_code != HTTPStatus.OK and num_retries > 0:
        time.sleep(1)
        num_retries -= 1
        r = cb()

    assert r.status_code == HTTPStatus.OK
    return r.json()


def fetch_adns_attestation(adns_url):
    response = requests.get(f"https://{adns_url}/node/quotes", verify=False)
    assert response.status_code == HTTPStatus.OK

    nodes = response.json()["quotes"]
    assert len(nodes) == 1, "One node expected"

    endorsements = nodes[0]["endorsements"]
    raw = nodes[0]["raw"]
    uvm_endorsements = nodes[0]["uvm_endorsements"]

    return raw, endorsements, uvm_endorsements


def extract_ksk_digest(keys):
    ksk = next((k for k in keys if k.flags == 257), None)
    assert ksk is not None, "No KSK (flag 257) found in DNSKEY records"
    assert ksk.algorithm == 14, f"Expected P-384 algorithm (14), got {ksk.algorithm}"
    assert len(ksk.key) == 96, f"Expected 96 bytes for P-384 key, got {len(ksk.key)}"

    # Save KSK in base64 format to file
    ksk_b64 = base64.b64encode(ksk.key).decode()
    with open("ksk.pinned", "w") as f:
        f.write(ksk_b64)

    # Convert P-384 key to DER format and hash
    x = int.from_bytes(ksk.key[:48], "big")
    y = int.from_bytes(ksk.key[48:], "big")
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key(
        default_backend()
    )
    der = pk.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sha256(der).hexdigest()


def verify_receipt(receipt, attested_node_key_digest):
    node_cert = x509.load_pem_x509_certificate(receipt["cert"].encode())
    node_key = node_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    node_key_digest = sha256(node_key).hexdigest()

    assert (
        node_key_digest == attested_node_key_digest
    ), f"Node key mismatch: {node_key_digest} != {attested_node_key_digest}"

    claims = bytes.fromhex(receipt["leaf_components"]["claims_digest"])
    ce_digest = sha256(receipt["leaf_components"]["commit_evidence"].encode()).digest()
    leaf = (
        sha256(
            bytes.fromhex(receipt["leaf_components"]["write_set_digest"])
            + ce_digest
            + claims
        )
        .digest()
        .hex()
    )

    root = reconstruct_root(leaf, receipt["proof"])
    verify_receipt_ccf(root, receipt["signature"], node_cert)


def get_server_cert(url):
    """Get server certificate using openssl s_client"""
    import subprocess

    cmd = ["openssl", "s_client", "-connect", url]

    result = subprocess.run(cmd, input="", text=True, capture_output=True, timeout=10)

    # Extract certificate from output
    cert_start = result.stdout.find("-----BEGIN CERTIFICATE-----")
    cert_end = result.stdout.find("-----END CERTIFICATE-----") + len(
        "-----END CERTIFICATE-----"
    )

    if cert_start != -1 and cert_end > cert_start:
        cert_pem = result.stdout[cert_start:cert_end]
        return cert_pem


def fetch_adns_ksk_receipt(adns_url):
    # To provide freshness, using the server TLS certificate when polling the receipt.
    server_cert_pem = get_server_cert(adns_url)
    server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode())
    tls_key_digest = sha256(
        server_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(server_cert_pem)
        cert_file = f.name

    def request():
        result = subprocess.run(
            [
                "curl",
                "-s",
                "--cacert",
                cert_file,
                "-w%{http_code}",
                "-XGET",
                '-d{"zone": "acidns10.attested.name."}',
                "-HContent-Type: application/json",
                f"https://{adns_url}/app/ksk-receipt",
            ],
            capture_output=True,
            text=True,
        )

        class MockResponse:
            def __init__(self, code, text):
                self.status_code, self.text = code, text

            def json(self):
                return json.loads(self.text)

        return MockResponse(int(result.stdout[-3:]), result.stdout[:-3])

    receipt = poll_receipt(request)
    return receipt, tls_key_digest


def poll_ksk_from_adns(adns_url, dns_name):
    dns_response = poll_ksk_dns(adns_url, dns_name)
    dns_name = dns.name.from_text(dns_name)
    keys = dns_response.find_rrset(
        dns_response.answer, dns_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )

    return extract_ksk_digest(keys)


def convert_inputs(attestation, endorsements, uvm_endorsements):
    attestation = base64.b64decode(attestation)
    endorsements = base64.b64decode(endorsements)
    uvm_endorsements = base64.b64decode(uvm_endorsements)

    # Certs reorg
    certs = endorsements.decode().split("-----END CERTIFICATE-----\n")[:-1]
    vcek_cert = certs[0] + "-----END CERTIFICATE-----\n"
    cert_chain = "".join(cert + "-----END CERTIFICATE-----\n" for cert in certs[1:])
    endorsements = json.dumps(
        {"vcekCert": vcek_cert, "certificateChain": cert_chain}
    ).encode()

    return attestation, endorsements, uvm_endorsements


PLATFORM_POLICY = """
    package policy
    default allow := false

    product_name_valid if {
        input.attestation.product_name == "Milan"
    }
    reported_tcb_valid if {
        input.attestation.reported_tcb.hexstring == "04000000000018db"
    }
    amd_tcb_valid if {
        product_name_valid
        reported_tcb_valid
    }

    uvm_did_valid if {
        input.attestation.uvm_endorsements.did == "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2"
    }
    uvm_feed_valid if {
        input.attestation.uvm_endorsements.feed == "ContainerPlat-AMD-UVM"
    }
    uvm_svn_valid if {
        input.attestation.uvm_endorsements.svn >= "101"
    }
    uvm_valid if {
        uvm_did_valid
        uvm_feed_valid
        uvm_svn_valid
    }

    allow if {
        amd_tcb_valid
        uvm_valid
    }
"""


SERVICE_POLICY = """
    package policy
    default allow := false

    host_data_valid if {
        input.attestation.host_data == "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10"
    }

    allow if {
        host_data_valid
    }
"""


def pack_tcb(tcb):
    return struct.pack(
        "<BB4sBB", tcb.bootloader, tcb.tee, tcb._reserved, tcb.snp, tcb.microcode
    )


def check_policy(policy, policy_input):
    rego = Interpreter(v1_compatible=True)
    rego.add_module("policy", policy)
    rego.set_input(policy_input)
    allow = rego.query("data.policy.allow")
    assert allow.results[0].expressions[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--adns",
        default=None,
        help="ADNS address",
    )
    args = parser.parse_args()

    # 1. Check server is running on a valid platform

    attestation, endorsements, uvm_endorsements = convert_inputs(
        *fetch_adns_attestation(args.adns)
    )
    product_name, report, did, feed, svn = verify_snp_attestation(
        attestation, endorsements, uvm_endorsements
    )
    platform_policy_input = {
        "attestation": {
            "product_name": product_name,
            "reported_tcb": {
                "hexstring": pack_tcb(report.reported_tcb).hex(),
            },
            "uvm_endorsements": {
                "did": did["id"],
                "feed": feed,
                "svn": svn,
            },
        }
    }
    check_policy(PLATFORM_POLICY, platform_policy_input)

    # 2. Check server is running a valid service code

    service_policy_input = {
        "attestation": {
            "host_data": report.host_data.hex(),
        }
    }
    check_policy(SERVICE_POLICY, service_policy_input)

    # 3. Fetch signed KSK from server and verify it against the attestation

    receipt, tls_key_digest = fetch_adns_ksk_receipt(args.adns)
    attested_node_key_digest = report.report_data[0:32]
    assert tls_key_digest == tls_key_digest

    verify_receipt(receipt, attested_node_key_digest.hex())

    # 4. DNS-resolved KSK matches the attested KSK

    ksk_dns = poll_ksk_from_adns(args.adns, "acidns10.attested.name.")
    ksk_digest = receipt["leaf_components"]["claims_digest"]

    assert ksk_dns == ksk_digest, f"KSK mismatch: {ksk_dns} != {ksk_digest}"

    print("Verified zone KSK is created and owned by a valid ADNS instance")


if __name__ == "__main__":
    main()
