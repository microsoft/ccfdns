import argparse
import requests
import base64
import time
import json
from http import HTTPStatus
from tools.attestation import verify_snp_attestation
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import sha256
import dns


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


def fetch_adns_ksk_from_receipt(adns_url):
    import subprocess

    def request():
        result = subprocess.run(
            [
                "curl",
                "-sk",
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
    ksk_digest = receipt["leaf_components"]["claims_digest"]
    return ksk_digest


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--adns",
        default=None,
        help="ADNS address",
    )
    args = parser.parse_args()

    # KSK from ADNS point of view
    ksk_dns = poll_ksk_from_adns(args.adns, "acidns10.attested.name.")

    # KSK signed by CCF node (TX receipt)
    ksk_ccf = fetch_adns_ksk_from_receipt(args.adns)

    # They have to match
    assert ksk_dns == ksk_ccf, f"KSK mismatch: {ksk_dns} != {ksk_ccf}"

    # Signing node attestation
    attestation, endorsements, uvm_endorsements = convert_inputs(
        *fetch_adns_attestation(args.adns)
    )
    verify_snp_attestation(attestation, endorsements, uvm_endorsements)

    print("Verified aDNS KSK and attestation")


if __name__ == "__main__":
    main()
