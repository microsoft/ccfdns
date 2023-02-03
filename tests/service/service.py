import base64
import requests
import sys
import time

import acme
import acme.client
import josepy

import dns
import dns.message
import dns.query
import dns.rdatatype as rdt
import dns.rdataclass as rdc

import platform

is_abc = platform.processor() == ""

if is_abc:
    from sevsnpmeasure import guest
    from sevsnpmeasure import vcpu_types
    from sevsnpmeasure.sev_mode import SevMode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

headers = {"content-type": "application/json"}
origin = "adns.ccf.dev."


def find_dns01_challenge(acme_order):
    authz_list = acme_order.authorizations

    for authz in authz_list:
        for challenge in authz.body.challenges:
            if isinstance(challenge.chall, acme.challenges.DNS01):
                return challenge

    return None


def get_attestation():
    ovmf_path = "/usr/share/OVMF/OVMF.fd"
    kernel_path = ""
    initrd_path = ""
    cmdline_str = ""
    vcpus_num = 1
    if is_abc:
        ld = guest.calc_launch_digest(
            SevMode.SEV_SNP,
            vcpus_num,
            vcpu_types.CPU_SIGS["EPYC-v4"],
            ovmf_path,
            kernel_path,
            initrd_path,
            cmdline_str,
        )
    else:
        ld = bytes()
    print("Measurement:", ld.hex())
    return ld, bytes()


def register(
    name: str,
    ip: str,
    evidence: bytes,
    endorsements: bytes,
    adns_base_url: str,
    public_key_pem: str,
):
    if name[-1] != ".":
        name = name + "."
    data = {
        "origin": origin,
        "name": name,
        "address": ip,
        "attestation": {
            "format": "AMD",
            "evidence": base64.b64encode(evidence).decode(),
            "endorsements": base64.b64encode(endorsements).decode(""),
        },
        "algorithm": "ECDSAP384SHA384",
        "public_key": public_key_pem,
    }
    url = adns_base_url + "/register-service"
    return requests.post(url, headers=headers, json=data, verify=False, timeout=10)


def get_acme_certificate(
    name: str,
    csr: bytes,
    account_private_key: ec.EllipticCurvePrivateKey,
    acme_directory_url: str,
    adns_base_url: str,
    email: str,
):
    certificate = None
    data = None

    if name[-1] != ".":
        name = name + "."

    try:
        jwk = josepy.JWKEC(key=account_private_key)
        network = acme.client.ClientNetwork(key=jwk, verify_ssl=False, alg=josepy.ES384)
        directory = acme.messages.Directory.from_json(
            network.get(acme_directory_url).json()
        )
        acme_client = acme.client.ClientV2(directory=directory, net=network)

        network.account = acme_client.new_account(
            acme.messages.NewRegistration.from_data(
                email=email, terms_of_service_agreed=True
            )
        )

        order = acme_client.new_order(csr.public_bytes(serialization.Encoding.PEM))
        challenge = find_dns01_challenge(order)
        response, validation = challenge.response_and_validation(acme_client.net.key)

        # -> install validation token

        url = adns_base_url + "/internal/add"
        rd = dns.rdata.from_text(rdc.IN, rdt.TXT, validation)
        data = {
            "origin": origin,
            "record": {
                "name": "_acme-challenge." + name,
                "type": 16,
                "class_": 1,
                "ttl": 0,
                "rdata": base64.b64encode(rd.to_wire()).decode(),
            },
        }

        requests.post(url, headers=headers, json=data, verify=False)

        acme_client.answer_challenge(challenge, response)

        finalized_order = acme_client.poll_and_finalize(order)
        certificate = finalized_order.fullchain_pem
    except Exception as ex:
        print(f"Exception: {ex}")
        if hasattr(ex, "failed_authzrs"):
            print(f"Failed authzrs: {ex.failed_authzrs}")
        raise ex
    finally:
        # Remove the challenge TXT record?
        pass

    return certificate


def generate_csr(name: str, private_key: ec.EllipticCurvePrivateKey):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, name),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(name),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA384())
    )


def main(argv):
    account_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    service_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    service_public_key = service_private_key.public_key()
    service_public_key_pem = service_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    acme_directory_url = "https://127.0.0.1:1024/dir"
    # acme_directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
    adns_base_url = "https://adns.ccf.dev:8000/app"
    email = "cwinter@microsoft.com"
    service_name = "service42.adns.ccf.dev"
    ip = open("/etc/ip", "r", encoding="ascii").read()

    evidence, endorsements = get_attestation()
    register(
        service_name,
        ip,
        evidence,
        endorsements,
        adns_base_url,
        service_public_key_pem,
    )
    csr = generate_csr(service_name, service_private_key)
    certificate = get_acme_certificate(
        service_name, csr, account_private_key, acme_directory_url, adns_base_url, email
    )
    with open("app_cert.pem", "w", encoding="ascii") as cf:
        cf.write(certificate)
    print(f"Certificate: {certificate}")


if __name__ == "__main__":
    main(sys.argv)
