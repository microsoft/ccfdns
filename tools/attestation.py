# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.


import json
import snp_pytools
import cwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cwt import COSE, COSEKey
from didx509.didx509 import resolve_did


def get_issuer_cn(cert):
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return issuer_cn
    except (IndexError, AttributeError):
        return None


def get_platform(*certs):
    platform = None
    for cert in certs:
        cert_platform = get_issuer_cn(cert).split("-")[1]
        platform = platform or cert_platform
        assert platform == cert_platform

    return platform


def check_signing_root(ark):
    """Currently Milan only"""

    amd_milan_root_trusted = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----"""

    amd_genoa_root_trusted = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9
VDBF69NDQF79oRhL/L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7Ldjc
RfKXjHl+0Qq/M4dZkh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P9
4tKXLp80oxt84ahyHoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSr
u92vJhlqWO27d/Rxc3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpW
g2DF6SwF0IgVMffnvtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89H
JSp8YbY9lySS6PlVEqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDn
mlA2SFfJ/Cc0mGNzW9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA
+y9edvhDCbOG8F2oxHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr
0f8QMKklIS5ruOfqlLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eX
HP1qYrnvhzaG1S70vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg8
0Hq/sbRuqesxz7wBWSY254cCAwEAAQ==
-----END PUBLIC KEY-----"""

    pkey = ark.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    for pkey_candidate in [amd_milan_root_trusted, amd_genoa_root_trusted]:
        if pkey.decode().strip() == pkey_candidate.strip():
            return

    assert False, "Unrecognized ARK root key"


def get_verified_descriptor(uvm_endorsements):
    decoded = cwt.cbor_processor.loads(uvm_endorsements)
    phdr = cwt.cbor_processor.loads(decoded.value[0])
    raw_chain = phdr[33]  # x5chain claim
    cert_chain = [
        x509.load_der_x509_certificate(cert_bytes, default_backend())
        for cert_bytes in raw_chain
    ]

    did = resolve_did(phdr["iss"], cert_chain, True)
    jwk = did["verificationMethod"][0]["publicKeyJwk"]

    # The resolved JWK presumably uses sha384, but doesn't set it.
    # At the moment PoC seems using sha384 with PSS padding, which is PS384.
    assert cert_chain[0].signature_hash_algorithm.name == "sha384"
    jwk["alg"] = "PS384"

    pkey = COSEKey.from_jwk(jwk)

    cose = COSE().new()
    # This verifies the signature
    phdr, _, payload = cose.decode_with_headers(uvm_endorsements, pkey)

    feed = phdr["feed"]
    svn = json.loads(payload)["x-ms-sevsnpvm-guestsvn"]
    measurement = json.loads(payload)["x-ms-sevsnpvm-launchmeasurement"]

    return did, feed, svn, measurement


def verify_snp_attestation(attestation, endorsements, uvm_endorsements):
    # ARK -> ASK chain
    cert_chain = json.loads(endorsements)
    ask, ark = x509.load_pem_x509_certificates(cert_chain["certificateChain"].encode())

    # Leaf (VCEK)
    vcek = x509.load_pem_x509_certificate(
        cert_chain["vcekCert"].encode(), default_backend()
    )

    product_name = get_platform(ark, ask, vcek)

    certificates = {"ark": ark, "ask": ask, "vcek": vcek}
    report, _, _ = snp_pytools.verify_attestation_bytes(
        attestation,
        processor_model=product_name,
        certificates=certificates,
        certificates_path="ca",
    )

    check_signing_root(ark)

    did, feed, svn, measurement = get_verified_descriptor(uvm_endorsements)
    assert report.measurement.hex() == measurement

    return product_name, report, did, feed, svn
