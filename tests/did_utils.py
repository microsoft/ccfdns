# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from hashlib import sha256


class Issuer:
    def __init__(self, did, certs, private_key):
        self.did = did
        self.certs = certs
        self.private_key = private_key


def create_issuer(chain_length=2):
    assert chain_length > 1

    certs = []
    private_keys = []
    eku = "1.3.6.1.5.5.7.3.36"

    for i in range(chain_length):
        is_root = i == 0
        is_leaf = i == chain_length - 1

        # Generate private key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_keys.append(private_key)

        # Create certificate
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    (
                        "Root CA"
                        if is_root
                        else (
                            f"Intermediate CA {i}"
                            if not is_leaf
                            else "Leaf Certificate"
                        )
                    ),
                ),
            ]
        )

        issuer_name = subject if is_root else certs[-1].subject
        signing_key = private_key if is_root else private_keys[i - 1]

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
        )

        # Add extensions in the pattern you specified
        subject_pub_key = private_key.public_key()
        issuer_key = private_key if is_root else private_keys[i - 1]

        cert = (
            cert.add_extension(
                x509.KeyUsage(
                    digital_signature=not is_root,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=is_root,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=is_root, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(subject_pub_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]), critical=False
            )
        )

        cert = cert.sign(signing_key, hashes.SHA256(), default_backend())
        certs.append(cert)

    root_cert_der = certs[0].public_bytes(serialization.Encoding.DER)
    fingerprint = sha256(root_cert_der).digest()
    fingerprint_b64url = base64.urlsafe_b64encode(fingerprint).decode().rstrip("=")

    did_issuer = f"did:x509:0:sha256:{fingerprint_b64url}::eku:{eku}"
    root_private_key = private_keys[0]

    certs.reverse()
    return Issuer(did_issuer, certs, root_private_key)
