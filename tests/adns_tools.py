# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time
import requests
import tempfile

from cryptography.hazmat.primitives import serialization

from loguru import logger as LOG


def pk_to_pem(x):
    """"""
    return x.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def cert_to_pem(x):
    """"""
    return x.public_bytes(serialization.Encoding.PEM).decode("ascii")


def split_pem(pem):
    r = []
    begin = "-----BEGIN "
    items = pem.split(begin)
    for item in items[1:]:
        r += [begin + item]
    return r


class NoReceiptException(Exception):
    pass


def write_ca_bundle(certs):
    r = tempfile.NamedTemporaryFile(delete=False)
    for cert in certs:
        r.write(cert.encode("ascii"))
        r.write(b"\n")
    r.close()
    return r.name


def poll_for_receipt(base_url, cabundle, txid):
    """Poll for a receipt of a transaction"""

    receipt_url = f"{base_url}/app/receipt?transaction_id={txid}"
    r = requests.get(receipt_url, timeout=10, verify=cabundle)
    while (
        r.status_code == http.HTTPStatus.ACCEPTED
        or r.status_code == http.HTTPStatus.NOT_FOUND
    ):
        if r.status_code == http.HTTPStatus.NOT_FOUND:
            b = r.json()
            if (
                "error" in b
                and "code" in b["error"]
                and b["error"]["code"] != "TransactionPendingOrUnknown"
            ):
                LOG.error(b)
                raise NoReceiptException()
        d = int(r.headers["retry-after"] if "retry-after" in r.headers else 3)
        LOG.info(f"waiting {d} seconds before retrying...")
        time.sleep(d)
        r = requests.get(receipt_url, timeout=10, verify=cabundle)
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    return r.json()
