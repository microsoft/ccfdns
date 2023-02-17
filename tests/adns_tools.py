# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import time
import json

import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import infra.interfaces

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


def poll_for_receipt(network: infra.network.Network, txid):
    """Poll for a receipt of a transaction"""
    primary, _ = network.find_primary()
    with primary.client() as client:
        receipt_url = f"/app/receipt?transaction_id={txid}"
        r = client.get(receipt_url)
        while (
            r.status_code == http.HTTPStatus.ACCEPTED
            or r.status_code == http.HTTPStatus.NOT_FOUND
        ):
            d = int(r.headers["retry-after"] if "retry-after" in r.headers else 3)
            LOG.info(f"waiting {d} seconds before retrying...")
            time.sleep(d)
            r = client.get(receipt_url)
        assert (
            r.status_code == http.HTTPStatus.OK
            or r.status_code == http.HTTPStatus.NO_CONTENT
        )
        return json.loads(str(r.body))
