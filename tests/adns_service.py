# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import http
import time
import json
import logging
import requests
import infra.network
from infra.interfaces import (
    RPCInterface,
    Endorsement,
    EndorsementAuthority,
    HostSpec,
    PRIMARY_RPC_INTERFACE,
)
from loguru import logger as LOG

DEFAULT_NODES = ["local://127.0.0.1:8080"]


class NoReceiptException(Exception):
    pass


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


class aDNSConfig(dict):
    """aDNS arguments"""

    def __init__(
        self,
        origin,
        service_name,
        node_addresses,
        soa,
        default_ttl,
        signing_algorithm,
        digest_type,
        use_key_signing_key,
        use_nsec3,
        nsec3_hash_algorithm,
        nsec3_hash_iterations,
        nsec3_salt_length,
    ):
        dict.__init__(
            self,
            origin=origin,
            service_name=service_name,
            node_addresses=node_addresses,
            soa=soa,
            default_ttl=default_ttl,
            signing_algorithm=signing_algorithm,
            digest_type=digest_type,
            use_key_signing_key=use_key_signing_key,
            use_nsec3=use_nsec3,
            nsec3_hash_algorithm=nsec3_hash_algorithm,
            nsec3_hash_iterations=nsec3_hash_iterations,
            nsec3_salt_length=nsec3_salt_length,
        )
        self.origin = origin
        self.service_name = service_name
        self.node_addresses = node_addresses
        self.soa = soa
        self.default_ttl = default_ttl
        self.signing_algorithm = signing_algorithm
        self.digest_type = digest_type
        self.use_key_signing_key = use_key_signing_key
        self.use_nsec3 = use_nsec3
        self.nsec3_hash_algorithm = nsec3_hash_algorithm
        self.nsec3_hash_iterations = nsec3_hash_iterations
        self.nsec3_salt_length = nsec3_salt_length


DEFAULT_C_ACI_POLICY = """
package policy

default allow := false

allow_svn if {
    input.svn >= 101
    input.svn != null
}

allow if {
    allow_svn
}
"""


def configure(base_url, cabundle, config, client_cert=None, num_retries=1):
    """Configure an aDNS service"""

    while num_retries > 0:
        try:
            url = base_url + "/app/configure"

            LOG.info(
                "Calling /app/configure with config:" + json.dumps(config, indent=2)
            )

            r = requests.post(
                url,
                json.dumps(config),
                timeout=60,
                verify=cabundle,
                headers={"Content-Type": "application/json"},
                cert=client_cert,
            )

            LOG.info("Resonse:" + json.dumps(r.json(), indent=2))
            ok = (
                r.status_code == http.HTTPStatus.OK
                or r.status_code == http.HTTPStatus.NO_CONTENT
            )
            if not ok:
                LOG.info(r.text)
            assert ok
            reginfo = r.json()["registration_info"]
            assert "x-ms-ccf-transaction-id" in r.headers

            reginfo["configuration_receipt"] = poll_for_receipt(
                base_url, cabundle, r.headers["x-ms-ccf-transaction-id"]
            )
            return reginfo
        except Exception as ex:
            logging.exception("caught exception")
            num_retries = num_retries - 1
            if num_retries == 0:
                raise ex
            else:
                n = 10
                LOG.error(f"Configuration failed; retrying in {n} seconds.")
                time.sleep(n)
    return None


def set_policy(network, proposal_name, policy):
    primary, _ = network.find_primary()

    proposal_body, careful_vote = network.consortium.make_proposal(
        proposal_name, new_policy=policy
    )

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )


def assign_node_addresses(network, addr, add_node_id=True):
    """Assign shortened node IDs as node names"""
    node_addresses = {}
    for node in network.nodes:
        for _, _, ext_name, ext_ip in addr:
            ext_if = node.host.rpc_interfaces["ext_if"]
            if ext_if.public_host == ext_name:
                name = ext_name
                if add_node_id:
                    name = node.node_id[:12] + "." + name
                node_addresses[node.node_id] = {
                    "name": name + ".",
                    "ip": ext_ip,
                    "protocol": ext_if.transport,
                    "port": ext_if.public_port,
                }
    return node_addresses


def run(args, tcp_port=None, udp_port=None):
    """Start an aDNS server network"""

    try:
        nodes = []
        for internal, external, ext_name, _ in args.node_addresses:
            host_spec: dict[str, RPCInterface] = {}
            int_if = RPCInterface()
            int_if.parse_from_str(internal)
            int_if.forwarding_timeout_ms = 10000
            host_spec[PRIMARY_RPC_INTERFACE] = int_if

            ext_if = RPCInterface()
            ext_if.parse_from_str(external)
            ext_if.forwarding_timeout_ms = 10000
            ext_if.public_host = ext_name
            ext_if.public_port = ext_if.port

            host_spec["ext_if"] = ext_if

            if tcp_port:
                tcp_dns_if = RPCInterface(
                    host=ext_if.host,
                    port=tcp_port,
                    transport="tcp",
                    endorsement=Endorsement(authority=EndorsementAuthority.Unsecured),
                    app_protocol="DNSTCP",
                )
                host_spec["tcp_dns_if"] = tcp_dns_if
            if udp_port:
                udp_dns_if = RPCInterface(
                    host=ext_if.host,
                    port=udp_port,
                    transport="udp",
                    endorsement=Endorsement(authority=EndorsementAuthority.Unsecured),
                    app_protocol="DNSUDP",
                )
                host_spec["udp_dns_if"] = udp_dns_if

            nodes += [HostSpec(rpc_interfaces=host_spec)]

        network = infra.network.Network(
            nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            library_dir=args.library_dir,
        )
        network.start_and_open(args)

        set_policy(network, "set_registration_policy", DEFAULT_C_ACI_POLICY)

        args.adns.node_addresses = args.adns["node_addresses"] = assign_node_addresses(
            network, args.node_addresses, False
        )

        pif0 = nodes[0].rpc_interfaces[PRIMARY_RPC_INTERFACE]
        base_url = "https://" + pif0.host + ":" + str(pif0.port)

        client_cert = (
            os.path.join(network.common_dir, "user0_cert.pem"),
            os.path.join(network.common_dir, "user0_privk.pem"),
        )

        reginfo = configure(base_url, network.cert_path, args.adns, client_cert)

        return network, reginfo

    except Exception:
        logging.exception("caught exception")

    return None, None
