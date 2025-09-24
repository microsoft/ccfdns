# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import json
import infra.network
from infra.interfaces import (
    RPCInterface,
    Endorsement,
    EndorsementAuthority,
    HostSpec,
    PRIMARY_RPC_INTERFACE,
)


AUTH_POLICY_ALLOW_ALL = """
package policy
default allow := true
"""


class NoReceiptException(Exception):
    pass


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


def set_configuration(network, config):
    primary, _ = network.find_primary()

    proposal_body, careful_vote = network.consortium.make_proposal(
        "set_configuration", new_config=config
    )

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )


def set_auth_policy(network, key, policy):
    primary, _ = network.find_primary()

    proposal_body, careful_vote = network.consortium.make_proposal(
        key, new_policy=policy
    )

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )


def set_initial_auth(network):
    set_auth_policy(network, "set_service_definition_auth", AUTH_POLICY_ALLOW_ALL)
    set_auth_policy(network, "set_platform_definition_auth", AUTH_POLICY_ALLOW_ALL)


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

    args.adns.node_addresses = args.adns["node_addresses"] = assign_node_addresses(
        network, args.node_addresses, False
    )

    set_configuration(network, json.dumps(args.adns))
    set_initial_auth(network)

    primary, _ = network.find_primary()
    with primary.client(identity="member0") as client:
        r = client.post("/app/configure")
        assert r.status_code == http.HTTPStatus.OK, r

    return network
