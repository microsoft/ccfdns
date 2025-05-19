# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import glob
import http
import time
import base64
import subprocess
import json
import logging
import requests

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
from infra.interfaces import (
    RPCInterface,
    Endorsement,
    EndorsementAuthority,
    HostSpec,
    PRIMARY_RPC_INTERFACE,
)

import dns
import dns.message
import dns.query
import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

from loguru import logger as LOG

import pebble
import adns_tools

DEFAULT_NODES = ["local://127.0.0.1:8080"]

nonzero_mrenclave_policy = """
    let r = true;
    for (const [name, claims] of Object.entries(data.claims)) {
        r &= claims.sgx_claims.report_body.mr_enclave.length == 32 &&
            JSON.stringify(claims.custom_claims.sgx_report_data) != JSON.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
    r == true;
"""
aci_policy = """
    let r = true;
    for (const [name, claims] of Object.entries(data.claims)) {
        r &= claims.reported_tcb.boot_loader == 3 && 
            claims.reported_tcb.microcode > 100 &&
            claims.reported_tcb.snp == 8 &&
            claims.reported_tcb.tee == 0 && 
            claims.guest_svn == 2;
    }
    r == true;
"""


class ServiceCAConfig(dict):
    def __init__(self, name, directory, ca_certificates=[]):
        dict.__init__(
            self, name=name, directory=directory, ca_certificates=ca_certificates
        )
        self.name = name
        self.directory = directory
        self.ca_certificates = ca_certificates


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


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/internal/add",
        {
            "origin": origin,
            "record": {
                "name": name,
                "type": int(rdt.from_text(stype)),
                "class_": int(rdc.IN),
                "ttl": 0 if stype == "SOA" else 86400,
                "rdata": base64.b64encode(rdata_obj.to_wire()).decode(),
            },
        },
    )
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


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

            reginfo["configuration_receipt"] = adns_tools.poll_for_receipt(
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


def populate(network, args):
    """Populate the zone with example entries"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        origin = args.origin

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "51.143.161.224")
        add_record(client, origin, origin, "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.NS, "ns1." + origin)
        add_record(client, origin, origin, "NS", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "51.143.161.224")
        add_record(client, origin, "ns1", "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "1.2.3.4")
        add_record(client, origin, "www", "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "1.2.3.5")
        add_record(client, origin, "www", "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.TXT, "something else")
        add_record(client, origin, "www", "TXT", rd)

        rd = dns.rdata.from_text(
            rdc.IN, rdt.AAAA, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"
        )
        add_record(client, origin, "www", "AAAA", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "51.143.161.224")
        add_record(client, origin, "cwinter", "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.TXT, "some text")
        add_record(client, origin, "cwinter", "TXT", rd)


def start_dns_to_http_proxy(binary, host, port, query_url, network_cert):
    args = [
        binary,
        "-a",
        host,
        "-p",
        port,
        "-r",
        query_url,
        "-v",
        "-v",
        "-l",
        "doh_proxy_" + host + ".log",
        "-C",
        network_cert,
    ]

    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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


def get_endorsed_certs(network, name):
    """Get the endorsed network certificate"""

    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/get-certificate",
            {"service_dns_name": name},
        )

    assert r.status_code == http.HTTPStatus.OK
    chain = json.loads(str(r.body))["certificate"]
    return adns_tools.split_pem(chain)


def wait_for_endorsed_certs(network, name, num_retries=20):
    """Wait until an endorsed network certificate is available"""
    while num_retries > 0:
        try:
            return get_endorsed_certs(network, name)
        except Exception:
            num_retries = num_retries - 1
        time.sleep(1)
    if num_retries == 0:
        raise Exception("Failed to obtain endorsed network certificate")


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


def run(
    args, wait_for_endorsed_cert=False, with_proxies=True, tcp_port=None, udp_port=None
):
    """Start an aDNS server network"""

    service_dns_name = args.adns.origin.strip(".")

    # DoH Proxy is here: https://github.com/aarond10/https_dns_proxy
    # Note: proxy needs: sudo setcap 'cap_net_bind_service=+ep' https_dns_proxy
    doh_proxy_binary = "https_dns_proxy"
    proxy_procs = []

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

        args.adns.node_addresses = args.adns["node_addresses"] = assign_node_addresses(
            network, args.node_addresses, False
        )

        registration_policy = nonzero_mrenclave_policy
        if args.service_type == "ACI":
            registration_policy = aci_policy

        set_policy(network, "set_registration_policy", registration_policy)
        set_policy(network, "set_delegation_policy", nonzero_mrenclave_policy)

        if with_proxies:
            done = []
            for host_spec in network.nodes:
                rpif = host_spec.host.rpc_interfaces[PRIMARY_RPC_INTERFACE]
                rhost, rport = rpif.host, rpif.port
                if rhost not in done:
                    net_cert_path = os.path.join(
                        host_spec.common_dir, "service_cert.pem"
                    )
                    proxy_procs += [
                        start_dns_to_http_proxy(
                            doh_proxy_binary,
                            rhost,
                            "53",
                            "https://" + rhost + ":" + str(rport) + "/app/dns-query",
                            net_cert_path,
                        )
                    ]
                    done += [rhost]

        pif0 = nodes[0].rpc_interfaces[PRIMARY_RPC_INTERFACE]
        base_url = "https://" + pif0.host + ":" + str(pif0.port)

        client_cert = (
            os.path.join(network.common_dir, "user0_cert.pem"),
            os.path.join(network.common_dir, "user0_privk.pem"),
        )

        reginfo = configure(base_url, network.cert_path, args.adns, client_cert)

        endorsed_certs = None
        if wait_for_endorsed_cert:
            endorsed_certs = wait_for_endorsed_certs(
                network, service_dns_name, num_retries=10000
            )

        # TODO: restart the proxy with endorsed_cert?

        LOG.success("Server/network for {} running.", args.adns["origin"])

        if args.wait_forever:
            LOG.info("Waiting forever...")
            while True:
                time.sleep(1)
        else:
            return network, proxy_procs, endorsed_certs, reginfo

    except Exception:
        logging.exception("caught exception")
        if proxy_procs:
            for p in proxy_procs:
                p.kill()

    return None, None, None, None


if __name__ == "__main__":

    def add(parser):
        """Add parser"""
        parser.description = "DNS sandboxing for aDNS networks"

        parser.add_argument(
            "-n",
            "--node",
            help=f"List of (local://|ssh://)hostname:port[,pub_hostnames:pub_port]. Default is {DEFAULT_NODES}",
            action="append",
            default=[],
        )

        parser.add_argument(
            "--service_type",
            help="Type of service to register",
            action="store",
            dest="service_type",
            default="CCF",
        )
        parser.add_argument("--wait-forever", help="Wait forever", action="store_true")

    procs = []

    pebble_args = pebble.Arguments(
        dns_address="ns1.adns.ccf.dev:53",
        wait_forever=False,
        http_port=8080,
        ca_cert_filename="pebble-tls-cert.pem",
        config_filename="pebble.config.json",
    )

    pebble_proc, _, _ = pebble.run_pebble(pebble_args)
    procs += [pebble_proc]
    while not os.path.exists(pebble_args.ca_cert_filename):
        time.sleep(0.25)
    pebble_certs = pebble.ca_certs(pebble_args.mgmt_address)
    pebble_certs += pebble.ca_certs_from_file(pebble_args.ca_cert_filename)

    gargs = infra.e2e_args.cli_args(add)
    gargs.node = ["local://10.1.0.4:8443"]
    gargs.nodes = infra.e2e_args.min_nodes(gargs, f=0)
    gargs.constitution = glob.glob("../tests/constitution/*")
    gargs.package = "libccfdns"
    gargs.proxy_ip = "10.1.0.4"
    gargs.wait_for_endorsed_cert = False
    gargs.fixed_zsk = False
    gargs.ca_certs = pebble_certs
    gargs.email = "cwinter@microsoft.com"

    gargs.adns = {
        "configuration": {
            "origin": "adns.ccf.dev.",
            "soa": str(
                SOA.SOA(
                    rdc.IN,
                    rdt.SOA,
                    mname="ns1." + gargs.origin,
                    rname="some-dev.my-site.com.",
                    serial=4,
                    refresh=604800,
                    retry=86400,
                    expire=2419200,
                    minimum=0,
                )
            ),
            "name": "ns1.adns.ccf.dev.",
            "ip": "51.143.161.224",
            "default_ttl": 86400,
            "signing_algorithm": "ECDSAP384SHA384",
            "digest_type": "SHA384",
            "use_key_signing_key": True,
            "use_nsec3": True,
            "nsec3_hash_algorithm": "SHA1",
            "nsec3_hash_iterations": 3,
            "ca_certs": [],
            "service_ca": {
                "directory": "https://127.0.0.1:1024/dir",
                "ca_certificates": pebble_certs,
            },
        }
    }

    nw = None
    procs = []
    try:
        nw, p, _, _ = run(gargs)
        procs += [p]
    finally:
        if nw:
            nw.stop_all_nodes()
        if procs:
            for p in procs:
                if p:
                    p.kill()
