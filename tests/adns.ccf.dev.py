# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http

import time
import http
import base64
import json

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import infra.interfaces


import dns
import dns.message
import dns.query
import dns.rdatatype as rdt
import dns.rdataclass as rdc

from loguru import logger as LOG

DEFAULT_NODES = ["local://127.0.0.1:8000"]


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/add",
        {
            "origin": origin,
            "record": {
                "name": name,
                "type": int(rdt.from_text(stype)),
                "class_": int(rdc.IN),
                "ttl": 3600,
                "rdata": base64.urlsafe_b64encode(rdata_obj.to_wire()).decode(),
            },
        },
    )
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


def populate_adns_ccf_dev(network, args):
    """Populate the adns.ccf.dev. zone"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = "adns.ccf.dev."

        rd = dns.rdata.from_text(
            rdc.IN,
            rdt.SOA,
            "ns1.adns.ccf.dev. some-dev.microsoft.com. 4 604800 86400 2419200 604800",
        )
        add_record(client, origin, origin, "SOA", rd)

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


def run(args):
    """Start the network"""

    if args.config_file is not None:
        with open(args.config_file, encoding="utf-8") as f:
            hosts = [
                infra.interfaces.HostSpec.from_json(
                    json.load(f)["network"]["rpc_interfaces"]
                )
            ]
    else:
        hosts = args.node or DEFAULT_NODES
        hosts = [
            infra.interfaces.HostSpec.from_str(node, http2=args.http2) for node in hosts
        ]

    with infra.network.network(
        hosts=hosts,
        binary_directory=args.binary_dir,
        library_directory=args.library_dir,
        dbg_nodes=args.debug_nodes,
    ) as network:
        network.start_and_open(args)
        populate_adns_ccf_dev(network, args)

        LOG.info("Waiting until network is torn down...")
        while True:
            time.sleep(1)


if __name__ == "__main__":

    def add(parser):
        """Add parser"""
        parser.description = "DNS sandboxing for adns.ccf.dev"

        parser.add_argument(
            "-n",
            "--node",
            help=f"List of (local://|ssh://)hostname:port[,pub_hostnames:pub_port]. Default is {DEFAULT_NODES}",
            action="append",
        )

    targs = infra.e2e_args.cli_args(add)

    targs.nodes = infra.e2e_args.min_nodes(targs, f=0)
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns"
    targs.binary_dir = "/data/cwinter/installed/ccf-http2/bin/"

    run(targs)
