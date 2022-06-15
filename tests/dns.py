# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import glob
from syslog import LOG_LOCAL0
import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

from loguru import logger as LOG


def mk_question(address):
    """Create a DNS question"""
    res = bytearray()
    labels = address.split(".")
    for label in labels:
        length = label[0]
        for i in range(length):
            res += label[i + 1]
    res = address.encode("ascii")
    return base64.urlsafe_b64encode(res).decode("ascii")


def test_basic(network, args):
    """Basic tests"""
    network.save_service_identity(args)
    primary, _ = network.find_primary()

    with primary.client() as client:
        client.post(
            "/app/update",
            {
                "name": "example.com",
                "zone": {
                    "entries": [{"name": "www", "type": "A", "data": "93.184.216.34"}]
                },
            },
        )
        client.get("/app/zone?name=example.com")

        # b64dns = mk_question("example.com")
        # client.get(f"/app/dns-query?dns={b64dns}")

        response = client.get(
            "/app/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
            log_capture=[],
        )
        print(f"Body data: {response.body.data().hex()}")


def run(args):
    """Run tests"""
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_basic(network, args)


if __name__ == "__main__":

    def add(parser):
        """Add parser"""
        parser.description = "DNS tests"

    targs = infra.e2e_args.cli_args(add)

    targs.nodes = infra.e2e_args.min_nodes(targs, f=0)
    targs.binary_dir = "/data/cwinter/installed/ccf/bin"
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns"

    run(targs)
