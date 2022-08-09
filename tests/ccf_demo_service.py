# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

from loguru import logger as LOG


def run(args):
    service_dns_name = "service43.adns.ccf.dev"
    adns_certs = [
        open(
            "workspace/adns.ccf.dev_common/service_cert.pem",
            mode="r",
            encoding="ascii",
        ).read()
    ]

    # Local pebble
    acme_directory = "https://127.0.0.1:1024/dir"
    ca_cert_file = "pebble-ca-cert.pem"
    ca_certs = [open(ca_cert_file, mode="r", encoding="ascii").read()]

    # Let's Encrypt (staging)
    # acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"

    args.acme = {
        "configurations": {
            "my_acme_config": {
                "ca_certs": adns_certs + ca_certs,
                "directory_url": acme_directory,
                "service_dns_name": service_dns_name,
                "contact": ["mailto:nobody@example.com"],
                "terms_of_service_agreed": True,
                "challenge_type": "dns-01",
                "challenge_server_interface": "",
            }
        }
    }

    for node in args.nodes:
        endorsed_interface = infra.interfaces.RPCInterface(
            host=infra.net.expand_localhost(),
            endorsement=infra.interfaces.Endorsement(
                authority=infra.interfaces.EndorsementAuthority.ACME,
                acme_configuration="my_acme_config",
            ),
        )
        endorsed_interface.public_host = service_dns_name
        node.rpc_interfaces["endorsed_interface"] = endorsed_interface

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:

        network.start_and_open(args)

        print("Network open")

        while True:
            time.sleep(1)


if __name__ == "__main__":

    def cliparser(parser):
        """Add parser"""
        parser.description = "CCF-based demo service"

    args = infra.e2e_args.cli_args(cliparser)
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    args.constitution = glob.glob("../tests/constitution/*")
    args.package = "libccf_demo_service"

    run(args)
