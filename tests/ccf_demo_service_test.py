# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

from loguru import logger as LOG


def test_registration(adns_args, adns_network, service_args, service_network):
    pass


def run(adns_args, service_args):
    with infra.network.network(
        adns_args.nodes,
        adns_args.binary_dir,
        adns_args.debug_nodes,
        adns_args.perf_nodes,
        pdb=adns_args.pdb,
    ) as adns_network:

        adns_network.start_and_open(adns_args)

        service_dns_name = "acc-cwinter.uksouth.cloudapp.azure.com"

        ca_cert = ""

        service_args.acme = {
            "configurations": {
                "my_acme_config": {
                    "ca_certs": [ca_cert],
                    "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
                    "service_dns_name": service_dns_name,
                    "contact": ["mailto:nobody@example.com"],
                    "terms_of_service_agreed": True,
                    "challenge_type": "dns-01",
                    "challenge_server_interface": "acme_challenge_server_if",
                }
            }
        }

        for node in service_args.nodes:
            endorsed_interface = infra.interfaces.RPCInterface(
                host=infra.net.expand_localhost(),
                endorsement=infra.interfaces.Endorsement(
                    authority=infra.interfaces.EndorsementAuthority.ACME,
                    acme_configuration="my_acme_config",
                ),
            )
            endorsed_interface.public_host = service_dns_name
            node.rpc_interfaces["acme_endorsed_interface"] = endorsed_interface

        with infra.network.network(
            service_args.nodes,
            service_args.binary_dir,
            service_args.debug_nodes,
            service_args.perf_nodes,
            pdb=service_args.pdb,
        ) as service_network:

            service_network.start_and_open(service_args)

            test_registration(adns_args, adns_network, service_args, service_network)


if __name__ == "__main__":

    def cliparser(parser):
        """Add parser"""
        parser.description = "CCF-based demo service"

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.nodes = infra.e2e_args.min_nodes(adns_args, f=0)
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.nodes = infra.e2e_args.min_nodes(service_args, f=0)
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"

    run(adns_args, service_args)
