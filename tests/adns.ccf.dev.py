# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
from sys import stdout
import time
import base64
import json
import subprocess
import shutil

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import infra.interfaces

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from OpenSSL.crypto import load_certificate, FILETYPE_PEM

import dns
import dns.message
import dns.query
import dns.rdatatype as rdt
import dns.rdataclass as rdc

from loguru import logger as LOG

import dnsstamps
from dnsstamps import Option

import pebble

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
                "ttl": 0 if stype == "SOA" else 86400,
                "rdata": base64.b64encode(rdata_obj.to_wire()).decode(),
            },
        },
    )
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


def populate_adns_ccf_dev(network, args):
    """Populate the adns.ccf.dev. zone"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        origin = "adns.ccf.dev."

        rd = dns.rdata.from_text(
            rdc.IN,
            rdt.SOA,
            "ns1.adns.ccf.dev. some-dev.microsoft.com. 4 604800 86400 2419200 0",
        )
        add_record(client, origin, origin, "SOA", rd)
        rd = dns.rdata.from_text(rdc.IN, rdt.A, "51.143.161.224")
        add_record(client, origin, origin, "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.NS, "ns1.adns.ccf.dev.")
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
        print(rd.to_wire())
        add_record(client, origin, "cwinter", "TXT", rd)
        # b'\x04some\x04text'


def start_dnscrypt_proxy(binary):
    # service_cert = "workspace/adns.ccf.dev_common/service_cert.pem"
    # hash = (
    #     subprocess.Popen(
    #         f"openssl asn1parse -in {service_cert} -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256",
    #         shell=True,
    #         stdout=subprocess.PIPE,
    #     )
    #     .stdout.read()
    #     .decode("ascii")
    # )
    # hash = hash[hash.find(" ") + 1 :]

    # service_cert2 = "workspace/adns.ccf.dev_0/0.pem"
    # hash2 = (
    #     subprocess.Popen(
    #         f"openssl asn1parse -in {service_cert2} -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256",
    #         shell=True,
    #         stdout=subprocess.PIPE,
    #     )
    #     .stdout.read()
    #     .decode("ascii")
    # )
    # hash2 = hash2[hash2.find(" ") + 1 :]

    shutil.copy("../tests/dnscrypt-proxy.toml", "dnscrypt-proxy.toml")

    stamp = dnsstamps.create_doh(
        "10.1.0.4",
        [],
        "10.1.0.4:8000",
        "/app/dns-query",
        [],
    )

    with open("dnscrypt-proxy.toml", "a", encoding="ascii") as f:
        f.write(f"\n    stamp='{stamp}'\n")

    try:
        p = subprocess.Popen(
            [binary, "-config", "dnscrypt-proxy.toml"],
        )

        pebble.wait_for_port_to_listen("127.0.0.1", 53, 5)
    except:
        if p:
            p.kill()

    return p


def run(args):
    """Start the network"""

    dnscrypt_proxy_process = None
    service_dns_name = "adns.ccf.dev"

    pebble_filename = "/opt/pebble/pebble_linux-amd64"
    config_filename = "pebble.config.json"
    ca_key_filename = "pebble-key.pem"
    ca_cert_filename = "pebble-ca-cert.pem"
    output_filename = "pebble.out"
    error_filename = "pebble.err"
    listen_address = "127.0.0.1:1024"
    mgmt_address = "127.0.0.1:1025"
    dns_address = "ns1.adns.ccf.dev:53"
    tls_port = 1026
    http_port = 1027

    with open(output_filename, "w", encoding="ascii") as pebble_out:
        with open(error_filename, "w", encoding="ascii") as pebble_err:

            pproc = pebble.run_proc(
                pebble_filename,
                config_filename,
                dns_address,
                listen_address,
                pebble_out,
                pebble_err,
            )

            acme_directory = "https://127.0.0.1:1024/dir"
            ca_cert_file = "pebble-ca-cert.pem"
            ca_certs = [open(ca_cert_file, mode="r", encoding="ascii").read()]

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
                    infra.interfaces.HostSpec.from_str(node, http2=args.http2)
                    for node in hosts
                ]

            # for node in args.nodes:
            #     node.rpc_interfaces[
            #         "acme_endorsed_interface"
            #     ] = infra.interfaces.RPCInterface(
            #         host=infra.net.expand_localhost(),
            #         endorsement=infra.interfaces.Endorsement(
            #             authority=infra.interfaces.EndorsementAuthority.ACME,
            #             acme_configuration="my_acme_config",
            #         ),
            #         public_host=service_dns_name,
            #     )
            #     node.rpc_interfaces[
            #         "acme_challenge_server_if"
            #     ] = infra.interfaces.RPCInterface(
            #         host=node.get_primary_interface().host,
            #         port=http_port,
            #         endorsement=infra.interfaces.Endorsement(
            #             authority=infra.interfaces.EndorsementAuthority.Unsecured
            #         ),
            #         accepted_endpoints=["/.well-known/acme-challenge/.*"],
            #     )

            # args.acme = {
            #     "configurations": {
            #         "my_acme_config": {
            #             "ca_certs": ca_certs,
            #             "directory_url": acme_directory,
            #             "service_dns_name": service_dns_name,
            #             "contact": ["mailto:nobody@example.com"],
            #             "terms_of_service_agreed": True,
            #             "challenge_type": "http-01",
            #             "challenge_server_interface": "acme_challenge_server_if",
            #         }
            #     }
            # }

            with infra.network.network(
                # args.nodes,
                hosts=hosts,
                binary_directory=args.binary_dir,
                library_directory=args.library_dir,
                dbg_nodes=args.debug_nodes,
            ) as network:
                network.start_and_open(args)
                populate_adns_ccf_dev(network, args)

                try:
                    # dnscrypt_proxy_process = start_dnscrypt_proxy(
                    #     "/data/cwinter/dnscrypt-proxy/linux-x86_64/dnscrypt-proxy"
                    # )

                    LOG.info("Waiting until network is torn down...")
                    while True:
                        time.sleep(1)
                except Exception as ex:
                    print(f"Exception: {ex}")
                    if dnscrypt_proxy_process:
                        dnscrypt_proxy_process.kill()

            pproc.kill()


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
    targs.binary_dir = "/data/cwinter/installed/ccf/bin/"

    run(targs)
