# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http

from numpy import byte
import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import requests
import http
import base64

import dns
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass

from loguru import logger as LOG


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/add",
        {
            "origin": origin,
            "record": {
                "name": name,
                "type": int(dns.rdatatype.from_text(stype)),
                "class_": int(dns.rdataclass.IN),
                "ttl": 3600,
                "rdata": base64.urlsafe_b64encode(rdata_obj.to_wire()).decode(),
            },
        },
    )
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


def check_record(host, port, ca, name, stype, expected_data=None):
    qname = dns.name.from_text(name)
    qtype = dns.rdatatype.from_text(stype)
    with requests.sessions.Session() as session:
        q = dns.message.make_query(qname, qtype)
        r = dns.query.https(
            q,
            "https://" + host + ":" + str(port) + "/app/dns-query",
            session=session,
            verify=ca,
            post=False,
        )
        # print(r)
        for a in r.answer:
            assert a.name == qname
            saw_expected = False
            for item in a.items:
                assert item.rdclass == dns.rdataclass.IN
                assert item.rdtype == qtype
                if expected_data:
                    if item.to_wire() == expected_data.to_wire():
                        saw_expected = True
            assert not expected_data or saw_expected


def test_basic(network, args):
    """Basic tests"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        add_record(client, "example.com.", "www", "A", rd)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.5")
        add_record(client, "example.com.", "www", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd)


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
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns"

    run(targs)
