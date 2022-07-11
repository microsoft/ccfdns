# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import requests
import base64

import dns
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.dnssec
import dns.rrset

from loguru import logger as LOG


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/add",
        {
            "origin": str(origin),
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
        for a in r.answer:
            assert a.name == qname
            saw_expected = False
            for item in a.items:
                assert item.rdclass == dns.rdataclass.IN
                assert item.rdtype in [
                    qtype,
                    dns.rdatatype.RRSIG,
                    dns.rdatatype.NSEC,
                ]
                if expected_data:
                    if (
                        item.rdtype != qtype
                        or item.to_wire() == expected_data.to_wire()
                    ):
                        saw_expected = True
            assert not expected_data or saw_expected


def validate_rrsigs(reply: dns.message.Message, qtype, keys):
    # print(r)
    if len(reply.answer) == 0:
        raise "no answers"
    name = reply.answer[0].name
    rrs = dns.rrset.RRset(name, dns.rdataclass.IN, qtype)
    rrsigs = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
    for a in reply.answer:
        if a.rdtype == qtype:
            rrs += a
        elif a.rdtype == dns.rdatatype.RRSIG:
            rrsigs += a
        else:
            raise "Unexpected record type"

    if keys is not None:
        dns.dnssec.validate(rrs, rrsigs, keys)


def get_records(host, port, ca, qname, stype, keys=None):
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
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
        if keys:
            validate_rrsigs(r, qtype, keys)
        return r
    return None


def test_basic(network, args):
    """Basic tests"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("example.com.")

        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        add_record(client, origin, "www", "A", rd)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.5")
        add_record(client, origin, "www", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.5")
        add_record(client, origin, "www2", "A", rd2)

        rrs = get_records(host, port, ca, origin, "DNSKEY", None)
        assert len(rrs.answer) == 2
        if rrs.answer[0].rdtype == dns.rdatatype.DNSKEY:
            key_rrs = rrs.answer[0]
            rrsig = rrs.answer[1]
        else:
            rrsig = rrs.answer[0]
            key_rrs = rrs.answer[1]
        keys = {origin: key_rrs}

        dns.dnssec.validate(key_rrs, rrsig, keys)

        name = dns.name.from_text("www2.example.com.")
        get_records(host, port, ca, name, "A", None)

        name = dns.name.from_text("www.example.com.")
        get_records(host, port, ca, name, "A", None)


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
