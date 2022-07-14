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
import dns.dnssec
import dns.rrset

from loguru import logger as LOG


rdc = dns.rdataclass
rdt = dns.rdatatype


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/add",
        {
            "origin": str(origin),
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


def check_record(host, port, ca, name, stype, expected_data=None):
    qname = dns.name.from_text(name)
    qtype = rdt.from_text(stype)
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
                assert item.rdclass == rdc.IN
                assert item.rdtype in [
                    qtype,
                    rdt.RRSIG,
                    rdt.NSEC,
                ]
                if expected_data:
                    if (
                        item.rdtype != qtype
                        or item.to_wire() == expected_data.to_wire()
                    ):
                        saw_expected = True
            assert not expected_data or saw_expected


def validate_rrsigs(response: dns.message.Message, qtype, keys):
    name = response.question[0].name
    rrs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, qtype)
    rrsigs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, rdt.RRSIG, qtype)
    print(rrs)
    print(rrsigs)
    if keys is not None:
        dns.dnssec.validate(rrs, rrsigs, keys)


def get_records(host, port, ca, qname, stype, keys=None):
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
    qtype = rdt.from_text(stype)
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

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "1.2.3.4")
        add_record(client, origin, "www", "A", rd)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = dns.rdata.from_text(rdc.IN, rdt.A, "1.2.3.5")
        add_record(client, origin, "www", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = dns.rdata.from_text(rdc.IN, rdt.A, "1.2.3.5")
        add_record(client, origin, "www2", "A", rd2)

        r = get_records(host, port, ca, origin, "DNSKEY", None)
        key_rrs = r.find_rrset(r.answer, origin, rdc.IN, rdt.DNSKEY)
        keys = {origin: key_rrs}
        validate_rrsigs(r, rdt.DNSKEY, keys)

        name = dns.name.from_text("www2.example.com.")
        get_records(host, port, ca, name, "A", keys)

        name = dns.name.from_text("www.example.com.")
        get_records(host, port, ca, name, "A", keys)

        name = dns.name.from_text("example.com.")
        ds_rrs = get_records(host, port, ca, name, "DS", None)
        assert len(ds_rrs.answer) == 1
        assert len(ds_rrs.answer[0]) == 1
        ds_rrs = ds_rrs.answer[0][0]
        key = keys[origin][1]
        ds = dns.dnssec.make_ds(origin, key, "SHA384")
        if ds_rrs.digest != ds.digest:
            raise Exception("DS record hash mismatch")


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
