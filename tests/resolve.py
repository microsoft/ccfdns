#!/usr/bin/env python3

import sys
import requests

import dns.message
import dns.query
import dns.rdatatype


def main(args):
    qtype = "A"
    if len(args) >= 3:
        qtype = args[2]

    where = "https://test.attested.name:8443/app/dns-query"

    with requests.sessions.Session() as session:
        q = dns.message.make_query(args[1], dns.rdatatype.from_text(qtype))
        r = dns.query.https(q, where, session=session, verify=False)
        if len(r.answer) == 0:
            print("No results")
        for answer in r.answer:
            print(answer)


if __name__ == "__main__":
    main(sys.argv)
