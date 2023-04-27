import argparse
import base64
import cbor2
import dns.resolver
import dns.dnssec
import json
import ssl
import requests
import tempfile
import urllib
import zlib

import ravl

from dns.rdatatype import RdataType as rd

from urllib.parse import urlparse

ATTEST = 32771  # RR type


def split_pem(pem):
    r = []
    begin = "-----BEGIN "
    items = pem.split(begin)
    for item in items[1:]:
        r += [begin + item]
    return r


def get_without_cert_check(url: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read().decode("utf-8")


def get_pebble_ca_certs(mgmt_address):
    """Get the pebble CA certificate(s)"""
    ca = get_without_cert_check("https://" + mgmt_address + "/roots/0")
    intermediate = get_without_cert_check(
        "https://" + mgmt_address + "/intermediates/0"
    )
    return [intermediate, ca]


def get_server_certificate(url) -> bytes:
    return ssl.get_server_certificate((url.hostname, url.port))


def default_port_protocol(scheme: str):
    """Get default port and protocol for a scheme"""
    if scheme == "http":
        return "tcp", 80
    elif scheme == "https":
        return "tcp", 443
    else:
        raise ValueError(f"unsupported scheme: {scheme}")


def get_records(name: str, dt: rd):
    """Get DNS records for a name and type"""
    rslvr = dns.resolver.Resolver()
    rslvr.use_edns(0, dns.flags.DO, 4096)
    answer = rslvr.resolve(name, dt, raise_on_no_answer=False)
    if not (answer.response.ednsflags & dns.flags.DO):
        raise ValueError("DNSSEC flag not set in answer")
    return answer


def get_addresses(hostname: str) -> dns.resolver.Answer:
    """Get all addresses for a hostname"""
    r = []
    rrs = get_records(hostname, rd.A)
    if rrs:
        for rr in rrs.rrset:
            r.append(rr.address)
    rrs = get_records(hostname, rd.AAAA)
    if rrs:
        for rr in rrs.rrset:
            r.append(rr.address)

    print(" - A/AAAA Addresses")
    for address in r:
        print(f"  - {address}")

    return r


def verify_tlsa(url):
    protocol, lport = default_port_protocol(url.scheme)
    if url.port:
        lport = url.port
    rrs = get_records(f"_{str(lport)}._{protocol}.{url.hostname}", rd.TLSA)

    print(" - TLSA record")
    for rr in rrs:
        print(f"  - {rr}")

    if len(rrs) != 1:
        raise ValueError(f"expected exactly one TLSA record, got {len(rrs)}")


def get_endorsements(
    adns_https_url, service_name: str, ca_certificates: "list[str]"
) -> str:
    ps = {"service_name": service_name}
    with tempfile.NamedTemporaryFile(mode="w") as f:
        if ca_certificates:
            for c in ca_certificates:
                f.write(c)
        f.flush()
        u = adns_https_url.geturl() + "/endorsements"
        response = requests.get(
            u,
            params=ps,
            verify=f.name,
            timeout=10,
        )
        if response.status_code != 200:
            return None
        r = response.content
    return zlib.decompress(r)


def find_adns_server(args, service_name):
    """Find the aDNS server for a service"""
    if args.server:
        return args.server
    else:
        num = 0
        while num == 0 and service_name != "":
            rrs = get_records(service_name, rd.NS)
            num = len(rrs)
            if num == 0:
                service_name = ".".join(service_name.split(".")[1:])
        if num != 0:
            return service_name
        else:
            raise ValueError("could not determine aDNS server")


def unfragment(name: str):
    """Unfragment AAAA records"""
    r = bytearray()

    num_bytes = 0

    i = 0
    n = 3
    bytes_seen = 0
    while num_bytes == 0 or bytes_seen < num_bytes:
        r += bytearray(64 * 15)
        rrs = get_records(f"_{i}." + name, rd.AAAA)
        for rr in rrs:
            b = rr.to_digestable()
            assert len(b) == 16
            index = b[0]
            if i == 0 and index == 0:
                num_bytes = b[1] << 8 | b[2]
                r[0:13] = b[3:]
                bytes_seen += 13
            else:
                start = (i * 64 * 15) - 2 + index * 15
                r[start : start + 15] = b[1:]
                bytes_seen += 15
            # print(f"{i}/{index:02d}:" + r.hex())
        i = i + 1

    r = r[:num_bytes]
    return r


def verify_attest(service_url, adns_https_url, ca_certificates):
    print(" - ATTEST records")
    rrs = get_records(service_url.hostname, ATTEST)
    print(f"  - {len(rrs)} attestation reports to verify")

    endorsements = get_endorsements(
        adns_https_url, service_url.hostname, ca_certificates
    )
    if endorsements:
        print(f"  - have endorsements ({len(endorsements)} bytes)")

    i = 1
    failures = 0
    for rr in rrs:
        crr = rr.to_digestable()
        ok = True
        try:
            cbor = zlib.decompress(crr)
        except Exception:
            raise ValueError("failed to decompress attestation")
        try:
            if not endorsements:
                cbor = zlib.decompress(crr)
                ok = ravl.verify_attestation_cbor(cbor)
            else:
                # Inject shared endorsements
                cbor = cbor2.loads(zlib.decompress(crr))
                cbor["endorsements"] = endorsements
                ok = ravl.verify_attestation_cbor(cbor2.dumps(cbor))
        except Exception:
            ok = False
        print(f"    {i}. verification " + ("successful" if ok else "failed"))
        failures += 0 if ok else 1
        i = i + 1
    if failures == 0:
        print("  - all records verified successfully")


def main(args):
    """Main entry point"""

    service_url = urlparse(args.url)
    print(f"* {args.url}")

    adns_https_url = urlparse(
        "https://"
        + find_adns_server(args, service_url.hostname)
        + ":"
        + str(args.https_port)
        + "/app"
    )

    adns_server_cert = get_server_certificate(adns_https_url)
    service_server_cert = get_server_certificate(service_url)

    ca_certificates = []
    # for f in args.ca_certificate_files:
    #     ca_certificates += split_pem(open(f, "r").read())

    ca_certificates = get_pebble_ca_certs("localhost:1025")

    addresses = get_addresses(service_url.hostname)
    verify_tlsa(service_url)
    verify_attest(service_url, adns_https_url, ca_certificates)

    return 0


if __name__ == "__main__":
    # r = unfragment("attest.node1.service43.adns.ccf.dev")
    # open("tmp.bin", "wb").write(r)
    # ur = zlib.decompress(r)
    # print(ur)

    parser = argparse.ArgumentParser(description="Verify aDNS properties.")
    parser.add_argument(
        "url",
        type=str,
        help="URL of an aDNS-registered service",
    )
    parser.add_argument(
        "-s",
        "--server",
        type=str,
        required=False,
        help="URL of the aDNS server to use",
        default=None,
    )
    parser.add_argument(
        "-p",
        "--https-port",
        type=str,
        help="aDNS server HTTPS port",
        default=8443,
    )
    parser.add_argument(
        "-c",
        "--ca-certificate",
        dest="ca_certificate_files",
        type=str,
        required=False,
        nargs="+",
        help="CA certificate filename",
    )
    main(parser.parse_args())
