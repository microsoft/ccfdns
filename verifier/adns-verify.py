import argparse
import base64
import json
import ssl
import tempfile
import urllib
import zlib
import time
import http
import sys
import traceback
from typing import List, Tuple

import cbor2
import dns.resolver
import dns.dnssec
from dns.rdatatype import RdataType as rd
import dns.rdtypes
import requests

import ravl


from urllib.parse import urlparse, urlunparse, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from hashlib import sha256

import ccf.receipt

ATTEST = 32771  # RR type
MAX_ENTRIES_PER_AAAA_NAME = 64

rslvr = dns.resolver.Resolver()


def split_pem(pem):
    """Split a string containing multiple PEM certificates"""
    r = []
    begin = "-----BEGIN "
    items = pem.split(begin)
    for item in items[1:]:
        r += [begin + item]
    return r


def get_without_cert_check(url: str):
    """Request with explicitly disabled TLS certificate check"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read().decode("utf-8")


def get_server_certificate(url) -> bytes:
    """Get server certificate for a URL"""
    return ssl.get_server_certificate((url.hostname, url.port if url.port else 443))


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

    global rslvr
    if not rslvr:
        rslvr = dns.resolver.Resolver()

    rslvr.use_edns(0, dns.flags.DO, 4096)
    answer = rslvr.resolve(name, dt, raise_on_no_answer=False)
    if not (answer.response.ednsflags & dns.flags.DO):
        raise ValueError("DNSSEC flag not set in answer")
    return answer


def get_addresses(service_name: str, indent=2) -> dns.resolver.Answer:
    """Get all addresses for a host/service name"""

    r = []
    rrs = get_records(service_name, rd.A)
    if rrs:
        for rr in rrs.rrset:
            r.append(rr.address)
    rrs = get_records(service_name, rd.AAAA)
    if rrs:
        for rr in rrs.rrset:
            r.append(rr.address)

    print(f"{' '*indent}- A/AAAA Addresses")
    for address in r:
        print(f"{' '*(indent+2)}- {address}")

    return r


def get_ns_records(domain: str, indent=2) -> List[Tuple[str, str]]:
    """Get all addresses for a host/service name"""

    names = []
    rrs = get_records(domain, rd.NS)
    if rrs is not None and rrs.response is not None:
        if rrs.response.authority:
            for rra in rrs:
                if rra.rdtype == rd.NS:
                    for rr in rra.items:
                        names.append(str(rr))
        else:
            for rr in rrs:
                names.append(str(rr))

    r = []
    for name in names:
        r += [(name, str(rr)) for rr in get_records(name, rd.A)]
        r += [(name, str(rr)) for rr in get_records(name, rd.AAAA)]

    print(f"{' '*indent}- Nameserver addresses")
    for n, a in r:
        print(f"{' '*(indent+2)}- {n}: {a}")

    return r


def extract_node_names(service_url, service_certificate: str) -> "list[str]":
    """Extract service node names from certificate"""

    r = []

    service_x509 = x509.load_pem_x509_certificate(service_certificate.encode("ascii"))
    san_ext = service_x509.extensions.get_extension_for_oid(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    for san in san_ext.value:
        if isinstance(san, x509.DNSName):
            if san.value != service_url.hostname:
                r += [san.value]

    return r


def verify_tlsa(url, service_certificate, indent=2):
    """Verify TLSA record"""

    protocol, lport = default_port_protocol(url.scheme)
    if url.port:
        lport = url.port
    rrs = get_records(f"_{str(lport)}._{protocol}.{url.hostname}", rd.TLSA)

    print(f"{' '*indent}- TLSA records")

    if len(rrs) != 1:
        raise ValueError(f"expected exactly one TLSA record, got {len(rrs)}")

    tlsa = rrs[0]

    if tlsa.usage != 3:
        raise ValueError(f"invalid TLSA usage: {tlsa.usage}")

    if tlsa.selector != 1:
        raise ValueError(f"invalid TLSA selector: {tlsa.selector}")

    if tlsa.mtype != 0:
        raise ValueError(f"invalid TLSA matching type: {tlsa.mtype}")

    tlsa_key_bytes = tlsa.cert

    service_x509 = x509.load_pem_x509_certificate(service_certificate.encode("ascii"))
    service_key_bytes = service_x509.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if tlsa_key_bytes != service_key_bytes:
        raise ValueError("service public key does not match TLSA record")
    else:
        print(f"{' '*(indent+2)}- Record matches service public key")


def get(url: str, params, ca_certificates: "list[str]", timeout=10):
    """HTTP-get"""

    with tempfile.NamedTemporaryFile(mode="w") as f:
        if ca_certificates:
            for c in ca_certificates:
                f.write(c)
        f.flush()
        r = requests.get(url, params=params, verify=f.name, timeout=timeout)
        while (
            r.status_code == http.HTTPStatus.ACCEPTED
            or r.status_code == http.HTTPStatus.NOT_FOUND
        ):
            if r.status_code == http.HTTPStatus.NOT_FOUND:
                b = r.json()
                if (
                    "error" in b
                    and "code" in b["error"]
                    and b["error"]["code"] != "TransactionPendingOrUnknown"
                ):
                    raise ValueError(f"receipt request error: {b}")
            d = int(r.headers["retry-after"] if "retry-after" in r.headers else 3)
            print(
                f"Waiting {d} seconds before retrying HTTP request...", file=sys.stderr
            )
            time.sleep(d)
            r = requests.get(url, params=params, verify=f.name, timeout=timeout)

        return r


def get_shared_endorsements(
    adns_https_url, service_name: str, ca_certificates: "list[str]", indent: int = 2
) -> str:
    """Download shared endorsements for a service"""

    response = get(
        adns_https_url.geturl() + "/endorsements",
        {"service_name": service_name},
        ca_certificates,
    )
    if response.status_code != 200:
        return None
    r = zlib.decompress(response.content)
    if r:
        print(f"{' '*indent}- Shared endorsements: {len(r)} bytes")
    return r


def find_adns_parent(args, subdomain):
    """Find the aDNS parent for a subdomain"""

    if "parent" in args and args.parent:
        return args.parent
    else:
        num = 0
        subdomain = ".".join(subdomain.split(".")[1:])
        while num == 0 and subdomain != "":
            rrs = get_records(subdomain, rd.NS)
            num = len(rrs)
            if num == 0:
                subdomain = ".".join(subdomain.split(".")[1:])
        if num != 0:
            return subdomain
        else:
            raise ValueError("could not determine aDNS server")


def recombine(name: str):
    """Recombine AAAA-fragmented records"""

    r = bytearray()
    num_bytes = 0

    i = 0
    bytes_seen = 0
    while num_bytes == 0 or bytes_seen < num_bytes:
        r += bytearray(MAX_ENTRIES_PER_AAAA_NAME * 15)
        rrs = get_records(f"_{i}." + name, rd.AAAA)
        if len(rrs) == 0:
            break
        else:
            for rr in rrs:
                b = rr.to_digestable()
                assert len(b) == 16
                index = b[0]
                if i == 0 and index == 0:
                    num_bytes = b[1] << 8 | b[2]
                    r[0:13] = b[3:]
                    bytes_seen += 13
                else:
                    start = (i * MAX_ENTRIES_PER_AAAA_NAME * 15) - 2 + index * 15
                    r[start : start + 15] = b[1:]
                    bytes_seen += 15
            i = i + 1

    r = r[:num_bytes]
    return r


def inject_endorsements(rdata, endorsements):
    """Inject (shared) endorsements into an attestation"""

    if not endorsements:
        return rdata
    else:
        cbor = cbor2.loads(rdata)
        cbor["endorsements"] = endorsements
        return cbor2.dumps(cbor)


def exwrap(fun, *args, indent=2):
    """Wrap a function call in an exception handler"""
    try:
        fun(*args, indent)
    except Exception as ex:
        msg = type(ex).__name__
        details = str(ex)
        if details:
            msg += f" ({details})"
        print(f"{' '*(indent*2)}- **Error**: {msg}")


def verify_attestation_cbor(cbor, endorsements):
    """Verify an attestation in CBOR format"""

    try:
        att = inject_endorsements(cbor, endorsements)
        return ravl.verify_attestation_cbor(att)
    except Exception as ex:
        raise ValueError(f"attestation verification error: {str(ex)}") from ex


def verify_attest(service_url, endorsements, indent=2):
    """Verify ATTEST records"""

    print(f"{' '*indent}- ATTEST records")
    rrs = get_records(service_url.hostname, ATTEST)
    if len(rrs) <= 0:
        raise ValueError("no attestation to verify")
    print(f"{' '*(indent+2)}- {len(rrs)} attestations")

    i = 1
    failures = 0
    for rr in rrs:
        cbor = zlib.decompress(rr.to_digestable())
        if verify_attestation_cbor(cbor, endorsements):
            print(f"{' '*(indent+4)}{i}. verified successfully")
        else:
            print(f"{' '*(indent+4)}{i}. verification **failed**")
            failures += 1
        i = i + 1
    if failures == 0:
        print(f"{' '*(indent+2)}- all attestations verified successfully")


def verify_fragmented_attest(service_url, endorsements, indent=2):
    """Verify a AAAA-fragmented attestation"""

    print(f"{' '*(indent)}- AAAA-Fragmented ATTEST records")

    rdata = recombine("attest." + service_url.hostname)
    cbor = zlib.decompress(rdata)
    atts = cbor2.loads(cbor)
    failures = 0
    i = 1
    if not isinstance(atts, list):
        atts = [atts]
    print(f"{' '*(indent+2)}- {len(atts)} attestations")
    for att in atts:
        att = inject_endorsements(cbor2.dumps(att), endorsements)
        if verify_attestation_cbor(att, endorsements):
            print(f"{' '*(indent+4)}{i}. verified successfully")
        else:
            print(f"{' '*(indent+4)}{i}. verification **failed**")
            failures += 1
        i = i + 1
    if failures == 0:
        print(f"{' '*(indent+2)}- all records verified successfully")


def verify_ccf_receipt(receipt, issuer_url, ca_certificates, indent=2):
    """Verify a receipt originating from CCF"""

    lc = receipt["leaf_components"]
    proof = receipt["proof"]
    signature = receipt["signature"]

    claims_dgst = bytes.fromhex(lc["claims_digest"])
    commit_evidence_dgst = sha256(lc["commit_evidence"].encode("ascii")).digest()
    write_set_dgst = bytes.fromhex(lc["write_set_digest"])

    leaf_data = write_set_dgst + commit_evidence_dgst + claims_dgst
    leaf = sha256(leaf_data).digest().hex()

    # Receipt is signed by node certificate
    node_cert_pem = receipt["cert"].encode("ascii")
    node_certificate = x509.load_pem_x509_certificate(node_cert_pem)
    ccf.receipt.verify(ccf.receipt.root(leaf, proof), signature, node_certificate)

    # Get the current CCF network certificate
    nw_url = urlunsplit(
        (
            issuer_url.scheme,
            issuer_url.netloc,
            "/node/network",
            None,
            None,
        )
    )
    response = get(nw_url, None, ca_certificates)
    if response.status_code != 200:
        raise ValueError("could not get CCF network certificate")
    nw = json.loads(response.text)
    service_cert_pem = nw["service_certificate"].encode("ascii")
    service_certificate = x509.load_pem_x509_certificate(service_cert_pem)

    # Check that node certificate is issued by the network certificate
    ccf.receipt.check_endorsement(node_certificate, service_certificate)

    print(f"{' '*indent}- Receipt verified successfully")


def verify_service_registration(
    service_url,
    service_certificate,
    adns_https_url,
    ca_certificates,
    receipt_checks=True,
    indent=2,
):
    """Verify service registration"""

    print(f"{' '*indent}- Registration")
    url = adns_https_url.geturl() + "/registration-receipt"
    link = url + f"?service-name={service_url.hostname}"
    print(f"{' '*(indent+2)}- See {link}")

    response = get(
        url,
        {"service-name": service_url.hostname},
        ca_certificates,
    )

    reg_info = json.loads(response.text)

    reg = reg_info["registration"]
    print(f"{' '*(indent+2)}- Contact: {reg['contact']}")

    service_cert_pem = service_certificate.encode("ascii")
    service_x509 = x509.load_pem_x509_certificate(service_cert_pem)
    service_key_bytes = service_x509.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    csr = x509.load_der_x509_csr(base64.b64decode(reg["csr"]))
    print(f"{' '*(indent+2)}- CSR subject: {csr.subject}")

    csr_key_bytes = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if service_key_bytes == csr_key_bytes:
        print(f"{' '*(indent+2)}- CSR public key matches service key")
    else:
        print(f"{' '*(indent+2)}- CSR public key **does not match** service key")

    if receipt_checks:
        receipt = reg_info["receipt"]
        verify_ccf_receipt(receipt, adns_https_url, ca_certificates, indent + 2)


def verify_delegation_registration(
    subdomain,
    service_certificate,
    adns_https_url,
    ca_certificates,
    receipt_checks=True,
    indent=2,
):
    """Verify service registration"""

    print(f"{' '*indent}- Registration")
    url = adns_https_url.geturl() + "/delegation-receipt"
    link = url + f"?subdomain={subdomain}"
    print(f"{' '*(indent+2)}- See {link}")

    response = get(
        url,
        {"subdomain": subdomain},
        ca_certificates,
    )

    reg_info = json.loads(response.text)

    reg = reg_info["delegation"]
    print(f"{' '*(indent+2)}- Contact: {reg['contact']}")

    service_cert_pem = service_certificate.encode("ascii")
    service_x509 = x509.load_pem_x509_certificate(service_cert_pem)
    service_key_bytes = service_x509.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    csr = x509.load_der_x509_csr(base64.b64decode(reg["csr"]))
    print(f"{' '*(indent+2)}- CSR subject: {csr.subject}")

    csr_key_bytes = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if service_key_bytes == csr_key_bytes:
        print(f"{' '*(indent+2)}- CSR public key matches service key")
    else:
        print(f"{' '*(indent+2)}- CSR public key **does not match** service key")

    if receipt_checks:
        receipt = reg_info["receipt"]
        verify_ccf_receipt(receipt, adns_https_url, ca_certificates, indent + 2)


def show_policy_links(adns_https_url, indent=2):
    """Show links to the registration and delegation policies"""

    url = adns_https_url.geturl() + "/registration-policy"
    print(f"{' '*indent}- Registration policy: {url}")
    url = adns_https_url.geturl() + "/delegation-policy"
    print(f"{' '*indent}- Delegation policy: {url}")


def verify_node_addresses(node_addresses, addresses, indent=2):
    """Verify that a set of node addresses is included in a set of addresses"""

    for n in node_addresses:
        if n not in addresses:
            raise ValueError(f"node address {n} not in address list")
    print(f"{' '*(indent)}- Appears in address records")


def service(args):
    """Service registration verification"""

    indent = 2
    try:
        if args.nameservers:
            rslvr.nameservers = args.nameservers

        service_url = urlparse(args.url)

        print(f"* Service: {args.url}")

        adns_https_url = urlparse(
            "https://"
            + find_adns_parent(args, service_url.hostname)
            + ":"
            + str(args.https_port)
            + "/app"
        )

        print(f"{' '*indent}- Registered at {adns_https_url.hostname}")
        show_policy_links(adns_https_url, indent=2 * indent)

        # adns_server_certificate = get_server_certificate(adns_https_url)
        service_certificate = get_server_certificate(service_url)

        ca_certificates = []
        if args.ca_certificate_files:
            for f in args.ca_certificate_files:
                ca_certificates += split_pem(open(f, "r", encoding="ascii").read())

        # ca_certificates = get_pebble_ca_certs("localhost:1025")

        addresses = get_addresses(service_url.hostname)
        node_names = extract_node_names(service_url, service_certificate)
        endorsements = get_shared_endorsements(
            adns_https_url, service_url.hostname, ca_certificates
        )

        # Verify service records
        exwrap(verify_tlsa, service_url, service_certificate)
        exwrap(verify_attest, service_url, endorsements)
        if not args.no_fragmented_checks:
            exwrap(verify_fragmented_attest, service_url, endorsements)
        exwrap(
            verify_service_registration,
            service_url,
            service_certificate,
            adns_https_url,
            ca_certificates,
            args.receipt_checks,
        )

        print(f"{' '*indent}- Individual node records")
        for n in node_names:
            print(f"{' '*(indent*2)}- {n}")
            node_url = urlparse("https://" + n)
            node_addresses = get_addresses(n, indent=3 * indent)
            exwrap(verify_attest, node_url, endorsements, indent=3 * indent)
            if not args.no_fragmented_checks:
                exwrap(
                    verify_fragmented_attest, node_url, endorsements, indent=3 * indent
                )
            exwrap(verify_node_addresses, node_addresses, addresses, indent=3 * indent)

        return 0
    except Exception as ex:
        print(f"{' '*(indent*2)}- **Error**: {str(ex)}")

    return 1


def delegation(args):
    """Verify delegation registrations"""

    indent = 2
    try:
        if args.nameservers:
            rslvr.nameservers = args.nameservers

        child_url = urlparse(args.domain)

        print(f"* Delegation: {args.domain}")

        parent_url = urlparse(
            "https://"
            + find_adns_parent(args, args.domain)
            + ":"
            + str(args.https_port)
            + "/app"
        )

        print(f"{' '*indent}- Parent at {parent_url.hostname}")
        show_policy_links(parent_url, indent=2 * indent)

        child_url = urlparse(
            "https://" + args.domain + ":" + str(args.https_port) + "/"
        )
        parent_certificate = get_server_certificate(parent_url)
        child_certificate = get_server_certificate(child_url)

        ca_certificates = []
        if args.ca_certificate_files:
            for f in args.ca_certificate_files:
                ca_certificates += split_pem(open(f, "r", encoding="ascii").read())

        # ca_certificates = get_pebble_ca_certs("localhost:1025")

        ns_names_addr = get_ns_records(args.domain)
        node_names = extract_node_names(child_url, child_certificate)
        endorsements = get_shared_endorsements(parent_url, args.domain, ca_certificates)

        exwrap(verify_attest, child_url, endorsements)
        if not args.no_fragmented_checks:
            exwrap(verify_fragmented_attest, child_url, endorsements)
        exwrap(
            verify_delegation_registration,
            args.domain,
            child_certificate,
            parent_url,
            ca_certificates,
            args.receipt_checks,
        )

        print(f"{' '*indent}- Individual node records")
        ns_addresses = [a for _, a in ns_names_addr]
        for n in node_names:
            print(f"{' '*(indent*2)}- {n}")
            node_url = urlparse("https://" + n)
            node_addresses = get_addresses(n, indent=3 * indent)
            exwrap(verify_attest, node_url, endorsements, indent=3 * indent)
            if not args.no_fragmented_checks:
                exwrap(
                    verify_fragmented_attest, node_url, endorsements, indent=3 * indent
                )
            exwrap(
                verify_node_addresses, node_addresses, ns_addresses, indent=3 * indent
            )

        return 0
    except Exception as ex:
        print(f"{' '*(indent*2)}- **Error**: {str(ex)}")
        traceback.print_exc()

    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify aDNS properties.")

    subparsers = parser.add_subparsers(title="subcommands")

    service_parser = subparsers.add_parser(
        "service", aliases=["s"], help="verify aDNS service registrations"
    )
    service_parser.add_argument(
        "url",
        type=str,
        help="URL of an aDNS-registered service",
    )
    service_parser.add_argument(
        "-s",
        "--server",
        type=str,
        required=False,
        help="URL of the aDNS server to check against",
        default=None,
    )
    service_parser.add_argument(
        "-n",
        "--name-server",
        type=str,
        required=False,
        nargs="+",
        help="Nameserver IP addresses",
        default=None,
        dest="nameservers",
    )
    service_parser.add_argument(
        "-p",
        "--https-port",
        type=str,
        help="aDNS server HTTPS port",
        default=8443,
    )
    service_parser.add_argument(
        "-c",
        "--ca-certificate",
        dest="ca_certificate_files",
        type=str,
        required=False,
        nargs="+",
        help="CA certificate filename",
    )
    service_parser.add_argument(
        "-r",
        "--no-receipt-checks",
        dest="receipt_checks",
        default=True,
        action="store_true",
        help="Do not check receipts (e.g. if they are not in CCF format)",
    )
    service_parser.add_argument(
        "-f",
        "--no-fragmented-checks",
        dest="no_fragmented_checks",
        default=False,
        action="store_true",
        help="Do not check AAAA-fragmented records",
    )
    service_parser.set_defaults(func=service)

    delegation_parser = subparsers.add_parser(
        "delegation", aliases=["d"], help="verify aDNS delegation"
    )
    delegation_parser.add_argument(
        "domain",
        type=str,
        help="aDNS-registered domain name",
    )
    delegation_parser.add_argument(
        "-c",
        "--ca-certificate",
        dest="ca_certificate_files",
        type=str,
        required=False,
        nargs="+",
        help="CA certificate filename",
    )
    delegation_parser.add_argument(
        "-p",
        "--https-port",
        type=str,
        help="aDNS server HTTPS (management) port",
        default=8443,
    )
    delegation_parser.add_argument(
        "-a",
        "--parent",
        type=str,
        required=False,
        help="Parent aDNS server",
        default=None,
    )
    delegation_parser.add_argument(
        "-n",
        "--name-server",
        type=str,
        required=False,
        nargs="+",
        help="Nameserver IP addresses",
        default=None,
        dest="nameservers",
    )
    delegation_parser.add_argument(
        "-r",
        "--no-receipt-checks",
        dest="receipt_checks",
        default=True,
        action="store_true",
        help="Do not check receipts (e.g. if they are not in CCF format)",
    )
    delegation_parser.add_argument(
        "-f",
        "--no-fragmented-checks",
        dest="no_fragmented_checks",
        default=False,
        action="store_true",
        help="Do not check AAAA-fragmented records",
    )
    delegation_parser.set_defaults(func=delegation)

    margs = parser.parse_args()
    margs.func(margs)
