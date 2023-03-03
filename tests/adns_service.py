# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import glob
import http
import time
import base64
import subprocess
import json
import logging
import requests
import tempfile

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
from infra.interfaces import (
    RPCInterface,
    AppProtocol,
    Endorsement,
    EndorsementAuthority,
    HostSpec,
    PRIMARY_RPC_INTERFACE,
)

import dns
import dns.message
import dns.query
import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

from loguru import logger as LOG

import pebble
import adns_tools

DEFAULT_NODES = ["local://127.0.0.1:8080"]

nonzero_mrenclave_policy = """
    let r = true;
    for (const [name, claims] of Object.entries(data.claims)) {
        r &= claims.sgx_claims.report_body.mr_enclave.length == 32 &&
            JSON.stringify(claims.custom_claims.sgx_report_data) != JSON.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
    r == true
"""


class ServiceCAConfig(dict):
    def __init__(self, name, directory, certificates=[]):
        dict.__init__(
            self, name=name, directory=directory, ca_certificates=certificates
        )
        self.name = name
        self.directory = directory
        self.certificates = certificates


class aDNSConfig(dict):
    """aDNS arguments"""

    def __init__(
        self,
        origin,
        service_name,
        node_addresses,
        soa,
        default_ttl,
        signing_algorithm,
        digest_type,
        use_key_signing_key,
        use_nsec3,
        nsec3_hash_algorithm,
        nsec3_hash_iterations,
        parent_base_url,
        service_ca,
        fixed_zsk=None,
    ):
        dict.__init__(
            self,
            origin=origin,
            service_name=service_name,
            node_addresses=node_addresses,
            soa=soa,
            default_ttl=default_ttl,
            signing_algorithm=signing_algorithm,
            digest_type=digest_type,
            use_key_signing_key=use_key_signing_key,
            use_nsec3=use_nsec3,
            nsec3_hash_algorithm=nsec3_hash_algorithm,
            nsec3_hash_iterations=nsec3_hash_iterations,
            parent_base_url=parent_base_url,
            service_ca=service_ca,
            fixed_zsk=fixed_zsk,
        )
        self.origin = origin
        self.service_name = service_name
        self.node_addresses = node_addresses
        self.soa = soa
        self.default_ttl = default_ttl
        self.signing_algorithm = signing_algorithm
        self.digest_type = digest_type
        self.use_key_signing_key = use_key_signing_key
        self.use_nsec3 = use_nsec3
        self.nsec3_hash_algorithm = nsec3_hash_algorithm
        self.nsec3_hash_iterations = nsec3_hash_iterations
        self.parent_base_url = parent_base_url
        self.service_ca = service_ca
        self.fixed_zsk = fixed_zsk


def add_record(client, origin, name, stype, rdata_obj):
    r = client.post(
        "/app/internal/add",
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


def configure(base_url, cabundle, config):
    """Configure an aDNS service"""

    url = base_url + "/app/configure"
    r = requests.post(
        url,
        json.dumps(config),
        timeout=10,
        verify=cabundle,
        headers={"Content-Type": "application/json"},
    )
    assert (
        r.status_code == http.HTTPStatus.OK
        or r.status_code == http.HTTPStatus.NO_CONTENT
    )
    reginfo = r.json()["registration_info"]
    assert "x-ms-ccf-transaction-id" in r.headers

    reginfo["configuration_receipt"] = adns_tools.poll_for_receipt(
        base_url, cabundle, r.headers["x-ms-ccf-transaction-id"]
    )
    return reginfo


def populate(network, args):
    """Populate the zone with example entries"""
    primary, _ = network.find_primary()

    with primary.client() as client:
        origin = args.origin

        rd = dns.rdata.from_text(rdc.IN, rdt.A, "51.143.161.224")
        add_record(client, origin, origin, "A", rd)

        rd = dns.rdata.from_text(rdc.IN, rdt.NS, "ns1." + origin)
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
        add_record(client, origin, "cwinter", "TXT", rd)


def start_dns_to_http_proxy(binary, host, port, query_url, network_cert):
    args = [
        binary,
        "-a",
        host,
        "-p",
        port,
        "-r",
        query_url,
        "-v",
        "-v",
        "-l",
        "doh_proxy_" + host + ".log",
        "-C",
        network_cert,
    ]

    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def set_policy(network, proposal_name, policy):
    primary, _ = network.find_primary()

    proposal_body, careful_vote = network.consortium.make_proposal(
        proposal_name, new_policy=policy
    )

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )


def get_endorsed_certs(network, name):
    """Get the endorsed network certificate"""

    primary, _ = network.find_primary()
    r = None
    with primary.client() as client:
        r = client.post(
            "/app/get-certificate",
            {"service_dns_name": name},
        )

    assert r.status_code == http.HTTPStatus.OK
    chain = json.loads(str(r.body))["certificate"]
    return adns_tools.split_pem(chain)


def wait_for_endorsed_certs(network, name, num_retries=20):
    """Wait until an endorsed network certificate is available"""
    while num_retries > 0:
        try:
            return get_endorsed_certs(network, name)
        except Exception:
            num_retries = num_retries - 1
        time.sleep(1)
    if num_retries == 0:
        raise Exception("Failed to obtain endorsed network certificate")


def make_acme_config(args, service_dns_name):
    """Build an ACME configuration for CCF"""

    config_name = args.acme_config_name
    config = {
        "ca_certs": [],
        "directory_url": "",
        "challenge_type": "dns-01",
        "contact": [],
        "service_dns_name": service_dns_name,
        "terms_of_service_agreed": True,
        "alternative_names": [],
    }

    if config_name != "custom":
        if config_name == "pebble":
            acme_directory = "https://127.0.0.1:1024/dir"
            email = args.email
            challenge_type = "http-01"
        elif config_name == "pebble-dns":
            acme_directory = "https://127.0.0.1:1024/dir"
            email = args.email
            challenge_type = "dns-01"
        elif config_name == "letsencrypt":
            if args.acme_http_port != 80:
                raise Exception(
                    "invalid HTTP port for Let's Encrypt ACME http-01 challenge"
                )
            # Note: cchost needs: sudo setcap 'cap_net_bind_service=+ep' cchost
            acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
            args.adns["ca_certs"] += [
                "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD\nExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq\nu785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA\nivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\nAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA\nKGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm\nMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl\nbmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy\nLm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI\nzj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY\nN5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm\n3HMFKzIR8eEPsMx4smMl\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\nFQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\nVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\nKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\nuc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\nvbtH7QiVzeKCOTQPINyRql6P\n-----END CERTIFICATE-----\n",
            ]
            if not args.email:
                raise Exception("Valid e-mail address is required for Let's Encrypt")
            email = args.email
            challenge_type = "http-01"
        else:
            acme_directory = args.acme_directory if "acme_directory" in args else ""
            email = args.email
            challenge_type = "http-01"

        config = {
            "ca_certs": args.ca_certs,
            "directory_url": acme_directory,
            "service_dns_name": service_dns_name,
            "contact": ["mailto:" + email],
            "terms_of_service_agreed": True,
            "challenge_type": challenge_type,
            "alternative_names": [],
        }

    return config_name, config


def assign_node_addresses(network, addr, add_node_id=True):
    """Assign shortened node IDs as node names"""
    node_addresses = {}
    for node in network.nodes:
        for _, _, ext_name, ext_ip in addr:
            ext_if = node.host.rpc_interfaces["ext_if"]
            if ext_if.public_host == ext_name:
                name = ext_name
                if add_node_id:
                    name = node.node_id[:12] + "." + name
                node_addresses[node.node_id] = {
                    "name": name + ".",
                    "protocol": ext_if.transport,
                    "ip": ext_ip,
                    "port": ext_if.public_port,
                }
    return node_addresses


def run(args, wait_for_endorsed_cert=False, with_proxies=True, tcp_port=None):
    """Start an aDNS server network"""

    service_dns_name = args.adns.origin.strip(".")

    # DoH Proxy is here: https://github.com/aarond10/https_dns_proxy
    # Note: proxy needs: sudo setcap 'cap_net_bind_service=+ep' https_dns_proxy
    doh_proxy_binary = "https_dns_proxy"
    proxy_procs = []

    acme_config_name, acme_config = make_acme_config(args, service_dns_name)

    args.acme = {"configurations": {acme_config_name: acme_config}}

    try:
        nodes = []
        for internal, external, ext_name, _ in args.node_addresses:
            host_spec = HostSpec.from_str(internal, http2=False)
            # int_if = host_spec.rpc_interfaces[PRIMARY_RPC_INTERFACE]
            ext_if = HostSpec.from_str(external, http2=False).rpc_interfaces[
                PRIMARY_RPC_INTERFACE
            ]
            ext_if.forwarding_timeout = 10000
            ext_if.endorsement = Endorsement(
                authority=EndorsementAuthority.ACME, acme_configuration=acme_config_name
            )
            ext_if.public_host = ext_name
            ext_if.public_port = ext_if.port
            host_spec.rpc_interfaces["ext_if"] = ext_if

            if tcp_port:
                tcp_dns_if = RPCInterface(
                    host=ext_if.host,
                    port=tcp_port,
                    transport="tcp",
                    endorsement=Endorsement(authority=EndorsementAuthority.Unsecured),
                    app_protocol=AppProtocol.Custom,
                )
                host_spec.rpc_interfaces["tcp_dns_if"] = tcp_dns_if

            nodes += [host_spec]

        network = infra.network.Network(
            nodes,
            args.binary_dir,
            args.debug_nodes,
            args.perf_nodes,
            library_dir=args.library_dir,
        )
        network.start_and_open(args)

        args.adns.node_addresses = args.adns["node_addresses"] = assign_node_addresses(
            network, args.node_addresses, False
        )

        set_policy(network, "set_registration_policy", nonzero_mrenclave_policy)
        set_policy(network, "set_delegation_policy", nonzero_mrenclave_policy)

        if with_proxies:
            done = []
            for host_spec in network.nodes:
                rpif = host_spec.host.rpc_interfaces[PRIMARY_RPC_INTERFACE]
                rhost, rport = rpif.host, rpif.port
                if rhost not in done:
                    net_cert_path = os.path.join(
                        host_spec.common_dir, "service_cert.pem"
                    )
                    proxy_procs += [
                        start_dns_to_http_proxy(
                            doh_proxy_binary,
                            rhost,
                            "53",
                            "https://" + rhost + ":" + str(rport) + "/app/dns-query",
                            net_cert_path,
                        )
                    ]
                    done += [rhost]

        pif0 = nodes[0].rpc_interfaces[PRIMARY_RPC_INTERFACE]
        base_url = "https://" + pif0.host + ":" + str(pif0.port)

        reginfo = configure(base_url, network.cert_path, args.adns)

        endorsed_certs = None
        if wait_for_endorsed_cert:
            endorsed_certs = wait_for_endorsed_certs(
                network, service_dns_name, num_retries=10000
            )

        # TODO: restart the proxy with endorsed_cert?

        LOG.success("Server/network for {} running.", args.adns["origin"])

        if args.wait_forever:
            LOG.info("Waiting forever...")
            while True:
                time.sleep(1)
        else:
            return network, proxy_procs, endorsed_certs, reginfo

    except Exception:
        logging.exception("caught exception")
        if proxy_procs:
            for p in proxy_procs:
                p.kill()

    return None, None, None, None


if __name__ == "__main__":

    def add(parser):
        """Add parser"""
        parser.description = "DNS sandboxing for aDNS networks"

        parser.add_argument(
            "-n",
            "--node",
            help=f"List of (local://|ssh://)hostname:port[,pub_hostnames:pub_port]. Default is {DEFAULT_NODES}",
            action="append",
            default=[],
        )

        parser.add_argument(
            "--acme",
            help="ACME configuration name",
            action="store",
            dest="acme_config_name",
            default="pebble",
        )

        parser.add_argument(
            "--service-port",
            help="Port for ACME-endorsed interface",
            action="store",
            dest="service_port",
            default=8443,
        )

        parser.add_argument(
            "--http-port",
            help="Port for unsecured ACME HTTP challenge server",
            action="store",
            dest="acme_http_port",
            default=8080,  # Pick something that the firewall lets through
        )

        parser.add_argument("--wait-forever", help="Wait forever", action="store_true")

    procs = []

    pebble_args = pebble.Arguments(
        dns_address="ns1.adns.ccf.dev:53",
        wait_forever=False,
        http_port=8080,
        ca_cert_filename="pebble-tls-cert.pem",
        config_filename="pebble.config.json",
    )

    pebble_proc, _, _ = pebble.run_pebble(pebble_args)
    procs += [pebble_proc]
    while not os.path.exists(pebble_args.ca_cert_filename):
        time.sleep(0.25)
    pebble_certs = pebble.ca_certs(pebble_args.mgmt_address)
    pebble_certs += pebble.ca_certs_from_file(pebble_args.ca_cert_filename)

    gargs = infra.e2e_args.cli_args(add)
    gargs.node = ["local://10.1.0.4:8443"]
    gargs.nodes = infra.e2e_args.min_nodes(gargs, f=0)
    gargs.constitution = glob.glob("../tests/constitution/*")
    gargs.package = "libccfdns"
    gargs.proxy_ip = "10.1.0.4"
    gargs.wait_for_endorsed_cert = False
    gargs.fixed_zsk = False
    gargs.ca_certs = pebble_certs
    gargs.email = "cwinter@microsoft.com"

    gargs.adns = {
        "configuration": {
            "origin": "adns.ccf.dev.",
            "soa": str(
                SOA.SOA(
                    rdc.IN,
                    rdt.SOA,
                    mname="ns1." + gargs.origin,
                    rname="some-dev.my-site.com.",
                    serial=4,
                    refresh=604800,
                    retry=86400,
                    expire=2419200,
                    minimum=0,
                )
            ),
            "name": "ns1.adns.ccf.dev.",
            "ip": "51.143.161.224",
            "default_ttl": 86400,
            "signing_algorithm": "ECDSAP384SHA384",
            "digest_type": "SHA384",
            "use_key_signing_key": True,
            "use_nsec3": True,
            "nsec3_hash_algorithm": "SHA1",
            "nsec3_hash_iterations": 3,
            "ca_certs": [],
            "service_ca": {
                "directory": "https://127.0.0.1:1024/dir",
                "ca_certificates": pebble_certs,
            },
        }
    }

    nw = None
    procs = []
    try:
        nw, p, _, _ = run(gargs)
        procs += [p]
    finally:
        if nw:
            nw.stop_all_nodes()
        if procs:
            for p in procs:
                if p:
                    p.kill()
