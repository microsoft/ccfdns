# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
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

service_port = 8080
DEFAULT_NODES = ["local://127.0.0.1:" + str(service_port)]


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


# def start_dnscrypt_proxy(binary):
#     # service_cert = "workspace/adns.ccf.dev_common/service_cert.pem"
#     # hash = (
#     #     subprocess.Popen(
#     #         f"openssl asn1parse -in {service_cert} -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256",
#     #         shell=True,
#     #         stdout=subprocess.PIPE,
#     #     )
#     #     .stdout.read()
#     #     .decode("ascii")
#     # )
#     # hash = hash[hash.find(" ") + 1 :]

#     # service_cert2 = "workspace/adns.ccf.dev_0/0.pem"
#     # hash2 = (
#     #     subprocess.Popen(
#     #         f"openssl asn1parse -in {service_cert2} -out /dev/stdout -noout -strparse 4 | openssl dgst -sha256",
#     #         shell=True,
#     #         stdout=subprocess.PIPE,
#     #     )
#     #     .stdout.read()
#     #     .decode("ascii")
#     # )
#     # hash2 = hash2[hash2.find(" ") + 1 :]

#     shutil.copy("../tests/dnscrypt-proxy.toml", "dnscrypt-proxy.toml")

#     stamp = dnsstamps.create_doh(
#         "10.1.0.4",
#         [],
#         "10.1.0.4:8000",
#         "/app/dns-query",
#         [],
#     )

#     with open("dnscrypt-proxy.toml", "a", encoding="ascii") as f:
#         f.write(f"\n    stamp='{stamp}'\n")

#     try:
#         p = subprocess.Popen(
#             [binary, "-config", "dnscrypt-proxy.toml"],
#         )

#         pebble.wait_for_port_to_listen("127.0.0.1", 53, 5)
#     except:
#         if p:
#             p.kill()

#     return p


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
        "debug",
        "-x",
        "-C",
        network_cert,
    ]
    print(args)
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def public_host_port(listen_addr):
    prot_host_port = listen_addr.split("//")
    host_port = prot_host_port[1].split(":")
    public_host = host_port[0]
    public_port = host_port[1] if len(host_port) > 1 else "53"
    return public_host, public_port


def run(args):
    """Start the network"""

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

    # Proxy is here: https://github.com/aarond10/https_dns_proxy
    # Note: proxy needs: sudo setcap 'cap_net_bind_service=+ep' https_dns_proxy
    doh_proxy_binary = "/data/cwinter/https_dns_proxy/build/https_dns_proxy"

    acme_config_name = "pebble"
    acme_directory = "https://127.0.0.1:1024/dir"
    ca_certs = [open(ca_cert_filename, mode="r", encoding="ascii").read()]
    email = "nobody@example.com"
    http_port = 8000  # pick something that the firewall allows through

    # Note: cchost needs: sudo setcap 'cap_net_bind_service=+ep' https_dns_proxy
    # acme_config_name = "letsencrypt"
    # acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
    # ca_certs = [
    #     "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n",
    #     "-----BEGIN CERTIFICATE-----\nMIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD\nExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq\nu785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA\nivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\nAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA\nKGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm\nMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl\nbmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy\nLm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI\nzj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY\nN5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm\n3HMFKzIR8eEPsMx4smMl\n-----END CERTIFICATE-----\n",
    #     "-----BEGIN CERTIFICATE-----\nMIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\nFQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\nVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\nKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\nuc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\nvbtH7QiVzeKCOTQPINyRql6P\n-----END CERTIFICATE-----\n",
    # ]
    # email = "cwinter@microsoft.com"
    # http_port = 80

    public_host, public_port = public_host_port(args.node[0])

    if acme_config_name == "pebble":
        pebble.make_pebble_config(
            config_filename,
            listen_address,
            mgmt_address,
            ca_cert_filename,
            ca_key_filename,
            http_port,
            tls_port,
        )

    with open(output_filename, "w", encoding="ascii") as pebble_out:
        with open(error_filename, "w", encoding="ascii") as pebble_err:

            if acme_config_name == "pebble":
                pproc = pebble.run_proc(
                    pebble_filename,
                    config_filename,
                    dns_address,
                    listen_address,
                    pebble_out,
                    pebble_err,
                )

            for node in args.nodes:
                endoed_if = infra.interfaces.RPCInterface(
                    host=public_host,
                    port=service_port,
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.ACME,
                        acme_configuration=acme_config_name,
                    ),
                    public_host=service_dns_name,
                )
                node.rpc_interfaces["acme_endorsed_interface"] = endoed_if
                node.rpc_interfaces[
                    "acme_challenge_server_if"
                ] = infra.interfaces.RPCInterface(
                    host=public_host,
                    port=http_port,
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.Unsecured
                    ),
                    accepted_endpoints=["/.well-known/acme-challenge/.*"],
                )

            args.acme = {
                "configurations": {
                    acme_config_name: {
                        "ca_certs": ca_certs,
                        "directory_url": acme_directory,
                        "service_dns_name": service_dns_name,
                        "contact": ["mailto:" + email],
                        "terms_of_service_agreed": True,
                        "challenge_type": "http-01",
                        "challenge_server_interface": "acme_challenge_server_if",
                    }
                }
            }

            with infra.network.network(
                args.nodes,
                binary_directory=args.binary_dir,
                library_directory=args.library_dir,
                dbg_nodes=args.debug_nodes,
            ) as network:
                network.start_and_open(args)
                populate_adns_ccf_dev(network, args)

                proxy_proc = None
                try:
                    node = network.find_random_node()
                    primary_if = node.host.rpc_interfaces[
                        infra.interfaces.PRIMARY_RPC_INTERFACE
                    ]
                    host, port = primary_if.host, primary_if.port
                    net_cert_path = os.path.join(node.common_dir, "service_cert.pem")

                    proxy_proc = start_dns_to_http_proxy(
                        doh_proxy_binary,
                        public_host,
                        public_port,
                        "https://" + host + ":" + str(port) + "/app/dns-query",
                        net_cert_path,
                    )

                    # TODO: wait for ACME cert to become available, then restart the proxy with the endorsed interface.

                    LOG.info("Waiting forever...")
                    while True:
                        time.sleep(1)
                except Exception as ex:
                    print(f"Exception: {ex}")
                finally:
                    if proxy_proc:
                        proxy_proc.kill()

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
