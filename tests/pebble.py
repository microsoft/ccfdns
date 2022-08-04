import os
import json
import subprocess
import time
import socket
import urllib
import ssl
import infra.e2e_args

from loguru import logger as LOG


def wait_for_port_to_listen(host, port, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            socket.create_connection((host, int(port)), timeout=0.1)
            return
        except Exception as ex:
            LOG.trace(f"Likely expected exception: {ex}")
            time.sleep(0.5)
    raise TimeoutError(f"port did not start listening within {timeout} seconds")


def start_pebble_process(
    filename, config_filename, dns_address, listen_address, out, err, env
):
    p = subprocess.Popen(
        [filename, "-config", config_filename, "-dnsserver", dns_address],
        stdout=out,
        stderr=err,
        close_fds=True,
        env=env,
    )
    host, port = listen_address.split(":")
    wait_for_port_to_listen(host, port, 5)
    return p


def get_without_cert_check(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx).read().decode("utf-8")


def get_pebble_ca_certs(mgmt_address):
    ca = get_without_cert_check("https://" + mgmt_address + "/roots/0")
    intermediate = get_without_cert_check(
        "https://" + mgmt_address + "/intermediates/0"
    )
    return ca, intermediate


def run_pebble(args):
    binary_filename = "/opt/pebble/pebble_linux-amd64"
    config_filename = "pebble.config.json"
    ca_key_filename = "pebble-key.pem"
    ca_cert_filename = "pebble-ca-cert.pem"
    output_filename = "pebble.out"
    error_filename = "pebble.err"
    listen_address = "127.0.0.1:1024"
    mgmt_address = "127.0.0.1:1025"
    dns_address = "ns1.adns.ccf.dev"
    tls_port = 1026
    http_port = 1027

    network_name = "my-network.ccf.dev"

    if not os.path.exists(binary_filename) or not os.path.exists(binary_filename):
        raise Exception("pebble not found; run playbooks to install it")

    config = {
        "pebble": {
            "listenAddress": listen_address,
            "managementListenAddress": mgmt_address,
            "certificate": ca_cert_filename,
            "privateKey": ca_key_filename,
            "httpPort": http_port,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": False,
        }
    }
    with open(config_filename, "w", encoding="ascii") as f:
        json.dump(config, f)

    ca_key, _ = infra.crypto.generate_ec_keypair("secp384r1")
    with open(ca_key_filename, "w", encoding="ascii") as f:
        f.write(ca_key)

    ca_cert = infra.crypto.generate_cert(ca_key, ca=True, cn="Pebble Test CA")
    with open(ca_cert_filename, "w", encoding="ascii") as f:
        f.write(ca_cert)

    args.acme = {
        "configurations": {
            "pebble": {
                "ca_certs": [ca_cert],
                "directory_url": f"https://{listen_address}/dir",
                "service_dns_name": network_name,
                "contact": ["mailto:nobody@example.com"],
                "terms_of_service_agreed": True,
                "challenge_type": "dns-01",
            }
        }
    }

    exception_seen = None
    pebble_proc = None

    try:
        with open(output_filename, "w", encoding="ascii") as out:
            with open(error_filename, "w", encoding="ascii") as err:
                pebble_proc = start_pebble_process(
                    binary_filename,
                    config_filename,
                    dns_address,
                    listen_address,
                    out,
                    err,
                    env={"PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_VA_NOSLEEP": "1"},
                )

                a_certs = get_pebble_ca_certs(mgmt_address)

                LOG.info("Pebble running.")

                while True:
                    time.sleep(0.1)

    except Exception as ex:
        exception_seen = ex
    finally:
        if pebble_proc:
            pebble_proc.kill()

    if exception_seen:
        LOG.info("Pebble out:")
        LOG.info(open(output_filename, "r", encoding="ascii").read())
        LOG.info("Pebble err:")
        LOG.info(open(error_filename, "r", encoding="ascii").read())
        raise exception_seen


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run_pebble(args)