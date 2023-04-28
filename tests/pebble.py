import os
import sys
import json
import subprocess
import time
import socket
import urllib
import urllib.request
import ssl
import datetime

from loguru import logger as LOG

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import adns_tools


def wait_for_port_to_listen(host, port, timeout=10):
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            socket.create_connection((host, int(port)), timeout=0.25)
            return
        except Exception as ex:
            LOG.trace(f"Likely expected exception: {ex}")
            time.sleep(0.5)
    raise TimeoutError(f"port did not start listening within {timeout} seconds")


def start_pebble_process(
    filename, config_filename, dns_address, listen_address, out, err, env
):
    args = [filename, "-config", config_filename]
    if dns_address:
        args += ["-dnsserver", dns_address]
    p = subprocess.Popen(
        args,
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


def ca_certs(mgmt_address):
    """Get the pebble CA certificate(s)"""
    ca = get_without_cert_check("https://" + mgmt_address + "/roots/0")
    intermediate = get_without_cert_check(
        "https://" + mgmt_address + "/intermediates/0"
    )
    return [intermediate, ca]


def generate_self_signed_cert(key, subject):
    """Generate a self-signed certificate"""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def make_pebble_config(
    config_filename,
    listen_address,
    mgmt_address,
    ca_cert_filename,
    ca_key_filename,
    http_port,
    tls_port,
):
    """Create a pebble config file"""
    pebble_config = {
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
        json.dump(pebble_config, f)


def get_pebble_ca_certs(mgmt_address):
    """Get the pebble CA certificate(s)"""
    ca = get_without_cert_check("https://" + mgmt_address + "/roots/0")
    intermediate = get_without_cert_check(
        "https://" + mgmt_address + "/intermediates/0"
    )
    return [intermediate, ca]


class Arguments:
    """Pebble arguments"""

    def __init__(
        self,
        binary_filename="/opt/pebble/pebble_linux-amd64",
        config_filename="pebble.config.json",
        ca_key_filename="pebble-key.pem",
        ca_cert_filename="pebble-tls-cert.pem",
        output_filename="pebble.out",
        error_filename="pebble.err",
        listen_address="127.0.0.1:1024",
        mgmt_address="127.0.0.1:1025",
        dns_address=None,
        tls_port=1026,
        http_port=1027,
        wait_forever=False,
    ):
        self.binary_filename = binary_filename
        self.config_filename = config_filename
        self.ca_key_filename = ca_key_filename
        self.ca_cert_filename = ca_cert_filename
        self.output_filename = output_filename
        self.error_filename = error_filename
        self.listen_address = listen_address
        self.mgmt_address = mgmt_address
        self.dns_address = dns_address
        self.tls_port = tls_port
        self.http_port = http_port
        self.wait_forever = wait_forever


def run_pebble(args):
    """Run pebble"""

    if not os.path.exists(args.binary_filename):
        raise Exception(f"pebble not found at {args.binary_filename}")

    make_pebble_config(
        args.config_filename,
        args.listen_address,
        args.mgmt_address,
        args.ca_cert_filename,
        args.ca_key_filename,
        args.http_port,
        args.tls_port,
    )

    ca_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    with open(args.ca_key_filename, "w", encoding="ascii") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("ascii")
        )

    ca_cert = generate_self_signed_cert(ca_key, "Pebble Test CA")
    with open(args.ca_cert_filename, "w", encoding="ascii") as f:
        f.write(
            ca_cert.public_bytes(encoding=serialization.Encoding.PEM).decode("ascii")
        )

    if args.wait_forever:
        run_blocking(
            args.output_filename,
            args.error_filename,
            args.binary_filename,
            args.config_filename,
            args.dns_address,
            args.listen_address,
            args.mgmt_address,
        )
        return None, None, None
    else:
        return run_pebble_proc(args)


def run_proc(binary_filename, config_filename, dns_address, listen_address, out, err):
    """Start the pebble process"""
    return start_pebble_process(
        binary_filename,
        config_filename,
        dns_address,
        listen_address,
        out,
        err,
        env={"PEBBLE_WFE_NONCEREJECT": "0", "PEBBLE_VA_NOSLEEP": "1"},
    )


def run_pebble_proc(args):
    """Start background pebble proc"""

    out = open(args.output_filename, "w", encoding="ascii")
    err = open(args.error_filename, "w", encoding="ascii")
    proc = run_proc(
        args.binary_filename,
        args.config_filename,
        args.dns_address,
        args.listen_address,
        out,
        err,
    )

    with open("pebble.pem", "w", encoding="ascii") as f:
        cs = get_pebble_ca_certs(args.mgmt_address)
        if cs:
            for c in cs:
                f.write(c)

    return proc, out, err


def ca_certs_from_file(filename):
    return adns_tools.split_pem(open(filename, mode="r", encoding="ascii").read())


def run_blocking(
    output_filename,
    error_filename,
    binary_filename,
    config_filename,
    dns_address,
    listen_address,
    mgmt_address,
):
    """Start and keep pebble running forever"""
    exception_seen = None
    pebble_proc = None

    try:
        with open(output_filename, "w", encoding="ascii") as out:
            with open(error_filename, "w", encoding="ascii") as err:
                pebble_proc = run_proc(
                    binary_filename,
                    config_filename,
                    dns_address,
                    listen_address,
                    out,
                    err,
                )

                _ = ca_certs(mgmt_address)

                LOG.success("Pebble running.")

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
    run_pebble(sys.argv)
