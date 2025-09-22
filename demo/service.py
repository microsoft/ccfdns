import ssl
import http
import base64
import tempfile
import os
import datetime
import ipaddress
import requests
import json
import urllib3
from hashlib import sha256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from http.server import BaseHTTPRequestHandler
import socketserver


class HTTPSHandler(BaseHTTPRequestHandler):
    """Simple HTTPS request handler"""

    def do_GET(self):
        """Handle GET requests"""
        print(f"GET request from {self.client_address}: {self.path}")

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        response = f"Hello from HTTPS server! You requested: {self.path}\n"
        self.wfile.write(response.encode())

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        print(f"POST request from {self.client_address}: {self.path}")
        print(f"POST data: {post_data.decode()}")

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        response = f"Echo: {post_data.decode()}\n"
        self.wfile.write(response.encode())


class ThreadedHTTPSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded HTTPS server"""

    allow_reuse_address = True


def generate_self_signed_cert(name):
    """Generate a self-signed certificate and private key"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(name),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert, private_key


def create_https_server(host, port, cert_path, key_path):
    try:
        server = ThreadedHTTPSServer((host, port), HTTPSHandler)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_path, key_path)
        context.verify_mode = ssl.CERT_NONE

        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(f"HTTPS server starting on {host}:{port}")
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
    finally:
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except:
            pass


def gen_csr(domain, key):
    """Generate CSR for registration request"""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(domain),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr


def get_dummy_attestation(report_data):
    """Generate dummy attestation for virtual enclave"""
    measurement = base64.b64encode(
        b"Insecure hard-coded virtual measurement v1"
    ).decode()
    attestation = {
        "measurement": measurement,
        "report_data": base64.b64encode(report_data).decode(),
    }
    return base64.b64encode(json.dumps(attestation).encode()).decode()


def get_attestation(report_data, enclave="virtual"):
    """Get attestation data for the given enclave type"""
    if enclave == "virtual":
        attestation = get_dummy_attestation(report_data)
        endorsements = ""
        uvm_endorsements = ""
    else:
        raise ValueError(f"Unknown enclave platform: {enclave}")

    attestation_format = "Insecure_Virtual" if enclave == "virtual" else "Unknown"
    dummy_attestation = {
        "format": attestation_format,
        "quote": attestation,
        "endorsements": endorsements,
        "uvm_endorsements": uvm_endorsements,
    }
    return json.dumps(dummy_attestation)


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Simple HTTPS Server with Self-Signed Certificate"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: localhost)"
    )
    parser.add_argument("--port", type=int, default=12345, help="Port to bind to")
    parser.add_argument(
        "--dns-name",
        default="supermegaserver.com",
        help="DNS name for the server (default: supermegaserver.com)",
    )
    parser.add_argument(
        "--adns",
        default=None,
        help="ADNS address",
    )

    args = parser.parse_args()

    print("Generating self-signed certificate...")
    cert, private_key = generate_self_signed_cert(name=args.dns_name)

    # Create temporary files for cert and key
    with tempfile.NamedTemporaryFile(
        mode="wb", delete=False, suffix=".crt"
    ) as cert_file:
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file.write(cert_pem)
        cert_path = cert_file.name

    with tempfile.NamedTemporaryFile(
        mode="wb", delete=False, suffix=".key"
    ) as key_file:
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_file.write(key_pem)
        key_path = key_file.name

    # Also save the certificate to a known location for client verification
    known_cert_path = "/tmp/server_cert.pem"
    with open(known_cert_path, "wb") as f:
        f.write(cert_pem)

    print(f"Server certificate saved to: {known_cert_path}")

    assert args.adns
    print(f"Registering service with ADNS at: {args.adns}")

    # Use the same private key that was generated for the server certificate
    service_key = private_key

    # Generate report data from the public key
    public_key = service_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    report_data = sha256(public_key).digest()

    # Create HTTPS request for ADNS
    try:
        # Disable SSL warnings for self-signed certs
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Submit service registration
        attestation = get_attestation(report_data, enclave="virtual")

        # Prepare registration data
        csr = gen_csr(args.dns_name, service_key)
        registration_data = {
            "csr": base64.b64encode(
                csr.public_bytes(serialization.Encoding.DER)
            ).decode(),
            "node_information": {
                # Possible to register multiple instances in one call
                "default": {
                    "address": {
                        "name": args.dns_name,
                        "ip": "127.0.0.1",
                        "protocol": "tcp",
                        "port": args.port,
                    },
                    "attestation": attestation,
                }
            },
        }

        # Make direct HTTPS request
        response = requests.post(
            f"https://{args.adns}/app/register-service",
            json=registration_data,
            verify=False,  # Skip SSL verification for self-signed certs
        )

        if response.status_code == http.HTTPStatus.NO_CONTENT:
            print(f"Service registration successful: {response.status_code}")
        else:
            print(
                f"Service registration failed: {response.status_code} {response.text}"
            )

    except Exception as e:
        print(f"Service registration failed: {e}")

    try:
        create_https_server(args.host, args.port, cert_path, key_path)
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()
