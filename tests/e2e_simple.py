# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import glob
import time
import http
import base64
import socket
import requests
import json

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher

import adns_service
from adns_service import aDNSConfig, ServiceCAConfig
import pebble

import dns
import dns.message
import dns.query
import dns.dnssec
import dns.rrset
import dns.rdtypes.ANY.SOA as SOA

rdc = dns.rdataclass
rdt = dns.rdatatype


def add_record(client, origin, name, stype, rdata_obj):
    """Add a DNS record"""
    print(f"Adding {stype} record for {name}...")
    r = client.post(
        "/app/internal/add",
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
    printf(response={r})
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


def mk_update_policy_proposal(new_policy):
    """Create a policy proposal for updating the registration policy"""
    return {
        "actions": [
            {
                "name": "set_member",
                "args": {"policy": new_policy},
            }
        ]
    }


def set_registration_policy(network, args):
    """Set the registration policy"""
    new_policy = """
    data.claims.sgx_claims.report_body.mr_enclave.length == 32 &&
    JSON.stringify(data.claims.custom_claims.some_name) == JSON.stringify([115, 111, 109, 101, 95, 118, 97, 108, 117, 101, 0]);
    """

    primary, _ = network.find_primary()

    proposal_body, careful_vote = network.consortium.make_proposal(
        "set_registration_policy", new_policy=new_policy
    )

    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )

    network.consortium.vote_using_majority(
        primary,
        proposal,
        careful_vote,
    )


def gen_csr(domain, key):
    """Generate CSR for registration request"""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                # Add SANs here
            ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr

def submit_service_registration(
    client, origin, name, address, port, protocol, service_key
):
    """Submit a service registration request"""

    demo_attestation = """{
        "source": "openenclave",
        "evidence": "AwACAAAAAAAIAA0Ak5pyM/ecTKmUCg2zlX8GByV7poCkzztBEA1BOoP0LTUAAAAAExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAL+GiaH9s4KO+lbZ8joVJOwfFkGWioERZbcEz2F49+ALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYAJZJn5IkTD587Qd7hqG0hMYUwp/HikFCd6JbwZEmKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADrJdgfT2OVVBjgFfTo5mAXKqsKIHwd6dJv2Eh35eavyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARBAAAFwOiY5gHFvAX3ASQ1Nh6SzoZHgNbv/fEXRJLwZxq1K2IJKEC2/8bCfYWQDZSCAe6yynuHkC3AJfB9a82FetQJpBWxRiC4Pxuqak78F0MDYo2IQy0PPTta8rsRgAZV3bfZj+xSqjHCfGZIhcoy7C1WCCXBlyL/EkDPTjDQqfJc4cExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAAAHAAAAAAAAAIzlhoW+NuRhh8Izx+me1v5127M/dWetohewd+zYz4L5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADaeHiXlftEWtCNsuUhLnySVEgAQYfKtaGgDAAVzDMzdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjGzAvqVqMFAZBhm+ZXw077rHYxYB/xb3izTOcK9RdQPoy7LkdysbJaKSZh4wSYpv0Vo68mC0liNyw68kKXvRMiAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FANwNAAAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRWpUQ0NCRFNnQXdJQkFnSVZBTDEzdExSZURGVnFSZFc2L2s3ZG1HY0pCSXduTUFvR0NDcUdTTTQ5QkFNQwpNSEV4SXpBaEJnTlZCQU1NR2tsdWRHVnNJRk5IV0NCUVEwc2dVSEp2WTJWemMyOXlJRU5CTVJvd0dBWURWUVFLCkRCRkpiblJsYkNCRGIzSndiM0poZEdsdmJqRVVNQklHQTFVRUJ3d0xVMkZ1ZEdFZ1EyeGhjbUV4Q3pBSkJnTlYKQkFnTUFrTkJNUXN3Q1FZRFZRUUdFd0pWVXpBZUZ3MHlNakEzTVRjd01ETTVNak5hRncweU9UQTNNVGN3TURNNQpNak5hTUhBeElqQWdCZ05WQkFNTUdVbHVkR1ZzSUZOSFdDQlFRMHNnUTJWeWRHbG1hV05oZEdVeEdqQVlCZ05WCkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0cKQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUQWxWVE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRQoxdGc4aDBhTDRDTW81cTZUV3JNa2IrWi8wWEs2ZU9Nc3NLYTEzbXZwWTZMUUN6ZnFzRDdvTUh5ODlHNVhmK2lrCkxxMW9mdlc4czdhV0RUSithMGExdEtPQ0FxZ3dnZ0trTUI4R0ExVWRJd1FZTUJhQUZORG9xdHAxMS9rdVNSZVkKUEhzVVpkRFY4bGxOTUd3R0ExVWRId1JsTUdNd1lhQmZvRjJHVzJoMGRIQnpPaTh2WVhCcExuUnlkWE4wWldSegpaWEoyYVdObGN5NXBiblJsYkM1amIyMHZjMmQ0TDJObGNuUnBabWxqWVhScGIyNHZkak12Y0dOclkzSnNQMk5oClBYQnliMk5sYzNOdmNpWmxibU52WkdsdVp6MWtaWEl3SFFZRFZSME9CQllFRkI1VmxaTitSaEdUVS9KMUpjeDcKbE5Sc0xpVXRNQTRHQTFVZER3RUIvd1FFQXdJR3dEQU1CZ05WSFJNQkFmOEVBakFBTUlJQjFBWUpLb1pJaHZoTgpBUTBCQklJQnhUQ0NBY0V3SGdZS0tvWklodmhOQVEwQkFRUVE3STA4cS9pZ3laYmh6S3FiblpTSDNqQ0NBV1FHCkNpcUdTSWI0VFFFTkFRSXdnZ0ZVTUJBR0N5cUdTSWI0VFFFTkFRSUJBZ0VSTUJBR0N5cUdTSWI0VFFFTkFRSUMKQWdFUk1CQUdDeXFHU0liNFRRRU5BUUlEQWdFQ01CQUdDeXFHU0liNFRRRU5BUUlFQWdFRU1CQUdDeXFHU0liNApUUUVOQVFJRkFnRUJNQkVHQ3lxR1NJYjRUUUVOQVFJR0FnSUFnREFRQmdzcWhraUcrRTBCRFFFQ0J3SUJCakFRCkJnc3Foa2lHK0UwQkRRRUNDQUlCQURBUUJnc3Foa2lHK0UwQkRRRUNDUUlCQURBUUJnc3Foa2lHK0UwQkRRRUMKQ2dJQkFEQVFCZ3NxaGtpRytFMEJEUUVDQ3dJQkFEQVFCZ3NxaGtpRytFMEJEUUVDREFJQkFEQVFCZ3NxaGtpRworRTBCRFFFQ0RRSUJBREFRQmdzcWhraUcrRTBCRFFFQ0RnSUJBREFRQmdzcWhraUcrRTBCRFFFQ0R3SUJBREFRCkJnc3Foa2lHK0UwQkRRRUNFQUlCQURBUUJnc3Foa2lHK0UwQkRRRUNFUUlCQ3pBZkJnc3Foa2lHK0UwQkRRRUMKRWdRUUVSRUNCQUdBQmdBQUFBQUFBQUFBQURBUUJnb3Foa2lHK0UwQkRRRURCQUlBQURBVUJnb3Foa2lHK0UwQgpEUUVFQkFZQWtHN1ZBQUF3RHdZS0tvWklodmhOQVEwQkJRb0JBREFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFVCkp5U1A3YkhpZjM2eEhEN2dmTTFHSEFGL1AvMy80azIzQ2k3OFAxTFQwZ0lnY3BqemNwbEJTbjNjSXMwNzNoY0QKREFxZ0U4L3NtdmNIdng5cDJ3TitBOG89Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNtRENDQWo2Z0F3SUJBZ0lWQU5Eb3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFV3TVRCYUZ3MHpNekExTWpFeE1EVXdNVEJhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lGTkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMrZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pnYnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWtaWEl3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhsbE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VBTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFDSmdUYnRWcU95WjFtM2pxaUFYTTZRWWE2cjVzV1MKNHkvRzd5OHVJSkd4ZHdJZ1JxUHZCU0t6elFhZ0JMUXE1czVBNzBwZG9pYVJKOHovMHVEejROZ1Y5MWs9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAAEAAAAAAAAAAQAAAAAAAAAKAAAAAAAAAAsAAAAAAAAAc29tZV9uYW1lAHNvbWVfdmFsdWUA",
        "endorsements": "AQAAAAIAAABMMAAACQAAAAAAAAAEAAAA8BIAAFUaAAAhHAAA4R0AAFYlAACuKAAAEzAAAAEAAAB7InRjYkluZm8iOnsidmVyc2lvbiI6MiwiaXNzdWVEYXRlIjoiMjAyMS0wMy0zMVQyMjowMzoxM1oiLCJuZXh0VXBkYXRlIjoiMjAyMS0wNC0zMFQyMjowMzoxM1oiLCJmbXNwYyI6IjAwOTA2ZWQ1MDAwMCIsInBjZUlkIjoiMDAwMCIsInRjYlR5cGUiOjAsInRjYkV2YWx1YXRpb25EYXRhTnVtYmVyIjoxMCwidGNiTGV2ZWxzIjpbeyJ0Y2IiOnsic2d4dGNiY29tcDAxc3ZuIjoxNywic2d4dGNiY29tcDAyc3ZuIjoxNywic2d4dGNiY29tcDAzc3ZuIjoyLCJzZ3h0Y2Jjb21wMDRzdm4iOjQsInNneHRjYmNvbXAwNXN2biI6MSwic2d4dGNiY29tcDA2c3ZuIjoxMjgsInNneHRjYmNvbXAwN3N2biI6Niwic2d4dGNiY29tcDA4c3ZuIjowLCJzZ3h0Y2Jjb21wMDlzdm4iOjAsInNneHRjYmNvbXAxMHN2biI6MCwic2d4dGNiY29tcDExc3ZuIjowLCJzZ3h0Y2Jjb21wMTJzdm4iOjAsInNneHRjYmNvbXAxM3N2biI6MCwic2d4dGNiY29tcDE0c3ZuIjowLCJzZ3h0Y2Jjb21wMTVzdm4iOjAsInNneHRjYmNvbXAxNnN2biI6MCwicGNlc3ZuIjoxMH0sInRjYkRhdGUiOiIyMDIwLTExLTExVDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6IlNXSGFyZGVuaW5nTmVlZGVkIn0seyJ0Y2IiOnsic2d4dGNiY29tcDAxc3ZuIjoxNywic2d4dGNiY29tcDAyc3ZuIjoxNywic2d4dGNiY29tcDAzc3ZuIjoyLCJzZ3h0Y2Jjb21wMDRzdm4iOjQsInNneHRjYmNvbXAwNXN2biI6MSwic2d4dGNiY29tcDA2c3ZuIjoxMjgsInNneHRjYmNvbXAwN3N2biI6MCwic2d4dGNiY29tcDA4c3ZuIjowLCJzZ3h0Y2Jjb21wMDlzdm4iOjAsInNneHRjYmNvbXAxMHN2biI6MCwic2d4dGNiY29tcDExc3ZuIjowLCJzZ3h0Y2Jjb21wMTJzdm4iOjAsInNneHRjYmNvbXAxM3N2biI6MCwic2d4dGNiY29tcDE0c3ZuIjowLCJzZ3h0Y2Jjb21wMTVzdm4iOjAsInNneHRjYmNvbXAxNnN2biI6MCwicGNlc3ZuIjoxMH0sInRjYkRhdGUiOiIyMDIwLTExLTExVDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6IkNvbmZpZ3VyYXRpb25BbmRTV0hhcmRlbmluZ05lZWRlZCJ9LHsidGNiIjp7InNneHRjYmNvbXAwMXN2biI6MTUsInNneHRjYmNvbXAwMnN2biI6MTUsInNneHRjYmNvbXAwM3N2biI6Miwic2d4dGNiY29tcDA0c3ZuIjo0LCJzZ3h0Y2Jjb21wMDVzdm4iOjEsInNneHRjYmNvbXAwNnN2biI6MTI4LCJzZ3h0Y2Jjb21wMDdzdm4iOjYsInNneHRjYmNvbXAwOHN2biI6MCwic2d4dGNiY29tcDA5c3ZuIjowLCJzZ3h0Y2Jjb21wMTBzdm4iOjAsInNneHRjYmNvbXAxMXN2biI6MCwic2d4dGNiY29tcDEyc3ZuIjowLCJzZ3h0Y2Jjb21wMTNzdm4iOjAsInNneHRjYmNvbXAxNHN2biI6MCwic2d4dGNiY29tcDE1c3ZuIjowLCJzZ3h0Y2Jjb21wMTZzdm4iOjAsInBjZXN2biI6MTB9LCJ0Y2JEYXRlIjoiMjAyMC0wNi0xMFQwMDowMDowMFoiLCJ0Y2JTdGF0dXMiOiJPdXRPZkRhdGUifSx7InRjYiI6eyJzZ3h0Y2Jjb21wMDFzdm4iOjE1LCJzZ3h0Y2Jjb21wMDJzdm4iOjE1LCJzZ3h0Y2Jjb21wMDNzdm4iOjIsInNneHRjYmNvbXAwNHN2biI6NCwic2d4dGNiY29tcDA1c3ZuIjoxLCJzZ3h0Y2Jjb21wMDZzdm4iOjEyOCwic2d4dGNiY29tcDA3c3ZuIjowLCJzZ3h0Y2Jjb21wMDhzdm4iOjAsInNneHRjYmNvbXAwOXN2biI6MCwic2d4dGNiY29tcDEwc3ZuIjowLCJzZ3h0Y2Jjb21wMTFzdm4iOjAsInNneHRjYmNvbXAxMnN2biI6MCwic2d4dGNiY29tcDEzc3ZuIjowLCJzZ3h0Y2Jjb21wMTRzdm4iOjAsInNneHRjYmNvbXAxNXN2biI6MCwic2d4dGNiY29tcDE2c3ZuIjowLCJwY2Vzdm4iOjEwfSwidGNiRGF0ZSI6IjIwMjAtMDYtMTBUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlQ29uZmlndXJhdGlvbk5lZWRlZCJ9LHsidGNiIjp7InNneHRjYmNvbXAwMXN2biI6MTQsInNneHRjYmNvbXAwMnN2biI6MTQsInNneHRjYmNvbXAwM3N2biI6Miwic2d4dGNiY29tcDA0c3ZuIjo0LCJzZ3h0Y2Jjb21wMDVzdm4iOjEsInNneHRjYmNvbXAwNnN2biI6MTI4LCJzZ3h0Y2Jjb21wMDdzdm4iOjYsInNneHRjYmNvbXAwOHN2biI6MCwic2d4dGNiY29tcDA5c3ZuIjowLCJzZ3h0Y2Jjb21wMTBzdm4iOjAsInNneHRjYmNvbXAxMXN2biI6MCwic2d4dGNiY29tcDEyc3ZuIjowLCJzZ3h0Y2Jjb21wMTNzdm4iOjAsInNneHRjYmNvbXAxNHN2biI6MCwic2d4dGNiY29tcDE1c3ZuIjowLCJzZ3h0Y2Jjb21wMTZzdm4iOjAsInBjZXN2biI6MTB9LCJ0Y2JEYXRlIjoiMjAxOS0xMi0xMVQwMDowMDowMFoiLCJ0Y2JTdGF0dXMiOiJPdXRPZkRhdGUifSx7InRjYiI6eyJzZ3h0Y2Jjb21wMDFzdm4iOjE0LCJzZ3h0Y2Jjb21wMDJzdm4iOjE0LCJzZ3h0Y2Jjb21wMDNzdm4iOjIsInNneHRjYmNvbXAwNHN2biI6NCwic2d4dGNiY29tcDA1c3ZuIjoxLCJzZ3h0Y2Jjb21wMDZzdm4iOjEyOCwic2d4dGNiY29tcDA3c3ZuIjowLCJzZ3h0Y2Jjb21wMDhzdm4iOjAsInNneHRjYmNvbXAwOXN2biI6MCwic2d4dGNiY29tcDEwc3ZuIjowLCJzZ3h0Y2Jjb21wMTFzdm4iOjAsInNneHRjYmNvbXAxMnN2biI6MCwic2d4dGNiY29tcDEzc3ZuIjowLCJzZ3h0Y2Jjb21wMTRzdm4iOjAsInNneHRjYmNvbXAxNXN2biI6MCwic2d4dGNiY29tcDE2c3ZuIjowLCJwY2Vzdm4iOjEwfSwidGNiRGF0ZSI6IjIwMTktMTItMTFUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlQ29uZmlndXJhdGlvbk5lZWRlZCJ9LHsidGNiIjp7InNneHRjYmNvbXAwMXN2biI6MTMsInNneHRjYmNvbXAwMnN2biI6MTMsInNneHRjYmNvbXAwM3N2biI6Miwic2d4dGNiY29tcDA0c3ZuIjo0LCJzZ3h0Y2Jjb21wMDVzdm4iOjEsInNneHRjYmNvbXAwNnN2biI6MTI4LCJzZ3h0Y2Jjb21wMDdzdm4iOjIsInNneHRjYmNvbXAwOHN2biI6MCwic2d4dGNiY29tcDA5c3ZuIjowLCJzZ3h0Y2Jjb21wMTBzdm4iOjAsInNneHRjYmNvbXAxMXN2biI6MCwic2d4dGNiY29tcDEyc3ZuIjowLCJzZ3h0Y2Jjb21wMTNzdm4iOjAsInNneHRjYmNvbXAxNHN2biI6MCwic2d4dGNiY29tcDE1c3ZuIjowLCJzZ3h0Y2Jjb21wMTZzdm4iOjAsInBjZXN2biI6OX0sInRjYkRhdGUiOiIyMDE5LTExLTEzVDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6Ik91dE9mRGF0ZSJ9LHsidGNiIjp7InNneHRjYmNvbXAwMXN2biI6MTMsInNneHRjYmNvbXAwMnN2biI6MTMsInNneHRjYmNvbXAwM3N2biI6Miwic2d4dGNiY29tcDA0c3ZuIjo0LCJzZ3h0Y2Jjb21wMDVzdm4iOjEsInNneHRjYmNvbXAwNnN2biI6MTI4LCJzZ3h0Y2Jjb21wMDdzdm4iOjAsInNneHRjYmNvbXAwOHN2biI6MCwic2d4dGNiY29tcDA5c3ZuIjowLCJzZ3h0Y2Jjb21wMTBzdm4iOjAsInNneHRjYmNvbXAxMXN2biI6MCwic2d4dGNiY29tcDEyc3ZuIjowLCJzZ3h0Y2Jjb21wMTNzdm4iOjAsInNneHRjYmNvbXAxNHN2biI6MCwic2d4dGNiY29tcDE1c3ZuIjowLCJzZ3h0Y2Jjb21wMTZzdm4iOjAsInBjZXN2biI6OX0sInRjYkRhdGUiOiIyMDE5LTExLTEzVDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6Ik91dE9mRGF0ZUNvbmZpZ3VyYXRpb25OZWVkZWQifSx7InRjYiI6eyJzZ3h0Y2Jjb21wMDFzdm4iOjIsInNneHRjYmNvbXAwMnN2biI6Miwic2d4dGNiY29tcDAzc3ZuIjoyLCJzZ3h0Y2Jjb21wMDRzdm4iOjQsInNneHRjYmNvbXAwNXN2biI6MSwic2d4dGNiY29tcDA2c3ZuIjoxMjgsInNneHRjYmNvbXAwN3N2biI6MCwic2d4dGNiY29tcDA4c3ZuIjowLCJzZ3h0Y2Jjb21wMDlzdm4iOjAsInNneHRjYmNvbXAxMHN2biI6MCwic2d4dGNiY29tcDExc3ZuIjowLCJzZ3h0Y2Jjb21wMTJzdm4iOjAsInNneHRjYmNvbXAxM3N2biI6MCwic2d4dGNiY29tcDE0c3ZuIjowLCJzZ3h0Y2Jjb21wMTVzdm4iOjAsInNneHRjYmNvbXAxNnN2biI6MCwicGNlc3ZuIjo3fSwidGNiRGF0ZSI6IjIwMTktMDUtMTVUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlIn0seyJ0Y2IiOnsic2d4dGNiY29tcDAxc3ZuIjoxLCJzZ3h0Y2Jjb21wMDJzdm4iOjEsInNneHRjYmNvbXAwM3N2biI6Miwic2d4dGNiY29tcDA0c3ZuIjo0LCJzZ3h0Y2Jjb21wMDVzdm4iOjEsInNneHRjYmNvbXAwNnN2biI6MTI4LCJzZ3h0Y2Jjb21wMDdzdm4iOjAsInNneHRjYmNvbXAwOHN2biI6MCwic2d4dGNiY29tcDA5c3ZuIjowLCJzZ3h0Y2Jjb21wMTBzdm4iOjAsInNneHRjYmNvbXAxMXN2biI6MCwic2d4dGNiY29tcDEyc3ZuIjowLCJzZ3h0Y2Jjb21wMTNzdm4iOjAsInNneHRjYmNvbXAxNHN2biI6MCwic2d4dGNiY29tcDE1c3ZuIjowLCJzZ3h0Y2Jjb21wMTZzdm4iOjAsInBjZXN2biI6N30sInRjYkRhdGUiOiIyMDE5LTAxLTA5VDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6Ik91dE9mRGF0ZSJ9LHsidGNiIjp7InNneHRjYmNvbXAwMXN2biI6MSwic2d4dGNiY29tcDAyc3ZuIjoxLCJzZ3h0Y2Jjb21wMDNzdm4iOjIsInNneHRjYmNvbXAwNHN2biI6NCwic2d4dGNiY29tcDA1c3ZuIjoxLCJzZ3h0Y2Jjb21wMDZzdm4iOjEyOCwic2d4dGNiY29tcDA3c3ZuIjowLCJzZ3h0Y2Jjb21wMDhzdm4iOjAsInNneHRjYmNvbXAwOXN2biI6MCwic2d4dGNiY29tcDEwc3ZuIjowLCJzZ3h0Y2Jjb21wMTFzdm4iOjAsInNneHRjYmNvbXAxMnN2biI6MCwic2d4dGNiY29tcDEzc3ZuIjowLCJzZ3h0Y2Jjb21wMTRzdm4iOjAsInNneHRjYmNvbXAxNXN2biI6MCwic2d4dGNiY29tcDE2c3ZuIjowLCJwY2Vzdm4iOjZ9LCJ0Y2JEYXRlIjoiMjAxOC0wOC0xNVQwMDowMDowMFoiLCJ0Y2JTdGF0dXMiOiJPdXRPZkRhdGUifV19LCJzaWduYXR1cmUiOiIyMTg1MjcxNWQxODc2ZDIwNzQ5N2YzMTEzZmNmZmE0YzhjNjUyYjZkY2Y4OTBmY2E4ZWVhMTdkNWFlMDBkMjVmYWIwMTdiMDUzYmRkMDRlYTE5Yzc4ZmE3MmU5OWJhZDVlMTU3MDc2MzlhOWJhZWMyNDViMTlhZmJhNDNjMDMxZiJ9AC0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDaXpDQ0FqS2dBd0lCQWdJVWZqaUMxZnRWS1VwQVNZNUZoQVBwRkpHOTlGVXdDZ1lJS29aSXpqMEVBd0l3CmFERWFNQmdHQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnYKY25CdmNtRjBhVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSgpCZ05WQkFZVEFsVlRNQjRYRFRFNE1EVXlNVEV3TlRBeE1Gb1hEVEkxTURVeU1URXdOVEF4TUZvd2JERWVNQndHCkExVUVBd3dWU1c1MFpXd2dVMGRZSUZSRFFpQlRhV2R1YVc1bk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRGIzSncKYjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3Q1FZRApWUVFHRXdKVlV6QlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJFTkZHOHh6eWRXUmZLOTJibUd2ClArbUFoOTFQRXlWN0poNkZHSmQ1bmRFOWFCSDdSM0U0QTd1YnJsaC96TjNDNHh2cG9vdUdsaXJNYmErVzJsanUKeXBhamdiVXdnYkl3SHdZRFZSMGpCQmd3Rm9BVUltVU0xbHFkTkluemc3U1ZVcjlRR3prbkJxd3dVZ1lEVlIwZgpCRXN3U1RCSG9FV2dRNFpCYUhSMGNITTZMeTlqWlhKMGFXWnBZMkYwWlhNdWRISjFjM1JsWkhObGNuWnBZMlZ6CkxtbHVkR1ZzTG1OdmJTOUpiblJsYkZOSFdGSnZiM1JEUVM1a1pYSXdIUVlEVlIwT0JCWUVGSDQ0Z3RYN1ZTbEsKUUVtT1JZUUQ2UlNSdmZSVk1BNEdBMVVkRHdFQi93UUVBd0lHd0RBTUJnTlZIUk1CQWY4RUFqQUFNQW9HQ0NxRwpTTTQ5QkFNQ0EwY0FNRVFDSUI5Qzh3T0FOL0lteER0R0FDVjI0NktjcWphZ1pPUjBreWN0eUJyc0dHSlZBaUFqCmZ0YnJOR3NHVThZSDIxMWRSaVlOb1BQdTE5WnAvemU4Sm1odWpCMG9Cdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAC0tLS0tQkVHSU4gWDUwOSBDUkwtLS0tLQpNSUlCS2pDQjBRSUJBVEFLQmdncWhrak9QUVFEQWpCeE1TTXdJUVlEVlFRRERCcEpiblJsYkNCVFIxZ2dVRU5MCklGQnliMk5sYzNOdmNpQkRRVEVhTUJnR0ExVUVDZ3dSU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlYKQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTVhEVEl5TURneApOREExTWpBeU5Wb1hEVEl5TURreE16QTFNakF5TlZxZ0x6QXRNQW9HQTFVZEZBUURBZ0VCTUI4R0ExVWRJd1FZCk1CYUFGTkRvcXRwMTEva3VTUmVZUEhzVVpkRFY4bGxOTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUFrUHVGR1cKQ2NSYmZyTm5jczlsQ1h3VUdCTE1mcHJxK1dXQkIrK1BkRWtUQWlFQWh3clNkSEI2bHFQN3hwQjRMb3duUG0xZApSczFXc2RLejNzQW91TEZJR1BBPQotLS0tLUVORCBYNTA5IENSTC0tLS0tCgAtLS0tLUJFR0lOIFg1MDkgQ1JMLS0tLS0KTUlJQklUQ0J5QUlCQVRBS0JnZ3Foa2pPUFFRREFqQm9NUm93R0FZRFZRUUREQkZKYm5SbGJDQlRSMWdnVW05dgpkQ0JEUVRFYU1CZ0dBMVVFQ2d3UlNXNTBaV3dnUTI5eWNHOXlZWFJwYjI0eEZEQVNCZ05WQkFjTUMxTmhiblJoCklFTnNZWEpoTVFzd0NRWURWUVFJREFKRFFURUxNQWtHQTFVRUJoTUNWVk1YRFRJeU1EUXhPVEE0TXpFeE9Gb1gKRFRJek1EUXhPVEE0TXpFeE9GcWdMekF0TUFvR0ExVWRGQVFEQWdFQk1COEdBMVVkSXdRWU1CYUFGQ0psRE5aYQpuVFNKODRPMGxWSy9VQnM1Sndhc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQzNnRnJQV1NFVFdFeEZ5TERoCkd5dUtuYlJpb2hXNytOVDlRV1U1MS9XcmRRSWdmL1ZwaE1VWm5QS3lQWmZUZXhCT3dPdTFKRFowOUJOR2lIcHIKMzcvZjYwST0KLS0tLS1FTkQgWDUwOSBDUkwtLS0tLQoALS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNtRENDQWo2Z0F3SUJBZ0lWQU5Eb3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFV3TVRCYUZ3MHpNekExTWpFeE1EVXdNVEJhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lGTkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMrZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pnYnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWtaWEl3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhsbE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VBTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFDSmdUYnRWcU95WjFtM2pxaUFYTTZRWWE2cjVzV1MKNHkvRzd5OHVJSkd4ZHdJZ1JxUHZCU0t6elFhZ0JMUXE1czVBNzBwZG9pYVJKOHovMHVEejROZ1Y5MWs9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAHsiZW5jbGF2ZUlkZW50aXR5Ijp7ImlkIjoiUUUiLCJ2ZXJzaW9uIjoyLCJpc3N1ZURhdGUiOiIyMDIxLTA3LTAxVDIzOjQ1OjAwWiIsIm5leHRVcGRhdGUiOiIyMDIxLTA3LTMxVDIzOjQ1OjAwWiIsInRjYkV2YWx1YXRpb25EYXRhTnVtYmVyIjoxMCwibWlzY3NlbGVjdCI6IjAwMDAwMDAwIiwibWlzY3NlbGVjdE1hc2siOiJGRkZGRkZGRiIsImF0dHJpYnV0ZXMiOiIxMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImF0dHJpYnV0ZXNNYXNrIjoiRkJGRkZGRkZGRkZGRkZGRjAwMDAwMDAwMDAwMDAwMDAiLCJtcnNpZ25lciI6IjhDNEY1Nzc1RDc5NjUwM0U5NjEzN0Y3N0M2OEE4MjlBMDA1NkFDOERFRDcwMTQwQjA4MUIwOTQ0OTBDNTdCRkYiLCJpc3Zwcm9kaWQiOjEsInRjYkxldmVscyI6W3sidGNiIjp7ImlzdnN2biI6NX0sInRjYkRhdGUiOiIyMDIwLTExLTExVDAwOjAwOjAwWiIsInRjYlN0YXR1cyI6IlVwVG9EYXRlIn0seyJ0Y2IiOnsiaXN2c3ZuIjo0fSwidGNiRGF0ZSI6IjIwMTktMTEtMTNUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlIn0seyJ0Y2IiOnsiaXN2c3ZuIjoyfSwidGNiRGF0ZSI6IjIwMTktMDUtMTVUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlIn0seyJ0Y2IiOnsiaXN2c3ZuIjoxfSwidGNiRGF0ZSI6IjIwMTgtMDgtMTVUMDA6MDA6MDBaIiwidGNiU3RhdHVzIjoiT3V0T2ZEYXRlIn1dfSwic2lnbmF0dXJlIjoiYzYxNDIyMzdlOWYzNjk0ZDhiYWQ0NDFiOWRjZTY0YzZhNWI2ZWI4ZTE2MDY0N2JhOGVkMDU0M2FkY2E3NzMyYzBkYjA4OGI4YjgzMDdlOTM1MGVlMTUxMWEzNjZhNzllMzJhM2RiM2QxYTFjOTBjYmJkY2NiMzg2ZjAxMDQyMTEifQAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ2l6Q0NBaktnQXdJQkFnSVVmamlDMWZ0VktVcEFTWTVGaEFQcEZKRzk5RlV3Q2dZSUtvWkl6ajBFQXdJdwphREVhTUJnR0ExVUVBd3dSU1c1MFpXd2dVMGRZSUZKdmIzUWdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnNJRU52CmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeEN6QUoKQmdOVkJBWVRBbFZUTUI0WERURTRNRFV5TVRFd05UQXhNRm9YRFRJMU1EVXlNVEV3TlRBeE1Gb3diREVlTUJ3RwpBMVVFQXd3VlNXNTBaV3dnVTBkWUlGUkRRaUJUYVdkdWFXNW5NUm93R0FZRFZRUUtEQkZKYm5SbGJDQkRiM0p3CmIzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVFzd0NRWUQKVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU5GRzh4enlkV1JmSzkyYm1HdgpQK21BaDkxUEV5VjdKaDZGR0pkNW5kRTlhQkg3UjNFNEE3dWJybGgvek4zQzR4dnBvb3VHbGlyTWJhK1cybGp1CnlwYWpnYlV3Z2JJd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3VWdZRFZSMGYKQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmxjblpwWTJWegpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWtaWEl3SFFZRFZSME9CQllFRkg0NGd0WDdWU2xLClFFbU9SWVFENlJTUnZmUlZNQTRHQTFVZER3RUIvd1FFQXdJR3dEQU1CZ05WSFJNQkFmOEVBakFBTUFvR0NDcUcKU000OUJBTUNBMGNBTUVRQ0lCOUM4d09BTi9JbXhEdEdBQ1YyNDZLY3FqYWdaT1Iwa3ljdHlCcnNHR0pWQWlBagpmdGJyTkdzR1U4WUgyMTFkUmlZTm9QUHUxOVpwL3plOEptaHVqQjBvQnc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDanpDQ0FqU2dBd0lCQWdJVUltVU0xbHFkTkluemc3U1ZVcjlRR3prbkJxd3dDZ1lJS29aSXpqMEVBd0l3CmFERWFNQmdHQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnYKY25CdmNtRjBhVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSgpCZ05WQkFZVEFsVlRNQjRYRFRFNE1EVXlNVEV3TkRVeE1Gb1hEVFE1TVRJek1USXpOVGsxT1Zvd2FERWFNQmdHCkExVUVBd3dSU1c1MFpXd2dVMGRZSUZKdmIzUWdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnNJRU52Y25CdmNtRjAKYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeEN6QUpCZ05WQkFZVApBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQzZuRXdNRElZWk9qL2lQV3NDemFFS2k3CjFPaU9TTFJGaFdHamJuQlZKZlZua1k0dTNJamtEWVlMME14TzRtcXN5WWpsQmFsVFZZeEZQMnNKQks1emxLT0IKdXpDQnVEQWZCZ05WSFNNRUdEQVdnQlFpWlF6V1dwMDBpZk9EdEpWU3YxQWJPU2NHckRCU0JnTlZIUjhFU3pCSgpNRWVnUmFCRGhrRm9kSFJ3Y3pvdkwyTmxjblJwWm1sallYUmxjeTUwY25WemRHVmtjMlZ5ZG1salpYTXVhVzUwClpXd3VZMjl0TDBsdWRHVnNVMGRZVW05dmRFTkJMbVJsY2pBZEJnTlZIUTRFRmdRVUltVU0xbHFkTkluemc3U1YKVXI5UUd6a25CcXd3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUV3Q2dZSQpLb1pJemowRUF3SURTUUF3UmdJaEFPVy81UWtSK1M5Q2lTRGNOb293THVQUkxzV0dmL1lpN0dTWDk0Qmd3VHdnCkFpRUE0SjBsckhvTXMrWG81by9zWDZPOVFXeEhSQXZaVUdPZFJRN2N2cVJYYXFJPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCgAyMDIyLTA4LTE0VDE3OjA3OjE0WgA="
    }"""

    csr = gen_csr(name, service_key)

    # For TLSA record - this is redundant with CSR, server should compute this
    #public_pem = service_key.public_key().public_bytes(
    #    encoding=serialization.Encoding.PEM,
    #    format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #)

    r = client.post(
        "/app/register-service",
        {
            "csr": base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode(),
            # Don't understand why this is in RegistrationRequest
            # This is delegation only for delegated SOA...
            "contact": ["antdl@microsoft.com"],
            "node_information": {
                # Possible to register multiple instances in one call
                "default": {
                    "address": {
                        "name": name,
                        "ip": address,
                        "protocol": protocol,
                        "port": port
                    },
                    "attestation": demo_attestation
                }
            }
        },
    )
    assert r.status_code == http.HTTPStatus.NO_CONTENT
    return r


def check_record(host, port, ca, name, stype, expected_data=None):
    """Checks for existence of a specific DNS record"""
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
        print(f"Check record: query=\n{q}\nresponse =\n{r.answer}")
        for a in r.answer:
            assert a.name == qname
            saw_expected = False
            for item in a.items:
                assert item.rdclass == rdc.IN
                assert item.rdtype in [
                    qtype,
                    rdt.RRSIG,
                    rdt.NSEC,
                    rdt.NSEC3,
                ]
                if expected_data:
                    if (
                        item.rdtype != qtype
                        or item.to_wire() == expected_data.to_wire()
                    ):
                        saw_expected = True
            assert not expected_data or saw_expected


def validate_rrsigs(response: dns.message.Message, qtype, keys):
    """Validate RRSIG records"""
    name = response.question[0].name
    rrs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, qtype)
    rrsigs = response.find_rrset(dns.message.ANSWER, name, rdc.IN, rdt.RRSIG, qtype)
    if keys is not None:
        dns.dnssec.validate(rrs, rrsigs, keys)


def get_records(host, port, ca, qname, stype, keys=None):
    """Get a set of DNS records"""
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


def get_keys(host, port, ca, origin):
    """Get DNSKEY records"""
    r = get_records(host, port, ca, origin, "DNSKEY", None)
    key_rrs = r.find_rrset(r.answer, origin, rdc.IN, rdt.DNSKEY)
    keys = {origin: key_rrs}
    validate_rrsigs(r, rdt.DNSKEY, keys)
    return keys


def A(s):
    """Parse an A record"""
    return dns.rdata.from_text(rdc.IN, rdt.A, s)


def test_basic(network, args):
    """Basic tests"""
    primary, _ = network.find_primary()

    with primary.client(identity="member0") as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("example.com.")

        rd = A("1.2.3.4")
        add_record(client, origin, "www", "A", rd)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = A("1.2.3.5")
        add_record(client, origin, "www", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd2)
        check_record(host, port, ca, "www.example.com.", "A", rd)

        rd2 = A("1.2.3.5")
        add_record(client, origin, "www2", "A", rd2)

        keys = get_keys(host, port, ca, origin)

        name = dns.name.from_text("www2.example.com.")
        get_records(host, port, ca, name, "A", keys)

        name = dns.name.from_text("www.example.com.")
        get_records(host, port, ca, name, "A", keys)

        # We're not authoritative for com., so we don't expect a DS record
        name = dns.name.from_text("example.com.")
        ds_rrs = get_records(host, port, ca, name, "DS", None)
        assert len(ds_rrs.answer) == 0

def test_eat(network, args):
    """Basic tests"""
    primary, _ = network.find_primary()

    with primary.client(identity="member0") as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        print("Create two issuer keys")
        client.post("/eat-create-signing-key",{ "alg": "Secp384R1" })
        client.post("/eat-create-signing-key",{ "alg": "Secp384R1" })

        print("OpenID Discovery")
        client.get("/common/v2.0/.well-known/openid-configuration",{})

        print("Key Discovery")
        jwks = client.get("/common/discovery/v2.0/keys",{}).body.json()
        print(f"JWKS: {jwks}")

        print("Token Issuance")
        service_name = "test.adns.ccf.dev."
        token = client.get("/common/oauth2/v2.0/token?service_name=" + service_name,{}).body.text()
        print(f"Token: {token} {type(token)}")

        """
        TODO: validate token 
        https://jwt.io/ displays the expected header and payload, but the signature seems invalid
        """

def test_service_reg(network, args):
    """Service registration tests"""
    primary, _ = network.find_primary()

    with primary.client(identity="member0") as client:
        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("adns.ccf.dev.")
        print("Getting DNSSEC key")
        keys = get_keys(host, port, ca, origin)

        service_name = "test.adns.ccf.dev."
        service_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        print(f"Registering test service at {service_name}")
        submit_service_registration(
            client, origin, service_name, "127.0.0.1", port, "tcp", service_key
        )

        print("Checking record is installed")
        check_record(host, port, ca, service_name, "A", A("127.0.0.1"))
        r = get_records(host, port, ca, service_name, "A", keys)
        print(r)


def run(args):
    """Run tests"""
    adns_nw = adns_endorsed_certs = None
    procs = []

    try:
        pebble_args = pebble.Arguments(
            # dns_address="10.1.0.4:53",
            binary_filename="/home/fournet/go/bin/pebble",
            wait_forever=False,
            http_port=8080,
            ca_cert_filename="pebble-tls-cert.pem",
            config_filename="pebble.config.json",
            listen_address="0.0.0.0:1024",
            mgmt_address="0.0.0.0:1025",
        )

        pebble_proc, _, _ = pebble.run_pebble(pebble_args)
        procs += [pebble_proc]
        while not os.path.exists(pebble_args.ca_cert_filename):
            time.sleep(0.2)
        #ca_certs = pebble.ca_certs(pebble_args.mgmt_address)
        #ca_certs += pebble.ca_certs_from_file(pebble_args.ca_cert_filename)
        ca_certs = pebble.ca_certs_from_file("pebble-root.pem")
        args.adns.service_ca.ca_certificates += ca_certs
        args.ca_certs += ca_certs

        adns_nw, adns_process, adns_endorsed_certs, reginfo = adns_service.run(
            args,
            wait_for_endorsed_cert=False,
            with_proxies=False,
            tcp_port=53,
            udp_port=53,
        )

        print("Service started")
        time.sleep(3)

        if not adns_nw:
            raise Exception("Failed to start aDNS network")

        #test_basic(adns_nw, args)
        #set_registration_policy(adns_nw, args)
        test_service_reg(adns_nw, args)
        test_eat(adns_nw, args)
        #print("Waiting forever...")
        time.sleep(5)
        #while True:
        #    pass
    finally:
        for p in procs:
            if p:
                p.kill()


def main():
    """Entry point"""

    def cliparser(parser):
        """Add parser"""
        parser.description = "DNS tests"

    targs = infra.e2e_args.cli_args(cliparser)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

    targs.nodes = infra.e2e_args.min_nodes(targs, f=0)
    targs.node_addresses = [
        (
            "local://127.0.0.1:1443",  # primary/internal
            "local://127.0.0.1:8443",  # external/endorsed
            "ns1.adns.ccf.dev",  # public name
            my_ip, # public IP
        )
    ]
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns.enclave.so.signed"
    targs.acme_config_name = "custom"

    targs.wait_forever = False
    targs.http2 = False
    targs.initial_node_cert_validity_days = 365
    targs.initial_service_cert_validity_days = 365
    targs.message_timeout_ms = 5000
    targs.election_timeout_ms = 60000

    # Let's encrypt - not currently working
    service_ca_config = ServiceCAConfig(
        name="letsencrypt.org",
        directory="https://acme-staging-v02.api.letsencrypt.org/directory",
        ca_certificates=[
            "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\nWhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\nZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\nMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\nh77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\nA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\nT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\nB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\nB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\nKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\nOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\njh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\nqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\nrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\nhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\nubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\nNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\nORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\nTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\njNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\noyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\nmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\nemyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD\nExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq\nu785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA\nivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\nAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA\nKGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm\nMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl\nbmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy\nLm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI\nzj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY\nN5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm\n3HMFKzIR8eEPsMx4smMl\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\nFQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\nVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\nKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\nuc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\nvbtH7QiVzeKCOTQPINyRql6P\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQzOFowZjELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTCC\nAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhsc\nZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPWnL++fgehT0FbRHZg\njOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4\nwSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmD\noaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPt\nTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstO\nfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6\nrkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQ\nFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8\nmS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/\nGI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26bW5LKeru\nmJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCsYyXDFDANBgkqhkiG\n9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8Y\nnLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrNKHkn5kn+9E9LCjCaEsyIIn2j\nqdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1x\nqAeaAhQ2rgo1F58hcflgqKTXnpPM02intVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/\nsTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5Q\nCJL6TERVDbM/aAPly8kJ1sWGLuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/\n5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmR\nxUuXY4xRdh45tMJnLTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/\nfxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWof\ngN9WUwCbEMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M\n7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc=\n-----END CERTIFICATE-----\n",
        ],
    )

    service_ca_config = ServiceCAConfig(
        name="pebble-dns",
        directory="https://127.0.0.1:1024/dir",
        ca_certificates=[]
    )

    targs.ca_certs = []

    targs.adns = aDNSConfig(
        origin="adns.ccf.dev.",
        service_name="adns.ccf.dev.",
        node_addresses={},
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.adns.ccf.dev.",
                rname="some-dev.adns.ccf.dev.",
                serial=8,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=3600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=0,
        nsec3_salt_length=8,
        parent_base_url=None,
        contact=["antdl@microsoft.com"],
        service_ca=service_ca_config,
    )

    run(targs)

if __name__ == "__main__":
    main()
