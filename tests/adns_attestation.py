# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import cbor2
import base64
import os
import shutil
from tools.attestation import verify_snp_attestation, pack_tcb


PLATFORM_POLICY = """
    package policy
    default allow := false

    product_name_valid if {
        input.attestation.product_name in ["Milan", "Genoa"]
    }
    reported_tcb_valid if {
        input.attestation.reported_tcb.hexstring in ["db18000000000004", "541700000000000a"]
    }
    amd_tcb_valid if {
        product_name_valid
        reported_tcb_valid
    }

    uvm_did_valid if {
        input.attestation.uvm_endorsements.did == "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2"
    }
    uvm_feed_valid if {
        input.attestation.uvm_endorsements.feed == "ContainerPlat-AMD-UVM"
    }
    uvm_svn_valid if {
        input.attestation.uvm_endorsements.svn >= "101"
    }
    uvm_valid if {
        uvm_did_valid
        uvm_feed_valid
        uvm_svn_valid
    }

    allow if {
        amd_tcb_valid
        uvm_valid
    }
"""


SERVICE_POLICY = """
    package policy
    default allow := false

    host_data_valid if {
        input.attestation.host_data == "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10"
    }

    allow if {
        host_data_valid
    }
"""


def check_policy(policy, policy_input):
    # Disabled until rego v1 compatibility is fixed. To manually enable, patch
    # local rego with
    #     def __init__(self, v1_compatible=False):
    #         """Initializer."""
    #         import ctypes
    #         self._impl = rego_new_v1(ctypes.c_char_p(0)) if v1_compatible else rego_new()

    # rego = Interpreter(v1_compatible=True)
    # rego.add_module("policy", policy)
    # rego.set_input(policy_input)
    # allow = rego.query("data.policy.allow")
    # assert allow.results[0].expressions[0]
    pass


def test_attestation(cbor_path):
    with open(cbor_path, "rb") as f:
        attestation_cbor = cbor2.load(f)

    endorsements = base64.b64decode(attestation_cbor["eds"])
    attestation = attestation_cbor["att"]

    product_name, report, did, feed, svn = verify_snp_attestation(
        attestation, endorsements, attestation_cbor["uvm"]
    )

    # CRLs are pulled into local "ca" dir, but only if it's non existent, so
    # after testing Milan it won't pull different CRLs for Genoa unless deleted.
    if os.path.exists("ca"):
        shutil.rmtree("ca")

    service_policy_input = {
        "attestation": {
            "host_data": report.host_data.hex(),
        }
    }

    platform_policy_input = {
        "attestation": {
            "product_name": product_name,
            "reported_tcb": {
                "hexstring": pack_tcb(report.reported_tcb).hex(),
            },
            "uvm_endorsements": {
                "did": did["id"],
                "feed": feed,
                "svn": svn,
            },
        }
    }

    check_policy(PLATFORM_POLICY, platform_policy_input)
    check_policy(SERVICE_POLICY, service_policy_input)


if __name__ == "__main__":
    for file in sys.argv[1].split(","):
        test_attestation(file)
