import base64
import requests
from OpenSSL import crypto

from sevsnpmeasure import guest
from sevsnpmeasure import vcpu_types
from sevsnpmeasure.sev_mode import SevMode

k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 4096)
pk = crypto.dump_publickey(crypto.FILETYPE_PEM, k).decode("ascii")

url = "https://adns.ccf.dev:8000/app/register"

headers = {"content-type": "application/json"}

ip = open("/etc/ip", "r", encoding="ascii").read()

ovmf_path = "/usr/share/OVMF/OVMF.fd"
kernel_path = ""
initrd_path = ""
cmdline_str = ""
vcpus_num = 1
ld = guest.calc_launch_digest(
    SevMode.SEV_SNP,
    vcpus_num,
    vcpu_types.CPU_SIGS["EPYC-v4"],
    ovmf_path,
    kernel_path,
    initrd_path,
    cmdline_str,
)
print("Calculated measurement:", ld.hex())


data = {
    "origin": "adns.ccf.dev.",
    "name": "service42.adns.ccf.dev.",
    "address": ip,
    "attestation": {
        "format": "AMD",
        "evidence": base64.b64encode(ld).decode("ascii"),
        "endorsements": base64.b64encode(bytes()).decode("ascii"),
    },
    "algorithm": "ECDSAP384SHA384",
    "public_key": pk,
}

r = requests.post(url, headers=headers, json=data, verify=False)
print(r)
print(r.text)
