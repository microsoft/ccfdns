# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import base64
import socket
import requests
import json
import infra.e2e_args
import adns_service
import dns
import dns.message
import dns.query
import dns.dnssec
import dns.rdtypes.ANY.SOA as SOA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import sha256
from adns_service import aDNSConfig

rdc = dns.rdataclass
rdt = dns.rdatatype

ENDORSEMENTS = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZRekNDQXZlZ0F3SUJBZ0lCQURCQkJn"
    "a3Foa2lHOXcwQkFRb3dOS0FQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZj"
    "TkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVEF3ZXpFVU1CSUdBMVVFQ3d3TApSVzVu"
    "YVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJH"
    "RnlZVEVMCk1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmtJRTFwWTNK"
    "dklFUmxkbWxqWlhNeEVqQVEKQmdOVkJBTU1DVk5GVmkxTmFXeGhiakFlRncweU5UQXhNak14"
    "T1RFME5URmFGdzB6TWpBeE1qTXhPVEUwTlRGYQpNSG94RkRBU0JnTlZCQXNNQzBWdVoybHVa"
    "V1Z5YVc1bk1Rc3dDUVlEVlFRR0V3SlZVekVVTUJJR0ExVUVCd3dMClUyRnVkR0VnUTJ4aGNt"
    "RXhDekFKQmdOVkJBZ01Ba05CTVI4d0hRWURWUVFLREJaQlpIWmhibU5sWkNCTmFXTnkKYnlC"
    "RVpYWnBZMlZ6TVJFd0R3WURWUVFEREFoVFJWWXRWa05GU3pCMk1CQUdCeXFHU000OUFnRUdC"
    "U3VCQkFBaQpBMklBQko5TzdiaVM4QzQ1VEEvaWhwVlZBTklQMTlGc0t1UEZyTWtEajI0WlJI"
    "MW9RVHZlZlJ4c1JabDk2UFdrCndZNjRvalAwd0hyRWJhNmt0dndBWWU4YkQyOVNFR1JFWWxG"
    "S3BzNHJSWXV4ZEkrcG5pYVhWNVVJNFlZUXlJb1MKMkNwY1NxT0NBUmN3Z2dFVE1CQUdDU3NH"
    "QVFRQm5IZ0JBUVFEQWdFQU1CY0dDU3NHQVFRQm5IZ0JBZ1FLRmdoTgphV3hoYmkxQ01EQVJC"
    "Z29yQmdFRUFaeDRBUU1CQkFNQ0FRUXdFUVlLS3dZQkJBR2NlQUVEQWdRREFnRUFNQkVHCkNp"
    "c0dBUVFCbkhnQkF3UUVBd0lCQURBUkJnb3JCZ0VFQVp4NEFRTUZCQU1DQVFBd0VRWUtLd1lC"
    "QkFHY2VBRUQKQmdRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdjRUF3SUJBREFSQmdvckJnRUVB"
    "Wng0QVFNREJBTUNBUmd3RWdZSwpLd1lCQkFHY2VBRURDQVFFQWdJQTJ6Qk5CZ2tyQmdFRUFa"
    "eDRBUVFFUUkyRW1EcjczS0VMU2lrNlhPSGJCcVhrCmpTckJmazJ4TWRQczBXUXZqWHZrbXNS"
    "MnZzWE1wemdpTE1lVmdOaTVXS2I1ZW1NeXA2eENndmZFRi92VFQ4NHcKUVFZSktvWklodmNO"
    "QVFFS01EU2dEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTgpC"
    "Z2xnaGtnQlpRTUVBZ0lGQUtJREFnRXdBNElDQVFCcW5xTXhiS0tleW5BdmxHTktwYnYvZUdO"
    "eFlxcWJ0QUpVCk4rT3d3WUZhakYwejIwNXA5eGRmMkJrWFc2UTFhcVg0ekR4czFCbTNqU1hZ"
    "VlVWQ1pKcU5la3ZISDRXK2UyTFoKcUhTMmJiQ0pwRy9EVnBBTEUyWm1MNXdnQW1IdWE5azZ6"
    "TldHY0htS1F2QjJwVC8raVVqOEpLV0wweTN2SEtMZgpHdWRZZnBsSGpwbDRlTm5ueStoM0Fo"
    "SWMyNXhGNjNqdmE2TW1YMUQ4L1RDT25uZTUzZVFTZEZOMXNxS3hmOU5lClZrK0JBYUVDVlV3"
    "alNEOEpwUW0ySzJXSkhQR2hSK2orV1IraXNiZ01WNHRsZGpKb3NnVnNPSGh5bmFxbTk2R24K"
    "ZTdqMjllMWVSSk0wSmdjSEdUZHQxaTFuYlVscFlpRHpINzVwRjF2R283eFZrZ0FYSk1xLytI"
    "R041WHNSSkh5YgpOeC85bURyNmpxR000SW45SU80bmRyemJJd0VqVlB4T29MMkUzM1dxa2VD"
    "citqdUVTUzg1RS9CZlRyQVNjQVR5ClRYWkdnS3ZwRkdpajB6Q0hwTDNiL2V4SnowOTRVUDFI"
    "Qm9XeG94eEdJdVZueTZxV3BKSzBCa3BkeDB2enhZVVQKa2doRTFacjY1enFMRDJSRXhZQzlW"
    "SVVVZUJQaXdBM3FsaGJpUnY3OTdQOC92UktHREFWeXBaOE9VVkkveGIrVAovWGx5NWZLSFpv"
    "dHNkNC9INlFzSGE0K0VSdDlpU2VkYjlSUFp3T1h4UU1YTldBK0RIdzBlc1psekpxZmFENmUy"
    "CjFndFpXbnVwZkdYVDkvTDUrcTl0L0l1MkRFNUZydFYvaWcvbmpFZndqcXNoUTNHbVFNOVJU"
    "aXZzN1RSUHBEdysKemtWam1yNTNPdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0t"
    "LS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdpVENDQkRpZ0F3SUJBZ0lEQVFBQk1FWUdD"
    "U3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtpRzl3"
    "MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05WQkFz"
    "TUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUyRnVk"
    "R0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1ObFpD"
    "Qk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNOTWpB"
    "eE1ESXlNVGd5TkRJd1doY05ORFV4TURJeQpNVGd5TkRJd1dqQjdNUlF3RWdZRFZRUUxEQXRG"
    "Ym1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJuUmhJ"
    "RU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldRZ1RX"
    "bGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKVTBWV0xVMXBiR0Z1TUlJQ0lqQU5CZ2tx"
    "aGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBblUyZHJyTlRmYmhOUUlsbGYrVzJ5"
    "K1JPQ2JTeklkMWFLWmZ0CjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05UY0IwVllYdDNKeFpT"
    "ek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXcKS1pYMEptUUV1WWptK1dLa3NMdHhnZExwOUU3"
    "RVpOd05EcVYxcjBxUlA1dEI4T1dreVFiSWRMZXU0YUN6N2ovUwpsMUZrQnl0ZXY5c2JGR3p0"
    "N2N3bmp6aTltN25vcXNrK3VSVkJwMytJbjM1UVBkY2o4WWZsRW1uSEJOdnVVREpoCkxDSk1X"
    "OEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pUTThLc05iVXgzQThl"
    "azVFVkwKalpXSDFwdDlFM1RmcFI2WHlmUUtuWTZrbDVhRUlQd2RXM2VGWWFxQ0ZQcklvOXBR"
    "VDZXdURTUDRKQ1lKYlpuZQpLS0liWmp6WGtKdDNOUUczMkV1a1lJbUJiOVNDa205K2ZTNUxa"
    "Rmc5b2p6dWJNWDMrTmtCb1NYSTdPUHZuSE14Cmp1cDltdzVzZTZRVVY3R3FwQ0EyVE55cG9s"
    "bXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGwKQWxKdzVEMENUUlRDMVk1"
    "WVdGREJDckEvdkdubVRucUc4QytqalVBUzdjampSOHE0T1BoeURtSlJQbmFDL1pHNQp1UDBL"
    "MHo2R29PLzN1ZW45d3FzaEN1SGVnTFRwT2VIRUpSS3JRRnI0UFZJd1ZPQjArZWJPNUZnb3lP"
    "dzQzbnlGCkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FSSXMxRW9xRWptRjhV"
    "dHJtUVdWMmhVand6cXd2SEYKZWk4clB4TUNBd0VBQWFPQm96Q0JvREFkQmdOVkhRNEVGZ1FV"
    "TzhadUdDckQvVDFpWkVpYjQ3ZEhMTFQ4di9ndwpId1lEVlIwakJCZ3dGb0FVaGF3YTBVUDN5"
    "S3hWMU1VZFFVaXIxWGhLMUZNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93SUJBREFPQmdOVkhR"
    "OEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIwY0hNNkx5OXIKWkhO"
    "cGJuUm1MbUZ0WkM1amIyMHZkbU5sYXk5Mk1TOU5hV3hoYmk5amNtd3dSZ1lKS29aSWh2Y05B"
    "UUVLTURtZwpEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJYjNEUUVCQ0RBTkJn"
    "bGdoa2dCWlFNRUFnSUZBS0lECkFnRXdvd01DQVFFRGdnSUJBSWdlVVFTY0FmM2xEWXFnV1Ux"
    "VnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEUKUEkxamgzZ0piTHhMNmdmM0s4anhjdHpP"
    "V25rWWNiZGZNT09yMjhLVDM1SWFBUjIwcmVrS1JGcHRUSGhlK0RGcgozQUZ6WkxERDdjV0sy"
    "OS9HcFBpdFBKREtDdkk3QTRVZzA2cms3SjB6QmUxZnovcWU0aTIvRjEycnZmd0NHWWhjClJ4"
    "UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpNa3Q3REZ2S1JoKzJ6"
    "Sys1cGxWR0cKRnNqREp0TXoydWQ5eTBwdk9FNGozZEg1SVc5akd4YVNHU3RxTnJhYm5ucEYy"
    "MzZFVHIxL2E0M2I4RkZLTDVRTgptdDhWcjl4blhScHpucUNSdnFqcitrVnJiNmRsZnVUbGxp"
    "WGVRVE1sQm9SV0ZKT1JMOEFjQkp4R1o0SzJtWGZ0CmwxalU1VExlaDVLWEw5Tlc3YS9xQU9J"
    "VXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnIKRWc2emt4bXZNdWFi"
    "Wk9zZEtmUmtXZmhIMlpLY1RsRGZtSDFIMHpxMFEyYkczdXZhVmRpQ3RGWTFMbFd5QjM4SgpT"
    "MmZOc1IvUHk2dDVickVKQ0ZOdnphRGt5NktlQzRpb24vY1ZnVWFpN3p6UzNiR1FXektES1Uz"
    "NVNxTlUyV2tQCkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBlMDF6RDBOOGF0Rnht"
    "V2lTbmZKbDY5MEI5ckpwTlIvZkkKYWp4Q1czU2Vpd3M2cjFabSt0Q3VWYk1pTnRwUzlUaGpO"
    "WDR1dmU1dGh5ZkUyRGdveFJGdlkxQ3NvRjVNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdZekNDQkJLZ0F3SUJBZ0lEQVFBQU1F"
    "WUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhEQWFCZ2txaGtp"
    "Rzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4RkRBUwpCZ05W"
    "QkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdBMVVFQnd3TFUy"
    "RnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RCWkJaSFpoYm1O"
    "bFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFdsc1lXNHdIaGNO"
    "TWpBeE1ESXlNVGN5TXpBMVdoY05ORFV4TURJeQpNVGN5TXpBMVdqQjdNUlF3RWdZRFZRUUxE"
    "QXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZCQWNNQzFOaGJu"
    "UmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdSMllXNWoKWldR"
    "Z1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKUVZKTExVMXBiR0Z1TUlJQ0lqQU5C"
    "Z2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJSSk9kZWlKbHFLMkpk"
    "c1ZtRDdGa3R1b3RXd1gxZk5nClc0MVhZOVh6MUhFaFNVbWhMejlDdTlESFJsdmdKU054YmVZ"
    "WXNuSmZ2eWp4MU1mVTBWNXRrS2lVMUVlc05GdGEKMWtUQTBzek5pc2RZYzlpc3FrN21YVDUr"
    "S2ZHUmJmYzRWLzl6UkljRThqbEhONjFTMWp1OFg5Mys2ZHhEVXJHMgpTenhxSjRCaHF5WW1V"
    "RHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0yQitPK3Zqc0MwCjYw"
    "ZDM3alk5TEZldU9QNE1lcmk4cWdmaTJTNWtLcWcvYUY2YVB0dUFaUVZSN3UzS0ZZWFA1OVht"
    "Smd0Y29nMDUKZ21JMFQvT2l0TGh1elZ2cFpjTHBoMG9kaC8xSVBYcXgzK01uakQ5N0E3Zlhw"
    "cUdkL3k4S3hYN2prc1RFekFPZwpiS0FlYW0zbG0rM3lLSWNUWU1sc1JNWFBjak5iSXZtc0J5"
    "a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzCitnVkRrdVZQaHNueklSTmdZdk00OFkr"
    "N0xHaUpZbnJtRTh4Y3JleGVrQnhydmEyVjlUSlFxbk4zUTUza3Q1dmkKUWkzK2dDZm1rd0Mw"
    "RjB0aXJJWmJMa1hQclB3elowTTllTnhoSXlTYjJucEpmZ25xejU1STB1MzN3aDRyMFpOUQpl"
    "VEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBDcTcrT2dwQ0NvTU5p"
    "dDJ1TG85TTE4CmZIejEwbE9NVDhuV0FVdlJaRnp0ZVhDbSs3UEhkWVBsbVF3VXczTHZlbkov"
    "SUxYb1FQSGZia0gwQ3lQZmhsMWoKV2hKRlphc0NBd0VBQWFOK01Id3dEZ1lEVlIwUEFRSC9C"
    "QVFEQWdFR01CMEdBMVVkRGdRV0JCU0ZyQnJSUS9mSQpyRlhVeFIxQlNLdlZlRXJVVXpBUEJn"
    "TlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VHCktXaDBkSEJ6T2k4"
    "dmEyUnphVzUwWmk1aGJXUXVZMjl0TDNaalpXc3ZkakV2VFdsc1lXNHZZM0pzTUVZR0NTcUcK"
    "U0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQkFR"
    "Z3dEUVlKWUlaSQpBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFDNm0wa0RwNnp2NE9q"
    "Zmd5K3psZWVoc3g2b2wwb2NnVmVsCkVUb2JweCtFdUNzcVZGUlBLMWpaMXNwL2x5ZDkrMGZR"
    "MHI2Nm43a2FnUms0Q2EzOWc2NldHVEpNZUpkcVlyaXcKU1RqakRDS1ZQU2VzV1hZUFZBeURo"
    "bVA1bjJ2K0JZaXBaV2hwdnFwYWlPK0VHSzVJQlArNTc4UWVXL3NTb2tySwpkSGFMQXhHMkxo"
    "WnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dTZ2tEZ3V0Q1RCMVlx"
    "CnpUNUR1d3ZBZStjbzJDSVZJek1EYW1ZdVNGalBOMEJDZ29qbDdWK2JUb3U3ZE1zcUl1L1RX"
    "L3JQQ1g5L0VVY3AKS0dLcVBRM1ArTjlyMWhqRUZZMXBsQmc5M3Q1M09PbzQ5R05JK1YxenZY"
    "UExJNnhJRlZzaCttdG8yUnRnRVgvZQpwbU1LVE5ONnBzVzg4cWc3YzFoVFd0TjZNYlJ1UTB2"
    "bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxCkhuSVloeHkwWUtYR3lhVzFOamZV"
    "THhycm14Vlc0d2NuNUU4R2RkbXZOYTZ5WW04c2NKYWdFaTEzbWhHdTRKcWgKM1FVM3NmOGlV"
    "U1VyMDl4UUR3SHRPUVVWSXF4NG1hQlpQQnRTTWYrcVVEdGpYU1NxOGxmV2NkOGJMcjltZHNV"
    "bgpKWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2VzFVbXEyNWJveENZ"
    "SitUdUJvYTRzK0hICkNWaUF2Z1Q5a2YvckJxMWQraXZqNnNra0h4dXpjeGJrMXh2NlpHeHJ0"
    "ZUp4Vkg3S2xYN1lSZFo2ZUFSS3dMZTQKQUZaRUF3b0tDUT09Ci0tLS0tRU5EIENFUlRJRklD"
    "QVRFLS0tLS0K"
)


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


def get_dummy_quote(report_data):
    measurement = base64.b64encode(
        b"Insecure hard-coded virtual measurement v1"
    ).decode()
    quote = {"measurement": measurement, "report_data": report_data}
    return base64.b64encode(json.dumps(quote).encode()).decode()


def get_snp_quote(client, report_data):
    response = client.post("/internal/attestation", {"report_data": report_data})
    print(f"report_data here is: {report_data}")
    quote = response.body.json()["quote"]
    return quote


def get_attestation(client, service_key, enclave_platform):
    public_key = service_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    report_data = base64.b64encode(sha256(public_key).digest()).decode()

    evidence = ""
    if enclave_platform == "snp":
        evidence = get_snp_quote(client, report_data)
    elif enclave_platform == "virtual":
        evidence = get_dummy_quote(report_data)
    else:
        raise ValueError(f"Unknown enclave platform: {enclave_platform}")

    dummy_attestation = {
        "evidence": evidence,
        "endorsements": ENDORSEMENTS,
        "uvm_endorsements": "",
    }
    return json.dumps(dummy_attestation)


def submit_service_registration(
    client, name, address, port, protocol, service_key, enclave_platform
):
    """Submit a service registration request"""

    csr = gen_csr(name, service_key)
    attestation = get_attestation(client, service_key, enclave_platform)
    r = client.post(
        "/app/register-service",
        {
            "csr": base64.b64encode(
                csr.public_bytes(serialization.Encoding.DER)
            ).decode(),
            "node_information": {
                # Possible to register multiple instances in one call
                "default": {
                    "address": {
                        "name": name,
                        "ip": address,
                        "protocol": protocol,
                        "port": port,
                    },
                    "attestation": attestation,
                }
            },
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
        assert r.answer
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
    try:
        key_rrs = r.find_rrset(r.answer, origin, rdc.IN, rdt.DNSKEY)
    except KeyError:
        print("No DNSKEY records found")
    keys = {origin: key_rrs}
    validate_rrsigs(r, rdt.DNSKEY, keys)
    return keys


def ARecord(s):
    """Parse an A record"""
    return dns.rdata.from_text(rdc.IN, rdt.A, s)


def test_service_reg(network, args):
    """Service registration tests"""
    primary, _ = network.find_primary()

    with primary.client(identity="member0") as client:

        host = primary.get_public_rpc_host()
        port = primary.get_public_rpc_port()
        ca = primary.session_ca()["ca"]

        origin = dns.name.from_text("acidns10.attested.name.")
        print("Getting DNSSEC key")
        keys = get_keys(host, port, ca, origin)

        service_name = "test.acidns10.attested.name"
        service_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

        submit_service_registration(
            client,
            service_name,
            "127.0.0.1",
            port,
            "tcp",
            service_key,
            args.enclave_platform,
        )

        print("Checking record is installed")
        check_record(host, port, ca, service_name, "A", ARecord("127.0.0.1"))
        r = get_records(host, port, ca, service_name, "A", keys)
        print(r)


def run(args):
    """Run tests"""

    adns_nw, _ = adns_service.run(
        args,
        tcp_port=53,
        udp_port=53,
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    test_service_reg(adns_nw, args)


def main():
    """Entry point"""

    def cliparser(parser):
        """Add parser"""
        parser.description = "DNS tests"

        parser.add_argument(
            "--service-type",
            help="Type of service",
            action="store",
            dest="service_type",
            default="CCF",
        )

    targs = infra.e2e_args.cli_args(cliparser)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

    print("Bringing up network on {}", my_ip)

    targs.nodes = infra.e2e_args.min_nodes(targs, f=0)
    targs.node_addresses = [
        (
            "local://0.0.0.0:1443",  # primary/internal
            "local://0.0.0.0:8443",  # external/endorsed
            "ns1.acidns10.attested.name",  # public name
            "20.160.110.47",  # public IP
        )
    ]
    targs.constitution = glob.glob("../tests/constitution/*")
    targs.package = "libccfdns"
    targs.acme_config_name = "custom"

    targs.http2 = False
    targs.initial_node_cert_validity_days = 365
    targs.initial_service_cert_validity_days = 365
    targs.message_timeout_ms = 5000
    targs.election_timeout_ms = 60000

    targs.adns = aDNSConfig(
        origin="acidns10.attested.name.",
        service_name="acidns10.attested.name.",
        node_addresses={},
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.acidns10.attested.name.",
                rname="some-dev.acidns10.attested.name.",
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
    )

    run(targs)


if __name__ == "__main__":
    main()
