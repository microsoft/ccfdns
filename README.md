# ccfdns

A CCF-based, attested DNS server

# Instructions

```
mkdir build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DVERBOSE_LOGGING=ON -DLVI_MITIGATIONS=OFF -DCMAKE_C_COMPILER=clang-10 -DCMAKE_CXX_COMPILER=clang++-10 ..
ninja
```

You may want/need to add `-DOE=/path/to/oe` and `-DCCF=/path/to/CCF` to the `cmake` settings if they are not in the usual location(s). `-DLVI_MITIGATIONS=OFF` can be enabled if the OE LVI mitigated toolchain is set up.

To run all tests:

```
./tests.sh
```

Sandbox:

(Depending on your version of CCF)

```
/path/to/CCF/bin/sandbox.sh -p libccfdns.virtual.so
```

# Add a dummy record

via json for now, for `www.example.com`:

```
curl -v -k https://127.0.0.1:8000/app/add -X POST -H "Content-Type: application/json" -d '{"origin": "example.com.", "record": { "name": "www", "type": 1 , "class_": 1, "ttl": 3600, "rdata": [1, 2, 3, 4] }}'
```


# Submit queries

... to sandbox at `https://127.0.0.1:8000`

## Raw HTTPS

Raw HTTPS query for `www.example.com`:

```
curl -v -k https://127.0.0.1:8000/app/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
```

##  dnslookup

```
sudo snap install dnslookup
RRTYPE=A VERIFY=0 dnslookup www.example.com https://127.0.0.1:8000/app/dns-query
```

should show something like this:

```
dnslookup v. 1.6.0-7201
TLS verification has been disabled
dnslookup result:
;; opcode: QUERY, status: NOERROR, id: 48667
;; flags: qr aa; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
www.example.com.        3600    IN      A       1.2.3.4
```


## Bind9/dig

Get the latest version of bind9 and/or utils; the current dig in the Ubuntu 20.04 package does not support DNS-over-HTTPS yet.

```
sudo add-apt-repository ppa:isc/bind
sudo apt update
sudo apt install bind9-dnsutils
```

In theory:

```
dig +https +https-get=/app/dns-query +tls-ca=workspace/sandbox_common/service_cert.pem @127.0.0.1 -p 8000 cwinter.adns.ccf.dev A
```

But it seems to require HTTP/2 which we don't have in CCF yet.

