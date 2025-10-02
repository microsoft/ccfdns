# OpenSSL DANE Patch Demo

This guide walks you through running a complete demonstration of the OpenSSL DANE patch.

## Demo Steps

Open VScode devcontainer with aDNS, then setup all dependencies, including custom openssl build.

```bash
cd demo
./setup.sh virtual/snp  # choose one
```

If same VM, run in separate terminals, otherwise run client/server/adns parts individually in order.

ADNS itself.

```
cd adns
./adns.sh
```

Service, registers itself in aDNS.

```
cd server
./service.sh 127.0.0.1:1443  # update if necessary
```

Client, want to resolve the server.

```
cd client
./discover_and_verify_adns_ksk.sh 127.0.0.1:1443  # update if necessary
./bind.sh 127.0.0.1:1443  # update if necessary
./resolve.sh
```

Check the scripts out for details. TL;DR:

- ADNS is run
- KSK is read from ADNS and pinned in BIND
- KSK TX receipt it checked, and ADNS's attestation is verified
- BIND set as local resolver
- Simple python backend server registers itself in ADNS
- Resolving the service using curl is the actual result demo aims to prove
