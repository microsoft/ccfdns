# OpenSSL DANE Patch Demo

This guide walks you through running a complete demonstration of the OpenSSL DANE patch.

## Demo Steps

Open VScode devcontainer with aDNS, then setup all dependencies, including custom openssl build.

```bash
cd demo
./setup.sh
```

In separate terminals, run

```
./adns.sh
./bind.sh # Depends on the previous, as it adds current aDNS KSK as a trusted-anchor
./service.sh
./resolve.sh
```

Check the scripts out for details. TL;DR:

- ADNS is run
- KSK is read from ADNS and pinned in BIND
- BIND set as local resolver
- Simple python backend server registers itself in ADNS
- Resolving the service using curl is the actual result demo aims to prove
