# OpenSSL DANE Patch Demo

This guide walks you through running a complete demonstration of the OpenSSL DANE patch.

## Demo Steps

Open VScode devcontainer with aDNS, then setup all dependencies, including custom openssl build. 

```bash
cd demo
./setup.sh
```

Nit. Setup contains openssl cloning+building, may need manual intervention if run multiple times.

In separate terminals, run

```
./adns.sh
./bind.sh # Depends on the previous, as it adds current aDNS KSK as a trusted-anchor
./service.sh
./resolve.sh
```
