# OpenSSL DANE Patch Demo

This guide walks you through running a complete demonstration of the OpenSSL DANE patch.

## Demo Steps

```bash
cd misc/ossldemo
docker run --privileged --user root --publish-all \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
  -ti -v "$PWD":/workspace \
  mcr.microsoft.com/azurelinux/base/core:3.0 /bin/bash
```

Inside the container, setup required deps + tools:

```bash
cd /workspace/demo
./setup.sh
```

Nit. Setup contains openssl cloning+building, may need intervention if run multiple times.

In separate terminals, run

```
./adns.sh
./bind.sh # Depends on the previous, as it adds current aDNS KSK as a trusted-anchor
./service.sh
./resolve.sh
```
