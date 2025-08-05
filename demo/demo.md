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

In separate terminals, run

```
./adns.sh
./service.sh
./resolve.sh
```
