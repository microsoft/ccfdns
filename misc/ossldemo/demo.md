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

Inside the container, install dependencies:

```bash
cd /workspace
./prepare_vm.sh
```

Clone OpenSSL repository and switch to version 3.3:

```bash
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout openssl-3.3
```

Apply the patch from the workspace:

```bash
patch -p1 < /workspace/ossl.3.3.patch
```

Configure, build and install:

```bash
./Configure --prefix=/opt/openssl --openssldir=/usr/local/ssl
make -j16
make install
```

Replace system OpenSSL with patched version:

```bash
cd /workspace
./hookup_custom.sh
```

Try and check STDERR:

```bash
curl -L https://good.dane.hugue.com 2> stderr.txt
```

To restore original OpenSSL libraries:

```bash
./restore_original.sh
```
