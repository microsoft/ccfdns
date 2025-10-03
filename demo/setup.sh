#!/bin/bash

set -e

PLATFORM=$1

tdnf -y install ca-certificates  \
    perl patch \
    net-tools bind bind-utils

# Check if CCF is already installed under /opt
if [ ! -d "/opt/ccf_${PLATFORM}" ]; then
    echo "CCF not found, downloading and installing..."
    curl -L https://github.com/microsoft/CCF/releases/download/ccf-6.0.14/ccf_${PLATFORM}_devel_6.0.14_x86_64.rpm -o ccf-devel.rpm  \
        && tdnf -y install ./ccf-devel.rpm
else
    echo "CCF already installed at /opt/ccf_${PLATFORM}"
fi

./../scripts/setup-ci.sh
./../scripts/setup-dev.sh

mkdir -p ../build
cd ../build
rm CMakeCache.txt || true
cmake -GNinja -DCOMPILE_TARGET=$PLATFORM -DCMAKE_BUILD_TYPE=Debug ..
ninja
cd ../demo

git clone https://github.com/openssl/openssl.git || true
cd openssl
git checkout openssl-3.3 || true
git stash
patch -p1 < ../ossl.3.3.patch
./Configure
make -j$(nproc)
cd ..
