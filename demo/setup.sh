#!/bin/bash

set -e

tdnf -y install ca-certificates  \
    perl patch \
    net-tools bind-utils

curl -L https://github.com/microsoft/CCF/releases/download/ccf-6.0.3/ccf_virtual_devel_6.0.3_x86_64.rpm -o ccf-devel.rpm  \
    && tdnf -y install ./ccf-devel.rpm

./../scripts/setup-ci.sh
./../scripts/setup-dev.sh

mkdir -p ../build
cd ../build
rm CMakeCache.txt || true
cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_BUILD_TYPE=Debug ..
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
