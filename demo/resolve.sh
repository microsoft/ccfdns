#!/bin/bash
set -x

LD_PRELOAD="$(pwd)/openssl/libssl.so.3 $(pwd)/openssl/libcrypto.so.3" \
curl https://test.e2e.acidns10.attested.name
