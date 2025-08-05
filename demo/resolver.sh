#!/bin/bash
set -x

# Capture original content
ORIGINAL_RESOLV=$(cat /etc/resolv.conf)

# Set what you want
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search .
EOF

# Run your test
LD_PRELOAD="$(pwd)/openssl/libssl.so.3 $(pwd)/openssl/libcrypto.so.3" \
curl https://test.e2e.acidns10.attested.name

# Restore original content using here document
cat > /etc/resolv.conf << EOF
$ORIGINAL_RESOLV
EOF