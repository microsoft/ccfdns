#!/bin/bash

set -x

# Set bind as only resolver.
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search .
EOF

# Prepare config.
cp named.conf /usr/etc/named.conf

# Start
named -g
