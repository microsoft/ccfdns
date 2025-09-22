#!/bin/bash

set -x

# Set bind as only resolver.
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search .
EOF

# Get DNSKEY and extract KSK (257)
KSK=$(dig @127.0.0.1 -p 5353 acidns10.attested.name DNSKEY +short | grep "257 3 14" | sed 's/.*14 //')

# Update trust-anchors with KSK
cat > named.conf << EOF
// Forward zone for .acidns10.attested.name domain
zone "acidns10.attested.name" {
    type forward;
    forward only;
    forwarders {
        127.0.0.1 port 5353;  // Your ADNS server
    };
};
trust-anchors {
    "acidns10.attested.name" initial-key 257 3 14 "$KSK";
};
options {
    dnssec-validation yes;
};
EOF

# Prepare config.
cp named.conf /usr/etc/named.conf

# Start
named -g
