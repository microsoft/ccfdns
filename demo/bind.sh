#!/bin/bash

set -x

# Backup original resolv.conf
if [ -f /etc/resolv.conf ]; then
    cp /etc/resolv.conf /etc/resolv.conf.backup
fi

# Restore function
restore_resolv() {
    if [ -f /etc/resolv.conf.backup ]; then
        cp /etc/resolv.conf.backup /etc/resolv.conf
        rm /etc/resolv.conf.backup
    fi
}

# Set trap to restore on exit
trap restore_resolv EXIT INT TERM

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
mkdir -p /usr/etc
cp named.conf /usr/etc/named.conf

# Start
named -g
