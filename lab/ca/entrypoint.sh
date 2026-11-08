#!/bin/sh
# Builds two root -> intermediate hierarchies for the lab: classic (ECDSA) and post-quantum (ML-DSA).
set -eu

issue_hierarchy() {
    name=$1
    shift
    label=$1
    shift
    if [ -f "/ca/${name}-intermediate.key" ]; then
        return
    fi
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >/tmp/ca.ext
    openssl req -x509 "$@" -nodes -days 3650 -subj "/O=Lab Kartika-01/CN=${label} Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "/ca/${name}-root.key" -out "/ca/${name}-root.pem" 2>/dev/null
    openssl req -new "$@" -nodes -subj "/O=Lab Kartika-01/CN=${label} Intermediate CA" \
        -keyout "/ca/${name}-intermediate.key" -out /tmp/intermediate.csr 2>/dev/null
    openssl x509 -req -in /tmp/intermediate.csr -CA "/ca/${name}-root.pem" -CAkey "/ca/${name}-root.key" \
        -set_serial "0x$(openssl rand -hex 8)" -days 1825 -extfile /tmp/ca.ext \
        -out "/ca/${name}-intermediate.pem" 2>/dev/null
}

issue_hierarchy classic "Klasik" -newkey ec -pkeyopt ec_paramgen_curve:P-256
issue_hierarchy pq "PQC" -newkey ML-DSA-65

# Issuing services run as root and read the keys; the app only gets the public roots.
cat /ca/classic-root.pem /ca/pq-root.pem >/public/ca.pem
chmod a+r /public/ca.pem
