#!/bin/sh
set -eu

mkdir -p /etc/gateway/tls /run
# Keep a mounted certificate. Otherwise issue one from the lab CA, or self-sign as a last resort.
if [ ! -f /etc/gateway/tls/key.pem ]; then
    tls=/etc/gateway/tls
    if [ -f /ca/classic-intermediate.key ]; then
        name="${SERVICE_NAME:-gateway}"
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=${name}" \
            -keyout "$tls/key.pem" -out /tmp/gateway.csr 2>/dev/null
        printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:%s,DNS:localhost\n' "$name" >/tmp/gateway.ext
        openssl x509 -req -in /tmp/gateway.csr -CA /ca/classic-intermediate.pem -CAkey /ca/classic-intermediate.key \
            -set_serial "0x$(openssl rand -hex 8)" -days 365 -extfile /tmp/gateway.ext -out /tmp/leaf.pem 2>/dev/null
        cat /tmp/leaf.pem /ca/classic-intermediate.pem >"$tls/cert.pem"
    else
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
            -subj "/CN=q-shield-gateway" -keyout "$tls/key.pem" -out "$tls/cert.pem" 2>/dev/null
    fi
fi

# The application runs as uid 1000 and writes routes here.
chown 1000:1000 /gateway-conf

nginx -g 'daemon off;' &
nginx_pid=$!

fingerprint() {
    cat /gateway-conf/*.conf 2>/dev/null | md5sum
}

# Only reload a configuration that passes validation; a bad route keeps the old one live.
current=$(fingerprint)
while kill -0 "$nginx_pid" 2>/dev/null; do
    sleep 1
    latest=$(fingerprint)
    if [ "$latest" != "$current" ]; then
        if nginx -t 2>/tmp/nginx-test.log; then
            nginx -s reload
            echo "gateway: routes reloaded"
        else
            echo "gateway: route rejected" >&2
            cat /tmp/nginx-test.log >&2
        fi
        current=$latest
    fi
done
wait "$nginx_pid"
