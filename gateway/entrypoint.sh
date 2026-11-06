#!/bin/sh
set -eu

mkdir -p /etc/gateway/tls /run
if [ ! -f /etc/gateway/tls/key.pem ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=q-shield-gateway" \
        -keyout /etc/gateway/tls/key.pem -out /etc/gateway/tls/cert.pem 2>/dev/null
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
