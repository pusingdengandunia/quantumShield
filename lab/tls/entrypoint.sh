#!/bin/sh
# Dummy TLS service for the lab. Keys are generated at start so none live in the repository.
set -eu

case "${MODE:-classic}" in
    classic)
        key_args="-newkey rsa:2048"
        protocols="TLSv1.2 TLSv1.3"
        curves="X25519:prime256v1"
        ciphers="HIGH:!aNULL"
        title="Portal Internal (dummy)"
        issuer="classic"
        extra_listen="listen 8443 ssl;"
        ;;
    legacy)
        # Deliberately weak. Security level 0 is needed before nginx will load an RSA-1024 key.
        key_args="-newkey rsa:1024"
        protocols="TLSv1.2"
        curves="prime256v1"
        ciphers="ALL:@SECLEVEL=0"
        title="API Logistik Lama (dummy)"
        cat >/tmp/openssl-weak.cnf <<'EOF'
openssl_conf = init
[init]
ssl_conf = ssl_section
[ssl_section]
system_default = defaults
[defaults]
CipherString = ALL:@SECLEVEL=0
EOF
        export OPENSSL_CONF=/tmp/openssl-weak.cnf
        ;;
    hybrid)
        key_args="-newkey ec -pkeyopt ec_paramgen_curve:P-256"
        protocols="TLSv1.3"
        curves="X25519MLKEM768:X25519"
        ciphers="HIGH:!aNULL"
        title="Layanan PQ-Ready (dummy)"
        issuer="classic"
        ;;
    pqfull)
        key_args="-newkey ML-DSA-65"
        protocols="TLSv1.3"
        curves="X25519MLKEM768:X25519"
        ciphers="HIGH:!aNULL"
        title="Layanan PQ-Full (dummy)"
        issuer="pq"
        ;;
    *)
        echo "unknown MODE" >&2
        exit 1
        ;;
esac

mkdir -p /tls /run /www
name="${SERVICE_NAME:-${MODE}}"
if [ -n "${issuer:-}" ]; then
    # shellcheck disable=SC2086
    openssl req -new $key_args -nodes -subj "/CN=${name}" -keyout /tls/key.pem -out /tmp/leaf.csr 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:%s,DNS:localhost\n' "$name" >/tmp/leaf.ext
    openssl x509 -req -in /tmp/leaf.csr -CA "/ca/${issuer}-intermediate.pem" -CAkey "/ca/${issuer}-intermediate.key" \
        -set_serial "0x$(openssl rand -hex 8)" -days 365 -extfile /tmp/leaf.ext -out /tmp/leaf.pem 2>/dev/null
    cat /tmp/leaf.pem "/ca/${issuer}-intermediate.pem" >/tls/cert.pem
else
    # The legacy service stays self-signed: an untrusted chain is part of what it demonstrates.
    # shellcheck disable=SC2086
    openssl req -x509 $key_args -nodes -days 365 -subj "/CN=${name}.kartika-01.lab" \
        -keyout /tls/key.pem -out /tls/cert.pem 2>/dev/null
fi

echo "<!doctype html><title>${title}</title><h1>${title}</h1><p>Layanan tiruan lab Satuan Kartika-01.</p>" >/www/index.html

cat >/etc/nginx/nginx.conf <<EOF
worker_processes 1;
pid /run/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 256; }
http {
    access_log off;
    server {
        listen 443 ssl;
        ${extra_listen:-}
        ssl_certificate /tls/cert.pem;
        ssl_certificate_key /tls/key.pem;
        ssl_protocols ${protocols};
        ssl_ecdh_curve ${curves};
        ssl_ciphers '${ciphers}';
        root /www;
        default_type text/html;
    }
}
EOF

exec nginx -g 'daemon off;'
