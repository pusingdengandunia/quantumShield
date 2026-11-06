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
        ;;
    *)
        echo "unknown MODE" >&2
        exit 1
        ;;
esac

mkdir -p /tls /run /www
# shellcheck disable=SC2086
openssl req -x509 $key_args -nodes -days 365 -subj "/CN=${MODE}.kartika-01.lab" \
    -keyout /tls/key.pem -out /tls/cert.pem 2>/dev/null

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
