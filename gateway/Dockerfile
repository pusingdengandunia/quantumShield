# alpine:3.22 nginx links OpenSSL 3.5, which provides X25519MLKEM768.
FROM alpine:3.22
RUN apk add --no-cache nginx openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 9443-9452
ENTRYPOINT ["/entrypoint.sh"]
