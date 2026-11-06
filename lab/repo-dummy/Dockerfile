# One-shot job: copies the dummy repository to a volume and adds throwaway keys,
# so no private key is ever committed to this project.
FROM alpine:3.22
RUN apk add --no-cache openssl
COPY src /template/src
COPY config /template/config
ENTRYPOINT ["/bin/sh", "-c", "cp -r /template/. /out/ && mkdir -p /out/keys && openssl genrsa -traditional -out /out/keys/dummy_rsa.pem 2048 2>/dev/null && chmod -R a+rX /out"]
