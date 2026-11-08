# One-shot job: creates the lab's certificate authorities on a volume at start,
# so no CA key ever lives in the repository or the image.
FROM alpine:3.22
RUN apk add --no-cache openssl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
