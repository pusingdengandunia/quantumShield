# alpine:3.22 ships OpenSSL 3.5, which the scanner needs to probe ML-KEM groups.
FROM python:3.13-alpine3.22
RUN apk add --no-cache openssl ca-certificates
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY qshield qshield
COPY lab/targets.json lab/targets.json
RUN adduser -D -u 1000 qshield && mkdir -p /data /gateway-conf && chown qshield /data /gateway-conf
USER qshield
ENV QSHIELD_DB=/data/qshield.db
EXPOSE 8000
CMD ["uvicorn", "qshield.app:app", "--host", "0.0.0.0", "--port", "8000"]
