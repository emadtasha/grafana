FROM aquasec/trivy:0.56.0

RUN apk add --no-cache bash jq coreutils

WORKDIR /app
COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh

ENTRYPOINT ["/app/scan.sh"]
