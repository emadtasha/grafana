FROM python:3.11-slim

ENV TRIVY_VERSION=0.53.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates tar && \
    curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    apt-get purge -y curl tar && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY watcher.py .

EXPOSE 8086 8090

CMD ["python", "watcher.py"]
