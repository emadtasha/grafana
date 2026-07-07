FROM aquasec/trivy:0.56.0 as trivy

FROM python:3.11-slim

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY watcher.py .

EXPOSE 8086 8090

CMD ["python", "watcher.py"]
