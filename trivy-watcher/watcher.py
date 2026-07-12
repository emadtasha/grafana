"""
trivy-watcher
-------------
Listens to the Docker daemon's event stream. Whenever a container starts,
it triggers a Trivy image vulnerability scan in a background thread and
exposes the results two ways:

  * JSON API on :8090   -> GET /api/results, /api/results/<container_id>, /health
  * Prometheus metrics on :8086 -> trivy_watcher_vulnerabilities{...}
"""

import json
import logging
import subprocess
import threading
import time

import docker
from flask import Flask, jsonify
from prometheus_client import Gauge, start_http_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [trivy-watcher] %(message)s",
)
log = logging.getLogger("trivy-watcher")

app = Flask(__name__)

results_lock = threading.Lock()
scan_results = {}  # container_id -> result dict

# Containers belonging to the monitoring stack itself are never scanned,
# mirroring the same "don't monitor the monitor" rule used for logging.
IGNORED_NAME_FRAGMENTS = [
    "trivy-watcher",
    "trivy-host-scanner",
    "vector",
    "loki",
    "grafana",
    "prometheus",
    "node-exporter",
    "cadvisor",
]

vuln_gauge = Gauge(
    "trivy_watcher_vulnerabilities",
    "Vulnerabilities found by trivy-watcher for a running container's image",
    ["container_name", "image", "severity"],
)
scan_duration_gauge = Gauge(
    "trivy_watcher_scan_duration_seconds",
    "Duration of the most recent scan for a container",
    ["container_name"],
)
scans_total_gauge = Gauge(
    "trivy_watcher_scans_total",
    "Total number of scans performed since startup",
)

_scans_done = 0
_scans_done_lock = threading.Lock()


def scan_image(container_id: str, container_name: str, image_tag: str) -> None:
    global _scans_done
    log.info("scanning image=%s (container=%s)", image_tag, container_name)
    start = time.time()
    try:
        proc = subprocess.run(
            ["trivy", "image", "--quiet", "--format", "json", image_tag],
            capture_output=True,
            text=True,
            timeout=600,
        )
        duration = time.time() - start

        if proc.returncode != 0:
            log.warning(
                "trivy exited %s for %s: %s",
                proc.returncode, image_tag, (proc.stderr or "")[:300],
            )

        data = json.loads(proc.stdout or "{}")
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                sev = vuln.get("Severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1

        for sev, count in counts.items():
            vuln_gauge.labels(
                container_name=container_name, image=image_tag, severity=sev
            ).set(count)
        scan_duration_gauge.labels(container_name=container_name).set(duration)

        with _scans_done_lock:
            _scans_done += 1
            scans_total_gauge.set(_scans_done)

        with results_lock:
            scan_results[container_id] = {
                "container_name": container_name,
                "image": image_tag,
                "scanned_at": time.time(),
                "duration_seconds": round(duration, 2),
                "vulnerability_counts": counts,
                "total_vulnerabilities": sum(counts.values()),
            }

        log.info("scan complete for %s: %s", image_tag, counts)
    except Exception as exc:  # noqa: BLE001 - log and move on, never crash the watcher
        log.error("scan failed for %s: %s", image_tag, exc)


def watch_docker_events() -> None:
    client = docker.from_env()
    log.info("listening for container 'start' events on the docker socket...")
    for event in client.events(decode=True, filters={"type": "container", "event": "start"}):
        try:
            # Newer Docker Engine API versions dropped the deprecated
            # top-level "id"/"status" fields on events; the container ID
            # now lives under Actor.ID. Fall back to the old field too,
            # in case this ever runs against an older daemon.
            container_id = (event.get("Actor") or {}).get("ID") or event.get("id")
            if not container_id:
                continue
            container = client.containers.get(container_id)
            container_name = container.name

            if any(frag in container_name for frag in IGNORED_NAME_FRAGMENTS):
                continue

            image_tags = container.image.tags
            image_tag = image_tags[0] if image_tags else container.attrs["Config"]["Image"]

            threading.Thread(
                target=scan_image,
                args=(container_id, container_name, image_tag),
                daemon=True,
            ).start()
        except Exception as exc:  # noqa: BLE001
            log.error("error handling docker event: %s", exc)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/results")
def api_results():
    with results_lock:
        return jsonify(scan_results)


@app.route("/api/results/<container_id>")
def api_result_one(container_id):
    with results_lock:
        result = scan_results.get(container_id)
    if not result:
        return jsonify({"error": "no scan result for that container id"}), 404
    return jsonify(result)


if __name__ == "__main__":
    start_http_server(8086)  # Prometheus metrics
    threading.Thread(target=watch_docker_events, daemon=True).start()
    app.run(host="0.0.0.0", port=8090)  # JSON API
