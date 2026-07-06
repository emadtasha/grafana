# Full-Stack Observability & Security Monitoring

A self-contained Docker Compose stack with three observability lanes:

| Lane      | Services                              | Purpose                                   |
|-----------|----------------------------------------|--------------------------------------------|
| Metrics   | Prometheus, node-exporter, cAdvisor    | Host + container CPU/RAM/health over time  |
| Logs      | Vector, Loki                           | Centralized container logs                 |
| Security  | trivy-host-scanner, trivy-watcher      | Continuous vulnerability scanning           |

Visualization is Grafana, with Prometheus and Loki wired in as data sources automatically.

## Directory layout

```
.
├── docker-compose.yml
├── .env.example
├── config/
│   ├── prometheus/prometheus.yml
│   ├── loki/loki-config.yaml
│   ├── vector/vector.yaml
│   └── grafana/provisioning/datasources/datasource.yml
├── trivy-host-scanner/       # scans the EC2 host filesystem on a timer
│   ├── Dockerfile
│   └── scan.sh
├── trivy-watcher/            # scans every container image as it starts
│   ├── Dockerfile
│   ├── requirements.txt
│   └── watcher.py
└── .github/workflows/deploy.yml   # optional: push-to-deploy via SSH
```

## Ports

| Service            | Port | Notes                                   |
|--------------------|------|-------------------------------------------|
| Grafana            | 9000 | UI, admin / value of `GRAFANA_ADMIN_PASSWORD` |
| Prometheus         | 9090 | UI / API                                  |
| Loki               | 3100 | Query API (used internally by Grafana)    |
| node-exporter      | 9100 | Host metrics + Trivy host-scan textfile   |
| cAdvisor           | 8085 | Container metrics                         |
| trivy-watcher API  | 8090 | JSON scan results, `/api/results`         |
| trivy-watcher metrics | 8086 | Prometheus metrics for the watcher      |

On your EC2 instance's security group, open these inbound (ideally restricted to your IP, not `0.0.0.0/0`, since Grafana/Prometheus have no auth on some endpoints by default):
`9000, 9090, 3100, 9100, 8085, 8090, 8086` (TCP).

## How the three lanes fit together

**Metrics** — Prometheus scrapes `node-exporter` (host-level: CPU, memory, disk, filesystem) and `cadvisor` (per-container). Both are visible in Grafana once you add dashboards (e.g. import community dashboard IDs 1860 for node-exporter and 14282 for cAdvisor).

**Logs** — Vector mounts `/var/run/docker.sock` read-only and uses its `docker_logs` source to tail every running container's log stream. The `exclude_containers` list explicitly omits the monitoring stack's own containers (`vector`, `loki`, `grafana`, `prometheus`, `node-exporter`, `cadvisor`, `trivy-host-scanner`, `trivy-watcher`) so the stack never floods itself with its own logs. A `remap` transform normalizes the timestamp and merges in any JSON your app logs emit, before shipping to Loki as JSON.

**Security** —
- `trivy-host-scanner` wakes up every `SCAN_INTERVAL` seconds (default 3600), runs `trivy fs` against `/host` (your EC2 root filesystem, mounted read-only), and writes a Prometheus-formatted `.prom` file into a volume shared with node-exporter's `--collector.textfile.directory`. Node-exporter automatically ingests it — no separate scrape job needed.
- `trivy-watcher` is a small Python service that subscribes to Docker's event stream. Every time a container starts, it runs `trivy image` against that container's image in a background thread, then exposes the counts both as JSON (`:8090/api/results`) and as Prometheus gauges (`:8086`, scraped by the `trivy-watcher` job in `prometheus.yml`).

## Data sources in Grafana

Per the task, Prometheus and Loki need to be linked as data sources in Grafana. This is done two ways here:

1. **Automatically**, via `config/grafana/provisioning/datasources/datasource.yml` — as soon as Grafana starts, both sources exist and Prometheus is set as default. This is the recommended approach (infra-as-code, survives container recreation).
2. **Manually**, if you want to verify or prefer doing it by hand: log into `http://<EC2_PUBLIC_IP>:9000` → **Connections → Data sources → Add data source**, and point one at `http://prometheus:9090` and the other at `http://loki:3100` (these are Docker network hostnames, not your EC2 IP, since Grafana talks to them over the internal `monitoring` network).

## Running locally (or directly on the EC2 box over SSH)

```bash
git clone <your-repo-url> monitoring-stack
cd monitoring-stack
cp .env.example .env
# edit .env: set EC2_PUBLIC_IP=100.58.158.7 and a real GRAFANA_ADMIN_PASSWORD

docker compose up -d --build
docker compose ps
```

Then visit:
- `http://100.58.158.7:9000` — Grafana
- `http://100.58.158.7:9090` — Prometheus
- `http://100.58.158.7:8090/api/results` — live vulnerability scan results per container

## Deploying via GitHub

Two options, pick what fits your workflow:

**A. Push-to-deploy (included)** — `.github/workflows/deploy.yml` SSHs into the EC2 box on every push to `main` and runs `git pull && docker compose up -d --build`. Set these repo secrets first:
- `HOST_IP` → your EC2 public IP address
- `EC2_SSH_USER` → your EC2 login user (`ubuntu` for Ubuntu AMIs, `ec2-user` for Amazon Linux)
- `EC2_SSH_KEY` → the private half of the key pair authorized on that instance
- `GRAFANA_ADMIN_PASSWORD` → optional, defaults to `changeme123`

**B. Manual pull** — just `git clone`/`git pull` on the instance yourself and run `docker compose up -d --build` as shown above. Simpler, no secrets to manage, fine for a single-week task.

## Notes / things worth knowing before you present this

- **cAdvisor runs `privileged: true`** and mounts `/dev/kmsg` — standard for accurate container metrics, but worth calling out if anyone asks about the security posture of the stack itself.
- **Trivy's vulnerability DB** downloads from the internet on first scan for both `trivy-host-scanner` and `trivy-watcher` — make sure the EC2 instance has outbound internet access (or a NAT/proxy) or scans will fail on a fully air-gapped box.
- **`trivy-watcher` scans on container *start*, not on a schedule** — restarting a container re-triggers a scan; a container that's already running when the watcher itself starts won't be scanned until it next restarts. If you want a full sweep of already-running containers on watcher startup too, that's a natural follow-up (iterate `client.containers.list()` once at boot).
- The Trivy versions pinned in the Dockerfiles (`0.53.0`) and other image tags are current as of this writing — bump them periodically.
