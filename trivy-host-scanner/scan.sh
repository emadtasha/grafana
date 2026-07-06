#!/bin/bash
set -euo pipefail

SCAN_INTERVAL="${SCAN_INTERVAL:-3600}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
OUTPUT_FILE="${OUTPUT_DIR}/trivy_host_scan.prom"
TMP_FILE="${OUTPUT_FILE}.tmp"

mkdir -p "${OUTPUT_DIR}"

echo "[trivy-host-scanner] starting, interval=${SCAN_INTERVAL}s, output=${OUTPUT_FILE}"

while true; do
  START_TS=$(date +%s)
  echo "[trivy-host-scanner] $(date -u +%FT%TZ) running scan of /host..."

  if ! RESULT_JSON=$(trivy fs --scanners vuln --format json --quiet /host 2>/tmp/trivy_err.log); then
    echo "[trivy-host-scanner] trivy scan failed:"
    cat /tmp/trivy_err.log || true
    sleep "${SCAN_INTERVAL}"
    continue
  fi

  CRITICAL=$(echo "${RESULT_JSON}" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length')
  HIGH=$(echo "${RESULT_JSON}"     | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length')
  MEDIUM=$(echo "${RESULT_JSON}"   | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length')
  LOW=$(echo "${RESULT_JSON}"      | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length')
  TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))
  END_TS=$(date +%s)
  DURATION=$((END_TS - START_TS))

  # Atomic write (write to tmp, then rename) so node-exporter's textfile
  # collector never reads a half-written file.
  {
    echo "# HELP trivy_host_vulnerabilities_total Vulnerabilities found on the last host filesystem scan, by severity"
    echo "# TYPE trivy_host_vulnerabilities_total gauge"
    echo "trivy_host_vulnerabilities_total{severity=\"CRITICAL\"} ${CRITICAL}"
    echo "trivy_host_vulnerabilities_total{severity=\"HIGH\"} ${HIGH}"
    echo "trivy_host_vulnerabilities_total{severity=\"MEDIUM\"} ${MEDIUM}"
    echo "trivy_host_vulnerabilities_total{severity=\"LOW\"} ${LOW}"
    echo "# HELP trivy_host_vulnerabilities_grand_total Sum of vulnerabilities across all severities"
    echo "# TYPE trivy_host_vulnerabilities_grand_total gauge"
    echo "trivy_host_vulnerabilities_grand_total ${TOTAL}"
    echo "# HELP trivy_host_scan_duration_seconds Duration of the last host scan in seconds"
    echo "# TYPE trivy_host_scan_duration_seconds gauge"
    echo "trivy_host_scan_duration_seconds ${DURATION}"
    echo "# HELP trivy_host_scan_timestamp_seconds Unix timestamp when the last scan completed"
    echo "# TYPE trivy_host_scan_timestamp_seconds gauge"
    echo "trivy_host_scan_timestamp_seconds ${END_TS}"
  } > "${TMP_FILE}"

  mv "${TMP_FILE}" "${OUTPUT_FILE}"

  echo "[trivy-host-scanner] scan complete in ${DURATION}s: total=${TOTAL} (critical=${CRITICAL} high=${HIGH} medium=${MEDIUM} low=${LOW})"
  sleep "${SCAN_INTERVAL}"
done
