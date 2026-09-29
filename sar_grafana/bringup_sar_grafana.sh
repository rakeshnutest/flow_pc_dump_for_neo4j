#!/usr/bin/env bash
# Bring up SAR Grafana stack from a Diamond/NTNX PE zip.
# Usage: ./bringup_sar_grafana.sh /path/to/PE.zip [grafana_port]
set -euo pipefail

ZIP="${1:-}"
REQ_PORT="${2:-}"

if [[ -z "${ZIP}" || "${ZIP}" == "-h" || "${ZIP}" == "--help" ]]; then
  cat <<'EOF'
Usage: ./bringup_sar_grafana.sh <ntnx-or-diamond.zip> [grafana_port]

What it does:
  1) Converts CVM SAR day files from the zip into data/preload/sarNN.txt
  2) Starts Docker Compose (Grafana + InfluxDB + ingest) listening on 0.0.0.0
  3) Prints eth0 IP and Grafana port to open

Examples:
  ./bringup_sar_grafana.sh ./2657578-PE-10.3.89.176.zip
  ./bringup_sar_grafana.sh ./bundle.zip 3100
EOF
  exit 1
fi

if [[ ! -f "${ZIP}" ]]; then
  echo "ERROR: zip not found: ${ZIP}" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required command: $1" >&2; exit 1; }; }
need docker
need python3
need xz
need ss

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose v2 is required" >&2
  exit 1
fi

port_free() {
  local p="$1"
  ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"
}

# Always choose the next free port starting from BASE (default 3000).
pick_port() {
  local base="${SAR_PORT_BASE:-3000}"
  local max="${SAR_PORT_MAX:-3999}"
  local p start
  if [[ -n "${REQ_PORT}" ]]; then
    start="${REQ_PORT}"
  else
    start="${base}"
  fi
  for p in $(seq "${start}" "${max}"); do
    if port_free "${p}"; then
      echo "${p}"
      return
    fi
  done
  echo "ERROR: no free port in ${start}-${max}" >&2
  exit 1
}

stop_existing_stack() {
  echo "==> Stopping any previous stack in ${ROOT} (and removing volumes for clean ingest)"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker ps -aq --filter name=grafana-stack --filter name=sar-zip-viewer --filter name=sar_grafana 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1 || true
}

eth0_ip() {
  local ip
  ip="$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="127.0.0.1"
  fi
  echo "${ip}"
}

stop_existing_stack

GRAFANA_PORT="$(pick_port)"
ETH0_IP="$(eth0_ip)"

echo "==> Using Grafana port ${GRAFANA_PORT} on 0.0.0.0"
echo "==> eth0 IP: ${ETH0_IP}"

echo "==> Converting SAR from zip: ${ZIP}"
mkdir -p data/preload
# clear previous preload texts so this zip is the source of truth
find data/preload -maxdepth 1 -type f -name 'sar*.txt' -delete

python3 - "${ZIP}" "${ROOT}/data/preload" <<'PY'
import subprocess, sys, zipfile
from pathlib import Path

zip_path = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

def decode(raw: bytes) -> str:
    if raw[:6] == b"\xfd7zXZ\x00":
        raw = subprocess.check_output(["xz", "-dc", "--stdout"], input=raw)
    if b"\x00" in raw[:512]:
        return ""
    return raw.decode("utf-8", errors="ignore")

kept = 0
with zipfile.ZipFile(zip_path) as zf:
    names = sorted(zf.namelist())
    candidates = []
    for name in names:
        base = Path(name).name
        norm = name.replace("\\", "/")
        if not (base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit()):
            continue
        candidates.append((name, base, norm))

    kernel = [c for c in candidates if "kernel/var/" in c[2]]
    selected = kernel if kernel else candidates

    for name, base, norm in selected:
        text = decode(zf.read(name))
        if "CPU" not in text and "%usr" not in text and "IFACE" not in text:
            continue
        dest = out / f"{base}.txt"
        dest.write_text(text)
        kept += 1
        print(f"  wrote {dest.name} ({len(text)} bytes) from {name}")

if kept == 0:
    raise SystemExit("No usable SAR day files found in zip (expected cvm_logs/kernel/var/sarNN)")
print(f"Converted {kept} SAR day file(s)")
PY

# Prefer not publishing Influx on host; Grafana is the UI users open.
export GRAFANA_BIND="0.0.0.0:${GRAFANA_PORT}"

echo "==> Starting Docker stack (Grafana on 0.0.0.0:${GRAFANA_PORT})"
docker compose up -d --build

echo "==> Waiting for ingest to finish"
for i in $(seq 1 90); do
  id="$(docker compose ps -aq ingest 2>/dev/null | head -1 || true)"
  if [[ -n "${id}" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "${id}" 2>/dev/null || echo missing)"
    code="$(docker inspect -f '{{.State.ExitCode}}' "${id}" 2>/dev/null || echo 1)"
    if [[ "${status}" == "exited" ]]; then
      if [[ "${code}" == "0" ]]; then
        echo "Ingest completed successfully"
        docker compose logs --tail 20 ingest || true
        break
      fi
      echo "ERROR: ingest exited with code ${code}" >&2
      docker compose logs --tail 80 ingest >&2 || true
      exit 1
    fi
  fi
  if [[ "${i}" -eq 90 ]]; then
    echo "WARNING: timed out waiting for ingest; check: docker compose logs ingest" >&2
  fi
  sleep 2
done

# Ensure Grafana answers
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

DASHBOARD_URL="http://${ETH0_IP}:${GRAFANA_PORT}/d/sar-overview"
LOCAL_URL="http://127.0.0.1:${GRAFANA_PORT}/d/sar-overview"

cat <<EOF

============================================
 SAR Grafana is up
============================================
 Listen:     0.0.0.0:${GRAFANA_PORT}
 eth0 open:  ${ETH0_IP}:${GRAFANA_PORT}
 Dashboard:  ${DASHBOARD_URL}
 Local:      ${LOCAL_URL}
 Login:      admin / saradmin123

 Filters: Host/CVM, Interface, Rx/Tx packets,
          Rx/Tx kB, errors/drops, Disk, time range

 Stop with:
   cd ${ROOT} && docker compose down
============================================
EOF
