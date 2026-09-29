#!/usr/bin/env bash
# Bring up SAR Grafana stack from one or more Diamond/NTNX PE zips (multi-host).
# Usage:
#   ./bringup_sar_grafana.sh <zip|dir> [zip|dir ...] [grafana_port]
#   ./bringup_sar_grafana.sh /path/to/dir-with-many-pe-zips
set -euo pipefail

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  ./bringup_sar_grafana.sh <zip-or-dir> [zip-or-dir ...] [grafana_port]

Converts CVM + AHV SAR from ALL given PE zips/dirs, starts Docker on 0.0.0.0,
picks the next free Grafana port, and prints eth0:port.

  CVM: cvm_logs/kernel/var/sarNN
  AHV: ahv/<ip>/files/var/log/sa/saNN  (needs local 'sar' / sysstat)

Examples:
  ./bringup_sar_grafana.sh ./PE-10.3.89.176.zip ./PE-10.3.89.177.zip ./PE-10.3.89.178.zip
  ./bringup_sar_grafana.sh /path/to/2026-09-07/          # all *.zip in that folder
  ./bringup_sar_grafana.sh ./bundle.zip 3100
EOF
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT}"

# Last numeric arg (if any) is optional Grafana port; everything else is inputs.
ARGS=("$@")
REQ_PORT=""
if [[ "${ARGS[-1]}" =~ ^[0-9]+$ ]]; then
  REQ_PORT="${ARGS[-1]}"
  unset 'ARGS[-1]'
fi
if [[ ${#ARGS[@]} -lt 1 ]]; then
  echo "ERROR: provide at least one zip or directory" >&2
  exit 1
fi

# Expand directories to *.zip inside them (plus the dir itself for extracted trees)
INPUTS=()
for item in "${ARGS[@]}"; do
  if [[ -d "${item}" ]]; then
    mapfile -t zips < <(find "${item}" -maxdepth 1 -type f -name '*.zip' | sort)
    if [[ ${#zips[@]} -gt 0 ]]; then
      INPUTS+=("${zips[@]}")
    else
      INPUTS+=("${item}")
    fi
  elif [[ -f "${item}" ]]; then
    INPUTS+=("${item}")
  else
    echo "ERROR: not found: ${item}" >&2
    exit 1
  fi
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required command: $1" >&2; exit 1; }; }
need docker
need python3
need xz
need ss
if ! command -v sar >/dev/null 2>&1; then
  echo "WARNING: 'sar' (sysstat) not found — AHV binary saNN files will be skipped" >&2
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose v2 is required" >&2
  exit 1
fi

port_free() {
  local p="$1"
  ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"
}

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
echo "==> Inputs (${#INPUTS[@]}):"
printf '   - %s\n' "${INPUTS[@]}"

echo "==> Converting SAR for ALL hosts into data/preload/"
mkdir -p data/preload
# Prefer home/cache over /tmp (often a small tmpfs) for AHV sa binary conversion.
export TMPDIR="${TMPDIR:-${HOME}/.cache/sar_grafana_tmp}"
mkdir -p "${TMPDIR}"
python3 "${ROOT}/convert_ntnx_sar.py" --clean -o "${ROOT}/data/preload" "${INPUTS[@]}"

HOST_COUNT="$(find data/preload -maxdepth 1 -type f -name '*__sar*.txt' | sed 's/__sar.*//' | sort -u | wc -l | tr -d ' ')"
FILE_COUNT="$(find data/preload -maxdepth 1 -type f -name '*__sar*.txt' | wc -l | tr -d ' ')"
echo "==> Preload ready: ${FILE_COUNT} day files, ${HOST_COUNT} host(s)"

export GRAFANA_BIND="0.0.0.0:${GRAFANA_PORT}"

echo "==> Starting Docker stack (Grafana on 0.0.0.0:${GRAFANA_PORT})"
docker compose up -d --build

echo "==> Waiting for ingest to finish (AHV binaries can take several minutes)"
for i in $(seq 1 360); do
  id="$(docker compose ps -aq ingest 2>/dev/null | head -1 || true)"
  if [[ -n "${id}" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "${id}" 2>/dev/null || echo missing)"
    code="$(docker inspect -f '{{.State.ExitCode}}' "${id}" 2>/dev/null || echo 1)"
    if [[ "${status}" == "exited" ]]; then
      if [[ "${code}" == "0" ]]; then
        echo "Ingest completed successfully"
        docker compose logs --tail 40 ingest || true
        break
      fi
      echo "ERROR: ingest exited with code ${code}" >&2
      docker compose logs --tail 120 ingest >&2 || true
      exit 1
    fi
  fi
  if [[ "${i}" -eq 120 ]]; then
    echo "WARNING: timed out waiting for ingest; check: docker compose logs ingest" >&2
  fi
  sleep 2
done

for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

DATA_FROM="$(python3 - <<'PY2'
from pathlib import Path
import re
from datetime import datetime
dates=[]
for f in Path("data/preload").glob("*sar*.txt"):
    head=f.read_text(errors="ignore")[:800]
    for m in re.finditer(r"\)\s+(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})", head):
        s=m.group(1)
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
            try:
                dates.append(datetime.strptime(s, fmt).date())
                break
            except ValueError:
                pass
print((min(dates).isoformat()+"T00:00:00.000Z") if dates else "now-90d")
PY2
)"
DATA_TO="$(python3 - <<'PY2'
from pathlib import Path
import re
from datetime import datetime
dates=[]
for f in Path("data/preload").glob("*sar*.txt"):
    head=f.read_text(errors="ignore")[:800]
    for m in re.finditer(r"\)\s+(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})", head):
        s=m.group(1)
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
            try:
                dates.append(datetime.strptime(s, fmt).date())
                break
            except ValueError:
                pass
print((max(dates).isoformat()+"T23:59:59.000Z") if dates else "now")
PY2
)"
HOSTS="$(python3 - <<'PY2'
from pathlib import Path
hosts=set()
for f in Path("data/preload").glob("*__sar*.txt"):
    # ntnx-x__cvm__sar05.txt or host__ahv__sar05.txt or legacy host__sar05.txt
    name=f.name
    if "__ahv__" in name:
        hosts.add(name.split("__ahv__")[0] + " (ahv)")
    elif "__cvm__" in name:
        hosts.add(name.split("__cvm__")[0] + " (cvm)")
    else:
        hosts.add(name.split("__sar")[0])
print(", ".join(sorted(hosts)) if hosts else "(none)")
PY2
)"

DASHBOARD_URL="http://${ETH0_IP}:${GRAFANA_PORT}/d/sar-overview?from=${DATA_FROM}&to=${DATA_TO}"
LOCAL_URL="http://127.0.0.1:${GRAFANA_PORT}/d/sar-overview?from=${DATA_FROM}&to=${DATA_TO}"
DASHBOARD_URL_REL="http://${ETH0_IP}:${GRAFANA_PORT}/d/sar-overview?from=now-90d&to=now"

cat <<EOF

============================================
 SAR Grafana is up (multi-host)
============================================
 Listen:     0.0.0.0:${GRAFANA_PORT}
 eth0 open:  ${ETH0_IP}:${GRAFANA_PORT}
 Dashboard:  ${DASHBOARD_URL}
 Local:      ${LOCAL_URL}
 Alt (90d):  ${DASHBOARD_URL_REL}
 Login:      admin / saradmin123
 Hosts:      ${HOSTS}
 Data window:${DATA_FROM} -> ${DATA_TO}

 Filters: Role (CVM/AHV), Host / CVM / AHV, Interface, Rx/Tx, errors, Disk

 Stop with:
   cd ${ROOT} && docker compose down
============================================
EOF
