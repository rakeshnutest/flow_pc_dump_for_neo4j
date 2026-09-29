#!/usr/bin/env bash
# Bring up Grafana board for conntrack_rates_*.csv (all AHV hosts).
#
# Usage:
#   ./bringup_conntrack_grafana.sh /path/to/csv_dir [grafana_port]
#   ./bringup_conntrack_grafana.sh ../sample_data 3100
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${HERE}"

DATA_DIR="${1:-${HERE}/../sample_data}"
REQ_PORT="${2:-}"

if [[ ! -d "${DATA_DIR}" ]]; then
  echo "ERROR: data dir not found: ${DATA_DIR}" >&2
  exit 1
fi
DATA_DIR="$(cd "${DATA_DIR}" && pwd)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing $1" >&2; exit 1; }; }
need docker
need python3
need ss
need curl
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose v2 required" >&2
  exit 1
fi

port_free() {
  local p="$1"
  ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"
}

pick_port() {
  local start="${1:-3100}"
  local end="${2:-3999}"
  local p
  for p in $(seq "${start}" "${end}"); do
    if port_free "${p}"; then
      echo "${p}"
      return
    fi
  done
  echo "ERROR: no free port in ${start}-${end}" >&2
  exit 1
}

eth0_ip() {
  local ip
  ip="$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
  [[ -z "${ip}" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "${ip:-127.0.0.1}"
}

# Auto-write mapping.json if missing (filename stem = series / line name)
MAP="${DATA_DIR}/mapping.json"
if [[ ! -f "${MAP}" ]]; then
  DATA_DIR="${DATA_DIR}" MAP="${MAP}" python3 - <<'PY'
import json, os
from pathlib import Path
data = Path(os.environ["DATA_DIR"])
map_path = Path(os.environ["MAP"])
hosts = {}
for p in sorted(data.rglob("*.csv")):
    if p.name.startswith("mapping"):
        continue
    stem = p.stem
    rel = str(p.relative_to(data))
    if stem in hosts and hosts[stem] != rel:
        stem = rel.replace("/", "__")
        if stem.lower().endswith(".csv"):
            stem = stem[:-4]
    hosts[stem] = rel
map_path.write_text(json.dumps({"hosts": hosts}, indent=2) + "\n")
print(f"wrote {map_path} with {len(hosts)} series (filename = line)")
PY
fi

HOST_COUNT="$(python3 -c "import json; print(len(json.load(open('${MAP}')).get('hosts',{})))")"
CSV_COUNT="$(find "${DATA_DIR}" -type f -name '*.csv' ! -name 'mapping*' | wc -l | tr -d ' ')"

GRAFANA_PORT="$(pick_port "${REQ_PORT:-3100}" 3999)"
# pick a free local Influx bind port (not exposed publicly)
INFLUX_PORT="$(pick_port 8087 8199)"
ETH0_IP="$(eth0_ip)"

echo "==> Stopping previous conntrack Grafana stack (clean volumes)"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

export DATA_DIR
export GRAFANA_BIND="0.0.0.0:${GRAFANA_PORT}"
export INFLUX_BIND="127.0.0.1:${INFLUX_PORT}"

echo "==> Data dir : ${DATA_DIR}"
echo "==> Mapping  : ${MAP} (${HOST_COUNT} hosts, ${CSV_COUNT} csv files)"
echo "==> Grafana  : 0.0.0.0:${GRAFANA_PORT}"
echo "==> Starting stack..."
docker compose up -d --build

echo "==> Waiting for ingest to finish"
for i in $(seq 1 180); do
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
  sleep 2
done

for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${GRAFANA_PORT}/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Derive data window from sample CSV timestamps for a useful default range
WINDOW="$(DATA_DIR="${DATA_DIR}" python3 - <<'PY'
import os, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
pat = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
times = []
root = Path(os.environ["DATA_DIR"])
for p in list(root.rglob("conntrack_rates_*.csv"))[:20] or list(root.rglob("*.csv"))[:20]:
    try:
        text = p.read_text(errors="ignore").splitlines()
    except OSError:
        continue
    for line in text[1:50] + text[-20:]:
        m = pat.match(line.strip())
        if m:
            try:
                times.append(datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc))
            except ValueError:
                pass
if not times:
    print("now-24h|now")
else:
    lo = min(times) - timedelta(minutes=5)
    hi = max(times) + timedelta(minutes=5)
    print(lo.strftime("%Y-%m-%dT%H:%M:%S.000Z") + "|" + hi.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
PY
)"
DATA_FROM="${WINDOW%%|*}"
DATA_TO="${WINDOW##*|}"

DASH="http://${ETH0_IP}:${GRAFANA_PORT}/d/conntrack-rates?from=${DATA_FROM}&to=${DATA_TO}&var-host=All"
LOCAL="http://127.0.0.1:${GRAFANA_PORT}/d/conntrack-rates?from=${DATA_FROM}&to=${DATA_TO}&var-host=All"

cat <<EOF

============================================
 Conntrack Grafana board is up
============================================
 Listen:     0.0.0.0:${GRAFANA_PORT}
 eth0 open:  ${ETH0_IP}:${GRAFANA_PORT}
 Dashboard:  ${DASH}
 Local:      ${LOCAL}
 Login:      admin / conntrack123
 Hosts:      ${HOST_COUNT}
 Data window:${DATA_FROM} -> ${DATA_TO}

 Panels: new/s, destroy/s, avg_new/s, avg_destroy/s
 Filter: File/line (multi-select, All = every CSV)

 Stop with:
   cd ${HERE} && DATA_DIR=${DATA_DIR} docker compose down -v
============================================
EOF
