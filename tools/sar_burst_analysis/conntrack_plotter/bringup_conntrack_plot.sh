#!/usr/bin/env bash
# Bring up Docker dashboard for conntrack_rates_*.csv from 60–90 AHV hosts.
#
# Usage:
#   ./bringup_conntrack_plot.sh /path/to/csv_dir [port]
#   ./bringup_conntrack_plot.sh ./sample_data 8088
#
# Optional mapping.json in the data dir:
#   {"hosts": {"hostname": "conntrack_rates_hostname.csv", ...}}
# If absent, all conntrack_rates_*.csv (else *.csv) under the dir are mapped.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${HERE}"

DATA_DIR="${1:-${HERE}/sample_data}"
PORT="${2:-8088}"

if [[ ! -d "${DATA_DIR}" ]]; then
  echo "ERROR: data dir not found: ${DATA_DIR}" >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing $1" >&2; exit 1; }; }
need docker
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose v2 required" >&2
  exit 1
fi

# Resolve absolute path for bind mount
DATA_DIR="$(cd "${DATA_DIR}" && pwd)"
OUT_DIR="${HERE}/out"
mkdir -p "${OUT_DIR}"

# Auto-write mapping.json if missing
MAP="${DATA_DIR}/mapping.json"
if [[ ! -f "${MAP}" ]]; then
  DATA_DIR="${DATA_DIR}" MAP="${MAP}" python3 - <<'PY'
import json, os, re
from pathlib import Path
data = Path(os.environ["DATA_DIR"])
map_path = Path(os.environ["MAP"])
pat = re.compile(r"conntrack_rates_(.+)\.csv$", re.I)
hosts = {}
files = sorted(data.rglob("conntrack_rates_*.csv")) or sorted(data.rglob("*.csv"))
for p in files:
    if p.name == "mapping.json":
        continue
    m = pat.search(p.name)
    label = m.group(1) if m else p.stem
    if label not in hosts:
        hosts[label] = str(p.relative_to(data))
map_path.write_text(json.dumps({"hosts": hosts}, indent=2) + "\n")
print(f"wrote {map_path} with {len(hosts)} hosts")
PY
fi

HOST_COUNT="$(python3 -c "import json; print(len(json.load(open('${MAP}')).get('hosts',{})))")"
CSV_COUNT="$(find "${DATA_DIR}" -type f -name '*.csv' ! -name 'mapping.json' | wc -l | tr -d ' ')"

eth0_ip() {
  local ip
  ip="$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
  [[ -z "${ip}" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "${ip:-127.0.0.1}"
}
ETH0_IP="$(eth0_ip)"

echo "==> Data dir : ${DATA_DIR}"
echo "==> Mapping  : ${MAP} (${HOST_COUNT} hosts)"
echo "==> CSV files: ${CSV_COUNT}"
echo "==> Port     : ${PORT}"

export DATA_DIR OUT_DIR
export CONNTRACK_PLOT_BIND="0.0.0.0:${PORT}"

docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build

for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/api/mapping" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cat <<EOF

============================================
 Conntrack rates plotter is up
============================================
 Dashboard:  http://${ETH0_IP}:${PORT}/
 Local:      http://127.0.0.1:${PORT}/
 Mapping:    http://127.0.0.1:${PORT}/api/mapping
 Static HTML:${OUT_DIR}/conntrack_rates_all.html
 Hosts:      ${HOST_COUNT}

 Stop with:
   cd ${HERE} && DATA_DIR=${DATA_DIR} docker compose down
============================================
EOF
