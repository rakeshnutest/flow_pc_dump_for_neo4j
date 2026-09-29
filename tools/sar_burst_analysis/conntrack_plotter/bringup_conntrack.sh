#!/usr/bin/env bash
# Bring up Grafana for every CSV in a folder.
# Each file = one line on the board; legend name = filename (without .csv).
#
# Usage:
#   ./bringup_conntrack.sh /path/to/csv_folder
#   ./bringup_conntrack.sh /path/to/csv_folder 3100
#
# CSV columns: time,new,destroy,avg_new,avg_destroy
#   e.g. 2026-09-29T16:22:44Z,189,11,318.623,318.677
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="${HERE}/grafana-stack"

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<EOF
Usage: $0 <csv_folder> [grafana_port]

  csv_folder   Directory with conntrack CSV files (all *.csv plotted)
  grafana_port Optional; default picks next free port from 3100

Each CSV becomes one Grafana series; the line name is the filename stem.
EOF
  exit 1
fi

FOLDER="$1"
PORT="${2:-}"

if [[ ! -d "${FOLDER}" ]]; then
  echo "ERROR: folder not found: ${FOLDER}" >&2
  exit 1
fi
FOLDER="$(cd "${FOLDER}" && pwd)"

CSV_COUNT="$(find "${FOLDER}" -type f -name '*.csv' ! -name 'mapping*' | wc -l | tr -d ' ')"
if [[ "${CSV_COUNT}" -lt 1 ]]; then
  echo "ERROR: no *.csv files under ${FOLDER}" >&2
  exit 1
fi

echo "==> Folder : ${FOLDER}"
echo "==> CSVs   : ${CSV_COUNT} (each filename = one graph line)"

# Always rebuild mapping so legend labels are filename stems
MAP="${FOLDER}/mapping.json"
FOLDER="${FOLDER}" MAP="${MAP}" python3 - <<'PY'
import json, os
from pathlib import Path
data = Path(os.environ["FOLDER"])
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
Path(os.environ["MAP"]).write_text(json.dumps({"hosts": hosts}, indent=2) + "\n")
print(f"==> Mapping: {os.environ['MAP']} ({len(hosts)} lines)")
for name in list(hosts)[:8]:
    print(f"     line: {name}")
if len(hosts) > 8:
    print(f"     ... +{len(hosts) - 8} more")
PY

if [[ -n "${PORT}" ]]; then
  exec "${STACK}/bringup_conntrack_grafana.sh" "${FOLDER}" "${PORT}"
else
  exec "${STACK}/bringup_conntrack_grafana.sh" "${FOLDER}"
fi
