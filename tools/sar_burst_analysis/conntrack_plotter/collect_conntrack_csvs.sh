#!/usr/bin/env bash
# Collect conntrack_rates_*.csv from all AHV hosts (run on a CVM).
#
# Usage:
#   bash collect_conntrack_csvs.sh [local_out_dir]
#
# Then plot:
#   ./bringup_conntrack_plot.sh /path/to/out_dir
set -euo pipefail

OUT_DIR="${1:-./conntrack_csv_bundle}"
REMOTE_DIR="${REMOTE_DIR:-/root/number_of_cps}"

if ! command -v hostips >/dev/null 2>&1; then
  echo "[-] hostips not found — run on a Nutanix CVM." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
HOSTS=$(hostips)
echo "[+] Collecting from: ${HOSTS}"
echo "[+] Into: $(cd "${OUT_DIR}" && pwd)"

for hip in ${HOSTS}; do
  echo "    <- ${hip}"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@${hip}:${REMOTE_DIR}/conntrack_rates_*.csv" \
    "${OUT_DIR}/" 2>/dev/null || \
    echo "       (no CSV yet on ${hip})"
done

COUNT=$(find "${OUT_DIR}" -maxdepth 1 -type f -name 'conntrack_rates_*.csv' | wc -l | tr -d ' ')
echo "[+] Collected ${COUNT} CSV file(s) into ${OUT_DIR}"
echo "    Plot: ./bringup_conntrack_plot.sh ${OUT_DIR}"
