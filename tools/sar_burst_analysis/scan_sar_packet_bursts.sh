#!/usr/bin/env bash
# ==============================================================================
# Scan all SAR binary files for network packet bursts >= 50k pkts/sec
# Run on AHV or CVM: bash scan_sar_packet_bursts.sh
# Cluster-wide from CVM: allssh "bash -s" < scan_sar_packet_bursts.sh
# ==============================================================================

set -euo pipefail

THRESHOLD="${THRESHOLD:-50000}"
SAR_DIR="${SAR_DIR:-/var/log/sa}"

echo "=== Scanning ${SAR_DIR}/ files for interface packet bursts >= ${THRESHOLD} pkts/s ==="
printf "%-12s %-10s %-12s %-16s %-16s %-16s\n" "DATE_FILE" "TIME" "IFACE" "rxpck/s" "txpck/s" "rxkB/s"

shopt -s nullglob
sa_files=("${SAR_DIR}"/sa[0-9]*)
if ((${#sa_files[@]} == 0)); then
  echo "No SAR files matching ${SAR_DIR}/sa[0-9]*" >&2
  exit 1
fi

# shellcheck disable=SC2012
for sa_file in $(ls -tr "${sa_files[@]}" 2>/dev/null); do
  fname=$(basename "$sa_file")
  LC_ALL=C sar -n DEV -f "$sa_file" 2>/dev/null | awk -v thresh="$THRESHOLD" -v sa="$fname" '
  $3 ~ /^(eth|br|bond|vnet)/ {
      rx = $4 + 0;
      tx = $5 + 0;
      if (rx >= thresh || tx >= thresh) {
          printf "%-12s %-10s %-12s %-16.2f %-16.2f %-16.2f\n", sa, $1, $3, $4, $5, $6
      }
  }'
done
