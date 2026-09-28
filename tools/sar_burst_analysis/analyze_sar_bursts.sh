#!/usr/bin/env bash
# ==============================================================================
# Script: analyze_sar_bursts.sh
# Purpose: Identify top network packet bursts and correlate with CPU / SoftIRQ
# Run on AHV or CVM: bash analyze_sar_bursts.sh
# Cluster-wide from CVM: allssh "bash -s" < analyze_sar_bursts.sh
# ==============================================================================

set -euo pipefail

SAR_DIR="${SAR_DIR:-/var/log/sa}"
PKT_THRESHOLD="${PKT_THRESHOLD:-50000}"
TOP_BURST_FLOOR="${TOP_BURST_FLOOR:-10000}"
RAMP_HOUR_PREFIX="${RAMP_HOUR_PREFIX:-08:}"

echo "=============================================================================="
echo "                   SAR NETWORK & CPU BURST ANALYSIS REPORT                     "
echo "=============================================================================="
echo "SAR_DIR=${SAR_DIR}  PKT_THRESHOLD=${PKT_THRESHOLD}  TOP_BURST_FLOOR=${TOP_BURST_FLOOR}"

shopt -s nullglob
sa_files=("${SAR_DIR}"/sa[0-9]*)
if ((${#sa_files[@]} == 0)); then
  echo "No SAR files matching ${SAR_DIR}/sa[0-9]*" >&2
  exit 1
fi

# 1. Top 15 Peak Network Surges across all recorded files
echo ""
echo "[+] Top 15 Peak Interface Bursts (rxpck/s + txpck/s):"
echo "------------------------------------------------------------------------------"
printf "%-12s %-10s %-12s %-14s %-14s %-14s\n" "SA_FILE" "TIMESTAMP" "INTERFACE" "rxpck/s" "txpck/s" "txkB/s"
echo "------------------------------------------------------------------------------"

# shellcheck disable=SC2012
for f in $(ls -tr "${sa_files[@]}" 2>/dev/null); do
  fname=$(basename "$f")
  LC_ALL=C sar -n DEV -f "$f" 2>/dev/null | awk -v sa="$fname" -v floor="$TOP_BURST_FLOOR" '
  $3 ~ /^(eth|br|bond|vnet)/ {
      if (($4+0) >= floor || ($5+0) >= floor) {
          print sa, $1, $3, $4, $5, $7
      }
  }'
done | sort -k4 -n -r | head -n 15 | while read -r sa ts iface rx tx txkb; do
  printf "%-12s %-10s %-12s %-14s %-14s %-14s\n" "$sa" "$ts" "$iface" "$rx" "$tx" "$txkb"
done

# 2. Correlate CPU System and SoftIRQ during burst hours (default 08:00 to 09:00)
echo ""
echo "[+] CPU Pressure (%sys / %soft) during ${RAMP_HOUR_PREFIX}xx Workday Ramp-up:"
echo "------------------------------------------------------------------------------"
printf "%-12s %-10s %-10s %-10s %-10s %-10s\n" "SA_FILE" "TIME" "%usr" "%sys" "%soft" "%idle"
echo "------------------------------------------------------------------------------"

# shellcheck disable=SC2012
for f in $(ls -tr "${sa_files[@]}" 2>/dev/null); do
  fname=$(basename "$f")
  LC_ALL=C sar -u -f "$f" 2>/dev/null | awk -v sa="$fname" -v prefix="$RAMP_HOUR_PREFIX" '
  index($1, prefix) == 1 {
      usr = $3 + 0;
      sys = $5 + 0;
      soft = $8 + 0;
      idle = $9 + 0;
      if (sys >= 15.0 || soft >= 2.5 || (100 - idle) >= 80.0) {
          printf "%-12s %-10s %-10.2f %-10.2f %-10.2f %-10.2f\n", sa, $1, $3, $5, $8, $9
      }
  }'
done | sort -k4 -n -r | head -n 10

echo ""
echo "=============================================================================="
echo "Analysis complete. Correlate timestamps with AHV exporter-cmd stats:"
echo "  curl -s -X POST -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"IpfixExporter.HandleExporterCmd\",\"params\":[{\"CommandType\":1}]}' \\"
echo "    http://127.0.0.1:1235/exporter-cmd"
echo "Look for IpfixEventQueueDrop / IpfixScannerQueueDrop (not ENOBUF)."
echo "=============================================================================="
