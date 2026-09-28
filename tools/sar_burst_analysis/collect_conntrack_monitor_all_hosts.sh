#!/usr/bin/env bash
# ==============================================================================
# Collect conntrack monitor files from every AHV host (from a CVM).
#
# Run on a CVM:
#   bash collect_conntrack_monitor_all_hosts.sh
#   bash collect_conntrack_monitor_all_hosts.sh /path/to/local_outdir
#
# Env overrides:
#   REMOTE_DIR=number_of_cps
#   OUT_DIR=./conntrack_collect_<timestamp>
# ==============================================================================

set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-number_of_cps}"
REMOTE_PATH="/root/${REMOTE_DIR}"
OUT_DIR="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${OUT_DIR}" ]; then
  OUT_DIR="${HERE}/conntrack_collect_$(date -u +%Y%m%dT%H%M%SZ)"
fi

if ! command -v hostips >/dev/null 2>&1; then
  echo "[-] hostips not found — run this on a Nutanix CVM." >&2
  exit 1
fi

HOSTS=$(hostips)
if [ -z "${HOSTS}" ]; then
  echo "[-] hostips returned no hosts." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
echo "[+] Target hosts: ${HOSTS}"
echo "[+] Remote dir  : ${REMOTE_PATH}"
echo "[+] Local out   : ${OUT_DIR}"

ok=0
fail=0
for hip in ${HOSTS}; do
  host_dir="${OUT_DIR}/${hip}"
  mkdir -p "${host_dir}"
  echo "[+] collect root@${hip}:${REMOTE_PATH}/ -> ${host_dir}/"
  if scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r \
    "root@${hip}:${REMOTE_PATH}/." \
    "${host_dir}/"; then
    echo "    OK ${hip}"
    ok=$((ok + 1))
  else
    echo "    FAIL ${hip}" >&2
    fail=$((fail + 1))
  fi
done

echo "[+] Done. ok=${ok} fail=${fail}"
echo "    Output: ${OUT_DIR}"
echo "    Layout: ${OUT_DIR}/<host_ip>/conntrack_rates_*.csv"
echo "Preview:  find ${OUT_DIR} -name 'conntrack_rates_*.csv' -exec ls -la {} +"
echo "Tail:     find ${OUT_DIR} -name 'conntrack_rates_*.csv' -exec sh -c 'echo === \$1 ===; tail -n 10 \"\$1\"' _ {} \\;"
