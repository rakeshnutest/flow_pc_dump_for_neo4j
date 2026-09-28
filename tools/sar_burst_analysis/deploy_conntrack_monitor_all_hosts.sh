#!/usr/bin/env bash
# ==============================================================================
# Deploy and start monitor_conntrack_rates.py on every AHV host (from a CVM).
#
# Run on a CVM:
#   bash deploy_conntrack_monitor_all_hosts.sh
#   bash deploy_conntrack_monitor_all_hosts.sh /path/to/monitor_conntrack_rates.py
# ==============================================================================

set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-number_of_cps}"
REMOTE_PATH="/root/${REMOTE_DIR}"
SCRIPT_SRC="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${SCRIPT_SRC}" ]; then
  SCRIPT_SRC="${HERE}/monitor_conntrack_rates.py"
fi

if [ ! -f "${SCRIPT_SRC}" ]; then
  echo "[-] Script not found: ${SCRIPT_SRC}" >&2
  echo "    Pass the path: $0 /path/to/monitor_conntrack_rates.py" >&2
  exit 1
fi

SCRIPT_BASENAME="$(basename "${SCRIPT_SRC}")"

if ! command -v hostips >/dev/null 2>&1 || ! command -v hostssh >/dev/null 2>&1; then
  echo "[-] hostips/hostssh not found — run this on a Nutanix CVM." >&2
  exit 1
fi

HOSTS=$(hostips)
if [ -z "${HOSTS}" ]; then
  echo "[-] hostips returned no hosts." >&2
  exit 1
fi

echo "[+] Target hosts: ${HOSTS}"
echo "[+] Local script: ${SCRIPT_SRC}"
echo "[+] Remote dir  : ${REMOTE_PATH}"

echo "[+] mkdir on all hosts..."
hostssh "mkdir -p ${REMOTE_PATH}"

echo "[+] chmod dir on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}"

echo "[+] scp ${SCRIPT_BASENAME} to each host..."
for hip in ${HOSTS}; do
  echo "    -> root@${hip}:${REMOTE_PATH}/"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SCRIPT_SRC}" \
    "root@${hip}:${REMOTE_PATH}/"
done

echo "[+] chmod script on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}/${SCRIPT_BASENAME}"

echo "[+] start monitor in background on all hosts..."
hostssh "nohup python3 /root/number_of_cps/monitor_conntrack_rates.py --print --output-dir /root/number_of_cps  2>&1 &"

echo "[+] Done. Start issued on all hosts."
echo "    CSV : ${REMOTE_PATH}/conntrack_rates_<hostname>.csv"
echo "Check: hostssh 'pgrep -af monitor_conntrack_rates || true'"
echo "Stop:  hostssh 'pkill -f ${REMOTE_PATH}/${SCRIPT_BASENAME}'"
