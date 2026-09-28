#!/usr/bin/env bash
# ==============================================================================
# Deploy and start monitor_conntrack_rates.py on every AHV host (from a CVM).
#
# Run on a CVM:
#   bash deploy_conntrack_monitor_all_hosts.sh
#   bash deploy_conntrack_monitor_all_hosts.sh /path/to/monitor_conntrack_rates.py
#
# hostssh only gets short commands (mkdir/chmod/bash starter). The long start
# logic is scp'd as start_monitor_on_host.sh so quoting is not mangled.
# ==============================================================================

set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-number_of_cps}"
REMOTE_PATH="/root/${REMOTE_DIR}"
MAX_HOURS="${MAX_HOURS:-24}"
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
START_HELPER_NAME="start_monitor_on_host.sh"
START_HELPER_LOCAL="${HERE}/${START_HELPER_NAME}"

# Bake paths into the AHV starter (no remote env needed).
# Use setsid -f so hostssh (30s timeout) returns immediately.
cat >"${START_HELPER_LOCAL}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
REMOTE_PATH="${REMOTE_PATH}"
SCRIPT="${REMOTE_PATH}/${SCRIPT_BASENAME}"
MAX_HOURS="${MAX_HOURS}"

chmod 755 "\${REMOTE_PATH}" "\${SCRIPT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing python3 on \$(hostname)" >&2
  exit 1
fi

pkill -f "\${SCRIPT}" 2>/dev/null || true
sleep 1

cd "\${REMOTE_PATH}"
setsid -f python3 "\${SCRIPT}" \\
  --output-dir "\${REMOTE_PATH}" \\
  --max-hours "\${MAX_HOURS}" \\
  </dev/null >"\${REMOTE_PATH}/monitor.out" 2>&1
sleep 1
pgrep -n -f "\${SCRIPT}" >"\${REMOTE_PATH}/monitor.pid" || true

PID=\$(cat "\${REMOTE_PATH}/monitor.pid" 2>/dev/null || true)
if [ -n "\${PID}" ] && kill -0 "\${PID}" 2>/dev/null; then
  echo "OK background pid=\${PID} host=\$(hostname)"
  ls -la "\${REMOTE_PATH}"
  exit 0
fi

echo "FAIL not running host=\$(hostname)" >&2
tail -40 "\${REMOTE_PATH}/monitor.out" >&2 || true
exit 1
EOF
chmod 755 "${START_HELPER_LOCAL}"

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
echo "[+] Start helper: ${START_HELPER_LOCAL}"
echo "[+] Remote dir  : ${REMOTE_PATH}"
echo "[+] Max hours   : ${MAX_HOURS}"

echo "[+] mkdir on all hosts..."
hostssh "mkdir -p ${REMOTE_PATH}"

echo "[+] chmod dir on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}"

echo "[+] scp files to each host..."
for hip in ${HOSTS}; do
  echo "    -> root@${hip}:${REMOTE_PATH}/"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SCRIPT_SRC}" "${START_HELPER_LOCAL}" \
    "root@${hip}:${REMOTE_PATH}/"
done

echo "[+] chmod scripts on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}/${SCRIPT_BASENAME} ${REMOTE_PATH}/${START_HELPER_NAME}"

echo "[+] start monitor in background on all hosts..."
hostssh "bash ${REMOTE_PATH}/${START_HELPER_NAME}"

echo "[+] Done. Monitors are running in background on all hosts."
echo "    CSV : ${REMOTE_PATH}/conntrack_rates_<hostname>.csv"
echo "    Log : ${REMOTE_PATH}/monitor.out"
echo "    PID : ${REMOTE_PATH}/monitor.pid"
echo "Check: hostssh 'cat ${REMOTE_PATH}/monitor.pid; pgrep -af monitor_conntrack_rates || true'"
echo "Stop:  hostssh 'kill \$(cat ${REMOTE_PATH}/monitor.pid) 2>/dev/null || pkill -f ${REMOTE_PATH}/${SCRIPT_BASENAME}'"
