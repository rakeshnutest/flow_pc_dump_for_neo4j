#!/usr/bin/env bash
# ==============================================================================
# Deploy and start monitor_conntrack_rates.py on every AHV host (from a CVM).
#
# Run on a CVM (needs hostips / hostssh / passwordless root SSH to AHVs):
#   bash deploy_conntrack_monitor_all_hosts.sh
#   bash deploy_conntrack_monitor_all_hosts.sh /path/to/monitor_conntrack_rates.py
#
# Generates start_monitor_on_host.sh next to this script (baked paths), scp's
# both scripts to /root/number_of_cps on each host, then runs the starter via
# a short hostssh command (avoids hostssh quoting failures on complex remotes).
#
# Env overrides:
#   REMOTE_DIR=number_of_cps
#   MAX_HOURS=24
# ==============================================================================

set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-number_of_cps}"
# AHV sessions via hostssh/scp are root → ~ is /root
REMOTE_PATH="/root/${REMOTE_DIR}"
MAX_HOURS="${MAX_HOURS:-24}"
SCRIPT_SRC="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARTER_NAME="start_monitor_on_host.sh"
STARTER_LOCAL="${SCRIPT_DIR}/${STARTER_NAME}"

if [ -z "${SCRIPT_SRC}" ]; then
  SCRIPT_SRC="${SCRIPT_DIR}/monitor_conntrack_rates.py"
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

# shellcheck disable=SC2046
HOSTS=$(hostips)
if [ -z "${HOSTS}" ]; then
  echo "[-] hostips returned no hosts." >&2
  exit 1
fi

echo "[+] Target hosts: ${HOSTS}"
echo "[+] Local script: ${SCRIPT_SRC}"
echo "[+] Remote dir  : ${REMOTE_PATH}"
echo "[+] Python      : python3 (from AHV PATH)"
echo "[+] Max hours   : ${MAX_HOURS}"

# Generate per-deploy starter with baked REMOTE_PATH / script name / MAX_HOURS.
# Keep hostssh to short commands; complex start logic lives in this file.
cat > "${STARTER_LOCAL}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

REMOTE_PATH="${REMOTE_PATH}"
SCRIPT_BASENAME="${SCRIPT_BASENAME}"
MAX_HOURS="${MAX_HOURS}"
SCRIPT_PATH="\${REMOTE_PATH}/\${SCRIPT_BASENAME}"

chmod 755 "\${REMOTE_PATH}" "\${SCRIPT_PATH}" "\${REMOTE_PATH}/${STARTER_NAME}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing python3 on \$(hostname)" >&2
  exit 1
fi
echo "using_python=\$(command -v python3) host=\$(hostname)"

pkill -f "\${SCRIPT_PATH}" 2>/dev/null || true
sleep 1

cd "\${REMOTE_PATH}"
setsid nohup python3 "./\${SCRIPT_BASENAME}" \\
  --output-dir "\${REMOTE_PATH}" \\
  --max-hours "\${MAX_HOURS}" \\
  </dev/null >"\${REMOTE_PATH}/monitor.out" 2>&1 &
echo \$! > "\${REMOTE_PATH}/monitor.pid"
sleep 1

if kill -0 "\$(cat "\${REMOTE_PATH}/monitor.pid")" 2>/dev/null; then
  echo "OK background pid=\$(cat "\${REMOTE_PATH}/monitor.pid") host=\$(hostname)"
else
  echo "FAIL not running host=\$(hostname)" >&2
  tail -20 "\${REMOTE_PATH}/monitor.out" || true
  exit 1
fi

ls -la "\${REMOTE_PATH}"
EOF
chmod 755 "${STARTER_LOCAL}"
echo "[+] Wrote starter: ${STARTER_LOCAL}"

# 1) Create folder on all AHVs (short hostssh)
echo "[+] mkdir on all hosts..."
hostssh "mkdir -p ${REMOTE_PATH}"

# 2) Permissions on the directory (short hostssh)
echo "[+] chmod dir on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}"

# 3) scp monitor + starter to each host IP
echo "[+] scp ${SCRIPT_BASENAME} + ${STARTER_NAME} to each host..."
for hip in ${HOSTS}; do
  echo "    -> root@${hip}:${REMOTE_PATH}/"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SCRIPT_SRC}" "${STARTER_LOCAL}" \
    "root@${hip}:${REMOTE_PATH}/"
done

# 4) Make both scripts executable (short hostssh)
echo "[+] chmod scripts on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH}/${SCRIPT_BASENAME} ${REMOTE_PATH}/${STARTER_NAME}"

# 5) Start monitor via the scp'd starter (short hostssh)
echo "[+] start monitor via ${STARTER_NAME} on all hosts..."
hostssh "bash ${REMOTE_PATH}/${STARTER_NAME}"

echo "[+] Done. Monitors are running in background on all hosts."
echo "    CSV : ${REMOTE_PATH}/conntrack_rates_<host_ip>.csv"
echo "    Log : ${REMOTE_PATH}/monitor.out"
echo "    PID : ${REMOTE_PATH}/monitor.pid"
echo "Check: hostssh 'cat ${REMOTE_PATH}/monitor.pid; pgrep -af monitor_conntrack_rates || true'"
echo "Stop:  hostssh 'kill \$(cat ${REMOTE_PATH}/monitor.pid) 2>/dev/null || pkill -f ${REMOTE_PATH}/${SCRIPT_BASENAME}'"
