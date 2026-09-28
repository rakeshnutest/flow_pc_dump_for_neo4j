#!/usr/bin/env bash
# ==============================================================================
# Deploy and start monitor_conntrack_rates.py on every AHV host (from a CVM).
#
# Run on a CVM (needs hostips / hostssh / passwordless root SSH to AHVs):
#   bash deploy_conntrack_monitor_all_hosts.sh
#   bash deploy_conntrack_monitor_all_hosts.sh /path/to/monitor_conntrack_rates.py
#
# Creates ~/number_of_cps (/root/number_of_cps) on each host, copies the script,
# then starts it detached in the background (setsid+nohup) with --output-dir so
# CSV lands in that folder and keeps running after hostssh returns.
#
# Env overrides:
#   REMOTE_DIR=number_of_cps
#   PYTHON_BIN=          # empty (default) = auto-detect on each AHV
#   PYTHON_BIN=/usr/bin/python3   # force a specific interpreter
#   MAX_HOURS=24
# ==============================================================================

set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:-number_of_cps}"
# AHV sessions via hostssh/scp are root → ~ is /root
REMOTE_PATH="/root/${REMOTE_DIR}"
PYTHON_BIN="${PYTHON_BIN:-}"
MAX_HOURS="${MAX_HOURS:-24}"
SCRIPT_SRC="${1:-}"

if [ -z "${SCRIPT_SRC}" ]; then
  SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/monitor_conntrack_rates.py"
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
if [ -n "${PYTHON_BIN}" ]; then
  echo "[+] Python      : ${PYTHON_BIN} (override)"
else
  echo "[+] Python      : auto (resolve on each AHV; override with PYTHON_BIN=/usr/bin/python3)"
fi
echo "[+] Max hours   : ${MAX_HOURS}"

# 1) Create folder + permissions on all AHVs
echo "[+] mkdir + chmod on all hosts..."
hostssh "mkdir -p ${REMOTE_PATH} && chmod 755 ${REMOTE_PATH} && ls -ld ${REMOTE_PATH}"

# 2) scp the script to each host IP
echo "[+] scp ${SCRIPT_BASENAME} to each host..."
for hip in ${HOSTS}; do
  echo "    -> root@${hip}:${REMOTE_PATH}/"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "${SCRIPT_SRC}" "root@${hip}:${REMOTE_PATH}/${SCRIPT_BASENAME}"
done

# 3) Make executable and start monitor fully detached (survives hostssh exit).
#    On each host, resolve PY: PYTHON_BIN (if set) → /.venv/bin/python3 →
#    /.venv/bin/bin/python3 → /usr/bin/python3 → /bin/python3 → PATH python3.
echo "[+] start monitor in background on all hosts..."
hostssh "chmod 755 ${REMOTE_PATH} ${REMOTE_PATH}/${SCRIPT_BASENAME}; \
  PY=''; \
  if [ -n '${PYTHON_BIN}' ] && [ -x '${PYTHON_BIN}' ]; then \
    PY='${PYTHON_BIN}'; \
  elif [ -x /.venv/bin/python3 ]; then \
    PY=/.venv/bin/python3; \
  elif [ -x /.venv/bin/bin/python3 ]; then \
    PY=/.venv/bin/bin/python3; \
  elif [ -x /usr/bin/python3 ]; then \
    PY=/usr/bin/python3; \
  elif [ -x /bin/python3 ]; then \
    PY=/bin/python3; \
  elif command -v python3 >/dev/null 2>&1 && [ -x \"\$(command -v python3)\" ]; then \
    PY=\$(command -v python3); \
  else \
    echo missing python3 on \$(hostname); exit 1; \
  fi; \
  echo using_python=\$PY host=\$(hostname); \
  pkill -f '${REMOTE_PATH}/${SCRIPT_BASENAME}' 2>/dev/null || true; \
  sleep 1; \
  cd ${REMOTE_PATH} && \
  setsid nohup \"\$PY\" ./${SCRIPT_BASENAME} \
    --output-dir ${REMOTE_PATH} \
    --max-hours ${MAX_HOURS} \
    </dev/null >${REMOTE_PATH}/monitor.out 2>&1 & \
  echo \$! > ${REMOTE_PATH}/monitor.pid; \
  sleep 1; \
  if kill -0 \$(cat ${REMOTE_PATH}/monitor.pid) 2>/dev/null; then \
    echo OK background pid=\$(cat ${REMOTE_PATH}/monitor.pid) host=\$(hostname); \
  else \
    echo FAIL not running host=\$(hostname); tail -20 ${REMOTE_PATH}/monitor.out; exit 1; \
  fi; \
  ls -la ${REMOTE_PATH}"

echo "[+] Done. Monitors are running in background on all hosts."
echo "    CSV : ${REMOTE_PATH}/conntrack_rates_<host_ip>.csv"
echo "    Log : ${REMOTE_PATH}/monitor.out"
echo "    PID : ${REMOTE_PATH}/monitor.pid"
echo "Check: hostssh 'cat ${REMOTE_PATH}/monitor.pid; pgrep -af monitor_conntrack_rates || true'"
echo "Stop:  hostssh 'kill \$(cat ${REMOTE_PATH}/monitor.pid) 2>/dev/null || pkill -f ${REMOTE_PATH}/${SCRIPT_BASENAME}'"
