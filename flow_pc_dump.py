#!/usr/bin/env python3
#
# Copyright (c) 2026 Nutanix Inc. All rights reserved.
#
# PC collect only. Copy this file to the PC. System python3. No Flow venv.
#   python3 flow_pc_dump.py
#   python3 flow_pc_dump.py --leader_only --output_dir /home/nutanix/upgrade/flow_pc_dump
#
# Write command stdout and AHV/OVS tarball members as-is. No flatten, no
# unwrap, no proto-to-v4. Convert locally:
#   python3 flow_pc_process.py --dump_dir ...
#
# Collects: idfcli, atlas_cli, flow_cli/kratos policy.list+get,
# v4 ServiceGroupGet (not v3 intentgw), AHV Gateway OVS, CMSP/SMSP OVN,
# vlan/global unique UUIDs. Never SSH to AHV. Never kubectl -it.
# SMSP OVN/kratos/atlas ZK: mspctl cluster kubeconfig flow.

import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from urllib.request import Request, urlopen

LOG = logging.getLogger("flow_pc_dump")
DUMP_SOURCE = "flow_pc_dump"
DUMP_MARKER = ".flow_pc_dump"
DEFAULT_OUTPUT_BASE = "/home/nutanix/upgrade/flow_pc_dump"
FLOW_LEADER_ZK_ROOTS = (
    "/appliance/logical/leaders",
    "/appliance/logical/pyleaders",
    "/appliance/logical/goleaders",
)
# IPv4 Handle: a.b.c.d:port or IPv6 Handle: [addr]:port
JAVA_LEADER_RE = re.compile(
    r"Handle:\s*"
    r"(?:"
    r"\[([0-9a-fA-F:.%]+)\]:\d+"
    r"|"
    r"(\d{1,3}(?:\.\d{1,3}){3}):\d+"
    r")"
    r".*Currently leader \(Y/N\):\s*Yes",
    re.I | re.DOTALL)
AHV_PORT = 7030
AHV_CERT_DIRS = (
    "/home/certs/ClusterHealthService",
    "/home/certs/PanaceaService",
    "/home/certs/GenesisService",
)
IDF_TYPES = (
    "vm", "mh_vm", "ahv_vm", "virtual_nic",
    "virtual_network", "subnet", "vpc", "virtual_private_cloud",
    "node", "host", "ahv_host", "cluster",
    "project", "projects", "iam_project", "xi_project", "abac_project",
    "abac_category", "category",
    "abac_entity_capability", "volume_group_entity_capability",
    "atlas_network_function", "network_function", "flow_network_function",
    "fns_fqdn_to_ip_info",
    "address_group", "network_address_group",
    "service_group", "network_service_group",
    "entity_group", "network_entity_group",
    "network_security_policy", "security_policy",
)
VLAN_ZK = "/appliance/logical/flow/vlan_unique_uuid"
GLOBAL_ZK = "/appliance/logical/flow/global_unique_uuid"
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Kept for callers/tests; prefer _is_valid_ip / _normalize_ip for dual-stack.
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _parse_ip(text):
  text = (text or "").strip().strip("[]")
  if not text:
    return None
  try:
    return ipaddress.ip_address(text)
  except ValueError:
    return None


def _normalize_ip(text):
  """Canonical IP string; IPv4-mapped IPv6 becomes dotted IPv4."""
  obj = _parse_ip(text)
  if obj is None:
    return ""
  if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped is not None:
    return str(obj.ipv4_mapped)
  return str(obj)


def _is_valid_ip(text):
  return bool(_normalize_ip(text))


def _is_usable_ip(text):
  """Valid cluster/management IP (skip link-local / loopback / unspecified)."""
  obj = _parse_ip(text)
  if obj is None:
    return False
  if obj.is_unspecified or obj.is_loopback or obj.is_link_local:
    return False
  return True


def _ip_for_url(host):
  """Host for https://... — bracket IPv6 literals."""
  obj = _parse_ip(host)
  if obj is None:
    return (host or "").strip()
  if isinstance(obj, ipaddress.IPv6Address):
    return "[%s]" % obj.compressed
  return str(obj)


def _ip_for_path(host):
  """Filesystem-safe host segment (IPv6 colons -> underscores)."""
  nip = _normalize_ip(host) or (host or "").strip()
  return nip.replace(":", "_").replace("%", "_")


# ServiceGroupGet in the Flow venv (same RPC as v4 GET service-groups).
SG_PY = r"""
import json, os, sys, tempfile
try:
  import gflags
  gflags.FLAGS(sys.argv[:1], known_only=True)
except Exception:
  pass
from util.sl_bufs.net.rpc_pb2 import RpcRequestContext
from flow.flow_interface_pb2 import ServiceGroupGetArg
from flow.client.client import FlowClient
from util.misc.protobuf import pb2json, reformat_proto
ctx = RpcRequestContext()
ctx.should_authorize = False
ret = FlowClient().ServiceGroupGet(ServiceGroupGetArg(), request_context=ctx)
payload = pb2json(reformat_proto(ret), b64_bytes=False, convert_enum_to_str=True)
if not isinstance(payload, dict) or not isinstance(payload.get("service_group_list"), list):
  sys.stderr.write("ServiceGroupGet missing service_group_list\n")
  sys.exit(2)
text = json.dumps(payload, separators=(",", ":"))
out = os.environ.get("FLOW_SG_OUT") or ""
if not out:
  sys.stdout.write(text)
  raise SystemExit(0)
dirname = os.path.dirname(out) or "."
fd, tmp = tempfile.mkstemp(prefix=".sg.", suffix=".tmp", dir=dirname)
try:
  os.write(fd, text.encode("utf-8")); os.close(fd); fd = None
  os.rename(tmp, out)
except Exception:
  if fd is not None:
    os.close(fd)
  try:
    os.remove(tmp)
  except Exception:
    pass
  raise
"""
ATLAS_ZK_PY = (
    "from zeus.zookeeper_session import ZookeeperSession\n"
    "zk = ZookeeperSession()\n"
    "for key, path in (("
    "'vlan_unique_uuid', '%s'), ('global_unique_uuid', '%s')):\n"
    "  val = zk.get(path)\n"
    "  if isinstance(val, (bytes, bytearray)):\n"
    "    val = val.decode('utf-8', 'replace')\n"
    "  print('%%s=%%s' %% (key, val))\n" % (VLAN_ZK, GLOBAL_ZK))


def _setup_logging(log_file=None):
  fmt = logging.Formatter(
      "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
  root = logging.getLogger()
  root.setLevel(logging.INFO)
  for handler in list(root.handlers):
    root.removeHandler(handler)
  stream = logging.StreamHandler(sys.stdout)
  stream.setFormatter(fmt)
  root.addHandler(stream)
  if log_file:
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    root.addHandler(fh)


def _which(*paths):
  for path in paths:
    if path and os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return paths[-1] if paths else ""


def _run(argv, timeout, input_text=None, stdout_path=None):
  kw = {"check": False, "timeout": max(5, int(timeout)), "text": True}
  if input_text is None:
    kw["stdin"] = subprocess.DEVNULL
  else:
    kw["input"] = input_text
  try:
    if stdout_path:
      os.makedirs(os.path.dirname(stdout_path) or ".", exist_ok=True)
      with open(stdout_path, "w") as handle:
        kw["stdout"] = handle
        kw["stderr"] = subprocess.PIPE
        proc = subprocess.run(argv, **kw)
      return proc.returncode, "", proc.stderr or ""
    kw["capture_output"] = True
    proc = subprocess.run(argv, **kw)
  except subprocess.TimeoutExpired:
    return -1, "", "timed out after %ss" % timeout
  except Exception as err:
    return -1, "", str(err)
  return proc.returncode, proc.stdout or "", proc.stderr or ""


def _bash(cmd, timeout=30):
  rc, out, err = _run(
      ["bash", "-lc", "source /etc/profile >/dev/null 2>&1; %s" % cmd], timeout)
  return rc, out, err


def _json_loads(text):
  text = (text or "").strip()
  if not text:
    return None
  try:
    return json.loads(text)
  except Exception:
    pass
  for a, b in (("{", "}"), ("[", "]")):
    start, end = text.find(a), text.rfind(b)
    if start >= 0 and end > start:
      try:
        return json.loads(text[start:end + 1])
      except Exception:
        pass
  return None


def _write_json(path, value):
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  tmp = "%s.tmp.%s" % (path, os.getpid())
  with open(tmp, "w") as handle:
    json.dump(value, handle, separators=(",", ":"))
    handle.flush()
  os.replace(tmp, path)
  LOG.info("Wrote %s (%s bytes)", path, os.path.getsize(path))
  return path


def _write_text(path, text):
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  with open(path, "w") as handle:
    handle.write(text or "")
  LOG.info("Wrote %s (%s bytes)", path, os.path.getsize(path))
  return path


def default_output_dir():
  return "%s_%d" % (DEFAULT_OUTPUT_BASE, int(time.time()))


def _zk_tool(name):
  for path in (
      "/home/nutanix/cluster/bin/%s" % name,
      "/usr/local/nutanix/cluster/bin/%s" % name,
      name):
    if path and os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return ""


def _zkls(path):
  tool = _zk_tool("zkls")
  if not tool:
    return []
  rc, out, _err = _run([tool, path], 30)
  if rc != 0:
    return []
  return [item for item in (out or "").split() if item]


def _zkcat(path):
  tool = _zk_tool("zkcat")
  if not tool:
    return ""
  rc, out, _err = _run([tool, path], 20)
  if rc != 0:
    return ""
  return (out or "").strip()


def _is_flow_leader_service(name):
  name = (name or "").strip()
  if not name:
    return False
  lower = name.lower()
  if lower == "flow" or lower.startswith("flow") or lower == "flow_master":
    return True
  if "microseg" in lower or "microsegmentation" in lower:
    return True
  return False


def _zk_root_kind(root):
  if root.endswith("/goleaders"):
    return "goleader"
  if root.endswith("/pyleaders"):
    return "pyleader"
  return "leader"


def _sort_zk_children(root, children):
  if not children:
    return children
  if root.endswith("/goleaders"):
    pairs = [child.rsplit("-", 1) for child in children]
    pairs = sorted(pairs, key=lambda item: item[-1])
    return ["-".join(tokens) for tokens in pairs]
  return sorted(children)


def _ip_from_leader_zk(kind, text):
  text = (text or "").strip()
  if not text:
    return ""
  if kind == "leader":
    match = JAVA_LEADER_RE.search(text)
    if not match:
      return ""
    raw = match.group(1) or match.group(2) or ""
    return _normalize_ip(raw)
  if kind == "pyleader":
    return _normalize_ip(text) if _is_usable_ip(text) else ""
  if kind == "goleader":
    parsed = _json_loads(text)
    if not isinstance(parsed, dict):
      return ""
    for flag in ("is_leader", "leader", "isLeader"):
      val = parsed.get(flag)
      if val in (True, "true", "True", 1, "1", "yes", "Yes"):
        ip = str(parsed.get("ip") or "").strip()
        if _is_usable_ip(ip):
          return _normalize_ip(ip)
    return ""
  return ""


def _cluster_svm_ips():
  tool = _zk_tool("svmips")
  if not tool:
    return []
  rc, out, _err = _run([tool], 20)
  if rc != 0:
    return []
  ips, seen = [], set()
  for token in (out or "").strip().split():
    if not _is_usable_ip(token):
      continue
    nip = _normalize_ip(token)
    if nip and nip not in seen:
      seen.add(nip)
      ips.append(nip)
  return ips


def _local_interface_ips():
  ips, seen = [], set()

  def _add(raw):
    if not _is_usable_ip(raw):
      return
    nip = _normalize_ip(raw)
    if nip and nip not in seen:
      seen.add(nip)
      ips.append(nip)

  rc, out, _err = _run(
      ["ip", "-4", "-o", "addr", "show", "dev", "eth0"], 10)
  if rc == 0:
    for line in (out or "").splitlines():
      match = re.search(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/", line)
      if match:
        _add(match.group(1))
  rc, out, _err = _run(
      ["ip", "-6", "-o", "addr", "show", "dev", "eth0"], 10)
  if rc == 0:
    for line in (out or "").splitlines():
      match = re.search(r"\binet6 ([0-9a-fA-F:]+)/", line)
      if match:
        _add(match.group(1))
  rc, out, _err = _run(["hostname", "-I"], 10)
  if rc == 0:
    for token in (out or "").strip().split():
      _add(token)
  return ips


def _ip_from_hostname():
  host = (socket.gethostname() or "").lower()
  match = re.search(r"(\d+-\d+-\d+-\d+)", host)
  if not match:
    return ""
  ip = match.group(1).replace("-", ".")
  return _normalize_ip(ip) if _is_usable_ip(ip) else ""


def _collect_flow_leader_ips():
  ips, seen = [], set()
  matched_services = []
  for root in FLOW_LEADER_ZK_ROOTS:
    kind = _zk_root_kind(root)
    for service in _zkls(root):
      if not _is_flow_leader_service(service):
        continue
      matched_services.append("%s/%s" % (root, service))
      service_path = "%s/%s" % (root, service)
      children = _sort_zk_children(root, _zkls(service_path))
      ip = ""
      if not children:
        ip = _ip_from_leader_zk(kind, _zkcat(service_path))
      else:
        for child in children:
          ip = _ip_from_leader_zk(
              kind, _zkcat("%s/%s" % (service_path, child)))
          if ip:
            break
      if ip and ip not in seen:
        seen.add(ip)
        ips.append(ip)
  if not ips and matched_services:
    LOG.warning(
        "DUMP leader_only: flow services in ZK but no leader IP parsed: %s",
        ",".join(matched_services))
  return ips


def _local_svm_ips():
  """Local PCVM management IPs that belong to this SVM (IPv4 and/or IPv6)."""
  cluster_ips = _cluster_svm_ips()
  cluster_set = set(cluster_ips)
  found, seen = [], set()

  def _add(ip):
    nip = _normalize_ip(ip)
    if not nip or nip in seen:
      return
    if cluster_set and nip not in cluster_set:
      return
    seen.add(nip)
    found.append(nip)

  hostname_ip = _ip_from_hostname()
  if hostname_ip and (not cluster_set or hostname_ip in cluster_set):
    _add(hostname_ip)
  for ip in _local_interface_ips():
    _add(ip)
  return found


def _local_svm_ip():
  ips = _local_svm_ips()
  return ips[0] if ips else ""


def flow_dump_leader_status():
  local_ips = _local_svm_ips()
  if not local_ips:
    return "error", "could not determine local SVM IP"
  leader_ips = _collect_flow_leader_ips()
  if not leader_ips:
    return "error", "could not determine flow leader from Zookeeper"
  if set(local_ips) & set(leader_ips):
    return "run", ""
  return "skip", "not leader (flow leaders=%s local=%s)" % (
      ",".join(leader_ips), ",".join(local_ips))


def is_recognized_dump_dir(path):
  marker_path = os.path.join(path, DUMP_MARKER)
  if os.path.isfile(marker_path):
    try:
      with open(marker_path) as handle:
        data = json.load(handle)
      if isinstance(data, dict) and data.get("source") == DUMP_SOURCE:
        return True
    except Exception:
      pass
  all_path = os.path.join(path, "all.json")
  if os.path.isfile(all_path):
    try:
      with open(all_path) as handle:
        data = json.load(handle)
      if isinstance(data, dict) and data.get("source") == DUMP_SOURCE:
        return True
    except Exception:
      pass
  return False


def prepare_output_dir(path):
  if not path or path in (".", "/", ""):
    raise ValueError("unsafe output_dir: %s" % path)
  if not os.path.exists(path):
    os.makedirs(path, exist_ok=True)
    return
  if not os.path.isdir(path):
    raise RuntimeError("output_dir exists but is not a directory: %s" % path)
  try:
    entries = os.listdir(path)
  except OSError as err:
    raise RuntimeError("cannot read output_dir %s: %s" % (path, err))
  if not entries:
    return
  if is_recognized_dump_dir(path):
    shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)
    LOG.info("Removed prior flow_pc_dump output at %s", path)
    return
  raise RuntimeError(
      "output_dir %s exists and does not look like a flow_pc_dump output; "
      "refusing to delete" % path)


def write_leader_skip_output(path, reason):
  """Wipe a prior dump (if recognized) and leave a skip stub for Logbay collect.

  Non-leaders exit before prepare_output_dir; without this, Logbay's file item
  would archive a stale dump from an earlier run on that PCVM.
  """
  if not path or path in (".", "/", ""):
    raise ValueError("unsafe output_dir: %s" % path)
  if os.path.exists(path):
    if not os.path.isdir(path):
      raise RuntimeError("output_dir exists but is not a directory: %s" % path)
    try:
      entries = os.listdir(path)
    except OSError as err:
      raise RuntimeError("cannot read output_dir %s: %s" % (path, err))
    if entries and not is_recognized_dump_dir(path):
      raise RuntimeError(
          "output_dir %s exists and does not look like a flow_pc_dump output; "
          "refusing to delete" % path)
    if entries:
      shutil.rmtree(path)
      LOG.info(
          "Removed prior flow_pc_dump output at %s (leader_only skip)", path)
  os.makedirs(path, exist_ok=True)
  payload = {
      "source": DUMP_SOURCE,
      "skipped": True,
      "skip_reason": reason or "not leader",
      "dumped_at": datetime.utcnow().isoformat() + "Z",
  }
  _write_json(os.path.join(path, "all.json"), payload)
  _write_json(os.path.join(path, "dump_errors.json"), {})
  write_dump_marker(path)


def write_dump_marker(output_dir):
  _write_json(os.path.join(output_dir, DUMP_MARKER), {
      "source": DUMP_SOURCE,
      "schema": 1,
      "created_at": datetime.utcnow().isoformat() + "Z",
  })


def _list_rows(parsed):
  if isinstance(parsed, list):
    return parsed
  if not isinstance(parsed, dict):
    return []
  data = parsed.get("data")
  if isinstance(data, list):
    return data
  if isinstance(data, dict):
    rows = []
    for key, value in data.items():
      row = dict(value) if isinstance(value, dict) else {"value": value}
      row.setdefault("uuid", key)
      rows.append(row)
    return rows
  for key in ("entities", "items", "value", "results"):
    if isinstance(parsed.get(key), list):
      return parsed[key]
  return []


def _item_uuid(item):
  if isinstance(item, str):
    return item if UUID_RE.search(item) else ""
  if not isinstance(item, dict):
    return ""
  for key in ("uuid", "ext_id", "extId", "UUID", "id"):
    val = str(item.get(key) or "")
    if UUID_RE.search(val):
      return UUID_RE.search(val).group(0)
  return ""


def _uuids_from_rows(rows):
  out, seen = [], set()
  for item in rows or []:
    uid = _item_uuid(item)
    if uid and uid not in seen:
      seen.add(uid)
      out.append(uid)
  return out


# --- idfcli ---

def dump_idfcli(output_dir, workers, timeout):
  dest = os.path.join(output_dir, "idfcli")
  os.makedirs(dest, exist_ok=True)
  binary = _which(
      "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
      "/home/nutanix/bin/idfcli",
      "/usr/local/nutanix/bin/idfcli",
      "idfcli")
  index = {"format": "idfcli_raw_json", "entity_types": {}}
  errors = {}

  def _one(entity_type):
    path = os.path.join(dest, "%s.json" % entity_type)
    err, stdout = "", b""
    for argv in (
        [binary, "get", "entity", "-e", entity_type, "--all", "-o", "json"],
        [binary, "get", "entitytype", "-e", entity_type, "-o", "json"]):
      try:
        proc = subprocess.run(
            argv, capture_output=True, check=False, timeout=timeout)
      except Exception as exc:
        err = "%s: %s" % (entity_type, exc)
        continue
      stdout = proc.stdout or b""
      if proc.returncode == 0 and stdout.strip():
        err = ""
        break
      err = "%s: rc=%s %s" % (
          entity_type, proc.returncode,
          (proc.stderr or b"").decode("utf-8", "replace")[:200])
    with open(path, "wb") as handle:
      handle.write(stdout)
    LOG.info("DUMP idfcli %s bytes=%s", entity_type, len(stdout))
    return entity_type, len(stdout), err

  with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
    for fut in [pool.submit(_one, t) for t in IDF_TYPES]:
      entity_type, nbytes, err = fut.result()
      index["entity_types"][entity_type] = {
          "bytes": nbytes, "error": err or "", "file": "%s.json" % entity_type}
      if err:
        errors["idfcli:%s" % entity_type] = err
  _write_json(os.path.join(dest, "index.json"), index)
  return index, errors


# --- platform / kubectl ---

def detect_platform():
  info = {"platform": "cmsp", "smsp_cluster_uuid": ""}
  _rc, out, err = _bash("mspctl cluster get flow --verbose", 45)
  parsed = _json_loads(out)
  uid = ""
  if isinstance(parsed, dict):
    uid = str(
        parsed.get("ClusterUUID") or parsed.get("cluster_uuid") or
        parsed.get("uuid") or "")
  if not uid:
    match = re.search(
        r"ClusterUUID['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F-]{36})",
        "%s\n%s" % (out, err), re.I)
    uid = match.group(1) if match else ""
  if uid:
    info["platform"] = "smsp"
    info["smsp_cluster_uuid"] = uid
    LOG.info("Detected SMSP uuid=%s", uid)
  else:
    LOG.info("Detected CMSP")
  return info


def _kubectl_bin():
  return _which(
      "/usr/bin/kubectl", "/usr/local/bin/kubectl",
      "/home/nutanix/bin/kubectl", "kubectl")


def _kubectl_prefix(kubeconfig=""):
  kubectl = _kubectl_bin()
  for prefix in (["sudo", "-n", kubectl], [kubectl]):
    rc, _out, _err = _run(prefix + ["get", "ns"], 20)
    if rc == 0:
      break
  else:
    prefix = ["sudo", "-n", kubectl]
  if kubeconfig:
    prefix = list(prefix) + ["--kubeconfig", kubeconfig]
  return list(prefix)


def _kubectl(extra, timeout, kubeconfig="", input_text=None, stdout_path=None):
  return _run(
      _kubectl_prefix(kubeconfig) + list(extra), timeout,
      input_text=input_text, stdout_path=stdout_path)


def _flow_kubeconfig(dest_dir):
  _rc, out, err = _bash("mspctl cluster kubeconfig flow", 45)
  text = out or ""
  yaml_text = ""
  for marker in ("apiVersion:", "kind: Config", "clusters:"):
    idx = text.find(marker)
    if idx >= 0:
      yaml_text = text[idx:].strip() + "\n"
      break
  if not yaml_text:
    return "", (err or out or "mspctl cluster kubeconfig flow failed")[:400]
  os.makedirs(dest_dir, exist_ok=True)
  path = os.path.join(dest_dir, ".flow.kubeconfig")
  with open(path, "w") as handle:
    handle.write(yaml_text)
  try:
    os.chmod(path, 0o600)
  except Exception:
    pass
  return path, ""


def _find_pod(app, preferred, namespace="", kubeconfig=""):
  ns_flag = ["-n", namespace] if namespace else ["-A"]
  rc, stdout, stderr = _kubectl(
      ["get", "pods"] + ns_flag + [
          "-o",
          "jsonpath={range .items[*]}{.metadata.namespace}{\"\\t\"}"
          "{.metadata.name}{\"\\t\"}{.status.phase}{\"\\t\"}"
          "{.metadata.labels.app}{\"\\n\"}{end}"],
      45, kubeconfig=kubeconfig)
  if rc != 0:
    return "", "", (stderr or stdout or "kubectl get pods failed")[:400]
  matches = []
  for line in (stdout or "").splitlines():
    parts = line.split("\t")
    if len(parts) < 3 or parts[2].strip() != "Running":
      continue
    ns, name = parts[0].strip(), parts[1].strip()
    label = parts[3].strip() if len(parts) > 3 else ""
    if name == preferred or label == app or name.startswith(app + "-"):
      matches.append((ns, name))
  if not matches:
    return "", "", "no Running pod %s" % preferred
  for ns, name in matches:
    if name == preferred:
      return ns, name, ""
  for ns, name in matches:
    if name.endswith("-0"):
      return ns, name, ""
  return matches[0][0], matches[0][1], ""


# --- atlas ---

def _atlas_argv(info):
  argv = [_which(
      "/usr/local/nutanix/bin/atlas_cli",
      "/home/nutanix/bin/atlas_cli",
      "/home/nutanix/atlas/bin/atlas_cli",
      "atlas_cli"), "-o", "json"]
  if info.get("platform") == "smsp" and info.get("smsp_cluster_uuid"):
    argv[1:1] = [
        "-u",
        "ws://smsp-%s.ntnx-ikat.svc:2060/atlas_cli" % info["smsp_cluster_uuid"]]
  return argv


def _atlas_cli(info, args, timeout, log_cmd=True):
  cmd = _atlas_argv(info) + list(args)
  if log_cmd:
    LOG.info("DUMP atlas_cli: %s", " ".join(cmd))
  rc, out, err = _run(cmd, timeout)
  parsed = _json_loads(out)
  if parsed is None:
    raise RuntimeError(
        "atlas_cli %s rc=%s: %s" % (" ".join(args), rc, (err or out)[:400]))
  return parsed, out


def dump_atlas(output_dir, workers, timeout, info):
  errors = {}
  list_timeout = max(60, min(300, int(timeout)))
  try:
    parsed, stdout = _atlas_cli(info, ["port_set.list"], list_timeout)
    if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
      raise RuntimeError("port_set.list status=%s" % parsed.get("status"))
  except Exception as err:
    errors["port_set_list"] = str(err)
    LOG.error("DATASET port_set_list FAILED: %s", err)
    parsed, stdout = {}, ""
  _write_text(os.path.join(output_dir, "port_set_list.json"), stdout)
  uuids = _uuids_from_rows(_list_rows(parsed))
  gets = {}
  per = max(15, min(45, int(timeout)))

  def _one(uid):
    parsed_one, _text = _atlas_cli(
        info, ["port_set.get", uid], per, log_cmd=False)
    if isinstance(parsed_one, dict) and parsed_one.get("status") not in (
        None, 0, "0"):
      raise RuntimeError("status=%s" % parsed_one.get("status"))
    return parsed_one

  if uuids:
    failed = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(uuids)))) as pool:
      fmap = {pool.submit(_one, uid): uid for uid in uuids}
      done, pending = wait(fmap.keys(), timeout=timeout)
      for fut in done:
        uid = fmap[fut]
        try:
          gets[uid] = fut.result(timeout=1)
        except Exception as err:
          failed.append(uid)
          LOG.error("DUMP port_set.get %s FAILED: %s", uid, err)
      for fut in pending:
        failed.append(fmap[fut])
        fut.cancel()
    if failed:
      errors["port_set_get"] = "failed %s of %s" % (len(failed), len(uuids))
  _write_json(os.path.join(output_dir, "port_set_get.json"), gets)
  return {
      "ran": True, "platform": info.get("platform") or "",
      "list_count": len(uuids), "get_count": len(gets), "errors": errors}


# --- flow_cli / kratos + ServiceGroupGet ---

def _flow_cli_bin():
  return _which(
      "/home/nutanix/flow/bin/flow_cli",
      "/usr/local/nutanix/bin/flow_cli",
      "/home/nutanix/bin/flow_cli",
      "flow_cli")


def _cli_join(cli, args):
  return " ".join([cli, "-o", "json"] + [str(a) for a in args])


def _run_bash_cli(inner, timeout, log_cmd=True):
  if log_cmd:
    LOG.info("DUMP flow_cli: bash -lc %s", inner)
  rc, out, err = _run(["bash", "-lc", inner], timeout)
  parsed = _json_loads(out)
  if parsed is None:
    raise RuntimeError("flow_cli rc=%s: %s" % (rc, (err or out)[:400]))
  return parsed, out


def _run_kratos_cli(kubeconfig, ns, pod, inner, timeout, log_cmd=True):
  if log_cmd:
    LOG.info("DUMP kratos: kubectl exec %s/%s -- bash -lc %s", ns, pod, inner)
  rc, out, err = _kubectl(
      ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
      timeout, kubeconfig=kubeconfig)
  parsed = _json_loads(out)
  if parsed is None:
    raise RuntimeError("kratos rc=%s: %s" % (rc, (err or out)[:400]))
  return parsed, out


def _pod_bin(kubeconfig, ns, pod, inner):
  rc, out, _err = _kubectl(
      ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
      30, kubeconfig=kubeconfig)
  for line in (out or "").strip().splitlines():
    cand = line.strip()
    if cand:
      return cand
  return ""


def _flow_python():
  return _which(
      "/home/nutanix/.venvs/flow/bin/python3",
      "/home/nutanix/.venvs/bin/bin/python3") or ""


def dump_service_groups(output_dir, timeout, info, kubeconfig="", ns="", pod=""):
  errors = {}
  rec = {"ran": True, "rpc": "ServiceGroupGet", "transport": "", "errors": errors}
  timeout = max(60, min(1800, int(timeout or 1800)))
  payload = None
  last_err = None
  for attempt in range(1, 4):
    try:
      if info.get("platform") == "smsp":
        if not (kubeconfig and pod):
          raise RuntimeError("SMSP kratos pod missing for ServiceGroupGet")
        py = _pod_bin(
            kubeconfig, ns or "ntnx-flow", pod,
            "ls /home/nutanix/.venvs/flow/bin/python3 2>/dev/null || command -v python3")
        if not py:
          raise RuntimeError("no python3 in kratos pod")
        rec["transport"] = "kubectl_kratos"
        rc, out, err = _kubectl(
            ["exec", "-i", "-n", ns or "ntnx-flow", pod, "--", py, "-"],
            timeout, kubeconfig=kubeconfig, input_text=SG_PY.strip() + "\n")
        if rc != 0:
          raise RuntimeError("kratos ServiceGroupGet rc=%s: %s" % (
              rc, (err or out)[:400]))
        payload = _json_loads(out)
        if payload is None:
          raise RuntimeError("kratos ServiceGroupGet no JSON")
      else:
        py = _flow_python()
        if not py:
          raise RuntimeError("Flow venv python3 missing for ServiceGroupGet")
        rec["transport"] = "pc"
        script = os.path.join(output_dir, ".flow_sg_collect.py")
        raw = os.path.join(output_dir, ".flow_sg_get.raw.json")
        with open(script, "w") as handle:
          handle.write(SG_PY.strip() + "\n")
        env = dict(os.environ)
        env["FLOW_SG_OUT"] = raw
        try:
          proc = subprocess.run(
              [py, script], capture_output=True, text=True, check=False,
              timeout=timeout, stdin=subprocess.DEVNULL, env=env)
        finally:
          try:
            os.remove(script)
          except Exception:
            pass
        if proc.returncode != 0 or not os.path.isfile(raw):
          raise RuntimeError("ServiceGroupGet rc=%s: %s" % (
              proc.returncode, (proc.stderr or proc.stdout or "")[:400]))
        with open(raw) as handle:
          payload = json.load(handle)
        try:
          os.remove(raw)
        except Exception:
          pass
      last_err = None
      break
    except Exception as err:
      last_err = err
      LOG.warning("DUMP ServiceGroupGet attempt %s/3 failed: %s", attempt, err)
  if last_err is not None:
    errors["service_groups"] = str(last_err)
    payload = {}
  _write_json(os.path.join(output_dir, "service_group_get.json"), payload)
  _write_json(os.path.join(output_dir, "service_group_list.json"), payload)
  rows = payload.get("service_group_list") if isinstance(payload, dict) else []
  rec["get_count"] = len(rows) if isinstance(rows, list) else 0
  rec["list_count"] = rec["get_count"]
  return rec


def dump_flow(output_dir, workers, timeout, info):
  errors = {}
  rec = {
      "ran": True, "platform": info.get("platform") or "cmsp",
      "cli": "", "transport": "", "pod": "", "namespace": "",
      "list_count": 0, "get_count": 0, "errors": errors}
  list_timeout = max(60, min(300, int(timeout)))
  per = max(15, min(45, int(timeout)))
  runner = None
  kubeconfig = ""
  try:
    if rec["platform"] == "smsp":
      kubeconfig, kube_err = _flow_kubeconfig(
          os.path.join(output_dir, "policy_cli"))
      if kubeconfig:
        ns, pod, err = _find_pod(
            "kratos", "kratos-0", "ntnx-flow", kubeconfig)
        if not pod:
          ns, pod, err = _find_pod("kratos", "kratos-0", "", kubeconfig)
        rec["namespace"] = ns or "ntnx-flow"
        rec["pod"] = pod or ""
        cli = ""
        if pod:
          cli = _pod_bin(
              kubeconfig, ns, pod,
              "command -v kratos_cli || command -v flow_cli || "
              "ls /home/nutanix/flow/bin/kratos_cli "
              "/home/nutanix/flow/bin/flow_cli 2>/dev/null | head -1")
        if pod and cli:
          rec["cli"] = os.path.basename(cli)
          rec["transport"] = "kubectl_kratos"
          runner = lambda args, t, log_cmd=True, _cli=cli, _ns=ns, _pod=pod: (
              _run_kratos_cli(
                  kubeconfig, _ns, _pod, _cli_join(_cli, args), t,
                  log_cmd=log_cmd))
        else:
          LOG.warning("DUMP kratos missing (%s)", err or "no cli")
      else:
        LOG.warning("DUMP SMSP kubeconfig failed: %s", kube_err or "")
      if runner is None:
        smsp_uuid = info.get("smsp_cluster_uuid") or ""
        if not smsp_uuid:
          errors["policy_list"] = "SMSP kratos exec failed and no ClusterUUID"
        else:
          rec["cli"] = "flow_cli"
          rec["transport"] = "smsp_ws"
          ws = "ws://smsp-%s.ntnx-ikat.svc:2051/flow_cli" % smsp_uuid
          bin_path = _flow_cli_bin()
          runner = lambda args, t, log_cmd=True, _b=bin_path, _ws=ws: (
              _run_bash_cli(
                  "%s -u '%s' -o json %s" % (
                      _b, _ws, " ".join(str(a) for a in args)),
                  t, log_cmd=log_cmd))
    else:
      rec["cli"] = "flow_cli"
      rec["transport"] = "pc"
      bin_path = _flow_cli_bin()
      runner = lambda args, t, log_cmd=True, _b=bin_path: _run_bash_cli(
          _cli_join(_b, args), t, log_cmd=log_cmd)

    list_text, rows, gets = "", [], {}
    if runner is not None:
      try:
        parsed, list_text = runner(["policy.list"], list_timeout)
        if isinstance(parsed, dict) and parsed.get("status") not in (
            None, 0, "0"):
          raise RuntimeError("policy.list status=%s" % parsed.get("status"))
        rows = _list_rows(parsed)
      except Exception as err:
        errors["policy_list"] = str(err)
        LOG.error("DATASET policy.list FAILED: %s", err)
      uuids = _uuids_from_rows(rows)
      rec["list_count"] = len(uuids)
      get_workers = max(1, min(int(workers), len(uuids) or 1))
      if rec.get("transport") == "kubectl_kratos":
        get_workers = min(8, get_workers)

      def _one(uid):
        parsed_one, _text = runner(["policy.get", uid], per, log_cmd=False)
        if isinstance(parsed_one, dict) and parsed_one.get("status") not in (
            None, 0, "0"):
          raise RuntimeError("status=%s" % parsed_one.get("status"))
        return parsed_one

      if uuids:
        failed = []
        with ThreadPoolExecutor(max_workers=get_workers) as pool:
          fmap = {pool.submit(_one, uid): uid for uid in uuids}
          done, pending = wait(fmap.keys(), timeout=timeout)
          for fut in done:
            uid = fmap[fut]
            try:
              gets[uid] = fut.result(timeout=1)
            except Exception as err:
              failed.append(uid)
              LOG.error("DUMP policy.get %s FAILED: %s", uid, err)
          for fut in pending:
            failed.append(fmap[fut])
            fut.cancel()
        if failed:
          errors["policy_get"] = "failed %s of %s" % (len(failed), len(uuids))
      rec["get_count"] = len(gets)
    _write_text(os.path.join(output_dir, "policy_list.json"), list_text)
    _write_json(os.path.join(output_dir, "policy_get.json"), gets)
    sg = dump_service_groups(
        output_dir, timeout, info, kubeconfig,
        rec.get("namespace") or "", rec.get("pod") or "")
    rec["sg_count"] = sg.get("get_count") or 0
    rec["sg_transport"] = sg.get("transport") or ""
    errors.update(sg.get("errors") or {})
  finally:
    if kubeconfig:
      try:
        os.remove(kubeconfig)
      except Exception:
        pass
  return rec


# --- unique UUIDs ---

def _pc_zk_uuids():
  out = {"vlan_unique_uuid": "", "global_unique_uuid": ""}
  zkcat = ""
  for path in (
      "/home/nutanix/cluster/bin/zkcat",
      "/usr/local/nutanix/cluster/bin/zkcat"):
    if os.path.exists(path) and os.access(path, os.X_OK):
      zkcat = path
      break
  if not zkcat:
    return out
  for key, path in (
      ("vlan_unique_uuid", VLAN_ZK), ("global_unique_uuid", GLOBAL_ZK)):
    rc, stdout, _err = _run([zkcat, path], 20)
    match = UUID_RE.search((stdout or "").strip())
    if rc == 0 and match:
      out[key] = match.group(0)
  return out


def dump_unique_uuids(output_dir, info):
  pc = _pc_zk_uuids()
  rec = {
      "vlan_unique_uuid": pc.get("vlan_unique_uuid") or "",
      "global_unique_uuid": pc.get("global_unique_uuid") or "",
      "source": "pc_zkcat",
      "pc_zk_vlan_unique_uuid": pc.get("vlan_unique_uuid") or "",
      "pc_zk_global_unique_uuid": pc.get("global_unique_uuid") or "",
  }
  if info.get("platform") != "smsp":
    _write_json(os.path.join(output_dir, "unique_uuids.json"), rec)
    return rec
  kubeconfig, kube_err = _flow_kubeconfig(
      os.path.join(output_dir, "unique_uuids_smsp"))
  if not kubeconfig:
    rec["smsp_error"] = kube_err
    _write_json(os.path.join(output_dir, "unique_uuids.json"), rec)
    return rec
  try:
    ns, pod, err = _find_pod("atlas", "atlas-0", "ntnx-flow", kubeconfig)
    if not pod:
      ns, pod, err = _find_pod("atlas", "atlas-0", "", kubeconfig)
    if not pod:
      rec["smsp_error"] = err or "no atlas pod"
    else:
      py = "/home/nutanix/.venvs/bin/bin/python3"
      rc, stdout, stderr = _kubectl(
          ["exec", "-n", ns, pod, "--", py, "-c", ATLAS_ZK_PY],
          60, kubeconfig=kubeconfig)
      text = "%s\n%s" % (stdout, stderr)
      for key in ("vlan_unique_uuid", "global_unique_uuid"):
        for line in text.splitlines():
          if key in line:
            match = UUID_RE.search(line)
            if match:
              rec[key] = match.group(0)
      if rec["vlan_unique_uuid"] and rec["global_unique_uuid"]:
        rec["source"] = "smsp_atlas_zk"
      else:
        rec["smsp_error"] = (stderr or stdout or "atlas ZK parse failed")[:400]
  finally:
    try:
      os.remove(kubeconfig)
    except Exception:
      pass
  _write_json(os.path.join(output_dir, "unique_uuids.json"), rec)
  return rec


# --- AHV Gateway: all networking/avm/ovn members, no filter ---

def _ahv_certs():
  for directory in AHV_CERT_DIRS:
    name = os.path.basename(directory.rstrip("/"))
    crt = os.path.join(directory, name + ".crt")
    key = os.path.join(directory, name + ".key")
    if os.path.isfile(crt) and os.path.isfile(key):
      return crt, key, directory
  return "", "", ""


def _ahv_open(host, path, crt, key, timeout, accept="application/octet-stream"):
  ctx = ssl._create_unverified_context()
  ctx.load_cert_chain(crt, key)
  url = "https://%s:%s/api%s" % (
      _ip_for_url(host), AHV_PORT,
      path if path.startswith("/") else "/" + path)
  req = Request(url, headers={"Accept": accept, "Accept-Encoding": "identity"})
  return urlopen(req, context=ctx, timeout=timeout)


def _ahv_write_member(dest_dir, member_name, data):
  rel = "/".join(
      p for p in str(member_name or "").replace("\\", "/").split("/")
      if p and p not in (".", ".."))
  if not rel:
    return ""
  path = os.path.join(dest_dir, rel)
  os.makedirs(os.path.dirname(path) or dest_dir, exist_ok=True)
  with open(path, "wb") as handle:
    handle.write(data or b"")
  return path


def _hypervisor_ips():
  ncli = _which("/usr/local/nutanix/cluster/bin/ncli", "/usr/bin/ncli", "ncli")
  rc, out, err = _run([ncli, "host", "list"], 60)
  if rc != 0:
    _prc, out, err = _bash("ncli host list", 60)
  ips, seen = [], set()
  for match in re.finditer(
      r"Hypervisor(?: IP)?(?: Address)?\s*:\s*(\S+)",
      "%s\n%s" % (out, err), re.I):
    ip_addr = match.group(1).strip().strip("[],;\"'")
    if not _is_usable_ip(ip_addr):
      continue
    nip = _normalize_ip(ip_addr)
    if nip and nip not in seen:
      seen.add(nip)
      ips.append(nip)
  return ips


def _ahv_classes(host, crt, key, timeout):
  try:
    resp = _ahv_open(
        host, "/host/v1/bugtool-classes", crt, key, min(timeout, 30),
        accept="application/json")
    data = json.loads((resp.read() or b"").decode("utf-8", "replace") or "{}")
    resp.close()
  except Exception as err:
    LOG.debug("AHV GW class list %s failed: %s", host, err)
    return ["networking", "avm"]
  names = []
  for item in data.get("classes") or []:
    name = item.get("name") if isinstance(item, dict) else item
    if name:
      names.append(str(name))
  keep = [
      n for n in names
      if re.search(r"network|ovs|ovn|avm|virt", n, re.I)]
  return keep or ["networking", "avm"]


def _ahv_extract(host, cls, dest_dir, crt, key, timeout):
  saved = []
  resp = None
  try:
    resp = _ahv_open(host, "/host/v1/bugtool/%s" % cls, crt, key, timeout)
    tar = tarfile.open(fileobj=resp, mode="r|*")
    for member in tar:
      if not getattr(member, "isfile", lambda: False)():
        continue
      handle = tar.extractfile(member)
      data = handle.read() if handle is not None else b""
      path = _ahv_write_member(dest_dir, member.name, data)
      if path:
        saved.append(path)
  finally:
    if resp is not None:
      try:
        resp.close()
      except Exception:
        pass
  return saved


def _ahv_one(ip_addr, dest_root, crt, key, class_timeout, deadline=0):
  host_dir = os.path.join(dest_root, _ip_for_path(ip_addr))
  os.makedirs(host_dir, exist_ok=True)
  rec = {"ip": ip_addr, "classes": [], "files": 0, "error": ""}
  if deadline and time.time() >= deadline:
    rec["error"] = "AHV gateway overall timeout exceeded"
    return rec
  try:
    classes = _ahv_classes(ip_addr, crt, key, 30)
    rec["classes"] = classes
    n = 0
    errs = []
    for cls in classes:
      if deadline and time.time() >= deadline:
        errs.append("%s:overall timeout" % cls)
        break
      remaining = (deadline - time.time()) if deadline else class_timeout
      per_class = min(class_timeout, max(30, int(remaining)))
      try:
        saved = _ahv_extract(
            ip_addr, cls, host_dir, crt, key, per_class)
        n += len(saved)
      except Exception as err:
        errs.append("%s:%s" % (cls, err))
        LOG.warning("DUMP AHV GW %s class %s failed: %s", ip_addr, cls, err)
    rec["files"] = n
    rec["error"] = "; ".join(errs)[:2000]
  except Exception as err:
    rec["error"] = str(err)
  return rec


def dump_ahv(output_dir, workers, class_timeout, gw_timeout=1800):
  dest = os.path.join(output_dir, "ahv_gateway")
  os.makedirs(dest, exist_ok=True)
  deadline = time.time() + max(60, int(gw_timeout))
  payload = {
      "ran": False, "transport": "ahv_gateway_mtls", "ssh_to_ahv": False,
      "port": AHV_PORT, "hosts": [], "error": "", "gw_timeout_secs": gw_timeout}
  crt, key, cert_dir = _ahv_certs()
  payload["cert_dir"] = cert_dir
  if not crt:
    payload["error"] = "AHV Gateway client certs not found"
    _write_json(os.path.join(dest, "index.json"), payload)
    return payload
  ips = _hypervisor_ips()
  if not ips:
    payload["error"] = "no PE hypervisor IPs"
    _write_json(os.path.join(dest, "index.json"), payload)
    return payload
  payload["ran"] = True
  recs = []
  with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips)))) as pool:
    futs = [
        pool.submit(
            _ahv_one, ip_addr, dest, crt, key, class_timeout, deadline)
        for ip_addr in ips]
    wait_timeout = max(0, deadline - time.time())
    done, pending = wait(futs, timeout=wait_timeout)
    for fut in done:
      try:
        recs.append(fut.result(timeout=1))
      except Exception as err:
        recs.append({"ip": "", "error": str(err), "files": 0, "classes": []})
    for fut in pending:
      fut.cancel()
      recs.append({
          "ip": "", "error": "AHV gateway overall timeout exceeded",
          "files": 0, "classes": []})
  if pending and not payload.get("error"):
    payload["error"] = "AHV gateway overall timeout exceeded"
  payload["hosts"] = recs
  payload["hosts_total"] = len(recs)
  payload["hosts_ok"] = sum(1 for rec in recs if rec.get("files"))
  bad = [rec.get("ip") for rec in recs if rec.get("error") or not rec.get("files")]
  if bad:
    payload["error"] = "AHV hosts with errors: %s" % ",".join(bad[:12])
  _write_json(os.path.join(dest, "index.json"), payload)
  _write_json(os.path.join(output_dir, "ahv_gateway.json"), payload)
  return payload


# --- OVN kubectl dumps ---

OVN_TARGETS = (
    {
        "key": "anc-ovn", "app": "anc-ovn", "pod": "anc-ovn-0",
        "container": "anc-ovn",
        "dumps": (
            ("ovsdb-client_dump_nb",
             ["ovsdb-client", "dump", "unix:/var/run/ovn/ovnnb_db.sock"]),
            ("ovsdb-client_dump_sb",
             ["ovsdb-client", "dump", "unix:/var/run/ovn/ovnsb_db.sock"]),
        ),
        "files": (
            ("/etc/openvswitch/ovnnb_db.db", "ovnnb_db.db"),
            ("/etc/openvswitch/ovnsb_db.db", "ovnsb_db.db"),
        ),
        "commands": (
            ("ovn-nbctl_show",
             ["ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "show"]),
            ("ovn-nbctl_ls-list",
             ["ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "ls-list"]),
            ("ovn-nbctl_lr-list",
             ["ovn-nbctl", "--db=unix:/var/run/ovn/ovnnb_db.sock", "lr-list"]),
            ("ovn-sbctl_show",
             ["ovn-sbctl", "--db=unix:/var/run/ovn/ovnsb_db.sock", "show"]),
            ("ovn-sbctl_list_Chassis",
             ["ovn-sbctl", "--db=unix:/var/run/ovn/ovnsb_db.sock",
              "list", "Chassis"]),
        ),
        "required": ("ovsdb-client_dump_nb", "ovsdb-client_dump_sb"),
    },
    {
        "key": "anc-ovn-ic-db", "app": "anc-ovn-ic-db",
        "pod": "anc-ovn-ic-db-0", "container": "anc-ovn-ic-db",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovn_ic_nb_db.db", "ovn_ic_nb_db.db"),
            ("/etc/openvswitch/ovn_ic_sb_db.db", "ovn_ic_sb_db.db"),
        ),
        "commands": (
            ("ovn-ic-nbctl_show",
             ["ovn-ic-nbctl", "--db=unix:/var/run/ovn/ovn_ic_nb_db.sock",
              "show"]),
            ("ovn-ic-sbctl_show",
             ["ovn-ic-sbctl", "--db=unix:/var/run/ovn/ovn_ic_sb_db.sock",
              "show"]),
        ),
        "required": (),
    },
    {
        "key": "anc-policydb", "app": "anc-policydb",
        "pod": "anc-policydb-0", "container": "anc-policydb",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovs-policy-config.db", "ovs-policy-config.db"),
        ),
        "commands": (), "required": (),
    },
)
CMSP_OVN_SMART_RETRY_LIMIT = 1


def _ovn_required(rec):
  return bool(rec.get("required_target"))


def _ovn_results_complete(results):
  if not results:
    return False
  for rec in results:
    if not _ovn_required(rec):
      continue
    if rec.get("pod_not_found"):
      return False
    if rec.get("missing"):
      return False
    if rec.get("error") and not rec.get("pod"):
      return False
  return True


def _ovn_next_action(results, cmsp_ovn_wait, attempt,
                     retry_limit=CMSP_OVN_SMART_RETRY_LIMIT):
  if _ovn_results_complete(results):
    return "done"
  if cmsp_ovn_wait:
    return "retry"
  if any(rec.get("pod_not_found") for rec in results if _ovn_required(rec)):
    return "break"
  if attempt >= retry_limit:
    return "break"
  return "retry"


def _ovn_write_payload(output_dir, payload):
  dest = os.path.join(output_dir, "cmsp_ovn")
  _write_json(os.path.join(dest, "index.json"), payload)
  _write_json(os.path.join(output_dir, "cmsp_ovn.json"), payload)
  if payload.get("platform") == "smsp":
    _write_json(os.path.join(output_dir, "smsp_ovn.json"), payload)


def _ensure_dump_file_readable(path):
  """kubectl cp via sudo leaves root-owned mode 640 files; Logbay reads as nutanix."""
  if not path or not os.path.isfile(path):
    return
  try:
    os.chmod(path, 0o644)
    return
  except OSError:
    pass
  _run(["sudo", "-n", "chmod", "644", path], 10)


def _kubectl_cp(ns, pod, container, remote, dest, timeout, kubeconfig=""):
  os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
  extra = ["cp"]
  if ns:
    extra.extend(["-n", ns])
  extra.extend(["%s:%s" % (pod, remote), dest, "-c", container])
  rc, _out, err = _kubectl(extra, timeout, kubeconfig=kubeconfig)
  if rc == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0:
    _ensure_dump_file_readable(dest)
    return True
  rc, _out, err = _kubectl(
      ["cp", "%s/%s:%s" % (ns or "default", pod, remote), dest, "-c", container],
      timeout, kubeconfig=kubeconfig)
  if rc == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0:
    _ensure_dump_file_readable(dest)
    return True
  return False


def _kubectl_exec_file(ns, pod, container, remote_argv, dest, timeout,
                       kubeconfig=""):
  extra = ["exec"]
  if ns:
    extra.extend(["-n", ns])
  extra.extend([pod, "-c", container, "--"] + list(remote_argv))
  rc, _out, err = _kubectl(
      extra, timeout, kubeconfig=kubeconfig, stdout_path=dest)
  ok = rc == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0
  if ok:
    _ensure_dump_file_readable(dest)
  return ok


def _ovn_target(target, dest_root, namespace, timeout, kubeconfig=""):
  rec = {
      "key": target["key"], "pod": "", "namespace": namespace,
      "error": "", "missing": [],
      "required_target": bool(target.get("required"))}
  dest_dir = os.path.join(dest_root, target["key"])
  cmd_dir = os.path.join(dest_dir, "commands")
  os.makedirs(cmd_dir, exist_ok=True)
  ns, pod, err = _find_pod(
      target["app"], target.get("pod") or "", namespace, kubeconfig)
  rec["namespace"] = ns or namespace
  rec["pod"] = pod or (target.get("pod") or "")
  if not rec["pod"]:
    rec["pod_not_found"] = True
    rec["error"] = err or "pod not found"
    rec["missing"] = list(target.get("required") or [])
    return rec
  rec["pod_not_found"] = False
  dump_timeout = max(60, min(600, int(timeout)))
  got = {}
  for name, argv in target.get("dumps") or ():
    dest = os.path.join(cmd_dir, name + ".txt")
    ok = _kubectl_exec_file(
        rec["namespace"], rec["pod"], target["container"], argv, dest,
        dump_timeout, kubeconfig)
    got[name] = ok
  per = max(30, min(180, int(timeout)))
  for remote, local_name in target.get("files") or ():
    _kubectl_cp(
        rec["namespace"], rec["pod"], target["container"], remote,
        os.path.join(dest_dir, local_name), per, kubeconfig)
  for name, argv in target.get("commands") or ():
    _kubectl_exec_file(
        rec["namespace"], rec["pod"], target["container"], argv,
        os.path.join(cmd_dir, name + ".txt"), per, kubeconfig)
  rec["missing"] = [
      name for name in target.get("required") or () if not got.get(name)]
  if rec["missing"]:
    rec["error"] = "missing: %s" % ",".join(rec["missing"])
  return rec


def dump_ovn(output_dir, timeout, info, namespace="", cmsp_ovn_wait=False):
  dest = os.path.join(output_dir, "cmsp_ovn")
  os.makedirs(dest, exist_ok=True)
  platform = info.get("platform") or "cmsp"
  ovn_label = "smsp_ovn" if platform == "smsp" else "cmsp_ovn"
  payload = {
      "ran": False, "transport": "kubectl",
      "platform": platform,
      "ssh_to_ahv": False, "pods": [], "error": ""}
  kubeconfig = ""
  if platform == "smsp":
    kubeconfig, kube_err = _flow_kubeconfig(dest)
    if kubeconfig:
      payload["kubeconfig_source"] = "mspctl cluster kubeconfig flow"
    else:
      payload["kubeconfig_source"] = "failed: %s" % (kube_err or "")
      payload["ran"] = True
      payload["error"] = kube_err or "mspctl cluster kubeconfig flow failed"
      LOG.info(
          "DUMP %s fail-fast: flow kubeconfig failed: %s",
          ovn_label, payload["error"])
      _ovn_write_payload(output_dir, payload)
      return payload
  deadline = time.time() + max(60, int(timeout))
  backoff = 2
  last = []
  smart_attempt = 0
  try:
    while time.time() < deadline:
      last = [
          _ovn_target(t, dest, namespace, max(60, int(deadline - time.time())),
                      kubeconfig)
          for t in OVN_TARGETS]
      payload["ran"] = True
      payload["pods"] = last
      action = _ovn_next_action(last, cmsp_ovn_wait, smart_attempt)
      if action == "done":
        payload["error"] = ""
        break
      if action == "break":
        if not cmsp_ovn_wait and any(
            rec.get("pod_not_found") for rec in last if _ovn_required(rec)):
          LOG.info(
              "DUMP %s fail-fast: required OVN pod not found, skipping retries",
              ovn_label)
        elif not cmsp_ovn_wait:
          LOG.info(
              "DUMP %s fail-fast: retries exhausted after %s attempts",
              ovn_label, smart_attempt + 1)
        break
      smart_attempt += 1
      sleep_for = min(backoff, max(0, int(deadline - time.time())))
      if sleep_for <= 0:
        break
      time.sleep(sleep_for)
      backoff = min(20, backoff * 2)
    else:
      payload["pods"] = last
      payload["ran"] = True
    missing = []
    for rec in last:
      if not _ovn_required(rec):
        continue
      missing.extend(
          "%s:%s" % (rec.get("key"), n) for n in rec.get("missing") or [])
    if missing:
      payload["error"] = "missing: %s" % ",".join(missing)
  finally:
    if kubeconfig:
      try:
        os.remove(kubeconfig)
      except Exception:
        pass
  _ovn_write_payload(output_dir, payload)
  return payload


# --- orchestrate ---

def dump_pc(output_dir, workers=16, skip_idf=False, skip_ahv=False,
            skip_cmsp=False, skip_atlas=False, skip_flow_cli=False,
            ahv_gw_timeout=1800, cmsp_ovn_timeout=1800, atlas_timeout=1800,
            atlas_get_workers=32, flow_cli_timeout=1800,
            flow_cli_get_workers=32, idf_timeout=180, ahv_workers=8,
            ahv_class_timeout=300, cmsp_ovn_namespace="",
            cmsp_ovn_wait=False,
            fail_on_error=False, log_file="", combined_path=""):
  os.makedirs(output_dir, exist_ok=True)
  combined_path = combined_path or os.path.join(output_dir, "all.json")
  log_file = log_file or os.path.join(output_dir, "dump.log")
  _setup_logging(log_file)
  write_dump_marker(output_dir)
  info = detect_platform()
  errors = {}
  index = {
      "source": DUMP_SOURCE,
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "platform": info.get("platform") or "",
      "smsp_cluster_uuid": info.get("smsp_cluster_uuid") or "",
  }
  LOG.info("DUMP collect only platform=%s output=%s", index["platform"], output_dir)
  with ThreadPoolExecutor(max_workers=6) as pool:
    futs = {}
    if not skip_idf:
      futs["idfcli"] = pool.submit(
          dump_idfcli, output_dir, min(8, workers), idf_timeout)
    if not skip_ahv:
      futs["ahv_gateway"] = pool.submit(
          dump_ahv, output_dir, ahv_workers, ahv_class_timeout, ahv_gw_timeout)
    if not skip_cmsp:
      futs["cmsp_ovn"] = pool.submit(
          dump_ovn, output_dir, cmsp_ovn_timeout, info, cmsp_ovn_namespace,
          cmsp_ovn_wait)
    if not skip_atlas:
      futs["atlas"] = pool.submit(
          dump_atlas, output_dir, atlas_get_workers, atlas_timeout, info)
    if not skip_flow_cli:
      futs["flow_cli"] = pool.submit(
          dump_flow, output_dir, flow_cli_get_workers, flow_cli_timeout, info)
    for name, fut in futs.items():
      try:
        index[name] = fut.result()
        if isinstance(index[name], tuple):
          index[name], extra = index[name]
          errors.update(extra or {})
        elif isinstance(index[name], dict):
          errors.update(index[name].get("errors") or {})
          if index[name].get("error"):
            errors[name] = index[name]["error"]
          if name == "cmsp_ovn" and index[name].get("platform") == "smsp":
            index["smsp_ovn"] = index[name]
      except Exception as err:
        errors[name] = str(err)
        index[name] = {"ran": False, "error": str(err)}
        LOG.error("DATASET %s FAILED: %s", name, err)
  uuids = dump_unique_uuids(output_dir, info)
  index["unique_uuid_source"] = uuids.get("source") or ""
  index["vlan_unique_uuid"] = uuids.get("vlan_unique_uuid") or ""
  index["global_unique_uuid"] = uuids.get("global_unique_uuid") or ""
  index["dump_errors"] = errors
  _write_json(os.path.join(output_dir, "dump_errors.json"), errors)
  _write_json(combined_path, index)
  LOG.info("DUMP done. Index: %s errors=%s", combined_path, errors or "<none>")
  LOG.info("Convert locally: python3 flow_pc_process.py --dump_dir %s", output_dir)
  if errors and fail_on_error:
    return 2
  return 0


def dump_collect(*args, **kwargs):
  return dump_pc(*args, **kwargs)


def build_parser():
  ap = argparse.ArgumentParser(
      prog="flow_pc_dump.py",
      description=(
          "PC collect only. Writes command stdout and AHV/OVS files as-is. "
          "Convert locally with flow_pc_process.py."))
  ap.add_argument("--output_dir", default="")
  ap.add_argument("--leader_only", action="store_true",
                  help="Run only on the Flow leader PCVM; non-leaders exit 0")
  ap.add_argument("--output", default="")
  ap.add_argument("--log_file", default="")
  ap.add_argument("--workers", type=int, default=16)
  ap.add_argument("--dataset_timeout_secs", type=int, default=180)
  ap.add_argument("--fail_on_error", action="store_true")
  ap.add_argument("--skip_idfcli", action="store_true")
  ap.add_argument("--skip_ahv_gateway", action="store_true")
  ap.add_argument("--skip_cmsp_ovn", action="store_true")
  ap.add_argument("--skip_atlas", action="store_true")
  ap.add_argument("--skip_flow_cli", action="store_true")
  ap.add_argument("--ahv_gateway_timeout_secs", type=int, default=1800)
  ap.add_argument("--ahv_gateway_class_timeout_secs", type=int, default=300)
  ap.add_argument("--ahv_gateway_workers", type=int, default=8)
  ap.add_argument("--ahv_gateway_port", type=int, default=7030)
  ap.add_argument(
      "--ahv_gateway_cert_dir", default="/home/certs/ClusterHealthService")
  ap.add_argument("--cmsp_ovn_timeout_secs", type=int, default=1800)
  ap.add_argument("--cmsp_ovn_namespace", default="")
  ap.add_argument(
      "--cmsp_ovn_wait", action="store_true",
      help="Retry cmsp_ovn collection until timeout (default: smart fail-fast)")
  ap.add_argument("--atlas_timeout_secs", type=int, default=1800)
  ap.add_argument("--atlas_get_workers", type=int, default=32)
  ap.add_argument("--flow_cli_timeout_secs", type=int, default=1800)
  ap.add_argument("--flow_cli_get_workers", type=int, default=32)
  return ap


def main(argv=None):
  argv = list(sys.argv if argv is None else argv)
  args = build_parser().parse_args(argv[1:])
  _setup_logging()
  if args.leader_only:
    status, reason = flow_dump_leader_status()
    if status == "skip":
      LOG.info("skipped: %s", reason)
      out = (args.output_dir or "").strip()
      if out:
        try:
          write_leader_skip_output(out, reason)
        except Exception as err:
          LOG.warning("leader_only skip cleanup failed: %s", err)
      return 0
    if status == "error":
      LOG.error("leader_only: %s", reason)
      return 1
  output_dir = args.output_dir or default_output_dir()
  try:
    prepare_output_dir(output_dir)
  except Exception as err:
    LOG.error("output_dir: %s", err)
    return 1
  global AHV_PORT, AHV_CERT_DIRS
  AHV_PORT = int(args.ahv_gateway_port)
  if args.ahv_gateway_cert_dir:
    AHV_CERT_DIRS = (args.ahv_gateway_cert_dir,) + tuple(
        d for d in AHV_CERT_DIRS if d != args.ahv_gateway_cert_dir)
  return dump_pc(
      output_dir,
      workers=max(1, int(args.workers)),
      skip_idf=bool(args.skip_idfcli),
      skip_ahv=bool(args.skip_ahv_gateway),
      skip_cmsp=bool(args.skip_cmsp_ovn),
      skip_atlas=bool(args.skip_atlas),
      skip_flow_cli=bool(args.skip_flow_cli),
      ahv_gw_timeout=max(60, int(args.ahv_gateway_timeout_secs)),
      cmsp_ovn_timeout=max(60, int(args.cmsp_ovn_timeout_secs)),
      atlas_timeout=max(60, int(args.atlas_timeout_secs)),
      atlas_get_workers=max(1, int(args.atlas_get_workers)),
      flow_cli_timeout=max(60, int(args.flow_cli_timeout_secs)),
      flow_cli_get_workers=max(1, int(args.flow_cli_get_workers)),
      idf_timeout=max(60, int(args.dataset_timeout_secs)),
      ahv_workers=max(1, int(args.ahv_gateway_workers)),
      ahv_class_timeout=max(30, int(args.ahv_gateway_class_timeout_secs)),
      cmsp_ovn_namespace=args.cmsp_ovn_namespace or "",
      cmsp_ovn_wait=bool(args.cmsp_ovn_wait),
      fail_on_error=bool(args.fail_on_error),
      log_file=args.log_file or "",
      combined_path=args.output or "")


if __name__ == "__main__":
  sys.exit(main(sys.argv))
