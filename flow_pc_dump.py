#!/usr/bin/env python
#
# Copyright (c) 2026 Nutanix Inc. All rights reserved.
#
# PC collect only. Copy this file to the PC. System python3. No Flow venv.
#   python3 flow_pc_dump.py --output_dir /home/nutanix/upgrade/flow_pc_dump
#
# Collects idfcli, atlas_cli, AHV Gateway OVS, CMSP OVN. No convert.
# Convert locally: python3 flow_pc_process.py --dump_dir ...
#
# Host OVS/OVN/virsh is collected from PC via AHV Gateway (mTLS :7030),
# never SSH to AHV. Per PE hypervisor, the dump loops until these exist:
#   ovs-vsctl show, ovs-dpctl -s show, ovs-ofctl dump-flows brAtlas
#   (plus other brAtlas ofctl outputs), virsh list --all, virsh dumpxml
#   (tap/MAC), tap devices, OVN/OVS DB (ovn*.db / conf.db).
# Classes: networking + avm (+ ovn if the gateway advertises it).
# Cert: /home/certs/ClusterHealthService/ (ClusterHealthService).
#
# Where files land:
#   AHV Gateway: <output_dir>/ahv_gateway/<hypervisor_ip>/
#   CMSP OVN:    <output_dir>/cmsp_ovn/{anc-ovn,anc-ovn-ic-db,anc-policydb}/
# On CMSP, OVN Northbound/Southbound live in kubectl pods on the PC
# (anc-ovn-0 / container anc-ovn), not on AHV. Collect with:
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
# Do not pass -it (this dump has no TTY). Loop until both dumps exist.
#

import argparse
import codecs
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
try:
  from urllib.request import Request, urlopen
except ImportError:
  from urllib2 import Request, urlopen


class FLAGS(object):
  ahv_gateway_port = 7030
  ahv_gateway_cert_dir = "/home/certs/ClusterHealthService"
  ahv_gateway_workers = 8
  ahv_gateway_class_timeout_secs = 300
  cmsp_ovn_namespace = ""


LOG = logging.getLogger("flow_pc_dump")
DEFAULT_OUTPUT = "/home/nutanix/upgrade/flow_pc_dump"

def _setup_logging(log_file=None):
  log_format = logging.Formatter(
      "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
  root = logging.getLogger()
  root.setLevel(logging.INFO)
  for handler in list(root.handlers):
    root.removeHandler(handler)
  stream = logging.StreamHandler(sys.stdout)
  stream.setFormatter(log_format)
  root.addHandler(stream)
  if log_file:
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(log_format)
    root.addHandler(file_handler)


def _uuid_str(value):
  if value is None or value == "" or value == b"":
    return None
  if hasattr(value, "hex"):
    hex_str = value.hex
    if len(hex_str) == 32:
      return "%s-%s-%s-%s-%s" % (
          hex_str[0:8], hex_str[8:12], hex_str[12:16],
          hex_str[16:20], hex_str[20:32])
    return str(value)
  if isinstance(value, (bytes, bytearray)):
    raw = bytes(value)
    if len(raw) == 16:
      return _uuid_str(uuid.UUID(bytes=raw))
    try:
      return _uuid_str(raw.decode("utf-8"))
    except Exception:
      return None
  text = str(value).strip()
  if not text:
    return None
  compact = text.replace("-", "")
  if len(compact) == 32:
    return "%s-%s-%s-%s-%s" % (
        compact[0:8], compact[8:12], compact[12:16],
        compact[16:20], compact[20:32])
  return text


IDF_DUMP_TYPES = (
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


def _idfcli_bin():
  for path in (
      "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
      "/home/nutanix/bin/idfcli",
      "/usr/local/nutanix/bin/idfcli"):
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "idfcli"


def _idf_unquote(raw):
  try:
    return codecs.decode(raw, "unicode_escape")
  except Exception:
    return raw


def _idf_bytes_raw(raw):
  text = _idf_unquote(raw)
  if isinstance(text, bytes):
    return text
  try:
    return text.encode("latin-1")
  except Exception:
    return text.encode("utf-8", "replace")


def _idf_bytes_to_value(raw):
  data = _idf_bytes_raw(raw)
  if len(data) == 16:
    return _uuid_str(data) or data.hex()
  decoded = data.decode("utf-8", "replace")
  return _uuid_str(decoded) or decoded


def _parse_idf_entities(text):
  entities = []
  blocks = re.split(r"^entity:\s*<", text or "", flags=re.MULTILINE)
  for block in blocks:
    if not block.strip():
      continue
    attrs = {}
    guid = re.search(r'entity_id:\s*"([^"]+)"', block)
    if not guid:
      guid = re.search(r'uuid:\s*"([^"]+)"', block)
    if guid:
      attrs["ext_id"] = _uuid_str(guid.group(1)) or guid.group(1)
    for match in re.finditer(
        r'attribute_data_map:\s*<\s*name:\s*"([^"]+)"(.*?)(?=attribute_data_map:|\Z)',
        block, re.DOTALL):
      name = match.group(1)
      body = match.group(2)
      str_list = re.findall(r'value_list:\s*"([^"]*)"', body)
      str_val = re.search(r'str_value:\s*"([^"]*)"', body)
      int_val = re.search(r'int64_value:\s*(-?\d+)', body)
      bool_val = re.search(r'bool_value:\s*(true|false)', body)
      bytes_list = re.findall(r'bytes_value:\s*"((?:\\.|[^"\\])*)"', body)
      if str_list:
        attrs[name] = [
            _uuid_str(item) or _idf_unquote(item) for item in str_list]
      elif len(bytes_list) > 1:
        attrs[name] = [_idf_bytes_to_value(item) for item in bytes_list]
      elif str_val:
        attrs[name] = _uuid_str(str_val.group(1)) or str_val.group(1)
      elif bytes_list:
        if name == "__zprotobuf__":
          continue
        attrs[name] = _idf_bytes_to_value(bytes_list[0])
      elif int_val:
        attrs[name] = int(int_val.group(1))
      elif bool_val:
        attrs[name] = bool_val.group(1) == "true"
    if attrs:
      entities.append(attrs)
  return entities


def dump_idfcli(output_dir, workers=8, timeout=180):
  """Run idfcli get entitytype; write raw .txt plus parsed .json (no convert)."""
  dest = os.path.join(output_dir, "idfcli")
  os.makedirs(dest, exist_ok=True)
  index = {
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "entity_types": {},
  }
  errors = {}
  binary = _idfcli_bin()

  def _one(entity_type):
    LOG.info("DUMP idfcli entitytype %s", entity_type)
    err = None
    text = ""
    try:
      proc = subprocess.run(
          [binary, "get", "entitytype", "-e", entity_type],
          capture_output=True, text=True, check=False, timeout=timeout)
      text = proc.stdout or ""
      if proc.returncode != 0 and not text:
        err = "%s: %s" % (entity_type, (proc.stderr or "").strip()[:200])
    except Exception as exc:
      err = "%s: %s" % (entity_type, exc)
    txt_path = os.path.join(dest, "%s.txt" % entity_type)
    with open(txt_path, "w") as handle:
      handle.write(text)
    rows = _parse_idf_entities(text)
    _write_json_file(os.path.join(dest, "%s.json" % entity_type), rows)
    LOG.info("DUMP idfcli %s parsed=%s", entity_type, len(rows))
    return entity_type, len(rows), err

  LOG.info("DUMP idfcli types=%s workers=%s", len(IDF_DUMP_TYPES), workers)
  with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
    futs = [pool.submit(_one, entity_type) for entity_type in IDF_DUMP_TYPES]
    for fut in futs:
      entity_type, count, err = fut.result()
      index["entity_types"][entity_type] = {
          "count": count,
          "error": err or "",
          "file": "%s.json" % entity_type,
      }
      if err:
        errors["idfcli:%s" % entity_type] = err
        LOG.warning("idfcli %s: %s", entity_type, err)
      else:
        LOG.info("idfcli %s count=%s", entity_type, count)
  _write_json_file(os.path.join(dest, "index.json"), index)
  LOG.info("DUMP idfcli wrote %s types under %s", len(IDF_DUMP_TYPES), dest)
  return index, errors


def _load_json_if_present(path, default):
  if not os.path.isfile(path):
    return default
  with open(path, "r") as handle:
    return json.load(handle) or default


def _json_default(value):
  if hasattr(value, "hex"):
    return _uuid_str(value)
  if isinstance(value, (bytes, bytearray)):
    return _uuid_str(value) or value.decode("utf-8", "replace")
  if hasattr(value, "isoformat"):
    return value.isoformat()
  return str(value)


def _write_json_file(path, value):
  parent = os.path.dirname(path)
  if parent:
    os.makedirs(parent, exist_ok=True)
  with open(path, "w") as handle:
    json.dump(value, handle, separators=(",", ":"), default=_json_default)
  size = os.path.getsize(path)
  LOG.info("Wrote %s (%s bytes)", path, size)
  return path, size


def fetch_unique_uuids():
  LOG.info("DUMP start vlan/global unique uuids")
  zkcats = (
      "/home/nutanix/cluster/bin/zkcat",
      "/usr/local/nutanix/cluster/bin/zkcat",
  )
  paths = {
      "vlan_unique_uuid": "/appliance/logical/flow/vlan_unique_uuid",
      "global_unique_uuid": "/appliance/logical/flow/global_unique_uuid",
  }
  out = {}
  for key, zk_path in paths.items():
    value = ""
    found_bin = False
    for zkcat in zkcats:
      if not (os.path.exists(zkcat) and os.access(zkcat, os.X_OK)):
        continue
      found_bin = True
      try:
        proc = subprocess.run(
            [zkcat, zk_path], capture_output=True, text=True, check=False,
            timeout=20)
      except Exception as err:
        LOG.error("DUMP %s failed: %s", key, err)
        continue
      text = (proc.stdout or "").strip()
      err_text = (proc.stderr or "").strip()
      if "no node" in ("%s %s" % (text, err_text)).lower():
        continue
      if proc.returncode == 0 and text:
        value = text.splitlines()[-1].strip()
        break
    if not found_bin:
      LOG.warning("zkcat missing; skip %s", key)
    out[key] = value
    LOG.info("DUMP %s=%s", key, value or "<empty>")
  return out

def _atlas_cli_bin():
  for path in (
      "/usr/local/nutanix/bin/atlas_cli",
      "/home/nutanix/bin/atlas_cli",
      "/home/nutanix/atlas/bin/atlas_cli"):
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "atlas_cli"


def _safe_json_loads(text):
  if not text or not str(text).strip():
    return None
  text = str(text).strip()
  try:
    return json.loads(text)
  except Exception:
    pass
  start = text.find("{")
  end = text.rfind("}")
  if start >= 0 and end > start:
    try:
      return json.loads(text[start:end + 1])
    except Exception:
      pass
  start = text.find("[")
  end = text.rfind("]")
  if start >= 0 and end > start:
    try:
      return json.loads(text[start:end + 1])
    except Exception:
      pass
  return None


def _run_profile_cmd(cmd, timeout=30):
  full = "source /etc/profile >/dev/null 2>&1; %s" % cmd
  try:
    proc = subprocess.run(
        full, shell=True, executable="/bin/bash",
        capture_output=True, text=True, check=False, timeout=timeout)
  except Exception as err:
    LOG.debug("cmd failed (%s): %s", cmd, err)
    return "", str(err), 1
  return proc.stdout or "", proc.stderr or "", proc.returncode


def _mspctl_cluster_list():
  out, err, _rc = _run_profile_cmd("mspctl cluster list --output json")
  parsed = _safe_json_loads(out)
  if isinstance(parsed, list):
    return parsed
  if isinstance(parsed, dict):
    for key in ("clusters", "data", "ClusterList", "items"):
      if isinstance(parsed.get(key), list):
        return parsed[key]
  LOG.debug("mspctl cluster list not JSON: %s", (out or err)[:300])
  return []


def _mspctl_flow_cluster():
  out, err, _rc = _run_profile_cmd("mspctl cluster get flow --verbose")
  parsed = _safe_json_loads(out)
  if isinstance(parsed, dict) and parsed.get("ClusterUUID"):
    return parsed
  text = "%s\n%s" % (out, err)
  if re.search(r"msp cluster not found|getClusterStatusV2NotFound|\b404\b",
               text, re.I):
    return {"_not_found": True, "_raw": text[:300]}
  return None


def _flow_cluster_from_list(clusters):
  for cluster in clusters or []:
    if not isinstance(cluster, dict):
      continue
    name = str(cluster.get("cluster_name") or cluster.get("name") or "")
    if name.strip().lower() == "flow":
      return cluster
  return None


def _cluster_uuid(cluster):
  if not isinstance(cluster, dict):
    return ""
  return str(
      cluster.get("cluster_uuid") or cluster.get("ClusterUUID") or
      cluster.get("uuid") or "")


def _zk_node_exists(zk_path):
  for zkcat in (
      "/home/nutanix/cluster/bin/zkcat",
      "/usr/local/nutanix/cluster/bin/zkcat"):
    if not (os.path.exists(zkcat) and os.access(zkcat, os.X_OK)):
      continue
    try:
      proc = subprocess.run(
          [zkcat, zk_path], capture_output=True, text=True, check=False,
          timeout=15)
    except Exception:
      continue
    text = "%s%s" % (proc.stdout or "", proc.stderr or "")
    if "no node" in text.lower():
      return False
    if proc.returncode == 0:
      return True
  return False


def _genesis_atlas_pids():
  out, err, _rc = _run_profile_cmd("genesis status", timeout=45)
  text = out or err
  for line in text.splitlines():
    stripped = line.strip().lower()
    if not stripped.startswith("atlas:"):
      continue
    if "[" not in line:
      return []
    inner = line.split("[", 1)[1].split("]", 1)[0]
    return [part.strip() for part in inner.split(",") if part.strip().isdigit()]
  return []


def detect_msp_platform():
  """Detect Flow SMSP vs CMSP from the PC itself (no --platform flag).

  SMSP: mspctl has a cluster named flow (service MSP). atlas_cli needs
        -u ws://smsp-<uuid>.ntnx-ikat.svc:2060/atlas_cli
  CMSP: only the controller MSP (prism-central/msp); Atlas runs on the PCVM.
  """
  info = {
      "platform": "cmsp",
      "detection_method": "no_flow_smsp_signals",
      "smsp_cluster_uuid": "",
  }
  with ThreadPoolExecutor(max_workers=3) as pool:
    list_fut = pool.submit(_mspctl_cluster_list)
    get_fut = pool.submit(_mspctl_flow_cluster)
    zk_fut = pool.submit(_zk_node_exists, "/appliance/logical/flow_smsp")
    clusters = list_fut.result()
    flow_get = get_fut.result()
    zk_smsp = zk_fut.result()
  names = [
      str(item.get("cluster_name") or item.get("name") or "")
      for item in clusters if isinstance(item, dict)]
  LOG.info("mspctl clusters: %s", names or "<none>")
  flow = _flow_cluster_from_list(clusters)
  smsp_uuid = _cluster_uuid(flow)
  if not smsp_uuid and isinstance(flow_get, dict):
    smsp_uuid = _cluster_uuid(flow_get)

  if smsp_uuid:
    info["platform"] = "smsp"
    info["smsp_cluster_uuid"] = smsp_uuid
    info["detection_method"] = (
        "mspctl_cluster_list_flow" if flow else "mspctl_cluster_get_flow")
    LOG.info(
        "Detected SMSP via %s uuid=%s", info["detection_method"], smsp_uuid)
    return info

  not_found = isinstance(flow_get, dict) and flow_get.get("_not_found")
  no_flow = not_found or (clusters and not flow)
  atlas_pids = []
  if not no_flow:
    atlas_pids = _genesis_atlas_pids()
  LOG.info(
      "SMSP probes: flow_cluster=%s flow_404=%s genesis_atlas_pids=%s "
      "zk_flow_smsp=%s",
      bool(flow), bool(not_found), len(atlas_pids), zk_smsp)

  if zk_smsp and not not_found:
    info["platform"] = "smsp"
    info["detection_method"] = "zk_flow_smsp"
    LOG.warning(
        "ZK /appliance/logical/flow_smsp exists but no flow MSP UUID; "
        "atlas_cli -u cannot be formed")
    return info

  if no_flow and atlas_pids:
    info["detection_method"] = "mspctl_no_flow_cluster+genesis_atlas"
  elif no_flow:
    info["detection_method"] = "mspctl_no_flow_cluster"
  elif atlas_pids:
    info["detection_method"] = "genesis_atlas"
  info["platform"] = "cmsp"
  LOG.info("Detected CMSP via %s", info["detection_method"])
  return info


def _atlas_cli_argv(platform_info):
  argv = [_atlas_cli_bin()]
  if (platform_info.get("platform") == "smsp" and
      platform_info.get("smsp_cluster_uuid")):
    argv.extend([
        "-u",
        "ws://smsp-%s.ntnx-ikat.svc:2060/atlas_cli" % (
            platform_info["smsp_cluster_uuid"]),
    ])
  argv.extend(["-o", "json"])
  return argv


def _run_atlas_cli(platform_info, args, timeout_secs, log_cmd=True):
  cmd = _atlas_cli_argv(platform_info) + list(args)
  if log_cmd:
    LOG.info("DUMP atlas_cli: %s", " ".join(cmd))
  try:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False,
        timeout=timeout_secs)
  except subprocess.TimeoutExpired:
    raise RuntimeError(
        "atlas_cli %s timed out after %ss" % (" ".join(args), timeout_secs))
  parsed = _safe_json_loads(proc.stdout or "")
  if parsed is None:
    err = (proc.stderr or proc.stdout or "").strip()[:500]
    raise RuntimeError(
        "atlas_cli %s failed rc=%s: %s" % (
            " ".join(args), proc.returncode, err or "no JSON output"))
  return parsed, proc.returncode, cmd


def _port_set_list_rows(parsed):
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
      if isinstance(value, dict):
        row = dict(value)
        row.setdefault("uuid", key)
        rows.append(row)
      else:
        rows.append({"uuid": key, "value": value})
    return rows
  for key in ("entities", "items", "value", "results"):
    if isinstance(parsed.get(key), list):
      return parsed[key]
  return []


def _port_set_uuid(item):
  if isinstance(item, str):
    return _uuid_str(item)
  if not isinstance(item, dict):
    return None
  return _uuid_str(
      item.get("uuid") or item.get("ext_id") or item.get("UUID") or
      item.get("id"))


def fetch_port_set_list(platform_info, timeout_secs):
  LOG.info(
      "DUMP start port_set_list platform=%s method=%s smsp_uuid=%s",
      platform_info.get("platform"),
      platform_info.get("detection_method"),
      platform_info.get("smsp_cluster_uuid") or "<none>")
  parsed, _status, cmd = _run_atlas_cli(
      platform_info, ["port_set.list"], timeout_secs)
  if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
    raise RuntimeError(
        "atlas_cli port_set.list status=%s cmd=%s" % (
            parsed.get("status"), " ".join(cmd)))
  rows = _port_set_list_rows(parsed)
  LOG.info("DUMP done port_set_list count=%s", len(rows))
  return rows


def _port_set_get_record(parsed, ps_uuid):
  if not isinstance(parsed, dict):
    return parsed if parsed is not None else {}
  data = parsed.get("data", parsed)
  if isinstance(data, dict):
    if ps_uuid in data and isinstance(data[ps_uuid], dict):
      return data[ps_uuid]
    if data.get("uuid") == ps_uuid or data.get("ext_id") == ps_uuid:
      return data
    if "data" in parsed and isinstance(parsed["data"], dict):
      inner = parsed["data"]
      if ps_uuid in inner:
        return inner[ps_uuid]
      if len(inner) == 1:
        only = list(inner.values())[0]
        if isinstance(only, dict):
          return only
    return data
  if isinstance(data, list) and data and isinstance(data[0], dict):
    return data[0]
  return parsed


def _normalize_port_set_get(gets):
  """Unwrap atlas_cli {data: {uuid: rec}} accidentally stored as the rec."""
  if not isinstance(gets, dict):
    return gets or {}
  out = {}
  for uid, rec in gets.items():
    if not isinstance(rec, dict):
      continue
    inner = rec
    nested = rec.get(uid)
    if isinstance(nested, dict) and (
        "virtual_nic_uuid_list" in nested or nested.get("name") is not None):
      inner = nested
    elif "virtual_nic_uuid_list" not in rec:
      candidates = [
          value for key, value in rec.items()
          if key != "uuid" and isinstance(value, dict) and (
              "virtual_nic_uuid_list" in value or value.get("name") is not None)]
      if len(candidates) == 1:
        inner = candidates[0]
    if isinstance(inner, dict):
      inner = dict(inner)
      inner.setdefault("uuid", uid)
    out[uid] = inner
  return out


def fetch_port_set_get(platform_info, uuids, workers, timeout_secs, errors):
  gets = {}
  if not uuids:
    LOG.info("DUMP skip port_set_get (no UUIDs from port_set.list)")
    return gets
  per_timeout = max(15, min(45, int(timeout_secs)))
  LOG.info("DUMP start port_set_get count=%s workers=%s", len(uuids), workers)

  def _one(ps_uuid):
    parsed, _status, _cmd = _run_atlas_cli(
        platform_info, ["port_set.get", ps_uuid], per_timeout, log_cmd=False)
    if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
      raise RuntimeError("status=%s" % parsed.get("status"))
    rec = _port_set_get_record(parsed, ps_uuid)
    if isinstance(rec, dict):
      rec.setdefault("uuid", ps_uuid)
    return rec

  failed = []
  with ThreadPoolExecutor(max_workers=max(1, min(workers, len(uuids)))) as pool:
    future_map = {pool.submit(_one, ps_uuid): ps_uuid for ps_uuid in uuids}
    done, pending = wait(future_map.keys(), timeout=timeout_secs)
    for future in done:
      ps_uuid = future_map[future]
      try:
        gets[ps_uuid] = future.result(timeout=1)
      except Exception as err:
        failed.append(ps_uuid)
        LOG.error("DUMP port_set.get %s FAILED: %s", ps_uuid, err)
    for future in pending:
      ps_uuid = future_map[future]
      future.cancel()
      failed.append(ps_uuid)
      LOG.error("DUMP port_set.get %s TIMEOUT after %ss", ps_uuid, timeout_secs)
  if failed:
    errors["port_set_get"] = "failed %s of %s: %s" % (
        len(failed), len(uuids), ",".join(failed[:20]))
  LOG.info(
      "DUMP done port_set_get got=%s failed=%s", len(gets), len(failed))
  return gets


def dump_atlas_port_sets(output_dir, workers=32, timeout_secs=1800):
  """atlas_cli port_set.list + port_set.get into dump JSON files."""
  errors = {}
  info = detect_msp_platform()
  list_timeout = max(60, min(300, int(timeout_secs)))
  try:
    rows = fetch_port_set_list(info, list_timeout)
  except Exception as err:
    errors["port_set_list"] = str(err)
    LOG.error("DATASET port_set_list FAILED: %s", err)
    rows = []
  _write_json_file(os.path.join(output_dir, "port_set_list.json"), rows)
  uuids = []
  seen = set()
  for item in rows:
    uid = _port_set_uuid(item)
    if uid and uid not in seen:
      seen.add(uid)
      uuids.append(uid)
  try:
    gets = fetch_port_set_get(
        info, uuids, max(1, int(workers)), max(60, int(timeout_secs)), errors)
  except Exception as err:
    errors["port_set_get"] = str(err)
    LOG.error("DATASET port_set_get FAILED: %s", err)
    gets = {}
  gets = _normalize_port_set_get(gets)
  _write_json_file(os.path.join(output_dir, "port_set_get.json"), gets)
  rec = {
      "ran": True,
      "platform": info.get("platform") or "",
      "detection_method": info.get("detection_method") or "",
      "list_count": len(rows),
      "get_count": len(gets),
      "errors": errors,
  }
  LOG.info(
      "DUMP atlas port_set list=%s get=%s platform=%s",
      rec["list_count"], rec["get_count"], rec["platform"])
  return rec

# Host OVS via AHV Gateway mTLS; OVN NB/SB via kubectl on CMSP PC.
NCLI_BIN_CANDIDATES = (
    "/usr/local/nutanix/bin/ncli",
    "/home/nutanix/prism/cli/ncli",
    "/usr/local/nutanix/cluster/bin/ncli",
    "/usr/bin/ncli")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NCLI_CLUSTER_ID_RE = re.compile(
    r"Cluster Id\s*:\s*([0-9a-fA-F-]{36})", re.I)

def _ncli_bin():
  for path in NCLI_BIN_CANDIDATES:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "ncli"


def _run_cmd_argv(argv, timeout_secs, cwd=None, stdout_path=None, binary=False):
  if not argv:
    return -1, "", "empty argv"
  timeout_secs = max(5, int(timeout_secs))
  try:
    if stdout_path:
      os.makedirs(os.path.dirname(stdout_path) or ".", exist_ok=True)
      mode = "wb" if binary else "w"
      with open(stdout_path, mode) as handle:
        proc = subprocess.run(
            argv, stdout=handle, stderr=subprocess.PIPE, check=False,
            timeout=timeout_secs, stdin=subprocess.DEVNULL, cwd=cwd,
            text=not binary)
      stderr = proc.stderr or (b"" if binary else "")
      if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
      return proc.returncode, "", stderr
    proc = subprocess.run(
        argv, capture_output=True, text=True, check=False,
        timeout=timeout_secs, stdin=subprocess.DEVNULL, cwd=cwd)
  except subprocess.TimeoutExpired as err:
    out = err.stdout or ""
    if isinstance(out, bytes):
      out = out.decode("utf-8", "replace")
    return -1, out or "", "timed out after %ss: %s" % (
        timeout_secs, " ".join(str(x) for x in argv))
  except Exception as err:
    return -1, "", str(err)
  return proc.returncode, proc.stdout or "", proc.stderr or ""

def _clean_ipv4(raw):
  text = str(raw or "").strip().strip("[],;\"'")
  if text.lower() in ("", "-", "none", "null", "n/a"):
    return ""
  if isinstance(raw, dict):
    text = str(raw.get("value") or raw.get("ipv4") or raw.get("ip") or "")
    if isinstance(text, dict):
      text = str(text.get("value") or "")
    text = text.strip()
  if _IPV4_RE.match(text):
    return text
  return ""


def _ncli_run(args, timeout_secs=60):
  binary = _ncli_bin()
  argv = [binary] + list(args)
  rc, stdout, stderr = _run_cmd_argv(argv, timeout_secs)
  if rc == 0 or stdout:
    return rc, stdout, stderr
  cmd = " ".join(["ncli"] + list(args))
  out, err, prc = _run_profile_cmd(cmd, timeout=timeout_secs)
  return prc, out, err


def _ncli_local_cluster():
  rec = {"ext_id": "", "name": "", "vip": ""}
  for args in (
      ["cluster", "info"],
      ["cluster", "get-params", "json=true"],
      ["cluster", "get-params", "-json=true"],
  ):
    rc, stdout, stderr = _ncli_run(args, timeout_secs=45)
    text = "%s\n%s" % (stdout, stderr)
    parsed = _safe_json_loads(stdout)
    if isinstance(parsed, dict):
      data = parsed.get("data") or parsed.get("clusterInfo") or parsed
      if isinstance(data, list) and data:
        data = data[0]
      if isinstance(data, dict):
        rec["ext_id"] = rec["ext_id"] or _uuid_str(
            data.get("clusterUuid") or data.get("uuid") or
            data.get("id") or data.get("cluster_uuid")) or ""
        rec["name"] = rec["name"] or str(
            data.get("clusterName") or data.get("name") or "")
        rec["vip"] = rec["vip"] or _clean_ipv4(
            data.get("clusterExternalIPAddress")
            or data.get("clusterExternalIp")
            or data.get("externalIp"))
    uid_match = _NCLI_CLUSTER_ID_RE.search(text)
    if uid_match:
      rec["ext_id"] = rec["ext_id"] or (_uuid_str(uid_match.group(1)) or "")
    name_match = re.search(r"Cluster Name\s*:\s*(.+)", text, re.I)
    if name_match and not rec["name"]:
      rec["name"] = name_match.group(1).strip()
    vip_match = re.search(
        r"Cluster External IP(?: Address)?\s*:\s*(\S+)", text, re.I)
    if vip_match and not rec["vip"]:
      rec["vip"] = _clean_ipv4(vip_match.group(1))
    if rec["ext_id"]:
      break
  return rec


def _parse_ncli_multicluster_json(parsed):
  rows = []
  if isinstance(parsed, dict):
    data = parsed.get("data") or parsed.get("clusters") or parsed.get("items")
    if data is None:
      data = [parsed]
  elif isinstance(parsed, list):
    data = parsed
  else:
    return rows
  for entry in data:
    if not isinstance(entry, dict):
      continue
    details = entry.get("clusterDetails") or entry.get("cluster_details") or {}
    if not isinstance(details, dict):
      details = {}
    uid = _uuid_str(
        entry.get("clusterUuid") or entry.get("cluster_uuid")
        or entry.get("uuid") or entry.get("id")
        or details.get("clusterUuid") or details.get("uuid")) or ""
    if not uid:
      continue
    name = (
        entry.get("clusterName") or entry.get("cluster_name")
        or entry.get("name") or details.get("clusterName")
        or details.get("name") or "")
    vip = _clean_ipv4(
        entry.get("clusterExternalIPAddress")
        or entry.get("clusterExternalIp")
        or entry.get("externalIp")
        or details.get("clusterExternalIPAddress")
        or details.get("clusterExternalIp")
        or details.get("externalIp"))
    ips_raw = (
        details.get("ipAddresses") or details.get("ip_addresses")
        or entry.get("ipAddresses") or entry.get("controllerVmIps")
        or [])
    cvm_ips = []
    for ip in _as_list(ips_raw):
      cleaned = _clean_ipv4(ip)
      if cleaned and cleaned not in cvm_ips:
        cvm_ips.append(cleaned)
    rows.append({
        "ext_id": uid,
        "name": str(name or ""),
        "vip": vip,
        "cvm_ips": cvm_ips,
        "cluster_type": str(
            entry.get("clusterType") or entry.get("clusterFunction")
            or details.get("clusterType") or ""),
        "source": "ncli_multicluster_json",
    })
  return rows


def _parse_ncli_multicluster_text(text):
  rows = []
  blocks = re.split(r"(?=Cluster Id\s*:)", text or "", flags=re.I)
  for block in blocks:
    uid_match = _NCLI_CLUSTER_ID_RE.search(block)
    if not uid_match:
      continue
    uid = _uuid_str(uid_match.group(1)) or ""
    if not uid:
      continue
    name_match = re.search(r"Cluster Name\s*:\s*(.+)", block, re.I)
    vip_match = re.search(
        r"Cluster External IP(?: Address)?\s*:\s*(\S+)", block, re.I)
    if not vip_match:
      vip_match = re.search(
          r"External (?:or Masquerading )?IP(?: Address)?\s*:\s*(\S+)",
          block, re.I)
    cvm_match = re.search(
        r"Controller VM IP Addre[^:]*:\s*\[([^\]]*)\]", block, re.I)
    ctype_match = re.search(
        r"Cluster (?:Type|Function)\s*:\s*(\S+)", block, re.I)
    cvm_ips = []
    if cvm_match:
      for part in cvm_match.group(1).split(","):
        cleaned = _clean_ipv4(part)
        if cleaned and cleaned not in cvm_ips:
          cvm_ips.append(cleaned)
    rows.append({
        "ext_id": uid,
        "name": (name_match.group(1).strip() if name_match else ""),
        "vip": _clean_ipv4(vip_match.group(1) if vip_match else ""),
        "cvm_ips": cvm_ips,
        "cluster_type": (ctype_match.group(1).strip() if ctype_match else ""),
        "source": "ncli_multicluster_text",
    })
  return rows


def _ncli_registered_clusters():
  rows = []
  for args in (
      ["multicluster", "get-cluster-state", "json=true"],
      ["multicluster", "get-cluster-state", "--json=true"],
      ["multicluster", "get-cluster-state", "-json=true"],
      ["multicluster", "get-cluster-state"],
      ["cluster", "list"],
  ):
    rc, stdout, stderr = _ncli_run(args, timeout_secs=60)
    text = "%s\n%s" % (stdout, stderr)
    parsed = _safe_json_loads(stdout)
    found = []
    if parsed is not None:
      found = _parse_ncli_multicluster_json(parsed)
    if not found:
      found = _parse_ncli_multicluster_text(text)
    if found:
      rows = found
      break
  return rows


def _cluster_from_dump_row(row):
  if not isinstance(row, dict):
    return {}
  uid = _uuid_str(row.get("ext_id") or row.get("uuid") or row.get("id")) or ""
  name = row.get("name") or ""
  net = ((row.get("network") or {}).get("external_address") or {})
  ipv4 = net.get("ipv4") if isinstance(net, dict) else {}
  vip = ""
  if isinstance(ipv4, dict):
    vip = _clean_ipv4(ipv4.get("value"))
  elif ipv4:
    vip = _clean_ipv4(ipv4)
  if not vip:
    vip = _clean_ipv4(row.get("vip") or row.get("ip_address"))
  return {
      "ext_id": uid,
      "name": str(name or ""),
      "vip": vip,
      "cvm_ips": list(row.get("cvm_ips") or []),
      "cluster_type": str(row.get("cluster_type") or ""),
      "source": row.get("source") or "dump",
  }


def _is_pc_cluster(rec, local_uuid=""):
  uid = (rec.get("ext_id") or "").lower()
  if local_uuid and uid and uid == local_uuid.lower():
    return True
  name = str(rec.get("name") or "").strip()
  if re.match(r"^PC[_\-\s]", name, re.I):
    return True
  if name.lower() in ("prism central", "prism_central", "prismcentral"):
    return True
  ctype = str(rec.get("cluster_type") or rec.get("cluster_function") or "")
  if re.search(
      r"multicluster|prism.?central|kprismcentral|\bkpc\b", ctype, re.I):
    return True
  return False


def _merge_pe_rec(dst, src):
  if not dst:
    return dict(src)
  for key in ("name", "vip", "cluster_type", "source"):
    if not dst.get(key) and src.get(key):
      dst[key] = src[key]
  cvms = list(dst.get("cvm_ips") or [])
  for ip in src.get("cvm_ips") or []:
    if ip and ip not in cvms:
      cvms.append(ip)
  dst["cvm_ips"] = cvms
  return dst


def _as_list(value):
  if value is None:
    return []
  if isinstance(value, list):
    return value
  return [value]


def _map_cluster(row):
  return row


def _idf_mapped(entity_types, mapper):
  """Live idfcli lookup for PE discovery. Policy convert is flow_pc_map.py."""
  rows = []
  errors = []
  binary = _idfcli_bin()
  for entity_type in entity_types:
    try:
      proc = subprocess.run(
          [binary, "get", "entitytype", "-e", entity_type],
          capture_output=True, text=True, check=False, timeout=180)
      parsed = _parse_idf_entities(proc.stdout or "")
    except Exception as exc:
      errors.append("%s: %s" % (entity_type, exc))
      continue
    for item in parsed or []:
      mapped = mapper(item) if mapper else item
      if mapped:
        rows.append(mapped)
    if parsed:
      break
  return rows, errors


def _discover_pe_clusters(dump_clusters=None):
  local = _ncli_local_cluster()
  local_uuid = local.get("ext_id") or ""
  found = {}
  errors = []
  sources = []

  def _add(rec, source):
    if not rec:
      return
    rec = dict(rec)
    rec["source"] = source
    uid = rec.get("ext_id") or ""
    if not uid:
      return
    if _is_pc_cluster(rec, local_uuid):
      return
    found[uid] = _merge_pe_rec(found.get(uid), rec)

  if dump_clusters:
    sources.append("dump_clusters")
    for row in dump_clusters:
      _add(_cluster_from_dump_row(row), "dump_clusters")
  try:
    ncli_rows = _ncli_registered_clusters()
    if ncli_rows:
      sources.append("ncli")
      for rec in ncli_rows:
        _add(rec, rec.get("source") or "ncli")
  except Exception as err:
    errors.append("ncli: %s" % err)
  try:
    idf_rows, idf_errs = _idf_mapped(("cluster",), _map_cluster)
    for err in idf_errs:
      errors.append("idf: %s" % err)
    if idf_rows:
      sources.append("idf")
      for row in idf_rows:
        _add(_cluster_from_dump_row(row), "idf")
  except Exception as err:
    errors.append("idf: %s" % err)
  pes = list(found.values())
  pes.sort(key=lambda item: item.get("ext_id") or "")
  LOG.info(
      "DUMP PE discovery count=%s local_pc=%s sources=%s",
      len(pes), local_uuid or "<none>", ",".join(sources) or "<none>")
  return pes, errors, sources, local


# AHV Gateway (PC → PE hypervisor :7030 mTLS). Never SSH to AHV.
AHV_GW_REQUIRED = (
    "ovs-vsctl_show",
    "ovs-dpctl_-s_show",
    "ovs-ofctl_dump-flows_brAtlas",
    "virsh_list",
    "virsh_dumpxml",
    "tap_interface",
    "ovn_or_ovs_db",
)
AHV_GW_CERT_FALLBACKS = (
    "/home/certs/ClusterHealthService",
    "/home/certs/PanaceaService",
    "/home/certs/GenesisService",
)


def _ahv_gw_port():
  try:
    return int(getattr(FLAGS, "ahv_gateway_port", 7030) or 7030)
  except (TypeError, ValueError):
    return 7030


def _ahv_gw_cert_pair():
  dirs = []
  flagged = str(getattr(FLAGS, "ahv_gateway_cert_dir", "") or "").strip()
  if flagged:
    dirs.append(flagged)
  dirs.extend(AHV_GW_CERT_FALLBACKS)
  seen = set()
  for directory in dirs:
    directory = os.path.abspath(directory)
    if directory in seen or not os.path.isdir(directory):
      continue
    seen.add(directory)
    name = os.path.basename(directory.rstrip("/"))
    crt = os.path.join(directory, name + ".crt")
    key = os.path.join(directory, name + ".key")
    if os.path.isfile(crt) and os.path.isfile(key):
      return crt, key, directory
  return "", "", ""


def _ahv_gw_ssl_context(crt, key):
  ctx = ssl._create_unverified_context()  # AHV GW SAN omits 192.168.5.1
  ctx.load_cert_chain(crt, key)
  return ctx


def _ahv_gw_open(host, path, crt, key, timeout_secs, accept="application/octet-stream"):
  if not path.startswith("/"):
    path = "/" + path
  url = "https://%s:%s/api%s" % (host, _ahv_gw_port(), path)
  req = Request(url, headers={"Accept": accept, "Accept-Encoding": "identity"})
  return urlopen(
      req, context=_ahv_gw_ssl_context(crt, key), timeout=timeout_secs)


def _ahv_gw_safe_relpath(member_name):
  text = str(member_name or "").replace("\\", "/").lstrip("/")
  parts = [p for p in text.split("/") if p and p not in (".", "..")]
  return os.path.join(*parts) if parts else ""


def _ahv_gw_write_member(dest_dir, member_name, data):
  rel = _ahv_gw_safe_relpath(member_name)
  if not rel:
    return ""
  path = os.path.join(dest_dir, rel)
  parent = os.path.dirname(path)
  if parent:
    os.makedirs(parent, exist_ok=True)
  with open(path, "wb") as handle:
    handle.write(data or b"")
  return path


def _ahv_gw_keep_networking(name):
  n = str(name or "").replace("\\", "/")
  base = n.split("/")[-1]
  low = n.lower()
  if "bratlas" in low and n.endswith((".stdout", ".stderr", ".rc", ".timeout")):
    return True
  if base in ("ovs-vsctl_show.stdout", "ovs-dpctl_-s_show.stdout"):
    return True
  if base.endswith(".db") and (
      "ovn" in low or "openvswitch" in low or base == "conf.db"):
    return True
  if any(tok in low for tok in (
      "ovn-nbctl", "ovn-sbctl", "ovnnb", "ovnsb", "ovn-controller")):
    return n.endswith(".stdout") or n.endswith(".db")
  return False


def _ahv_gw_keep_avm(name):
  n = str(name or "").replace("\\", "/").lower()
  if "virsh" in n and "list_--all" in n and n.endswith(
      (".stdout", ".stderr", ".rc")):
    return True
  if "dumpxml" in n and n.endswith(".stdout") and "net-dumpxml" not in n:
    return True
  if n.endswith(".stdout") and any(
      tok in n for tok in ("tuntap", "domiflist")):
    return True
  return False


def _ahv_gw_keep_ovn(name):
  n = str(name or "").replace("\\", "/").lower()
  return n.endswith(".db") or "ovn" in n


def _ahv_gw_keep_for_class(cls, name):
  if cls == "networking":
    return _ahv_gw_keep_networking(name)
  if cls == "avm":
    return _ahv_gw_keep_avm(name)
  if "ovn" in str(cls or "").lower():
    return _ahv_gw_keep_ovn(name)
  return False


def _ahv_gw_classify_saved(path, member_name):
  n = str(member_name or path or "").replace("\\", "/")
  low = n.lower()
  keys = []
  size = 0
  try:
    size = os.path.getsize(path) if path and os.path.isfile(path) else 0
  except OSError:
    size = 0
  if low.endswith("ovs-vsctl_show.stdout") and size > 0:
    keys.append("ovs-vsctl_show")
  if "ovs-dpctl_-s_show.stdout" in low and size > 0:
    keys.append("ovs-dpctl_-s_show")
  if "dump-flows_bratlas.stdout" in low and size > 100:
    keys.append("ovs-ofctl_dump-flows_brAtlas")
  if "virsh" in low and "list_--all.stdout" in low and size > 0:
    keys.append("virsh_list")
  if "dumpxml" in low and low.endswith(".stdout") and "net-dumpxml" not in low:
    if size > 0:
      keys.append("virsh_dumpxml")
      blob = b""
      try:
        blob = open(path, "rb").read(65536)
      except Exception:
        pass
      if b"<target" in blob and b"tap" in blob.lower():
        keys.append("tap_interface")
  if low.endswith(".stdout") and any(
      tok in low for tok in ("tuntap", "domiflist")) and size > 0:
    keys.append("tap_interface")
  if size > 0 and (
      (low.endswith(".db") and ("ovn" in low or "openvswitch" in low or
                                low.endswith("conf.db"))) or
      any(tok in low for tok in ("ovnnb", "ovnsb", "ovn-nb", "ovn-sb"))):
    keys.append("ovn_or_ovs_db")
  return keys


def _ahv_gw_scan_collected(host_dir):
  found = set()
  files = []
  if not host_dir or not os.path.isdir(host_dir):
    return found, files
  for root, _, names in os.walk(host_dir):
    for name in names:
      if name == "host.json":
        continue
      path = os.path.join(root, name)
      rel = os.path.relpath(path, host_dir).replace("\\", "/")
      files.append(rel)
      found.update(_ahv_gw_classify_saved(path, rel))
  return found, files


def _ahv_gw_list_classes(host, crt, key, timeout_secs):
  names = []
  try:
    resp = _ahv_gw_open(
        host, "/host/v1/bugtool-classes", crt, key, min(timeout_secs, 30),
        accept="application/json")
    raw = resp.read()
    resp.close()
    data = json.loads(raw.decode("utf-8", "replace") or "{}")
    for item in data.get("classes") or []:
      if isinstance(item, dict) and item.get("name"):
        names.append(str(item.get("name")))
      elif item:
        names.append(str(item))
  except Exception as err:
    LOG.debug("AHV GW class list %s failed: %s", host, err)
  return names


def _ahv_gw_extract_class(host, cls, dest_dir, crt, key, timeout_secs):
  saved = []
  resp = None
  try:
    resp = _ahv_gw_open(
        host, "/host/v1/bugtool/%s" % cls, crt, key, timeout_secs)
    tar = tarfile.open(fileobj=resp, mode="r|*")
    for member in tar:
      if not getattr(member, "isfile", lambda: False)():
        continue
      if not _ahv_gw_keep_for_class(cls, member.name):
        continue
      handle = tar.extractfile(member)
      data = handle.read() if handle is not None else b""
      path = _ahv_gw_write_member(dest_dir, member.name, data)
      if path:
        saved.append(path)
  finally:
    if resp is not None:
      try:
        resp.close()
      except Exception:
        pass
  return saved


def _host_hypervisor_ip(row):
  if not isinstance(row, dict):
    return ""
  hyp = row.get("hypervisor") or {}
  addr = hyp.get("external_address") if isinstance(hyp, dict) else {}
  ipv4 = addr.get("ipv4") if isinstance(addr, dict) else {}
  ip_addr = ""
  if isinstance(ipv4, dict):
    ip_addr = ipv4.get("value") or ""
  return _clean_ipv4(
      ip_addr
      or row.get("hypervisor_ip")
      or row.get("hypervisor_address")
      or row.get("host_ip"))


def _ncli_hypervisor_ips(cluster_uuid=""):
  ips = []
  arg_sets = []
  if cluster_uuid:
    arg_sets.extend((
        ["host", "list", "cluster-uuid=%s" % cluster_uuid],
        ["host", "list", "cluster-id=%s" % cluster_uuid],
    ))
  arg_sets.append(["host", "list"])
  for args in arg_sets:
    _rc, stdout, stderr = _ncli_run(args, timeout_secs=60)
    text = "%s\n%s" % (stdout, stderr)
    found = []
    for match in re.finditer(
        r"Hypervisor(?: IP)?(?: Address)?\s*:\s*(\S+)", text, re.I):
      ip_addr = _clean_ipv4(match.group(1))
      if ip_addr:
        found.append(ip_addr)
    if found:
      ips.extend(found)
      break
  out = []
  seen = set()
  for ip_addr in ips:
    if ip_addr not in seen:
      seen.add(ip_addr)
      out.append(ip_addr)
  return out


def _ahv_gw_discover_hosts(dump_hosts=None, dump_clusters=None):
  pes, disc_errors, disc_sources, local_pc = _discover_pe_clusters(
      dump_clusters)
  local_uuid = (local_pc or {}).get("ext_id") or ""
  pe_uuids = set(
      (rec.get("ext_id") or "").lower()
      for rec in pes if rec.get("ext_id"))
  hosts = {}

  def _add(ip_addr, name="", cluster_uuid="", source=""):
    ip_addr = _clean_ipv4(ip_addr)
    if not ip_addr:
      return
    rec = hosts.get(ip_addr) or {
        "ip": ip_addr, "name": "", "cluster_uuid": "", "sources": []}
    if name and not rec["name"]:
      rec["name"] = name
    if cluster_uuid and not rec["cluster_uuid"]:
      rec["cluster_uuid"] = cluster_uuid
    if source and source not in rec["sources"]:
      rec["sources"].append(source)
    hosts[ip_addr] = rec

  for row in dump_hosts or []:
    cluster_uuid = ""
    cluster = row.get("cluster") if isinstance(row, dict) else None
    if isinstance(cluster, dict):
      cluster_uuid = _uuid_str(
          cluster.get("uuid") or cluster.get("ext_id")) or ""
    if local_uuid and cluster_uuid and cluster_uuid.lower() == local_uuid.lower():
      continue
    if pe_uuids and cluster_uuid and cluster_uuid.lower() not in pe_uuids:
      continue
    _add(
        _host_hypervisor_ip(row),
        name=str((row or {}).get("host_name") or (row or {}).get("name") or ""),
        cluster_uuid=cluster_uuid,
        source="dump_hosts")
  for rec in pes:
    uid = rec.get("ext_id") or ""
    for ip_addr in _ncli_hypervisor_ips(uid):
      _add(ip_addr, cluster_uuid=uid, source="ncli_host_list")
  rows = list(hosts.values())
  rows.sort(key=lambda item: item.get("ip") or "")
  LOG.info(
      "DUMP AHV GW hosts=%s pe_clusters=%s sources=%s",
      len(rows), len(pes), ",".join(disc_sources) or "<none>")
  return rows, disc_errors, disc_sources, local_pc


def _ahv_gw_classes_for_missing(missing, advertised):
  classes = []
  if missing & set((
      "ovs-vsctl_show", "ovs-dpctl_-s_show",
      "ovs-ofctl_dump-flows_brAtlas", "ovn_or_ovs_db")):
    classes.append("networking")
  if missing & set(("virsh_list", "virsh_dumpxml", "tap_interface")):
    classes.append("avm")
  for name in advertised or []:
    if "ovn" in name.lower() and name not in classes:
      if "ovn_or_ovs_db" in missing:
        classes.append(name)
  out = []
  seen = set()
  for cls in classes:
    if cls not in seen:
      seen.add(cls)
      out.append(cls)
  return out or ["networking", "avm"]


def _ahv_gw_collect_one_host(host_rec, dest_root, crt, key, deadline):
  ip_addr = host_rec.get("ip") or ""
  host_dir = os.path.join(dest_root, ip_addr)
  os.makedirs(host_dir, exist_ok=True)
  rec = {
      "ip": ip_addr,
      "name": host_rec.get("name") or "",
      "cluster_uuid": host_rec.get("cluster_uuid") or "",
      "attempts": 0,
      "classes": [],
      "collected": [],
      "missing": list(AHV_GW_REQUIRED),
      "complete": False,
      "error": "",
      "files": [],
  }
  advertised = []
  class_timeout = max(30, int(getattr(
      FLAGS, "ahv_gateway_class_timeout_secs", 300) or 300))
  backoff = 5
  while time.time() < deadline:
    found, files = _ahv_gw_scan_collected(host_dir)
    missing = [key for key in AHV_GW_REQUIRED if key not in found]
    rec["collected"] = sorted(found)
    rec["missing"] = missing
    rec["files"] = files
    if not missing:
      rec["complete"] = True
      rec["error"] = ""
      return rec
    if not advertised:
      advertised = _ahv_gw_list_classes(
          ip_addr, crt, key, min(30, max(5, int(deadline - time.time()))))
      rec["advertised_classes"] = advertised
    rec["attempts"] += 1
    classes = _ahv_gw_classes_for_missing(set(missing), advertised)
    rec["classes"] = classes
    LOG.info(
        "DUMP AHV GW %s attempt=%s missing=%s classes=%s",
        ip_addr, rec["attempts"], ",".join(missing), ",".join(classes))
    errors = []
    for cls in classes:
      if time.time() >= deadline:
        break
      remain = max(15, int(deadline - time.time()))
      try:
        _ahv_gw_extract_class(
            ip_addr, cls, host_dir, crt, key, min(class_timeout, remain))
      except Exception as err:
        errors.append("%s:%s" % (cls, err))
        LOG.warning("DUMP AHV GW %s class %s failed: %s", ip_addr, cls, err)
    rec["error"] = "; ".join(errors)[:2000]
    found, files = _ahv_gw_scan_collected(host_dir)
    missing = [key for key in AHV_GW_REQUIRED if key not in found]
    rec["collected"] = sorted(found)
    rec["missing"] = missing
    rec["files"] = files
    if not missing:
      rec["complete"] = True
      rec["error"] = ""
      return rec
    sleep_for = min(backoff, max(0, int(deadline - time.time())))
    if sleep_for <= 0:
      break
    time.sleep(sleep_for)
    backoff = min(30, backoff * 2)
  rec["complete"] = False
  if not rec["error"]:
    rec["error"] = "deadline with missing: %s" % ",".join(
        rec.get("missing") or [])
  return rec


def fetch_ahv_gateway_host_state(output_dir, dump_hosts=None, dump_clusters=None,
                                 timeout_secs=1800):
  dest_root = os.path.join(output_dir, "ahv_gateway")
  os.makedirs(dest_root, exist_ok=True)
  timeout_secs = max(60, int(timeout_secs or 1800))
  payload = {
      "ran": False,
      "complete": False,
      "transport": "ahv_gateway_mtls",
      "ssh_to_ahv": False,
      "port": _ahv_gw_port(),
      "required": list(AHV_GW_REQUIRED),
      "hosts": [],
      "hosts_total": 0,
      "hosts_ok": 0,
      "error": "",
      "cert_dir": "",
  }
  crt, key, cert_dir = _ahv_gw_cert_pair()
  payload["cert_dir"] = cert_dir
  if not crt:
    payload["error"] = (
        "AHV Gateway client certs not found under %s" % (
            getattr(FLAGS, "ahv_gateway_cert_dir", "") or
            AHV_GW_CERT_FALLBACKS[0]))
    LOG.warning("DUMP AHV GW: %s", payload["error"])
    _write_json_file(os.path.join(dest_root, "index.json"), payload)
    return payload
  hosts, disc_errors, disc_sources, local_pc = _ahv_gw_discover_hosts(
      dump_hosts, dump_clusters)
  payload["discovery"] = {
      "sources": disc_sources,
      "errors": disc_errors,
      "local_pc": local_pc,
  }
  payload["hosts_total"] = len(hosts)
  if not hosts:
    payload["error"] = "no PE hypervisor IPs for AHV Gateway collect"
    LOG.warning("DUMP AHV GW: %s", payload["error"])
    _write_json_file(os.path.join(dest_root, "index.json"), payload)
    return payload
  payload["ran"] = True
  deadline = time.time() + timeout_secs
  workers = max(1, int(getattr(FLAGS, "ahv_gateway_workers", 8) or 8))
  LOG.info(
      "DUMP AHV GW start hosts=%s workers=%s timeout=%ss cert=%s",
      len(hosts), workers, timeout_secs, cert_dir)
  recs = []
  if workers == 1 or len(hosts) == 1:
    for host_rec in hosts:
      recs.append(_ahv_gw_collect_one_host(
          host_rec, dest_root, crt, key, deadline))
  else:
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
      futs = [
          pool.submit(
              _ahv_gw_collect_one_host, host_rec, dest_root, crt, key,
              deadline)
          for host_rec in hosts
      ]
      for fut in futs:
        recs.append(fut.result())
  recs.sort(key=lambda item: item.get("ip") or "")
  payload["hosts"] = recs
  payload["hosts_ok"] = sum(1 for rec in recs if rec.get("complete"))
  payload["complete"] = bool(recs) and payload["hosts_ok"] == len(recs)
  if not payload["complete"]:
    bad = [
        "%s:%s" % (rec.get("ip"), ",".join(rec.get("missing") or []))
        for rec in recs if not rec.get("complete")
    ]
    payload["error"] = (
        "AHV Gateway incomplete %s/%s hosts: %s" % (
            payload["hosts_ok"], len(recs), "; ".join(bad[:12])))
    LOG.warning("DUMP AHV GW: %s", payload["error"][:500])
  else:
    LOG.info("DUMP AHV GW complete hosts=%s", len(recs))
  _write_json_file(os.path.join(dest_root, "index.json"), payload)
  return payload


KUBECTL_BIN_CANDIDATES = (
    "/usr/bin/kubectl",
    "/usr/local/bin/kubectl",
    "/home/nutanix/bin/kubectl",
)

# CMSP: dump live OVN NB/SB from the ANC northd pod. Same as:
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
CMSP_OVN_POD = "anc-ovn-0"
CMSP_OVN_CONTAINER = "anc-ovn"
CMSP_OVN_NB_SOCK = "unix:/var/run/ovn/ovnnb_db.sock"
CMSP_OVN_SB_SOCK = "unix:/var/run/ovn/ovnsb_db.sock"

CMSP_OVN_TARGETS = (
    {
        "key": "anc-ovn",
        "app": "anc-ovn",
        "pod": CMSP_OVN_POD,
        "container": CMSP_OVN_CONTAINER,
        "dumps": (
            ("ovsdb-client_dump_nb",
             ["ovsdb-client", "dump", CMSP_OVN_NB_SOCK],
             ("Logical_Switch", "ACL", "NB_Global", "Logical_Router")),
            ("ovsdb-client_dump_sb",
             ["ovsdb-client", "dump", CMSP_OVN_SB_SOCK],
             ("Chassis", "Port_Binding", "Datapath_Binding", "SB_Global")),
        ),
        "files": (
            ("/etc/openvswitch/ovnnb_db.db", "ovnnb_db.db"),
            ("/etc/openvswitch/ovnsb_db.db", "ovnsb_db.db"),
        ),
        "commands": (
            ("ovn-nbctl_show",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "show"]),
            ("ovn-nbctl_ls-list",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "ls-list"]),
            ("ovn-nbctl_lr-list",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "lr-list"]),
            ("ovn-sbctl_show",
             ["ovn-sbctl", "--db=%s" % CMSP_OVN_SB_SOCK, "show"]),
            ("ovn-sbctl_list_Chassis",
             ["ovn-sbctl", "--db=%s" % CMSP_OVN_SB_SOCK, "list", "Chassis"]),
        ),
        "required": ("ovsdb-client_dump_nb", "ovsdb-client_dump_sb"),
    },
    {
        "key": "anc-ovn-ic-db",
        "app": "anc-ovn-ic-db",
        "pod": "anc-ovn-ic-db-0",
        "container": "anc-ovn-ic-db",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovn_ic_nb_db.db", "ovn_ic_nb_db.db"),
            ("/etc/openvswitch/ovn_ic_sb_db.db", "ovn_ic_sb_db.db"),
        ),
        "commands": (
            ("ovn-ic-nbctl_show",
             ["ovn-ic-nbctl",
              "--db=unix:/var/run/ovn/ovn_ic_nb_db.sock", "show"]),
            ("ovn-ic-sbctl_show",
             ["ovn-ic-sbctl",
              "--db=unix:/var/run/ovn/ovn_ic_sb_db.sock", "show"]),
        ),
        "required": (),
    },
    {
        "key": "anc-policydb",
        "app": "anc-policydb",
        "pod": "anc-policydb-0",
        "container": "anc-policydb",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovs-policy-config.db",
             "ovs-policy-config.db"),
        ),
        "commands": (),
        "required": (),
    },
)

_KUBECTL_PREFIX_CACHE = []


def _kubectl_bin():
  for path in KUBECTL_BIN_CANDIDATES:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "kubectl"


def _kubectl_prefix():
  """Prefer passwordless sudo kubectl, matching the CMSP runbook command."""
  global _KUBECTL_PREFIX_CACHE
  if _KUBECTL_PREFIX_CACHE:
    return list(_KUBECTL_PREFIX_CACHE)
  kubectl = _kubectl_bin()
  for prefix in (["sudo", "-n", kubectl], ["sudo", kubectl], [kubectl]):
    rc, _stdout, _stderr = _run_cmd_argv(prefix + ["get", "ns"], 20)
    if rc == 0:
      _KUBECTL_PREFIX_CACHE = list(prefix)
      LOG.info("kubectl via %s", " ".join(prefix))
      return list(prefix)
  _KUBECTL_PREFIX_CACHE = ["sudo", "-n", kubectl]
  return list(_KUBECTL_PREFIX_CACHE)


def _kubectl_argv(extra):
  return _kubectl_prefix() + list(extra)


def _cmsp_ovn_namespace():
  return str(getattr(FLAGS, "cmsp_ovn_namespace", "") or "").strip()


def _kubectl_ns_args(namespace):
  if namespace:
    return ["-n", namespace]
  return []


def _kubectl_dump_looks_ok(path, markers):
  if not os.path.isfile(path) or os.path.getsize(path) < 64:
    return False
  try:
    with open(path, "r") as handle:
      head = handle.read(65536)
  except Exception:
    return False
  low = head.lower()
  if low.startswith("error") or "unable to connect" in low:
    return False
  if any(token in head for token in markers):
    return True
  return os.path.getsize(path) > 4096 and "table" in low


def _kubectl_find_pod(app, preferred_name, namespace=""):
  """Find a Running pod. Prefer anc-ovn-0 as in the runbook."""
  ns_flag = ["-n", namespace] if namespace else ["-A"]
  argv = _kubectl_argv([
      "get", "pods"] + ns_flag + [
      "-o",
      "jsonpath={range .items[*]}{.metadata.namespace}{\"\\t\"}"
      "{.metadata.name}{\"\\t\"}{.status.phase}{\"\\t\"}"
      "{.metadata.labels.app}{\"\\n\"}{end}",
  ])
  rc, stdout, stderr = _run_cmd_argv(argv, 45)
  if rc != 0:
    return "", "", (stderr or stdout or "kubectl get pods failed").strip()[:400]
  matches = []
  for line in (stdout or "").splitlines():
    parts = line.split("\t")
    if len(parts) < 3:
      continue
    ns, name, phase = parts[0].strip(), parts[1].strip(), parts[2].strip()
    label = parts[3].strip() if len(parts) > 3 else ""
    if phase != "Running":
      continue
    if name == preferred_name or label == app or name.startswith(app + "-"):
      matches.append((ns, name))
  if not matches:
    return "", "", "no Running pod %s / app=%s" % (preferred_name, app)
  for ns, name in matches:
    if name == preferred_name:
      return ns, name, ""
  for ns, name in matches:
    if name.endswith("-0"):
      return ns, name, ""
  return matches[0][0], matches[0][1], ""


def _kubectl_cp_file(namespace, pod, container, remote_path, dest_path,
                     timeout_secs):
  os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
  extra = ["cp"]
  extra.extend(_kubectl_ns_args(namespace))
  extra.extend(["%s:%s" % (pod, remote_path), dest_path, "-c", container])
  rc, stdout, stderr = _run_cmd_argv(_kubectl_argv(extra), timeout_secs)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  src = "%s/%s:%s" % (namespace or "default", pod, remote_path)
  rc, stdout, stderr = _run_cmd_argv(
      _kubectl_argv(["cp", src, dest_path, "-c", container]), timeout_secs)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  return False, (stderr or stdout or "kubectl cp failed rc=%s" % rc).strip()[:400]


def _kubectl_exec_to_file(namespace, pod, container, remote_argv, dest_path,
                          timeout_secs):
  """sudo kubectl exec POD -c CONTAINER -- CMD  (never -it)."""
  os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
  extra = ["exec"]
  extra.extend(_kubectl_ns_args(namespace))
  extra.extend([pod, "-c", container, "--"] + list(remote_argv))
  rc, _stdout, stderr = _run_cmd_argv(
      _kubectl_argv(extra), timeout_secs, stdout_path=dest_path)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  return False, (stderr or "kubectl exec failed rc=%s" % rc).strip()[:400]


def _cmsp_ovn_ovsdb_name(path):
  try:
    with open(path, "r") as handle:
      handle.readline()
      schema_line = handle.readline()
  except Exception:
    return ""
  try:
    schema = json.loads(schema_line)
  except Exception:
    return ""
  return str(schema.get("name") or "")


def _collect_cmsp_ovn_target(target, dest_root, namespace, timeout_secs):
  rec = {
      "key": target["key"],
      "app": target["app"],
      "namespace": namespace,
      "pod": "",
      "complete": False,
      "dumps": {},
      "files": {},
      "commands": {},
      "missing": [],
      "error": "",
  }
  dest_dir = os.path.join(dest_root, target["key"])
  cmd_dir = os.path.join(dest_dir, "commands")
  os.makedirs(cmd_dir, exist_ok=True)
  preferred = target.get("pod") or ""
  found_ns, pod, err = _kubectl_find_pod(
      target["app"], preferred, namespace)
  rec["namespace"] = found_ns or namespace
  rec["pod"] = pod or preferred
  if not rec["pod"]:
    rec["error"] = err or "pod not found"
    rec["missing"] = list(target.get("required") or [])
    rec["complete"] = not rec["missing"]
    return rec
  dump_timeout = max(60, min(600, int(timeout_secs)))
  for dump_name, remote_argv, markers in target.get("dumps") or ():
    dest = os.path.join(cmd_dir, dump_name + ".txt")
    ok, dump_err = _kubectl_exec_to_file(
        rec["namespace"], rec["pod"], target["container"], remote_argv,
        dest, dump_timeout)
    looks = bool(ok) and _kubectl_dump_looks_ok(dest, markers)
    rec["dumps"][dump_name] = {
        "ok": looks,
        "bytes": os.path.getsize(dest) if os.path.isfile(dest) else 0,
        "argv": list(remote_argv),
        "error": "" if looks else (
            dump_err or err or "dump missing expected OVN tables"),
    }
    rec["commands"][dump_name] = rec["dumps"][dump_name]
  per_cmd = max(30, min(180, int(timeout_secs)))
  for remote_path, local_name in target.get("files") or ():
    dest = os.path.join(dest_dir, local_name)
    ok, cp_err = _kubectl_cp_file(
        rec["namespace"], rec["pod"], target["container"], remote_path,
        dest, per_cmd)
    rec["files"][local_name] = {
        "ok": ok,
        "bytes": os.path.getsize(dest) if ok else 0,
        "ovsdb_name": _cmsp_ovn_ovsdb_name(dest) if ok else "",
        "error": "" if ok else cp_err,
    }
  for cmd_name, remote_argv in target.get("commands") or ():
    dest = os.path.join(cmd_dir, cmd_name + ".txt")
    ok, cmd_err = _kubectl_exec_to_file(
        rec["namespace"], rec["pod"], target["container"], remote_argv,
        dest, per_cmd)
    rec["commands"][cmd_name] = {
        "ok": ok,
        "bytes": os.path.getsize(dest) if os.path.isfile(dest) else 0,
        "argv": list(remote_argv),
        "error": "" if ok else cmd_err,
    }
  missing = []
  for name in target.get("required") or ():
    if name in rec["dumps"]:
      if not rec["dumps"][name].get("ok"):
        missing.append(name)
    elif name in rec["files"]:
      if not rec["files"][name].get("ok"):
        missing.append(name)
    elif name in rec["commands"]:
      if not rec["commands"][name].get("ok"):
        missing.append(name)
    else:
      missing.append(name)
  rec["missing"] = missing
  rec["complete"] = not missing
  if missing:
    rec["error"] = "missing: %s" % ",".join(missing)
  return rec


def fetch_cmsp_ovn_nb_sb(output_dir, timeout_secs=1800):
  """Dump OVN NB/SB via: sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump ..."""
  dest_root = os.path.join(output_dir, "cmsp_ovn")
  os.makedirs(dest_root, exist_ok=True)
  timeout_secs = max(60, int(timeout_secs or 1800))
  namespace = _cmsp_ovn_namespace()
  payload = {
      "ran": False,
      "complete": False,
      "transport": "kubectl",
      "platform": "cmsp",
      "namespace": namespace,
      "pod": CMSP_OVN_POD,
      "container": CMSP_OVN_CONTAINER,
      "method": (
          "sudo kubectl exec %s -c %s -- ovsdb-client dump %s"
          % (CMSP_OVN_POD, CMSP_OVN_CONTAINER, CMSP_OVN_NB_SOCK)),
      "ssh_to_ahv": False,
      "pods": [],
      "error": "",
      "bundle_dir": dest_root,
  }
  kubectl = _kubectl_bin()
  if not os.path.exists(kubectl) and kubectl == "kubectl":
    which_rc, which_out, _err = _run_cmd_argv(["which", "kubectl"], 10)
    if which_rc != 0 and not which_out.strip():
      payload["error"] = "kubectl not found on this node"
      _write_json_file(os.path.join(dest_root, "index.json"), payload)
      return payload

  deadline = time.time() + timeout_secs
  backoff = 2
  last = []
  while time.time() < deadline:
    last = []
    for target in CMSP_OVN_TARGETS:
      remain = max(60, int(deadline - time.time()))
      last.append(_collect_cmsp_ovn_target(
          target, dest_root, namespace, remain))
    payload["pods"] = last
    payload["ran"] = True
    if last:
      payload["namespace"] = last[0].get("namespace") or namespace
      payload["pod"] = last[0].get("pod") or CMSP_OVN_POD
    if all(rec.get("complete") for rec in last):
      payload["complete"] = True
      payload["error"] = ""
      _write_json_file(os.path.join(dest_root, "index.json"), payload)
      LOG.info(
          "CMSP OVN NB/SB dumped via sudo kubectl exec %s -c %s -- ovsdb-client dump",
          payload.get("pod"), CMSP_OVN_CONTAINER)
      return payload
    missing = []
    for rec in last:
      missing.extend(
          "%s:%s" % (rec.get("key"), name)
          for name in rec.get("missing") or [])
    LOG.info(
        "CMSP OVN collect incomplete (%s); retrying",
        ",".join(missing) or "unknown")
    sleep_for = min(backoff, max(0, int(deadline - time.time())))
    if sleep_for <= 0:
      break
    time.sleep(sleep_for)
    backoff = min(20, backoff * 2)

  payload["pods"] = last
  payload["ran"] = True
  payload["complete"] = False
  missing = []
  for rec in last:
    missing.extend(
        "%s:%s" % (rec.get("key"), name)
        for name in rec.get("missing") or [])
  payload["error"] = "deadline with missing: %s" % (
      ",".join(missing) or "unknown")
  _write_json_file(os.path.join(dest_root, "index.json"), payload)
  return payload

def dump_pc(output_dir, workers=8, skip_idf=False, skip_ahv=False,
            skip_cmsp=False, skip_atlas=False,
            ahv_gw_timeout=1800, cmsp_ovn_timeout=1800, atlas_timeout=1800,
            atlas_get_workers=32, idf_timeout=180,
            fail_on_error=False, log_file="", combined_path=""):
  """PC dump only: idfcli + OVN + OVS + atlas_cli. No convert or enrich."""
  os.makedirs(output_dir, exist_ok=True)
  combined_path = combined_path or os.path.join(output_dir, "all.json")
  log_file = log_file or os.path.join(output_dir, "dump.log")
  _setup_logging(log_file)
  workers = max(1, int(workers))
  LOG.info("logs=%s combined=%s output_dir=%s",
           log_file, combined_path, output_dir)
  LOG.info(
      "dump=idfcli+OVN+OVS+atlas (no convert) skip_idfcli=%s "
      "skip_ahv_gateway=%s skip_cmsp_ovn=%s skip_atlas=%s workers=%s "
      "ahv_gw_timeout=%ss cmsp_ovn_timeout=%ss atlas_timeout=%ss",
      skip_idf, skip_ahv, skip_cmsp, skip_atlas, workers,
      ahv_gw_timeout, cmsp_ovn_timeout, atlas_timeout)

  errors = {}
  payload = {
      "source": "flow_pc_dump",
      "collects": ["idfcli", "ovn", "ovs", "atlas"],
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "idfcli": {},
      "ahv_gateway": {},
      "cmsp_ovn": {},
      "atlas": {},
      "port_set_list": [],
      "port_set_get": {},
  }

  LOG.info("Collecting idfcli + AHV Gateway OVS + CMSP OVN + atlas_cli")
  with ThreadPoolExecutor(max_workers=4) as pool:
    idf_fut = None
    ahv_gw_fut = None
    cmsp_ovn_fut = None
    atlas_fut = None
    if skip_idf:
      LOG.info("Skipping idfcli (--skip_idfcli)")
      payload["idfcli"] = {"ran": False, "error": "skipped (--skip_idfcli)"}
    else:
      idf_fut = pool.submit(
          dump_idfcli, output_dir, min(8, workers), idf_timeout)
    if skip_ahv:
      LOG.info("Skipping AHV Gateway collect (--skip_ahv_gateway)")
      payload["ahv_gateway"] = {
          "ran": False,
          "complete": False,
          "error": "skipped (--skip_ahv_gateway)",
          "ssh_to_ahv": False,
      }
    else:
      ahv_gw_fut = pool.submit(
          fetch_ahv_gateway_host_state, output_dir, None, None, ahv_gw_timeout)
    if skip_cmsp:
      LOG.info("Skipping CMSP OVN NB/SB kubectl dump (--skip_cmsp_ovn)")
      payload["cmsp_ovn"] = {
          "ran": False,
          "complete": False,
          "error": "skipped (--skip_cmsp_ovn)",
          "ssh_to_ahv": False,
          "transport": "kubectl",
      }
    else:
      cmsp_ovn_fut = pool.submit(
          fetch_cmsp_ovn_nb_sb, output_dir, cmsp_ovn_timeout)
    if skip_atlas:
      LOG.info("Skipping atlas_cli (--skip_atlas)")
      payload["atlas"] = {"ran": False, "error": "skipped (--skip_atlas)"}
    else:
      atlas_fut = pool.submit(
          dump_atlas_port_sets, output_dir,
          max(1, int(atlas_get_workers)), atlas_timeout)
    if idf_fut is not None:
      try:
        index, idf_errors = idf_fut.result()
        payload["idfcli"] = index
        errors.update(idf_errors)
      except Exception as err:
        errors["idfcli"] = str(err)
        payload["idfcli"] = {"ran": False, "error": str(err)}
        LOG.error("DATASET idfcli FAILED: %s", err)
    if ahv_gw_fut is not None:
      try:
        payload["ahv_gateway"] = ahv_gw_fut.result()
      except Exception as err:
        errors["ahv_gateway"] = str(err)
        payload["ahv_gateway"] = {
            "ran": False,
            "complete": False,
            "error": str(err),
            "ssh_to_ahv": False,
        }
        LOG.error("DATASET ahv_gateway FAILED: %s", err)
      else:
        gw = payload.get("ahv_gateway") or {}
        if gw.get("complete"):
          LOG.info("AHV Gateway complete; OVS/virsh/tap captured")
        elif gw.get("error"):
          errors["ahv_gateway"] = gw["error"]
    if cmsp_ovn_fut is not None:
      try:
        payload["cmsp_ovn"] = cmsp_ovn_fut.result()
      except Exception as err:
        errors["cmsp_ovn"] = str(err)
        payload["cmsp_ovn"] = {
            "ran": False,
            "complete": False,
            "error": str(err),
            "transport": "kubectl",
            "ssh_to_ahv": False,
        }
        LOG.error("DATASET cmsp_ovn FAILED: %s", err)
      else:
        cmsp = payload.get("cmsp_ovn") or {}
        if not cmsp.get("complete") and cmsp.get("error"):
          errors["cmsp_ovn"] = cmsp["error"]
    if atlas_fut is not None:
      try:
        payload["atlas"] = atlas_fut.result()
      except Exception as err:
        errors["atlas"] = str(err)
        payload["atlas"] = {"ran": False, "error": str(err)}
        LOG.error("DATASET atlas FAILED: %s", err)
      else:
        atlas_rec = payload.get("atlas") or {}
        errors.update(atlas_rec.get("errors") or {})

  uuids = fetch_unique_uuids()
  payload["vlan_unique_uuid"] = uuids.get("vlan_unique_uuid") or ""
  payload["global_unique_uuid"] = uuids.get("global_unique_uuid") or ""
  _write_json_file(os.path.join(output_dir, "unique_uuids.json"), uuids)
  payload["port_set_list"] = _load_json_if_present(
      os.path.join(output_dir, "port_set_list.json"), [])
  payload["port_set_get"] = _normalize_port_set_get(_load_json_if_present(
      os.path.join(output_dir, "port_set_get.json"), {}))

  payload["dump_errors"] = errors
  _write_json_file(
      os.path.join(output_dir, "ahv_gateway.json"),
      payload.get("ahv_gateway") or {})
  _write_json_file(
      os.path.join(output_dir, "cmsp_ovn.json"),
      payload.get("cmsp_ovn") or {})
  _write_json_file(os.path.join(output_dir, "dump_errors.json"), errors)
  _write_json_file(combined_path, payload)

  LOG.info("===== DUMP SUMMARY (idfcli + OVN + OVS + atlas) =====")
  LOG.info("  %-22s %s", "vlan_unique_uuid",
           payload.get("vlan_unique_uuid") or "<empty>")
  LOG.info("  %-22s %s", "global_unique_uuid",
           payload.get("global_unique_uuid") or "<empty>")
  types = (payload.get("idfcli") or {}).get("entity_types") or {}
  LOG.info("  %-22s %s types", "idfcli", len(types))
  for name, rec in sorted(types.items()):
    LOG.info(
        "  %-22s count=%s err=%s",
        name, rec.get("count"), rec.get("error") or "<none>")
  gw = payload.get("ahv_gateway") or {}
  LOG.info(
      "  %-22s ran=%s complete=%s hosts=%s/%s error=%s",
      "ahv_gateway",
      gw.get("ran"),
      gw.get("complete"),
      gw.get("hosts_ok"),
      gw.get("hosts_total"),
      (gw.get("error") or "")[:80] or "<none>")
  for host_rec in gw.get("hosts") or []:
    LOG.info(
        "  %-22s ip=%s name=%s ok=%s missing=%s err=%s",
        "",
        host_rec.get("ip") or "",
        host_rec.get("name") or "",
        host_rec.get("complete"),
        ",".join(host_rec.get("missing") or []) or "<none>",
        (host_rec.get("error") or "")[:50] or "<none>")
  cmsp = payload.get("cmsp_ovn") or {}
  LOG.info(
      "  %-22s ran=%s complete=%s pods=%s error=%s",
      "cmsp_ovn",
      cmsp.get("ran"),
      cmsp.get("complete"),
      len(cmsp.get("pods") or []),
      (cmsp.get("error") or "")[:80] or "<none>")
  for pod_rec in cmsp.get("pods") or []:
    LOG.info(
        "  %-22s key=%s pod=%s ok=%s missing=%s err=%s",
        "",
        pod_rec.get("key") or "",
        pod_rec.get("pod") or "",
        pod_rec.get("complete"),
        ",".join(pod_rec.get("missing") or []) or "<none>",
        (pod_rec.get("error") or "")[:50] or "<none>")
  atlas = payload.get("atlas") or {}
  LOG.info(
      "  %-22s ran=%s list=%s get=%s platform=%s error=%s",
      "atlas",
      atlas.get("ran"),
      atlas.get("list_count"),
      atlas.get("get_count"),
      atlas.get("platform") or "",
      (atlas.get("error") or "")[:80] or "<none>")
  LOG.info("  %-22s %s", "port_set_list", len(payload.get("port_set_list") or []))
  LOG.info("  %-22s %s", "port_set_get", len(payload.get("port_set_get") or {}))
  if errors:
    LOG.warning("Failed datasets: %s", ", ".join(sorted(errors)))
    if fail_on_error:
      return 2
  LOG.info("Done. Index: %s", combined_path)
  LOG.info("idfcli=%s/idfcli  ovs=%s/ahv_gateway  ovn=%s/cmsp_ovn  atlas=%s",
           output_dir, output_dir, output_dir, output_dir)
  LOG.info("Convert locally: python3 flow_pc_process.py --dump_dir %s",
           output_dir)
  return 0


def dump_collect(*args, **kwargs):
  return dump_pc(*args, **kwargs)


def build_parser():
  ap = argparse.ArgumentParser(
      prog="flow_pc_dump.py",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      description=(
          "PC dump only: idfcli, atlas_cli, AHV Gateway OVS, and CMSP OVN. "
          "No convert or enrich. Run on PCVM with system python3."),
      epilog="""
On PC (collect only, system python3):

  python3 %(prog)s --output_dir %(out)s

Writes under --output_dir:
  idfcli/<entity_type>.json and .txt
  ahv_gateway/   (OVS via AHV Gateway mTLS :7030)
  cmsp_ovn/      (OVN NB/SB via kubectl ovsdb-client dump)
  port_set_list.json / port_set_get.json  (atlas_cli)
  unique_uuids.json dump.log all.json dump_errors.json

Convert/enrich locally (not on PC):

  python3 flow_pc_process.py --dump_dir <dump> --ingest --log_bundle_id N
""" % {"prog": "flow_pc_dump.py", "out": DEFAULT_OUTPUT})
  ap.add_argument(
      "--output_dir", default=DEFAULT_OUTPUT,
      help="Directory for idfcli/, ahv_gateway/, cmsp_ovn/, atlas")
  ap.add_argument("--output", default="", help="Combined JSON path")
  ap.add_argument("--log_file", default="", help="Log file path")
  ap.add_argument("--workers", type=int, default=16)
  ap.add_argument("--dataset_timeout_secs", type=int, default=180)
  ap.add_argument("--fail_on_error", action="store_true")
  ap.add_argument("--skip_idfcli", action="store_true")
  ap.add_argument("--skip_ahv_gateway", action="store_true")
  ap.add_argument("--skip_cmsp_ovn", action="store_true")
  ap.add_argument("--skip_atlas", action="store_true")
  ap.add_argument("--ahv_gateway_timeout_secs", type=int, default=1800)
  ap.add_argument("--ahv_gateway_class_timeout_secs", type=int, default=300)
  ap.add_argument("--ahv_gateway_workers", type=int, default=8)
  ap.add_argument("--ahv_gateway_port", type=int, default=7030)
  ap.add_argument(
      "--ahv_gateway_cert_dir", default="/home/certs/ClusterHealthService")
  ap.add_argument("--cmsp_ovn_timeout_secs", type=int, default=1800)
  ap.add_argument("--cmsp_ovn_namespace", default="")
  ap.add_argument("--atlas_timeout_secs", type=int, default=1800)
  ap.add_argument("--atlas_get_workers", type=int, default=32)
  return ap


def main(argv=None):
  argv = list(sys.argv if argv is None else argv)
  parser = build_parser()
  args, _unknown = parser.parse_known_args(argv[1:])
  FLAGS.ahv_gateway_class_timeout_secs = args.ahv_gateway_class_timeout_secs
  FLAGS.ahv_gateway_workers = args.ahv_gateway_workers
  FLAGS.ahv_gateway_port = args.ahv_gateway_port
  FLAGS.ahv_gateway_cert_dir = args.ahv_gateway_cert_dir
  FLAGS.cmsp_ovn_namespace = args.cmsp_ovn_namespace
  return dump_pc(
      args.output_dir or DEFAULT_OUTPUT,
      workers=max(1, int(args.workers)),
      skip_idf=bool(args.skip_idfcli),
      skip_ahv=bool(args.skip_ahv_gateway),
      skip_cmsp=bool(args.skip_cmsp_ovn),
      skip_atlas=bool(args.skip_atlas),
      ahv_gw_timeout=max(60, int(args.ahv_gateway_timeout_secs)),
      cmsp_ovn_timeout=max(60, int(args.cmsp_ovn_timeout_secs)),
      atlas_timeout=max(60, int(args.atlas_timeout_secs)),
      atlas_get_workers=max(1, int(args.atlas_get_workers)),
      idf_timeout=max(60, int(args.dataset_timeout_secs)),
      fail_on_error=bool(args.fail_on_error),
      log_file=args.log_file or "",
      combined_path=args.output or "")


if __name__ == "__main__":
  sys.exit(main(sys.argv))
