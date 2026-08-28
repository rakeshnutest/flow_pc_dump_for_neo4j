#!/usr/bin/env python3
"""PC collect: dump one JSON file (VM, IP, NIC, host, cluster).

System python3 on the PC. idfcli only.

  python3 vm_host_collect.py
"""
from __future__ import print_function

import argparse
import codecs
import json
import os
import shutil
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
)
DEFAULT_OUT = "/tmp/vms.json"


def as_uuid(value):
  if isinstance(value, dict):
    value = value.get("ext_id") or value.get("uuid") or value.get("id")
  if value is None or value == "" or value == b"":
    return ""
  if hasattr(value, "hex"):
    hex_str = str(value.hex).replace("-", "").lower()
    if len(hex_str) == 32 and all(c in "0123456789abcdef" for c in hex_str):
      return "%s-%s-%s-%s-%s" % (
          hex_str[0:8], hex_str[8:12], hex_str[12:16],
          hex_str[16:20], hex_str[20:32])
  if isinstance(value, (bytes, bytearray)):
    raw = bytes(value)
    if len(raw) == 16:
      return as_uuid(uuid.UUID(bytes=raw))
    try:
      value = raw.decode("utf-8")
    except Exception:
      return ""
  text = str(value).strip()
  if "::" in text:
    text = text.split("::", 1)[0]
  compact = text.replace("-", "").lower()
  if len(compact) == 32 and all(c in "0123456789abcdef" for c in compact):
    return "%s-%s-%s-%s-%s" % (
        compact[0:8], compact[8:12], compact[12:16],
        compact[16:20], compact[20:32])
  return ""


def first_attr(row, *names, default=None):
  for name in names:
    if row.get(name) not in (None, "", []):
      return row.get(name)
  return default


def as_list(value):
  if value is None:
    return []
  if isinstance(value, list):
    return value
  return [value]


def collect_ips(*groups):
  out, seen = [], set()
  for group in groups:
    for ip in as_list(group):
      text = str(ip).strip()
      if "/" in text and not text.startswith("/"):
        text = text.split("/", 1)[0]
      if not text or text in seen:
        continue
      seen.add(text)
      out.append(text)
  return out


def idf_unquote(raw):
  try:
    return codecs.decode(raw, "unicode_escape")
  except Exception:
    return raw


def idf_json_value(value):
  if value is None:
    return None
  if isinstance(value, list):
    return [idf_json_value(item) for item in value]
  if not isinstance(value, dict):
    return value
  if "str_list" in value:
    inner = value.get("str_list")
    items = list(inner.get("value_list") or []) if isinstance(inner, dict) else (
        inner if isinstance(inner, list) else [])
    out = []
    for item in items:
      if isinstance(item, str):
        out.append(as_uuid(item) or idf_unquote(item))
      else:
        out.append(item)
    return out
  if "value_list" in value and set(value.keys()) <= set(
      ("value_list", "timestamp_usecs")):
    return [idf_json_value(item) for item in (value.get("value_list") or [])]
  if "str_value" in value:
    text = str(value.get("str_value") or "")
    return as_uuid(text) or idf_unquote(text)
  if "bool_value" in value:
    return bool(value.get("bool_value"))
  for key in ("int64_value", "uint64_value", "int32_value"):
    if key in value:
      try:
        return int(value.get(key))
      except (TypeError, ValueError):
        return value.get(key)
  if "bytes_value" in value or "bytes_list" in value:
    return None
  return value


def flatten_entity(ent):
  if not isinstance(ent, dict):
    return None
  attrs = {}
  guid = ent.get("entity_guid") or {}
  if isinstance(guid, dict):
    uid = as_uuid(guid.get("entity_id") or "")
    if uid:
      attrs["ext_id"] = uid
  adm = ent.get("attribute_data_map")
  items = []
  if isinstance(adm, list):
    items = adm
  elif isinstance(adm, dict):
    if adm.get("name"):
      items = [adm]
    else:
      items = [{"name": key, "value": val} for key, val in adm.items()]
  if not items:
    row = dict(ent)
    row.pop("attribute_data_map", None)
    row.pop("__zprotobuf__", None)
    if attrs.get("ext_id"):
      row.setdefault("ext_id", attrs["ext_id"])
    return row
  for item in items:
    if not isinstance(item, dict):
      continue
    name = item.get("name") or ""
    if not name or name == "__zprotobuf__":
      continue
    if "value" in item:
      attrs[name] = idf_json_value(item.get("value"))
    else:
      attrs[name] = idf_json_value(
          {key: val for key, val in item.items() if key != "name"})
  return attrs or None


def loaded_rows(parsed):
  ents = []
  if isinstance(parsed, list):
    ents = parsed
  elif isinstance(parsed, dict):
    raw = parsed.get("entity")
    if raw is None:
      raw = parsed.get("entities")
    if raw is None:
      raw = parsed.get("data")
    if isinstance(raw, list):
      ents = raw
    elif isinstance(raw, dict) and raw:
      ents = [raw]
    elif parsed.get("attribute_data_map") or parsed.get("entity_guid"):
      ents = [parsed]
  out = []
  for ent in ents:
    if not isinstance(ent, dict):
      continue
    if ent.get("attribute_data_map") or ent.get("entity_guid"):
      flat = flatten_entity(ent)
      if flat:
        out.append(flat)
      continue
    row = dict(ent)
    row.pop("__zprotobuf__", None)
    out.append(row)
  return out


def parse_idf_stdout(stdout):
  text = (stdout or b"").decode("utf-8", "replace") if isinstance(
      stdout, (bytes, bytearray)) else (stdout or "")
  if not text.strip():
    return [], "empty stdout"
  try:
    parsed = json.loads(text)
  except ValueError as exc:
    return [], "invalid json: %s" % exc
  return loaded_rows(parsed), ""


def idfcli_bin(explicit=""):
  if explicit:
    return explicit
  for path in IDF_BINS:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  found = shutil.which("idfcli")
  return found or "idfcli"


def run_idfcli(entity_type, binary, timeout):
  err, stdout = "", b""
  for argv in (
      [binary, "get", "entity", "-e", entity_type, "--all", "-o", "json"],
      [binary, "get", "entitytype", "-e", entity_type, "-o", "json"]):
    try:
      proc = subprocess.run(
          argv, capture_output=True, check=False, timeout=timeout)
    except Exception as exc:
      err = "%s" % exc
      continue
    stdout = proc.stdout or b""
    if proc.returncode == 0 and stdout.strip():
      rows, parse_err = parse_idf_stdout(stdout)
      if parse_err:
        err = parse_err
        continue
      return rows, ""
    err = "rc=%s %s" % (
        proc.returncode,
        (proc.stderr or b"").decode("utf-8", "replace")[:200])
  return [], err


def load_type(entity_type, binary, timeout, file_dir):
  if file_dir:
    path = os.path.join(file_dir, "%s.json" % entity_type)
    if not os.path.isfile(path):
      return [], "%s: not in dump" % entity_type
    try:
      with open(path, "rb") as handle:
        raw = handle.read()
    except Exception as exc:
      return [], "%s: %s" % (entity_type, exc)
    rows, err = parse_idf_stdout(raw)
    if err:
      return [], "%s: %s" % (entity_type, err)
    return rows, ""
  rows, err = run_idfcli(entity_type, binary, timeout)
  if err:
    return [], "%s: %s" % (entity_type, err)
  return rows, ""


def first_nonempty(types, binary, timeout, file_dir):
  errors, rows = [], []
  for entity_type in types:
    parsed, err = load_type(entity_type, binary, timeout, file_dir)
    if err:
      errors.append(err)
    if parsed:
      rows = parsed
      break
  return rows, errors


def subnet_type_name(value, vpc_ref=None, vlan_id=None, advanced=None):
  if advanced is False:
    return "VLAN"
  text = "" if value in (None, "") else str(value).strip()
  upper = text.upper().lstrip("K")
  if upper in ("VLAN", "0"):
    return "VLAN"
  if upper in ("OVERLAY", "1"):
    return "OVERLAY"
  if vpc_ref:
    return "OVERLAY"
  if vlan_id not in (None, "", 0, "0"):
    return "VLAN"
  return text or "VLAN"


def as_bool(value, default=False):
  if value is None or value == "":
    return default
  if isinstance(value, bool):
    return value
  text = str(value).strip().lower()
  if text in ("true", "1", "yes"):
    return True
  if text in ("false", "0", "no"):
    return False
  return default


def map_vm(row):
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "vm_uuid", "uuid", "id")),
      "name": str(first_attr(row, "vm_name", "name", "display_name") or ""),
      "host": as_uuid(first_attr(row, "node", "host_uuid", "node_uuid", "host")),
      "cluster": as_uuid(first_attr(row, "cluster", "cluster_uuid")),
      "cluster_name": str(first_attr(row, "cluster_name", "clusterName") or ""),
      "nic_ids": [as_uuid(x) for x in as_list(
          first_attr(row, "virtual_nic_uuids", "nic_uuid", default=[])) if as_uuid(x)],
      "ips": collect_ips(
          row.get("ip_addresses"), row.get("ipv4_addresses"),
          row.get("vm_ipv4_addresses"), row.get("ipv6_addresses")),
      "mac": str(first_attr(row, "mac_address", "mac") or ""),
      "subnet_id": as_uuid(first_attr(row, "subnet_uuid", "virtual_network_uuid")),
  }


def map_nic(row):
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")),
      "vm": as_uuid(first_attr(row, "vm", "vm_uuid")),
      "subnet_id": as_uuid(first_attr(
          row, "virtual_network", "subnet_uuid", "network_uuid")),
      "mac": str(first_attr(row, "mac_address", "mac") or ""),
      "ips": collect_ips(
          row.get("ipv4_addresses"), row.get("assigned_ipv4_addresses"),
          row.get("ipv6_addresses"), row.get("assigned_ipv6_addresses"),
          row.get("ip_addresses")),
      "cluster": as_uuid(first_attr(row, "cluster", "cluster_uuid")),
      "cluster_name": str(first_attr(row, "cluster_name") or ""),
  }


def map_host(row):
  ips = collect_ips(
      row.get("ipv4_addresses"), row.get("ip_address"),
      row.get("hypervisor_ip"), row.get("external_ip"))
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id", "node_uuid")),
      "host": str(first_attr(row, "host_name", "node_name", "name") or ""),
      "host_ip": ips[0] if ips else "",
      "cluster_uuid": as_uuid(first_attr(row, "cluster", "cluster_uuid", "cluster_id")),
      "cluster": str(first_attr(row, "cluster_name") or ""),
  }


def map_cluster(row):
  return {
      "ext_id": as_uuid(first_attr(
          row, "ext_id", "uuid", "id", "cluster_uuid", "clusterUuid")),
      "name": str(first_attr(row, "name", "cluster_name", "clusterName") or ""),
  }


def map_subnet(row):
  vpc_ref = as_uuid(first_attr(
      row, "overlay_network_uuid", "vpc_uuid", "vpc_reference"))
  vlan_id = first_attr(row, "vlan_id", "vlan")
  advanced = first_attr(
      row, "is_advanced_networking", "advanced_networking",
      "advance_vlan", "is_advanced")
  advanced_bool = None if advanced in (None, "") else as_bool(advanced, False)
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")),
      "name": str(first_attr(row, "name", "subnet_name") or ""),
      "subnet_type": subnet_type_name(
          first_attr(row, "subnet_type", "type"), vpc_ref, vlan_id, advanced_bool),
  }


def unique_mapped(rows, mapper):
  out, seen = [], set()
  for row in rows or []:
    rec = mapper(row)
    uid = rec.get("ext_id") or ""
    if not uid or uid in seen:
      continue
    seen.add(uid)
    out.append(rec)
  return out


  return out


def inventory_rows(vms, nics, hosts, clusters, subnets):
  cluster_names = {}
  for rec in clusters:
    if rec.get("ext_id"):
      cluster_names[rec["ext_id"]] = rec.get("name") or ""
  host_by = {}
  for rec in hosts:
    uid = rec.get("ext_id") or ""
    if not uid:
      continue
    cluster_uuid = rec.get("cluster_uuid") or ""
    host_by[uid] = {
        "host": rec.get("host") or "",
        "host_ip": rec.get("host_ip") or "",
        "cluster_uuid": cluster_uuid,
        "cluster": rec.get("cluster") or cluster_names.get(cluster_uuid, ""),
    }
  sub_by = {rec["ext_id"]: rec for rec in subnets if rec.get("ext_id")}
  nics_by_vm = {}
  for nic in nics:
    vm_id = nic.get("vm") or ""
    if vm_id:
      nics_by_vm.setdefault(vm_id, []).append(nic)
  rows = []
  for vm in vms:
    vm_uuid = vm.get("ext_id") or ""
    host_uuid = vm.get("host") or ""
    host_rec = host_by.get(host_uuid) or {}
    cluster_uuid = (
        host_rec.get("cluster_uuid") or vm.get("cluster") or "")
    cluster_name = (
        host_rec.get("cluster") or cluster_names.get(cluster_uuid, "")
        or vm.get("cluster_name") or "")
    vm_nics = nics_by_vm.get(vm_uuid) or []
    if not vm_nics:
      vm_nics = [{
          "ext_id": (vm.get("nic_ids") or [""])[0] if vm.get("nic_ids") else "",
          "mac": vm.get("mac") or "",
          "ips": vm.get("ips") or [],
          "subnet_id": vm.get("subnet_id") or "",
      }]
    for nic in vm_nics:
      subnet_uuid = nic.get("subnet_id") or ""
      dump_sub = sub_by.get(subnet_uuid) or {}
      rows.append({
          "vm": vm.get("name") or "",
          "vm_uuid": vm_uuid,
          "nic_uuid": nic.get("ext_id") or "",
          "mac": nic.get("mac") or "",
          "ip": ",".join(nic.get("ips") or []),
          "subnet": dump_sub.get("name") or "",
          "subnet_uuid": subnet_uuid,
          "subnet_type": dump_sub.get("subnet_type") or "",
          "host": host_rec.get("host") or "",
          "host_uuid": host_uuid,
          "host_ip": host_rec.get("host_ip") or "",
          "cluster": cluster_name,
          "cluster_uuid": cluster_uuid,
      })
  return rows


def log(msg):
  sys.stderr.write(msg + "\n")


def collect(binary, timeout, file_dir, workers):
  def _group(name, types, mapper):
    raw, errors = first_nonempty(types, binary, timeout, file_dir)
    for err in errors:
      log("WARN %s" % err)
    mapped = unique_mapped(raw, mapper)
    log("idfcli %s raw=%s mapped=%s" % (name, len(raw), len(mapped)))
    return mapped

  with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
    fut_vms = pool.submit(
        _group, "vms", ("vm", "mh_vm", "ahv_vm"), map_vm)
    fut_nics = pool.submit(
        _group, "nics", ("virtual_nic",), map_nic)
    fut_hosts = pool.submit(
        _group, "hosts", ("node", "host", "ahv_host"), map_host)
    fut_clusters = pool.submit(
        _group, "clusters", ("cluster",), map_cluster)
    fut_subnets = pool.submit(
        _group, "subnets", ("virtual_network", "subnet"), map_subnet)
    vms = fut_vms.result()
    nics = fut_nics.result()
    hosts = fut_hosts.result()
    clusters = fut_clusters.result()
    subnets = fut_subnets.result()
  return inventory_rows(vms, nics, hosts, clusters, subnets)


def main(argv=None):
  ap = argparse.ArgumentParser(
      description="Dump VM/IP/NIC/host/cluster JSON via idfcli.")
  ap.add_argument(
      "--out", default=DEFAULT_OUT,
      help="JSON path. Default: %s" % DEFAULT_OUT)
  ap.add_argument("--idfcli", default="", help="idfcli binary path.")
  ap.add_argument("--timeout_secs", type=int, default=180)
  ap.add_argument("--workers", type=int, default=5)
  args = ap.parse_args(argv)
  binary = idfcli_bin(args.idfcli)
  if not shutil.which(binary) and not (
      os.path.exists(binary) and os.access(binary, os.X_OK)):
    log("idfcli not found (tried %s)" % binary)
    return 2
  log("idfcli %s" % binary)
  rows = collect(binary, max(30, int(args.timeout_secs)), "", args.workers)
  if not rows:
    log("no VMs from idfcli")
    return 2
  out_path = os.path.abspath(args.out)
  parent = os.path.dirname(out_path)
  if parent:
    os.makedirs(parent, exist_ok=True)
  with open(out_path, "w") as handle:
    json.dump(rows, handle, indent=2)
    handle.write("\n")
  log("wrote %s rows=%s" % (out_path, len(rows)))
  return 0


if __name__ == "__main__":
  sys.exit(main())
