#!/usr/bin/env python3
"""Standalone PC collect: VM / NIC / host / cluster + categories + VPC.

Runs on the PC with system python3. Uses idfcli only.
Does **not** need flow_pc_dump.py, flow_pc_process.py, or flow_pc_map.py.

Each JSON row is one NIC, with:
  vm, ip, nic, host, cluster,
  vm_category / vm_category_uuid,
  subnet_category / subnet_category_uuid,
  vpc_category / vpc_category_uuid,
  vpc / vpc_uuid / vpc_type

  python3 vm_host_collect.py
  python3 vm_host_collect.py --out /tmp/vms.json
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
from concurrent.futures import ThreadPoolExecutor, as_completed

IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
)
ATLAS_BINS = (
    "/usr/local/nutanix/bin/atlas_cli",
    "/home/nutanix/bin/atlas_cli",
    "/home/nutanix/atlas/bin/atlas_cli",
)
DEFAULT_OUT = "/tmp/vms_port_set.json"
UUID_ZERO = "00000000-0000-0000-0000-000000000000"
ALL_VLAN_VPC_UUID = "00000000-0000-0000-0000-000000000001"
ALL_VLAN_VPC_NAME = "VLAN"


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
    return [], ""
  if text.strip().lower().startswith("notfound"):
    return [], ""
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


def load_all(types, binary, timeout, file_dir):
  errors, rows = [], []
  for entity_type in types:
    parsed, err = load_type(entity_type, binary, timeout, file_dir)
    if err:
      errors.append(err)
    rows.extend(parsed or [])
  return rows, errors


def looks_uuid(text):
  return bool(as_uuid(text))


def prefer_human_key(old, new):
  old = str(old or "").strip()
  new = str(new or "").strip()
  if new and not looks_uuid(new):
    return new
  if old and not looks_uuid(old):
    return old
  return new or old


def category_ids_from_row(row):
  raw = first_attr(row, "category_id_list", "category_ids", "categories", default=[])
  ids = []
  for item in as_list(raw):
    if isinstance(item, dict):
      cat_id = as_uuid(item.get("ext_id") or item.get("uuid"))
    else:
      cat_id = as_uuid(item)
    if cat_id and cat_id not in ids:
      ids.append(cat_id)
  return ids


def mapping_cat_names(row):
  names = []
  for item in as_list(first_attr(
      row, "categories_mapping_list", "category_mapping_list", default=[])):
    if isinstance(item, dict):
      key = item.get("key") or item.get("name") or ""
      value = item.get("value") or ""
      text = ("%s:%s" % (key, value)).strip(":") if key or value else ""
    else:
      text = str(item).strip()
    if not text or looks_uuid(text):
      continue
    if text not in names:
      names.append(text)
  return names


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


def vpc_name_from_subnet(name):
  text = str(name or "").strip()
  if not text:
    return ""
  lower = text.lower()
  for token in ("_subnet_", "-subnet-"):
    idx = lower.rfind(token)
    if idx > 0:
      return text[:idx]
  return ""


def vpc_display_name(vpc_ref, subnet_name=None, existing=""):
  if vpc_ref == ALL_VLAN_VPC_UUID:
    return ALL_VLAN_VPC_NAME
  name = str(existing or "").strip()
  if name and name.lower() not in ("unnamed", "(unnamed)", "none", "null"):
    return name
  inferred = vpc_name_from_subnet(subnet_name)
  if inferred:
    return inferred
  ext = str(vpc_ref or "")
  return ("VPC_%s" % ext[:8]) if ext else ""


def cap_target(kind):
  compact = str(kind or "").lower().replace(" ", "").replace("-", "_").lstrip("k")
  if compact in ("vpc", "virtual_private_cloud") or (
      "vpc" in compact and "subnet" not in compact and "route" not in compact):
    return "vpc"
  if compact in ("subnet", "virtual_network", "overlay_subnet"):
    return "subnet"
  if compact in ("vm", "mh_vm", "ahv_vm", "virtual_machine"):
    return "vm"
  return ""


def category_label(cat):
  key = str(cat.get("key") or "").strip()
  value = str(cat.get("value") or "").strip()
  if key and value:
    return "%s:%s" % (key, value)
  return key or value or cat.get("ext_id") or ""


def format_cats(cat_ids, extra_names, cat_by_id):
  """Return (name_csv, uuid_csv) in the same order."""
  names, uuids, seen = [], [], set()
  for cid in cat_ids or []:
    if not cid or cid in seen:
      continue
    seen.add(cid)
    label = category_label(cat_by_id.get(cid) or {}) or cid
    names.append(label)
    uuids.append(cid)
  for extra in extra_names or []:
    if not extra or extra in seen or extra in names:
      continue
    # name-only fallback: keep CSV slots aligned with an empty UUID
    seen.add(extra)
    names.append(extra)
    uuids.append("")
  return ",".join(names), ",".join(uuids)


def apply_caps(caps):
  stores = {"vm": {}, "subnet": {}, "vpc": {}}

  def add(kind, eid, cats, names):
    rec = stores[kind].setdefault(eid, {"ids": [], "names": []})
    for cid in cats or []:
      if cid and cid not in rec["ids"]:
        rec["ids"].append(cid)
    for name in names or []:
      if name and name not in rec["names"]:
        rec["names"].append(name)

  for cap in caps or []:
    target = cap_target(cap.get("kind"))
    if not target:
      continue
    for eid in cap.get("ids") or []:
      add(target, eid, cap.get("category_ids"), cap.get("category_names"))
  return stores


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
  subnet_type = subnet_type_name(
      first_attr(row, "subnet_type", "type"), vpc_ref, vlan_id, advanced_bool)
  if advanced_bool is False:
    subnet_type = "VLAN"
    if not vpc_ref:
      vpc_ref = ALL_VLAN_VPC_UUID
  elif not vpc_ref and subnet_type == "VLAN":
    vpc_ref = ALL_VLAN_VPC_UUID
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")),
      "name": str(first_attr(row, "name", "subnet_name") or ""),
      "subnet_type": subnet_type,
      "vpc_uuid": vpc_ref or "",
  }


def map_vpc(row):
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")),
      "name": str(first_attr(row, "name", "vpc_name") or ""),
      "vpc_type": str(first_attr(row, "vpc_type", "type") or "REGULAR"),
  }


def map_category(row):
  fq = str(first_attr(row, "fq_name") or "")
  key = first_attr(row, "key", "category_key") or ""
  value = first_attr(row, "value", "category_value") or ""
  name = str(first_attr(row, "name", "user_specified_name") or "")
  if fq and ":" in fq:
    fq_key, fq_val = fq.split(":", 1)
    key = prefer_human_key(key, fq_key)
    if fq_val and not value:
      value = fq_val
  elif "/" in fq:
    fq_key, fq_val = fq.split("/", 1)
    key = prefer_human_key(key, fq_key)
    if fq_val and not value:
      value = fq_val
  elif name and ":" in name:
    nkey, nval = name.split(":", 1)
    key = prefer_human_key(key, nkey)
    if nval and not value:
      value = nval
  elif not value and name and name != key and not looks_uuid(name):
    value = name
  if not key and name and not looks_uuid(name) and ":" not in name:
    key = name
  if looks_uuid(key):
    key = ""
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")),
      "key": key,
      "value": value,
  }


def map_cap(row):
  uid = as_uuid(first_attr(row, "kind_id"))
  return {
      "ext_id": as_uuid(first_attr(row, "ext_id", "uuid", "id")) or uid,
      "kind": str(first_attr(row, "kind") or "").lower(),
      "ids": [uid] if uid else [],
      "category_ids": category_ids_from_row(row),
      "category_names": mapping_cat_names(row),
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


def merge_categories(rows):
  by_id = {}
  for rec in rows or []:
    uid = rec.get("ext_id") or ""
    if not uid:
      continue
    prev = by_id.get(uid)
    if prev is None:
      by_id[uid] = rec
      continue
    prev["key"] = prefer_human_key(prev.get("key"), rec.get("key"))
    if not prev.get("value"):
      prev["value"] = rec.get("value") or ""
  return list(by_id.values())


def atlas_bin(explicit=""):
  if explicit:
    return explicit
  for path in ATLAS_BINS:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  found = shutil.which("atlas_cli")
  return found or "atlas_cli"


def run_cmd(argv, timeout):
  try:
    proc = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, timeout=timeout)
  except subprocess.TimeoutExpired:
    return 124, b"", b"timeout"
  except Exception as exc:
    return 1, b"", str(exc).encode("utf-8", "replace")
  return proc.returncode, proc.stdout or b"", proc.stderr or b""


def load_json_path(path):
  with open(path, "rb") as handle:
    raw = handle.read()
  if not raw.strip():
    return None
  return json.loads(raw.decode("utf-8", "replace"))


def atlas_json(args, timeout, binary):
  cmd = [binary, "-o", "json"] + list(args)
  rc, out, err = run_cmd(cmd, timeout)
  text = out.decode("utf-8", "replace") if out else ""
  try:
    parsed = json.loads(text) if text.strip() else None
  except ValueError:
    parsed = None
  if parsed is None:
    err_text = err.decode("utf-8", "replace") if err else text
    raise RuntimeError(
        "atlas_cli %s rc=%s: %s" % (" ".join(args), rc, err_text[:400]))
  return parsed


def unwrap_port_set_get(rec, uid=""):
  """Handle atlas_cli {data:{uuid: record}} wrappers."""
  if not isinstance(rec, dict):
    return {}
  if "data" in rec and "virtual_nic_uuid_list" not in rec:
    data = rec.get("data")
    if isinstance(data, dict):
      rec = data
    elif isinstance(data, list) and data and isinstance(data[0], dict):
      rec = data[0]
  nested = rec.get(uid) if uid else None
  if isinstance(nested, dict) and (
      "virtual_nic_uuid_list" in nested or nested.get("name") is not None):
    nested = dict(nested)
    nested.setdefault("uuid", uid)
    return nested
  if "virtual_nic_uuid_list" not in rec:
    candidates = [
        value for key, value in rec.items()
        if key != "uuid" and isinstance(value, dict) and (
            "virtual_nic_uuid_list" in value or value.get("name") is not None)]
    if len(candidates) == 1:
      inner = dict(candidates[0])
      inner.setdefault("uuid", uid or inner.get("uuid"))
      return inner
  return rec


def list_port_sets(parsed):
  """Return {uuid: {uuid,name,network_name}} from port_set.list JSON."""
  rows = []
  if isinstance(parsed, dict):
    data = parsed.get("data")
    if isinstance(data, list):
      rows = data
    elif isinstance(data, dict):
      rows = [
          dict(val, uuid=key) if isinstance(val, dict) else {"uuid": key}
          for key, val in data.items()]
    elif parsed.get("uuid") or parsed.get("name"):
      rows = [parsed]
  elif isinstance(parsed, list):
    rows = parsed
  out = {}
  for item in rows:
    if not isinstance(item, dict):
      continue
    uid = as_uuid(item.get("uuid"))
    if not uid:
      continue
    network_name = item.get("network_name")
    out[uid] = {
        "uuid": uid,
        "name": str(item.get("name") or ""),
        "network_name": "" if network_name in (None, "") else str(network_name),
    }
  return out


def port_set_detail(uid, rec, listed=None):
  """Return (detail_dict, nic_uuid_list) for one Atlas port-set."""
  listed = listed or {}
  inner = unwrap_port_set_get(rec, uid)
  ps_uuid = as_uuid(inner.get("uuid")) or as_uuid(uid) or uid
  name = str(inner.get("name") or listed.get("name") or "")
  network_name = str(
      listed.get("network_name")
      or inner.get("virtual_network_name")
      or "")
  nics = []
  seen = set()
  for nic in as_list(inner.get("virtual_nic_uuid_list")):
    nic_uuid = as_uuid(nic)
    if not nic_uuid or nic_uuid in seen:
      continue
    seen.add(nic_uuid)
    nics.append(nic_uuid)
  detail = {
      "uuid": ps_uuid,
      "name": name,
      "network_name": network_name,
      "virtual_network_uuid": as_uuid(inner.get("virtual_network_uuid")) or "",
      "virtual_network_name": str(
          inner.get("virtual_network_name") or network_name or ""),
      "logical_timestamp": inner.get("logical_timestamp"),
      "advertise_to_global_controller": inner.get(
          "advertise_to_global_controller"),
      "generated_mac_address_set_uuid": as_uuid(
          inner.get("generated_mac_address_set_uuid")) or "",
      "generated_ipv4_address_set_uuid": as_uuid(
          inner.get("generated_ipv4_address_set_uuid")) or "",
      "generated_ipv6_address_set_uuid": as_uuid(
          inner.get("generated_ipv6_address_set_uuid")) or "",
      "nic_count": len(nics),
  }
  return detail, nics


def resolve_atlas_paths(atlas_dir, idfcli_dir, list_path, get_path):
  if list_path and get_path:
    return os.path.abspath(list_path), os.path.abspath(get_path)
  base = os.path.abspath(atlas_dir) if atlas_dir else ""
  if not base and idfcli_dir:
    parent = os.path.dirname(os.path.abspath(idfcli_dir).rstrip(os.sep))
    if os.path.isfile(os.path.join(parent, "port_set_get.json")):
      base = parent
  if not base:
    return "", ""
  return (
      os.path.join(base, "port_set_list.json"),
      os.path.join(base, "port_set_get.json"),
  )


def collect_port_sets(binary, timeout, workers, list_path="", get_path=""):
  """Build nic_uuid -> [port_set_detail, ...] from Atlas list+get."""
  listed = {}
  gets = {}
  if list_path and get_path:
    if not os.path.isfile(list_path):
      raise RuntimeError("missing %s" % list_path)
    if not os.path.isfile(get_path):
      raise RuntimeError("missing %s" % get_path)
    listed = list_port_sets(load_json_path(list_path))
    raw_gets = load_json_path(get_path)
    if isinstance(raw_gets, dict):
      gets = raw_gets
    elif isinstance(raw_gets, list):
      gets = {
          as_uuid(item.get("uuid")): item
          for item in raw_gets
          if isinstance(item, dict) and as_uuid(item.get("uuid"))
      }
    log("atlas files list=%s get=%s" % (len(listed), len(gets)))
  else:
    list_timeout = max(60, min(300, int(timeout)))
    parsed = atlas_json(["port_set.list"], list_timeout, binary)
    if isinstance(parsed, dict) and parsed.get("status") not in (
        None, 0, "0"):
      raise RuntimeError("port_set.list status=%s" % parsed.get("status"))
    listed = list_port_sets(parsed)
    uuids = list(listed.keys())
    log("atlas port_set.list count=%s" % len(uuids))
    per = max(15, min(45, int(timeout)))
    failed = []

    def _one(uid):
      one = atlas_json(["port_set.get", uid], per, binary)
      if isinstance(one, dict) and one.get("status") not in (None, 0, "0"):
        raise RuntimeError("status=%s" % one.get("status"))
      return uid, one

    if uuids:
      with ThreadPoolExecutor(
          max_workers=max(1, min(int(workers), len(uuids)))) as pool:
        futs = [pool.submit(_one, uid) for uid in uuids]
        for fut in as_completed(futs):
          try:
            uid, one = fut.result()
            gets[uid] = one
          except Exception as err:
            failed.append("%s" % err)
    if failed:
      log("WARN port_set.get failed %s of %s (sample: %s)" % (
          len(failed), len(uuids), failed[0][:160]))
    log("atlas port_set.get count=%s" % len(gets))

  nic_to_port_sets = {}
  for uid, rec in gets.items():
    uid = as_uuid(uid) or uid
    detail, nics = port_set_detail(uid, rec, listed.get(uid))
    for nic_uuid in nics:
      nic_to_port_sets.setdefault(nic_uuid, []).append(detail)
  for nic_uuid, items in nic_to_port_sets.items():
    items.sort(key=lambda d: (d.get("name") or "", d.get("uuid") or ""))
  return nic_to_port_sets


def inventory_rows(vms, nics, hosts, clusters, subnets, vpcs, categories, caps,
                   nic_to_port_sets=None):
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
  cat_by_id = {rec["ext_id"]: rec for rec in categories or [] if rec.get("ext_id")}
  cap_stores = apply_caps(caps)
  vpc_by = {rec["ext_id"]: rec for rec in vpcs or [] if rec.get("ext_id")}
  for rec in subnets or []:
    vpc_uuid = rec.get("vpc_uuid") or ""
    if not vpc_uuid or vpc_uuid == ALL_VLAN_VPC_UUID:
      continue
    if vpc_uuid not in vpc_by:
      vpc_by[vpc_uuid] = {
          "ext_id": vpc_uuid,
          "name": vpc_name_from_subnet(rec.get("name") or ""),
          "vpc_type": "REGULAR",
      }
    elif not vpc_by[vpc_uuid].get("name"):
      inferred = vpc_name_from_subnet(rec.get("name") or "")
      if inferred:
        vpc_by[vpc_uuid]["name"] = inferred
  vpc_by.setdefault(ALL_VLAN_VPC_UUID, {
      "ext_id": ALL_VLAN_VPC_UUID,
      "name": ALL_VLAN_VPC_NAME,
      "vpc_type": "VLAN",
  })
  nic_to_port_sets = nic_to_port_sets or {}
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
    vm_cap = cap_stores["vm"].get(vm_uuid) or {}
    for nic in vm_nics:
      subnet_uuid = nic.get("subnet_id") or ""
      dump_sub = sub_by.get(subnet_uuid) or {}
      subnet_type = str(dump_sub.get("subnet_type") or "")
      vpc_uuid = dump_sub.get("vpc_uuid") or ""
      if subnet_type.upper() == "VLAN":
        vpc_uuid = ALL_VLAN_VPC_UUID
      vpc_rec = vpc_by.get(vpc_uuid) or {}
      vpc_name = vpc_display_name(
          vpc_uuid, dump_sub.get("name"), vpc_rec.get("name") or "")
      vpc_type = vpc_rec.get("vpc_type") or (
          "VLAN" if vpc_uuid == ALL_VLAN_VPC_UUID else (subnet_type or ""))
      sub_cap = cap_stores["subnet"].get(subnet_uuid) or {}
      vpc_cap = cap_stores["vpc"].get(vpc_uuid) or {}
      vm_cat_names, vm_cat_uuids = format_cats(
          vm_cap.get("ids"), vm_cap.get("names"), cat_by_id)
      sub_cat_names, sub_cat_uuids = format_cats(
          sub_cap.get("ids"), sub_cap.get("names"), cat_by_id)
      vpc_cat_names, vpc_cat_uuids = format_cats(
          vpc_cap.get("ids"), vpc_cap.get("names"), cat_by_id)
      rows.append({
          "vm": vm.get("name") or "",
          "vm_uuid": vm_uuid,
          "nic_uuid": nic.get("ext_id") or "",
          "mac": nic.get("mac") or "",
          "ip": ",".join(nic.get("ips") or []),
          "subnet": dump_sub.get("name") or "",
          "subnet_uuid": subnet_uuid,
          "subnet_type": subnet_type,
          "host": host_rec.get("host") or "",
          "host_uuid": host_uuid,
          "host_ip": host_rec.get("host_ip") or "",
          "cluster": cluster_name,
          "cluster_uuid": cluster_uuid,
          "vm_category": vm_cat_names,
          "vm_category_uuid": vm_cat_uuids,
          "subnet_category": sub_cat_names,
          "subnet_category_uuid": sub_cat_uuids,
          "vpc_category": vpc_cat_names,
          "vpc_category_uuid": vpc_cat_uuids,
          "vm_cat": vm_cat_names,
          "subnet_cat": sub_cat_names,
          "vpc_cat": vpc_cat_names,
          "vpc": vpc_name,
          "vpc_uuid": vpc_uuid,
          "vpc_type": vpc_type,
          "port_set": ",".join(
              (d.get("name") or d.get("uuid") or "") for d in (
                  nic_to_port_sets.get(nic.get("ext_id") or "") or [])),
          "port_set_uuid": ",".join(
              (d.get("uuid") or "") for d in (
                  nic_to_port_sets.get(nic.get("ext_id") or "") or [])),
          "port_sets": list(
              nic_to_port_sets.get(nic.get("ext_id") or "") or []),
      })
  return rows


def log(msg):
  sys.stderr.write(msg + "\n")


def collect(binary, timeout, file_dir, workers, atlas_binary="",
            atlas_list_path="", atlas_get_path=""):
  def _group(name, types, mapper, merge=False):
    loader = load_all if merge else first_nonempty
    raw, errors = loader(types, binary, timeout, file_dir)
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
    fut_vpcs = pool.submit(
        _group, "vpcs", ("vpc", "virtual_private_cloud"), map_vpc)
    fut_caps = pool.submit(
        _group, "caps",
        ("abac_entity_capability", "volume_group_entity_capability"),
        map_cap, True)

    def _categories():
      raw, errors = load_all(
          ("abac_category", "category"), binary, timeout, file_dir)
      for err in errors:
        log("WARN %s" % err)
      mapped = [map_category(row) for row in raw]
      merged = merge_categories(mapped)
      log("idfcli categories raw=%s mapped=%s" % (len(raw), len(merged)))
      return merged

    fut_cats = pool.submit(_categories)
    vms = fut_vms.result()
    nics = fut_nics.result()
    hosts = fut_hosts.result()
    clusters = fut_clusters.result()
    subnets = fut_subnets.result()
    vpcs = fut_vpcs.result()
    caps = fut_caps.result()
    categories = fut_cats.result()
  nic_to_port_sets = collect_port_sets(
      atlas_binary, timeout, workers, atlas_list_path, atlas_get_path)
  return inventory_rows(
      vms, nics, hosts, clusters, subnets, vpcs, categories, caps,
      nic_to_port_sets)


def main(argv=None):
  ap = argparse.ArgumentParser(
      description=(
          "Dump VM/NIC inventory with Atlas port-set membership "
          "(idfcli + atlas_cli)."))
  ap.add_argument(
      "--out", default=DEFAULT_OUT,
      help="JSON path. Default: %s" % DEFAULT_OUT)
  ap.add_argument("--idfcli", default="", help="idfcli binary path.")
  ap.add_argument(
      "--idfcli_dir", default="",
      help="Read idfcli/*.json instead of running idfcli.")
  ap.add_argument("--atlas_cli", default="", help="atlas_cli binary path.")
  ap.add_argument(
      "--atlas_dir", default="",
      help="Dir with port_set_list.json and port_set_get.json.")
  ap.add_argument(
      "--port_set_list", default="",
      help="Explicit path to port_set_list.json.")
  ap.add_argument(
      "--port_set_get", default="",
      help="Explicit path to port_set_get.json.")
  ap.add_argument("--timeout_secs", type=int, default=180)
  ap.add_argument("--workers", type=int, default=16)
  args = ap.parse_args(argv)
  file_dir = os.path.abspath(args.idfcli_dir) if args.idfcli_dir else ""
  binary = idfcli_bin(args.idfcli)
  atlas_binary = atlas_bin(args.atlas_cli)
  list_path, get_path = resolve_atlas_paths(
      args.atlas_dir, file_dir, args.port_set_list, args.port_set_get)
  if not file_dir:
    if not shutil.which(binary) and not (
        os.path.exists(binary) and os.access(binary, os.X_OK)):
      log("idfcli not found (tried %s)" % binary)
      return 2
    log("idfcli %s" % binary)
  else:
    if not os.path.isdir(file_dir):
      log("need idfcli dir %s" % file_dir)
      return 2
    log("idfcli_dir %s" % file_dir)
  if list_path and get_path:
    log("atlas files list=%s get=%s" % (list_path, get_path))
  else:
    if not shutil.which(atlas_binary) and not (
        os.path.exists(atlas_binary) and os.access(atlas_binary, os.X_OK)):
      log("atlas_cli not found (tried %s); pass --atlas_dir" % atlas_binary)
      return 2
    log("atlas_cli %s" % atlas_binary)
  try:
    rows = collect(
        binary, max(30, int(args.timeout_secs)), file_dir, args.workers,
        atlas_binary=atlas_binary,
        atlas_list_path=list_path, atlas_get_path=get_path)
  except Exception as err:
    log("port_set collect failed: %s" % err)
    return 2
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
  with_vm_cat = sum(1 for row in rows if row.get("vm_cat"))
  with_subnet_cat = sum(1 for row in rows if row.get("subnet_cat"))
  with_vpc_cat = sum(1 for row in rows if row.get("vpc_cat"))
  with_vpc = sum(1 for row in rows if row.get("vpc_uuid"))
  with_ps = sum(1 for row in rows if row.get("port_set_uuid"))
  log("wrote %s rows=%s with_vm_cat=%s with_subnet_cat=%s with_vpc_cat=%s "
      "with_vpc=%s with_port_set=%s" % (
          out_path, len(rows), with_vm_cat, with_subnet_cat, with_vpc_cat,
          with_vpc, with_ps))
  return 0


if __name__ == "__main__":
  sys.exit(main())
