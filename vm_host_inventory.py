#!/usr/bin/env python3
"""One row per VM NIC: VM, IP, subnet, host, cluster.

Reads processed dump JSON (vms.json, hosts.json, subnets.json, clusters.json).
Stdlib only. Run after flow_pc_process.py.

  python3 vm_host_inventory.py --dump_dir /path/to/dump
  python3 vm_host_inventory.py --dump_dir /path/to/dump --out vm_nics.tsv
  python3 vm_host_inventory.py --dump_dir /path/to/dump --json
"""
from __future__ import print_function

import argparse
import csv
import json
import os
import sys

UUID_ZERO = "00000000-0000-0000-0000-000000000000"
COLUMNS = (
    "vm", "vm_uuid", "nic_uuid", "mac", "ip",
    "subnet", "subnet_uuid", "subnet_type",
    "host", "host_uuid", "host_ip",
    "cluster", "cluster_uuid",
)


def load_json(path, default):
  if not os.path.isfile(path):
    return default
  with open(path) as handle:
    return json.load(handle) or default


def unwrap(row):
  if isinstance(row, dict) and isinstance(row.get("data"), dict):
    return row["data"]
  return row or {}


def as_uuid(value):
  if isinstance(value, dict):
    value = value.get("ext_id") or value.get("uuid") or value.get("id")
  text = str(value or "").strip()
  if "::" in text:
    text = text.split("::", 1)[0]
  return text.lower() if text else ""


def ip_values(raw):
  out = []
  if raw is None or raw == "":
    return out
  if not isinstance(raw, list):
    raw = [raw]
  for item in raw:
    if isinstance(item, dict):
      val = item.get("value") or item.get("ip") or item.get("address")
      if val:
        out.append(str(val).strip())
    elif item:
      out.append(str(item).strip())
  return out


def nic_ips(nic):
  net = nic.get("nic_network_info") or {}
  out = []
  ipv4_info = net.get("ipv4_info") or {}
  ipv4_config = net.get("ipv4_config") or {}
  ipv6_info = net.get("ipv6_info") or {}
  ipv6_config = net.get("ipv6_config") or {}
  out.extend(ip_values(ipv4_info.get("learned_ip_addresses")))
  out.extend(ip_values(ipv4_config.get("ip_address")))
  out.extend(ip_values(ipv4_config.get("secondary_ip_address_list")))
  out.extend(ip_values(ipv6_info.get("learned_ipv6_addresses")))
  out.extend(ip_values(ipv6_config.get("ip_address")))
  out.extend(ip_values(ipv6_config.get("secondary_ipv6_address_list")))
  seen = set()
  uniq = []
  for ip in out:
    if ip and ip not in seen:
      seen.add(ip)
      uniq.append(ip)
  return uniq


def nested_ip(blob):
  if not isinstance(blob, dict):
    return str(blob or "").strip()
  v4 = ((blob.get("external_address") or {}).get("ipv4") or {})
  return str(v4.get("value") or blob.get("value") or "").strip()


def host_maps(hosts, clusters):
  cluster_names = {}
  for row in clusters or []:
    rec = unwrap(row)
    uid = as_uuid(rec.get("ext_id") or rec.get("uuid"))
    if uid:
      cluster_names[uid] = str(rec.get("name") or "")
  by_uuid = {}
  for row in hosts or []:
    rec = unwrap(row)
    uid = as_uuid(rec.get("ext_id"))
    if not uid:
      continue
    cluster_uuid = as_uuid(rec.get("cluster"))
    by_uuid[uid] = {
        "host": str(rec.get("host_name") or rec.get("name") or ""),
        "host_ip": nested_ip(rec.get("hypervisor") or {}),
        "cluster_uuid": cluster_uuid,
        "cluster": cluster_names.get(cluster_uuid, ""),
    }
  return by_uuid


def subnet_map(subnets):
  out = {}
  for row in subnets or []:
    rec = unwrap(row)
    uid = as_uuid(rec.get("ext_id"))
    if uid:
      out[uid] = rec
  return out


def inventory_rows(dump_dir):
  vms = load_json(os.path.join(dump_dir, "vms.json"), [])
  hosts = load_json(os.path.join(dump_dir, "hosts.json"), [])
  clusters = load_json(os.path.join(dump_dir, "clusters.json"), [])
  subnets = load_json(os.path.join(dump_dir, "subnets.json"), [])
  host_by = host_maps(hosts, clusters)
  sub_by = subnet_map(subnets)
  rows = []
  for vm in vms:
    vm = unwrap(vm)
    vm_uuid = as_uuid(vm.get("ext_id"))
    vm_name = str(vm.get("name") or "")
    host_uuid = as_uuid(vm.get("host"))
    host_rec = host_by.get(host_uuid) or {}
    nics = vm.get("nics") or [None]
    if not nics:
      nics = [None]
    for nic in nics:
      nic = nic or {}
      net = nic.get("nic_network_info") or {}
      sub = dict(net.get("subnet") or {})
      subnet_uuid = as_uuid(sub.get("ext_id"))
      dump_sub = sub_by.get(subnet_uuid) or {}
      mac = str((nic.get("nic_backing_info") or {}).get("mac_address") or "")
      rows.append({
          "vm": vm_name,
          "vm_uuid": vm_uuid,
          "nic_uuid": as_uuid(nic.get("ext_id")),
          "mac": mac,
          "ip": ",".join(nic_ips(nic)),
          "subnet": str(sub.get("name") or dump_sub.get("name") or ""),
          "subnet_uuid": subnet_uuid,
          "subnet_type": str(
              sub.get("subnet_type") or dump_sub.get("subnet_type") or ""),
          "host": host_rec.get("host") or "",
          "host_uuid": host_uuid,
          "host_ip": host_rec.get("host_ip") or "",
          "cluster": host_rec.get("cluster") or "",
          "cluster_uuid": host_rec.get("cluster_uuid") or "",
      })
  return rows


def write_tsv(rows, handle):
  writer = csv.DictWriter(
      handle, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n",
      extrasaction="ignore")
  writer.writeheader()
  for row in rows:
    writer.writerow(row)


def main(argv=None):
  ap = argparse.ArgumentParser(
      description="VM / IP / subnet / host inventory from a processed dump.")
  ap.add_argument("--dump_dir", required=True)
  ap.add_argument("--out", default="", help="Write TSV/JSON here. Default: stdout.")
  ap.add_argument("--json", action="store_true", help="JSON array instead of TSV.")
  args = ap.parse_args(argv)
  dump_dir = os.path.abspath(args.dump_dir)
  vms_path = os.path.join(dump_dir, "vms.json")
  if not os.path.isfile(vms_path):
    sys.stderr.write("need vms.json under %s (run flow_pc_process.py first)\n" % dump_dir)
    return 2
  rows = inventory_rows(dump_dir)
  if args.out:
    out_path = os.path.abspath(args.out)
    parent = os.path.dirname(out_path)
    if parent:
      os.makedirs(parent, exist_ok=True)
    handle = open(out_path, "w")
  else:
    handle = sys.stdout
  try:
    if args.json:
      json.dump(rows, handle, indent=2)
      handle.write("\n")
    else:
      write_tsv(rows, handle)
  finally:
    if handle is not sys.stdout:
      handle.close()
  nics = sum(1 for row in rows if row.get("nic_uuid"))
  with_ip = sum(1 for row in rows if row.get("ip"))
  with_host = sum(1 for row in rows if row.get("host_uuid"))
  sys.stderr.write(
      "rows=%s nics=%s with_ip=%s with_host=%s hosts=%s clusters=%s\n" % (
          len(rows), nics, with_ip, with_host,
          len(set(row["host_uuid"] for row in rows if row.get("host_uuid"))),
          len(set(row["cluster_uuid"] for row in rows if row.get("cluster_uuid")))))
  return 0


if __name__ == "__main__":
  sys.exit(main())
