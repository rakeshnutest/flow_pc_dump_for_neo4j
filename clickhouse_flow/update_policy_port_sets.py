#!/usr/bin/env python3
"""Dump Flow policies and write policy.json with hashes and unmarshalled groups.

Standalone. Stdlib only. No nutest, no neo4j, no pip, no flow_pc_dump.py.
Same folder as vm_host_collect_port_set.py. On the PC:

  python3 update_policy_port_sets.py --from-pc

That collects port-set→IP into /tmp, dumps policies into /tmp, and
writes /tmp/policy.json with every port_set unmarshalled to ip_list.
No extra flags. Unique UUIDs, AG, SG, and every member IP come from the PC.

Offline:

  python3 update_policy_port_sets.py --dump_dir /path/to/dump

policy.json has, per rule component:
  - port_set        EG / VM / SUBNET / VPC category (uuid5 APPLICATION)
  - ip_list         every NIC IP in that port-set
  - address_set     address_group / ip_subnet (uuid5(ag, "IPv4"|"IPv6"))
  - address_group   resolved CIDRs, ranges, FQDNs
  - service_group   unmarshalled TCP/UDP/ICMP ports

Top-level policy.json["port_sets"] is the full port_set -> ip_list map.

Dump path:
  SMSP: kratos kubectl / flow_cli websocket, atlas ZK unique UUIDs
  CMSP: local flow_cli, zkcat unique UUIDs, Flow venv ServiceGroupGet
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import uuid as uuid_lib
from concurrent.futures import ThreadPoolExecutor, wait

ZERO = "00000000-0000-0000-0000-000000000000"
DEFAULT_PROJECT = ZERO
SALUS_SERVICE_NAME = "salus"
GLOBAL_SCOPE_UNIQUE_ID = "global-scope-unique-id"
VLAN_SCOPE_UNIQUE_ID = "vlan-scope-unique-id"
_U_QUOTE = re.compile(r"'[a-z0-9A-Z\-]+'")
CAT_SUFFIX = {"VM": "kVM", "SUBNET": "kSubnet", "VPC": "kVPC"}
CAT_TYPE = {
    "kVM": "VM", "VM": "VM",
    "kSubnet": "SUBNET", "SUBNET": "SUBNET", "kSUBNET": "SUBNET",
    "kVPC": "VPC", "VPC": "VPC",
}
GLOBAL_SCOPES = frozenset(("kGlobal", "GLOBAL", "ALL_VPC", "kAllVpc"))
VLAN_SCOPES = frozenset(("kAllVlan", "ALL_VLAN", "kVlan", "", None))
VPC_CAT_SCOPES = frozenset(("kVpcAsCategory", "VPC_AS_CATEGORY"))
VPC_LIST_SCOPES = frozenset(("kVpc", "kVpcList", "VPC_LIST", "VPC"))
COMPONENT_KEYS = (
    "endpoint", "secured_group", "src_endpoint", "dest_endpoint",
    "first_secured_group", "second_secured_group", "isolation_group",
)
RULE_KEYS = (
    "application_rule", "quarantine_rule", "secured_group_rule",
    "flex_policy_rule", "isolation_rule", "multi_env_isolation_rule",
    "shared_service_rule",
)
SKIP_ALLOW = frozenset(("kTypeAll", "kTypeNone", "ALL", "NONE"))
TCP_PROTOS = frozenset(("kTCP", "TCP", "3"))
UDP_PROTOS = frozenset(("kUDP", "UDP", "4"))
ICMP_PROTOS = frozenset(("kICMP", "ICMP", "2"))
ICMP6_PROTOS = frozenset(("kICMPv6", "kICMPV6", "ICMPv6", "ICMPV6", "5"))
ALL_PROTOS = frozenset(("kALL", "kAll", "ALL", "1"))
LOG = logging.getLogger("update_policy_port_sets")
DEFAULT_OUTPUT_BASE = "/tmp"
IDF_AG_TYPES = ("network_address_group", "address_group")
IDF_FQDN_TYPES = ("fns_fqdn_to_ip_info",)
VLAN_ZK = "/appliance/logical/flow/vlan_unique_uuid"
GLOBAL_ZK = "/appliance/logical/flow/global_unique_uuid"
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
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


def parse_scalar(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    if val in ("True", "true"):
        return True
    if val in ("False", "false"):
        return False
    if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
        return int(val)
    return val


def first(node, key, default=""):
    if not isinstance(node, dict):
        return default
    vals = node.get(key, default)
    if vals is None or vals == "":
        return default
    if isinstance(vals, list):
        return vals[0] if vals else default
    return vals


def values(node, key):
    if not isinstance(node, dict):
        return []
    vals = node.get(key)
    if vals is None or vals == "":
        return []
    if isinstance(vals, list):
        return [item for item in vals if item not in (None, "")]
    return [vals]


def parse_message(lines, open_i):
    raw = lines[open_i]
    stripped = raw.strip()
    key = stripped.split("{", 1)[0].strip()
    indent = len(raw) - len(raw.lstrip(" "))
    node = {"_key": key, "_start": open_i, "_indent": indent}
    i = open_i + 1
    while i < len(lines):
        line = lines[i]
        text = line.strip()
        if text == "}":
            node["_end"] = i
            return node, i + 1
        if not text:
            i += 1
            continue
        if text.endswith("{") and ":" not in text.split("{", 1)[0]:
            child, i = parse_message(lines, i)
            node.setdefault(child["_key"], []).append(child)
            continue
        name, sep, val = text.partition(":")
        if not sep:
            i += 1
            continue
        node.setdefault(name.strip(), []).append(parse_scalar(val))
        i += 1
    raise ValueError("unclosed %s starting at line %s" % (key, open_i + 1))


def parse_policies(text):
    lines = text.splitlines(True)
    policies = []
    i = 0
    while i < len(lines):
        if lines[i].strip() in ("network_security_policy {", "network_security_policy{"):
            node, i = parse_message(lines, i)
            policies.append(node)
        else:
            i += 1
    return policies, lines


def generate_port_set_id(entity_type, refs, unique_uuid, project_uuid=None,
                         is_flex=False):
    """APPLICATION uuid5; FLEX MD5(salus+scope+Go list). Same as ingest.py."""
    refs = list(refs or [])
    if not unique_uuid:
        return "", ""
    if is_flex:
        body = "[" + " ".join(sorted(refs)) + "]"
        body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
        if entity_type and entity_type not in ("VM", "EG"):
            suffix = CAT_SUFFIX.get(entity_type)
            if suffix:
                body = body + ":" + str(suffix)
        if project_uuid and project_uuid != DEFAULT_PROJECT:
            body = body + ":project:" + project_uuid
        digest = hashlib.md5(
            (SALUS_SERVICE_NAME + unique_uuid + body).encode()).digest()
        return str(uuid_lib.UUID(bytes=digest)), body
    body = str(sorted(list(refs)))
    body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
    if entity_type and entity_type not in ("VM", "EG"):
        body = body + ":" + str(CAT_SUFFIX.get(entity_type))
    if project_uuid and project_uuid != DEFAULT_PROJECT:
        body = body + ":project:" + project_uuid
    return str(uuid_lib.uuid5(uuid_lib.UUID(str(unique_uuid)), body)), body


def scope_unique_uuid(scope, is_flex, vlan_uuid, global_uuid, vpc_uuids):
    if scope in GLOBAL_SCOPES:
        return GLOBAL_SCOPE_UNIQUE_ID if is_flex else global_uuid
    if scope in VLAN_SCOPES:
        return VLAN_SCOPE_UNIQUE_ID if is_flex else vlan_uuid
    if scope in VPC_CAT_SCOPES or scope in VPC_LIST_SCOPES:
        return vpc_uuids[0] if vpc_uuids else ""
    return vlan_uuid if not is_flex else VLAN_SCOPE_UNIQUE_ID


def policy_vpc_uuids(policy):
    out = []
    for key in ("vpc_uuid_list", "vpc_uuids", "target_vpc_uuid",
                "vpc_reference", "scope_vpc_uuid", "vpc_references",
                "scope_references"):
        for item in values(policy, key):
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
    return out


def as_uuid_list(items):
    out = []
    seen = set()
    for item in items or []:
        text = str(item or "").strip().lower()
        if not text or text in seen or text == ZERO:
            continue
        seen.add(text)
        out.append(text)
    return out


def as_str_list(value):
    out = []
    if value is None or value == "":
        return out
    if isinstance(value, list):
        for item in value:
            out.extend(as_str_list(item))
        return out
    if isinstance(value, dict):
        if "value_list" in value:
            return as_str_list(value.get("value_list"))
        for key in ("value", "str_value", "ip", "cidr", "address", "ipv4", "ipv6"):
            if value.get(key) not in (None, ""):
                return as_str_list(value.get(key))
        return out
    text = str(value).strip()
    if text:
        out.append(text)
    return out


def component_refs(comp):
    """Return (entity_type, refs, skip_reason) for EG/category port-sets."""
    allow = str(first(comp, "allow_type") or "")
    if allow in SKIP_ALLOW:
        return None, [], "allow_type=%s" % allow
    egs = as_uuid_list(values(comp, "entity_group_uuid_list"))
    if egs:
        return None, egs, ""
    cats = as_uuid_list(values(comp, "category_uuid_list"))
    if cats:
        if any(item in ("all", "any") for item in cats):
            return None, [], "wildcard category"
        sel = CAT_TYPE.get(
            str(first(comp, "category_selection_type") or "kVM"), "VM")
        return sel, cats, ""
    vms = as_uuid_list(values(comp, "vm_uuid_list"))
    if vms:
        return "VM", vms, ""
    subnets = as_uuid_list(values(comp, "subnet_uuid_list"))
    if subnets:
        return "SUBNET", subnets, ""
    vpcs = as_uuid_list(values(comp, "vpc_uuid_list"))
    if vpcs:
        return "VPC", vpcs, ""
    if values(comp, "address_group_uuid") or values(comp, "ip_subnet"):
        return None, [], ""
    return None, [], "no entity refs"


def compute_addressset_hashes(entity_uuid, has_ipv4, has_ipv6):
    vid = uuid_lib.UUID(str(entity_uuid))
    rows = []
    if has_ipv4:
        rows.append({
            "ip_version": "IPv4",
            "address_set_uuid": str(uuid_lib.uuid5(vid, "IPv4")),
        })
    if has_ipv6:
        rows.append({
            "ip_version": "IPv6",
            "address_set_uuid": str(uuid_lib.uuid5(vid, "IPv6")),
        })
    if not rows:
        rows.append({
            "ip_version": "IPv4",
            "address_set_uuid": str(uuid_lib.uuid5(vid, "IPv4")),
        })
    return rows


def is_ipv4_text(text):
    try:
        return isinstance(
            ipaddress.ip_address(str(text).split("/")[0].split("-")[0]),
            ipaddress.IPv4Address)
    except ValueError:
        return "." in str(text) and ":" not in str(text)


def is_ipv6_text(text):
    try:
        return isinstance(
            ipaddress.ip_address(str(text).split("/")[0]),
            ipaddress.IPv6Address)
    except ValueError:
        return ":" in str(text)


def cidrs_from_addresses(addresses):
    out = []
    for addr in addresses or []:
        if isinstance(addr, str):
            text = addr.strip()
            if text:
                out.append(text)
            continue
        if not isinstance(addr, dict):
            continue
        value = addr.get("value")
        prefix = addr.get("prefix_length")
        if value is not None and prefix is not None:
            out.append("%s/%s" % (value, prefix))
            continue
        ip_val = addr.get("ip")
        if ip_val is not None and prefix is not None:
            out.append("%s/%s" % (ip_val, prefix))
            continue
        for key in ("ipv4", "ipv6", "cidr", "ip", "address"):
            text = str(addr.get(key) or "").strip()
            if text:
                out.append(text)
                break
    return out


def ips_in_range(start_ip, end_ip, cap=4096):
    try:
        start = ipaddress.ip_address(str(start_ip).split("/")[0])
        end = ipaddress.ip_address(str(end_ip).split("/")[0])
    except ValueError:
        return ["%s-%s" % (start_ip, end_ip)]
    if start > end:
        start, end = end, start
    n = int(end) - int(start) + 1
    if n > cap:
        return ["%s-%s" % (start, end)]
    out = []
    current = start
    while current <= end:
        out.append(str(current))
        current = ipaddress.ip_address(int(current) + 1)
    return out


def expand_ip_ranges(ranges):
    out = []
    if isinstance(ranges, dict):
        ranges = ranges.get("ipv4_ranges") or ranges.get("ranges") or []
    for rng in ranges or []:
        if isinstance(rng, str) and "-" in rng:
            start, end = rng.split("-", 1)
            out.extend(ips_in_range(start.strip(), end.strip()))
            continue
        if not isinstance(rng, dict):
            continue
        start = rng.get("start_ip") or rng.get("start_address") or rng.get("start")
        end = rng.get("end_ip") or rng.get("end_address") or rng.get("end")
        if start and end:
            out.extend(ips_in_range(start, end))
    return out


def expand_address_group(ag, fqdn_map=None):
    fqdn_map = fqdn_map or {}
    out = []
    out.extend(cidrs_from_addresses(ag.get("ipv4_addresses")))
    out.extend(cidrs_from_addresses(ag.get("ipv6_addresses")))
    out.extend(expand_ip_ranges(ag.get("ip_ranges") or ag.get("ranges")))
    for fqdn in ag.get("fqdns") or []:
        mapped = fqdn_map.get(fqdn) or fqdn_map.get(str(fqdn).lower()) or []
        if mapped:
            out.extend(mapped)
        else:
            out.append(str(fqdn))
    return list(dict.fromkeys(str(item) for item in out if item))


def port_row(start, end=None, all_allowed=False):
    start = int(start or 0)
    end = int(end if end is not None else start)
    return {
        "start_port": start,
        "end_port": end,
        "is_all_allowed": bool(all_allowed),
    }


def icmp_row(icmp_type=None, icmp_code=None, all_allowed=False):
    icmp_type = int(icmp_type or 0)
    icmp_code = int(icmp_code or 0)
    return {
        "type": icmp_type,
        "code": icmp_code,
        "start_port": icmp_type,
        "end_port": icmp_type,
        "is_all_allowed": bool(all_allowed),
    }


def _port_ranges(svc, *keys):
    out = []
    for key in keys:
        for item in svc.get(key) or []:
            if isinstance(item, dict):
                out.append(item)
    return out


def unmarshal_service_list(service_list):
    tcp, udp, icmp, icmp6 = [], [], [], []
    for svc in service_list or []:
        if not isinstance(svc, dict):
            continue
        proto = str(svc.get("protocol") or first(svc, "protocol") or "")
        if proto in ALL_PROTOS:
            tcp.append(port_row(0, 65535, True))
            udp.append(port_row(0, 65535, True))
            icmp.append(icmp_row(all_allowed=True))
            icmp6.append(icmp_row(all_allowed=True))
            continue
        tcp_ranges = _port_ranges(svc, "tcp_port_range_list", "tcpPortRangeList")
        udp_ranges = _port_ranges(svc, "udp_port_range_list", "udpPortRangeList")
        any_ranges = _port_ranges(svc, "port_range_list", "portRangeList")
        if proto in TCP_PROTOS or (not proto and tcp_ranges):
            for item in tcp_ranges or any_ranges:
                tcp.append(port_row(item.get("start_port"), item.get("end_port")))
        if proto in UDP_PROTOS or (not proto and udp_ranges):
            for item in udp_ranges or any_ranges:
                udp.append(port_row(item.get("start_port"), item.get("end_port")))
        if proto in ICMP_PROTOS:
            for item in svc.get("icmp_type_code_list") or []:
                if isinstance(item, dict):
                    icmp.append(icmp_row(
                        item.get("icmp_type") or item.get("type"),
                        item.get("icmp_code") or item.get("code")))
        if proto in ICMP6_PROTOS:
            for item in svc.get("icmp_v6_type_code_list") or []:
                if isinstance(item, dict):
                    icmp6.append(icmp_row(
                        item.get("icmp_type") or item.get("type"),
                        item.get("icmp_code") or item.get("code")))
        if not proto:
            for item in any_ranges:
                tcp.append(port_row(item.get("start_port"), item.get("end_port")))
    return {
        "tcp_services": tcp,
        "udp_services": udp,
        "icmp_services": icmp,
        "icmp_v6_services": icmp6,
    }


def map_service_group(row):
    if not isinstance(row, dict):
        return None
    uid = str(
        row.get("uuid") or row.get("ext_id") or row.get("extId") or "").strip()
    if not uid:
        return None
    ports = unmarshal_service_list(row.get("service_list") or [])
    if not any(ports.values()):
        ports = {
            "tcp_services": row.get("tcp_services") or row.get("tcpServices") or [],
            "udp_services": row.get("udp_services") or row.get("udpServices") or [],
            "icmp_services": row.get("icmp_services") or row.get("icmpServices") or [],
            "icmp_v6_services": (
                row.get("icmp_v6_services") or row.get("icmpV6Services") or []),
        }
    return {
        "uuid": uid,
        "name": row.get("name") or "",
        "description": row.get("description") or "",
        "tcp_services": ports.get("tcp_services") or [],
        "udp_services": ports.get("udp_services") or [],
        "icmp_services": ports.get("icmp_services") or [],
        "icmp_v6_services": ports.get("icmp_v6_services") or [],
    }


def unmarshal_rule_services(rule, sg_map):
    out = []
    for svc in values(rule, "services"):
        if not isinstance(svc, dict):
            continue
        sg_uuid = str(first(svc, "service_group_uuid") or "").strip()
        if sg_uuid:
            rec = sg_map.get(sg_uuid.lower()) or sg_map.get(sg_uuid)
            if rec is None:
                rec = {
                    "uuid": sg_uuid,
                    "name": "",
                    "missing": True,
                    "tcp_services": [],
                    "udp_services": [],
                    "icmp_services": [],
                    "icmp_v6_services": [],
                }
            out.append({
                "service_group_uuid": sg_uuid,
                "service_group": rec,
            })
            continue
        proto = str(first(svc, "protocol") or "")
        ports = unmarshal_service_list([svc])
        row = {"protocol": proto}
        row.update(ports)
        out.append(row)
    return out


def idf_json_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [idf_json_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "str_list" in value:
        inner = value.get("str_list")
        if isinstance(inner, dict):
            return as_str_list(inner.get("value_list"))
        if isinstance(inner, list):
            return as_str_list(inner)
        return []
    if "int64_list" in value:
        inner = value.get("int64_list") or {}
        items = inner.get("value_list") if isinstance(inner, dict) else inner
        out = []
        for item in items or []:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                out.append(item)
        return out
    if "value_list" in value and set(value.keys()) <= set(
            ("value_list", "timestamp_usecs")):
        return [idf_json_value(item) for item in (value.get("value_list") or [])]
    if "str_value" in value:
        return str(value.get("str_value") or "")
    if "bool_value" in value:
        return bool(value.get("bool_value"))
    for key in ("int64_value", "uint64_value", "int32_value"):
        if key in value:
            try:
                return int(value.get(key))
            except (TypeError, ValueError):
                return value.get(key)
    return value


def flatten_idf_entity(ent):
    if not isinstance(ent, dict):
        return None
    attrs = {}
    guid = ent.get("entity_guid") or {}
    if isinstance(guid, dict):
        uid = str(guid.get("entity_id") or "").strip()
        if uid:
            attrs["ext_id"] = uid
            attrs["uuid"] = uid
    elif ent.get("ext_id") or ent.get("uuid"):
        uid = str(ent.get("ext_id") or ent.get("uuid") or "").strip()
        if uid:
            attrs["ext_id"] = uid
            attrs["uuid"] = uid
    adm = ent.get("attribute_data_map")
    items = []
    if isinstance(adm, list):
        items = adm
    elif isinstance(adm, dict):
        if adm.get("name"):
            items = [adm]
        else:
            items = [{"name": key, "value": val} for key, val in adm.items()]
    if not items and not adm:
        row = dict(ent)
        row.pop("attribute_data_map", None)
        row.pop("__zprotobuf__", None)
        return row
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        if not name or name == "__zprotobuf__":
            continue
        attrs[name] = idf_json_value(item.get("value"))
    return attrs or None


def parse_idf_entities(payload):
    ents = []
    if isinstance(payload, dict):
        raw = payload.get("entity")
        if raw is None:
            raw = payload.get("entities")
        if isinstance(raw, list):
            ents = raw
        elif isinstance(raw, dict):
            ents = [raw]
        elif payload.get("attribute_data_map") or payload.get("entity_guid"):
            ents = [payload]
    elif isinstance(payload, list):
        ents = payload
    rows = []
    for ent in ents:
        row = flatten_idf_entity(ent)
        if row:
            rows.append(row)
    return rows


def map_address_group(row):
    if not isinstance(row, dict):
        return None
    uid = str(row.get("uuid") or row.get("ext_id") or row.get("extId") or "").strip()
    if not uid:
        return None
    ipv4 = as_str_list(
        row.get("ipv4_addresses") or row.get("ip_address_block_list") or [])
    ipv6 = as_str_list(row.get("ipv6_addresses") or [])
    if not ipv4:
        ips = as_str_list(row.get("ip_v4_value") or [])
        prefs = row.get("ip_v4_prefix") or []
        if not isinstance(prefs, list):
            prefs = [prefs]
        for idx, ip_val in enumerate(ips):
            pref = prefs[idx] if idx < len(prefs) else 32
            ipv4.append("%s/%s" % (ip_val, pref))
    ag_string = row.get("address_group_string")
    if ag_string and not ipv4:
        try:
            parsed = json.loads(ag_string) if isinstance(ag_string, str) else ag_string
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            ipv4.extend(cidrs_from_addresses(parsed))
    ranges = row.get("ip_ranges") or row.get("ranges") or []
    if isinstance(ranges, str):
        try:
            ranges = json.loads(ranges)
        except ValueError:
            ranges = []
    fqdns = as_str_list(row.get("fqdns") or row.get("fqdn_addresses") or [])
    return {
        "uuid": uid,
        "name": row.get("name") or "",
        "description": row.get("description") or "",
        "ipv4_addresses": list(dict.fromkeys(ipv4)),
        "ipv6_addresses": list(dict.fromkeys(ipv6)),
        "ip_ranges": ranges or [],
        "fqdns": fqdns,
    }


def load_json(path, default=None):
    if not path or not os.path.isfile(path):
        return default
    with open(path, encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except ValueError:
            return default


def load_unique_uuids(path):
    data = load_json(path, {}) or {}
    if not isinstance(data, dict):
        return "", ""
    return (
        str(data.get("global_unique_uuid") or "").strip(),
        str(data.get("vlan_unique_uuid") or "").strip(),
    )


def load_ag_map(dump_dir):
    rows = []
    converted = load_json(os.path.join(dump_dir, "address_groups.json"), None)
    if isinstance(converted, list):
        rows = converted
    elif isinstance(converted, dict):
        rows = list(converted.values())
    if not rows:
        for name in IDF_AG_TYPES:
            payload = load_json(os.path.join(dump_dir, "idfcli", "%s.json" % name), None)
            if payload is None:
                payload = load_json(os.path.join(dump_dir, "%s.json" % name), None)
            rows.extend(parse_idf_entities(payload) if payload is not None else [])
    out = {}
    for row in rows:
        mapped = map_address_group(row)
        if mapped:
            out[mapped["uuid"].lower()] = mapped
    return out


def load_sg_map(dump_dir):
    records = []
    gets = load_json(os.path.join(dump_dir, "service_group_get.json"), None)
    listed = load_json(os.path.join(dump_dir, "service_group_list.json"), None)
    converted = load_json(os.path.join(dump_dir, "service_groups.json"), None)
    for blob in (gets, listed):
        if isinstance(blob, dict) and isinstance(blob.get("service_group_list"), list):
            records = [x for x in blob["service_group_list"] if isinstance(x, dict)]
            break
        if isinstance(blob, dict) and blob:
            tmp = []
            for uid, rec in blob.items():
                if uid == "service_group_list" or not isinstance(rec, dict):
                    continue
                row = dict(rec)
                row.setdefault("uuid", uid)
                tmp.append(row)
            if tmp:
                records = tmp
                break
        if isinstance(blob, list):
            records = [x for x in blob if isinstance(x, dict)]
            break
    if not records and isinstance(converted, list):
        records = converted
    out = {}
    for row in records:
        mapped = map_service_group(row)
        if mapped:
            out[mapped["uuid"].lower()] = mapped
    return out


def load_fqdn_map(dump_dir):
    out = {}
    converted = load_json(os.path.join(dump_dir, "fqdn_to_ip_map.json"), None)
    if isinstance(converted, dict):
        for fqdn, ips in converted.items():
            out[str(fqdn)] = as_str_list(ips)
    payload = load_json(
        os.path.join(dump_dir, "idfcli", "fns_fqdn_to_ip_info.json"), None)
    for row in parse_idf_entities(payload) if payload is not None else []:
        fqdn = str(row.get("fqdn") or "").strip()
        if not fqdn:
            continue
        ips = as_str_list(row.get("resolved_ipv4_addresses") or [])
        ips.extend(as_str_list(row.get("resolved_ipv6_addresses") or []))
        if ips:
            out[fqdn] = list(dict.fromkeys(out.get(fqdn, []) + ips))
    return out


def unwrap_policy(rec):
    if not isinstance(rec, dict):
        return None
    if rec.get("_key") == "network_security_policy":
        return rec
    if "network_security_policy" in rec and isinstance(
            rec.get("network_security_policy"), dict):
        return rec["network_security_policy"]
    data = rec.get("data")
    if isinstance(data, dict) and isinstance(data.get("network_security_policy"), dict):
        return data["network_security_policy"]
    if rec.get("uuid") and rec.get("rules_list") is not None:
        return rec
    return None


def load_policies_from_policy_get(path):
    data = load_json(path, None)
    policies = []
    if isinstance(data, dict):
        if data.get("data") or data.get("network_security_policy") or data.get("rules_list"):
            rec = unwrap_policy(data)
            if rec:
                policies.append(rec)
        else:
            for rec in data.values():
                policy = unwrap_policy(rec)
                if policy:
                    policies.append(policy)
    elif isinstance(data, list):
        for rec in data:
            policy = unwrap_policy(rec)
            if policy:
                policies.append(policy)
    return policies


def load_policies(dump_dir, policy_path=""):
    proto_lines = None
    if policy_path and os.path.isfile(policy_path):
        with open(policy_path, encoding="utf-8") as handle:
            text = handle.read()
        if "network_security_policy {" in text[:4000]:
            policies, proto_lines = parse_policies(text)
            if policies:
                return policies, proto_lines
        loaded = load_policies_from_policy_get(policy_path)
        if loaded:
            return loaded, None
    if dump_dir:
        get_path = os.path.join(dump_dir, "policy_get.json")
        if os.path.isfile(get_path):
            loaded = load_policies_from_policy_get(get_path)
            if loaded:
                return loaded, None
        for name in ("policy_list.json", "policy_list.pbtxt"):
            cand = os.path.join(dump_dir, name)
            if os.path.isfile(cand):
                with open(cand, encoding="utf-8") as handle:
                    text = handle.read()
                if "network_security_policy {" in text[:4000]:
                    policies, proto_lines = parse_policies(text)
                    if policies:
                        return policies, proto_lines
    return [], proto_lines


def walk_components(node, sink, role=None):
    if not isinstance(node, dict):
        return
    key = role or node.get("_key") or ""
    if key in COMPONENT_KEYS:
        if node.get("_key") != key:
            node = dict(node)
            node["_key"] = key
        sink.append(node)
        return
    for child_key, val in node.items():
        if str(child_key).startswith("_"):
            continue
        if isinstance(val, dict):
            walk_components(val, sink, child_key)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    walk_components(item, sink, child_key)


def rule_is_flex(rule, policy_type):
    if (rule.get("_key") or "") == "flex_policy_rule":
        return True
    return str(policy_type or "") in ("kFlex", "FLEX")


def annotate_component(comp, unique_uuid, project_uuid, is_flex, include_project,
                       ag_map=None, fqdn_map=None, ps_ip_map=None):
    ag_map = ag_map or {}
    fqdn_map = fqdn_map or {}
    ps_ip_map = ps_ip_map or {}
    entity_type, refs, skip = component_refs(comp)
    role = comp.get("_key") or ""
    row = {
        "role": role,
        "kind": "",
        "entity_type": entity_type,
        "refs": refs,
        "skip_reason": skip or None,
        "hash_body": "",
        "port_set": "",
        "ip_list": [],
        "port_set_uuid": "",
        "port_set_name": "",
        "address_set": [],
        "address_set_uuid": "",
        "address_group": None,
        "ip_subnet": [],
    }
    ag_uuids = as_uuid_list(values(comp, "address_group_uuid"))
    ip_subnets = [str(item) for item in values(comp, "ip_subnet") if item]
    if ag_uuids:
        addresses = []
        resolved = []
        for uid in ag_uuids:
            rec = ag_map.get(uid) or ag_map.get(uid.lower())
            if rec is None:
                rec = {"uuid": uid, "name": "", "missing": True,
                       "ipv4_addresses": [], "ipv6_addresses": [],
                       "ip_ranges": [], "fqdns": []}
            else:
                rec = dict(rec)
            rec["uuid"] = rec.get("uuid") or rec.get("ext_id") or uid
            rec["addresses"] = expand_address_group(rec, fqdn_map)
            addresses.extend(rec["addresses"])
            resolved.append(rec)
        has_v4 = any(is_ipv4_text(item) for item in addresses)
        has_v6 = any(is_ipv6_text(item) for item in addresses)
        if not has_v4 and not has_v6:
            has_v4 = True
        sets = []
        for uid in ag_uuids:
            sets.extend(compute_addressset_hashes(uid, has_v4, has_v6))
        row["kind"] = "address_set"
        row["refs"] = ag_uuids
        row["address_group"] = resolved[0] if len(resolved) == 1 else resolved
        row["address_set"] = sets
        row["address_set_uuid"] = sets[0]["address_set_uuid"] if sets else ""
        row["skip_reason"] = None
        return row
    if ip_subnets:
        row["kind"] = "address_set"
        row["ip_subnet"] = ip_subnets
        row["skip_reason"] = None
        return row
    if skip or not refs or not unique_uuid:
        if not skip and not unique_uuid and refs:
            row["skip_reason"] = "no scope unique uuid"
        return row
    project = project_uuid if include_project else None
    hashed, body = generate_port_set_id(
        entity_type, refs, unique_uuid, project, is_flex=is_flex)
    rec = ps_ip_map.get(hashed) or ps_ip_map.get(str(hashed).lower()) or {}
    ips = [str(ip_val) for ip_val in (rec.get("ip_list") or []) if ip_val]
    row["kind"] = "port_set"
    row["hash_body"] = body
    row["port_set"] = hashed
    row["ip_list"] = ips
    row["port_set_uuid"] = hashed
    row["port_set_name"] = rec.get("name") or ""
    return row


def iter_rules(policy):
    for rules_list in values(policy, "rules_list"):
        if not isinstance(rules_list, dict):
            continue
        for rkey in RULE_KEYS:
            for rule in values(rules_list, rkey):
                if isinstance(rule, dict):
                    if not rule.get("_key"):
                        rule = dict(rule)
                        rule["_key"] = rkey
                    yield rkey, rule


def annotate_policy(policy, vlan_uuid, global_uuid, include_project,
                    ag_map=None, sg_map=None, fqdn_map=None, ps_ip_map=None):
    ag_map = ag_map or {}
    sg_map = sg_map or {}
    fqdn_map = fqdn_map or {}
    ps_ip_map = ps_ip_map or {}
    name = first(policy, "name")
    policy_uuid = first(policy, "uuid")
    scope = first(policy, "scope") or "kAllVlan"
    mode = first(policy, "mode")
    policy_type = first(policy, "policy_type")
    project = first(policy, "project_uuid") or ZERO
    vpc_uuids = policy_vpc_uuids(policy)
    rules_out = []
    insertions = []
    save_mode = str(mode) in ("kSave", "SAVE")
    if not save_mode:
        for rkey, rule in iter_rules(policy):
            is_flex = rule_is_flex(rule, policy_type) or rkey == "flex_policy_rule"
            unique = scope_unique_uuid(
                scope, is_flex, vlan_uuid, global_uuid, vpc_uuids)
            info = first(rule, "rule_info") or {}
            if not isinstance(info, dict):
                info = {}
            rule_uuid = first(info, "uuid") or first(rule, "uuid") or ""
            desc = first(info, "description") if isinstance(info, dict) else ""
            comps = []
            walk_components(rule, comps)
            seen = set()
            unique_comps = []
            for comp in comps:
                marker = (comp.get("_start"), comp.get("_end"), id(comp))
                if marker in seen:
                    continue
                seen.add(marker)
                unique_comps.append(comp)
            component_rows = []
            for comp in unique_comps:
                row = annotate_component(
                    comp, unique, project, is_flex, include_project,
                    ag_map=ag_map, fqdn_map=fqdn_map, ps_ip_map=ps_ip_map)
                component_rows.append(row)
                if row["port_set_uuid"] and comp.get("_end") is not None:
                    insertions.append({
                        "end": comp["_end"],
                        "indent": (comp.get("_indent") or 0) + 2,
                        "uuid": row["port_set_uuid"],
                    })
            rules_out.append({
                "rule_kind": rkey or rule.get("_key"),
                "rule_uuid": rule_uuid,
                "description": desc,
                "direction": first(rule, "direction"),
                "is_flex": is_flex,
                "unique_uuid": unique,
                "components": component_rows,
                "services": unmarshal_rule_services(rule, sg_map),
            })
    return {
        "name": name,
        "uuid": policy_uuid,
        "scope": scope,
        "mode": mode,
        "policy_type": policy_type,
        "project_uuid": project,
        "skipped_save": save_mode,
        "rules": rules_out,
    }, insertions


def apply_insertions(lines, insertions):
    """Insert port_set_uuid before each component closing brace."""
    by_end = {}
    for item in insertions:
        by_end.setdefault(item["end"], []).append(item)
    out = []
    for idx, line in enumerate(lines):
        extras = by_end.get(idx) or []
        for extra in extras:
            existing = False
            look = idx - 1
            while look >= 0:
                prev = lines[look].strip()
                if not prev:
                    look -= 1
                    continue
                if prev.startswith("port_set_uuid:"):
                    existing = True
                break
            if existing:
                continue
            pad = " " * extra["indent"]
            out.append('%sport_set_uuid: "%s"\n' % (pad, extra["uuid"]))
        out.append(line)
    return out


def summarize(policies_out):
    hashed = 0
    address_sets = 0
    skipped = 0
    rules = 0
    services = 0
    ag_resolved = 0
    sg_resolved = 0
    ps_with_ips = 0
    for policy in policies_out:
        rules += len(policy.get("rules") or [])
        for rule in policy.get("rules") or []:
            for svc in rule.get("services") or []:
                services += 1
                rec = svc.get("service_group") or {}
                if rec and not rec.get("missing"):
                    sg_resolved += 1
            for comp in rule.get("components") or []:
                if comp.get("port_set") or comp.get("port_set_uuid"):
                    hashed += 1
                    if comp.get("ip_list"):
                        ps_with_ips += 1
                elif comp.get("kind") == "address_set":
                    address_sets += 1
                    ag = comp.get("address_group")
                    recs = ag if isinstance(ag, list) else ([ag] if ag else [])
                    if any(not rec.get("missing") for rec in recs if rec):
                        ag_resolved += 1
                else:
                    skipped += 1
    return {
        "policies": len(policies_out),
        "rules": rules,
        "components_hashed": hashed,
        "address_sets": address_sets,
        "components_skipped": skipped,
        "services": services,
        "address_groups_resolved": ag_resolved,
        "service_groups_resolved": sg_resolved,
        "port_sets_with_ips": ps_with_ips,
    }


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
    for prefix in (["sudo", "-n", kubectl], ["sudo", kubectl], [kubectl]):
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
        "/home/nutanix/.venvs/bin/bin/python3",
        sys.executable or "") or ""


def dump_idfcli(output_dir, workers, timeout, entity_types=None):
    dest = os.path.join(output_dir, "idfcli")
    os.makedirs(dest, exist_ok=True)
    binary = _which(
        "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
        "/home/nutanix/bin/idfcli",
        "/usr/local/nutanix/bin/idfcli",
        "idfcli")
    types = list(entity_types or (IDF_AG_TYPES + IDF_FQDN_TYPES))
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

    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), len(types) or 1))) as pool:
        for fut in [pool.submit(_one, t) for t in types]:
            entity_type, nbytes, err = fut.result()
            index["entity_types"][entity_type] = {
                "bytes": nbytes, "error": err or "", "file": "%s.json" % entity_type}
            if err:
                errors["idfcli:%s" % entity_type] = err
    _write_json(os.path.join(dest, "index.json"), index)
    return index, errors


def dump_service_groups(output_dir, timeout, info, kubeconfig="", ns="", pod=""):
    errors = {}
    rec = {"ran": True, "rpc": "ServiceGroupGet", "transport": "", "errors": errors}
    timeout = max(60, min(300, int(timeout or 1800)))
    payload = None
    last_err = None
    for attempt in range(1, 4):
        try:
            if info.get("platform") == "smsp":
                if not (kubeconfig and pod):
                    raise RuntimeError("SMSP kratos pod missing for ServiceGroupGet")
                py = _pod_bin(
                    kubeconfig, ns or "ntnx-flow", pod,
                    "ls /home/nutanix/.venvs/flow/bin/python3 2>/dev/null || "
                    "ls /home/nutanix/.venvs/bin/bin/python3 2>/dev/null || "
                    "command -v python3")
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


def port_sets_catalog(ps_ip_map):
    """uuid -> {uuid, name, ip_list} for policy.json (all IPs, no NIC rows)."""
    catalog = {}
    for uid, rec in (ps_ip_map or {}).items():
        if not isinstance(rec, dict):
            continue
        catalog[str(uid)] = {
            "uuid": rec.get("uuid") or uid,
            "name": rec.get("name") or "",
            "ip_list": [str(ip_val) for ip_val in (rec.get("ip_list") or []) if ip_val],
        }
    return catalog


def load_port_set_ip_map(dump_dir, explicit=""):
    """Load port_set_uuid -> {name, ip_list} from collect output."""
    paths = []
    if explicit:
        paths.append(explicit)
    for base in (dump_dir, DEFAULT_OUTPUT_BASE):
        if not base:
            continue
        paths.append(os.path.join(base, "port_set_ips.json"))
        paths.append(os.path.join(base, "vms_port_set.json"))
    payload = None
    for path in paths:
        payload = load_json(path, None)
        if payload is not None:
            LOG.info("port_set ips from %s", path)
            break
    if payload is None:
        return {}
    mapping = {}

    def add_ps(uid, name, ips):
        uid = str(uid or "").strip().lower()
        if not uid:
            return
        rec = mapping.setdefault(uid, {"uuid": uid, "name": "", "ip_list": []})
        if name and not rec["name"]:
            rec["name"] = str(name)
        for ip_val in ips or []:
            text = str(ip_val or "").strip()
            if "/" in text:
                text = text.split("/", 1)[0]
            if text and text not in rec["ip_list"]:
                rec["ip_list"].append(text)

    if isinstance(payload, dict) and not isinstance(payload.get("port_sets"), list):
        sample = None
        for rec in payload.values():
            if isinstance(rec, dict):
                sample = rec
                break
        if isinstance(sample, dict) and (
                "ip_list" in sample or "nics" in sample or sample.get("uuid")):
            for uid, rec in payload.items():
                if not isinstance(rec, dict):
                    if isinstance(rec, list):
                        add_ps(uid, "", rec)
                    continue
                add_ps(rec.get("uuid") or uid, rec.get("name"), rec.get("ip_list"))
            return mapping
    rows = payload
    if isinstance(payload, dict):
        rows = payload.get("vms") or payload.get("rows") or payload.get("port_sets") or []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ips = []
        for part in str(row.get("ip") or "").replace(";", ",").split(","):
            text = part.strip().split("/", 1)[0]
            if text:
                ips.append(text)
        if row.get("ip_list") and row.get("uuid"):
            add_ps(row.get("uuid"), row.get("name"), row.get("ip_list"))
            continue
        for ps in row.get("port_sets") or []:
            if not isinstance(ps, dict):
                continue
            add_ps(ps.get("uuid"), ps.get("name"), ps.get("ip_list") or ips)
    return mapping


def find_collect_script():
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    for path in (
            os.path.join(here, "vm_host_collect_port_set.py"),
            os.path.join(cwd, "vm_host_collect_port_set.py"),
            os.path.join(DEFAULT_OUTPUT_BASE, "vm_host_collect_port_set.py"),
            os.path.join(os.path.dirname(here), "policy_port_set",
                         "vm_host_collect_port_set.py"),
            os.path.join(os.path.dirname(here), "flow_pc_dump_github",
                         "vm_host_collect_port_set.py"),
            os.path.join(os.path.dirname(here), "flow_pc_dump_github",
                         "policy_port_set", "vm_host_collect_port_set.py")):
        if os.path.isfile(path):
            return os.path.abspath(path)
    return ""


def run_collect(output_dir, workers=16, timeout=1800):
    collect_py = find_collect_script()
    if not collect_py:
        raise SystemExit(
            "vm_host_collect_port_set.py must sit in the same folder")
    os.makedirs(output_dir, exist_ok=True)
    vms = os.path.join(output_dir, "vms_port_set.json")
    ips = os.path.join(output_dir, "port_set_ips.json")
    argv = [
        sys.executable, collect_py,
        "--out", vms,
        "--port_set_ips", ips,
        "--workers", str(max(1, int(workers) or 8)),
        "--timeout_secs", "180",
    ]
    LOG.info("collect %s", " ".join(argv))
    rc, stdout, stderr = _run(argv, max(int(timeout) or 1800, 600))
    if stdout:
        LOG.info("%s", stdout.strip()[:2000])
    if stderr:
        LOG.info("%s", stderr.strip()[:4000])
    if rc != 0:
        raise SystemExit("vm_host_collect_port_set.py failed rc=%s" % rc)
    return load_port_set_ip_map(output_dir, explicit=ips)


def dump_from_pc(output_dir, workers=8, timeout=1800):
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "dump.log")
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    logging.getLogger().addHandler(fh)
    info = detect_platform()
    LOG.info("platform=%s smsp=%s output=%s",
             info.get("platform"), info.get("smsp_cluster_uuid") or "", output_dir)
    rec = {
        "platform": info.get("platform") or "cmsp",
        "smsp_cluster_uuid": info.get("smsp_cluster_uuid") or "",
    }
    idf_index, idf_err = dump_idfcli(
        output_dir, min(4, int(workers) or 1), 180,
        entity_types=IDF_AG_TYPES + IDF_FQDN_TYPES)
    rec["idfcli"] = idf_index
    rec["flow"] = dump_flow(output_dir, workers, timeout, info)
    rec["unique_uuids"] = dump_unique_uuids(output_dir, info)
    errors = {}
    errors.update(idf_err or {})
    errors.update((rec.get("flow") or {}).get("errors") or {})
    rec["errors"] = errors
    _write_json(os.path.join(output_dir, "dump_index.json"), rec)
    return rec


def build_policy_json(policies_out, global_uuid, vlan_uuid, include_project,
                      extra=None):
    stats = summarize(policies_out)
    payload = {
        "global_unique_uuid": global_uuid,
        "vlan_unique_uuid": vlan_uuid,
        "include_project": bool(include_project),
        "hash": {
            "port_set": "uuid5(scope, str(sorted(refs)) with u-prefix); "
                        "FLEX MD5(salus+scope+[refs])",
            "address_set": 'uuid5(address_group_uuid, "IPv4"|"IPv6")',
        },
        "stats": stats,
        "policies": policies_out,
    }
    if extra:
        payload.update(extra)
    return payload, stats


def _compact_json_array(items, col, width=120):
    quoted = [json.dumps(str(item), ensure_ascii=False) for item in items]
    if not quoted:
        return "[]"
    chunks, row, row_len = [], [], 0
    for item in quoted:
        extra = len(item) if not row else len(item) + 2
        if row and col + 1 + row_len + extra > width:
            chunks.append(", ".join(row))
            row, row_len = [item], len(item)
        else:
            row.append(item)
            row_len += extra
    if row:
        chunks.append(", ".join(row))
    if len(chunks) == 1:
        return "[" + chunks[0] + "]"
    pad = " " * (col + 1)
    return "[" + (",\n" + pad).join(chunks) + "]"


def dump_policy_json(payload, handle, compact_keys=("ip_list",)):
    """Pretty-print JSON but keep ip_list (and similar) horizontal."""
    bags = []

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, val in node.items():
                if key in compact_keys and isinstance(val, list):
                    bags.append(list(val))
                    out[key] = "__COMPACT_LIST_%d__" % (len(bags) - 1)
                else:
                    out[key] = walk(val)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    text = json.dumps(walk(payload), indent=2, ensure_ascii=False)
    for idx, items in enumerate(bags):
        needle = '"__COMPACT_LIST_%d__"' % idx
        pos = text.find(needle)
        if pos < 0:
            continue
        col = pos - (text.rfind("\n", 0, pos) + 1)
        text = text[:pos] + _compact_json_array(items, col) + text[pos + len(needle):]
    handle.write(text)
    if not text.endswith("\n"):
        handle.write("\n")


def run_build(dump_dir, global_uuid, vlan_uuid, include_project, json_path,
              policy_path="", proto_out="", in_place=False, ps_ip_map=None):
    policies, proto_lines = load_policies(dump_dir, policy_path)
    if not policies:
        raise SystemExit(
            "no policies in policy_get.json or proto policy_list.json under %s"
            % (dump_dir or policy_path or "."))
    ag_map = load_ag_map(dump_dir) if dump_dir else {}
    sg_map = load_sg_map(dump_dir) if dump_dir else {}
    fqdn_map = load_fqdn_map(dump_dir) if dump_dir else {}
    if ps_ip_map is None:
        ps_ip_map = load_port_set_ip_map(dump_dir) if dump_dir else {}
    LOG.info("loaded policies=%s address_groups=%s service_groups=%s port_sets_ips=%s",
             len(policies), len(ag_map), len(sg_map), len(ps_ip_map))
    policies_out = []
    insertions = []
    for policy in policies:
        annotated, extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project,
            ag_map=ag_map, sg_map=sg_map, fqdn_map=fqdn_map,
            ps_ip_map=ps_ip_map)
        policies_out.append(annotated)
        insertions.extend(extra)
    payload, stats = build_policy_json(
        policies_out, global_uuid, vlan_uuid, include_project,
        extra={
            "address_groups": len(ag_map),
            "service_groups": len(sg_map),
            "port_set_ip_maps": len(ps_ip_map),
            "port_sets": port_sets_catalog(ps_ip_map),
        })
    json_path = json_path or os.path.join(dump_dir or ".", "policy.json")
    dest_dir = os.path.dirname(os.path.abspath(json_path)) or "."
    os.makedirs(dest_dir, exist_ok=True)
    tmp_path = json_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        dump_policy_json(payload, handle)
    os.replace(tmp_path, json_path)
    proto_path = ""
    if proto_lines is not None:
        annotated_lines = apply_insertions(proto_lines, insertions)
        proto_path = policy_path if in_place else (
            proto_out or ((policy_path or "policy_list.json") + ".port_sets.pbtxt"))
        with open(proto_path, "w", encoding="utf-8") as handle:
            handle.writelines(annotated_lines)
    return stats, json_path, proto_path


def self_test():
    global_uuid = "702970d3-d72d-41b9-9655-50c40ffd96f4"
    vlan_uuid = "29332a4d-9133-4c73-a219-ce82ea53d532"
    eg = "407982f9-5504-4504-a42d-78143d09f3fe"
    hashed, body = generate_port_set_id(None, [eg], global_uuid)
    expect = "917386ac-6978-5da1-91a6-3782ffebd275"
    if hashed != expect:
        raise SystemExit("hash mismatch: %s != %s body=%s" % (hashed, expect, body))
    ag = "589092d7-b775-462c-a806-8475180ce23f"
    aset = compute_addressset_hashes(ag, True, False)
    expect_ag = str(uuid_lib.uuid5(uuid_lib.UUID(ag), "IPv4"))
    if aset[0]["address_set_uuid"] != expect_ag:
        raise SystemExit("address_set mismatch: %s" % aset)
    sg = map_service_group({
        "uuid": "a54f7bd7-9ae2-42d9-a89a-f6bbbf8c6ef7",
        "name": "web",
        "service_list": [{
            "protocol": "kTCP",
            "port_range_list": [{"start_port": 80, "end_port": 80}],
            "tcp_port_range_list": [{"start_port": 80, "end_port": 80}],
        }],
    })
    if not sg or sg["tcp_services"][0]["start_port"] != 80:
        raise SystemExit("service_group unmarshal failed: %s" % sg)
    tmp = tempfile.mkdtemp(prefix="port_set_self_test_")
    dump_dir = tmp
    policy_get = {
        "11111111-1111-1111-1111-111111111111": {
            "data": {
                "network_security_policy": {
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "name": "T",
                    "mode": "kApply",
                    "policy_type": "kApplication",
                    "scope": "kGlobal",
                    "project_uuid": ZERO,
                    "rules_list": [{
                        "application_rule": {
                            "direction": "kIn",
                            "rule_info": {
                                "uuid": "22222222-2222-2222-2222-222222222222",
                            },
                            "endpoint": {"address_group_uuid": ag},
                            "secured_group": {"entity_group_uuid_list": [eg]},
                            "services": [{
                                "service_group_uuid": sg["uuid"],
                            }],
                        }
                    }],
                }
            },
            "status": 0,
        }
    }
    with open(os.path.join(dump_dir, "policy_get.json"), "w", encoding="utf-8") as handle:
        json.dump(policy_get, handle)
    with open(os.path.join(dump_dir, "unique_uuids.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "global_unique_uuid": global_uuid,
            "vlan_unique_uuid": vlan_uuid,
        }, handle)
    with open(os.path.join(dump_dir, "service_group_get.json"), "w", encoding="utf-8") as handle:
        json.dump({"service_group_list": [{
            "uuid": sg["uuid"],
            "name": "web",
            "service_list": [{
                "protocol": "kTCP",
                "port_range_list": [{"start_port": 80, "end_port": 80}],
                "tcp_port_range_list": [{"start_port": 80, "end_port": 80}],
            }],
        }]}, handle)
    with open(os.path.join(dump_dir, "address_groups.json"), "w", encoding="utf-8") as handle:
        json.dump([{
            "ext_id": ag,
            "name": "AG_3",
            "ipv4_addresses": ["10.1.2.3/32", "10.1.2.4/32"],
            "ipv6_addresses": [],
            "ip_ranges": [],
            "fqdns": [],
        }], handle)
    with open(os.path.join(dump_dir, "port_set_ips.json"), "w", encoding="utf-8") as handle:
        json.dump({
            expect: {
                "uuid": expect,
                "name": "EG-T",
                "ip_list": ["142.58.233.98", "10.28.2.149"],
            }
        }, handle)
    json_path = os.path.join(dump_dir, "policy.json")
    stats, json_path, _proto = run_build(
        dump_dir, global_uuid, vlan_uuid, False, json_path)
    if stats["components_hashed"] != 1:
        raise SystemExit("expected 1 port_set, got %s" % stats)
    if stats["address_sets"] != 1:
        raise SystemExit("expected 1 address_set, got %s" % stats)
    if stats["address_groups_resolved"] != 1:
        raise SystemExit("address_group not resolved: %s" % stats)
    if stats["service_groups_resolved"] != 1:
        raise SystemExit("service_group not resolved: %s" % stats)
    with open(json_path, encoding="utf-8") as handle:
        payload = json.load(handle)
    rule = payload["policies"][0]["rules"][0]
    endpoint = [c for c in rule["components"] if c["role"] == "endpoint"][0]
    if "10.1.2.3/32" not in (endpoint["address_group"] or {}).get("addresses") or []:
        raise SystemExit("address_group addresses missing: %s" % endpoint)
    if endpoint["address_set_uuid"] != expect_ag:
        raise SystemExit("address_set_uuid mismatch: %s" % endpoint)
    if rule["services"][0]["service_group"]["tcp_services"][0]["start_port"] != 80:
        raise SystemExit("service ports missing: %s" % rule["services"])
    secured = [c for c in rule["components"] if c["role"] == "secured_group"][0]
    keys = list(secured.keys())
    if "port_set" not in keys or "ip_list" not in keys:
        raise SystemExit("port_set/ip_list keys missing: %s" % keys)
    if keys.index("port_set") >= keys.index("ip_list"):
        raise SystemExit("port_set must precede ip_list: %s" % keys)
    if secured.get("port_set") != expect:
        raise SystemExit("port_set uuid missing: %s" % secured)
    if secured.get("ip_list") != ["142.58.233.98", "10.28.2.149"]:
        raise SystemExit("port_set ip_list missing: %s" % secured)
    catalog = (payload.get("port_sets") or {}).get(expect) or {}
    if catalog.get("ip_list") != ["142.58.233.98", "10.28.2.149"]:
        raise SystemExit("policy.json port_sets catalog missing ips: %s" % catalog)
    with open(json_path, encoding="utf-8") as handle:
        raw = handle.read()
    if '"ip_list": [\n' in raw:
        raise SystemExit("ip_list should be horizontal, got vertical")
    if '"ip_list": ["142.58.233.98", "10.28.2.149"]' not in raw:
        raise SystemExit("ip_list not one-line")
    if stats.get("port_sets_with_ips") != 1:
        raise SystemExit("port_sets_with_ips %s" % stats)
    proto = (
        "network_security_policy {\n"
        "  mode: \"kApply\"\n"
        "  name: \"T\"\n"
        "  policy_type: \"kApplication\"\n"
        "  project_uuid: \"%s\"\n"
        "  rules_list {\n"
        "    application_rule {\n"
        "      direction: \"kIn\"\n"
        "      endpoint {\n"
        "        entity_group_uuid_list: \"%s\"\n"
        "      }\n"
        "      rule_info {\n"
        "        uuid: \"11111111-1111-1111-1111-111111111111\"\n"
        "      }\n"
        "      secured_group {\n"
        "        entity_group_uuid_list: \"%s\"\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  scope: \"kGlobal\"\n"
        "  uuid: \"22222222-2222-2222-2222-222222222222\"\n"
        "}\n"
    ) % (ZERO, eg, eg)
    proto_dir = os.path.join(tmp, "proto")
    os.makedirs(proto_dir)
    policy_path = os.path.join(proto_dir, "policy_list.json")
    with open(policy_path, "w", encoding="utf-8") as handle:
        handle.write(proto)
    stats2, _jp, proto_path = run_build(
        proto_dir, global_uuid, vlan_uuid, False, "", policy_path=policy_path)
    if stats2["components_hashed"] != 2:
        raise SystemExit("expected 2 hashed proto components, got %s" % stats2)
    with open(proto_path, encoding="utf-8") as handle:
        annotated = handle.read()
    if 'port_set_uuid: "%s"' % expect not in annotated:
        raise SystemExit("annotated proto missing port_set_uuid")
    print("self-test ok hash=%s address_set=%s hashed=%s address_sets=%s json=%s" % (
        expect, expect_ag, stats["components_hashed"], stats["address_sets"], json_path))


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Dump Flow policies (CMSP/SMSP) and write policy.json with "
            "port_set + ip_list, address_set, unmarshalled groups"))
    parser.add_argument(
        "--from-pc", "--self-pc", action="store_true", dest="from_pc",
        help="Collect port-set IPs, dump policies, write /tmp/policy.json")
    parser.add_argument("--policy", default="",
                        help="Proto-text or policy.get JSON")
    parser.add_argument("--dump_dir", default="",
                        help="Dump dir with policy_get.json / unique_uuids.json")
    parser.add_argument(
        "--output_dir", default="",
        help="PC dump + policy.json dir (default /tmp)")
    parser.add_argument("--unique-uuids", default="",
                        help="Path to unique_uuids.json")
    parser.add_argument("--global-uuid", default="",
                        help="zk /appliance/logical/flow/global_unique_uuid")
    parser.add_argument("--vlan-uuid", default="",
                        help="zk /appliance/logical/flow/vlan_unique_uuid")
    parser.add_argument(
        "--out", default="",
        help="Annotated proto-text (default: <policy>.port_sets.pbtxt)")
    parser.add_argument(
        "--json-out", default="",
        help="policy.json path (default: <dump_dir>/policy.json)")
    parser.add_argument(
        "--port-set-ips", default="",
        help="port_set_ips.json from vm_host_collect_port_set.py")
    parser.add_argument(
        "--vms", default="",
        help="vms_port_set.json (used if --port-set-ips is missing)")
    parser.add_argument(
        "--include-project", action="store_true",
        help="Append :project:<uuid> like ingest.py (validator does not)")
    parser.add_argument(
        "--in-place", action="store_true",
        help="Overwrite --policy with annotated proto-text")
    parser.add_argument(
        "--workers", type=int, default=8,
        help="Parallel policy.get workers for --from-pc")
    parser.add_argument(
        "--timeout", type=int, default=1800,
        help="policy.list/get timeout seconds for --from-pc")
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run a stdlib-only hash + unmarshal check and exit")
    return parser.parse_args()


def resolve_uuids(args, dump_dir):
    global_uuid = args.global_uuid or ""
    vlan_uuid = args.vlan_uuid or ""
    uuid_path = args.unique_uuids or ""
    if not uuid_path and dump_dir:
        cand = os.path.join(dump_dir, "unique_uuids.json")
        if os.path.isfile(cand):
            uuid_path = cand
    if uuid_path:
        loaded_global, loaded_vlan = load_unique_uuids(uuid_path)
        global_uuid = global_uuid or loaded_global
        vlan_uuid = vlan_uuid or loaded_vlan
    if (not global_uuid or not vlan_uuid) and dump_dir:
        os.makedirs(dump_dir, exist_ok=True)
        rec = dump_unique_uuids(dump_dir, detect_platform())
        global_uuid = global_uuid or rec.get("global_unique_uuid") or ""
        vlan_uuid = vlan_uuid or rec.get("vlan_unique_uuid") or ""
    if not global_uuid or not vlan_uuid:
        raise SystemExit(
            "need unique_uuids.json. On the PC run: python3 update_policy_port_sets.py --from-pc")
    return global_uuid, vlan_uuid


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")


def main():
    args = parse_args()
    setup_logging()
    if args.self_test:
        self_test()
        return
    dump_dir = args.dump_dir or args.output_dir or ""
    from_pc = args.from_pc
    if dump_dir and not args.policy:
        if not os.path.isfile(os.path.join(dump_dir, "policy_get.json")):
            from_pc = True
    if from_pc:
        dump_dir = args.output_dir or args.dump_dir or DEFAULT_OUTPUT_BASE
        os.makedirs(dump_dir, exist_ok=True)
        run_collect(dump_dir, workers=args.workers, timeout=args.timeout)
        rec = dump_from_pc(dump_dir, workers=args.workers, timeout=args.timeout)
        LOG.info("dump done platform=%s errors=%s",
                 rec.get("platform"), rec.get("errors") or {})
    if not dump_dir and not args.policy:
        raise SystemExit("on the PC run: python3 update_policy_port_sets.py --from-pc")
    if args.policy and not dump_dir:
        dump_dir = os.path.dirname(os.path.abspath(args.policy)) or "."
    global_uuid, vlan_uuid = resolve_uuids(args, dump_dir)
    json_path = args.json_out or os.path.join(dump_dir, "policy.json")
    ps_ip_map = load_port_set_ip_map(
        dump_dir, explicit=(args.port_set_ips or args.vms or ""))
    stats, json_path, proto_path = run_build(
        dump_dir, global_uuid, vlan_uuid, args.include_project, json_path,
        policy_path=args.policy, proto_out=args.out, in_place=args.in_place,
        ps_ip_map=ps_ip_map)
    print("global_unique_uuid=%s" % global_uuid)
    print("vlan_unique_uuid=%s" % vlan_uuid)
    print(
        "policies=%s rules=%s port_sets=%s address_sets=%s skipped=%s "
        "services=%s ag_resolved=%s sg_resolved=%s port_sets_with_ips=%s" % (
            stats["policies"], stats["rules"],
            stats["components_hashed"], stats["address_sets"],
            stats["components_skipped"], stats["services"],
            stats["address_groups_resolved"], stats["service_groups_resolved"],
            stats.get("port_sets_with_ips") or 0))
    print("policy.json=%s" % os.path.abspath(json_path))
    if proto_path:
        print("proto=%s" % os.path.abspath(proto_path))


if __name__ == "__main__":
    main()
