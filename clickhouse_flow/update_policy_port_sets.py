#!/usr/bin/env python3
"""Dump Flow policies and write policy.json with hashes and unmarshalled groups.

Runs on the PC (CMSP or SMSP) with system python3. Stdlib only. No nutest,
no neo4j, no pip. Copy this file and flow_pc_dump.py to the PC.

  python3 update_policy_port_sets.py --from-pc
  python3 update_policy_port_sets.py --dump_dir /path/to/flow_pc_dump

policy.json has, per rule component:
  - port_set_uuid   EG / VM / SUBNET / VPC category (uuid5 APPLICATION)
  - address_set     address_group / ip_subnet (uuid5(ag, "IPv4"|"IPv6"))
  - address_group   resolved CIDRs, ranges, FQDNs
  - service_group   unmarshalled TCP/UDP/ICMP ports

Dump path (same as flow_pc_dump.py):
  SMSP: kratos kubectl / flow_cli websocket, atlas ZK unique UUIDs
  CMSP: local flow_cli, zkcat unique UUIDs, Flow venv ServiceGroupGet
"""

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import logging
import os
import re
import sys
import tempfile
import uuid as uuid_lib

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
DEFAULT_OUTPUT_BASE = "/home/nutanix/upgrade/policy_dump"
IDF_AG_TYPES = ("network_address_group", "address_group")
IDF_FQDN_TYPES = ("fns_fqdn_to_ip_info",)


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
                       ag_map=None, fqdn_map=None):
    ag_map = ag_map or {}
    fqdn_map = fqdn_map or {}
    entity_type, refs, skip = component_refs(comp)
    role = comp.get("_key") or ""
    row = {
        "role": role,
        "kind": "",
        "entity_type": entity_type,
        "refs": refs,
        "skip_reason": skip or None,
        "hash_body": "",
        "port_set_uuid": "",
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
    row["kind"] = "port_set"
    row["hash_body"] = body
    row["port_set_uuid"] = hashed
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
                    ag_map=None, sg_map=None, fqdn_map=None):
    ag_map = ag_map or {}
    sg_map = sg_map or {}
    fqdn_map = fqdn_map or {}
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
                    ag_map=ag_map, fqdn_map=fqdn_map)
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
    for policy in policies_out:
        rules += len(policy.get("rules") or [])
        for rule in policy.get("rules") or []:
            for svc in rule.get("services") or []:
                services += 1
                rec = svc.get("service_group") or {}
                if rec and not rec.get("missing"):
                    sg_resolved += 1
            for comp in rule.get("components") or []:
                if comp.get("port_set_uuid"):
                    hashed += 1
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
    }


def find_flow_pc_dump():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = (
        os.path.join(here, "flow_pc_dump.py"),
        os.path.join(os.path.dirname(here), "flow_pc_dump.py"),
        os.path.join(os.getcwd(), "flow_pc_dump.py"),
        os.path.join("/home/nutanix/data", "flow_pc_dump.py"),
    )
    for path in candidates:
        if os.path.isfile(path):
            return path
    return ""


def load_flow_pc_dump():
    path = find_flow_pc_dump()
    if not path:
        raise SystemExit(
            "need flow_pc_dump.py next to this script (copy both files to the PC)")
    spec = importlib.util.spec_from_file_location("flow_pc_dump", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dump_from_pc(output_dir, workers=8, timeout=1800):
    dump = load_flow_pc_dump()
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "dump.log")
    dump._setup_logging(log_file)
    orig_types = list(dump.IDF_TYPES)
    dump.IDF_TYPES = IDF_AG_TYPES + IDF_FQDN_TYPES
    info = dump.detect_platform()
    LOG.info("platform=%s smsp=%s output=%s",
             info.get("platform"), info.get("smsp_cluster_uuid") or "", output_dir)
    rec = {
        "platform": info.get("platform") or "cmsp",
        "smsp_cluster_uuid": info.get("smsp_cluster_uuid") or "",
    }
    try:
        idf_index, idf_err = dump.dump_idfcli(
            output_dir, min(4, int(workers) or 1), 180)
        rec["idfcli"] = idf_index
        rec["flow"] = dump.dump_flow(output_dir, workers, timeout, info)
        rec["unique_uuids"] = dump.dump_unique_uuids(output_dir, info)
        errors = {}
        errors.update(idf_err or {})
        errors.update((rec.get("flow") or {}).get("errors") or {})
        rec["errors"] = errors
    finally:
        dump.IDF_TYPES = orig_types
    dump._write_json(os.path.join(output_dir, "dump_index.json"), rec)
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


def run_build(dump_dir, global_uuid, vlan_uuid, include_project, json_path,
              policy_path="", proto_out="", in_place=False):
    policies, proto_lines = load_policies(dump_dir, policy_path)
    if not policies:
        raise SystemExit(
            "no policies in policy_get.json or proto policy_list.json under %s"
            % (dump_dir or policy_path or "."))
    ag_map = load_ag_map(dump_dir) if dump_dir else {}
    sg_map = load_sg_map(dump_dir) if dump_dir else {}
    fqdn_map = load_fqdn_map(dump_dir) if dump_dir else {}
    LOG.info("loaded policies=%s address_groups=%s service_groups=%s",
             len(policies), len(ag_map), len(sg_map))
    policies_out = []
    insertions = []
    for policy in policies:
        annotated, extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project,
            ag_map=ag_map, sg_map=sg_map, fqdn_map=fqdn_map)
        policies_out.append(annotated)
        insertions.extend(extra)
    payload, stats = build_policy_json(
        policies_out, global_uuid, vlan_uuid, include_project,
        extra={
            "address_groups": len(ag_map),
            "service_groups": len(sg_map),
        })
    json_path = json_path or os.path.join(dump_dir or ".", "policy.json")
    dest_dir = os.path.dirname(os.path.abspath(json_path)) or "."
    os.makedirs(dest_dir, exist_ok=True)
    tmp_path = json_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
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
            "port_set, address_set, unmarshalled address_group and service_group"))
    parser.add_argument(
        "--from-pc", action="store_true",
        help="Dump on this PC via flow_pc_dump.py then write policy.json")
    parser.add_argument("--policy", default="",
                        help="Proto-text or policy.get JSON")
    parser.add_argument("--dump_dir", default="",
                        help="Dump dir with policy_get.json / unique_uuids.json")
    parser.add_argument(
        "--output_dir", default="",
        help="PC dump + policy.json dir (default %s)" % DEFAULT_OUTPUT_BASE)
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
    if not global_uuid or not vlan_uuid:
        raise SystemExit(
            "need --global-uuid and --vlan-uuid, or unique_uuids.json from PC dump")
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
    if args.from_pc:
        dump_dir = args.output_dir or args.dump_dir or DEFAULT_OUTPUT_BASE
        rec = dump_from_pc(dump_dir, workers=args.workers, timeout=args.timeout)
        LOG.info("dump done platform=%s errors=%s",
                 rec.get("platform"), rec.get("errors") or {})
    if not dump_dir and not args.policy:
        raise SystemExit("need --from-pc, --dump_dir, or --policy")
    if args.policy and not dump_dir:
        dump_dir = os.path.dirname(os.path.abspath(args.policy)) or "."
    global_uuid, vlan_uuid = resolve_uuids(args, dump_dir)
    json_path = args.json_out or os.path.join(dump_dir, "policy.json")
    stats, json_path, proto_path = run_build(
        dump_dir, global_uuid, vlan_uuid, args.include_project, json_path,
        policy_path=args.policy, proto_out=args.out, in_place=args.in_place)
    print("global_unique_uuid=%s" % global_uuid)
    print("vlan_unique_uuid=%s" % vlan_uuid)
    print(
        "policies=%s rules=%s port_sets=%s address_sets=%s skipped=%s "
        "services=%s ag_resolved=%s sg_resolved=%s" % (
            stats["policies"], stats["rules"],
            stats["components_hashed"], stats["address_sets"],
            stats["components_skipped"], stats["services"],
            stats["address_groups_resolved"], stats["service_groups_resolved"]))
    print("policy.json=%s" % os.path.abspath(json_path))
    if proto_path:
        print("proto=%s" % os.path.abspath(proto_path))


if __name__ == "__main__":
    main()
