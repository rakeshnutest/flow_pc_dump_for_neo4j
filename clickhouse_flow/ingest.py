#!/usr/bin/env python3
"""Ingest dump JSON into the flat flow_policy.portset table.

computed_port_set_uuid uses neo4j_db_insert.generate_port_set_id /
compute_hash_value (see portset_hash.py). Every policy is ingested
(APPLICATION, FLEX, kube/Cilium included). Address-set hashes are not
inserted as port-sets. Compare keeps Atlas-only leftovers as mismatches;
leftover analysis is a separate skill that ignores kube.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import uuid as uuid_lib
from collections import defaultdict

from portset_hash import (
    DEFAULT_PROJECT_EXT_ID,
    compute_hash_value,
)

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
BATCH = 10_000
ZERO = "00000000-0000-0000-0000-000000000000"
ALL_VLAN_VPC = "00000000-0000-0000-0000-000000000001"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
CAT_TYPE_MAP = {"VM": "kVM", "VPC": "kVPC", "SUBNET": "kSubnet"}


def as_uuid(value):
    text = str(value or "").strip()
    if not text or not UUID_RE.match(text):
        return ""
    return text.lower()


def uuid_list(values):
    out = []
    seen = set()
    for item in values or []:
        uid = as_uuid(item)
        if uid and uid not in seen and uid != ZERO:
            seen.add(uid)
            out.append(uid)
    return out


def namespace_for_policy(policy, vlan_uuid, global_uuid):
    """Return (hash_namespace, scope). Hash namespace is UUID-only.

    ALL_VLAN / GLOBAL use the Flow unique UUIDs. VPC_LIST uses the first VPC
    UUID. VPC_AS_CATEGORY uses the first scope category UUID (same as
    neo4j_db_insert.compute_hash_value).
    """
    scope = str(policy.get("scope") or "ALL_VLAN")
    if scope in ("ALL_VLAN", "kAllVlan"):
        return vlan_uuid, scope
    if scope in ("GLOBAL", "kGlobal", "ALL_VPC"):
        return global_uuid, scope
    if scope == "VPC_AS_CATEGORY":
        refs = uuid_list(policy.get("scope_references"))
        return (refs[0] if refs else ""), scope
    refs = uuid_list(
        policy.get("vpc_references") or policy.get("scope_references"))
    if refs:
        return refs[0], scope
    return "", scope


def policy_project_uuid(policy):
    """Non-default project UUID, or empty. Atlas appends :project:<uuid>."""
    project = as_uuid(
        policy.get("project_ext_id")
        or policy.get("projectExtId")
        or (policy.get("project") or {}).get("ext_id"))
    if not project or project == ZERO:
        return ""
    return project


def unwrap(row):
    if isinstance(row, dict) and isinstance(row.get("data"), dict):
        return row["data"]
    return row or {}


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as handle:
        return json.load(handle)


def ch_client(*args, input_text=None):
    cmd = [
        "clickhouse-client",
        "--host", CH_HOST,
        "--port", CH_NATIVE,
        "--user", "default",
    ]
    cmd.extend(args)
    proc = subprocess.run(
        cmd, input=input_text, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "ch failed")
    return proc.stdout


def insert_json(table, rows):
    if not rows:
        return
    for offset in range(0, len(rows), BATCH):
        chunk = rows[offset:offset + BATCH]
        payload = "\n".join(json.dumps(row) for row in chunk)
        ch_client(
            "--query",
            "INSERT INTO %s FORMAT JSONEachRow" % table,
            input_text=payload)


def ips_in_range(start_ip, end_ip, cap=8192):
    """Same idea as neo4j_db_insert.get_ips_in_range, with a safety cap."""
    try:
        start = ipaddress.ip_address(str(start_ip))
        end = ipaddress.ip_address(str(end_ip))
    except ValueError:
        return []
    if start > end:
        start, end = end, start
    n = int(end) - int(start) + 1
    if n > cap:
        return ["%s/%s" % (start, start.max_prefixlen)]
    out = []
    current = start
    while current <= end:
        out.append(str(current))
        current = ipaddress.ip_address(int(current) + 1)
    return out


def cidrs_from_addresses(addresses):
    out = []
    for addr in addresses or []:
        if not isinstance(addr, dict):
            continue
        value = addr.get("value")
        prefix = addr.get("prefix_length")
        if value is not None and prefix is not None:
            out.append("%s/%s" % (value, prefix))
    return out


def cidrs_from_ip_ranges(ranges):
    out = []
    for rng in ranges or []:
        if not isinstance(rng, dict):
            continue
        start = rng.get("start_ip")
        end = rng.get("end_ip")
        if start and end:
            out.extend(ips_in_range(start, end))
    ipv4_ranges = ranges.get("ipv4_ranges") if isinstance(ranges, dict) else None
    if ipv4_ranges:
        out.extend(cidrs_from_ip_ranges(ipv4_ranges))
    return out


def expand_entity_group(eg, ag_map=None):
    ag_map = ag_map or {}
    sel = {
        "vm_category_refs": [],
        "subnet_category_refs": [],
        "vpc_category_refs": [],
        "vm_ext_ids": [],
        "subnet_ext_ids": [],
        "subnet_list": [],
        "exception_list": [],
        "entity_group_uuid": as_uuid(eg.get("ext_id")),
        "is_kube": False,
    }
    allowed = ((eg.get("allowed_config") or {}).get("entities")) or []
    kinds = [str(entity.get("type") or "").upper() for entity in allowed]
    sel["is_kube"] = any(k.startswith("KUBE") for k in kinds) and not any(
        k in ("VM", "SUBNET", "VPC") for k in kinds)
    for entity in allowed:
        kind = str(entity.get("type") or "").upper()
        select_by = str(entity.get("select_by") or "")
        refs = uuid_list(entity.get("reference_ext_ids"))
        if kind == "VM" and select_by == "CATEGORY_EXT_ID":
            sel["vm_category_refs"].extend(refs)
        elif kind == "VM":
            sel["vm_ext_ids"].extend(refs)
        elif kind == "SUBNET" and select_by == "CATEGORY_EXT_ID":
            sel["subnet_category_refs"].extend(refs)
        elif kind == "SUBNET":
            sel["subnet_ext_ids"].extend(refs)
        elif kind == "VPC":
            sel["vpc_category_refs"].extend(refs)
        elif kind == "ADDRESS_GROUP":
            addrs = entity.get("addresses") or {}
            sel["subnet_list"].extend(cidrs_from_addresses(addrs.get("ipv4_addresses")))
            sel["subnet_list"].extend(cidrs_from_addresses(addrs.get("ipv6_addresses")))
            ranges = entity.get("ip_ranges") or {}
            if isinstance(ranges, dict):
                sel["subnet_list"].extend(cidrs_from_ip_ranges(ranges.get("ipv4_ranges")))
            else:
                sel["subnet_list"].extend(cidrs_from_ip_ranges(ranges))
            for ag_ref in refs:
                sel["subnet_list"].extend(
                    (ag_map.get(ag_ref) or {}).get("subnet_list") or [])
    excepted = ((eg.get("except_config") or {}).get("entities")) or []
    for entity in excepted:
        kind = str(entity.get("type") or "").upper()
        if kind != "ADDRESS_GROUP":
            continue
        addrs = entity.get("addresses") or {}
        sel["exception_list"].extend(cidrs_from_addresses(addrs.get("ipv4_addresses")))
        sel["exception_list"].extend(cidrs_from_addresses(addrs.get("ipv6_addresses")))
        for ag_ref in uuid_list(entity.get("reference_ext_ids")):
            sel["exception_list"].extend(
                (ag_map.get(ag_ref) or {}).get("subnet_list") or [])
    for key in (
            "vm_category_refs", "subnet_category_refs", "vpc_category_refs",
            "vm_ext_ids", "subnet_ext_ids"):
        sel[key] = uuid_list(sel[key])
    return sel


def expand_address_group(ag):
    """CIDRs from an address group, same fields neo4j_db_insert.ag_map uses."""
    out = []
    out.extend(cidrs_from_addresses(ag.get("ipv4_addresses")))
    out.extend(cidrs_from_addresses(ag.get("ipv6_addresses")))
    ranges = ag.get("ip_ranges") or []
    if isinstance(ranges, dict):
        out.extend(cidrs_from_ip_ranges(ranges.get("ipv4_ranges")))
    else:
        out.extend(cidrs_from_ip_ranges(ranges))
    return list(dict.fromkeys(out))


def policy_hash_vpc_refs(policy, scope):
    """policy_vpc_references passed into compute_hash_value."""
    if scope == "VPC_AS_CATEGORY":
        return uuid_list(policy.get("scope_references"))
    if scope == "VPC_LIST":
        return uuid_list(
            policy.get("vpc_references") or policy.get("scope_references"))
    return []


def hash_selector(
        sel, scope, project_uuid, vpc_refs, vlan_uuid, global_uuid,
        is_flex, is_endpoint):
    """Call neo4j_db_insert.compute_hash_value. Skip Atlas 'all' port-sets."""
    vm_refs = list(sel.get("vm_category_refs") or [])
    if vm_refs == ["all"] or "all" in vm_refs or "any" in vm_refs:
        return "", [], ""
    eg = as_uuid(sel.get("entity_group_uuid"))
    hashed = compute_hash_value(
        vm_category_refs=uuid_list(vm_refs),
        subnet_category_refs=uuid_list(sel.get("subnet_category_refs")),
        vpc_category_refs=uuid_list(sel.get("vpc_category_refs")),
        entity_group_ref=eg,
        addresses=list(sel.get("addresses") or []),
        subnet_list=list(sel.get("subnet_list") or []),
        policy_vpc_references=vpc_refs,
        scope=scope,
        vm_ext_ids=uuid_list(sel.get("vm_ext_ids")),
        subnet_ext_ids=uuid_list(sel.get("subnet_ext_ids")),
        project_uuid=project_uuid or DEFAULT_PROJECT_EXT_ID,
        is_flex=is_flex,
        is_endpoint=is_endpoint,
        vlan_unique_uuid=vlan_uuid,
        global_unique_uuid=global_uuid,
    )
    if not hashed or isinstance(hashed, list):
        return "", [], ""
    if eg:
        return "EG", [eg], hashed
    if uuid_list(vm_refs) or uuid_list(sel.get("vm_ext_ids")):
        return "VM", uuid_list(vm_refs) or uuid_list(sel.get("vm_ext_ids")), hashed
    if uuid_list(sel.get("subnet_category_refs")) or uuid_list(sel.get("subnet_ext_ids")):
        return "SUBNET", (
            uuid_list(sel.get("subnet_category_refs"))
            or uuid_list(sel.get("subnet_ext_ids"))), hashed
    if uuid_list(sel.get("vpc_category_refs")):
        return "VPC", uuid_list(sel.get("vpc_category_refs")), hashed
    return "", [], hashed


def ip_in_cidrs(ips, cidrs):
    networks = []
    for cidr in cidrs or []:
        try:
            networks.append(ipaddress.ip_network(str(cidr), strict=False))
        except ValueError:
            continue
    if not networks:
        return False
    for ip in ips or []:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if any(addr in net for net in networks):
            return True
    return False


def nic_index(nics):
    by_vm_cat = defaultdict(set)
    by_sub_cat = defaultdict(set)
    by_vpc_cat = defaultdict(set)
    by_vm = defaultdict(set)
    by_subnet = defaultdict(set)
    by_vpc = defaultdict(set)
    all_nics = {}
    for nic in nics:
        uid = nic["nic_uuid"]
        all_nics[uid] = nic
        by_vm[nic["vm_uuid"]].add(uid)
        by_subnet[nic["subnet_uuid"]].add(uid)
        if nic["vpc_uuid"]:
            by_vpc[nic["vpc_uuid"]].add(uid)
        for cat in nic["vm_cat_ids"]:
            by_vm_cat[cat].add(uid)
        for cat in nic["subnet_cat_ids"]:
            by_sub_cat[cat].add(uid)
        for cat in nic["vpc_cat_ids"]:
            by_vpc_cat[cat].add(uid)
    return {
        "by_vm_cat": by_vm_cat,
        "by_sub_cat": by_sub_cat,
        "by_vpc_cat": by_vpc_cat,
        "by_vm": by_vm,
        "by_subnet": by_subnet,
        "by_vpc": by_vpc,
        "all_nics": all_nics,
    }


def intersect_cat(index_map, refs):
    if not refs:
        return None
    groups = [index_map.get(ref, set()) for ref in refs]
    out = set(groups[0])
    for group in groups[1:]:
        out &= group
        if not out:
            break
    return out


def scope_nics(matched, index, namespace, vlan_uuid, global_uuid, scope):
    if not matched:
        return matched
    if scope in ("ALL_VLAN", "kAllVlan") or namespace == vlan_uuid:
        return matched & index["by_vpc"].get(ALL_VLAN_VPC, set())
    if scope in ("GLOBAL", "kGlobal", "ALL_VPC", "VPC_AS_CATEGORY"):
        return matched
    if namespace == global_uuid:
        return matched
    return matched & index["by_vpc"].get(namespace, set())


def match_nics(sel, index, namespace, vlan_uuid, global_uuid, scope):
    vm_refs = [u for u in (sel.get("vm_category_refs") or []) if u not in ("all", "any")]
    sub_refs = [u for u in (sel.get("subnet_category_refs") or []) if u not in ("all", "any")]
    vpc_refs = uuid_list(sel.get("vpc_category_refs"))
    vm_ext = uuid_list(sel.get("vm_ext_ids"))
    sub_ext = uuid_list(sel.get("subnet_ext_ids"))
    cidrs = sel.get("subnet_list") or []

    if sel.get("vm_category_refs") == ["all"] or "all" in (sel.get("vm_category_refs") or []):
        return set()

    if vm_ext or sub_ext:
        out = set()
        for vm_uuid in vm_ext:
            out |= index["by_vm"].get(vm_uuid, set())
        for subnet_uuid in sub_ext:
            out |= index["by_subnet"].get(subnet_uuid, set())
        return scope_nics(out, index, namespace, vlan_uuid, global_uuid, scope)

    vm_set = intersect_cat(index["by_vm_cat"], vm_refs)
    sub_set = intersect_cat(index["by_sub_cat"], sub_refs)
    vpc_set = intersect_cat(index["by_vpc_cat"], vpc_refs)

    if vm_refs and not sub_refs:
        matched = vm_set or set()
    elif sub_refs and not vm_refs:
        matched = sub_set or set()
    elif vm_refs and sub_refs:
        matched = (vm_set or set()) & (sub_set or set())
    elif vpc_refs:
        matched = vpc_set or set()
    elif cidrs:
        matched = set()
        for nic_uuid, nic in index["all_nics"].items():
            if ip_in_cidrs(nic["ips"], cidrs):
                matched.add(nic_uuid)
    else:
        return set()
    return scope_nics(matched, index, namespace, vlan_uuid, global_uuid, scope)


def learned_ips(nic):
    info = (nic.get("nic_network_info") or {}).get("ipv4_info") or {}
    out = []
    for item in info.get("learned_ip_addresses") or []:
        if isinstance(item, dict):
            val = item.get("value")
            if val:
                out.append(str(val))
        elif item:
            out.append(str(item))
    return out


def collect_nics(vms):
    nics = []
    for vm in vms or []:
        vm_uuid = as_uuid(vm.get("ext_id"))
        vm_cat_ids = uuid_list(
            vm.get("category_ids")
            or (vm.get("metadata") or {}).get("category_ids"))
        for nic in vm.get("nics") or []:
            nic_uuid = as_uuid(nic.get("ext_id"))
            if not nic_uuid:
                continue
            net = nic.get("nic_network_info") or {}
            subnet = net.get("subnet") or {}
            vpc = net.get("vpc") or {}
            nic_vm_cats = uuid_list(net.get("vm_category_ids") or vm_cat_ids)
            nics.append({
                "nic_uuid": nic_uuid,
                "vm_uuid": vm_uuid or ZERO,
                "vm_name": str(vm.get("name") or ""),
                "subnet_uuid": as_uuid(subnet.get("ext_id")) or ZERO,
                "subnet": str(subnet.get("name") or ""),
                "vpc_uuid": as_uuid(vpc.get("ext_id")) or ZERO,
                "vpc": str(vpc.get("name") or ""),
                "vm_cat_ids": nic_vm_cats,
                "subnet_cat_ids": uuid_list(subnet.get("category_ids")),
                "vpc_cat_ids": uuid_list(vpc.get("category_ids")),
                "ips": learned_ips(nic),
                "ip": ",".join(learned_ips(nic)),
            })
    return nics


def add_component(
        components, role, sel, policy, rule, namespace, scope, eg_map,
        project_uuid, vlan_uuid, global_uuid):
    if sel.get("entity_group_uuid") and sel["entity_group_uuid"] in eg_map:
        expanded = dict(eg_map[sel["entity_group_uuid"]])
        for key, value in sel.items():
            if key == "entity_group_uuid":
                continue
            if value:
                expanded[key] = value
        sel = expanded
    is_flex = str(rule.get("type") or "") == "FLEX"
    # neo4j applied_hash_value uses is_flex only (is_endpoint defaults false).
    is_endpoint = role not in ("secured", "applied_to")
    entity_type, refs, port_set = hash_selector(
        sel, scope, project_uuid, policy_hash_vpc_refs(policy, scope),
        vlan_uuid, global_uuid, is_flex, is_endpoint)
    if not port_set:
        return
    rule_uuid = as_uuid(rule.get("ext_id")) or ZERO
    policy_uuid = as_uuid(policy.get("ext_id")) or ZERO
    component_id = "%s:%s:%s" % (policy_uuid, rule_uuid, role)
    components.append({
        "entity_type": entity_type or "VM",
        "port_set_uuid": port_set,
        "policy_uuid": policy_uuid,
        "policy_name": str(policy.get("name") or ""),
        "rule_uuid": rule_uuid,
        "role": role,
        "component_id": component_id,
        "namespace_uuid": namespace,
        "policy_scope": scope,
        "virtual_network_uuid": ZERO,
        "entity_group_uuid": sel.get("entity_group_uuid") or ZERO,
        "entity_group_name": "",
        "reference_uuids": refs,
        "vm_category_refs": uuid_list(sel.get("vm_category_refs")),
        "subnet_category_refs": uuid_list(sel.get("subnet_category_refs")),
        "vpc_category_refs": uuid_list(sel.get("vpc_category_refs")),
        "vm_ext_ids": uuid_list(sel.get("vm_ext_ids")),
        "subnet_ext_ids": uuid_list(sel.get("subnet_ext_ids")),
        "subnet_list": list(sel.get("subnet_list") or []),
        "exception_list": list(sel.get("exception_list") or []),
        "sel": sel,
    })


def selectors_from_spec(spec, ag_map=None):
    out = []
    ag_map = ag_map or {}
    sg_refs = uuid_list(spec.get("secured_group_category_references"))
    sg_eg = as_uuid(spec.get("secured_group_entity_group_reference"))
    if sg_refs:
        et = str(spec.get("secured_group_category_associated_entity_type") or "VM")
        sel = {
            "vm_category_refs": sg_refs if et == "VM" else [],
            "subnet_category_refs": sg_refs if et == "SUBNET" else [],
            "vpc_category_refs": sg_refs if et == "VPC" else [],
        }
        out.append(("secured", sel))
    elif sg_eg:
        out.append(("secured", {"entity_group_uuid": sg_eg}))

    def subnet_cidrs(key):
        subnet = spec.get(key)
        if not isinstance(subnet, dict):
            return []
        value = subnet.get("value")
        prefix = subnet.get("prefix_length")
        if value is None or prefix is None:
            return []
        return ["%s/%s" % (value, prefix)]

    src_cidrs = subnet_cidrs("src_subnet")
    dst_cidrs = subnet_cidrs("dest_subnet")
    if src_cidrs:
        out.append(("src", {"subnet_list": src_cidrs}))
    if dst_cidrs:
        out.append(("dest", {"subnet_list": dst_cidrs}))

    applied = uuid_list(spec.get("applied_to_entity_group_references"))
    if applied:
        out.append(("applied_to", {"entity_group_uuid": applied[0]}))

    ag_src = uuid_list(spec.get("src_address_group_references"))
    ag_dst = uuid_list(spec.get("dest_address_group_references"))
    # neo4j_db_insert FLEX: address groups become Endpoint subnet_list +
    # addresses, hashed as address_set (not port_set). Prefer AG over "all".
    if spec.get("should_allow_any_src") and not ag_src:
        out.append(("src", {"vm_category_refs": ["all"]}))
    if spec.get("should_allow_any_dst") and not ag_dst:
        out.append(("dest", {"vm_category_refs": ["all"]}))
    if ag_src:
        cidrs = []
        for uid in ag_src:
            cidrs.extend((ag_map.get(uid) or {}).get("subnet_list") or [])
        out.append(("src", {"addresses": ag_src, "subnet_list": cidrs}))
    if ag_dst:
        cidrs = []
        for uid in ag_dst:
            cidrs.extend((ag_map.get(uid) or {}).get("subnet_list") or [])
        out.append(("dest", {"addresses": ag_dst, "subnet_list": cidrs}))

    for side, prefix in (("src", "src"), ("dest", "dest")):
        refs = uuid_list(spec.get("%s_category_references" % prefix))
        et = str(spec.get("%s_category_associated_entity_type" % prefix) or "VM")
        eg = as_uuid(spec.get("%s_entity_group_reference" % prefix))
        if not eg:
            eg_list = uuid_list(spec.get("%s_entity_group_references" % prefix))
            eg = eg_list[0] if eg_list else ""
        if refs:
            sel = {
                "vm_category_refs": refs if et == "VM" else [],
                "subnet_category_refs": refs if et == "SUBNET" else [],
                "vpc_category_refs": refs if et == "VPC" else [],
            }
            out.append((side, sel))
        elif eg:
            out.append((side, {"entity_group_uuid": eg}))

    first = uuid_list(spec.get("first_isolation_group"))
    second = uuid_list(spec.get("second_isolation_group"))
    if first:
        out.append(("isolation_a", {"vm_category_refs": first}))
    if second:
        out.append(("isolation_b", {"vm_category_refs": second}))
    nested = ((spec.get("spec") or {}).get("isolation_groups")) or []
    for idx, group in enumerate(nested):
        refs = uuid_list(group.get("group_category_references"))
        et = str(group.get("group_category_associated_entity_type") or "VM")
        eg = as_uuid(group.get("group_entity_group_reference"))
        role = "isolation_%s" % idx
        if refs:
            sel = {
                "vm_category_refs": refs if et == "VM" else [],
                "subnet_category_refs": refs if et == "SUBNET" else [],
                "vpc_category_refs": refs if et == "VPC" else [],
            }
            out.append((role, sel))
        elif eg:
            out.append((role, {"entity_group_uuid": eg}))
    return out


def atlas_by_uuid(port_set_list, port_set_get):
    if isinstance(port_set_get, dict):
        records = list(port_set_get.values())
    else:
        records = port_set_get or []
    by_uuid = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        uid = as_uuid(rec.get("uuid") or rec.get("ext_id"))
        if uid:
            by_uuid[uid] = rec
    listed = port_set_list or []
    if isinstance(listed, dict):
        listed = list(listed.values())
    out = {}
    for item in listed:
        uid = as_uuid(item.get("uuid") if isinstance(item, dict) else item)
        if not uid or uid in out:
            continue
        rec = by_uuid.get(uid) or (item if isinstance(item, dict) else {})
        listed_name = str(item.get("name") or "") if isinstance(item, dict) else ""
        out[uid] = {
            "virtual_network_uuid": as_uuid(rec.get("virtual_network_uuid")) or ZERO,
            "atlas_nic_uuids": uuid_list(rec.get("virtual_nic_uuid_list")),
            "atlas_name": str(rec.get("name") or listed_name or ""),
            "vpc_name": str(rec.get("virtual_network_name") or ""),
        }
    for uid, rec in by_uuid.items():
        if uid in out:
            continue
        out[uid] = {
            "virtual_network_uuid": as_uuid(rec.get("virtual_network_uuid")) or ZERO,
            "atlas_nic_uuids": uuid_list(rec.get("virtual_nic_uuid_list")),
            "atlas_name": str(rec.get("name") or ""),
            "vpc_name": str(rec.get("virtual_network_name") or ""),
        }
    return out


def category_name_map(categories):
    out = {}
    for row in categories or []:
        data = unwrap(row)
        uid = as_uuid(data.get("ext_id") or data.get("uuid"))
        if not uid:
            continue
        key = str(data.get("key") or "")
        value = str(data.get("value") or "")
        name = str(data.get("name") or "")
        if key and value:
            out[uid] = "%s:%s" % (key, value)
        else:
            out[uid] = name or value or key
    return out


def named_map(rows, name_key="name"):
    out = {}
    for row in rows or []:
        data = unwrap(row)
        uid = as_uuid(data.get("ext_id") or data.get("uuid"))
        if uid:
            out[uid] = str(data.get(name_key) or data.get("name") or "")
    return out


def map_names(uuids, mapping):
    return [mapping.get(uid, "") for uid in uuids]


def nic_tuples(uuids, by_uuid):
    """(vm_name, nic_uuid, subnet, vpc, ip) per NIC."""
    out = []
    for uid in uuids:
        rec = by_uuid.get(uid) or {}
        out.append({
            "vm_name": rec.get("vm_name") or "",
            "nic_uuid": uid,
            "subnet": rec.get("subnet") or "",
            "vpc": rec.get("vpc") or "",
            "ip": rec.get("ip") or "",
        })
    return out


def attach_nics(components, nics, vlan_uuid, global_uuid):
    index = nic_index(nics)
    cache = {}
    for comp in components:
        sel = comp.pop("sel")
        if sel.get("vm_category_refs") == ["all"] or "all" in (sel.get("vm_category_refs") or []):
            comp["computed_nic_uuids"] = []
            continue
        key = (
            comp["namespace_uuid"],
            comp.get("policy_scope") or "",
            tuple(sel.get("vm_category_refs") or []),
            tuple(sel.get("subnet_category_refs") or []),
            tuple(sel.get("vpc_category_refs") or []),
            tuple(sel.get("vm_ext_ids") or []),
            tuple(sel.get("subnet_ext_ids") or []),
            tuple(sel.get("subnet_list") or []),
        )
        if key not in cache:
            cache[key] = match_nics(
                sel, index, comp["namespace_uuid"], vlan_uuid, global_uuid,
                comp.get("policy_scope") or "")
        comp["computed_nic_uuids"] = sorted(cache[key])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dump_dir",
        default="/home/rakeshkumar.r/panacea/flow_pc_dumps/full")
    parser.add_argument(
        "--schema",
        default=os.path.join(here, "schema.sql"))
    args = parser.parse_args()
    dump_dir = args.dump_dir

    ch_client("--query", "SELECT 1")
    with open(args.schema) as handle:
        ch_client("--multiquery", input_text=handle.read())

    meta = load_json(os.path.join(dump_dir, "meta.json"), {})
    vlan_uuid = as_uuid(meta.get("vlan_unique_uuid"))
    global_uuid = as_uuid(meta.get("global_unique_uuid"))
    vms = load_json(os.path.join(dump_dir, "vms.json"), [])
    policies = [unwrap(p) for p in load_json(os.path.join(dump_dir, "policies.json"), [])]
    egs = [unwrap(e) for e in load_json(os.path.join(dump_dir, "entity_groups.json"), [])]
    categories = load_json(os.path.join(dump_dir, "categories.json"), [])
    vpcs = load_json(os.path.join(dump_dir, "vpcs.json"), [])
    atlas_list = load_json(os.path.join(dump_dir, "port_set_list.json"), [])
    atlas_get = load_json(os.path.join(dump_dir, "port_set_get.json"), {})

    cat_map = category_name_map(categories)
    vpc_map = named_map(vpcs)
    eg_names = named_map(egs)
    insert_json("flow_policy.category", [
        {"category_uuid": uid, "name": name} for uid, name in cat_map.items()
    ])
    address_groups = [
        unwrap(row) for row in load_json(os.path.join(dump_dir, "address_groups.json"), [])]
    ag_map = {}
    for ag in address_groups:
        uid = as_uuid(ag.get("ext_id") or ag.get("uuid"))
        if uid:
            ag_map[uid] = {"subnet_list": expand_address_group(ag)}
    eg_map = {
        as_uuid(eg.get("ext_id")): expand_entity_group(eg, ag_map) for eg in egs}
    eg_map.pop("", None)
    nics = collect_nics(vms)
    insert_json("flow_policy.vm_nic", [{
        "nic_uuid": nic["nic_uuid"],
        "vm_uuid": nic["vm_uuid"] or ZERO,
        "vm_name": nic["vm_name"],
        "subnet_uuid": nic["subnet_uuid"] or ZERO,
        "subnet": nic["subnet"],
        "vpc_uuid": nic["vpc_uuid"] or ZERO,
        "vpc": nic["vpc"],
        "ip": nic["ip"],
    } for nic in nics])
    atlas = atlas_by_uuid(atlas_list, atlas_get)

    components = []
    for policy in policies:
        namespace, scope = namespace_for_policy(policy, vlan_uuid, global_uuid)
        if not namespace:
            continue
        project_uuid = policy_project_uuid(policy) or DEFAULT_PROJECT_EXT_ID
        for rule in policy.get("rules") or []:
            spec = rule.get("spec") or {}
            for role, sel in selectors_from_spec(spec, ag_map):
                add_component(
                    components, role, sel, policy, rule, namespace, scope,
                    eg_map, project_uuid, vlan_uuid, global_uuid)

    attach_nics(components, nics, vlan_uuid, global_uuid)
    nic_by_uuid = {nic["nic_uuid"]: nic for nic in nics}

    def fill_names(row, atlas_rec):
        computed = list(row.get("computed_nic_uuids") or [])
        atlas_nics = list(row.get("atlas_nic_uuids") or [])
        row["computed_nic_uuids"] = computed
        row["atlas_nic_uuids"] = atlas_nics
        row["computed_nics"] = nic_tuples(computed, nic_by_uuid)
        row["atlas_nics"] = nic_tuples(atlas_nics, nic_by_uuid)
        vn = row.get("virtual_network_uuid") or ZERO
        ns = row.get("namespace_uuid") or ZERO
        row["atlas_name"] = atlas_rec.get("atlas_name") or ""
        row["vpc_name"] = (
            atlas_rec.get("vpc_name")
            or vpc_map.get(vn)
            or vpc_map.get(ns)
            or "")
        row["entity_group_name"] = eg_names.get(row.get("entity_group_uuid"), "")
        row["vm_category_names"] = map_names(row.get("vm_category_refs") or [], cat_map)
        row["subnet_category_names"] = map_names(
            row.get("subnet_category_refs") or [], cat_map)
        row["vpc_category_names"] = map_names(row.get("vpc_category_refs") or [], cat_map)
        row["reference_names"] = [
            cat_map.get(uid) or eg_names.get(uid) or ""
            for uid in (row.get("reference_uuids") or [])
        ]
        row["policy_name"] = row.get("policy_name") or ""

    rows = []
    seen = set()
    for row in components:
        row.pop("policy_scope", None)
        ps = row["port_set_uuid"]
        seen.add(ps)
        atlas_rec = atlas.get(ps) or {}
        vn = atlas_rec.get("virtual_network_uuid") or ZERO
        if vn != ZERO:
            row["virtual_network_uuid"] = vn
        row["computed_port_set_uuid"] = ps
        row["atlas_port_set_uuid"] = ps if ps in atlas else ZERO
        row["computed_nic_uuids"] = list(row.get("computed_nic_uuids") or [])
        row["atlas_nic_uuids"] = list(atlas_rec.get("atlas_nic_uuids") or [])
        fill_names(row, atlas_rec)
        rows.append(row)
    for ps, atlas_rec in atlas.items():
        if ps in seen:
            continue
        row = {
            "port_set_uuid": ps,
            "computed_port_set_uuid": ZERO,
            "atlas_port_set_uuid": ps,
            "policy_uuid": ZERO,
            "policy_name": "",
            "rule_uuid": ZERO,
            "role": "",
            "component_id": ps,
            "entity_type": "",
            "namespace_uuid": ZERO,
            "virtual_network_uuid": atlas_rec.get("virtual_network_uuid") or ZERO,
            "entity_group_uuid": ZERO,
            "reference_uuids": [],
            "vm_category_refs": [],
            "subnet_category_refs": [],
            "vpc_category_refs": [],
            "vm_ext_ids": [],
            "subnet_ext_ids": [],
            "subnet_list": [],
            "exception_list": [],
            "computed_nic_uuids": [],
            "atlas_nic_uuids": list(atlas_rec.get("atlas_nic_uuids") or []),
        }
        fill_names(row, atlas_rec)
        rows.append(row)
    insert_json("flow_policy.portset", rows)

    print("nics", len(nics))
    print("atlas_uuids", len(atlas))
    print("computed_components", len(components))
    print("computed_uuids", len(seen))
    print("rows", len(rows))
    print("inserted_into", "flow_policy.portset,flow_policy.vm_nic,flow_policy.category")


if __name__ == "__main__":
    main()
