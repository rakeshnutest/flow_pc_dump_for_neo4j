#!/usr/bin/env python3
"""Ingest dump JSON into the flat flow_policy.portset table.

Self-contained: stdlib + clickhouse-client. No nutest, no neo4j, no pip.
Hash is in this file (uuid5 for APPLICATION, MD5 salus+scope for FLEX).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import uuid as uuid_lib
from collections import defaultdict

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
BATCH = 10_000
U_SG_NS = uuid_lib.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
ZERO = "00000000-0000-0000-0000-000000000000"
ALL_VLAN_VPC = "00000000-0000-0000-0000-000000000001"
DEFAULT_PROJECT_EXT_ID = ZERO
ISOLATION_RULE_TYPES = frozenset(("TWO_ENV_ISOLATION", "MULTI_ENV_ISOLATION"))
ALLOW_ANY_SPECS = frozenset(("ALL", "NONE"))
GLOBAL_SCOPE_UNIQUE_ID = "global-scope-unique-id"
VLAN_SCOPE_UNIQUE_ID = "vlan-scope-unique-id"
SALUS_SERVICE_NAME = "salus"
ATLAS_ALLOW_ANY = "all"
CATEGORY_SELECTION_TYPE_MAP = {"VM": "kVM", "SUBNET": "kSubnet", "VPC": "kVPC"}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
CAT_TYPE_MAP = {"VM": "kVM", "VPC": "kVPC", "SUBNET": "kSubnet"}
_U_QUOTE = re.compile(r"'[a-z0-9A-Z\-]+'")

POLICY_TABLES = ("bundle", "portset", "u_sg", "vm_nic", "category")
RESET_SCHEMA_SQL = """
CREATE DATABASE IF NOT EXISTS flow_policy;
DROP VIEW IF EXISTS flow_policy.v_port_set_nic_diff;
DROP TABLE IF EXISTS flow_policy.atlas_port_set;
DROP TABLE IF EXISTS flow_policy.computed_port_set;
DROP TABLE IF EXISTS flow_policy.bundle;
DROP TABLE IF EXISTS flow_policy.portset;
DROP TABLE IF EXISTS flow_policy.u_sg;
DROP TABLE IF EXISTS flow_policy.sg;
DROP TABLE IF EXISTS flow_policy.vm_nic;
DROP TABLE IF EXISTS flow_policy.category;
"""
LOG_BUNDLE_ID = 0


def load_schema_sql(path=""):
    here = os.path.dirname(os.path.abspath(__file__))
    schema_path = path or os.path.join(here, "schema.sql")
    with open(schema_path) as handle:
        return handle.read()


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


def atlas_port_set_id(entity_type, refs, unique_uuid, project_uuid=None,
                      is_flex=False):
    """APPLICATION: uuid5(scope uuid, sorted refs). FLEX: MD5(salus+scope+refs)."""
    refs = list(refs or [])
    if not unique_uuid:
        return ""
    if is_flex:
        body = "[" + " ".join(sorted(refs)) + "]"
        body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
        if entity_type and entity_type not in ("VM", "EG"):
            suffix = CATEGORY_SELECTION_TYPE_MAP.get(entity_type)
            if suffix:
                body = body + ":" + str(suffix)
        if project_uuid and project_uuid != DEFAULT_PROJECT_EXT_ID:
            body = body + ":project:" + project_uuid
        digest = hashlib.md5(
            (SALUS_SERVICE_NAME + unique_uuid + body).encode()).digest()
        return str(uuid_lib.UUID(bytes=digest))
    body = str(sorted(list(refs)))
    body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
    if entity_type and entity_type not in ("VM", "EG"):
        body = body + ":" + str(CATEGORY_SELECTION_TYPE_MAP.get(entity_type))
    if project_uuid and project_uuid != DEFAULT_PROJECT_EXT_ID:
        body = body + ":project:" + project_uuid
    return str(uuid_lib.uuid5(uuid_lib.UUID(str(unique_uuid)), body))


def apply_ip_version_combo(
        has_ipv4, has_ipv6, ipv4_only=None, ipv6_only=None,
        is_ipv6_traffic_allowed=False):
    if ipv4_only is None and ipv6_only is None:
        return bool(has_ipv4), bool(has_ipv6)
    ipv4_only = bool(ipv4_only)
    ipv6_only = bool(ipv6_only)
    if is_ipv6_traffic_allowed:
        ipv6_only = False
    if ipv4_only and ipv6_only:
        return bool(has_ipv4), bool(has_ipv6)
    if ipv4_only and not ipv6_only:
        return bool(has_ipv4), False
    if not ipv4_only and ipv6_only:
        return False, bool(has_ipv6)
    return False, bool(has_ipv6) and bool(is_ipv6_traffic_allowed)


def dump_allow_any(sel):
    return bool(
        sel.get("should_allow_any_src")
        or sel.get("should_allow_any_dst")
        or sel.get("src_allow_spec") in ALLOW_ANY_SPECS
        or sel.get("dest_allow_spec") in ALLOW_ANY_SPECS)


def scope_unique_uuid(scope, is_flex, vlan_uuid, global_uuid, policy_vpc_uuids):
    policy_vpc_uuids = policy_vpc_uuids or []
    if scope in ("GLOBAL", "kGlobal", "ALL_VPC"):
        return GLOBAL_SCOPE_UNIQUE_ID if is_flex else global_uuid
    if scope in ("ALL_VLAN", "kAllVlan"):
        return VLAN_SCOPE_UNIQUE_ID if is_flex else vlan_uuid
    if scope in ("VPC_AS_CATEGORY", "VPC_LIST") and policy_vpc_uuids:
        return policy_vpc_uuids[0]
    return ""


def port_set_uuid(
        sel, *, scope, project_uuid, vlan_uuid, global_uuid,
        policy_vpc_uuids=None, is_flex=False, as_address_set=False,
        skip_cidrs=False, ipv4_only=None, ipv6_only=None,
        is_ipv6_traffic_allowed=False):
    """Dump selector -> (entity_type, refs, uuid). Empty if not a port-set."""
    del ipv4_only, ipv6_only, is_ipv6_traffic_allowed
    sel = sel or {}
    eg = str(sel.get("entity_group_uuid") or "").strip()
    cidrs = [] if skip_cidrs else list(sel.get("subnet_list") or [])
    addresses = [] if skip_cidrs else list(sel.get("addresses") or [])
    allow_any = dump_allow_any(sel)
    entity_type = None
    refs = None
    if eg and cidrs and as_address_set:
        return "", [], ""
    if eg:
        entity_type = "EG"
        refs = [eg]
    elif allow_any:
        entity_type = "VM"
        refs = [ATLAS_ALLOW_ANY]
    elif uuid_list(sel.get("vm_category_refs")):
        entity_type = "VM"
        refs = uuid_list(sel.get("vm_category_refs"))
    elif uuid_list(sel.get("vm_ext_ids")):
        entity_type = "VM"
        refs = uuid_list(sel.get("vm_ext_ids"))
    elif uuid_list(sel.get("subnet_category_refs")):
        entity_type = "SUBNET"
        refs = uuid_list(sel.get("subnet_category_refs"))
    elif uuid_list(sel.get("subnet_ext_ids")):
        entity_type = "SUBNET"
        refs = uuid_list(sel.get("subnet_ext_ids"))
    elif uuid_list(sel.get("vpc_category_refs")):
        entity_type = "VPC"
        refs = uuid_list(sel.get("vpc_category_refs"))
    elif addresses:
        return "", [], ""
    unique = scope_unique_uuid(
        scope, is_flex, vlan_uuid, global_uuid, policy_vpc_uuids)
    if not entity_type or not refs or not unique:
        return "", [], ""
    hashed = atlas_port_set_id(
        entity_type, refs, unique, project_uuid, is_flex=is_flex)
    if not hashed:
        return "", [], ""
    return entity_type, ([] if allow_any else refs), hashed


def compute_addressset_hashes(entity_uuid, has_ipv4, has_ipv6):
    vid = uuid_lib.UUID(entity_uuid)
    hashes = []
    if has_ipv4 and has_ipv6:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv4")))
        hashes.append(str(uuid_lib.uuid5(vid, "IPv6")))
    elif has_ipv6:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv6")))
    else:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv4")))
    return hashes


generate_port_set_id = atlas_port_set_id


def namespace_for_policy(policy, vlan_uuid, global_uuid):
    """Return (hash_namespace, scope). Hash namespace is UUID-only.

    ALL_VLAN / GLOBAL use dump vlan_unique_uuid / global_unique_uuid.
    VPC_LIST uses the first vpc_references UUID. VPC_AS_CATEGORY uses
    the first scope_references UUID.
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
    return entity_project_uuid(policy)


def entity_project_uuid(entity):
    if not isinstance(entity, dict):
        return ""
    project = as_uuid(
        entity.get("project_ext_id")
        or entity.get("projectExtId")
        or (entity.get("project") or {}).get("ext_id"))
    if not project or project == ZERO:
        return ""
    return project


def as_bool(value, default=None):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return default


def nic_advanced_networking(nic):
    """Dump subnet flags. Prefer advance_vlan, else is_advanced_networking."""
    if nic.get("advance_vlan") is not None:
        return as_bool(nic.get("advance_vlan"), None)
    if nic.get("is_advanced_networking") is not None:
        return as_bool(nic.get("is_advanced_networking"), None)
    if nic.get("advanced_networking") is not None:
        return as_bool(nic.get("advanced_networking"), None)
    return None


def is_basic_vlan_nic(nic):
    """VLAN Basic: dump advance_vlan false or is_advanced_networking false.

    Overlay is never Basic VLAN. Advanced VLAN (flag true) can still use
    the ALL_VLAN placeholder VPC.
    """
    if str(nic.get("subnet_type") or "").upper() == "OVERLAY":
        return False
    return nic_advanced_networking(nic) is False


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
        "--date_time_input_format=best_effort",
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
    bid = int(LOG_BUNDLE_ID)
    batch = 50 if table.endswith("portset") else BATCH
    for offset in range(0, len(rows), batch):
        chunk = rows[offset:offset + batch]
        for row in chunk:
            row["log_bundle_id"] = bid
        payload = "\n".join(json.dumps(row) for row in chunk)
        ch_client(
            "--query",
            "INSERT INTO %s FORMAT JSONEachRow" % table,
            input_text=payload)


def resolve_log_bundle_id(explicit, dump_dir=""):
    """Panacea log_bundle_id. Flag, env, meta.json, else stable hash of dump_dir."""
    if explicit and int(explicit) > 0:
        return int(explicit)
    env = os.environ.get("PANACEA_LOG_BUNDLE_ID") or os.environ.get("LOG_BUNDLE_ID")
    if env:
        return int(env)
    meta_path = os.path.join(dump_dir, "meta.json") if dump_dir else ""
    if meta_path and os.path.isfile(meta_path):
        meta = load_json(meta_path, {})
        for key in ("log_bundle_id", "id", "bundle_id"):
            val = meta.get(key)
            if val not in (None, "", 0, "0"):
                return int(val)
    if dump_dir:
        digest = hashlib.sha256(os.path.abspath(dump_dir).encode()).digest()
        return int.from_bytes(digest[:8], "big")
    raise SystemExit("need --log_bundle_id")


def has_bundle_column(table):
    out = ch_client(
        "--query",
        "SELECT count() FROM system.columns "
        "WHERE database = 'flow_policy' AND table = '%s' "
        "AND name = 'log_bundle_id'" % table)
    try:
        return int((out or "0").strip().splitlines()[-1]) > 0
    except ValueError:
        return False


def drop_bundle_partitions(bundle_id):
    """DROP PARTITION is instant (insert-mutation-avoid-delete). Other bundles stay."""
    bid = int(bundle_id)
    for table in POLICY_TABLES:
        q = "ALTER TABLE flow_policy.%s DROP PARTITION %s" % (table, bid)
        try:
            ch_client("--query", q)
        except RuntimeError as exc:
            text = str(exc)
            if any(
                s in text
                for s in (
                    "doesn't exist",
                    "does not exist",
                    "Unknown table",
                    "No such partition",
                )
            ):
                continue
            raise
        print("  dropped partition %s %s" % (bid, table))


def jsonl_table_dir(path):
    if os.path.isfile(os.path.join(path, "portset.jsonl")):
        return path
    nested = os.path.join(path, "flow_policy")
    if os.path.isfile(os.path.join(nested, "portset.jsonl")):
        return nested
    raise SystemExit("no portset.jsonl under %s" % path)


def load_jsonl(path):
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path) as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def ingest_from_jsonl(path):
    d = jsonl_table_dir(path)
    insert_json("flow_policy.bundle", [{
        "dump_dir": os.path.abspath(d),
    }])
    for table in ("category", "vm_nic", "u_sg", "portset"):
        rows = load_jsonl(os.path.join(d, table + ".jsonl"))
        insert_json("flow_policy." + table, rows)
        print("jsonl_%s" % table, len(rows))
    print("inserted_into",
          "flow_policy.bundle,flow_policy.portset,flow_policy.u_sg,"
          "flow_policy.vm_nic,flow_policy.category",
          "log_bundle_id=%s" % LOG_BUNDLE_ID)


def ips_in_range(start_ip, end_ip, cap=8192):
    """Expand IPv4 ranges to CIDRs, with a safety cap."""
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


def name_matches(name, pattern, criteria=""):
    """EG REGEX: CONTAINS / STARTS_WITH / ENDS_WITH / EQUALS.

    If match_criteria is empty and the pattern has regex metacharacters,
    treat it as a full-string regex.
    """
    name = str(name or "")
    pattern = str(pattern or "")
    if not pattern:
        return False
    crit = str(criteria or "").upper().replace(" ", "_")
    if crit == "CONTAINS":
        return pattern in name
    if crit in ("STARTS_WITH", "STARTSWITH"):
        return name.startswith(pattern)
    if crit in ("ENDS_WITH", "ENDSWITH"):
        return name.endswith(pattern)
    if crit == "EQUALS":
        return name == pattern
    if re.search(r"[.*+?^${}()|[\]\\]", pattern):
        try:
            return re.fullmatch(pattern, name) is not None
        except re.error:
            return False
    return name == pattern


def _entity_names(entity):
    out = []
    for key in ("reference_names", "names", "name_list"):
        value = entity.get(key)
        if isinstance(value, list):
            out.extend(str(item).strip() for item in value if str(item).strip())
        elif value:
            out.append(str(value).strip())
    for item in entity.get("reference_ext_ids") or []:
        if not as_uuid(item) and str(item).strip():
            out.append(str(item).strip())
    return out


def resolve_ext_ids(entity, inventory):
    """UUID refs plus NAME/REGEX resolution against dump VM/subnet inventory.

    EXT_ID/NAME append reference_ext_ids; REGEX matches vm.name with
    match_criteria and appends vm.ext_id. Identity is UUID after resolve.
    """
    select_by = str(entity.get("select_by") or "").upper()
    refs = uuid_list(entity.get("reference_ext_ids"))
    pattern = str(entity.get("reference_string") or "")
    criteria = str(entity.get("match_criteria") or "")
    is_regex = select_by == "REGEX" or bool(pattern)
    if is_regex and pattern:
        for row in inventory or []:
            if name_matches(row.get("name"), pattern, criteria or "EQUALS"):
                uid = as_uuid(row.get("ext_id"))
                if uid:
                    refs.append(uid)
        return uuid_list(refs)
    names = _entity_names(entity)
    if select_by == "NAME" or names:
        want = set(names)
        for row in inventory or []:
            if str(row.get("name") or "") in want:
                uid = as_uuid(row.get("ext_id"))
                if uid:
                    refs.append(uid)
    return uuid_list(refs)


def vm_subnet_inventory(vms, subnets=None):
    """ext_id + name for REGEX/NAME resolve. UUIDs only after match."""
    vm_rows = []
    seen_vm = set()
    for vm in vms or []:
        data = unwrap(vm) if isinstance(vm, dict) else vm
        if not isinstance(data, dict):
            continue
        uid = as_uuid(data.get("ext_id") or data.get("uuid"))
        name = str(data.get("name") or "")
        if uid and uid not in seen_vm:
            seen_vm.add(uid)
            vm_rows.append({"ext_id": uid, "name": name})
    sub_rows = []
    seen_sub = set()
    for row in subnets or []:
        data = unwrap(row) if isinstance(row, dict) else row
        if not isinstance(data, dict):
            continue
        uid = as_uuid(data.get("ext_id") or data.get("uuid"))
        name = str(data.get("name") or "")
        if uid and uid not in seen_sub:
            seen_sub.add(uid)
            sub_rows.append({"ext_id": uid, "name": name})
    for vm in vms or []:
        data = unwrap(vm) if isinstance(vm, dict) else vm
        if not isinstance(data, dict):
            continue
        for nic in data.get("nics") or []:
            subnet = (nic.get("nic_network_info") or {}).get("subnet") or {}
            uid = as_uuid(subnet.get("ext_id"))
            if uid and uid not in seen_sub:
                seen_sub.add(uid)
                sub_rows.append({
                    "ext_id": uid,
                    "name": str(subnet.get("name") or ""),
                })
    return vm_rows, sub_rows


def expand_entity_group(eg, ag_map=None, fqdn_map=None, vms=None, subnets=None):
    ag_map = ag_map or {}
    fqdn_map = fqdn_map or {}
    vm_inv, sub_inv = vm_subnet_inventory(vms, subnets)
    sel = {
        "name": str(eg.get("name") or ""),
        "vm_category_refs": [],
        "subnet_category_refs": [],
        "vpc_category_refs": [],
        "vm_category_names": [],
        "subnet_category_names": [],
        "vpc_category_names": [],
        "vm_ext_ids": [],
        "subnet_ext_ids": [],
        "subnet_list": [],
        "exception_list": [],
        "eg_address_grp": [],
        "eg_exception_address_grp": [],
        "entity_group_uuid": as_uuid(eg.get("ext_id")),
        "is_kube": False,
        "has_direct_vm": False,
        "has_direct_subnet": False,
    }
    allowed = ((eg.get("allowed_config") or {}).get("entities")) or []
    kinds = [str(entity.get("type") or "").upper() for entity in allowed]
    sel["is_kube"] = any(k.startswith("KUBE") for k in kinds) and not any(
        k in ("VM", "SUBNET", "VPC") for k in kinds)
    for entity in allowed:
        kind = str(entity.get("type") or "").upper()
        select_by = str(entity.get("select_by") or "").upper()
        refs = uuid_list(entity.get("reference_ext_ids"))
        if kind == "VM" and select_by == "CATEGORY_EXT_ID":
            sel["vm_category_refs"].extend(refs)
        elif kind == "VM":
            # EXT_ID / NAME / REGEX -> vm_ext_ids
            sel["vm_ext_ids"].extend(resolve_ext_ids(entity, vm_inv))
            sel["has_direct_vm"] = True
        elif kind == "SUBNET" and select_by == "CATEGORY_EXT_ID":
            sel["subnet_category_refs"].extend(refs)
        elif kind == "SUBNET":
            sel["subnet_ext_ids"].extend(resolve_ext_ids(entity, sub_inv))
            sel["has_direct_subnet"] = True
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
                rec = ag_map.get(ag_ref) or {}
                sel["subnet_list"].extend(rec.get("subnet_list") or [])
                ag_name = rec.get("name") or ""
                if ag_name:
                    sel["eg_address_grp"].append(ag_name)
            # Dump FQDN resolved IPs append to EG subnet_list.
            for fqdn in entity.get("fqdns") or []:
                sel["subnet_list"].extend(fqdn_map.get(fqdn) or [])
            sel["subnet_list"].extend(entity.get("resolved_ips") or [])
    excepted = ((eg.get("except_config") or {}).get("entities")) or []
    for entity in excepted:
        kind = str(entity.get("type") or "").upper()
        if kind != "ADDRESS_GROUP":
            continue
        addrs = entity.get("addresses") or {}
        sel["exception_list"].extend(cidrs_from_addresses(addrs.get("ipv4_addresses")))
        sel["exception_list"].extend(cidrs_from_addresses(addrs.get("ipv6_addresses")))
        for ag_ref in uuid_list(entity.get("reference_ext_ids")):
            rec = ag_map.get(ag_ref) or {}
            sel["exception_list"].extend(rec.get("subnet_list") or [])
            ag_name = rec.get("name") or ""
            if ag_name:
                sel["eg_exception_address_grp"].append(ag_name)
        for fqdn in entity.get("fqdns") or []:
            sel["exception_list"].extend(fqdn_map.get(fqdn) or [])
        sel["exception_list"].extend(entity.get("resolved_ips") or [])
    if eg.get("subnet_list"):
        sel["subnet_list"].extend(eg.get("subnet_list") or [])
    sel["subnet_list"] = list(dict.fromkeys(sel["subnet_list"]))
    sel["exception_list"] = list(dict.fromkeys(sel["exception_list"]))
    sel["eg_address_grp"] = list(dict.fromkeys(sel["eg_address_grp"]))
    sel["eg_exception_address_grp"] = list(
        dict.fromkeys(sel["eg_exception_address_grp"]))
    for key in (
            "vm_category_refs", "subnet_category_refs", "vpc_category_refs",
            "vm_ext_ids", "subnet_ext_ids"):
        sel[key] = uuid_list(sel[key])
    # VPC-only EG: names keep "any"; refs stay UUID-only.
    if (sel["vpc_category_refs"]
            and not sel["vm_category_refs"]
            and not sel["subnet_category_refs"]):
        sel["vm_category_names"] = ["any"]
        sel["subnet_category_names"] = ["any"]
    return sel


def expand_address_group(ag, fqdn_map=None):
    """CIDRs from dump address group ipv4/ipv6 fields and fqdn_to_ip_map."""
    fqdn_map = fqdn_map or {}
    out = []
    out.extend(cidrs_from_addresses(ag.get("ipv4_addresses")))
    out.extend(cidrs_from_addresses(ag.get("ipv6_addresses")))
    ranges = ag.get("ip_ranges") or []
    if isinstance(ranges, dict):
        out.extend(cidrs_from_ip_ranges(ranges.get("ipv4_ranges")))
    else:
        out.extend(cidrs_from_ip_ranges(ranges))
    for fqdn in ag.get("fqdns") or []:
        out.extend(fqdn_map.get(fqdn) or [])
    return list(dict.fromkeys(out))


def policy_hash_vpc_refs(policy, scope):
    """Dump vpc_references / scope_references used as VPC_LIST unique uuid."""
    if scope == "VPC_AS_CATEGORY":
        return uuid_list(policy.get("scope_references"))
    if scope == "VPC_LIST":
        return uuid_list(
            policy.get("vpc_references") or policy.get("scope_references"))
    return []


def is_allow_all_selector(sel):
    """Dump should_allow_any_src/dst or src_allow_spec/dest_allow_spec ALL|NONE.

    FLEX applied_to with applied_to_entity_group_references missing is
    UI Global (no Atlas port-set).
    """
    if dump_allow_any(sel):
        return True
    if ("applied_to_entity_group_references" in sel
            and sel.get("applied_to_entity_group_references") is None):
        return True
    return False


def rule_selects_all_ports(rule):
    """Dump is_all_protocol_allowed / isolation / src_allow_spec NONE."""
    spec = apply_rule_service_defaults(rule)
    rule_type = str(rule.get("type") or "")
    orig = rule.get("spec") or {}
    has_sg = bool(
        orig.get("service_group_references")
        or orig.get("secured_group_service_references"))
    if rule_type in ISOLATION_RULE_TYPES:
        return True
    if orig.get("src_allow_spec") == "NONE" or orig.get("dest_allow_spec") == "NONE":
        return True
    if spec.get("is_all_protocol_allowed") and not has_sg:
        return True
    return False


def hash_selector(
        sel, scope, project_uuid, vpc_refs, vlan_uuid, global_uuid,
        is_flex, is_endpoint, ipv4_only=None, ipv6_only=None,
        is_ipv6_traffic_allowed=False, role=""):
    """Dump selector -> Atlas port-set UUID via port_set_uuid.

    Skip FLEX Global applied_to (dump key applied_to_entity_group_references
    missing). AppliedTo hashes in global-scope-unique-id with no CIDRs.
    """
    # FnsPortSetValidator skips Atlas token "all". Do not emit a computed
    # port-set UUID Atlas will never list.
    if is_allow_all_selector(sel):
        return "", [], ""
    applied = role == "applied_to"
    return port_set_uuid(
        sel,
        scope="GLOBAL" if applied else scope,
        project_uuid=project_uuid or DEFAULT_PROJECT_EXT_ID,
        vlan_uuid=vlan_uuid,
        global_uuid=global_uuid,
        policy_vpc_uuids=[] if applied else vpc_refs,
        is_flex=is_flex,
        as_address_set=(is_flex or is_endpoint) and not applied,
        skip_cidrs=applied,
        ipv4_only=ipv4_only,
        ipv6_only=ipv6_only,
        is_ipv6_traffic_allowed=is_ipv6_traffic_allowed,
    )


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
            addr = ipaddress.ip_address(str(ip).split("/")[0])
        except ValueError:
            continue
        if any(addr in net for net in networks):
            return True
    return False


def is_ipv4_addr(ip):
    try:
        return isinstance(
            ipaddress.ip_address(str(ip).split("/")[0]), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_hostname(ip):
    text = str(ip or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text.split("/")[0])
        return False
    except ValueError:
        return True


def is_link_local(ip):
    """IPv4 169.254.0.0/16 and IPv6 fe80::/10."""
    try:
        addr = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return addr in ipaddress.ip_network("169.254.0.0/16")
    return addr.is_link_local


def ip_version_flags(policy, rule):
    """Dump is_ipv4_address_scope / is_ipv6_address_scope; link_local default True."""
    ipv4_only = bool(policy.get("is_ipv4_address_scope"))
    ipv6_only = bool(policy.get("is_ipv6_address_scope"))
    allowed = bool(policy.get("is_ipv6_traffic_allowed"))
    version = str((rule.get("spec") or {}).get("ip_version") or "").upper()
    if version == "IPV4":
        ipv4_only, ipv6_only = True, False
    elif version == "IPV6":
        ipv4_only, ipv6_only = False, True
    elif version in ("IPV4_IPV6", "IPV4IPV6"):
        ipv4_only, ipv6_only = True, True
    if allowed:
        ipv6_only = False
    link_local = policy.get("link_local")
    if link_local is None:
        link_local = (rule.get("spec") or {}).get("link_local")
    if link_local is None:
        link_local = True
    return ipv4_only, ipv6_only, allowed, bool(link_local)


def filter_ips_by_protocol(
        ips, ipv4_only, ipv6_only, is_ipv6_traffic_allowed, link_local=True):
    """Keep IPs for dump ipv4_only / ipv6_only / is_ipv6_traffic_allowed."""
    out = []
    for ip in ips or []:
        if ip is None or is_hostname(ip):
            continue
        ipv4 = is_ipv4_addr(ip)
        if not link_local and is_link_local(ip):
            continue
        if ipv4_only and ipv6_only:
            out.append(ip)
        elif ipv4_only and not ipv6_only and ipv4:
            out.append(ip)
        elif not ipv4_only and ipv6_only and not ipv4:
            out.append(ip)
        elif (not ipv4_only and not ipv6_only and not ipv4
              and is_ipv6_traffic_allowed):
            out.append(ip)
    return out


def filter_cidrs_by_protocol(
        cidrs, ipv4_only, ipv6_only, is_ipv6_traffic_allowed):
    v4 = [cidr for cidr in cidrs or [] if ":" not in str(cidr)]
    v6 = [cidr for cidr in cidrs or [] if ":" in str(cidr)]
    keep_v4, keep_v6 = apply_ip_version_combo(
        bool(v4), bool(v6), ipv4_only, ipv6_only, is_ipv6_traffic_allowed)
    out = []
    if keep_v4:
        out.extend(v4)
    if keep_v6:
        out.extend(v6)
    return out


def nic_index(nics):
    by_vm_cat = defaultdict(set)
    by_sub_cat = defaultdict(set)
    by_vpc_cat = defaultdict(set)
    by_vm = defaultdict(set)
    by_subnet = defaultdict(set)
    by_vpc = defaultdict(set)
    by_project = defaultdict(set)
    all_nics = {}
    for nic in nics:
        uid = nic["nic_uuid"]
        all_nics[uid] = nic
        by_vm[nic["vm_uuid"]].add(uid)
        by_subnet[nic["subnet_uuid"]].add(uid)
        if nic["vpc_uuid"]:
            by_vpc[nic["vpc_uuid"]].add(uid)
        if nic.get("project_uuid"):
            by_project[nic["project_uuid"]].add(uid)
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
        "by_project": by_project,
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


def scope_nics(matched, index, namespace, vlan_uuid, global_uuid, scope,
               role=""):
    if not matched:
        return matched
    # AppliedTo membership is global (any VPC/VLAN). Policy scope only
    # clips src/dest port-sets.
    if role == "applied_to":
        return matched
    if role == "secured":
        return set(
            uid for uid in matched
            if not is_basic_vlan_nic(index["all_nics"].get(uid) or {}))
    if scope in ("ALL_VLAN", "kAllVlan") or namespace == vlan_uuid:
        return matched & index["by_vpc"].get(ALL_VLAN_VPC, set())
    if scope in ("GLOBAL", "kGlobal", "ALL_VPC", "VPC_AS_CATEGORY"):
        return matched
    if namespace == global_uuid:
        return matched
    return matched & index["by_vpc"].get(namespace, set())


def match_nics(
        sel, index, namespace, vlan_uuid, global_uuid, scope,
        ipv4_only=False, ipv6_only=False, is_ipv6_traffic_allowed=False,
        link_local=True, role="", project_uuid=""):
    vm_refs = [u for u in (sel.get("vm_category_refs") or []) if u not in ("all", "any")]
    sub_refs = [u for u in (sel.get("subnet_category_refs") or []) if u not in ("all", "any")]
    vpc_refs = uuid_list(sel.get("vpc_category_refs"))
    vm_ext = uuid_list(sel.get("vm_ext_ids"))
    sub_ext = uuid_list(sel.get("subnet_ext_ids"))
    cidrs = filter_cidrs_by_protocol(
        sel.get("subnet_list") or [], ipv4_only, ipv6_only,
        is_ipv6_traffic_allowed)
    exceptions = filter_cidrs_by_protocol(
        sel.get("exception_list") or [], ipv4_only, ipv6_only,
        is_ipv6_traffic_allowed)

    if is_allow_all_selector(sel):
        if role not in ("src", "dest"):
            return set()
        if project_uuid and project_uuid != ZERO:
            return set(index["by_project"].get(project_uuid, set()))
        return set(index["all_nics"])

    if vm_ext or sub_ext:
        out = set()
        for vm_uuid in vm_ext:
            out |= index["by_vm"].get(vm_uuid, set())
        for subnet_uuid in sub_ext:
            out |= index["by_subnet"].get(subnet_uuid, set())
        return scope_nics(
            out, index, namespace, vlan_uuid, global_uuid, scope, role=role)

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
            filtered = filter_ips_by_protocol(
                nic["ips"], ipv4_only, ipv6_only, is_ipv6_traffic_allowed,
                link_local)
            in_sel = [ip for ip in filtered if ip_in_cidrs([ip], cidrs)]
            in_exc = [ip for ip in in_sel if ip_in_cidrs([ip], exceptions)]
            if set(in_sel) - set(in_exc):
                matched.add(nic_uuid)
    else:
        return set()
    return scope_nics(
        matched, index, namespace, vlan_uuid, global_uuid, scope, role=role)


def ip_values(items):
    if items is None:
        return []
    if isinstance(items, dict):
        items = [items]
    out = []
    for item in items or []:
        if isinstance(item, dict):
            val = item.get("value")
            if val:
                out.append(str(val))
        elif item:
            out.append(str(item))
    return out


def learned_ips(nic):
    """IPv4 + every IPv6 (link-local and global) from learned and config."""
    network = nic.get("nic_network_info") or {}
    out = []
    ipv4_info = network.get("ipv4_info") or {}
    ipv4_config = network.get("ipv4_config") or {}
    ipv6_info = network.get("ipv6_info") or {}
    ipv6_config = network.get("ipv6_config") or {}
    out.extend(ip_values(ipv4_info.get("learned_ip_addresses")))
    out.extend(ip_values(ipv4_config.get("ip_address")))
    out.extend(ip_values(ipv4_config.get("secondary_ip_address_list")))
    out.extend(ip_values(ipv6_info.get("learned_ipv6_addresses")))
    out.extend(ip_values(ipv6_config.get("ip_address")))
    out.extend(ip_values(ipv6_config.get("secondary_ipv6_address_list")))
    seen = set()
    uniq = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def _entity_cat_ids(*objs):
    out = []
    seen = set()
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        raw = (
            obj.get("category_ids")
            or obj.get("vm_category_ids")
            or (obj.get("metadata") or {}).get("category_ids")
            or [])
        for uid in uuid_list(raw):
            if uid not in seen:
                seen.add(uid)
                out.append(uid)
    return out


def atlas_vpc_names(port_set_get):
    """Atlas virtual_network_name -> VPC UUID from port_set.get."""
    if isinstance(port_set_get, dict):
        records = list(port_set_get.values())
    else:
        records = port_set_get or []
    out = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("virtual_network_name") or "").strip()
        uid = as_uuid(rec.get("virtual_network_uuid"))
        if name and uid:
            out[name] = uid
    return out


def vpc_uuid_for_subnet(subnet, vpc_names):
    """VLAN / VLAN Basic -> ALL_VLAN. Overlay: dump vpc_reference or Atlas name."""
    subnet = subnet or {}
    if nic_advanced_networking(subnet) is False:
        return ALL_VLAN_VPC
    ref = as_uuid(subnet.get("vpc_reference") or (subnet.get("vpc") or {}).get("ext_id"))
    if ref and ref != ZERO:
        return ref
    subnet_type = str(subnet.get("subnet_type") or "").upper()
    if subnet_type == "VLAN":
        return ALL_VLAN_VPC
    text = str(subnet.get("name") or "")
    best_name = ""
    best_uid = ""
    for name, uid in (vpc_names or {}).items():
        if not name or not text.startswith(name):
            continue
        rest = text[len(name):]
        if rest[:1].isdigit():
            continue
        if len(name) > len(best_name):
            best_name = name
            best_uid = uid
    return best_uid


def parse_dump_uuid(value):
    """Dump host/cluster UUID. Host cluster may be '<uuid>::<id>'."""
    if isinstance(value, dict):
        value = value.get("ext_id") or value.get("uuid") or value.get("id")
    text = str(value or "").strip()
    if "::" in text:
        text = text.split("::", 1)[0]
    return as_uuid(text)


def host_cluster_map(hosts, clusters):
    """host_uuid -> host name + cluster uuid/name from dump hosts.json / clusters.json."""
    cluster_names = {}
    for row in clusters or []:
        rec = unwrap(row)
        uid = parse_dump_uuid(rec.get("ext_id") or rec.get("uuid"))
        if uid:
            cluster_names[uid] = str(rec.get("name") or "")
    out = {}
    for row in hosts or []:
        rec = unwrap(row)
        uid = parse_dump_uuid(rec.get("ext_id"))
        if not uid:
            continue
        cluster = rec.get("cluster")
        cluster_uuid = parse_dump_uuid(cluster)
        out[uid] = {
            "host_uuid": uid,
            "host": str(rec.get("host_name") or rec.get("name") or ""),
            "cluster_uuid": cluster_uuid or ZERO,
            "cluster": cluster_names.get(cluster_uuid, ""),
        }
    return out


def collect_nics(vms, subnets=None, vpc_names=None, host_map=None, vpc_map=None):
    nics = []
    host_map = host_map or {}
    sub_by = {}
    for row in subnets or []:
        uid = as_uuid(row.get("ext_id"))
        if uid:
            sub_by[uid] = row
    vpc_names = vpc_names or {}
    # Overlay VPC names live on Atlas virtual_network_*; dump vpcs.json
    # may omit those UUIDs. UUID identity is unchanged.
    vpc_uuid_to_name = dict(vpc_map or {})
    for name, uid in vpc_names.items():
        if uid and name:
            vpc_uuid_to_name[uid] = name
    for vm in vms or []:
        vm = unwrap(vm)
        name = str(vm.get("name") or "")
        if (name.startswith("VMx_") or name.startswith("VMx")
                or name.startswith("flow-") or name.startswith("auto_pc_")):
            continue
        vm_uuid = as_uuid(vm.get("ext_id"))
        vm_cat_ids = _entity_cat_ids(vm)
        vm_project = entity_project_uuid(vm)
        for nic in vm.get("nics") or []:
            nic_uuid = as_uuid(nic.get("ext_id"))
            if not nic_uuid:
                continue
            net = nic.get("nic_network_info") or {}
            subnet = dict(net.get("subnet") or {})
            subnet_uuid = as_uuid(subnet.get("ext_id"))
            dump_sub = sub_by.get(subnet_uuid) or {}
            if dump_sub:
                if dump_sub.get("name") and not subnet.get("name"):
                    subnet["name"] = dump_sub.get("name")
                if dump_sub.get("subnet_type") and not subnet.get("subnet_type"):
                    subnet["subnet_type"] = dump_sub.get("subnet_type")
                if dump_sub.get("vpc_reference") and not subnet.get("vpc_reference"):
                    subnet["vpc_reference"] = dump_sub.get("vpc_reference")
                if dump_sub.get("is_advanced_networking") is not None:
                    subnet.setdefault(
                        "is_advanced_networking",
                        dump_sub.get("is_advanced_networking"))
            vpc = dict(net.get("vpc") or {})
            dump_vpc = dump_sub.get("vpc") if isinstance(dump_sub.get("vpc"), dict) else {}
            if dump_vpc:
                if dump_vpc.get("ext_id") and not vpc.get("ext_id"):
                    vpc["ext_id"] = dump_vpc.get("ext_id")
                if dump_vpc.get("name") and not vpc.get("name"):
                    vpc["name"] = dump_vpc.get("name")
            vpc_uuid = (
                as_uuid(vpc.get("ext_id"))
                or vpc_uuid_for_subnet(subnet, vpc_names)
                or ZERO)
            vpc_name = str(vpc.get("name") or "")
            if not vpc_name and vpc_uuid and vpc_uuid not in (ZERO, ALL_VLAN_VPC):
                vpc_name = str(vpc_uuid_to_name.get(vpc_uuid) or "")
            nic_vm_cats = _entity_cat_ids(net, vm) or vm_cat_ids
            flags = {}
            flags.update(nic)
            flags.update(net)
            flags.update(subnet)
            advanced = nic_advanced_networking(flags)
            host_uuid = parse_dump_uuid(vm.get("host"))
            host_rec = host_map.get(host_uuid) or {}
            nics.append({
                "nic_uuid": nic_uuid,
                "vm_uuid": vm_uuid or ZERO,
                "vm_name": name,
                "subnet_uuid": subnet_uuid or ZERO,
                "subnet": str(subnet.get("name") or dump_sub.get("name") or ""),
                "subnet_type": str(
                    subnet.get("subnet_type") or dump_sub.get("subnet_type")
                    or net.get("subnet_type") or ""),
                "advance_vlan": advanced,
                "is_advanced_networking": advanced,
                "vpc_uuid": vpc_uuid,
                "vpc": vpc_name,
                "host_uuid": host_uuid or ZERO,
                "host": host_rec.get("host") or "",
                "cluster_uuid": host_rec.get("cluster_uuid") or ZERO,
                "cluster": host_rec.get("cluster") or "",
                "project_uuid": (
                    entity_project_uuid(nic)
                    or entity_project_uuid(net)
                    or vm_project),
                "vm_cat_ids": nic_vm_cats,
                "subnet_cat_ids": _entity_cat_ids(subnet, dump_sub),
                "vpc_cat_ids": _entity_cat_ids(vpc),
                "ips": learned_ips(nic),
                "ip": ",".join(learned_ips(nic)),
            })
    return nics


def expand_selector(sel, eg_map):
    if not sel:
        return sel
    eg_map = eg_map or {}
    if sel.get("entity_group_uuid") and sel["entity_group_uuid"] in eg_map:
        expanded = dict(eg_map[sel["entity_group_uuid"]])
        for key, value in sel.items():
            if key == "entity_group_uuid":
                continue
            if value:
                expanded[key] = value
        return expanded
    return sel


def empty_applied_to_columns():
    """FLEX applied_to_* defaults. Zero UUID / empty arrays when not FLEX."""
    return {
        "applied_to_port_set_uuid": ZERO,
        "applied_to_entity_group_uuid": ZERO,
        "applied_to_vm_category_refs": [],
        "applied_to_subnet_category_refs": [],
        "applied_to_vpc_category_refs": [],
        "applied_to_vm_ext_ids": [],
        "applied_to_subnet_ext_ids": [],
        "applied_to_subnet_list": [],
        "applied_to_exception_list": [],
        "applied_to_entity_group_name": "",
        "applied_to_vm_category_names": [],
        "applied_to_subnet_category_names": [],
        "applied_to_vpc_category_names": [],
    }


def applied_to_columns_from_row(row):
    """Second port-set UUID + expanded applied_to EG selector on src/dest."""
    cols = empty_applied_to_columns()
    cols["applied_to_port_set_uuid"] = row.get("port_set_uuid") or ZERO
    cols["applied_to_entity_group_uuid"] = (
        row.get("entity_group_uuid") or ZERO)
    cols["applied_to_vm_category_refs"] = list(
        row.get("vm_category_refs") or [])
    cols["applied_to_subnet_category_refs"] = list(
        row.get("subnet_category_refs") or [])
    cols["applied_to_vpc_category_refs"] = list(
        row.get("vpc_category_refs") or [])
    cols["applied_to_vm_ext_ids"] = list(row.get("vm_ext_ids") or [])
    cols["applied_to_subnet_ext_ids"] = list(row.get("subnet_ext_ids") or [])
    cols["applied_to_subnet_list"] = list(row.get("subnet_list") or [])
    cols["applied_to_exception_list"] = list(row.get("exception_list") or [])
    cols["applied_to_entity_group_name"] = row.get("entity_group_name") or ""
    cols["applied_to_vm_category_names"] = list(
        row.get("vm_category_names") or [])
    cols["applied_to_subnet_category_names"] = list(
        row.get("subnet_category_names") or [])
    cols["applied_to_vpc_category_names"] = list(
        row.get("vpc_category_names") or [])
    return cols


def attach_applied_to_on_peers(rows):
    """Copy applied_to EG onto FLEX src/dest (two port-set UUIDs)."""
    applied = None
    for row in rows:
        if row.get("role") == "applied_to":
            applied = row
            break
    if not applied:
        return
    payload = applied_to_columns_from_row(applied)
    for row in rows:
        row.update(payload)


def nic_match_key(comp, sel):
    return (
        comp["namespace_uuid"],
        comp.get("policy_scope") or "",
        comp.get("role") or "",
        comp.get("policy_project_uuid") or "",
        tuple(sel.get("vm_category_refs") or []),
        tuple(sel.get("subnet_category_refs") or []),
        tuple(sel.get("vpc_category_refs") or []),
        tuple(sel.get("vm_ext_ids") or []),
        tuple(sel.get("subnet_ext_ids") or []),
        tuple(sel.get("subnet_list") or []),
        tuple(sel.get("exception_list") or []),
        sel.get("should_allow_any_src"),
        sel.get("should_allow_any_dst"),
        sel.get("src_allow_spec"),
        sel.get("dest_allow_spec"),
        comp.get("ipv4_only"),
        comp.get("ipv6_only"),
        comp.get("is_ipv6_traffic_allowed"),
        comp.get("link_local"),
    )


def add_component(
        components, role, sel, policy, rule, namespace, scope, eg_map,
        project_uuid, vlan_uuid, global_uuid):
    sel = expand_selector(sel, eg_map)
    rule_type = str(rule.get("type") or "")
    is_flex = rule_type == "FLEX"
    # Isolation groups hash as Secured (not Endpoint address-set).
    isolation = (
        rule_type in ISOLATION_RULE_TYPES
        or str(role).startswith("isolation"))
    is_endpoint = (not isolation) and role not in ("secured", "applied_to")
    # FnsPortSetValidator step 2: skip inbound/outbound EG that is AG/NA
    # (entity_group_ref with no VM/subnet/VPC category refs). UUID and
    # REGEX members count even when name resolve found zero VMs this dump.
    if is_endpoint and sel.get("entity_group_uuid"):
        if not (
                uuid_list(sel.get("vm_category_refs"))
                or uuid_list(sel.get("subnet_category_refs"))
                or uuid_list(sel.get("vpc_category_refs"))
                or uuid_list(sel.get("vm_ext_ids"))
                or uuid_list(sel.get("subnet_ext_ids"))
                or sel.get("has_direct_vm")
                or sel.get("has_direct_subnet")):
            return "ag_na"
    # Kube EGs are not Atlas port-sets (neo4j kube_cluster path).
    if sel.get("is_kube"):
        return "kube"
    if is_allow_all_selector(sel):
        return "allow_all"
    ipv4_only, ipv6_only, allowed, link_local = ip_version_flags(policy, rule)
    entity_type, refs, port_set = hash_selector(
        sel, scope, project_uuid, policy_hash_vpc_refs(policy, scope),
        vlan_uuid, global_uuid, is_flex, is_endpoint,
        ipv4_only, ipv6_only, allowed, role=role)
    if not port_set:
        return "no_hash"
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
        "namespace_uuid": global_uuid if role == "applied_to" else namespace,
        "policy_scope": "GLOBAL" if role == "applied_to" else scope,
        "policy_project_uuid": (
            project_uuid if project_uuid and project_uuid != ZERO else ""),
        "virtual_network_uuid": ZERO,
        "entity_group_uuid": sel.get("entity_group_uuid") or ZERO,
        "entity_group_name": str(sel.get("name") or ""),
        "reference_uuids": refs,
        "vm_category_refs": uuid_list(sel.get("vm_category_refs")),
        "subnet_category_refs": uuid_list(sel.get("subnet_category_refs")),
        "vpc_category_refs": uuid_list(sel.get("vpc_category_refs")),
        "vm_ext_ids": uuid_list(sel.get("vm_ext_ids")),
        "subnet_ext_ids": uuid_list(sel.get("subnet_ext_ids")),
        "subnet_list": list(sel.get("subnet_list") or []),
        "exception_list": list(sel.get("exception_list") or []),
        **empty_applied_to_columns(),
        "eg_address_grp": list(sel.get("eg_address_grp") or []),
        "eg_exception_address_grp": list(
            sel.get("eg_exception_address_grp") or []),
        **empty_rule_service_columns(),
        "vm_category_names": list(sel.get("vm_category_names") or []),
        "subnet_category_names": list(sel.get("subnet_category_names") or []),
        "vpc_category_names": list(sel.get("vpc_category_names") or []),
        "effective_vpc_refs": [],
        "effective_vpc_names": [],
        "ipv4_only": ipv4_only,
        "ipv6_only": ipv6_only,
        "is_ipv6_traffic_allowed": allowed,
        "link_local": link_local,
        "all_ports": 1 if rule_selects_all_ports(rule) else 0,
        "should_allow_any": dump_allow_any(sel),
        "sel": sel,
    })
    return "ok"


def is_allow_any(spec, side, rule_type=""):
    """Dump should_allow_any_src/dst or src_allow_spec/dest_allow_spec ALL|NONE."""
    del rule_type
    if side == "src":
        return bool(
            spec.get("should_allow_any_src")
            or spec.get("src_allow_spec") in ALLOW_ANY_SPECS)
    return bool(
        spec.get("should_allow_any_dst")
        or spec.get("dest_allow_spec") in ALLOW_ANY_SPECS)


def apply_rule_service_defaults(rule):
    """Dump isolation / is_all_protocol_allowed / src_allow_spec NONE ports."""
    spec = dict(rule.get("spec") or {})
    rule_type = str(rule.get("type") or "")
    has_sg = bool(
        spec.get("service_group_references")
        or spec.get("secured_group_service_references"))
    has_ports = bool(
        spec.get("tcp_services") or spec.get("udp_services")
        or spec.get("icmp_services") or spec.get("icmp_v6_services"))
    if rule_type in ISOLATION_RULE_TYPES:
        spec["is_all_protocol_allowed"] = True
        spec["secured_group_action"] = spec.get("secured_group_action") or "DENY_ALL"
        spec["tcpPort"] = ["0-65535"]
        spec["udpPort"] = ["0-65535"]
        spec["icmpTypes"] = ["any:any"]
        spec["icmpv6Types"] = ["any:any"]
    elif spec.get("src_allow_spec") == "NONE" or spec.get("dest_allow_spec") == "NONE":
        spec["is_all_protocol_allowed"] = True
        spec["secured_group_action"] = "DENY"
        spec["tcpPort"] = ["0-65535"]
        spec["udpPort"] = ["0-65535"]
        spec["icmpTypes"] = ["any:any"]
        spec["icmpv6Types"] = ["any:any"]
    elif spec.get("is_all_protocol_allowed") and not has_sg:
        spec.setdefault("tcpPort", ["0-65535"])
        spec.setdefault("udpPort", ["0-65535"])
        spec.setdefault("icmpTypes", ["any:any"])
        spec.setdefault("icmpv6Types", ["any:any"])
        spec.setdefault("secured_group_action", "allow")
    elif spec.get("secured_group_action") and not has_sg and not has_ports:
        spec["is_all_protocol_allowed"] = True
        spec["tcpPort"] = ["0-65535"]
        spec["udpPort"] = ["0-65535"]
        spec["icmpTypes"] = ["any:any"]
        spec["icmpv6Types"] = ["any:any"]
    return spec


def unique_strings(values):
    out = []
    seen = set()
    for value in values or []:
        text = str(value).strip() if value is not None else ""
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def port_range_strings(services, kind):
    """Dump tcp_services / icmp_services -> 'start-end' or 'type:code'."""
    out = []
    for ports in services or []:
        if isinstance(ports, str):
            if ports.strip():
                out.append(ports.strip())
            continue
        if not isinstance(ports, dict):
            continue
        if ports.get("is_all_allowed"):
            out.append("0-65535" if kind in ("tcp", "udp") else "any:any")
            continue
        if kind in ("tcp", "udp"):
            start = ports.get("start_port", 0)
            end = ports.get("end_port", start)
            out.append(str(start) if start == end else "%s-%s" % (start, end))
        else:
            out.append("%s:%s" % (ports.get("type", 0), ports.get("code", 0)))
    return unique_strings(out)


def nf_pair_rows(pairs):
    out = []
    for pair in pairs or []:
        if not isinstance(pair, dict):
            continue
        out.append({
            "vm_uuid": as_uuid(
                pair.get("vm_reference") or pair.get("vm_uuid")) or ZERO,
            "ingress_nic_uuid": as_uuid(
                pair.get("ingress_nic_reference")
                or pair.get("ingress_nic_uuid")) or ZERO,
            "egress_nic_uuid": as_uuid(
                pair.get("egress_nic_reference")
                or pair.get("egress_nic_uuid")) or ZERO,
            "high_availability_state": str(
                pair.get("high_availability_state") or ""),
            "data_plane_health_status": str(
                pair.get("data_plane_health_status") or ""),
        })
    return out


def rule_side_type(role):
    """How this port-set is used on the rule (not APPLICATION INBOUND/OUTBOUND)."""
    role = str(role or "")
    if role == "src":
        return "end_point_src"
    if role == "dest":
        return "end_point_dst"
    return "secured_entity"


def policy_type_value(policy, rule=None):
    """Dump policy.type → app / isolation / quarantine."""
    raw = str((policy or {}).get("type") or "").upper()
    if raw == "APPLICATION":
        return "app"
    if raw == "ISOLATION":
        return "isolation"
    if raw == "QUARANTINE":
        return "quarantine"
    if rule and str(rule.get("type") or "") in ISOLATION_RULE_TYPES:
        return "isolation"
    return raw.lower() or "app"


def policy_mode_value(policy):
    """Dump policy.state → enforce / monitor / save. APPLY is enforce."""
    raw = str((policy or {}).get("state") or "").upper()
    if raw in ("APPLY", "ENFORCE"):
        return "enforce"
    if raw == "MONITOR":
        return "monitor"
    if raw == "SAVE":
        return "save"
    return raw.lower()


def rule_priority_value(rule, spec=None):
    """FLEX dump spec.priority (rule_priority). APPLICATION has none → 0."""
    spec = spec if spec is not None else ((rule or {}).get("spec") or {})
    raw = spec.get("priority")
    if raw is None:
        raw = (rule or {}).get("priority")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def empty_rule_service_columns():
    return {"rule_u_sg": []}


def rule_u_sg_entry(rule_uuid, role, spec, u_sg_row, policy, rule):
    u_sg_row = u_sg_row or {}
    policy = policy or {}
    rule = rule or {}
    return {
        "rule_uuid": rule_uuid or ZERO,
        "sg_id": list(u_sg_row.get("sg_uuids") or []),
        "sg_ports": {
            "tcp": list(u_sg_row.get("tcp_ports") or []),
            "udp": list(u_sg_row.get("udp_ports") or []),
            "icmp": list(u_sg_row.get("icmp_types") or []),
            "icmpv6": list(u_sg_row.get("icmp_v6_types") or []),
        },
        "policy_name": str(policy.get("name") or ""),
        "policy_uuid": as_uuid(policy.get("ext_id")) or ZERO,
        "policy_type": policy_type_value(policy, rule),
        "policy_mode": policy_mode_value(policy),
        "flex_policy": 1 if str(rule.get("type") or "") == "FLEX" else 0,
        "rule_priority": rule_priority_value(rule, spec),
        "type": rule_side_type(role),
    }


def load_service_group_map(rows):
    out = {}
    for row in rows or []:
        sg = unwrap(row)
        uid = as_uuid(sg.get("ext_id"))
        if not uid:
            continue
        out[uid] = {
            "name": str(sg.get("name") or ""),
            "tcp_ports": port_range_strings(
                sg.get("tcp_services") or sg.get("tcpPort"), "tcp"),
            "udp_ports": port_range_strings(
                sg.get("udp_services") or sg.get("udpPort"), "udp"),
            "icmp_types": port_range_strings(
                sg.get("icmp_services") or sg.get("icmpTypes"), "icmp"),
            "icmp_v6_types": port_range_strings(
                sg.get("icmp_v6_services") or sg.get("icmpv6Types"), "icmpv6"),
        }
    return out


def load_network_function_map(nf_rows, by_id):
    out = {}

    def add(nf):
        if not isinstance(nf, dict):
            return
        rec = unwrap(nf)
        uid = as_uuid(rec.get("ext_id"))
        if uid:
            out[uid] = rec

    for row in nf_rows or []:
        add(row)
    if isinstance(by_id, dict):
        for uid, wrapped in by_id.items():
            detailed = wrapped
            if isinstance(wrapped, dict) and isinstance(wrapped.get("data"), dict):
                detailed = wrapped["data"]
            if isinstance(detailed, dict) and not detailed.get("ext_id"):
                detailed = dict(detailed)
                detailed["ext_id"] = uid
            add(detailed)
    return out


def sg_row(kind, refs, names, tcp, udp, icmp, icmp6):
    """Dump SG UUID, list of dump SG UUIDs, or inline ports. No synthetic sg_id."""
    refs = list(refs or [])
    sg_id = refs[0] if kind == "sg" and refs else ZERO
    return {
        "sg_id": sg_id,
        "kind": kind,
        "sg_uuids": refs,
        "sg_names": list(names or []),
        "tcp_ports": list(tcp or []),
        "udp_ports": list(udp or []),
        "icmp_types": list(icmp or []),
        "icmp_v6_types": list(icmp6 or []),
        "is_inline": 1 if kind == "inline" else 0,
    }


def sg_row_key(row):
    return (
        row.get("kind") or "",
        row.get("sg_id") or ZERO,
        tuple(row.get("sg_uuids") or []),
        tuple(row.get("tcp_ports") or []),
        tuple(row.get("udp_ports") or []),
        tuple(row.get("icmp_types") or []),
        tuple(row.get("icmp_v6_types") or []),
    )


def unique_service(spec, sg_map, nf_map):
    """u_sg_id = sg identity + service function (dump network_function_reference).

    sg_id is the dump UUID when the rule names one SG. Lists and inline
    ports keep sg_id zero (no synthetic SG UUID).
    """
    spec = spec or {}
    sg_map = sg_map or {}
    nf_map = nf_map or {}
    refs = uuid_list(spec.get("service_group_references"))
    for uid in uuid_list(spec.get("secured_group_service_references")):
        if uid not in refs:
            refs.append(uid)
    names = []
    tcp = list(spec.get("tcpPort") or [])
    udp = list(spec.get("udpPort") or [])
    icmp = list(spec.get("icmpTypes") or [])
    icmp6 = list(spec.get("icmpv6Types") or [])
    details = spec.get("service_group_details") or []
    if details:
        tcp, udp, icmp, icmp6 = [], [], [], []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            uid = as_uuid(detail.get("ext_id"))
            if uid and uid not in refs:
                refs.append(uid)
            if uid or str(detail.get("name") or ""):
                names.append(str(detail.get("name") or ""))
            tcp.extend(detail.get("tcpPort") or port_range_strings(
                detail.get("tcp_services"), "tcp"))
            udp.extend(detail.get("udpPort") or port_range_strings(
                detail.get("udp_services"), "udp"))
            icmp.extend(detail.get("icmpTypes") or port_range_strings(
                detail.get("icmp_services"), "icmp"))
            icmp6.extend(detail.get("icmpv6Types") or port_range_strings(
                detail.get("icmp_v6_services"), "icmpv6"))
    elif refs:
        tcp, udp, icmp, icmp6 = [], [], [], []
        for uid in refs:
            rec = sg_map.get(uid) or {}
            names.append(str(rec.get("name") or ""))
            tcp.extend(rec.get("tcp_ports") or [])
            udp.extend(rec.get("udp_ports") or [])
            icmp.extend(rec.get("icmp_types") or [])
            icmp6.extend(rec.get("icmp_v6_types") or [])
    if spec.get("tcp_services"):
        tcp = port_range_strings(spec.get("tcp_services"), "tcp")
    if spec.get("udp_services"):
        udp = port_range_strings(spec.get("udp_services"), "udp")
    if spec.get("icmp_services"):
        icmp = port_range_strings(spec.get("icmp_services"), "icmp")
    if spec.get("icmp_v6_services"):
        icmp6 = port_range_strings(spec.get("icmp_v6_services"), "icmpv6")
    tcp = unique_strings(tcp)
    udp = unique_strings(udp)
    icmp = unique_strings(icmp)
    icmp6 = unique_strings(icmp6)
    if len(refs) > 1:
        kind = "sg_list"
    elif refs:
        kind = "sg"
    else:
        kind = "inline"
    action = spec.get("secured_group_action") or spec.get("action") or ""
    if isinstance(action, list):
        action = action[0] if action else ""
    action = str(action or "")
    nf_uid = as_uuid(spec.get("network_function_reference"))
    nf = {}
    details_nf = spec.get("network_function_details")
    if isinstance(details_nf, dict) and details_nf:
        nf = unwrap(details_nf)
        nf_uid = as_uuid(nf.get("ext_id")) or nf_uid
    elif nf_uid:
        nf = nf_map.get(nf_uid) or {}
    sg = sg_row(kind, refs, names, tcp, udp, icmp, icmp6)
    inline_ports = kind == "inline"
    body = "|".join((
        kind,
        ",".join(refs),
        ",".join(tcp if inline_ports else []),
        ",".join(udp if inline_ports else []),
        ",".join(icmp if inline_ports else []),
        ",".join(icmp6 if inline_ports else []),
        nf_uid or "",
        action,
    ))
    u_sg_id = str(uuid_lib.uuid5(U_SG_NS, "u_sg:" + body))
    all_ports = int(
        tcp == ["0-65535"] and udp == ["0-65535"]
        and icmp == ["any:any"] and icmp6 == ["any:any"])
    return u_sg_id, {
        "u_sg_id": u_sg_id,
        "sg_id": sg["sg_id"],
        "kind": kind,
        "sg_uuids": refs,
        "sg_names": names,
        "tcp_ports": tcp,
        "udp_ports": udp,
        "icmp_types": icmp,
        "icmp_v6_types": icmp6,
        "is_inline": sg["is_inline"],
        "is_all_ports": all_ports,
        "secured_group_action": action,
        "network_function_uuid": nf_uid or ZERO,
        "network_function_name": str(nf.get("name") or ""),
        "network_function_failure_handling": str(
            nf.get("failure_handling") or ""),
        "network_function_traffic_forwarding_mode": str(
            nf.get("traffic_forwarding_mode") or ""),
        "network_function_high_availability_mode": str(
            nf.get("high_availability_mode") or ""),
        "network_function_nic_pairs": nf_pair_rows(nf.get("nic_pairs")),
    }


def attach_portset_rules(components):
    """Same port-set UUID can belong to many rules; each rule has dump SGs/ports."""
    by_ps = defaultdict(list)
    for row in components:
        entry = row.get("_rule_u_sg")
        if not entry:
            continue
        by_ps[row["port_set_uuid"]].append(entry)
    for row in components:
        pairs = []
        seen = set()
        for entry in by_ps.get(row["port_set_uuid"], []):
            key = (entry.get("rule_uuid"), entry.get("type"),
                   entry.get("policy_uuid"))
            if key in seen:
                continue
            seen.add(key)
            pairs.append(entry)
        row["rule_u_sg"] = pairs
        row.pop("_rule_u_sg", None)
        row.pop("rule_uuid", None)


def collapse_by_port_set(components):
    """One ClickHouse row per port-set UUID. Policy/rule live only in rule_u_sg."""
    by = {}
    order = []
    for row in components:
        uid = row["port_set_uuid"]
        if uid not in by:
            by[uid] = row
            order.append(uid)
            continue
        keep = by[uid]
        seen_nics = set(keep.get("computed_nic_uuids") or [])
        for nic in row.get("computed_nic_uuids") or []:
            if nic not in seen_nics:
                seen_nics.add(nic)
                keep.setdefault("computed_nic_uuids", []).append(nic)
        if str(row.get("role") or "").startswith("isolation"):
            keep["role"] = row.get("role") or keep.get("role") or ""
        keep["all_ports"] = int(bool(keep.get("all_ports")) or bool(row.get("all_ports")))
        if (keep.get("applied_to_port_set_uuid") or ZERO) == ZERO:
            for key, value in row.items():
                if str(key).startswith("applied_to_") and value:
                    keep[key] = value
    out = []
    for uid in order:
        row = by[uid]
        row.pop("component_id", None)
        row.pop("policy_uuid", None)
        row.pop("policy_name", None)
        row.pop("rule_uuid", None)
        out.append(row)
    return out


def _side_eg_uuid(spec, prefix):
    eg = as_uuid(spec.get("%s_entity_group_reference" % prefix))
    if eg:
        return eg
    eg_list = uuid_list(spec.get("%s_entity_group_references" % prefix))
    return eg_list[0] if eg_list else ""


def _side_category_sel(spec, prefix):
    refs = uuid_list(spec.get("%s_category_references" % prefix))
    if not refs:
        return None
    et = str(spec.get("%s_category_associated_entity_type" % prefix) or "VM")
    return {
        "vm_category_refs": refs if et == "VM" else [],
        "subnet_category_refs": refs if et == "SUBNET" else [],
        "vpc_category_refs": refs if et == "VPC" else [],
    }


def _side_subnet_sel(spec, prefix):
    subnet = spec.get("%s_subnet" % prefix)
    if not isinstance(subnet, dict):
        return None
    value = subnet.get("value")
    prefix_len = subnet.get("prefix_length")
    if value is None or prefix_len is None:
        return None
    return {"subnet_list": ["%s/%s" % (value, prefix_len)]}


def _side_ag_sel(spec, prefix, ag_map):
    ag = uuid_list(spec.get("%s_address_group_references" % prefix))
    if not ag:
        return None
    cidrs = []
    for uid in ag:
        cidrs.extend((ag_map.get(uid) or {}).get("subnet_list") or [])
    return {"addresses": ag, "subnet_list": cidrs}


def _allow_any_sel(spec, side):
    sel = {}
    if side == "src":
        if spec.get("should_allow_any_src"):
            sel["should_allow_any_src"] = True
        if spec.get("src_allow_spec") in ALLOW_ANY_SPECS:
            sel["src_allow_spec"] = spec["src_allow_spec"]
    else:
        if spec.get("should_allow_any_dst"):
            sel["should_allow_any_dst"] = True
        if spec.get("dest_allow_spec") in ALLOW_ANY_SPECS:
            sel["dest_allow_spec"] = spec["dest_allow_spec"]
    return sel or None


def peer_selector(spec, side, ag_map, rule_type=""):
    """One src or dest selector from dump spec keys.

    FLEX: EG elif should_allow_any_* elif subnet elif AG.
    APPLICATION: subnet elif AG elif category elif EG elif should_allow_any
    / src_allow_spec|dest_allow_spec ALL|NONE.
    """
    prefix = "src" if side == "src" else "dest"
    if str(rule_type) == "FLEX":
        eg = _side_eg_uuid(spec, prefix)
        if eg:
            return {"entity_group_uuid": eg}
        allow = _allow_any_sel(spec, side)
        if allow:
            return allow
        sub = _side_subnet_sel(spec, prefix)
        if sub:
            return sub
        return _side_ag_sel(spec, prefix, ag_map)
    sub = _side_subnet_sel(spec, prefix)
    if sub:
        return sub
    ag = _side_ag_sel(spec, prefix, ag_map)
    if ag:
        return ag
    cat = _side_category_sel(spec, prefix)
    if cat:
        return cat
    eg = _side_eg_uuid(spec, prefix)
    if eg:
        return {"entity_group_uuid": eg}
    return _allow_any_sel(spec, side)


def applied_to_selector(spec, rule_type=""):
    """FLEX dump applied_to_entity_group_references -> role applied_to.

    Key missing (UI Global): no Atlas port-set. Empty list: no hash.
    EG hashes in global-scope-unique-id with no CIDRs.
    """
    if str(rule_type) != "FLEX":
        return None
    applied = uuid_list(spec.get("applied_to_entity_group_references"))
    if applied:
        return {"entity_group_uuid": applied[0]}
    if "applied_to_entity_group_references" not in spec:
        return {"applied_to_entity_group_references": None}
    return None


def selectors_from_spec(spec, ag_map=None, rule_type=""):
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

    src = peer_selector(spec, "src", ag_map, rule_type)
    if src:
        out.append(("src", src))
    dst = peer_selector(spec, "dest", ag_map, rule_type)
    if dst:
        out.append(("dest", dst))

    applied = applied_to_selector(spec, rule_type)
    if applied:
        out.append(("applied_to", applied))

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


def category_names(refs, mapping, existing=None):
    mapped = map_names(refs or [], mapping)
    if any(mapped):
        return mapped
    return [name for name in (existing or []) if name in ("any", "all")]


def vpc_category_map(vpcs):
    """VPC uuid -> category uuid list, plus ALL_VLAN empty list."""
    out = {ALL_VLAN_VPC: []}
    for row in vpcs or []:
        data = unwrap(row) if isinstance(row, dict) else row
        if not isinstance(data, dict):
            continue
        uid = as_uuid(data.get("ext_id") or data.get("uuid"))
        if not uid:
            continue
        meta = data.get("metadata") or {}
        out[uid] = uuid_list(meta.get("category_ids") or data.get("category_ids"))
    return out


def effective_vpc_refs(vpc_cat_refs, vpc_cat_map):
    """VPCs whose categories contain every selector VPC cat.

    If the selector has no VPC cats, skip storing all VPC UUIDs (too large).
    """
    vpc_cat_map = vpc_cat_map or {}
    want = set(uuid_list(vpc_cat_refs))
    if not want:
        return []
    return [
        vpc_uid for vpc_uid, cats in vpc_cat_map.items()
        if want <= set(uuid_list(cats))
    ]


def nic_tuples(uuids, by_uuid, ipv4_only=None, ipv6_only=None,
               is_ipv6_traffic_allowed=False, link_local=True):
    """(vm_name, nic_uuid, subnet, vpc, ip, host_uuid, host, cluster_uuid, cluster).

    When ipv4_only/ipv6_only are set, IP text follows those dump flags.
    Atlas rows pass neither so every learned IP is kept.
    """
    out = []
    apply_proto = ipv4_only is not None or ipv6_only is not None
    for uid in uuids:
        rec = by_uuid.get(uid) or {}
        if apply_proto:
            ips = filter_ips_by_protocol(
                rec.get("ips") or [], bool(ipv4_only), bool(ipv6_only),
                is_ipv6_traffic_allowed, link_local)
        else:
            ips = list(rec.get("ips") or [])
        out.append({
            "vm_name": rec.get("vm_name") or "",
            "nic_uuid": uid,
            "subnet": rec.get("subnet") or "",
            "vpc": rec.get("vpc") or "",
            "ip": ",".join(ips),
            "host_uuid": rec.get("host_uuid") or ZERO,
            "host": rec.get("host") or "",
            "cluster_uuid": rec.get("cluster_uuid") or ZERO,
            "cluster": rec.get("cluster") or "",
        })
    return out


def attach_nics(components, nics, vlan_uuid, global_uuid):
    index = nic_index(nics)
    cache = {}
    for comp in components:
        sel = comp.pop("sel")
        key = nic_match_key(comp, sel)
        if key not in cache:
            cache[key] = match_nics(
                sel, index, comp["namespace_uuid"], vlan_uuid, global_uuid,
                comp.get("policy_scope") or "",
                ipv4_only=bool(comp.get("ipv4_only")),
                ipv6_only=bool(comp.get("ipv6_only")),
                is_ipv6_traffic_allowed=bool(
                    comp.get("is_ipv6_traffic_allowed")),
                link_local=comp.get("link_local", True),
                role=comp.get("role") or "",
                project_uuid=comp.get("policy_project_uuid") or "")
        comp["computed_nic_uuids"] = sorted(cache[key])


def main():
    global LOG_BUNDLE_ID
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Ingest PC dump JSON into ClickHouse. Stdlib + clickhouse-client only.")
    parser.add_argument("--dump_dir", default="", help="Directory of dump JSON files")
    parser.add_argument(
        "--from_jsonl",
        default="",
        help="Load flow_policy/*.jsonl (ClickHouse dump). Use when PC dump JSON is absent.")
    parser.add_argument(
        "--log_bundle_id",
        type=int,
        default=0,
        help="Panacea log_bundle_id. Re-ingest DROPs this partition only.")
    parser.add_argument("--cluster_uuid", default="", help="Cluster UUID (bundle catalog)")
    parser.add_argument("--cluster_name", default="", help="Cluster display name")
    parser.add_argument("--pc_ip", default="", help="Prism Central IP")
    parser.add_argument("--nos_version", default="", help="AOS / NOS version")
    parser.add_argument(
        "--reset-schema",
        action="store_true",
        help="DROP all flow_policy tables then recreate (all bundles). First migration.")
    parser.add_argument(
        "--drop-bundle",
        type=int,
        default=0,
        help="Only DROP PARTITION for this log_bundle_id and exit.")
    parser.add_argument(
        "--schema",
        default="",
        help="Optional schema.sql; clickhouse_flow/schema.sql is used if omitted")
    args = parser.parse_args()
    dump_dir = args.dump_dir or args.from_jsonl

    ch_client("--query", "SELECT 1")
    if args.drop_bundle:
        drop_bundle_partitions(args.drop_bundle)
        print("dropped bundle %s" % args.drop_bundle)
        return 0
    if not dump_dir:
        parser.error("need --dump_dir or --from_jsonl")
    LOG_BUNDLE_ID = resolve_log_bundle_id(args.log_bundle_id, dump_dir)
    print("log_bundle_id=%s" % LOG_BUNDLE_ID)
    if args.reset_schema or not has_bundle_column("portset"):
        if not args.reset_schema:
            print("  existing tables lack log_bundle_id; recreating schema")
        ch_client("--multiquery", input_text=RESET_SCHEMA_SQL)
    schema_path = args.schema or os.path.join(here, "schema.sql")
    ch_client("--multiquery", input_text=load_schema_sql(schema_path))
    print("dropping old partition %s (other bundles kept)..." % LOG_BUNDLE_ID)
    drop_bundle_partitions(LOG_BUNDLE_ID)
    if args.from_jsonl:
        ingest_from_jsonl(args.from_jsonl)
        return 0

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
    vpc_cat_map = vpc_category_map(vpcs)
    eg_names = named_map(egs)
    cluster_uuid = as_uuid(args.cluster_uuid) or as_uuid(meta.get("cluster_uuid")) or ZERO
    insert_json("flow_policy.bundle", [{
        "dump_dir": os.path.abspath(dump_dir),
        "cluster_uuid": cluster_uuid,
        "cluster_name": args.cluster_name or str(meta.get("cluster_name") or ""),
        "pc_ip": args.pc_ip or str(meta.get("pc_ip") or ""),
        "nos_version": (
            args.nos_version
            or str(meta.get("nos_version") or meta.get("aos_version") or "")),
    }])
    insert_json("flow_policy.category", [
        {"category_uuid": uid, "name": name} for uid, name in cat_map.items()
    ])
    address_groups = [
        unwrap(row) for row in load_json(os.path.join(dump_dir, "address_groups.json"), [])]
    fqdn_map = load_json(os.path.join(dump_dir, "fqdn_to_ip_map.json"), {}) or {}
    subnet_rows = [
        unwrap(row) for row in load_json(os.path.join(dump_dir, "subnets.json"), [])]
    ag_map = {}
    for ag in address_groups:
        uid = as_uuid(ag.get("ext_id") or ag.get("uuid"))
        if uid:
            ag_map[uid] = {
                "subnet_list": expand_address_group(ag, fqdn_map),
                "name": str(ag.get("name") or ""),
            }
    eg_map = {
        as_uuid(eg.get("ext_id")): expand_entity_group(
            eg, ag_map, fqdn_map, vms, subnet_rows)
        for eg in egs}
    eg_map.pop("", None)
    sg_map = load_service_group_map(
        load_json(os.path.join(dump_dir, "service_groups.json"), []))
    nf_map = load_network_function_map(
        load_json(os.path.join(dump_dir, "network_functions.json"), []),
        load_json(os.path.join(dump_dir, "network_function_by_id.json"), {}) or {})
    nics = collect_nics(
        vms, subnet_rows, atlas_vpc_names(atlas_get),
        host_cluster_map(
            load_json(os.path.join(dump_dir, "hosts.json"), []),
            load_json(os.path.join(dump_dir, "clusters.json"), [])),
        vpc_map)
    insert_json("flow_policy.vm_nic", [{
        "nic_uuid": nic["nic_uuid"],
        "vm_uuid": nic["vm_uuid"] or ZERO,
        "vm_name": nic["vm_name"],
        "subnet_uuid": nic["subnet_uuid"] or ZERO,
        "subnet": nic["subnet"],
        "vpc_uuid": nic["vpc_uuid"] or ZERO,
        "vpc": nic["vpc"],
        "ip": nic["ip"],
        "host_uuid": nic.get("host_uuid") or ZERO,
        "host": nic.get("host") or "",
        "cluster_uuid": nic.get("cluster_uuid") or ZERO,
        "cluster": nic.get("cluster") or "",
    } for nic in nics])
    atlas = atlas_by_uuid(atlas_list, atlas_get)

    components = []
    u_sg_rows = {}
    verify = {
        "save": 0, "allow_all": 0, "ag_na": 0, "no_hash": 0, "ok": 0,
        "dump_should_allow_any": 0, "dump_should_allow_any_src": 0,
        "dump_should_allow_any_dst": 0, "dump_all_protocol": 0,
    }
    for policy in policies:
        if str(policy.get("state") or "").upper() == "SAVE":
            verify["save"] += 1
            continue
        namespace, scope = namespace_for_policy(policy, vlan_uuid, global_uuid)
        if not namespace:
            continue
        project_uuid = policy_project_uuid(policy) or DEFAULT_PROJECT_EXT_ID
        for rule in policy.get("rules") or []:
            orig = rule.get("spec") or {}
            if orig.get("should_allow_any_src"):
                verify["dump_should_allow_any_src"] += 1
                verify["dump_should_allow_any"] += 1
            if orig.get("should_allow_any_dst"):
                verify["dump_should_allow_any_dst"] += 1
                if not orig.get("should_allow_any_src"):
                    verify["dump_should_allow_any"] += 1
            if orig.get("is_all_protocol_allowed"):
                verify["dump_all_protocol"] += 1
            spec = apply_rule_service_defaults(rule)
            u_sg_id, u_sg_row = unique_service(spec, sg_map, nf_map)
            rule_type = str(rule.get("type") or "")
            rule_start = len(components)
            hashed_ok = False
            for role, sel in selectors_from_spec(spec, ag_map, rule_type):
                reason = add_component(
                    components, role, sel, policy, rule, namespace, scope,
                    eg_map, project_uuid, vlan_uuid, global_uuid)
                verify[reason] = verify.get(reason, 0) + 1
                if role == "applied_to":
                    key = "applied_to_%s" % reason
                    verify[key] = verify.get(key, 0) + 1
                if reason == "ok":
                    components[-1]["_rule_u_sg"] = rule_u_sg_entry(
                        components[-1]["rule_uuid"], role, spec, u_sg_row,
                        policy, rule)
                    hashed_ok = True
            if hashed_ok:
                u_sg_rows[u_sg_id] = u_sg_row
            attach_applied_to_on_peers(components[rule_start:])

    attach_portset_rules(components)
    attach_nics(components, nics, vlan_uuid, global_uuid)
    computed_component_count = len(components)
    isolation_component_count = sum(
        1 for row in components
        if str(row.get("role") or "").startswith("isolation"))
    allow_any_src_rows = sum(
        1 for row in components
        if row.get("role") == "src" and row.get("should_allow_any"))
    allow_any_dst_rows = sum(
        1 for row in components
        if row.get("role") == "dest" and row.get("should_allow_any"))
    allow_any_src_nics = sum(
        len(row.get("computed_nic_uuids") or []) for row in components
        if row.get("role") == "src" and row.get("should_allow_any"))
    allow_any_dst_nics = sum(
        len(row.get("computed_nic_uuids") or []) for row in components
        if row.get("role") == "dest" and row.get("should_allow_any"))
    components = collapse_by_port_set(components)
    nic_by_uuid = {nic["nic_uuid"]: nic for nic in nics}

    def fill_names(row, atlas_rec):
        computed = list(row.get("computed_nic_uuids") or [])
        atlas_nics = list(row.get("atlas_nic_uuids") or [])
        row["computed_nic_uuids"] = computed
        row["atlas_nic_uuids"] = atlas_nics
        proto = {}
        if "ipv4_only" in row or "ipv6_only" in row:
            proto = {
                "ipv4_only": bool(row.get("ipv4_only")),
                "ipv6_only": bool(row.get("ipv6_only")),
                "is_ipv6_traffic_allowed": bool(
                    row.get("is_ipv6_traffic_allowed")),
                "link_local": row.get("link_local", True),
            }
        row["computed_nics"] = nic_tuples(computed, nic_by_uuid, **proto)
        row["atlas_nics"] = nic_tuples(atlas_nics, nic_by_uuid)
        vn = row.get("virtual_network_uuid") or ZERO
        ns = row.get("namespace_uuid") or ZERO
        row["atlas_name"] = atlas_rec.get("atlas_name") or ""
        row["vpc_name"] = (
            atlas_rec.get("vpc_name")
            or vpc_map.get(vn)
            or vpc_map.get(ns)
            or "")
        row["entity_group_name"] = (
            row.get("entity_group_name")
            or eg_names.get(row.get("entity_group_uuid"), "")
            or "")
        row["vm_category_names"] = category_names(
            row.get("vm_category_refs") or [], cat_map,
            row.get("vm_category_names"))
        row["subnet_category_names"] = category_names(
            row.get("subnet_category_refs") or [], cat_map,
            row.get("subnet_category_names"))
        row["vpc_category_names"] = category_names(
            row.get("vpc_category_refs") or [], cat_map,
            row.get("vpc_category_names"))
        row["applied_to_entity_group_name"] = (
            row.get("applied_to_entity_group_name")
            or eg_names.get(row.get("applied_to_entity_group_uuid"), "")
            or "")
        row["applied_to_vm_category_names"] = category_names(
            row.get("applied_to_vm_category_refs") or [], cat_map,
            row.get("applied_to_vm_category_names"))
        row["applied_to_subnet_category_names"] = category_names(
            row.get("applied_to_subnet_category_refs") or [], cat_map,
            row.get("applied_to_subnet_category_names"))
        row["applied_to_vpc_category_names"] = category_names(
            row.get("applied_to_vpc_category_refs") or [], cat_map,
            row.get("applied_to_vpc_category_names"))
        if row.get("role") or (row.get("computed_port_set_uuid") or ZERO) != ZERO:
            vpc_refs = effective_vpc_refs(
                row.get("vpc_category_refs"), vpc_cat_map)
            row["effective_vpc_refs"] = vpc_refs
            row["effective_vpc_names"] = map_names(vpc_refs, vpc_map)
        else:
            row["effective_vpc_refs"] = []
            row["effective_vpc_names"] = []
        row["reference_names"] = [
            cat_map.get(uid) or eg_names.get(uid) or ""
            for uid in (row.get("reference_uuids") or [])
        ]
        row.pop("policy_name", None)
        row.pop("policy_uuid", None)
        row.pop("component_id", None)

    rows = []
    seen = set()
    for row in components:
        row.pop("policy_scope", None)
        row.pop("policy_project_uuid", None)
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
        row.pop("ipv4_only", None)
        row.pop("ipv6_only", None)
        row.pop("is_ipv6_traffic_allowed", None)
        row.pop("link_local", None)
        row.pop("should_allow_any", None)
        row.pop("rule_uuid", None)
        row.pop("sel", None)
        rows.append(row)
    for ps, atlas_rec in atlas.items():
        if ps in seen:
            continue
        row = {
            "port_set_uuid": ps,
            "computed_port_set_uuid": ZERO,
            "atlas_port_set_uuid": ps,
            "role": "",
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
            **empty_applied_to_columns(),
            "effective_vpc_refs": [],
            "effective_vpc_names": [],
            "eg_address_grp": [],
            "eg_exception_address_grp": [],
            **empty_rule_service_columns(),
            "computed_nic_uuids": [],
            "atlas_nic_uuids": list(atlas_rec.get("atlas_nic_uuids") or []),
            "all_ports": 0,
        }
        fill_names(row, atlas_rec)
        rows.append(row)
    insert_json("flow_policy.u_sg", list(u_sg_rows.values()))
    insert_json("flow_policy.portset", rows)

    print("nics", len(nics))
    print("atlas_uuids", len(atlas))
    print("computed_components", computed_component_count)
    print("isolation_components", isolation_component_count)
    print("portset_rows", len(rows))
    print("dump_should_allow_any", verify["dump_should_allow_any"])
    print("dump_should_allow_any_src", verify["dump_should_allow_any_src"])
    print("dump_should_allow_any_dst", verify["dump_should_allow_any_dst"])
    print("dump_is_all_protocol_allowed", verify["dump_all_protocol"])
    print("verify_skip_save", verify["save"])
    print("verify_allow_all_skipped", verify["allow_all"])
    print("verify_kube_skipped", verify.get("kube", 0))
    print("allow_any_src_rows", allow_any_src_rows)
    print("allow_any_dst_rows", allow_any_dst_rows)
    print("allow_any_src_nics", allow_any_src_nics)
    print("allow_any_dst_nics", allow_any_dst_nics)
    print("verify_applied_to_hashed", verify.get("applied_to_ok", 0))
    print("verify_applied_to_all_skipped", verify.get("applied_to_allow_all", 0))
    print("applied_to_with_vm_cats", sum(
        1 for row in components
        if row.get("role") == "applied_to" and row.get("vm_category_refs")))
    print("applied_to_with_subnet_cats", sum(
        1 for row in components
        if row.get("role") == "applied_to" and row.get("subnet_category_refs")))
    print("applied_to_with_vpc_cats", sum(
        1 for row in components
        if row.get("role") == "applied_to" and row.get("vpc_category_refs")))
    print("applied_to_with_subnet_list", sum(
        1 for row in components
        if row.get("role") == "applied_to" and row.get("subnet_list")))
    print("applied_to_with_vm_ext_ids", sum(
        1 for row in components
        if row.get("role") == "applied_to" and row.get("vm_ext_ids")))
    print("verify_ag_na_skipped", verify["ag_na"])
    print("verify_no_hash", verify["no_hash"])
    print("verify_all_ports_components", sum(
        1 for row in components if row.get("all_ports")))
    print("eg_vm_ext_ids", sum(
        len(sel.get("vm_ext_ids") or []) for sel in eg_map.values()))
    print("eg_subnet_ext_ids", sum(
        len(sel.get("subnet_ext_ids") or []) for sel in eg_map.values()))
    print("eg_direct_vm", sum(
        1 for sel in eg_map.values() if sel.get("has_direct_vm")))
    print("computed_uuids", len(seen))
    print("service_groups", len(sg_map))
    print("network_functions", len(nf_map))
    print("u_sg", len(u_sg_rows))
    print("u_sg_sg", sum(1 for row in u_sg_rows.values() if row.get("kind") == "sg"))
    print("u_sg_sg_list", sum(
        1 for row in u_sg_rows.values() if row.get("kind") == "sg_list"))
    print("u_sg_inline", sum(
        1 for row in u_sg_rows.values() if row.get("kind") == "inline"))
    print("u_sg_with_nf", sum(
        1 for row in u_sg_rows.values()
        if (row.get("network_function_uuid") or ZERO) != ZERO))
    print("nics_with_host", sum(
        1 for nic in nics if (nic.get("host_uuid") or ZERO) != ZERO))
    print("nics_with_cluster", sum(
        1 for nic in nics if (nic.get("cluster_uuid") or ZERO) != ZERO))
    print("rows", len(rows))
    print("inserted_into",
          "flow_policy.bundle,flow_policy.portset,flow_policy.u_sg,"
          "flow_policy.vm_nic,flow_policy.category",
          "log_bundle_id=%s" % LOG_BUNDLE_ID)


if __name__ == "__main__":
    main()
