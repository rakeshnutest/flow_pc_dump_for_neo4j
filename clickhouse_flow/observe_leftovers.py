#!/usr/bin/env python3
"""Discover Atlas leftover and Atlas-missing port-set UUIDs.

Match identity is port-set UUID only. Names are display labels.
NIC UUID in computed and missing in Atlas is a bug. NIC UUID in Atlas and
missing in computed is a bug. Atlas missing (computed UUID with no Atlas
UUID) is critical.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ingest import (  # noqa: E402
    DEFAULT_PROJECT_EXT_ID,
    GLOBAL_SCOPE_UNIQUE_ID,
    VLAN_SCOPE_UNIQUE_ID,
    compute_addressset_hashes,
    generate_port_set_id,
)
from leftover_ignore import leftover_ignore_reason  # noqa: E402

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
ZERO = "00000000-0000-0000-0000-000000000000"
DEFAULT_PORTSET_JSONL = (
    "/home/rakeshkumar.r/panacea/flow_pc_dumps/clickhouse_all_dump/"
    "flow_policy/portset.jsonl"
)
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


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


def unwrap(row):
    if isinstance(row, dict) and isinstance(row.get("data"), dict):
        return row["data"]
    return row or {}


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as handle:
        return json.load(handle)


def ch_query(sql):
    cmd = [
        "clickhouse-client",
        "--host", CH_HOST,
        "--port", CH_NATIVE,
        "--user", "default",
        "--query", sql,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "ch failed")
    return proc.stdout


def present(uid):
    return bool(as_uuid(uid)) and as_uuid(uid) != ZERO


def category_name(row):
    data = unwrap(row)
    uid = as_uuid(data.get("ext_id") or data.get("uuid"))
    key = str(data.get("key") or "")
    value = str(data.get("value") or "")
    name = str(data.get("name") or "")
    if key and value:
        return uid, "%s:%s" % (key, value)
    return uid, name or value or key or uid


def eg_is_kube(eg):
    allowed = ((eg.get("allowed_config") or {}).get("entities")) or []
    kinds = [str(entity.get("type") or "").upper() for entity in allowed]
    has_kube = any(kind.startswith("KUBE") for kind in kinds)
    has_workload = any(kind in ("VM", "SUBNET", "VPC") for kind in kinds)
    return has_kube and not has_workload


def eg_members(eg):
    """Full allowed/except entity values for an entity group."""
    out = {"allowed": [], "excepted": []}
    if not eg:
        return out
    for bucket, key in (("allowed", "allowed_config"), ("excepted", "except_config")):
        for entity in ((eg.get(key) or {}).get("entities")) or []:
            kind = str(entity.get("type") or "")
            select_by = str(entity.get("select_by") or "")
            refs = uuid_list(entity.get("reference_ext_ids"))
            kube_entities = [str(x) for x in (entity.get("kube_entities") or []) if x]
            fqdns = [str(x) for x in (entity.get("fqdns") or []) if x]
            addrs = entity.get("addresses") or {}
            ipv4 = addrs.get("ipv4_addresses") or []
            ipv6 = addrs.get("ipv6_addresses") or []
            out[bucket].append({
                "type": kind,
                "select_by": select_by,
                "reference_ext_ids": refs,
                "kube_entities": kube_entities,
                "fqdns": fqdns,
                "ipv4_addresses": ipv4,
                "ipv6_addresses": ipv6,
            })
    return out


def spec_uuids(spec):
    found = []
    for key, value in (spec or {}).items():
        if "reference" not in str(key).lower() and "group" not in str(key).lower():
            continue
        if isinstance(value, str):
            uid = as_uuid(value)
            if uid:
                found.append(uid)
        elif isinstance(value, list):
            found.extend(uuid_list(value))
    nested = ((spec.get("spec") or {}).get("isolation_groups")) or []
    for group in nested:
        found.extend(spec_uuids(group))
    return found


LEFTOVER_SQL = """
SELECT
    toString(p.port_set_uuid) AS port_set_uuid,
    toString(p.computed_port_set_uuid) AS computed_port_set_uuid,
    toString(p.atlas_port_set_uuid) AS atlas_port_set_uuid,
    p.match_status,
    p.mismatch_kind,
    p.atlas_name,
    p.entity_type,
    p.role,
    p.rule_u_sg,
    toString(p.entity_group_uuid) AS entity_group_uuid,
    p.entity_group_name,
    toString(p.namespace_uuid) AS namespace_uuid,
    toString(p.virtual_network_uuid) AS virtual_network_uuid,
    p.vpc_name,
    p.reference_uuids,
    p.reference_names,
    p.vm_category_refs,
    p.vm_category_names,
    p.subnet_category_refs,
    p.subnet_category_names,
    p.vpc_category_refs,
    p.vpc_category_names,
    p.vm_ext_ids,
    p.subnet_ext_ids,
    p.subnet_list,
    p.exception_list,
    p.effective_vpc_refs,
    p.effective_vpc_names,
    p.eg_address_grp,
    p.eg_exception_address_grp,
    p.computed_nic_uuids,
    p.atlas_nic_uuids,
    p.computed_nics,
    p.atlas_nics
FROM flow_policy.portset AS p
FINAL
WHERE (
    (p.atlas_port_set_uuid != toUUID('%(z)s') AND p.computed_port_set_uuid = toUUID('%(z)s'))
    OR
    (p.computed_port_set_uuid != toUUID('%(z)s') AND p.atlas_port_set_uuid = toUUID('%(z)s'))
)
FORMAT JSONEachRow
""" % {"z": ZERO}


def fetch_leftover_rows():
    rows = []
    for line in ch_query(LEFTOVER_SQL).splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def fetch_leftover_rows_from_jsonl(path):
    """Leftovers from portset.jsonl. Does not query flow_policy ClickHouse."""
    rows = []
    with open(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            kind = str(row.get("mismatch_kind") or "")
            status = str(row.get("match_status") or "")
            atlas = as_uuid(row.get("atlas_port_set_uuid"))
            comp = as_uuid(row.get("computed_port_set_uuid"))
            atlas_only = (
                kind in ("atlas_without_computed", "atlas_only")
                or status in ("atlas_without_computed", "atlas_only")
                or (present(atlas) and not present(comp))
            )
            computed_only = (
                kind in ("computed_without_atlas", "computed_only")
                or status in ("computed_without_atlas", "computed_only")
                or (present(comp) and not present(atlas))
            )
            if atlas_only or computed_only:
                rows.append(row)
    return rows


def group_leftovers(rows):
    grouped = {}
    for row in rows:
        uid = as_uuid(row.get("port_set_uuid")) or str(row.get("port_set_uuid") or "")
        rec = grouped.setdefault(uid, {
            "uuid": uid,
            "rows": [],
            "computed_uuids": set(),
            "atlas_uuids": set(),
            "computed_nics": set(),
            "atlas_nics": set(),
            "policy_names": [],
            "atlas_names": [],
            "entity_group_uuids": [],
        })
        rec["rows"].append(row)
        if present(row.get("computed_port_set_uuid")):
            rec["computed_uuids"].add(as_uuid(row["computed_port_set_uuid"]))
        if present(row.get("atlas_port_set_uuid")):
            rec["atlas_uuids"].add(as_uuid(row["atlas_port_set_uuid"]))
        rec["computed_nics"].update(uuid_list(row.get("computed_nic_uuids")))
        rec["atlas_nics"].update(uuid_list(row.get("atlas_nic_uuids")))
        for entry in (row.get("rule_u_sg") or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get("policy_name") or ""
            if name and name not in rec["policy_names"]:
                rec["policy_names"].append(name)
        if row.get("atlas_name") and row["atlas_name"] not in rec["atlas_names"]:
            rec["atlas_names"].append(row["atlas_name"])
        eg = as_uuid(row.get("entity_group_uuid"))
        if eg and eg not in rec["entity_group_uuids"]:
            rec["entity_group_uuids"].append(eg)
    for rec in grouped.values():
        has_c = bool(rec["computed_uuids"])
        has_a = bool(rec["atlas_uuids"])
        if has_c and not has_a:
            rec["kind"] = "computed_without_atlas"
        elif has_a and not has_c:
            rec["kind"] = "atlas_without_computed"
        else:
            rec["kind"] = "other"
        rec["computed_uuid"] = next(iter(rec["computed_uuids"]), ZERO)
        rec["atlas_uuid"] = next(iter(rec["atlas_uuids"]), ZERO)
        rec["policy_name"] = rec["policy_names"][0] if rec["policy_names"] else ""
        rec["atlas_name"] = rec["atlas_names"][0] if rec["atlas_names"] else ""
        rec["entity_group_uuid"] = rec["entity_group_uuids"][0] if rec["entity_group_uuids"] else ""
        rec["entity_type"] = (rec["rows"][0].get("entity_type") or "") if rec["rows"] else ""
        rec["atlas_nics_n"] = len(rec["atlas_nics"])
        rec["computed_nics_n"] = len(rec["computed_nics"])
    return grouped


def remember(index, hashed, meta):
    if not hashed:
        return
    values = hashed if isinstance(hashed, list) else [hashed]
    for item in values:
        uid = as_uuid(item) or str(item).lower()
        if uid:
            index[uid].append(meta)


def build_hash_index(dump):
    index = defaultdict(list)
    meta = dump["meta"]
    vlan = as_uuid(meta.get("vlan_unique_uuid"))
    glob = as_uuid(meta.get("global_unique_uuid"))
    namespaces = []
    if vlan:
        namespaces.append((vlan, "ALL_VLAN", False))
        namespaces.append((VLAN_SCOPE_UNIQUE_ID, "ALL_VLAN", True))
    if glob:
        namespaces.append((glob, "GLOBAL", False))
        namespaces.append((GLOBAL_SCOPE_UNIQUE_ID, "GLOBAL", True))
    for vpc in dump["vpcs"]:
        uid = as_uuid(vpc.get("ext_id") or vpc.get("uuid"))
        if uid:
            namespaces.append((uid, "VPC_LIST", False))
    for policy in dump["policies"]:
        for uid in uuid_list(policy.get("scope_references")):
            namespaces.append((uid, "VPC_AS_CATEGORY", False))
    seen_ns = set()
    unique_ns = []
    for item in namespaces:
        key = (str(item[0]), item[1], item[2])
        if key in seen_ns:
            continue
        seen_ns.add(key)
        unique_ns.append(item)

    projects = {DEFAULT_PROJECT_EXT_ID}
    for policy in dump["policies"]:
        uid = as_uuid(
            policy.get("project_ext_id")
            or policy.get("projectExtId")
            or (policy.get("project") or {}).get("ext_id"))
        if uid:
            projects.add(uid)

    def hash_entity(etype, refs, label, kube=False, eg_uuid=""):
        for ns, scope, is_flex in unique_ns:
            for project in projects:
                hashed = generate_port_set_id(
                    (etype, refs), ns, project, is_flex=is_flex)
                remember(index, hashed, {
                    "kind": "port_set",
                    "entity_type": etype,
                    "refs": list(refs),
                    "label": label,
                    "scope": scope,
                    "namespace": str(ns),
                    "flex": is_flex,
                    "project": project,
                    "kube": kube,
                    "eg_uuid": eg_uuid,
                })

    for uid, name in dump["categories"].items():
        for etype in ("VM", "SUBNET", "VPC"):
            hash_entity(etype, [uid], name)
        remember(index, compute_addressset_hashes(uid, True, False), {
            "kind": "address_set", "label": name, "ip": "IPv4", "kube": False})
        remember(index, compute_addressset_hashes(uid, False, True), {
            "kind": "address_set", "label": name, "ip": "IPv6", "kube": False})

    for eg in dump["egs"]:
        uid = as_uuid(eg.get("ext_id"))
        if not uid:
            continue
        name = str(eg.get("name") or uid)
        kube = eg_is_kube(eg)
        hash_entity("EG", [uid], name, kube=kube, eg_uuid=uid)
        remember(index, compute_addressset_hashes(uid, True, False), {
            "kind": "address_set", "label": name, "ip": "IPv4", "kube": kube,
            "eg_uuid": uid})
        remember(index, compute_addressset_hashes(uid, False, True), {
            "kind": "address_set", "label": name, "ip": "IPv6", "kube": kube,
            "eg_uuid": uid})

    for ag in dump["ags"]:
        uid = as_uuid(ag.get("ext_id") or ag.get("uuid"))
        if not uid:
            continue
        name = str(ag.get("name") or uid)
        remember(index, compute_addressset_hashes(uid, True, False), {
            "kind": "address_set", "label": name, "ip": "IPv4", "kube": False})
        remember(index, compute_addressset_hashes(uid, False, True), {
            "kind": "address_set", "label": name, "ip": "IPv6", "kube": False})
    return index


def empty_dump():
    return {
        "unavailable": True,
        "meta": {},
        "policies": [],
        "egs": [],
        "eg_by_uuid": {},
        "categories": {},
        "vpcs": [],
        "vpc_names": {},
        "ags": [],
        "kube_egs": set(),
        "policy_names": set(),
        "policies_by_name": {},
        "referenced": set(),
        "kube_policy_names": set(),
    }


def load_dump(dump_dir):
    policies = [unwrap(p) for p in load_json(os.path.join(dump_dir, "policies.json"), [])]
    egs = [unwrap(e) for e in load_json(os.path.join(dump_dir, "entity_groups.json"), [])]
    categories = {}
    for row in load_json(os.path.join(dump_dir, "categories.json"), []):
        uid, name = category_name(row)
        if uid:
            categories[uid] = name
    vpcs = [unwrap(v) for v in load_json(os.path.join(dump_dir, "vpcs.json"), [])]
    ags = [unwrap(a) for a in load_json(os.path.join(dump_dir, "address_groups.json"), [])]
    eg_by_uuid = {}
    kube_egs = set()
    for eg in egs:
        uid = as_uuid(eg.get("ext_id"))
        if not uid:
            continue
        eg_by_uuid[uid] = eg
        if eg_is_kube(eg):
            kube_egs.add(uid)
    policy_names = {str(p.get("name") or "") for p in policies}
    referenced = set()
    kube_policy_names = set()
    policies_by_name = {}
    for policy in policies:
        name = str(policy.get("name") or "")
        policies_by_name.setdefault(name, []).append(policy)
        used = set()
        for rule in policy.get("rules") or []:
            used.update(spec_uuids(rule.get("spec") or {}))
        referenced.update(used)
        if used & kube_egs:
            kube_policy_names.add(name)
    vpc_names = {}
    for vpc in vpcs:
        uid = as_uuid(vpc.get("ext_id") or vpc.get("uuid"))
        if uid:
            vpc_names[uid] = str(vpc.get("name") or uid)
    return {
        "meta": load_json(os.path.join(dump_dir, "meta.json"), {}),
        "policies": policies,
        "egs": egs,
        "eg_by_uuid": eg_by_uuid,
        "categories": categories,
        "vpcs": vpcs,
        "vpc_names": vpc_names,
        "ags": ags,
        "kube_egs": kube_egs,
        "policy_names": policy_names,
        "policies_by_name": policies_by_name,
        "referenced": referenced,
        "kube_policy_names": kube_policy_names,
    }


def leftover_is_kube(rec, hits, dump):
    """EG membership (KUBE_* types). Reporting skip is leftover_ignore.py."""
    if rec.get("entity_group_uuid") in dump["kube_egs"]:
        return True
    for uid in rec.get("entity_group_uuids") or []:
        if uid in dump["kube_egs"]:
            return True
    for hit in hits:
        if hit.get("kube") or hit.get("eg_uuid") in dump["kube_egs"]:
            return True
        refs = hit.get("refs") or []
        if refs and all(ref in dump["kube_egs"] for ref in refs):
            return True
    return False


def observe_one(leftover, hits, dump):
    """Notes are UUID-only. Display names are never used as identity."""
    kind = leftover["kind"]
    hit = hits[0] if hits else {}
    notes = []
    if kind == "atlas_without_computed":
        notes.append(
            "This UUID is in Atlas and not in computed. Match is UUID identity, not name.")
    elif kind == "computed_without_atlas":
        notes.append(
            "This UUID is in computed and not in Atlas (Atlas missing). Match is UUID identity, not name.")
    if dump.get("unavailable"):
        notes.append(
            "PC dump JSON not available; leftover classified from portset.jsonl only.")
        hit = {}
    if hit.get("kind") == "address_set":
        notes.append(
            "Reverse-hashes as address_set %s of entity UUID %s."
            % (hit.get("ip") or "", hit.get("label") or ""))
    elif hit:
        notes.append(
            "Reverse-hashes to entity_type %s, selector UUID(s) %s, namespace %s%s."
            % (hit.get("entity_type") or "",
               ", ".join(hit.get("refs") or []) or "(none)",
               hit.get("namespace") or hit.get("scope") or "",
               " FLEX" if hit.get("flex") else ""))
        refs = hit.get("refs") or []
        if refs and not any(ref in dump["referenced"] for ref in refs):
            notes.append(
                "No dump policy selector list contains these selector UUIDs, so ingest cannot emit this port-set UUID.")
        elif refs and any(ref in dump["referenced"] for ref in refs):
            notes.append(
                "Dump policies do reference these selector UUIDs, but none of those policies emit this port-set UUID.")
    elif not dump.get("unavailable"):
        notes.append(
            "This port-set UUID does not reverse-hash to any dump category, entity-group, or address-group UUID.")
    only_c = leftover["computed_nics"] - leftover["atlas_nics"]
    only_a = leftover["atlas_nics"] - leftover["computed_nics"]
    if only_c:
        notes.append("BUG: computed NIC UUIDs missing in Atlas: %s." % sorted(only_c))
    if only_a:
        notes.append("BUG: Atlas NIC UUIDs missing in computed: %s." % sorted(only_a))
    if not only_c and not only_a:
        notes.append("No NIC-UUID bug on this leftover (both NIC sets empty or equal).")
    return notes


def fmt_list(values):
    values = [str(v) for v in (values or []) if str(v)]
    return ", ".join("`%s`" % v for v in values) if values else "(none)"


def matching_lines(rec):
    computed = rec.get("computed_uuid") or ZERO
    atlas = rec.get("atlas_uuid") or ZERO
    c_ok = present(computed)
    a_ok = present(atlas)
    only_c = sorted(rec["computed_nics"] - rec["atlas_nics"])
    only_a = sorted(rec["atlas_nics"] - rec["computed_nics"])
    both = sorted(rec["computed_nics"] & rec["atlas_nics"])
    if c_ok and a_ok and rec["computed_nics"] == rec["atlas_nics"]:
        verdict = "match (same UUID both sides, NIC UUID sets equal)"
    elif c_ok and a_ok:
        verdict = "NIC bug (same port-set UUID both sides, NIC UUID sets differ)"
    elif c_ok:
        verdict = "Atlas missing (this UUID is computed-only)"
    elif a_ok:
        verdict = "Atlas leftover (this UUID is Atlas-only)"
    else:
        verdict = "neither side present"
    return [
        "- **UUID match**",
        "  - verdict: **%s**" % verdict,
        "  - this UUID: `%s`" % rec["uuid"],
        "  - computed has this UUID: `%s`" % ("yes" if c_ok else "no"),
        "  - Atlas has this UUID: `%s`" % ("yes" if a_ok else "no"),
        "  - computed NIC UUIDs (%s): %s" % (
            rec["computed_nics_n"], fmt_list(sorted(rec["computed_nics"]))),
        "  - Atlas NIC UUIDs (%s): %s" % (
            rec["atlas_nics_n"], fmt_list(sorted(rec["atlas_nics"]))),
        "  - NIC UUIDs in both: %s" % fmt_list(both),
        "  - computed NIC UUIDs missing in Atlas: %s" % fmt_list(only_c),
        "  - Atlas NIC UUIDs missing in computed: %s" % fmt_list(only_a),
    ]


def member_lines(members, dump):
    lines = []
    if not members:
        lines.append("  - (none)")
        return lines
    for entity in members:
        kind = entity.get("type") or ""
        select_by = entity.get("select_by") or ""
        lines.append("  - type: `%s` select_by: `%s`" % (kind, select_by or "(none)"))
        refs = entity.get("reference_ext_ids") or []
        if refs:
            named = []
            for uid in refs:
                named.append("%s (%s)" % (
                    uid, dump["vpc_names"].get(uid) or dump["categories"].get(uid) or "ext_id"))
            lines.append("    - reference_ext_ids: %s" % fmt_list(named))
        if entity.get("kube_entities"):
            lines.append("    - kube_entities: %s" % fmt_list(entity["kube_entities"]))
        if entity.get("fqdns"):
            lines.append("    - fqdns: %s" % fmt_list(entity["fqdns"]))
        for label, addrs in (
                ("ipv4_addresses", entity.get("ipv4_addresses")),
                ("ipv6_addresses", entity.get("ipv6_addresses"))):
            if not addrs:
                continue
            shown = []
            for addr in addrs:
                if isinstance(addr, dict):
                    shown.append("%s/%s" % (addr.get("value"), addr.get("prefix_length")))
                else:
                    shown.append(str(addr))
            lines.append("    - %s: %s" % (label, fmt_list(shown)))
    return lines


def entity_lines(rec, dump, hits):
    lines = []
    eg_uuids = list(rec.get("entity_group_uuids") or [])
    for hit in hits:
        uid = as_uuid(hit.get("eg_uuid"))
        if uid and uid not in eg_uuids:
            eg_uuids.append(uid)
    if not eg_uuids and rec.get("entity_group_uuid"):
        eg_uuids.append(rec["entity_group_uuid"])
    if not eg_uuids:
        row = rec["rows"][0] if rec["rows"] else {}
        lines.append("- entity_type: `%s`" % (rec.get("entity_type") or row.get("entity_type") or ""))
        if row.get("vm_category_names") or row.get("vm_category_refs"):
            lines.append("- vm categories: %s" % fmt_list(
                row.get("vm_category_names") or row.get("vm_category_refs")))
        if row.get("subnet_category_names") or row.get("subnet_category_refs"):
            lines.append("- subnet categories: %s" % fmt_list(
                row.get("subnet_category_names") or row.get("subnet_category_refs")))
        if row.get("vpc_category_names") or row.get("vpc_category_refs"):
            lines.append("- vpc categories: %s" % fmt_list(
                row.get("vpc_category_names") or row.get("vpc_category_refs")))
        if row.get("reference_names") or row.get("reference_uuids"):
            lines.append("- references: %s" % fmt_list(
                row.get("reference_names") or row.get("reference_uuids")))
        return lines
    for eg_uuid in eg_uuids:
        eg = dump["eg_by_uuid"].get(eg_uuid) or {}
        members = eg_members(eg)
        lines.append("- entity_group_uuid: `%s`" % eg_uuid)
        lines.append("- entity_group_name: `%s`" % (eg.get("name") or rec["rows"][0].get("entity_group_name") or ""))
        lines.append("- allowed entities:")
        lines.extend(member_lines(members["allowed"], dump))
        if members["excepted"]:
            lines.append("- except entities:")
            lines.extend(member_lines(members["excepted"], dump))
    return lines


def component_lines(rec, dump):
    lines = ["- **components**"]
    for row in rec["rows"]:
        ns = as_uuid(row.get("namespace_uuid"))
        vn = as_uuid(row.get("virtual_network_uuid"))
        names = []
        for entry in (row.get("rule_u_sg") or []):
            if isinstance(entry, dict) and entry.get("policy_name"):
                if entry["policy_name"] not in names:
                    names.append(entry["policy_name"])
        lines.append(
            "  - policy=`%s` role=`%s` entity_type=`%s`"
            % (", ".join(names[:4]) or row.get("atlas_name") or "",
               row.get("role") or "",
               row.get("entity_type") or ""))
        for entry in (row.get("rule_u_sg") or []):
            if not isinstance(entry, dict):
                continue
            lines.append(
                "    - rule_uuid: `%s` type=`%s` policy=`%s` mode=`%s`"
                % (as_uuid(entry.get("rule_uuid")) or ZERO,
                   entry.get("type") or "",
                   entry.get("policy_type") or "",
                   entry.get("policy_mode") or ""))
        lines.append(
            "    - namespace_uuid: `%s` (%s)"
            % (ns or ZERO, dump["vpc_names"].get(ns) or row.get("vpc_name") or ""))
        if vn:
            lines.append(
                "    - virtual_network_uuid: `%s` (%s)"
                % (vn, dump["vpc_names"].get(vn) or row.get("vpc_name") or ""))
        if row.get("reference_names") or row.get("reference_uuids"):
            lines.append("    - references: %s" % fmt_list(
                row.get("reference_names") or row.get("reference_uuids")))
        if row.get("vm_category_names"):
            lines.append("    - vm_category_names: %s" % fmt_list(row["vm_category_names"]))
        if row.get("subnet_list"):
            lines.append("    - subnet_list: %s" % fmt_list(row["subnet_list"]))
    return lines


def render_leftover(item, dump):
    lines = ["### `%s`" % item["uuid"], ""]
    lines.append("- kind: `%s`" % item["kind"])
    lines.append("- display atlas_name: `%s`" % (item.get("atlas_name") or "(none)"))
    for name in item.get("policy_names") or []:
        lines.append("- display policy_name: `%s`" % name)
    lines.extend(matching_lines(item))
    if item.get("hash_label"):
        hit = (item.get("hits") or [{}])[0]
        lines.append(
            "- reverse_hash selector UUIDs: %s"
            % fmt_list(hit.get("refs") or []))
    lines.extend(entity_lines(item, dump, item.get("hits") or []))
    lines.extend(component_lines(item, dump))
    for note in item.get("notes") or []:
        lines.append("- observation: %s" % note)
    lines.append("")
    return lines


def render(path, leftovers, dump, dump_dir, skipped=None, source=""):
    atlas_left = [x for x in leftovers if x["kind"] == "atlas_without_computed"]
    atlas_missing = [x for x in leftovers if x["kind"] == "computed_without_atlas"]
    nic_bugs = [
        x for x in leftovers
        if (x["computed_nics"] - x["atlas_nics"]) or (x["atlas_nics"] - x["computed_nics"])
    ]
    skipped = skipped or {"k8s": 0, "empty_quarantine": 0}
    lines = [
        "# Port-set leftover observations",
        "",
        "Generated: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Dump: `%s`" % dump_dir,
    ]
    if source:
        lines.append("Source: `%s`" % source)
    lines.extend([
        "Identity is port-set UUID only. Names are display labels.",
        "K8s / empty Quarantine names are ignore-class noise only, not identity.",
        "",
        "## Counts",
        "",
        "- Atlas leftover (this UUID in Atlas, not in computed): **%s**" % len(atlas_left),
        "- Atlas missing (this UUID in computed, not in Atlas) **critical**: **%s**" % len(atlas_missing),
        "- NIC UUID bugs: **%s**" % len(nic_bugs),
        "- ignored %s K8s leftovers, %s empty Quarantine leftovers"
        % (skipped.get("k8s", 0), skipped.get("empty_quarantine", 0)),
        "",
        "Empty Quarantine means `atlas_nic_uuids`, `computed_nic_uuids`, "
        "`only_atlas_nics`, `atlas_nics`, and `computed_nics` are all empty.",
        "",
        "## Atlas leftover",
        "",
        "Each UUID below is present in Atlas and absent from computed.",
        "A different UUID that already matches is a different object.",
        "",
    ])
    if not atlas_left:
        lines.append("None.")
        lines.append("")
    for item in atlas_left:
        lines.extend(render_leftover(item, dump))
    lines.append("## Atlas missing (critical)")
    lines.append("")
    lines.append("Each UUID below is present in computed and absent from Atlas.")
    lines.append("")
    if not atlas_missing:
        lines.append("None.")
        lines.append("")
    for item in atlas_missing:
        lines.extend(render_leftover(item, dump))
    with open(path, "w") as handle:
        handle.write("\n".join(lines))


def enrich(rec, index, dump):
    hits = index.get(rec["uuid"].lower()) or []
    rec["hits"] = hits
    rec["notes"] = observe_one(rec, hits, dump)
    if hits:
        rec["hash_label"] = "%s %s" % (
            hits[0].get("entity_type") or hits[0].get("kind"),
            hits[0].get("label") or "")
    return leftover_ignore_reason(rec)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dump_dir", default="", help="Directory of dump JSON files")
    parser.add_argument(
        "--from_jsonl",
        default="",
        help="Read leftovers from portset.jsonl (does not query flow_policy)")
    parser.add_argument(
        "--from_ch",
        action="store_true",
        help="Read leftovers from flow_policy ClickHouse instead of jsonl")
    parser.add_argument(
        "--out",
        default=os.path.join(HERE, "leftover_observations.md"))
    args = parser.parse_args()
    if args.dump_dir and os.path.isdir(args.dump_dir):
        dump = load_dump(args.dump_dir)
    else:
        dump = empty_dump()
        args.dump_dir = args.dump_dir or "(none)"
    index = {} if dump.get("unavailable") else build_hash_index(dump)
    jsonl_path = args.from_jsonl
    if not args.from_ch:
        jsonl_path = jsonl_path or DEFAULT_PORTSET_JSONL
    if args.from_ch:
        grouped = group_leftovers(fetch_leftover_rows())
        source = "flow_policy ClickHouse"
    else:
        grouped = group_leftovers(fetch_leftover_rows_from_jsonl(jsonl_path))
        source = jsonl_path
    observed = []
    skipped = {"k8s": 0, "empty_quarantine": 0}
    for rec in grouped.values():
        reason = enrich(rec, index, dump)
        if reason:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        observed.append(rec)
    observed.sort(key=lambda r: (r["kind"], r["uuid"]))
    render(args.out, observed, dump, args.dump_dir, skipped=skipped, source=source)
    print("atlas_leftover", sum(1 for r in observed if r["kind"] == "atlas_without_computed"))
    print("atlas_missing", sum(1 for r in observed if r["kind"] == "computed_without_atlas"))
    print("ignored_k8s", skipped.get("k8s", 0))
    print("ignored_empty_quarantine", skipped.get("empty_quarantine", 0))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
