#!/usr/bin/env python3
"""Annotate network_security_policy proto-text with Atlas port-set UUIDs.

Hash matches FnsPortSetValidator._generate_port_set_id (APPLICATION uuid5).
FLEX rules use the ingest/Salus MD5 (salus + scope + Go-style list).

How a port-set UUID is generated
--------------------------------
1. Pick the scope namespace:
   - kGlobal / GLOBAL     -> zk /appliance/logical/flow/global_unique_uuid
   - kAllVlan / missing   -> zk /appliance/logical/flow/vlan_unique_uuid
   - VPC_LIST / VPC_AS_CATEGORY -> first VPC UUID on the policy
   FLEX uses the strings "global-scope-unique-id" / "vlan-scope-unique-id".

2. Pick entity refs on the component (endpoint / secured_group):
   - entity_group_uuid_list          -> type None/EG, refs=[eg]
   - category_uuid_list + kVM        -> type VM,     refs=categories
   - category_uuid_list + kSubnet    -> type SUBNET, refs=categories + ":kSubnet"
   - category_uuid_list + kVPC       -> type VPC,    refs=categories + ":kVPC"
   Skip allow-any (kTypeAll), allow-none (kTypeNone), address_group (AG).

3. APPLICATION / QUARANTINE uuid5:
      body = str(sorted(refs))          # Python list, e.g. "['uuid']"
      body = re.sub(r"'[a-z0-9A-Z\\-]+'", lambda m: "u" + m.group(0), body)
      if type not in (None, "VM", "EG"): body += ":kSubnet"|":kVPC"
      port_set_uuid = uuid5(UUID(unique_uuid), body)

4. Write port_set_uuid onto that component in the rule.

Stdlib only. No nutest, no neo4j, no pip.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
    vals = node.get(key) or []
    return vals[0] if vals else default


def values(node, key):
    out = []
    for item in node.get(key) or []:
        if item in (None, ""):
            continue
        out.append(item)
    return out


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
    # FnsPortSetValidator._generate_port_set_id
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
                "vpc_reference", "scope_vpc_uuid"):
        for item in values(policy, key):
            if item and item not in out:
                out.append(str(item))
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


def component_refs(comp):
    """Return (entity_type, refs, skip_reason) for one proto component."""
    allow = str(first(comp, "allow_type") or "")
    if allow in SKIP_ALLOW:
        return None, [], "allow_type=%s" % allow
    if values(comp, "address_group_uuid"):
        return None, [], "address_group"
    if values(comp, "ip_subnet") or values(comp, "addresses"):
        return None, [], "ip_subnet"
    egs = as_uuid_list(values(comp, "entity_group_uuid_list"))
    if egs:
        return None, egs, ""
    cats = as_uuid_list(values(comp, "category_uuid_list"))
    if cats:
        if any(item in ("all", "any") for item in cats):
            return None, [], "wildcard category"
        sel = CAT_TYPE.get(str(first(comp, "category_selection_type") or "kVM"), "VM")
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
    return None, [], "no entity refs"


def annotate_component(comp, unique_uuid, project_uuid, is_flex, include_project):
    entity_type, refs, skip = component_refs(comp)
    row = {
        "role": comp.get("_key"),
        "line_start": (comp.get("_start") or 0) + 1,
        "line_end": (comp.get("_end") or 0) + 1,
        "entity_type": entity_type,
        "refs": refs,
        "skip_reason": skip or None,
        "hash_body": "",
        "port_set_uuid": "",
    }
    if skip or not refs or not unique_uuid:
        if not skip and not unique_uuid:
            row["skip_reason"] = "no scope unique uuid"
        return row
    project = project_uuid if include_project else None
    hashed, body = generate_port_set_id(
        entity_type, refs, unique_uuid, project, is_flex=is_flex)
    row["hash_body"] = body
    row["port_set_uuid"] = hashed
    return row


def walk_components(node, sink):
    if not isinstance(node, dict):
        return
    if node.get("_key") in COMPONENT_KEYS:
        sink.append(node)
    for key, items in node.items():
        if key.startswith("_"):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                walk_components(item, sink)


def rule_is_flex(rule, policy_type):
    if rule.get("_key") == "flex_policy_rule":
        return True
    return str(policy_type or "") in ("kFlex", "FLEX")


def annotate_policy(policy, vlan_uuid, global_uuid, include_project):
    name = first(policy, "name")
    policy_uuid = first(policy, "uuid")
    scope = first(policy, "scope") or "kAllVlan"
    mode = first(policy, "mode")
    policy_type = first(policy, "policy_type")
    project = first(policy, "project_uuid") or ZERO
    vpc_uuids = policy_vpc_uuids(policy)
    rules_out = []
    insertions = []
    for rules_list in values(policy, "rules_list"):
        if not isinstance(rules_list, dict):
            continue
        for rkey in RULE_KEYS:
            for rule in values(rules_list, rkey):
                if not isinstance(rule, dict):
                    continue
                is_flex = rule_is_flex(rule, policy_type)
                unique = scope_unique_uuid(
                    scope, is_flex, vlan_uuid, global_uuid, vpc_uuids)
                info = first(rule, "rule_info") or {}
                rule_uuid = first(info, "uuid") if isinstance(info, dict) else ""
                desc = first(info, "description") if isinstance(info, dict) else ""
                comps = []
                walk_components(rule, comps)
                seen = set()
                unique_comps = []
                for comp in comps:
                    marker = (comp.get("_start"), comp.get("_end"))
                    if marker in seen:
                        continue
                    seen.add(marker)
                    unique_comps.append(comp)
                component_rows = []
                for comp in unique_comps:
                    row = annotate_component(
                        comp, unique, project, is_flex, include_project)
                    component_rows.append(row)
                    if row["port_set_uuid"] and comp.get("_end") is not None:
                        insertions.append({
                            "end": comp["_end"],
                            "indent": (comp.get("_indent") or 0) + 2,
                            "uuid": row["port_set_uuid"],
                        })
                rules_out.append({
                    "rule_kind": rule.get("_key"),
                    "rule_uuid": rule_uuid,
                    "description": desc,
                    "direction": first(rule, "direction"),
                    "is_flex": is_flex,
                    "unique_uuid": unique,
                    "components": component_rows,
                })
    return {
        "name": name,
        "uuid": policy_uuid,
        "scope": scope,
        "mode": mode,
        "policy_type": policy_type,
        "project_uuid": project,
        "skipped_save": str(mode) in ("kSave", "SAVE"),
        "rules": [] if str(mode) in ("kSave", "SAVE") else rules_out,
    }, ([] if str(mode) in ("kSave", "SAVE") else insertions)


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
    skipped = 0
    rules = 0
    for policy in policies_out:
        rules += len(policy.get("rules") or [])
        for rule in policy.get("rules") or []:
            for comp in rule.get("components") or []:
                if comp.get("port_set_uuid"):
                    hashed += 1
                else:
                    skipped += 1
    return {
        "policies": len(policies_out),
        "rules": rules,
        "components_hashed": hashed,
        "components_skipped": skipped,
    }


def load_unique_uuids(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle) or {}
    if not isinstance(data, dict):
        return "", ""
    return (
        str(data.get("global_unique_uuid") or "").strip(),
        str(data.get("vlan_unique_uuid") or "").strip(),
    )


def resolve_inputs(args):
    dump_dir = args.dump_dir or ""
    policy = args.policy or ""
    if not policy and dump_dir:
        for name in ("policy_list.json", "policy_list.pbtxt"):
            cand = os.path.join(dump_dir, name)
            if os.path.isfile(cand):
                policy = cand
                break
    if not policy and os.path.isfile("policy_list.json"):
        policy = os.path.abspath("policy_list.json")
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
    if not policy:
        raise SystemExit("need --policy or --dump_dir with policy_list.json")
    if not global_uuid or not vlan_uuid:
        raise SystemExit(
            "need --global-uuid and --vlan-uuid, or unique_uuids.json")
    return policy, global_uuid, vlan_uuid


def run_annotate(policy_path, global_uuid, vlan_uuid, include_project,
                 out_path, json_path, in_place):
    with open(policy_path, encoding="utf-8") as handle:
        text = handle.read()
    policies, lines = parse_policies(text)
    if not policies:
        raise SystemExit("no network_security_policy messages in %s" % policy_path)
    policies_out = []
    insertions = []
    for policy in policies:
        annotated, extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project)
        policies_out.append(annotated)
        insertions.extend(extra)
    stats = summarize(policies_out)
    payload = {
        "global_unique_uuid": global_uuid,
        "vlan_unique_uuid": vlan_uuid,
        "include_project": bool(include_project),
        "hash": "uuid5(scope, str(sorted(refs)) with u-prefix); "
                "FLEX MD5(salus+scope+[refs])",
        "stats": stats,
        "policies": policies_out,
    }
    json_path = json_path or (policy_path + ".port_sets.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    annotated_lines = apply_insertions(lines, insertions)
    proto_path = policy_path if in_place else (
        out_path or (policy_path + ".port_sets.pbtxt"))
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
    tmp = tempfile.mkdtemp(prefix="port_set_self_test_")
    policy_path = os.path.join(tmp, "policy_list.json")
    uuid_path = os.path.join(tmp, "unique_uuids.json")
    with open(policy_path, "w", encoding="utf-8") as handle:
        handle.write(proto)
    with open(uuid_path, "w", encoding="utf-8") as handle:
        json.dump({
            "global_unique_uuid": global_uuid,
            "vlan_unique_uuid": vlan_uuid,
        }, handle)
    stats, json_path, proto_path = run_annotate(
        policy_path, global_uuid, vlan_uuid, False, "", "", False)
    if stats["components_hashed"] != 2:
        raise SystemExit("expected 2 hashed components, got %s" % stats)
    with open(proto_path, encoding="utf-8") as handle:
        annotated = handle.read()
    if 'port_set_uuid: "%s"' % expect not in annotated:
        raise SystemExit("annotated proto missing port_set_uuid")
    loaded_g, loaded_v = load_unique_uuids(uuid_path)
    if (loaded_g, loaded_v) != (global_uuid, vlan_uuid):
        raise SystemExit("unique_uuids.json load failed")
    print("self-test ok hash=%s hashed=%s proto=%s json=%s" % (
        expect, stats["components_hashed"], proto_path, json_path))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Write Atlas port-set UUIDs onto rule components")
    parser.add_argument("--policy", default="",
                        help="Proto-text network_security_policy dump")
    parser.add_argument("--dump_dir", default="",
                        help="Dump dir with policy_list.json and unique_uuids.json")
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
        help="JSON map of policy/rule/component -> port_set_uuid")
    parser.add_argument(
        "--include-project", action="store_true",
        help="Append :project:<uuid> like ingest.py (validator does not)")
    parser.add_argument(
        "--in-place", action="store_true",
        help="Overwrite --policy with annotated proto-text")
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run a stdlib-only hash + annotate check and exit")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.self_test:
        self_test()
        return
    policy, global_uuid, vlan_uuid = resolve_inputs(args)
    stats, json_path, proto_path = run_annotate(
        policy, global_uuid, vlan_uuid, args.include_project,
        args.out, args.json_out, args.in_place)
    print("policies=%s rules=%s hashed=%s skipped=%s" % (
        stats["policies"], stats["rules"],
        stats["components_hashed"], stats["components_skipped"]))
    print("json=%s" % os.path.abspath(json_path))
    print("proto=%s" % os.path.abspath(proto_path))


if __name__ == "__main__":
    main()
