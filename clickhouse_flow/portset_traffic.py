#!/usr/bin/env python3
"""Traffic allowed into and out of each port-set, from OVN ACLs.

Same split as policy_port_set/ovn_port_set_traffic.sh:

- outport == @port_group_<uuid>  -> traffic allowed into the port-set
  (peer is ip4/ip6.src)
- inport  == @port_group_<uuid>  -> traffic allowed out of the port-set
  (peer is ip4/ip6.dst)

Only allow, allow-related, and allow-stateless are stored. Address-set
names are replaced with Address_Set.addresses when the NB dump is present.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
ALLOW_ACTIONS = frozenset(("allow", "allow-related", "allow-stateless"))
NB_REL = ("cmsp_ovn", "anc-ovn", "commands", "ovsdb-client_dump_nb.txt")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PG_RE = re.compile(
    r"(inport|outport)\s*==\s*@(port_group_[0-9a-fA-F_]+)")
RANGE_RE = re.compile(
    r"(tcp|udp)\.(dst|src)\s*>=\s*(\d+)\s*&&\s*(tcp|udp)\.(dst|src)\s*<=\s*(\d+)")
EQ_RE = re.compile(r"(tcp|udp)\.(dst|src)\s*==\s*(\d+)")
ICMP_RE = re.compile(r"(icmp4|icmp6)\.type\s*==\s*(\d+)")
SRC_RE = re.compile(
    r"ip[46]\.src\s*==\s*(\$address_set_[0-9a-fA-F_]+|[0-9a-fA-F:.]+(?:/\d+)?)")
DST_RE = re.compile(
    r"ip[46]\.dst\s*==\s*(\$address_set_[0-9a-fA-F_]+|[0-9a-fA-F:.]+(?:/\d+)?)")

ENSURE_SQL = """
ALTER TABLE flow_policy.portset
    ADD COLUMN IF NOT EXISTS traffic_in Array(Tuple(
        priority Int32,
        action LowCardinality(String),
        peers Array(String),
        ports Array(String)
    )) DEFAULT [];
ALTER TABLE flow_policy.portset
    ADD COLUMN IF NOT EXISTS traffic_out Array(Tuple(
        priority Int32,
        action LowCardinality(String),
        peers Array(String),
        ports Array(String)
    )) DEFAULT [];
"""


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


def ensure_traffic_columns(run_sql=None):
    """Add the columns on a table created before this schema change."""
    if run_sql is None:
        cmd = [
            "clickhouse-client",
            "--host", CH_HOST,
            "--port", CH_NATIVE,
            "--user", "default",
            "--multiquery",
            "--query", ENSURE_SQL,
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "ch failed")
        return
    run_sql("--multiquery", input_text=ENSURE_SQL)


def _unique(values):
    out = []
    seen = set()
    for value in values or []:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def port_group_uuid(token):
    body = token[len("port_group_"):] if token.startswith("port_group_") else token
    parts = body.split("_")
    if [len(part) for part in parts] != [8, 4, 4, 4, 12]:
        return ""
    uid = "-".join(parts).lower()
    if not UUID_RE.match(uid):
        return ""
    return uid


def l4_ports(match):
    ports = []
    covered = []
    for found in RANGE_RE.finditer(match or ""):
        if found.group(1) != found.group(4) or found.group(2) != found.group(5):
            continue
        ports.append("%s.%s %s-%s" % (
            found.group(1), found.group(2), found.group(3), found.group(6)))
        covered.append((found.start(), found.end()))
    for found in EQ_RE.finditer(match or ""):
        if any(start <= found.start() < end for start, end in covered):
            continue
        ports.append("%s.%s %s" % (found.group(1), found.group(2), found.group(3)))
    for found in ICMP_RE.finditer(match or ""):
        ports.append("%s.type %s" % (found.group(1), found.group(2)))
    return _unique(ports) or ["ALL"]


def _resolve(token, address_sets):
    if token.startswith("$"):
        name = token[1:]
        ips = address_sets.get(name) or address_sets.get(token) or []
        return list(ips) if ips else [token]
    return [token]


def peers_for(match, side, address_sets):
    pattern = SRC_RE if side == "src" else DST_RE
    found = []
    for item in pattern.findall(match or ""):
        found.extend(_resolve(item, address_sets))
    return _unique(found) or ["ANY"]


def traffic_by_portset(acls, address_sets=None):
    """port_set_uuid -> {traffic_in, traffic_out}."""
    address_sets = address_sets or {}
    by = {}
    for acl in acls or []:
        action = str(acl.get("action") or "").strip().lower()
        if action not in ALLOW_ACTIONS:
            continue
        match = str(acl.get("match") or "")
        try:
            priority = int(acl.get("priority") or 0)
        except (TypeError, ValueError):
            priority = 0
        ports = l4_ports(match)
        for direction, token in PG_RE.findall(match):
            uid = port_group_uuid(token)
            if not uid:
                continue
            side = "src" if direction == "outport" else "dst"
            key = "traffic_in" if direction == "outport" else "traffic_out"
            bucket = by.setdefault(uid, {"traffic_in": [], "traffic_out": []})
            bucket[key].append({
                "priority": priority,
                "action": action,
                "peers": peers_for(match, side, address_sets),
                "ports": ports,
            })
    for rec in by.values():
        for key in ("traffic_in", "traffic_out"):
            seen = set()
            kept = []
            for row in sorted(rec[key], key=lambda item: (-item["priority"], item["action"])):
                marker = (
                    row["priority"], row["action"],
                    tuple(row["peers"]), tuple(row["ports"]))
                if marker in seen:
                    continue
                seen.add(marker)
                kept.append(row)
            rec[key] = kept
    return by


def nb_under(dump_dir):
    if not dump_dir:
        return ""
    path = os.path.join(dump_dir, *NB_REL)
    return path if os.path.isfile(path) else ""


def _parse_nb(nb_path):
    ovn_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "clickhouse_ovn", "ingest.py")
    spec = importlib.util.spec_from_file_location("ovn_nb_parse", ovn_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tables = mod.parse_dump(nb_path, ["ACL", "Address_Set"])
    acls = []
    for row in tables.get("ACL") or []:
        acls.append({
            "action": row.get("action"),
            "match": row.get("match"),
            "priority": row.get("priority"),
        })
    address_sets = {}
    for row in tables.get("Address_Set") or []:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        raw = row.get("addresses") or []
        if isinstance(raw, str):
            raw = [raw]
        address_sets[name] = _unique(raw)
    return acls, address_sets


def _acls_from_clickhouse(log_bundle_id):
    bid = int(log_bundle_id or 0)
    if bid <= 0:
        return []
    try:
        text = ch_query(
            "SELECT action, match, priority FROM flow_ovn.ovn_acl FINAL "
            "WHERE log_bundle_id = %d FORMAT JSONEachRow" % bid)
    except RuntimeError:
        return []
    rows = []
    for line in text.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _bundle_dump_dir(log_bundle_id):
    bid = int(log_bundle_id or 0)
    queries = []
    if bid > 0:
        queries.append(
            "SELECT dump_dir FROM flow_ovn.bundle FINAL "
            "WHERE log_bundle_id = %d LIMIT 1" % bid)
    queries.append(
        "SELECT dump_dir FROM flow_ovn.bundle FINAL "
        "ORDER BY updated_at DESC LIMIT 1")
    for sql in queries:
        try:
            text = (ch_query(sql) or "").strip()
        except RuntimeError:
            continue
        if text:
            return text.splitlines()[0].strip()
    return ""


def load_acl_sources(dump_dir="", nb_path="", log_bundle_id=0):
    path = nb_path or nb_under(dump_dir)
    if not path:
        path = nb_under(_bundle_dump_dir(log_bundle_id))
    if path:
        return _parse_nb(path)
    return _acls_from_clickhouse(log_bundle_id), {}


def attach_portset_traffic(rows, dump_dir="", nb_path="", log_bundle_id=0):
    """Fill traffic_in / traffic_out on each port-set row. Returns (in, out) counts."""
    acls, address_sets = load_acl_sources(dump_dir, nb_path, log_bundle_id)
    by = traffic_by_portset(acls, address_sets)
    n_in = 0
    n_out = 0
    for row in rows or []:
        uid = str(row.get("port_set_uuid") or "").strip().lower()
        rec = by.get(uid) or {}
        row["traffic_in"] = list(rec.get("traffic_in") or [])
        row["traffic_out"] = list(rec.get("traffic_out") or [])
        n_in += len(row["traffic_in"])
        n_out += len(row["traffic_out"])
    return n_in, n_out


def _self_test():
    match = (
        "ip4 && (ip4.src == $address_set_49d3b015_7bac_5a2a_8d9a_5c033243ba71) && "
        "((ip.proto == 6 && (tcp.dst == 22 || tcp.dst == 80)) || "
        "(ip.proto == 17 && (udp.dst == 22)) || "
        "(ip.proto == 1 && (icmp4.type == 8))) && "
        "outport == @port_group_13333d69_bd6f_5531_bd50_524687c27814"
    )
    addrs = {
        "address_set_49d3b015_7bac_5a2a_8d9a_5c033243ba71": [
            "192.168.1.10/32", "192.168.1.11/32"],
    }
    acls = [
        {"action": "allow-related", "priority": 125362, "match": match},
        {"action": "drop", "priority": 1060, "match": match},
        {
            "action": "allow",
            "priority": 100,
            "match": (
                "inport == @port_group_13333d69_bd6f_5531_bd50_524687c27814 "
                "&& ip4.dst == 10.0.0.0/8"),
        },
    ]
    by = traffic_by_portset(acls, addrs)
    uid = "13333d69-bd6f-5531-bd50-524687c27814"
    rec = by[uid]
    if len(rec["traffic_in"]) != 1:
        raise SystemExit("expected 1 inbound allow, got %s" % rec["traffic_in"])
    inbound = rec["traffic_in"][0]
    if inbound["peers"] != ["192.168.1.10/32", "192.168.1.11/32"]:
        raise SystemExit("peers %s" % inbound["peers"])
    if inbound["ports"] != ["tcp.dst 22", "tcp.dst 80", "udp.dst 22", "icmp4.type 8"]:
        raise SystemExit("ports %s" % inbound["ports"])
    if len(rec["traffic_out"]) != 1 or rec["traffic_out"][0]["peers"] != ["10.0.0.0/8"]:
        raise SystemExit("outbound %s" % rec["traffic_out"])
    if rec["traffic_out"][0]["ports"] != ["ALL"]:
        raise SystemExit("outbound ports %s" % rec["traffic_out"])
    rows = [{"port_set_uuid": uid}]
    # No dump and no ClickHouse in this check: call the pure function only.
    del rows
    print("portset_traffic self-test ok")


if __name__ == "__main__":
    _self_test()
