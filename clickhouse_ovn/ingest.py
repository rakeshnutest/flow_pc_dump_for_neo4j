#!/usr/bin/env python3
"""Ingest ovsdb-client dump (NB+SB) + AHV dumpxml into flow_ovn.

stdlib + clickhouse-client only. Does not touch flow_policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

CH_HOST = "127.0.0.1"
CH_PORT = "19000"
CH_USER = "default"
BATCH = 10_000
ZERO = "00000000-0000-0000-0000-000000000000"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
MAC_RE = re.compile(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F:]{2,}:[0-9a-fA-F:.]{2,})(?:/\d{1,3})?\b")
TABLE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*) table\s*$")
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
OVN_TABLES = (
    "bundle",
    "ovn_ls",
    "ovn_lsp",
    "ovn_lr",
    "ovn_lrp",
    "ovn_acl",
    "ovn_acl_on_ls",
    "ovn_pg",
    "ovn_acl_on_pg",
    "ovn_pg_port",
    "ovn_pbr",
    "ovn_nat",
    "ovn_vm",
    "ovn_vm_nic",
    "ovn_chassis",
    "ovn_encap",
    "ovn_datapath",
    "ovn_port_binding",
    "ovn_mac_binding",
    "ovn_ha_chassis",
    "ovn_edge_ls_lr",
    "ovn_edge_lr_lr",
    "ovn_ls_stretch",
)
RESET_SCHEMA_SQL = (
    "CREATE DATABASE IF NOT EXISTS flow_ovn;\n"
    + "\n".join(f"DROP TABLE IF EXISTS flow_ovn.{t};" for t in reversed(OVN_TABLES))
    + "\n"
)
LOG_BUNDLE_ID = 0

NB_TABLES = {
    "ACL",
    "Logical_Switch",
    "Logical_Switch_Port",
    "Logical_Router",
    "Logical_Router_Port",
    "Logical_Router_Policy",
    "NAT",
    "Port_Group",
    "HA_Chassis_Group",
    "HA_Chassis",
}
SB_TABLES = {
    "Chassis",
    "Encap",
    "Datapath_Binding",
    "Port_Binding",
    "MAC_Binding",
    "HA_Chassis_Group",
    "HA_Chassis",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def is_uuid(s: str) -> bool:
    return bool(s) and bool(UUID_RE.match(s))


def as_uuid(val: Any) -> str:
    if val is None:
        return ZERO
    if isinstance(val, list):
        if not val:
            return ZERO
        val = val[0]
    s = str(val).strip().strip('"')
    return s if is_uuid(s) else ZERO


def as_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return "" if not val else as_str(val[0])
    if isinstance(val, dict):
        return ""
    s = str(val)
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


def as_str_list(val: Any) -> List[str]:
    if val is None or val == [] or val == {}:
        return []
    if isinstance(val, list):
        out = []
        for x in val:
            s = as_str(x)
            if s:
                out.append(s)
        return out
    s = as_str(val)
    return [s] if s else []


def as_map(val: Any) -> Dict[str, str]:
    if isinstance(val, dict):
        return {str(k): as_str(v) for k, v in val.items()}
    return {}


def as_int(val: Any, default: int = 0) -> int:
    if val is None or val == [] or val == {}:
        return default
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, int):
        return val
    s = as_str(val)
    try:
        return int(s)
    except ValueError:
        return default


def as_bool(val: Any, default: int = 0) -> int:
    if val is None or val == [] or val == {}:
        return default
    if isinstance(val, bool):
        return 1 if val else 0
    if isinstance(val, int):
        return 1 if val else 0
    s = as_str(val).lower()
    if s in ("true", "1", "yes"):
        return 1
    if s in ("false", "0", "no"):
        return 0
    return default


def local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# --- ovsdb-client dump parser -------------------------------------------------

def _parse_quoted(s: str, i: int) -> Tuple[str, int]:
    i += 1
    out: List[str] = []
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return "".join(out), i


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\n":
        i += 1
    return i


def _parse_value(s: str, i: int) -> Tuple[Any, int]:
    i = _skip_ws(s, i)
    if i >= len(s):
        return "", i
    c = s[i]
    if c == '"':
        return _parse_quoted(s, i)
    if c == "[":
        return _parse_list(s, i)
    if c == "{":
        return _parse_map(s, i)
    j = i
    while j < len(s) and s[j] not in ",]} \t":
        j += 1
    tok = s[i:j]
    if tok == "true":
        return True, j
    if tok == "false":
        return False, j
    if tok == "[]":
        return [], j
    if tok == "{}":
        return {}, j
    try:
        if tok and (tok[0].isdigit() or (tok[0] == "-" and len(tok) > 1)):
            return int(tok), j
    except ValueError:
        pass
    return tok, j


def _parse_list(s: str, i: int) -> Tuple[List[Any], int]:
    i += 1
    items: List[Any] = []
    i = _skip_ws(s, i)
    if i < len(s) and s[i] == "]":
        return items, i + 1
    while i < len(s):
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == "]":
            return items, i + 1
        val, i = _parse_value(s, i)
        items.append(val)
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        if i < len(s) and s[i] == "]":
            return items, i + 1
        break
    return items, i


def _parse_map(s: str, i: int) -> Tuple[Dict[str, Any], int]:
    i += 1
    out: Dict[str, Any] = {}
    i = _skip_ws(s, i)
    if i < len(s) and s[i] == "}":
        return out, i + 1
    while i < len(s):
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == "}":
            return out, i + 1
        if s[i] == '"':
            key, i = _parse_quoted(s, i)
        else:
            j = i
            while j < len(s) and s[j] not in "=} \t":
                j += 1
            key = s[i:j]
            i = j
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == "=":
            i += 1
        val, i = _parse_value(s, i)
        out[key] = val
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        if i < len(s) and s[i] == "}":
            return out, i + 1
        break
    return out, i


def parse_cell(cell: str) -> Any:
    cell = cell.strip()
    if cell == "" or cell == "[]":
        return []
    if cell == "{}":
        return {}
    val, _ = _parse_value(cell, 0)
    return val


def dash_starts(dash: str) -> List[int]:
    starts: List[int] = []
    i = 0
    n = len(dash)
    while i < n:
        if dash[i] == "-":
            starts.append(i)
            while i < n and dash[i] == "-":
                i += 1
        else:
            i += 1
    return starts


def slice_row(line: str, starts: List[int]) -> List[str]:
    cells = []
    for i, st in enumerate(starts):
        en = starts[i + 1] if i + 1 < len(starts) else len(line)
        cells.append(line[st:en].rstrip())
    return cells


def parse_dump(path: str, wanted: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    wanted_set = set(wanted)
    tables: Dict[str, List[Dict[str, Any]]] = {t: [] for t in wanted_set}
    current: Optional[str] = None
    keep = False
    state = "seek"
    cols: List[str] = []
    starts: List[int] = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            s = line.rstrip("\n")
            m = TABLE_RE.match(s)
            if m:
                current = m.group(1)
                keep = current in wanted_set
                state = "header" if keep else "skip"
                cols = []
                starts = []
                continue
            if not keep:
                continue
            if state == "header":
                if not s.strip():
                    continue
                cols = s.split()
                state = "dash"
                continue
            if state == "dash":
                starts = dash_starts(s)
                if len(starts) != len(cols):
                    # fall back to header names only; skip malformed
                    if len(starts) > 0:
                        cols = cols[: len(starts)]
                    else:
                        keep = False
                        state = "skip"
                        continue
                state = "rows"
                continue
            if not s.strip():
                continue
            cells = slice_row(s, starts)
            row: Dict[str, Any] = {}
            for name, cell in zip(cols, cells):
                row[name] = parse_cell(cell)
            if current is not None:
                tables[current].append(row)
    return tables


def parse_mac_ips(addresses: List[str], dynamic: str) -> Tuple[str, List[str], List[str]]:
    blobs = list(addresses)
    if dynamic:
        blobs.append(dynamic)
    mac = ""
    ip4: List[str] = []
    ip6: List[str] = []
    for blob in blobs:
        m = MAC_RE.search(blob)
        if m and not mac:
            mac = m.group(1).lower()
        for x in IPV4_RE.findall(blob):
            if x not in ip4:
                ip4.append(x)
        for x in IPV6_RE.findall(blob):
            if x.lower() not in ("unknown",) and ":" in x and x not in ip6:
                ip6.append(x)
    return mac, ip4, ip6


def nic_uuid_from_name(name: str) -> str:
    if name.startswith("port_"):
        rest = name[5:]
        if is_uuid(rest):
            return rest
    if is_uuid(name):
        return name
    return ZERO


# --- ClickHouse ---------------------------------------------------------------

def ch_run(args: List[str], input_text: Optional[str] = None) -> str:
    cmd = [
        "clickhouse-client",
        "--host",
        CH_HOST,
        "--port",
        CH_PORT,
        "--user",
        CH_USER,
        "--date_time_input_format=best_effort",
    ] + args
    proc = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "clickhouse-client failed").strip()
        raise RuntimeError(err)
    return proc.stdout


def apply_schema() -> None:
    with open(SCHEMA, "r") as fh:
        sql = fh.read()
    ch_run(["--multiquery", "--query", sql])


def resolve_log_bundle_id(explicit: int, dump_dir: str = "") -> int:
    """Panacea log_bundle_id. Flag, env, meta.json, else stable hash of dump_dir."""
    if explicit and int(explicit) > 0:
        return int(explicit)
    env = os.environ.get("PANACEA_LOG_BUNDLE_ID") or os.environ.get("LOG_BUNDLE_ID")
    if env:
        return int(env)
    meta_path = os.path.join(dump_dir, "meta.json") if dump_dir else ""
    if meta_path and os.path.isfile(meta_path):
        with open(meta_path) as fh:
            meta = json.load(fh) or {}
        for key in ("log_bundle_id", "id", "bundle_id"):
            val = meta.get(key)
            if val not in (None, "", 0, "0"):
                return int(val)
    if dump_dir:
        digest = hashlib.sha256(os.path.abspath(dump_dir).encode()).digest()
        return int.from_bytes(digest[:8], "big")
    raise SystemExit("need --log_bundle_id")


def has_bundle_column(table: str) -> bool:
    out = ch_run(
        [
            "--query",
            "SELECT count() FROM system.columns "
            "WHERE database = 'flow_ovn' AND table = '{t}' "
            "AND name = 'log_bundle_id'".format(t=table),
        ]
    )
    try:
        return int((out or "0").strip().splitlines()[-1]) > 0
    except ValueError:
        return False


def drop_bundle_partitions(bundle_id: int) -> None:
    """DROP PARTITION is instant (insert-mutation-avoid-delete). Other bundles stay."""
    bid = int(bundle_id)
    for table in OVN_TABLES:
        q = f"ALTER TABLE flow_ovn.{table} DROP PARTITION {bid}"
        try:
            ch_run(["--query", q])
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
        print(f"  dropped partition {bid} {table}")


def insert_rows(table: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print(f"  {table}: 0 rows")
        return
    bid = int(LOG_BUNDLE_ID)
    n = 0
    for i in range(0, len(rows), BATCH):
        chunk = rows[i : i + BATCH]
        for row in chunk:
            row["log_bundle_id"] = bid
        payload = "\n".join(json.dumps(r, separators=(",", ":")) for r in chunk)
        ch_run(
            ["--query", f"INSERT INTO flow_ovn.{table} FORMAT JSONEachRow"],
            input_text=payload,
        )
        n += len(chunk)
    print(f"  {table}: {n} rows")


# --- Transform ----------------------------------------------------------------

def t_ls(rows: List[Dict[str, Any]]) -> Tuple[List[dict], List[dict], Dict[str, str]]:
    out = []
    acl_edges = []
    lsp_to_ls: Dict[str, str] = {}
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        out.append({"ls_uuid": uid, "name": as_str(r.get("name")), "updated_at": ts})
        for a in as_str_list(r.get("acls")):
            if is_uuid(a):
                acl_edges.append({"ls_uuid": uid, "acl_uuid": a, "updated_at": ts})
        for p in as_str_list(r.get("ports")):
            if is_uuid(p):
                lsp_to_ls[p] = uid
    return out, acl_edges, lsp_to_ls


def t_lsp(rows: List[Dict[str, Any]], lsp_to_ls: Dict[str, str]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        opts = as_map(r.get("options"))
        addrs = as_str_list(r.get("addresses"))
        dyn = as_str(r.get("dynamic_addresses"))
        mac, ip4, ip6 = parse_mac_ips(addrs, dyn)
        ptype = as_str(r.get("type"))
        name = as_str(r.get("name"))
        out.append(
            {
                "lsp_uuid": uid,
                "ls_uuid": lsp_to_ls.get(uid, ZERO),
                "name": name,
                "type": ptype,
                "mac": mac,
                "ip4": ip4,
                "ip6": ip6,
                "addresses": addrs,
                "dynamic_addresses": dyn,
                "enabled": as_bool(r.get("enabled"), 1),
                "up": as_bool(r.get("up"), 0),
                "parent_name": as_str(r.get("parent_name")),
                "tag": as_int(r.get("tag"), 0),
                "options_router_port": opts.get("router-port", "") or opts.get("router_port", ""),
                "options_network_name": opts.get("network_name", "") or opts.get("network-name", ""),
                "peer": as_str(r.get("peer")),
                "nic_uuid": nic_uuid_from_name(name),
                "updated_at": ts,
            }
        )
    return out


def t_lr(rows: List[Dict[str, Any]]) -> Tuple[List[dict], Dict[str, str], Dict[str, List[str]]]:
    out = []
    lrp_to_lr: Dict[str, str] = {}
    lr_nats: Dict[str, List[str]] = {}
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        nats = [x for x in as_str_list(r.get("nat")) if is_uuid(x)]
        out.append(
            {
                "lr_uuid": uid,
                "name": as_str(r.get("name")),
                "enabled": as_bool(r.get("enabled"), 1),
                "has_nat": 1 if nats else 0,
                "updated_at": ts,
            }
        )
        lr_nats[uid] = nats
        for p in as_str_list(r.get("ports")):
            if is_uuid(p):
                lrp_to_lr[p] = uid
    return out, lrp_to_lr, lr_nats


def t_lrp(rows: List[Dict[str, Any]], lrp_to_lr: Dict[str, str]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        name = as_str(r.get("name"))
        is_ext = 1 if ("ext_gw" in name or name.endswith("_ext") or "localnet" in name) else 0
        out.append(
            {
                "lrp_uuid": uid,
                "lr_uuid": lrp_to_lr.get(uid, ZERO),
                "name": name,
                "mac": as_str(r.get("mac")).lower().strip('"'),
                "networks": as_str_list(r.get("networks")),
                "peer": as_str(r.get("peer")),
                "ha_chassis_group": as_uuid(r.get("ha_chassis_group")),
                "is_ext_gw": is_ext,
                "updated_at": ts,
            }
        )
    return out


def t_acl(rows: List[Dict[str, Any]]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        out.append(
            {
                "acl_uuid": as_uuid(r.get("_uuid")),
                "name": as_str(r.get("name")),
                "direction": as_str(r.get("direction")),
                "action": as_str(r.get("action")),
                "match": as_str(r.get("match")),
                "priority": as_int(r.get("priority"), 0),
                "log": as_bool(r.get("log"), 0),
                "updated_at": ts,
            }
        )
    return out


def t_pg(rows: List[Dict[str, Any]]) -> Tuple[List[dict], List[dict], List[dict]]:
    pgs, acl_e, port_e = [], [], []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        pgs.append({"pg_uuid": uid, "name": as_str(r.get("name")), "updated_at": ts})
        for a in as_str_list(r.get("acls")):
            if is_uuid(a):
                acl_e.append({"pg_uuid": uid, "acl_uuid": a, "updated_at": ts})
        for p in as_str_list(r.get("ports")):
            if is_uuid(p):
                port_e.append({"pg_uuid": uid, "lsp_uuid": p, "updated_at": ts})
    return pgs, acl_e, port_e


def t_pbr(rows: List[Dict[str, Any]], lr_policies: Dict[str, str]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        out.append(
            {
                "pbr_uuid": uid,
                "lr_uuid": lr_policies.get(uid, ZERO),
                "match": as_str(r.get("match")),
                "action": as_str(r.get("action")),
                "nexthop": as_str(r.get("nexthop")),
                "nexthops": as_str_list(r.get("nexthops")),
                "priority": as_int(r.get("priority"), 0),
                "updated_at": ts,
            }
        )
    return out


def lr_policy_index(lr_rows: List[Dict[str, Any]]) -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for r in lr_rows:
        uid = as_uuid(r.get("_uuid"))
        for p in as_str_list(r.get("policies")):
            if is_uuid(p):
                idx[p] = uid
    return idx


def t_nat(rows: List[Dict[str, Any]], lr_nats: Dict[str, List[str]]) -> List[dict]:
    nat_to_lr: Dict[str, str] = {}
    for lr, nats in lr_nats.items():
        for n in nats:
            nat_to_lr[n] = lr
    out = []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        out.append(
            {
                "nat_uuid": uid,
                "lr_uuid": nat_to_lr.get(uid, ZERO),
                "type": as_str(r.get("type")),
                "external_ip": as_str(r.get("external_ip")),
                "logical_ip": as_str(r.get("logical_ip")),
                "logical_port": as_str(r.get("logical_port")),
                "external_mac": as_str(r.get("external_mac")),
                "updated_at": ts,
            }
        )
    return out


def t_ha(nb_g: List[dict], nb_h: List[dict]) -> List[dict]:
    # HA_Chassis_Group.ha_chassis -> HA_Chassis._uuid; chassis_name on HA_Chassis
    ch_by_uuid = {as_uuid(r.get("_uuid")): r for r in nb_h}
    out = []
    ts = now_iso()
    for g in nb_g:
        gid = as_uuid(g.get("_uuid"))
        gname = as_str(g.get("name"))
        members = as_str_list(g.get("ha_chassis"))
        if not members:
            out.append(
                {
                    "group_uuid": gid,
                    "group_name": gname,
                    "chassis_name": "",
                    "priority": 0,
                    "updated_at": ts,
                }
            )
            continue
        for mid in members:
            h = ch_by_uuid.get(mid, {})
            out.append(
                {
                    "group_uuid": gid,
                    "group_name": gname,
                    "chassis_name": as_str(h.get("chassis_name")),
                    "priority": as_int(h.get("priority"), 0),
                    "updated_at": ts,
                }
            )
    return out


def t_chassis(rows: List[Dict[str, Any]]) -> Tuple[List[dict], Dict[str, str]]:
    out = []
    encap_to_ch: Dict[str, str] = {}
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        out.append(
            {
                "chassis_uuid": uid,
                "name": as_str(r.get("name")),
                "hostname": as_str(r.get("hostname")),
                "updated_at": ts,
            }
        )
        for e in as_str_list(r.get("encaps")):
            if is_uuid(e):
                encap_to_ch[e] = uid
    return out, encap_to_ch


def t_encap(rows: List[Dict[str, Any]], encap_to_ch: Dict[str, str]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        uid = as_uuid(r.get("_uuid"))
        out.append(
            {
                "encap_uuid": uid,
                "chassis_uuid": encap_to_ch.get(uid, ZERO),
                "chassis_name": as_str(r.get("chassis_name")),
                "ip": as_str(r.get("ip")),
                "encap_type": as_str(r.get("type")),
                "updated_at": ts,
            }
        )
    return out


def t_datapath(rows: List[Dict[str, Any]]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        ext = as_map(r.get("external_ids"))
        ls = ext.get("logical-switch", "") or ext.get("logical_switch", "")
        lr = ext.get("logical-router", "") or ext.get("logical_router", "")
        if is_uuid(str(ls)):
            kind, nb, name = "ls", str(ls), ext.get("name", "")
        elif is_uuid(str(lr)):
            kind, nb, name = "lr", str(lr), ext.get("name", "")
        else:
            kind, nb, name = "", ZERO, ext.get("name", "") or ext.get("interconn-ts", "")
        out.append(
            {
                "datapath_uuid": as_uuid(r.get("_uuid")),
                "kind": kind,
                "nb_uuid": nb if is_uuid(str(nb)) else ZERO,
                "name": as_str(name),
                "tunnel_key": as_int(r.get("tunnel_key"), 0),
                "updated_at": ts,
            }
        )
    return out


def t_port_binding(rows: List[Dict[str, Any]]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        out.append(
            {
                "pb_uuid": as_uuid(r.get("_uuid")),
                "logical_port": as_str(r.get("logical_port")),
                "type": as_str(r.get("type")),
                "datapath_uuid": as_uuid(r.get("datapath")),
                "chassis_uuid": as_uuid(r.get("chassis")),
                "mac": as_str_list(r.get("mac")),
                "tunnel_key": as_int(r.get("tunnel_key"), 0),
                "up": as_bool(r.get("up"), 0),
                "updated_at": ts,
            }
        )
    return out


def t_mac_binding(rows: List[Dict[str, Any]]) -> List[dict]:
    out = []
    ts = now_iso()
    for r in rows:
        out.append(
            {
                "mb_uuid": as_uuid(r.get("_uuid")),
                "datapath_uuid": as_uuid(r.get("datapath")),
                "ip": as_str(r.get("ip")),
                "logical_port": as_str(r.get("logical_port")),
                "mac": as_str(r.get("mac")).lower(),
                "updated_at": ts,
            }
        )
    return out


def build_edges(lsps: List[dict], lrps: List[dict]) -> Tuple[List[dict], List[dict]]:
    ts = now_iso()
    lrp_by_name = {r["name"]: r for r in lrps if r["name"]}
    ls_lr = []
    for p in lsps:
        if p["type"] != "router":
            continue
        lrp_name = p.get("options_router_port") or ""
        lrp = lrp_by_name.get(lrp_name)
        if not lrp:
            continue
        ls_lr.append(
            {
                "ls_uuid": p["ls_uuid"],
                "lr_uuid": lrp["lr_uuid"],
                "lsp_uuid": p["lsp_uuid"],
                "lrp_uuid": lrp["lrp_uuid"],
                "lsp_name": p["name"],
                "lrp_name": lrp["name"],
                "updated_at": ts,
            }
        )
    lr_lr = []
    seen = set()
    for lrp in lrps:
        peer_name = lrp.get("peer") or ""
        if not peer_name:
            continue
        peer = lrp_by_name.get(peer_name)
        if not peer:
            continue
        a, b = lrp["lr_uuid"], peer["lr_uuid"]
        if a == b or a == ZERO or b == ZERO:
            continue
        key = ("peer", min(a, b), max(a, b), ZERO)
        if key in seen:
            continue
        seen.add(key)
        lr_lr.append(
            {
                "via": "peer",
                "lr_a": min(a, b),
                "lr_b": max(a, b),
                "via_ls_uuid": ZERO,
                "lrp_a": lrp["lrp_uuid"] if a <= b else peer["lrp_uuid"],
                "lrp_b": peer["lrp_uuid"] if a <= b else lrp["lrp_uuid"],
                "updated_at": ts,
            }
        )
    by_ls: Dict[str, List[dict]] = defaultdict(list)
    for e in ls_lr:
        by_ls[e["ls_uuid"]].append(e)
    for ls_uuid, edges in by_ls.items():
        lrs = {}
        for e in edges:
            lrs.setdefault(e["lr_uuid"], e)
        ids = sorted(lrs)
        for i, a in enumerate(ids):
            for b in ids[i + 1 :]:
                key = ("transit_ls", a, b, ls_uuid)
                if key in seen:
                    continue
                seen.add(key)
                ea, eb = lrs[a], lrs[b]
                lr_lr.append(
                    {
                        "via": "transit_ls",
                        "lr_a": a,
                        "lr_b": b,
                        "via_ls_uuid": ls_uuid,
                        "lrp_a": ea["lrp_uuid"],
                        "lrp_b": eb["lrp_uuid"],
                        "updated_at": ts,
                    }
                )
    return ls_lr, lr_lr


def build_stretch(
    lsps: List[dict],
    pbs: List[dict],
    chassis: List[dict],
    encaps: List[dict],
    datapaths: List[dict],
) -> List[dict]:
    ts = now_iso()
    lsp_by_name = {p["name"]: p for p in lsps if p["name"]}
    ch_by_uuid = {c["chassis_uuid"]: c for c in chassis}
    enc_by_ch: Dict[str, dict] = {}
    for e in encaps:
        enc_by_ch.setdefault(e["chassis_uuid"], e)
    dp_to_ls = {d["datapath_uuid"]: d["nb_uuid"] for d in datapaths if d["kind"] == "ls"}
    counts: Dict[Tuple[str, str], int] = defaultdict(int)
    meta: Dict[Tuple[str, str], dict] = {}
    for pb in pbs:
        if pb["type"] not in ("", "vif"):
            continue
        ch = pb["chassis_uuid"]
        if ch == ZERO:
            continue
        ls = dp_to_ls.get(pb["datapath_uuid"], ZERO)
        if ls == ZERO:
            lsp = lsp_by_name.get(pb["logical_port"])
            if lsp:
                ls = lsp["ls_uuid"]
        if ls == ZERO:
            continue
        key = (ls, ch)
        counts[key] += 1
        if key not in meta:
            c = ch_by_uuid.get(ch, {})
            enc = enc_by_ch.get(ch, {})
            meta[key] = {
                "hostname": c.get("hostname", ""),
                "encap_type": enc.get("encap_type", ""),
                "encap_ip": enc.get("ip", ""),
            }
    out = []
    for (ls, ch), n in counts.items():
        m = meta[(ls, ch)]
        out.append(
            {
                "ls_uuid": ls,
                "chassis_uuid": ch,
                "hostname": m["hostname"],
                "encap_type": m["encap_type"],
                "encap_ip": m["encap_ip"],
                "vif_count": n,
                "updated_at": ts,
            }
        )
    return out


# --- AHV dumpxml --------------------------------------------------------------

def parse_dumpxml(path: str, host_ip: str) -> Tuple[Optional[dict], List[dict]]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        return None, []
    uuid_el = root.find("uuid")
    title_el = root.find("title")
    name_el = root.find("name")
    vm_uuid = (uuid_el.text or "").strip() if uuid_el is not None else ""
    vm_name = ""
    if title_el is not None and title_el.text:
        vm_name = title_el.text.strip()
    elif name_el is not None and name_el.text:
        vm_name = name_el.text.strip()
    if not is_uuid(vm_uuid):
        return None, []
    mac_to_nic: Dict[str, str] = {}
    mac_to_ip: Dict[str, str] = {}
    for el in root.iter():
        tag = local_tag(el.tag)
        if tag == "vnic":
            nu = el.get("uuid") or ""
            mac = (el.get("mac_addr") or el.get("mac") or "").lower()
            if is_uuid(nu) and mac:
                mac_to_nic[mac] = nu
            for ch in el.iter():
                ct = local_tag(ch.tag)
                if ct == "mac":
                    m = (ch.get("address") or (ch.text or "")).lower().strip()
                    if m:
                        if is_uuid(nu):
                            mac_to_nic[m] = nu
                        else:
                            mac_to_nic.setdefault(m, ZERO)
                if ct == "ip" and (ch.get("version") or "4") == "4" and ch.get("address"):
                    m = (el.get("mac_addr") or "").lower()
                    if m:
                        mac_to_ip.setdefault(m, ch.get("address") or "")
        elif tag == "mac":
            mac = (el.get("address") or "").lower()
            if mac:
                mac_to_nic.setdefault(mac, ZERO)
        elif tag == "net_binding":
            ip = ""
            mac = ""
            for ch in list(el):
                ct = local_tag(ch.tag)
                if ct == "ip" and (ch.get("version") or "4") == "4":
                    ip = ch.get("address") or ""
                if ct == "mac":
                    mac = (ch.get("address") or "").lower()
            if mac and ip:
                mac_to_ip[mac] = ip
        elif tag == "interface":
            mac = ""
            nic = ZERO
            for ch in el:
                ct = local_tag(ch.tag)
                if ct == "mac":
                    mac = (ch.get("address") or "").lower()
                if ct == "alias":
                    al = ch.get("name") or ""
                    if al.startswith("ua-") and is_uuid(al[3:]):
                        nic = al[3:]
            if mac:
                if nic != ZERO:
                    mac_to_nic[mac] = nic
                else:
                    mac_to_nic.setdefault(mac, ZERO)
    ts = now_iso()
    vm = {"vm_uuid": vm_uuid, "name": vm_name, "host_ip": host_ip, "updated_at": ts}
    nics = []
    for mac, nic in mac_to_nic.items():
        if not mac:
            continue
        nics.append(
            {
                "nic_uuid": nic if is_uuid(nic) else ZERO,
                "vm_uuid": vm_uuid,
                "vm_name": vm_name,
                "mac": mac,
                "ip4": mac_to_ip.get(mac, ""),
                "host_ip": host_ip,
                "lsp_uuid": ZERO,
                "ls_uuid": ZERO,
                "updated_at": ts,
            }
        )
    return vm, nics


def load_ahv(ahv_dir: str) -> Tuple[List[dict], List[dict]]:
    vms: List[dict] = []
    nics: List[dict] = []
    if not ahv_dir or not os.path.isdir(ahv_dir):
        return vms, nics
    for host in sorted(os.listdir(ahv_dir)):
        cmd_dir = os.path.join(ahv_dir, host, "commands")
        if not os.path.isdir(cmd_dir):
            continue
        for fn in os.listdir(cmd_dir):
            if not fn.startswith("virsh_--readonly_dumpxml_") or not fn.endswith(".stdout"):
                continue
            vm, ns = parse_dumpxml(os.path.join(cmd_dir, fn), host)
            if vm:
                vms.append(vm)
            nics.extend(ns)
    return vms, nics


def join_nics(nics: List[dict], lsps: List[dict]) -> List[dict]:
    by_mac = {p["mac"]: p for p in lsps if p.get("mac")}
    by_nic = {p["nic_uuid"]: p for p in lsps if p.get("nic_uuid") and p["nic_uuid"] != ZERO}
    out = []
    for n in nics:
        p = by_mac.get(n["mac"]) or by_nic.get(n["nic_uuid"])
        if p:
            n = dict(n)
            n["lsp_uuid"] = p["lsp_uuid"]
            n["ls_uuid"] = p["ls_uuid"]
            if n["nic_uuid"] == ZERO and p["nic_uuid"] != ZERO:
                n["nic_uuid"] = p["nic_uuid"]
            if not n["ip4"] and p.get("ip4"):
                n["ip4"] = p["ip4"][0]
        out.append(n)
    return out


def find_dump(dump_dir: str) -> Tuple[str, str, str]:
    nb = os.path.join(
        dump_dir, "cmsp_ovn", "anc-ovn", "commands", "ovsdb-client_dump_nb.txt"
    )
    sb = os.path.join(
        dump_dir, "cmsp_ovn", "anc-ovn", "commands", "ovsdb-client_dump_sb.txt"
    )
    ahv = os.path.join(dump_dir, "ahv_gateway")
    if not os.path.isfile(nb):
        raise SystemExit(f"NB dump not found: {nb}")
    if not os.path.isfile(sb):
        raise SystemExit(f"SB dump not found: {sb}")
    return nb, sb, ahv


def main() -> int:
    global LOG_BUNDLE_ID
    ap = argparse.ArgumentParser(description="Ingest OVN dumps into flow_ovn")
    ap.add_argument(
        "--dump_dir",
        default="/home/rakeshkumar.r/panacea/flow_pc_dumps/ovn_ovs_verify",
    )
    ap.add_argument(
        "--log_bundle_id",
        type=int,
        default=0,
        help="Panacea log_bundle_id. Re-ingest DROPs this partition only.",
    )
    ap.add_argument("--cluster_uuid", default="", help="Cluster UUID (bundle catalog)")
    ap.add_argument("--cluster_name", default="", help="Cluster display name")
    ap.add_argument("--pc_ip", default="", help="Prism Central IP")
    ap.add_argument("--nos_version", default="", help="AOS / NOS version")
    ap.add_argument(
        "--reset-schema",
        action="store_true",
        help="DROP all flow_ovn tables then recreate (all bundles). First migration.",
    )
    ap.add_argument(
        "--drop-bundle",
        type=int,
        default=0,
        help="Only DROP PARTITION for this log_bundle_id and exit.",
    )
    ap.add_argument("--skip-ahv", action="store_true")
    ap.add_argument("--skip-sb", action="store_true")
    args = ap.parse_args()
    if args.drop_bundle:
        drop_bundle_partitions(args.drop_bundle)
        print(f"dropped bundle {args.drop_bundle}")
        return 0
    LOG_BUNDLE_ID = resolve_log_bundle_id(args.log_bundle_id, args.dump_dir)
    print(f"log_bundle_id={LOG_BUNDLE_ID}")
    nb_path, sb_path, ahv_dir = find_dump(args.dump_dir)
    print("applying schema...")
    if args.reset_schema or not has_bundle_column("ovn_ls"):
        if not args.reset_schema:
            print("  existing tables lack log_bundle_id; recreating schema")
        ch_run(["--multiquery", "--query", RESET_SCHEMA_SQL])
    apply_schema()
    print(f"dropping old partition {LOG_BUNDLE_ID} (other bundles kept)...")
    drop_bundle_partitions(LOG_BUNDLE_ID)
    print(f"parsing NB {nb_path}")
    nb = parse_dump(nb_path, NB_TABLES)
    for t, rows in sorted(nb.items()):
        print(f"  NB {t}: {len(rows)}")
    ls_rows, acl_ls, lsp_to_ls = t_ls(nb.get("Logical_Switch", []))
    lsp_rows = t_lsp(nb.get("Logical_Switch_Port", []), lsp_to_ls)
    lr_rows, lrp_to_lr, lr_nats = t_lr(nb.get("Logical_Router", []))
    lrp_rows = t_lrp(nb.get("Logical_Router_Port", []), lrp_to_lr)
    for r in lrp_rows:
        for net in r["networks"]:
            if net.startswith("10.") and "/18" in net:
                r["is_ext_gw"] = 1
        if "ext_gw" in r["name"] or r["name"].startswith("lrp-ext_"):
            r["is_ext_gw"] = 1
    acl_rows = t_acl(nb.get("ACL", []))
    pg_rows, acl_pg, pg_ports = t_pg(nb.get("Port_Group", []))
    pbr_rows = t_pbr(
        nb.get("Logical_Router_Policy", []),
        lr_policy_index(nb.get("Logical_Router", [])),
    )
    nat_rows = t_nat(nb.get("NAT", []), lr_nats)
    ha_rows = t_ha(nb.get("HA_Chassis_Group", []), nb.get("HA_Chassis", []))
    ls_lr, lr_lr = build_edges(lsp_rows, lrp_rows)

    chassis_rows: List[dict] = []
    encap_rows: List[dict] = []
    dp_rows: List[dict] = []
    pb_rows: List[dict] = []
    mb_rows: List[dict] = []
    stretch_rows: List[dict] = []
    if not args.skip_sb:
        print(f"parsing SB {sb_path}")
        sb = parse_dump(sb_path, SB_TABLES)
        for t, rows in sorted(sb.items()):
            print(f"  SB {t}: {len(rows)}")
        chassis_rows, encap_to_ch = t_chassis(sb.get("Chassis", []))
        encap_rows = t_encap(sb.get("Encap", []), encap_to_ch)
        dp_rows = t_datapath(sb.get("Datapath_Binding", []))
        pb_rows = t_port_binding(sb.get("Port_Binding", []))
        mb_rows = t_mac_binding(sb.get("MAC_Binding", []))
        stretch_rows = build_stretch(lsp_rows, pb_rows, chassis_rows, encap_rows, dp_rows)

    vm_rows: List[dict] = []
    nic_rows: List[dict] = []
    if not args.skip_ahv:
        print(f"parsing AHV dumpxml {ahv_dir}")
        vm_rows, nic_rows = load_ahv(ahv_dir)
        nic_rows = join_nics(nic_rows, lsp_rows)
        print(f"  VMs {len(vm_rows)} nics {len(nic_rows)}")

    print("inserting...")
    insert_rows(
        "bundle",
        [
            {
                "dump_dir": os.path.abspath(args.dump_dir),
                "cluster_uuid": as_uuid(args.cluster_uuid) if args.cluster_uuid else ZERO,
                "cluster_name": args.cluster_name or "",
                "pc_ip": args.pc_ip or "",
                "nos_version": args.nos_version or "",
                "collected_at": now_iso(),
                "updated_at": now_iso(),
            }
        ],
    )
    insert_rows("ovn_ls", ls_rows)
    insert_rows("ovn_lsp", lsp_rows)
    insert_rows("ovn_lr", lr_rows)
    insert_rows("ovn_lrp", lrp_rows)
    insert_rows("ovn_acl", acl_rows)
    insert_rows("ovn_acl_on_ls", acl_ls)
    insert_rows("ovn_pg", pg_rows)
    insert_rows("ovn_acl_on_pg", acl_pg)
    insert_rows("ovn_pg_port", pg_ports)
    insert_rows("ovn_pbr", pbr_rows)
    insert_rows("ovn_nat", nat_rows)
    insert_rows("ovn_ha_chassis", ha_rows)
    insert_rows("ovn_vm", vm_rows)
    insert_rows("ovn_vm_nic", nic_rows)
    insert_rows("ovn_chassis", chassis_rows)
    insert_rows("ovn_encap", encap_rows)
    insert_rows("ovn_datapath", dp_rows)
    insert_rows("ovn_port_binding", pb_rows)
    insert_rows("ovn_mac_binding", mb_rows)
    insert_rows("ovn_edge_ls_lr", ls_lr)
    insert_rows("ovn_edge_lr_lr", lr_lr)
    insert_rows("ovn_ls_stretch", stretch_rows)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
