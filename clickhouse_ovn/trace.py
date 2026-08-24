#!/usr/bin/env python3
"""Trace OVN NB/SB paths from flow_ovn. stdlib + clickhouse-client."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import ipaddress
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

OUT_DIR = "/home/rakeshkumar.r/panacea/clickhouse_ovn/out"

from dataplane import (
    address_set_label,
    ip_in_address_set,
    ovs_for_gw,
    ovs_for_vif,
    port_group_label,
    refs_from_acls,
    rewrite_match,
    static_routes_for_lr,
    nb_lr_meta,
    nb_ls_meta,
)

CH_HOST = "127.0.0.1"
CH_PORT = "19000"
CH_USER = "default"
ZERO = "00000000-0000-0000-0000-000000000000"
DB = "flow_ovn"
Node = Tuple[str, str]  # ("ls"|"lr", uuid)


def ch(sql: str) -> List[Dict[str, Any]]:
    cmd = [
        "clickhouse-client",
        "--host", CH_HOST,
        "--port", CH_PORT,
        "--user", CH_USER,
        "--database", DB,
        "--format", "JSONEachRow",
        "--query", sql,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "clickhouse failed").strip())
    rows = []
    for line in proc.stdout.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_graph() -> Dict[str, Any]:
    ls = {r["ls_uuid"]: r for r in ch("SELECT ls_uuid, name, other_config FROM ovn_ls")}
    lr = {r["lr_uuid"]: r for r in ch("SELECT lr_uuid, name, has_nat, enabled FROM ovn_lr")}
    lsp = ch(
        "SELECT lsp_uuid, ls_uuid, name, type, mac, ip4, ip6, addresses, "
        "nic_uuid, options_router_port, options_network_name, peer, "
        "dynamic_addresses "
        "FROM ovn_lsp"
    )
    lrp = ch(
        "SELECT lrp_uuid, lr_uuid, name, mac, networks, peer, is_ext_gw, "
        "ha_chassis_group FROM ovn_lrp"
    )
    dps = ch(
        "SELECT datapath_uuid, kind, nb_uuid, name, tunnel_key FROM ovn_datapath"
    )
    ls_lr = ch(
        "SELECT ls_uuid, lr_uuid, lsp_uuid, lrp_uuid, lsp_name, lrp_name FROM ovn_edge_ls_lr"
    )
    lr_lr = ch(
        "SELECT via, lr_a, lr_b, via_ls_uuid, lrp_a, lrp_b FROM ovn_edge_lr_lr"
    )
    nics = ch(
        "SELECT nic_uuid, vm_uuid, vm_name, mac, ip4, host_ip, lsp_uuid, ls_uuid "
        "FROM ovn_vm_nic"
    )
    adj: Dict[Node, List[Tuple[Node, dict]]] = defaultdict(list)

    def push(a: Node, b: Node, meta: dict) -> None:
        if a[1] == ZERO or b[1] == ZERO or a == b:
            return
        adj[a].append((b, meta))

    for e in ls_lr:
        meta = {"kind": "ls_lr", **e}
        push(("ls", e["ls_uuid"]), ("lr", e["lr_uuid"]), meta)
        push(("lr", e["lr_uuid"]), ("ls", e["ls_uuid"]), meta)
    for e in lr_lr:
        meta = {"kind": "lr_lr", **e}
        push(("lr", e["lr_a"]), ("lr", e["lr_b"]), meta)
        push(("lr", e["lr_b"]), ("lr", e["lr_a"]), meta)
    return {
        "ls": ls,
        "lr": lr,
        "lsp": lsp,
        "lrp": lrp,
        "ls_lr": ls_lr,
        "lr_lr": lr_lr,
        "nics": nics,
        "adj": adj,
        "lsp_by_uuid": {p["lsp_uuid"]: p for p in lsp},
        "lrp_by_uuid": {p["lrp_uuid"]: p for p in lrp},
        "nic_by_lsp": {n["lsp_uuid"]: n for n in nics if n["lsp_uuid"] != ZERO},
        "localnet_ls": {
            p["ls_uuid"] for p in lsp if (p.get("type") or "") == "localnet"
        },
        "dp_by_nb": {str(r["nb_uuid"]): r for r in dps if r.get("nb_uuid")},
    }


def ip_of_lsp(p: dict) -> str:
    v = p.get("ip4") or []
    if isinstance(v, list):
        return v[0] if v else ""
    return str(v)


def _looks_ip(token: str) -> bool:
    try:
        ipaddress.ip_address((token or "").split("/")[0])
        return True
    except ValueError:
        return False


def resolve(g: Dict[str, Any], token: str) -> Dict[str, Any]:
    t = token.strip()
    if t.lower() in ("external", "ext", "northbound", "nat"):
        return {"kind": "external", "dest_ip": ""}
    if _looks_ip(t):
        return {"kind": "external", "dest_ip": t.split("/")[0]}
    tl = t.lower()
    for n in g["nics"]:
        if n["vm_name"] == t or (n["mac"] or "").lower() == tl or n["nic_uuid"] == t or n["lsp_uuid"] == t:
            lsp = g["lsp_by_uuid"].get(n["lsp_uuid"], {})
            return {
                "kind": "vif",
                "nic": n,
                "lsp": lsp,
                "ls_uuid": n["ls_uuid"] or lsp.get("ls_uuid", ZERO),
            }
    for p in g["lsp"]:
        mac = (p.get("mac") or "").lower()
        if p["lsp_uuid"] == t or p["name"] == t or mac == tl or p["nic_uuid"] == t:
            nic = g["nic_by_lsp"].get(p["lsp_uuid"], {})
            return {"kind": "vif", "nic": nic, "lsp": p, "ls_uuid": p["ls_uuid"]}
    for rec in g["ls"].values():
        if rec["ls_uuid"] == t or rec["name"] == t:
            return {"kind": "ls", "ls_uuid": rec["ls_uuid"]}
    for rec in g["lr"].values():
        if rec["lr_uuid"] == t or rec["name"] == t:
            return {"kind": "lr", "lr_uuid": rec["lr_uuid"], "lr": rec}
    raise SystemExit(f"could not resolve endpoint: {token}")


def bfs(g: Dict[str, Any], src: Node, dsts: List[Node]) -> Optional[List[Tuple[Node, Optional[dict]]]]:
    dest = set(dsts)
    queue: deque = deque([[(src, None)]])
    seen = {src}
    while queue:
        path = queue.popleft()
        node = path[-1][0]
        if len(path) > 1 and node in dest:
            return path
        if len(path) == 1 and node in dest:
            return path
        for nxt, meta in g["adj"].get(node, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append(path + [(nxt, meta)])
    return None


def classify(path: List[Tuple[Node, Optional[dict]]]) -> str:
    lrs = [n[0][1] for n in path if n[0][0] == "lr"]
    if not lrs:
        return "same_l2"
    if len(set(lrs)) == 1:
        return "l2_l3_l2"
    return "two_router"


def acls_for_ls(ls_uuid: str, in_lsp: str, out_lsp: str) -> List[dict]:
    rows = ch(
        "SELECT a.acl_uuid AS acl_uuid, a.name AS name, a.direction AS direction, "
        "a.action AS action, a.match AS match, a.priority AS priority, 'ls' AS src "
        "FROM ovn_acl_on_ls AS m INNER JOIN ovn_acl AS a ON a.acl_uuid = m.acl_uuid "
        f"WHERE m.ls_uuid = '{ls_uuid}' ORDER BY a.priority DESC"
    )
    ports = [p for p in (in_lsp, out_lsp) if p and p != ZERO]
    if ports:
        plist = ",".join("'%s'" % p for p in ports)
        rows += ch(
            "SELECT a.acl_uuid AS acl_uuid, a.name AS name, a.direction AS direction, "
            "a.action AS action, a.match AS match, a.priority AS priority, 'pg' AS src "
            "FROM ovn_pg_port AS pp "
            "INNER JOIN ovn_acl_on_pg AS pm ON pm.pg_uuid = pp.pg_uuid "
            "INNER JOIN ovn_acl AS a ON a.acl_uuid = pm.acl_uuid "
            f"WHERE pp.lsp_uuid IN ({plist}) ORDER BY a.priority DESC"
        )
    seen = set()
    out = []
    for r in rows:
        if r["acl_uuid"] in seen:
            continue
        seen.add(r["acl_uuid"])
        out.append(r)
    return out


def pbrs(lr_uuid: str) -> List[dict]:
    return ch(
        "SELECT pbr_uuid, match, action, nexthop, nexthops, priority FROM ovn_pbr "
        f"WHERE lr_uuid = '{lr_uuid}' ORDER BY priority DESC"
    )


def nats(lr_uuid: str) -> List[dict]:
    return ch(
        "SELECT nat_uuid, type, external_ip, logical_ip, logical_port, external_mac "
        f"FROM ovn_nat WHERE lr_uuid = '{lr_uuid}' ORDER BY type, external_ip, logical_ip"
    )


def routes_for_lr(g: Dict[str, Any], lr_uuid: str) -> List[dict]:
    """Connected CIDRs on every LRP of this LR (policy routes are PBR)."""
    out: List[dict] = []
    for p in g.get("lrp") or []:
        if p.get("lr_uuid") != lr_uuid:
            continue
        nets = p.get("networks") or []
        if isinstance(nets, str):
            nets = [x.strip() for x in nets.split(",") if x.strip()]
        for cidr in nets:
            out.append(
                {
                    "lrp": p.get("name") or "",
                    "cidr": cidr,
                    "ext_gw": "yes" if p.get("is_ext_gw") in (1, "1", True) else "",
                }
            )
    return out


def chassis_info(token: str) -> Dict[str, str]:
    """Resolve HA chassis_name / Chassis UUID / hostname to SB chassis + Geneve."""
    t = (token or "").strip()
    empty = {
        "hostname": "",
        "chassis_uuid": "",
        "name": "",
        "geneve_ip": "",
        "encap_type": "geneve",
        "host_ip": "",
    }
    if not t:
        return dict(empty)
    rows = ch(
        "SELECT c.chassis_uuid AS chassis_uuid, c.name AS name, "
        "c.hostname AS hostname, e.ip AS geneve_ip, e.encap_type AS encap_type "
        "FROM ovn_chassis AS c "
        "LEFT JOIN ovn_encap AS e ON e.chassis_uuid = c.chassis_uuid "
        f"WHERE c.chassis_uuid = '{t}' OR c.name = '{t}' OR c.hostname = '{t}' "
        "LIMIT 1"
    )
    if not rows:
        return dict(empty)
    r = rows[0]
    geneve = r.get("geneve_ip") or ""
    return {
        "hostname": r.get("hostname") or "",
        "chassis_uuid": str(r.get("chassis_uuid") or ""),
        "name": r.get("name") or "",
        "geneve_ip": geneve,
        "encap_type": r.get("encap_type") or "geneve",
        "host_ip": geneve,
    }


def enrich_rc(rows: List[dict]) -> List[dict]:
    out = []
    for r in rows or []:
        info = chassis_info(str(r.get("chassis_name") or ""))
        nr = dict(r)
        nr.update(info)
        out.append(nr)
    return out


def gw_host_from_rc(rcs: List[dict]) -> Dict[str, str]:
    if not rcs:
        return {}
    top = sorted(rcs, key=lambda r: int(r.get("priority") or 0), reverse=True)[0]
    return {
        "hostname": top.get("hostname") or "",
        "chassis_uuid": top.get("chassis_uuid") or "",
        "name": top.get("name") or top.get("chassis_name") or "",
        "geneve_ip": top.get("geneve_ip") or "",
        "encap_type": top.get("encap_type") or "geneve",
        "host_ip": top.get("host_ip") or top.get("geneve_ip") or "",
        "priority": str(top.get("priority") or ""),
    }


def gw_dataplane(g: Dict[str, Any], lr_uuid: str, gw_host: Dict[str, str]) -> Dict[str, str]:
    """Localnet + brAtlas patch on the External GW Host for this ext-GW LR."""
    out = {
        "tap": "",
        "ofport": "",
        "dp_port": "",
        "bridge": "brAtlas",
        "iface_id": "",
        "localnet": "",
        "ext_ls": "",
    }
    localnet = ""
    ext_ls = ""
    for e in g.get("ls_lr") or []:
        if e.get("lr_uuid") != lr_uuid:
            continue
        lrp = g["lrp_by_uuid"].get(e.get("lrp_uuid") or "", {})
        if lrp.get("is_ext_gw") not in (1, "1", True):
            continue
        ext_ls = e.get("ls_uuid") or ""
        break
    if ext_ls:
        for p in g.get("lsp") or []:
            if p.get("ls_uuid") == ext_ls and (p.get("type") or "") == "localnet":
                localnet = p.get("name") or ""
                break
    host_ip = (gw_host or {}).get("host_ip") or (gw_host or {}).get("geneve_ip") or ""
    ovs = ovs_for_gw(host_ip, localnet) if host_ip and localnet else {}
    out.update(ovs)
    out["localnet"] = localnet
    out["ext_ls"] = ext_ls
    return out


def rc_for_lr(g: Dict[str, Any], lr_uuid: str) -> List[dict]:
    """HA / router chassis members for any LRP on this LR with a non-zero group."""
    groups = []
    seen = set()
    for p in g.get("lrp") or []:
        if p.get("lr_uuid") != lr_uuid:
            continue
        gid = str(p.get("ha_chassis_group") or ZERO)
        if gid == ZERO or gid in seen:
            continue
        seen.add(gid)
        groups.append(gid)
    if not groups:
        return []
    glist = ",".join("'%s'" % x for x in groups)
    rows = ch(
        "SELECT group_uuid, group_name, chassis_name, priority FROM ovn_ha_chassis "
        f"WHERE group_uuid IN ({glist}) ORDER BY priority DESC, chassis_name"
    )
    return enrich_rc(rows)


def path_ls_uuids(
    nodes: List[Tuple[Node, Optional[dict]]], g: Dict[str, Any]
) -> set:
    uids = set()
    for node, meta in nodes:
        if node[0] == "ls":
            uids.add(node[1])
        if meta:
            via = meta.get("via_ls_uuid") or ""
            if via and via != ZERO:
                uids.add(via)
            ls = meta.get("ls_uuid") or ""
            if ls and ls != ZERO:
                uids.add(ls)
    return uids


def lrps_on_path(g: Dict[str, Any], lr_uuid: str, path_ls: set, lr_name: str) -> List[dict]:
    """Path LRPs only: src LS ↔ LR, LR ↔ transit, transit ↔ GW, GW ↔ external."""
    seen = set()
    out: List[dict] = []
    gw_lr = "gw-scale-out" in (lr_name or "").lower() and "router" in (lr_name or "").lower()

    def add(lrp: dict, role: str, ls_uuid: str = "") -> None:
        uid = lrp.get("lrp_uuid") or lrp.get("name") or ""
        if not uid or uid in seen:
            return
        seen.add(uid)
        nets = lrp.get("networks") or []
        if isinstance(nets, str):
            nets = [x.strip() for x in nets.split(",") if x.strip()]
        out.append(
            {
                "lrp": lrp.get("name") or "",
                "mac": lrp.get("mac") or "",
                "networks": nets,
                "cidr": ", ".join(str(x) for x in nets),
                "ext_gw": "yes" if lrp.get("is_ext_gw") in (1, "1", True) else "",
                "role": role,
                "ls_uuid": ls_uuid,
            }
        )

    for e in g.get("ls_lr") or []:
        if e.get("lr_uuid") != lr_uuid:
            continue
        lrp = g["lrp_by_uuid"].get(e.get("lrp_uuid") or "", {})
        if not lrp:
            continue
        ls_uuid = e.get("ls_uuid") or ""
        ls_name = (g["ls"].get(ls_uuid) or {}).get("name") or ""
        ext = lrp.get("is_ext_gw") in (1, "1", True)
        on_path = ls_uuid in path_ls
        if not on_path and not ext:
            continue
        if ext:
            role = "GW ↔ external"
        elif is_transit_ls(ls_name):
            role = "transit ↔ GW" if gw_lr else "LR ↔ transit"
        else:
            role = "src LS ↔ LR"
        add(lrp, role, ls_uuid)
    for p in g.get("lrp") or []:
        if p.get("lr_uuid") == lr_uuid and p.get("is_ext_gw") in (1, "1", True):
            add(p, "GW ↔ external")
    return out


def ext_gw_lrp(g: Dict[str, Any], lr_uuid: str) -> Dict[str, str]:
    """MAC + CIDR of the LRP facing external (lrp-ext_gw_port)."""
    for p in g.get("lrp") or []:
        if p.get("lr_uuid") != lr_uuid:
            continue
        if p.get("is_ext_gw") not in (1, "1", True):
            continue
        nets = p.get("networks") or []
        if isinstance(nets, str):
            nets = [x.strip() for x in nets.split(",") if x.strip()]
        cidr = ", ".join(str(x) for x in nets)
        ip0 = str(nets[0]).split("/")[0] if nets else ""
        return {
            "ext_lrp": p.get("name") or "",
            "ext_mac": (p.get("mac") or "").lower(),
            "ext_cidr": cidr,
            "ext_ip": ip0,
        }
    return {"ext_lrp": "", "ext_mac": "", "ext_cidr": "", "ext_ip": ""}


def scaleout_siblings(g: Dict[str, Any], lr_uuid: str) -> List[dict]:
    """Other gw-scale-out routers on the same transit LS (all scale-out hosts)."""
    transit = set()
    for e in g.get("ls_lr") or []:
        if e.get("lr_uuid") != lr_uuid:
            continue
        ls_name = (g["ls"].get(e.get("ls_uuid") or "") or {}).get("name") or ""
        if is_transit_ls(ls_name):
            transit.add(e["ls_uuid"])
    peers: List[dict] = []
    seen = {lr_uuid}
    for e in g.get("ls_lr") or []:
        if e.get("ls_uuid") not in transit:
            continue
        oid = e.get("lr_uuid") or ""
        if not oid or oid in seen:
            continue
        rec = g["lr"].get(oid) or {}
        name = rec.get("name") or ""
        if "gw-scale-out" not in name.lower():
            continue
        seen.add(oid)
        rc = rc_for_lr(g, oid)
        host = gw_host_from_rc(rc)
        ovs = gw_dataplane(g, oid, host)
        ext = ext_gw_lrp(g, oid)
        meta = gather_lr_meta(g, oid, path_ls=transit)
        peers.append(
            {
                "uuid": oid,
                "name": name,
                "rc": rc,
                "gw_host": host,
                "ovs": ovs,
                "active": False,
                "meta": meta,
                **ext,
            }
        )
    return peers


def stretch(ls_uuid: str) -> List[dict]:
    return ch(
        "SELECT chassis_uuid, hostname, encap_type, encap_ip, vif_count "
        f"FROM ovn_ls_stretch WHERE ls_uuid = '{ls_uuid}' ORDER BY hostname"
    )


def fmt_ep(ep: Dict[str, Any]) -> str:
    if ep.get("kind") == "external":
        dip = ep.get("dest_ip") or ""
        return f"external/NAT dest={dip}" if dip else "external/NAT"
    nic = ep.get("nic") or {}
    lsp = ep.get("lsp") or {}
    bits = []
    if ep.get("kind") == "lr":
        rec = ep.get("lr") or {}
        return f"lr={rec.get('name', '')} uuid={ep.get('lr_uuid')}"
    if nic.get("vm_name"):
        bits.append(f"vm={nic['vm_name']}")
    if nic.get("nic_uuid") and nic["nic_uuid"] != ZERO:
        bits.append(f"nic={nic['nic_uuid']}")
    if lsp.get("name"):
        bits.append(f"lsp={lsp['name']}")
    if lsp.get("lsp_uuid"):
        bits.append(f"lsp_uuid={lsp['lsp_uuid']}")
    mac = nic.get("mac") or lsp.get("mac")
    if mac:
        bits.append(f"mac={mac}")
    ip = nic.get("ip4") or ip_of_lsp(lsp)
    if ip:
        bits.append(f"ip={ip}")
    return " ".join(bits) or str(ep.get("kind"))


def split_acls(acls: List[dict], reverse: bool) -> Tuple[List[dict], List[dict]]:
    from_l = [a for a in acls if a["direction"] == "from-lport"]
    to_l = [a for a in acls if a["direction"] == "to-lport"]
    if reverse:
        from_l, to_l = to_l, from_l
    from_l.sort(key=lambda a: int(a.get("priority") or 0), reverse=True)
    to_l.sort(key=lambda a: int(a.get("priority") or 0), reverse=True)
    return from_l, to_l


def show_acls(lines: List[str], acls: List[dict], reverse: bool) -> None:
    from_l, to_l = split_acls(acls, reverse)

    def dump(lbl: str, items: List[dict]) -> None:
        if not items:
            lines.append(f"       ACLs {lbl}: (none)")
            return
        lines.append(f"       ACLs {lbl}: {len(items)} (full list)")
        for a in items:
            lines.append(
                f"         pri={a['priority']} {a['action']} {a['direction']} "
                f"[{a['src']}] {a.get('match') or ''}"
            )

    dump("from-lport (ingress on this hop)", from_l)
    dump("to-lport (egress on this hop)", to_l)


def host_of_vif(ep: Dict[str, Any]) -> Dict[str, str]:
    nic = ep.get("nic") or {}
    lsp = ep.get("lsp") or {}
    lsp_uuid = lsp.get("lsp_uuid") or nic.get("lsp_uuid") or ""
    lsp_name = lsp.get("name") or ""
    out = {
        "hostname": "",
        "chassis_uuid": "",
        "chassis_name": "",
        "host_ip": nic.get("host_ip") or "",
        "geneve_ip": "",
        "encap_type": "geneve",
        "vm": nic.get("vm_name") or "",
        "nic": nic.get("nic_uuid") or "",
        "mac": nic.get("mac") or lsp.get("mac") or "",
        "ip": nic.get("ip4") or ip_of_lsp(lsp),
        "lsp": lsp_name,
        "lsp_uuid": lsp_uuid,
    }
    if not lsp_uuid and not lsp_name:
        return out
    where = []
    if lsp_uuid:
        where.append(f"l.lsp_uuid = '{lsp_uuid}'")
    if lsp_name:
        where.append(f"l.name = '{lsp_name}'")
    rows = ch(
        "SELECT c.hostname AS hostname, c.chassis_uuid AS chassis_uuid, "
        "c.name AS chassis_name, n.host_ip AS host_ip, "
        "e.ip AS geneve_ip, e.encap_type AS encap_type "
        "FROM ovn_lsp AS l "
        "LEFT JOIN ovn_vm_nic AS n ON n.lsp_uuid = l.lsp_uuid "
        "LEFT JOIN ovn_port_binding AS pb ON pb.logical_port = l.name "
        "LEFT JOIN ovn_chassis AS c ON c.chassis_uuid = pb.chassis_uuid "
        "LEFT JOIN ovn_encap AS e ON e.chassis_uuid = c.chassis_uuid "
        f"WHERE {' OR '.join(where)} LIMIT 1"
    )
    if rows:
        r = rows[0]
        out["hostname"] = r.get("hostname") or out["hostname"]
        out["chassis_uuid"] = str(r.get("chassis_uuid") or "")
        out["chassis_name"] = r.get("chassis_name") or ""
        out["host_ip"] = r.get("host_ip") or out["host_ip"]
        out["geneve_ip"] = r.get("geneve_ip") or out["geneve_ip"]
        out["encap_type"] = r.get("encap_type") or out["encap_type"]
    return out


def _esc(text: Any) -> str:
    s = str(text or "").replace('"', "'").replace("<", "(").replace(">", ")")
    return s.replace("\n", " ").replace("{", "(").replace("}", ")")


def _mlabel(text: Any) -> str:
    """Escape mermaid label text but keep <br/> line breaks."""
    s = str(text or "").replace('"', "'").replace("{", "(").replace("}", ")")
    s = s.replace("<br/>", "\x00BR\x00")
    s = s.replace("<", "(").replace(">", ")")
    return s.replace("\x00BR\x00", "<br/>").replace("\n", " ")


def _short8(uid: Any) -> str:
    s = str(uid or "").replace("-", "")
    return s[-8:] if s else ""


def vif_card(ep: Dict[str, Any]) -> Dict[str, str]:
    h = host_of_vif(ep) if ep.get("kind") == "vif" else {}
    nic = ep.get("nic") or {}
    lsp = ep.get("lsp") or {}
    ovs = ovs_for_vif(nic, lsp) if ep.get("kind") == "vif" else {}
    return {
        "hostname": h.get("hostname") or "",
        "chassis_uuid": h.get("chassis_uuid") or "",
        "chassis_name": h.get("chassis_name") or "",
        "host_ip": h.get("host_ip") or nic.get("host_ip") or "",
        "geneve_ip": h.get("geneve_ip") or "",
        "encap_type": h.get("encap_type") or "geneve",
        "vm": nic.get("vm_name") or "",
        "nic": nic.get("nic_uuid") or "",
        "mac": nic.get("mac") or lsp.get("mac") or "",
        "ip": nic.get("ip4") or ip_of_lsp(lsp),
        "lsp": lsp.get("name") or "",
        "lsp_uuid": lsp.get("lsp_uuid") or "",
        "ls_uuid": ep.get("ls_uuid") or lsp.get("ls_uuid") or "",
        "tap": ovs.get("tap") or "",
        "ofport": ovs.get("ofport") or "",
        "dp_port": ovs.get("dp_port") or "",
        "bridge": ovs.get("bridge") or "",
        "iface_id": ovs.get("iface_id") or "",
    }


def is_transit_ls(name: str) -> bool:
    n = (name or "").lower()
    return "gw-scale-out-network" in n or n.startswith("transit")


def is_gw_router(name: str = "", rec: Optional[dict] = None) -> bool:
    n = (name or (rec or {}).get("name") or "").lower()
    if "gw-scale-out" in n and "router" in n:
        return True
    if rec and rec.get("is_ext_gw"):
        return True
    return False


def vpc_label(vm_name: str) -> str:
    m = re.search(r"Customer_\d+", vm_name or "")
    return m.group(0) if m else (vm_name or "")


def _pairs_to_map(val: Any) -> Dict[str, str]:
    if isinstance(val, dict):
        return {str(k): str(v) for k, v in val.items() if k is not None}
    out: Dict[str, str] = {}
    if isinstance(val, list):
        for item in val:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out[str(item[0])] = str(item[1])
            elif isinstance(item, dict) and "1" in item:
                out[str(item.get("1"))] = str(item.get("2"))
    return out


def _pb_for_ports(names: List[str]) -> Dict[str, dict]:
    names = [n for n in names if n]
    if not names:
        return {}
    quoted = ",".join("'%s'" % n.replace("'", "\\'") for n in names)
    rows = ch(
        "SELECT pb.logical_port AS logical_port, pb.chassis_uuid AS chassis_uuid, "
        "pb.tunnel_key AS tunnel_key, pb.type AS pb_type, c.hostname AS hostname "
        "FROM ovn_port_binding AS pb "
        "LEFT JOIN ovn_chassis AS c ON c.chassis_uuid = pb.chassis_uuid "
        f"WHERE pb.logical_port IN ({quoted})"
    )
    return {str(r.get("logical_port") or ""): r for r in rows}


def gather_ls_meta(
    g: Dict[str, Any],
    ls_uuid: str,
    path_lsp: Optional[set] = None,
    path_lr: Optional[set] = None,
) -> dict:
    rec = dict(g["ls"].get(ls_uuid) or {})
    dump = nb_ls_meta(ls_uuid)
    oc = _pairs_to_map(dump.get("other_config") or rec.get("other_config"))
    ext = _pairs_to_map(dump.get("external_ids"))
    dp = g.get("dp_by_nb") or {}
    dpr = dp.get(str(ls_uuid)) or {}
    ports = []
    names = []
    for p in g.get("lsp") or []:
        if p.get("ls_uuid") != ls_uuid:
            continue
        ptype = p.get("type") or "vif"
        uid = p.get("lsp_uuid") or ""
        on_path = bool(path_lsp and uid in path_lsp)
        router_on_path = False
        if ptype == "router" and path_lr:
            lrp_name = p.get("options_router_port") or ""
            for rp in g.get("lrp") or []:
                if rp.get("name") == lrp_name and rp.get("lr_uuid") in path_lr:
                    router_on_path = True
                    break
        keep = on_path or ptype in ("localnet",) or router_on_path
        if not keep:
            continue
        ip = ip_of_lsp(p)
        ports.append(
            {
                "lsp_uuid": uid,
                "name": p.get("name") or "",
                "type": ptype or "vif",
                "mac": p.get("mac") or "",
                "ip": ip,
                "addresses": p.get("addresses") or [],
                "options_router_port": p.get("options_router_port") or "",
                "peer": p.get("peer") or "",
            }
        )
        names.append(p.get("name") or "")
    pbs = _pb_for_ports(names)
    for p in ports:
        pb = pbs.get(p["name"]) or {}
        p["chassis_uuid"] = str(pb.get("chassis_uuid") or "")
        p["hostname"] = pb.get("hostname") or ""
        p["pb_tunnel_key"] = pb.get("tunnel_key") or 0
    return {
        "ls_uuid": ls_uuid,
        "name": rec.get("name") or dump.get("name") or ls_uuid,
        "other_config": oc,
        "external_ids": ext,
        "datapath_uuid": str(dpr.get("datapath_uuid") or ""),
        "tunnel_key": dpr.get("tunnel_key") or 0,
        "ports": ports,
    }


def gather_lr_meta(g: Dict[str, Any], lr_uuid: str, path_ls: Optional[set] = None) -> dict:
    rec = dict(g["lr"].get(lr_uuid) or {})
    dump = nb_lr_meta(lr_uuid)
    opts = _pairs_to_map(dump.get("options"))
    ext = _pairs_to_map(dump.get("external_ids"))
    dp = g.get("dp_by_nb") or {}
    dpr = dp.get(str(lr_uuid)) or {}
    lrps = []
    path_lrps = []
    for p in g.get("lrp") or []:
        if p.get("lr_uuid") != lr_uuid:
            continue
        nets = p.get("networks") or []
        if isinstance(nets, str):
            nets = [x.strip() for x in nets.split(",") if x.strip()]
        row = {
            "lrp_uuid": p.get("lrp_uuid") or "",
            "name": p.get("name") or "",
            "mac": p.get("mac") or "",
            "networks": nets,
            "cidr": ", ".join(str(x) for x in nets),
            "peer": p.get("peer") or "",
            "ha_chassis_group": str(p.get("ha_chassis_group") or ""),
            "is_ext_gw": p.get("is_ext_gw") in (1, "1", True),
        }
        lrps.append(row)
        on_path = False
        if row["is_ext_gw"]:
            on_path = True
        if path_ls:
            for e in g.get("ls_lr") or []:
                if e.get("lrp_uuid") == row["lrp_uuid"] and e.get("ls_uuid") in path_ls:
                    on_path = True
                    break
        if on_path:
            path_lrps.append(row)
    if not path_lrps:
        path_lrps = lrps[:8]
    return {
        "lr_uuid": lr_uuid,
        "name": rec.get("name") or dump.get("name") or lr_uuid,
        "enabled": rec.get("enabled"),
        "has_nat": rec.get("has_nat"),
        "options": opts,
        "external_ids": ext,
        "datapath_uuid": str(dpr.get("datapath_uuid") or ""),
        "tunnel_key": dpr.get("tunnel_key") or 0,
        "lrps": lrps,
        "path_lrps": path_lrps,
    }


def _oc_bits(m: Dict[str, str], keys: Tuple[str, ...] = ()) -> List[str]:
    bits = []
    want = keys or tuple(m.keys())
    interesting = (
        "vpc",
        "subnet",
        "network",
        "mtu",
        "vpc_id",
        "neutron:network_name",
        "neutron:router_name",
        "snat-ct-zone",
        "chassis",
        "mac",
        "dynamic_neigh_routers",
        "always_learn_from_arp_request",
        "requested-tnl-key",
    )
    seen = set()
    for k in list(want) + list(interesting) + list(m.keys()):
        if k in seen or k not in m:
            continue
        seen.add(k)
        v = m.get(k)
        if v in (None, "", "[]", "{}"):
            continue
        if k not in interesting and k not in want and len(bits) >= 8:
            continue
        bits.append(f"{k}={v}")
        if len(bits) >= 10:
            break
    return bits


def ls_mermaid_label(tag: str, hop: dict) -> str:
    m = hop.get("meta") or {}
    lines = [
        tag,
        str(hop.get("name") or m.get("name") or ""),
        f"uuid {hop.get('uuid') or m.get('ls_uuid') or ''}",
    ]
    tk = m.get("tunnel_key") or 0
    if tk:
        lines.append(f"tunnel_key {tk}")
    if m.get("datapath_uuid"):
        lines.append(f"datapath {m.get('datapath_uuid')}")
    lines.extend(_oc_bits(m.get("other_config") or {}))
    lines.extend(_oc_bits(m.get("external_ids") or {}))
    for p in (m.get("ports") or [])[:8]:
        bit = f"LSP {p.get('type') or 'vif'} {p.get('name') or ''}"
        if p.get("mac") or p.get("ip"):
            bit += f" MAC {p.get('mac') or ''} IP {p.get('ip') or ''}"
        if p.get("hostname") or p.get("chassis_uuid"):
            bit += f" chassis {p.get('hostname') or p.get('chassis_uuid')}"
        lines.append(bit)
    return "<br/>".join(_esc(x) for x in lines if x)


def lr_mermaid_label(hop: dict, gw: bool = False) -> str:
    m = hop.get("meta") or {}
    title = "External GW" if gw else "Router"
    lines = [
        title,
        str(hop.get("name") or m.get("name") or ""),
        f"uuid {hop.get('uuid') or m.get('lr_uuid') or ''}",
    ]
    tk = m.get("tunnel_key") or 0
    if tk:
        lines.append(f"tunnel_key {tk}")
    if m.get("datapath_uuid"):
        lines.append(f"datapath {m.get('datapath_uuid')}")
    lines.extend(_oc_bits(m.get("options") or {}))
    lines.extend(_oc_bits(m.get("external_ids") or {}))
    show = m.get("path_lrps") or []
    alln = m.get("lrps") or []
    for p in show[:8]:
        bit = f"LRP {p.get('name') or ''} uuid {p.get('lrp_uuid') or ''}"
        bit += f" MAC {p.get('mac') or ''} {p.get('cidr') or ''}"
        if p.get("peer"):
            bit += f" peer {p.get('peer')}"
        if p.get("is_ext_gw"):
            bit += " ext-GW"
        lines.append(bit)
    if len(alln) > len(show):
        lines.append(f"LRPs {len(alln)} total (path {len(show)}; full Metadata)")
    elif alln:
        lines.append(f"LRPs {len(alln)}")
    pbr_n = len(hop.get("pbrs") or [])
    st_n = len(hop.get("static_routes") or [])
    conn_n = len(hop.get("routes") or [])
    nat_n = len(hop.get("nats") or [])
    lines.append(f"routes connected {conn_n} static {st_n} PBR {pbr_n} NAT {nat_n}")
    if gw:
        mac = hop.get("ext_mac") or ""
        cidr = hop.get("ext_cidr") or ""
        if mac or cidr:
            lines.append(f"IP {cidr} MAC {mac}")
        if hop.get("has_nat") or hop.get("nats"):
            lines.append("NAT")
    ha = []
    for r in hop.get("rc") or []:
        ha.append(
            f"{r.get('hostname') or r.get('chassis_name')} pri={r.get('priority')}"
        )
    if ha:
        lines.append("HA " + "; ".join(ha[:4]))
    return "<br/>".join(_esc(x) for x in lines if x)


def mermaid_topology(
    title: str,
    kind: str,
    start: Dict[str, Any],
    end: Dict[str, Any],
    hops: List[dict],
    from_acls: List[dict],
    to_acls: List[dict],
    acls_by_ls: List[Tuple[str, List[dict], List[dict]]],
    nats_by_lr: Optional[List[Tuple[str, List[dict]]]] = None,
    pbrs_by_lr: Optional[List[Tuple[str, List[dict]]]] = None,
) -> str:
    """VM→NIC→TAP→OVS brAtlas→Switch→… . Host boxes only if chassis differ."""
    nats_by_lr = nats_by_lr or []
    pbrs_by_lr = pbrs_by_lr or []
    s = vif_card(start) if start.get("kind") == "vif" else {}
    e = vif_card(end) if end.get("kind") == "vif" else {}
    s_host = (s.get("hostname") or s.get("host_ip") or "").strip()
    e_host = (e.get("hostname") or e.get("host_ip") or "").strip()
    s_vif = start.get("kind") == "vif"
    e_vif = end.get("kind") == "vif"
    split_hosts = bool(s_vif and e_vif and s_host and e_host and s_host != e_host)
    wrap_src = bool(s_vif and s_host and (split_hosts or not e_vif))
    wrap_dst = bool(e_vif and e_host and (split_hosts or not s_vif))
    overlay = None
    for hop in hops:
        if hop.get("kind") == "overlay":
            overlay = hop
            break
    if overlay is None and split_hosts:
        overlay = {
            "kind": "overlay",
            "encap_type": s.get("encap_type") or e.get("encap_type") or "geneve",
            "src": s.get("geneve_ip") or s.get("host_ip") or "",
            "dst": e.get("geneve_ip") or e.get("host_ip") or "",
        }
    if overlay is None and s_host:
        for hop in hops:
            if hop.get("kind") != "router":
                continue
            gh = hop.get("gw_host") or {}
            ghn = (gh.get("hostname") or "").strip()
            if ghn and ghn != s_host:
                overlay = {
                    "kind": "overlay",
                    "encap_type": s.get("encap_type") or gh.get("encap_type") or "geneve",
                    "src": s.get("geneve_ip") or s.get("host_ip") or "",
                    "dst": gh.get("geneve_ip") or gh.get("host_ip") or "",
                }
                break

    ids: List[str] = []
    classes: Dict[str, str] = {}
    lines = [
        "**How to read:** left to right is packet flow. Blue stadium = VM. Rectangle = NIC, "
        "then TAP, then OVS port on brAtlas (ofport / datapath port / iface-id). "
        "Green cylinder = Switch (LS), orange hexagon = Router (LR) / External GW. "
        "Host subgraphs wrap compute VIF hops and every scale-out External GW Host "
        "(active RC vs standby). External GW label is MAC + IP/CIDR. "
        "Dashed yellow / pink / gray hang off a router = NAT / PBR / RC. "
        "Teal dashed = port group (policy applied-to). Gold dashed = address set (policy dest/src IPs). "
        "Purple dashed = Geneve when chassis differ. Red dashed = drop ACLs. "
        "Identity is UUID; names are display. `@port_group_*` and `$address_set_*` "
        "are rewritten to policy category / dest names in the ACL tables.",
        "",
        "```mermaid",
        "flowchart LR",
        "  %% required VIF hops: TAP_S OVS_S TAP_D OVS_D (OVS label always brAtlas)",
        "  classDef vm fill:#4C8BF5,stroke:#1a4fa0,color:#fff",
        "  classDef nic fill:#E8F0FE,stroke:#4C8BF5,color:#111",
        "  classDef sw fill:#34A853,stroke:#137333,color:#fff",
        "  classDef rt fill:#FB8C00,stroke:#E65100,color:#111",
        "  classDef nat fill:#FFF59D,stroke:#F9A825,color:#111,stroke-dasharray: 5 5",
        "  classDef pbr fill:#F8BBD0,stroke:#C2185B,color:#111,stroke-dasharray: 5 5",
        "  classDef rc fill:#BDBDBD,stroke:#616161,color:#111,stroke-dasharray: 5 5",
        "  classDef ext fill:#EA4335,stroke:#B31412,color:#fff",
        "  classDef ovl fill:#CE93D8,stroke:#7B1FA2,color:#111,stroke-dasharray: 5 5",
        "  classDef dropacl fill:#FCE8E6,stroke:#C5221F,color:#111,stroke-dasharray: 5 5",
        "  classDef tap fill:#E0F2F1,stroke:#00796B,color:#111",
        "  classDef ovs fill:#ECEFF1,stroke:#37474F,color:#111",
        "  classDef pg fill:#E0F7FA,stroke:#00838F,color:#111,stroke-dasharray: 5 5",
        "  classDef aset fill:#FFF8E1,stroke:#FF8F00,color:#111,stroke-dasharray: 5 5",
    ]
    seq = 0
    gw_i = {"n": 0}

    def emit(label: str, shape: str, cls: str, main: bool = True, nid: str = "") -> str:
        nonlocal seq
        if not nid:
            seq += 1
            nid = f"N{seq}"
        lab = _mlabel(label)
        if shape == "stadium":
            lines.append(f'  {nid}(["{lab}"])')
        elif shape == "cyl":
            lines.append(f'  {nid}[("{lab}")]')
        elif shape == "hex":
            lines.append(f'  {nid}{{{{"{lab}"}}}}')
        else:
            lines.append(f'  {nid}["{lab}"]')
        classes[nid] = cls
        if main:
            ids.append(nid)
        return nid

    def host_title(card: Dict[str, str], gw: bool = False, role: str = "") -> str:
        prefix = "External GW Host " if gw else "Host "
        bits = [prefix + (card.get("hostname") or "")]
        if role:
            bits[0] = bits[0] + f" ({role})"
        if card.get("chassis_uuid"):
            bits.append("chassis " + card["chassis_uuid"])
        if card.get("host_ip"):
            bits.append(card["host_ip"])
        if card.get("geneve_ip"):
            bits.append("geneve " + card["geneve_ip"])
        return "<br/>".join(_esc(b) for b in bits if b)

    def nic_label(card: Dict[str, str]) -> str:
        return (
            f"NIC {_esc(card.get('nic'))}<br/>"
            f"MAC {_esc(card.get('mac'))}<br/>IP {_esc(card.get('ip'))}"
        )

    def tap_label(card: Dict[str, str]) -> str:
        return f"TAP {_esc(card.get('tap') or '(missing)')}"

    def ovs_label(card: Dict[str, str]) -> str:
        ofp = _esc(card.get("ofport") or card.get("ofport") or "?")
        dp = _esc(card.get("dp_port") or card.get("dp_port") or "?")
        iface = _esc(card.get("iface_id") or card.get("lsp") or "")
        return (
            f"OVS brAtlas<br/>ofport {ofp} dp_port {dp}<br/>iface-id {iface}"
        )

    def emit_vif(card: Dict[str, str], leaving: bool, side: str) -> None:
        """Always VM, NIC, TAP, OVS brAtlas. Reverse order on enter."""
        nodes_src = [
            (f"VM_{side}", f"VM {_esc(card.get('vm'))}", "stadium", "vm"),
            (f"NIC_{side}", nic_label(card), "rect", "nic"),
            (f"TAP_{side}", tap_label(card), "rect", "tap"),
            (f"OVS_{side}", ovs_label(card), "rect", "ovs"),
        ]
        if not leaving:
            nodes_src.reverse()
        for nid, lab, shape, cls in nodes_src:
            emit(lab, shape, cls, nid=nid)

    def is_gw(hop: dict) -> bool:
        if hop.get("is_ext_gw"):
            return True
        n = (hop.get("name") or "").lower()
        return "gw-scale-out" in n and "router" in n

    def gw_rt_label(hop: dict, role: str) -> str:
        lab = lr_mermaid_label(hop, gw=True)
        if role and role not in lab:
            lab += f"<br/>{_esc(role)}"
        return lab

    def emit_rc_nodes(rid: str, rcs: List[dict], active: bool) -> None:
        ranked = sorted(rcs or [], key=lambda r: int(r.get("priority") or 0), reverse=True)
        for i, r in enumerate(ranked):
            if active:
                role = "active RC" if i == 0 else "HA standby"
            else:
                role = "standby scale-out"
            hn = r.get("hostname") or r.get("chassis_name") or ""
            cu = r.get("chassis_uuid") or r.get("chassis_name") or ""
            emit(
                f"RC {role}<br/>{_esc(hn)}<br/>chassis {_esc(cu)} pri={r.get('priority')}",
                "stadium",
                "rc",
                main=False,
            )
            lines.append(f"  {rid} -.-> N{seq}")

    def emit_gw_hosts(hop: dict) -> None:
        """Every scale-out host: active RC Host + each standby peer Host.

        idx=0 keeps TAP_GW / OVS_GW / RT_GW0 (northbound). Later GW hops on a
        two-VPC walk use TAP_GW1 / OVS_GW1 / … so mermaid IDs stay unique.
        """
        idx = gw_i["n"]
        gw_i["n"] += 1
        tag = "" if idx == 0 else str(idx)
        rcs = hop.get("rc") or []
        host = hop.get("gw_host") or gw_host_from_rc(rcs)
        ovs = hop.get("ovs") or {}
        peers = hop.get("scaleout_peers") or []
        rid_active = ""
        for i, peer in enumerate(peers):
            ph = peer.get("gw_host") or {}
            povs = peer.get("ovs") or {}
            title = host_title(ph, gw=True, role="standby scale-out")
            lines.append(f'  subgraph HGW{tag}p{i}["{title}"]')
            if povs.get("tap") or povs.get("ofport"):
                emit(
                    tap_label(povs),
                    "rect",
                    "tap",
                    main=False,
                    nid=f"TAP_GW{tag}p{i}",
                )
                emit(
                    ovs_label(povs),
                    "rect",
                    "ovs",
                    main=False,
                    nid=f"OVS_GW{tag}p{i}",
                )
            peer_nid = f"RT_GW{i}" if idx == 0 else f"RT_GW{tag}p{i}"
            pid = emit(
                gw_rt_label(peer, "standby scale-out"),
                "hex",
                "rt",
                main=False,
                nid=peer_nid,
            )
            emit_rc_nodes(pid, peer.get("rc") or [], active=False)
            lines.append("  end")
        wrap = bool(host.get("hostname") or host.get("chassis_uuid"))
        if wrap:
            lines.append(
                f'  subgraph HGW{tag}["{host_title(host, gw=True, role="active RC")}"]'
            )
        tap_id = "TAP_GW" if idx == 0 else f"TAP_GW{tag}"
        ovs_id = "OVS_GW" if idx == 0 else f"OVS_GW{tag}"
        emit(tap_label(ovs), "rect", "tap", nid=tap_id)
        emit(ovs_label(ovs), "rect", "ovs", nid=ovs_id)
        rid_active = emit(gw_rt_label(hop, "active RC"), "hex", "rt")
        nat_rows = hop.get("nats") or []
        if hop.get("has_nat") or nat_rows or hop.get("is_ext_gw"):
            emit(f"NAT {len(nat_rows)}", "rect", "nat", main=False)
            lines.append(f"  {rid_active} -.-> N{seq}")
        pbr_rows = hop.get("pbrs") or []
        if pbr_rows:
            emit(f"PBR {len(pbr_rows)}", "rect", "pbr", main=False)
            lines.append(f"  {rid_active} -.-> N{seq}")
        emit_rc_nodes(rid_active, rcs, active=True)
        if wrap:
            lines.append("  end")
        for i, _peer in enumerate(peers):
            peer_nid = f"RT_GW{i}" if idx == 0 else f"RT_GW{tag}p{i}"
            lines.append(f"  {rid_active} -.-> {peer_nid}")

    comp_id = "DOWN" if "own" in (title or "").lower() or title == "REVERSE" else "UP"
    comp_lab = "Downstream" if comp_id == "DOWN" else "Upstream"
    lines.append(f'  subgraph {comp_id}["{comp_lab} composite"]')
    layer = {"id": ""}

    def set_layer(lid: str, lab: str) -> None:
        if layer["id"] == lid:
            return
        if layer["id"]:
            lines.append("  end")
        layer["id"] = lid
        lines.append(f'  subgraph {lid}["{lab}"]')

    def close_layer() -> None:
        if layer["id"]:
            lines.append("  end")
            layer["id"] = ""

    set_layer("L2", "L2 stretch")
    if wrap_src:
        lines.append(f'  subgraph H1["{host_title(s)}"]')
    if s_vif:
        emit_vif(s, leaving=True, side="S")
    if wrap_src:
        lines.append("  end")

    first_sw = None
    seen_l3 = seen_gw = seen_ext = False
    rc_rows: List[Tuple[str, List[dict]]] = []
    for hop in hops:
        hk = hop.get("kind")
        if hk == "overlay":
            continue
        if hk == "switch":
            if hop.get("external_ls") or hop.get("localnet"):
                set_layer("EXT", "External")
                seen_ext = True
                tag = "Switch External localnet"
            else:
                set_layer("L2", "L2 stretch")
                tag = "Switch transit" if hop.get("transit") else "Switch"
            nid = emit(ls_mermaid_label(tag, hop), "cyl", "sw")
            if first_sw is None:
                first_sw = nid
        elif hk == "router":
            gw = is_gw(hop)
            if gw:
                set_layer("GW", "GW")
                seen_gw = True
                emit_gw_hosts(hop)
                continue
            set_layer("L3", "L3 routing / PBR")
            seen_l3 = True
            rlab = lr_mermaid_label(hop, gw=False)
            if hop.get("has_nat"):
                if "NAT" not in rlab:
                    rlab += "<br/>NAT"
            rid = emit(rlab, "hex", "rt")
            nat_rows = hop.get("nats") or []
            if hop.get("has_nat") or nat_rows:
                emit(f"NAT {len(nat_rows)}", "rect", "nat", main=False)
                lines.append(f"  {rid} -.-> N{seq}")
            pbr_rows = hop.get("pbrs") or []
            if pbr_rows:
                emit(f"PBR {len(pbr_rows)}", "rect", "pbr", main=False)
                lines.append(f"  {rid} -.-> N{seq}")
        elif hk == "external":
            set_layer("EXT", "External")
            seen_ext = True
            dip = hop.get("dest_ip") or end.get("dest_ip") or ""
            lab = "External / NAT GW" + (f"<br/>{_esc(dip)}" if dip else "")
            emit(lab, "stadium", "ext")

    set_layer("L2", "L2 stretch")
    if wrap_dst:
        lines.append(f'  subgraph H2["{host_title(e)}"]')
    if e_vif:
        emit_vif(e, leaving=False, side="D")
    elif end.get("kind") == "external":
        if not any(h.get("kind") == "external" for h in hops):
            set_layer("EXT", "External")
            seen_ext = True
            dip = end.get("dest_ip") or ""
            lab = "External / NAT GW" + (f"<br/>{_esc(dip)}" if dip else "")
            emit(lab, "stadium", "ext")
    if wrap_dst:
        lines.append("  end")

    if overlay and first_sw:
        set_layer("L2", "L2 stretch")
        enc = _esc(overlay.get("encap_type") or "geneve")
        src_ip = _esc(overlay.get("src") or s.get("geneve_ip") or "")
        dst_ip = _esc(overlay.get("dst") or e.get("geneve_ip") or "")
        emit(f"Overlay {enc}<br/>{src_ip} to {dst_ip}", "rect", "ovl", main=False)
        lines.append(f"  {first_sw} -.-> N{seq}")

    if not seen_l3:
        set_layer("L3", "L3 routing / PBR")
        emit("L3 N/A", "rect", "rt", main=False)
    if not seen_gw:
        set_layer("GW", "GW")
        emit("GW N/A", "rect", "nat", main=False)
    if not seen_ext:
        set_layer("EXT", "External")
        emit("External N/A", "rect", "ext", main=False)

    drop_from = [a for a in from_acls if (a.get("action") or "") == "drop"]
    drop_to = [a for a in to_acls if (a.get("action") or "") == "drop"]
    pgs, asets = refs_from_acls(list(from_acls) + list(to_acls))
    set_layer("ACL", "ACL Policy")
    if first_sw:
        for pg in pgs:
            emit(port_group_label(pg), "rect", "pg", main=False)
            lines.append(f"  {first_sw} -.-> N{seq}")
        for aset in asets:
            emit(address_set_label(aset), "rect", "aset", main=False)
            lines.append(f"  {first_sw} -.-> N{seq}")
    if first_sw and (drop_from or drop_to):
        top = drop_from[0] if drop_from else drop_to[0]
        emit(
            f"ACL drop pri={top.get('priority')}<br/>"
            f"from-lport {len(drop_from)} / to-lport {len(drop_to)}",
            "rect",
            "dropacl",
            main=False,
        )
        lines.append(f"  {first_sw} -.-> N{seq}")
    if not pgs and not asets and not drop_from and not drop_to:
        emit("ACL tables below", "rect", "pg", main=False)
    close_layer()
    lines.append("  end")

    for a, b in zip(ids, ids[1:]):
        lines.append(f"  {a} --> {b}")
    for nid, cls in classes.items():
        lines.append(f"  class {nid} {cls}")
    lines.append("```")
    lines.append("")
    if wrap_src or wrap_dst or any(
        (h.get("gw_host") or {}).get("hostname") for h in hops if h.get("kind") == "router"
    ):
        host_note = (
            "Host boxes wrap VM+NIC+TAP+OVS brAtlas when chassis differ. "
            "Scale-out draws every External GW Host (active RC vs standby), "
            "with TAP_GW / OVS brAtlas when dataplane has them. "
            "External GW node is MAC + IP/CIDR."
        )
    else:
        host_note = (
            "Same chassis: no Host boxes; TAP and OVS brAtlas stay on the chain."
        )
    lines.append(f"_{title} `{kind}`. {host_note}_")
    lines.append("")
    lines.extend(format_metadata_md(title, hops))
    lines.append("")
    lines.append(
        f"#### {title} — full from-lport ACL list (leave source NIC) — {len(from_acls)} rules"
    )
    lines.extend(acl_table(from_acls))
    lines.append("")
    lines.append(
        f"#### {title} — full to-lport ACL list (enter dest NIC) — {len(to_acls)} rules"
    )
    lines.extend(acl_table(to_acls))
    if len(acls_by_ls) > 1:
        for ls_name, fr, to in acls_by_ls:
            if not fr and not to:
                continue
            lines.append("")
            lines.append(
                f"#### {title} — switch `{_esc(ls_name)}` from-lport (full) — {len(fr)} rules"
            )
            lines.extend(acl_table(fr))
            lines.append("")
            lines.append(
                f"#### {title} — switch `{_esc(ls_name)}` to-lport (full) — {len(to)} rules"
            )
            lines.extend(acl_table(to))
    for hop in hops:
        if hop.get("kind") != "router":
            continue
        lr_name = hop.get("name") or hop.get("uuid") or ""
        ext = " ext-GW" if hop.get("is_ext_gw") else ""
        lines.append("")
        lines.append(f"#### {title} — router `{_esc(lr_name)}`{ext}")
        lines.append("")
        nat_rows = hop.get("nats") or []
        lines.append(
            f"#### {title} — NAT on router `{_esc(lr_name)}` (full) — {len(nat_rows)} rows"
        )
        lines.extend(nat_table(nat_rows))
        pbr_rows = hop.get("pbrs") or []
        lines.append("")
        lines.append(
            f"#### {title} — PBR on router `{_esc(lr_name)}` (full) — {len(pbr_rows)} rows"
        )
        lines.extend(pbr_table(pbr_rows))
        route_rows = hop.get("routes") or []
        lines.append("")
        lines.append(
            f"#### {title} — connected routes on router `{_esc(lr_name)}` (full) — "
            f"{len(route_rows)} rows"
        )
        lines.extend(route_table(route_rows))
        static_rows = hop.get("static_routes") or []
        lines.append("")
        lines.append(
            f"#### {title} — static routes on router `{_esc(lr_name)}` (full) — "
            f"{len(static_rows)} rows"
        )
        lines.extend(static_table(static_rows))
        gw_rows = hop.get("rc") or []
        lines.append("")
        lines.append(
            f"#### {title} — GW chassis (RC) on router `{_esc(lr_name)}` (full) — "
            f"{len(gw_rows)} rows"
        )
        lines.extend(rc_table(gw_rows, active=True))
        path_lrp_rows = hop.get("path_lrps") or []
        lines.append("")
        lines.append(
            f"#### {title} — path LRPs on router `{_esc(lr_name)}` (full) — "
            f"{len(path_lrp_rows)} rows"
        )
        lines.extend(lrp_table(path_lrp_rows))
        if hop.get("ext_mac") or hop.get("ext_cidr"):
            lines.append("")
            lines.append(
                f"#### {title} — External GW MAC/IP on `{_esc(lr_name)}`"
            )
            lines.append("")
            lines.append(
                f"- LRP `{hop.get('ext_lrp') or ''}` MAC `{hop.get('ext_mac') or ''}` "
                f"IP `{hop.get('ext_cidr') or ''}`"
            )
        for peer in hop.get("scaleout_peers") or []:
            ph = peer.get("gw_host") or {}
            lines.append("")
            lines.append(
                f"#### {title} — scale-out peer `{_esc(peer.get('name'))}` "
                f"(standby) host `{ph.get('hostname') or ''}` chassis "
                f"`{ph.get('chassis_uuid') or ''}`"
            )
            lines.append("")
            lines.append(
                f"- External GW MAC `{peer.get('ext_mac') or ''}` "
                f"IP `{peer.get('ext_cidr') or ''}`"
            )
            lines.extend(rc_table(peer.get("rc") or [], active=False))
    return "\n".join(lines)


def acl_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | pri | action | direction | attach | match |",
        "|---|-----|--------|-----------|--------|-------|",
    ]
    for i, a in enumerate(items, 1):
        match = rewrite_match(a.get("match") or "").replace("|", "\\|")
        action = a.get("action") or ""
        if action == "drop":
            action = "**drop**"
        out.append(
            f"| {i} | {a.get('priority')} | {action} | "
            f"{a.get('direction')} | {a.get('src')} | `{match}` |"
        )
    return out


def nat_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | type | external_ip | logical_ip | logical_port |",
        "|---|------|-------------|------------|--------------|",
    ]
    for i, n in enumerate(items, 1):
        out.append(
            f"| {i} | {n.get('type')} | `{n.get('external_ip') or ''}` | "
            f"`{n.get('logical_ip') or ''}` | `{n.get('logical_port') or ''}` |"
        )
    return out


def pbr_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | pri | action | match | nexthop |",
        "|---|-----|--------|-------|---------|",
    ]
    for i, p in enumerate(items, 1):
        match = (p.get("match") or "").replace("|", "\\|")
        nh = p.get("nexthop") or ""
        extra = p.get("nexthops") or []
        if extra and not nh:
            nh = ",".join(str(x) for x in extra)
        out.append(
            f"| {i} | {p.get('priority')} | {p.get('action')} | `{match}` | `{nh}` |"
        )
    return out


def route_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | lrp | cidr | ext_gw |",
        "|---|-----|------|--------|",
    ]
    for i, r in enumerate(items, 1):
        out.append(
            f"| {i} | `{r.get('lrp') or ''}` | `{r.get('cidr') or ''}` | "
            f"{r.get('ext_gw') or ''} |"
        )
    return out


def static_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | prefix | nexthop | policy | output_port |",
        "|---|--------|---------|--------|-------------|",
    ]
    for i, r in enumerate(items, 1):
        out.append(
            f"| {i} | `{r.get('prefix') or ''}` | `{r.get('nexthop') or ''}` | "
            f"`{r.get('policy') or ''}` | `{r.get('output_port') or ''}` |"
        )
    return out


def rc_table(items: List[dict], active: bool = True) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | role | hostname | chassis_uuid | chassis_name | priority |",
        "|---|------|----------|--------------|--------------|----------|",
    ]
    ranked = sorted(items, key=lambda r: int(r.get("priority") or 0), reverse=True)
    for i, r in enumerate(ranked, 1):
        if active:
            role = "active RC" if i == 1 else "HA standby"
        else:
            role = "standby scale-out"
        out.append(
            f"| {i} | {role} | `{r.get('hostname') or ''}` | "
            f"`{r.get('chassis_uuid') or ''}` | `{r.get('chassis_name') or r.get('chassis_name') or ''}` | "
            f"{r.get('priority')} |"
        )
    return out


def lrp_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | role | lrp | mac | cidr | ext_gw |",
        "|---|------|-----|-----|------|--------|",
    ]
    for i, r in enumerate(items, 1):
        out.append(
            f"| {i} | {r.get('role') or ''} | `{r.get('lrp') or ''}` | "
            f"`{r.get('mac') or ''}` | `{r.get('cidr') or ''}` | "
            f"{r.get('ext_gw') or ''} |"
        )
    return out


def format_metadata_md(title: str, hops: List[dict]) -> List[str]:
    """Complete LS/LR fields from flow_ovn (+ dump options) under the mermaid."""
    out = [f"#### {title} — Metadata (LS / LR from flow_ovn)", ""]
    seen_ls = set()
    seen_lr = set()
    for hop in hops:
        if hop.get("kind") == "switch":
            uid = hop.get("uuid") or ""
            if uid in seen_ls:
                continue
            seen_ls.add(uid)
            m = hop.get("meta") or {}
            out.append(f"##### Switch `{hop.get('name')}` uuid `{uid}`")
            out.append("")
            blob = {
                "ls_uuid": uid,
                "name": hop.get("name"),
                "transit": bool(hop.get("transit")),
                "localnet": bool(hop.get("localnet") or hop.get("external_ls")),
                "datapath_uuid": m.get("datapath_uuid"),
                "tunnel_key": m.get("tunnel_key"),
                "other_config": m.get("other_config") or {},
                "external_ids": m.get("external_ids") or {},
                "ports": m.get("ports") or [],
            }
            out.append("```json")
            out.append(json.dumps(blob, indent=2, default=str))
            out.append("```")
            out.append("")
            ports = m.get("ports") or []
            out.append(f"Path LSPs — {len(ports)} rows")
            if not ports:
                out.append("(none)")
            else:
                out.append("| # | type | lsp | uuid | mac | ip | chassis |")
                out.append("|---|------|-----|------|-----|----|---------|")
                for i, p in enumerate(ports, 1):
                    chs = p.get("hostname") or p.get("chassis_uuid") or ""
                    out.append(
                        f"| {i} | {p.get('type')} | `{p.get('name')}` | "
                        f"`{p.get('lsp_uuid')}` | `{p.get('mac')}` | "
                        f"`{p.get('ip')}` | `{chs}` |"
                    )
            out.append("")
        elif hop.get("kind") == "router":
            uid = hop.get("uuid") or ""
            if uid in seen_lr:
                continue
            seen_lr.add(uid)
            m = hop.get("meta") or {}
            out.append(f"##### Router `{hop.get('name')}` uuid `{uid}`")
            out.append("")
            blob = {
                "lr_uuid": uid,
                "name": hop.get("name"),
                "has_nat": hop.get("has_nat"),
                "datapath_uuid": m.get("datapath_uuid"),
                "tunnel_key": m.get("tunnel_key"),
                "options": m.get("options") or {},
                "external_ids": m.get("external_ids") or {},
                "lrp_count": len(m.get("lrps") or []),
            }
            out.append("```json")
            out.append(json.dumps(blob, indent=2, default=str))
            out.append("```")
            out.append("")
            lrps = m.get("lrps") or []
            out.append(f"Every LRP — {len(lrps)} rows")
            if not lrps:
                out.append("(none)")
            else:
                out.append(
                    "| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |"
                )
                out.append(
                    "|---|-----|------|-----|------|------|--------|----------|"
                )
                for i, p in enumerate(lrps, 1):
                    out.append(
                        f"| {i} | `{p.get('name')}` | `{p.get('lrp_uuid')}` | "
                        f"`{p.get('mac')}` | `{p.get('cidr')}` | "
                        f"`{p.get('peer')}` | "
                        f"{'yes' if p.get('is_ext_gw') else ''} | "
                        f"`{p.get('ha_chassis_group') or ''}` |"
                    )
            out.append("")
            for peer in hop.get("scaleout_peers") or []:
                puid = peer.get("uuid") or ""
                if puid in seen_lr:
                    continue
                seen_lr.add(puid)
                pm = peer.get("meta") or {}
                out.append(
                    f"##### Router (standby scale-out) `{peer.get('name')}` uuid `{puid}`"
                )
                out.append("")
                pblob = {
                    "lr_uuid": puid,
                    "name": peer.get("name"),
                    "datapath_uuid": pm.get("datapath_uuid"),
                    "tunnel_key": pm.get("tunnel_key"),
                    "options": pm.get("options") or {},
                    "external_ids": pm.get("external_ids") or {},
                    "ext_mac": peer.get("ext_mac"),
                    "ext_cidr": peer.get("ext_cidr"),
                    "lrp_count": len(pm.get("lrps") or []),
                }
                out.append("```json")
                out.append(json.dumps(pblob, indent=2, default=str))
                out.append("```")
                out.append("")
                plrps = pm.get("lrps") or []
                out.append(f"Every LRP — {len(plrps)} rows")
                if not plrps:
                    out.append("(none)")
                else:
                    out.append(
                        "| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |"
                    )
                    out.append(
                        "|---|-----|------|-----|------|------|--------|----------|"
                    )
                    for i, p in enumerate(plrps, 1):
                        out.append(
                            f"| {i} | `{p.get('name')}` | `{p.get('lrp_uuid')}` | "
                            f"`{p.get('mac')}` | `{p.get('cidr')}` | "
                            f"`{p.get('peer')}` | "
                            f"{'yes' if p.get('is_ext_gw') else ''} | "
                            f"`{p.get('ha_chassis_group') or ''}` |"
                        )
                out.append("")
    return out


def _dedup_acls(rows: List[dict]) -> List[dict]:
    seen = set()
    out = []
    for a in rows:
        uid = a.get("acl_uuid")
        if uid in seen:
            continue
        seen.add(uid)
        out.append(a)
    return out


def build_hops(
    g: Dict[str, Any],
    nodes: List[Tuple[Node, Optional[dict]]],
    start_vif: Dict[str, Any],
    end_vif: Dict[str, Any],
    dst: Dict[str, Any],
    reverse: bool,
) -> Tuple[
    List[dict],
    List[dict],
    List[dict],
    List[Tuple[str, List[dict], List[dict]]],
    List[Tuple[str, List[dict]]],
    List[Tuple[str, List[dict]]],
]:
    hops: List[dict] = []
    all_from: List[dict] = []
    all_to: List[dict] = []
    acls_by_ls: List[Tuple[str, List[dict], List[dict]]] = []
    nats_by_lr: List[Tuple[str, List[dict]]] = []
    pbrs_by_lr: List[Tuple[str, List[dict]]] = []
    src_ls = start_vif.get("ls_uuid")
    dst_ls = end_vif.get("ls_uuid") if end_vif.get("kind") == "vif" else None
    in_lsp = (start_vif.get("lsp") or {}).get("lsp_uuid") or ZERO
    out_lsp = (end_vif.get("lsp") or {}).get("lsp_uuid") or ZERO
    path_ls = path_ls_uuids(nodes, g)
    path_lrs = {n[1] for n, _m in nodes if n[0] == "lr"}
    path_lsps = {x for x in (in_lsp, out_lsp) if x and x != ZERO}
    for e in g.get("ls_lr") or []:
        if e.get("ls_uuid") in path_ls and e.get("lsp_uuid"):
            path_lsps.add(e["lsp_uuid"])

    def add_switch(uid: str, rec: dict, meta: Optional[dict], transit: bool) -> None:
        a_in = in_lsp if uid == src_ls else ZERO
        a_out = out_lsp if uid == dst_ls else ZERO
        if meta and meta.get("kind") == "ls_lr" and meta.get("ls_uuid") == uid:
            if a_out == ZERO:
                a_out = meta.get("lsp_uuid") or ZERO
            if a_in == ZERO:
                a_in = meta.get("lsp_uuid") or ZERO
        rows = acls_for_ls(uid, a_in, a_out)
        fr, to = split_acls(rows, reverse)
        all_from.extend(fr)
        all_to.extend(to)
        name = rec.get("name") or uid
        localnet = uid in (g.get("localnet_ls") or set())
        acls_by_ls.append((name, fr, to))
        hops.append(
            {
                "kind": "switch",
                "name": name,
                "uuid": uid,
                "acl_n": len(rows),
                "transit": transit or is_transit_ls(name),
                "external_ls": localnet,
                "localnet": localnet,
                "stretch": stretch(uid),
                "meta": gather_ls_meta(g, uid, path_lsp=path_lsps, path_lr=path_lrs),
            }
        )

    def add_router(uid: str, rec: dict, meta: Optional[dict]) -> None:
        lrp_name, nets, mac = "", "", ""
        is_ext = rec.get("has_nat") in (1, "1")
        if meta and meta.get("kind") == "ls_lr":
            lrp = g["lrp_by_uuid"].get(meta.get("lrp_uuid") or "", {})
            lrp_name = meta.get("lrp_name") or lrp.get("name") or ""
            nets = lrp.get("networks") or ""
            mac = lrp.get("mac") or ""
            if lrp.get("is_ext_gw") in (1, "1"):
                is_ext = True
        for p in g.get("lrp") or []:
            if p.get("lr_uuid") == uid and p.get("is_ext_gw") in (1, "1"):
                is_ext = True
        nat_rows = nats(uid)
        pbr_rows = pbrs(uid)
        rc_rows_lr = rc_for_lr(g, uid)
        name = rec.get("name") or uid
        path_ls = path_ls_uuids(nodes, g)
        path_lrps = lrps_on_path(g, uid, path_ls, name)
        ext = ext_gw_lrp(g, uid) if is_ext or ("gw-scale-out" in name.lower()) else {}
        gw_host = gw_host_from_rc(rc_rows_lr) if rc_rows_lr else {}
        ovs = gw_dataplane(g, uid, gw_host) if gw_host else {}
        peers = (
            scaleout_siblings(g, uid)
            if is_ext or ("gw-scale-out" in name.lower() and "router" in name.lower())
            else []
        )
        static_rows = static_routes_for_lr(uid)
        meta = gather_lr_meta(g, uid, path_ls=path_ls)
        hops.append(
            {
                "kind": "router",
                "name": name,
                "uuid": uid,
                "lrp": lrp_name,
                "nets": nets,
                "mac": mac,
                "has_nat": rec.get("has_nat") in (1, "1") or bool(nat_rows),
                "is_ext_gw": is_ext,
                "nats": nat_rows,
                "pbrs": pbr_rows,
                "rc": rc_rows_lr,
                "routes": routes_for_lr(g, uid),
                "static_routes": static_rows,
                "path_lrps": path_lrps,
                "gw_host": gw_host,
                "ovs": ovs,
                "scaleout_peers": peers,
                "meta": meta,
                **ext,
            }
        )
        nats_by_lr.append((name, nat_rows))
        pbrs_by_lr.append((name, pbr_rows))

    def maybe_transit(meta: Optional[dict], before: bool) -> None:
        if not meta or meta.get("kind") != "lr_lr":
            return
        via_ls = meta.get("via_ls_uuid")
        if not via_ls or via_ls == ZERO:
            return
        if before and reverse:
            return
        if not before and not reverse:
            return
        rec = g["ls"].get(via_ls, {}) or {"name": via_ls}
        add_switch(via_ls, rec, None, is_transit_ls(rec.get("name") or ""))

    if reverse and dst.get("kind") == "external":
        hops.append({"kind": "external", "dest_ip": dst.get("dest_ip") or ""})

    for node, meta in nodes:
        nkind, uid = node
        if nkind == "ls":
            add_switch(uid, g["ls"].get(uid, {}), meta, False)
        else:
            maybe_transit(meta, before=True)
            add_router(uid, g["lr"].get(uid, {}), meta)
            maybe_transit(meta, before=False)

    if dst.get("kind") == "external" and not reverse:
        hops.append({"kind": "external", "dest_ip": dst.get("dest_ip") or ""})
    elif end_vif.get("kind") == "external":
        if not any(h.get("kind") == "external" for h in hops):
            hops.append({"kind": "external", "dest_ip": dst.get("dest_ip") or ""})

    hs = vif_card(start_vif) if start_vif.get("kind") == "vif" else {}
    he = vif_card(end_vif) if end_vif.get("kind") == "vif" else {}
    sh = (hs.get("hostname") or hs.get("host_ip") or "").strip()
    eh = (he.get("hostname") or he.get("host_ip") or "").strip()
    gw_h = ""
    gw_g = ""
    gw_enc = "geneve"
    for h in hops:
        if h.get("kind") != "router":
            continue
        gh = h.get("gw_host") or {}
        if gh.get("hostname"):
            gw_h = (gh.get("hostname") or "").strip()
            gw_g = gh.get("geneve_ip") or gh.get("host_ip") or ""
            gw_enc = gh.get("encap_type") or "geneve"
            break
    if sh and eh and sh != eh:
        hops.append(
            {
                "kind": "overlay",
                "encap_type": hs.get("encap_type") or he.get("encap_type") or "geneve",
                "src": hs.get("geneve_ip") or hs.get("host_ip") or "",
                "dst": he.get("geneve_ip") or he.get("host_ip") or "",
            }
        )
    elif sh and gw_h and sh != gw_h:
        hops.append(
            {
                "kind": "overlay",
                "encap_type": hs.get("encap_type") or gw_enc,
                "src": hs.get("geneve_ip") or hs.get("host_ip") or "",
                "dst": gw_g,
            }
        )
    return (
        hops,
        _dedup_acls(all_from),
        _dedup_acls(all_to),
        acls_by_ls,
        nats_by_lr,
        pbrs_by_lr,
    )


def render_path(
    g: Dict[str, Any],
    src: Dict[str, Any],
    dst: Dict[str, Any],
    path: List[Tuple[Node, Optional[dict]]],
    reverse: bool,
) -> str:
    lines: List[str] = []
    kind = classify(path)
    if dst.get("kind") == "external":
        kind = "northbound"
    title = "Downstream" if reverse else "Upstream"
    lines.append(f"## {title} composite")
    lines.append(f"=== {title} ({kind}) ===")
    if reverse:
        lines.append(f"src: {fmt_ep(dst)}")
        lines.append(f"dst: {fmt_ep(src)}")
    else:
        lines.append(f"src: {fmt_ep(src)}")
        lines.append(f"dst: {fmt_ep(dst)}")
    nodes = list(reversed(path)) if reverse else path
    hop = 1
    start_vif = src if not reverse else dst
    end_vif = dst if not reverse else src
    if reverse and dst.get("kind") == "external":
        lines.append(f"  {hop}. EXTERNAL (NAT / ext GW)")
        hop += 1
    if start_vif.get("kind") == "vif":
        lines.append(f"  {hop}. VIF {fmt_ep(start_vif)}")
        hop += 1
    src_ls = start_vif.get("ls_uuid")
    dst_ls = end_vif.get("ls_uuid") if end_vif.get("kind") == "vif" else None
    in_lsp = (start_vif.get("lsp") or {}).get("lsp_uuid") or ZERO
    out_lsp = (end_vif.get("lsp") or {}).get("lsp_uuid") or ZERO
    for node, meta in nodes:
        nkind, uid = node
        if nkind == "ls":
            rec = g["ls"].get(uid, {})
            lines.append(f"  {hop}. LS {rec.get('name', '')} uuid={uid}")
            st = stretch(uid)
            if st:
                bits = [
                    f"{r['hostname'] or r['chassis_uuid'][:8]}:{r['encap_type']}:{r['encap_ip']}"
                    for r in st[:8]
                ]
                extra = f" (+{len(st) - 8})" if len(st) > 8 else ""
                lines.append(f"       stretch {', '.join(bits)}{extra}")
            a_in = in_lsp if uid == src_ls else ZERO
            a_out = out_lsp if uid == dst_ls else ZERO
            if meta and meta.get("kind") == "ls_lr" and meta.get("ls_uuid") == uid:
                if a_out == ZERO:
                    a_out = meta.get("lsp_uuid") or ZERO
                if a_in == ZERO:
                    a_in = meta.get("lsp_uuid") or ZERO
            show_acls(lines, acls_for_ls(uid, a_in, a_out), reverse)
            hop += 1
        else:
            rec = g["lr"].get(uid, {})
            lines.append(
                f"  {hop}. LR {rec.get('name', '')} uuid={uid} has_nat={rec.get('has_nat')}"
            )
            if meta and meta.get("kind") == "ls_lr":
                lrp = g["lrp_by_uuid"].get(meta.get("lrp_uuid") or "", {})
                lines.append(
                    f"       LRP {meta.get('lrp_name')} mac={lrp.get('mac', '')} "
                    f"nets={lrp.get('networks')}"
                )
            if meta and meta.get("kind") == "lr_lr":
                via = meta.get("via")
                via_ls = meta.get("via_ls_uuid")
                if via_ls and via_ls != ZERO:
                    lsn = g["ls"].get(via_ls, {}).get("name", via_ls)
                    lines.append(f"       via {via} LS {lsn} uuid={via_ls}")
                    st = stretch(via_ls)
                    if st:
                        bits = [
                            f"{r['hostname'] or r['chassis_uuid'][:8]}:{r['encap_type']}"
                            for r in st[:6]
                        ]
                        lines.append(f"       transit stretch {', '.join(bits)}")
                    show_acls(lines, acls_for_ls(via_ls, ZERO, ZERO), reverse)
                else:
                    lines.append(f"       via {via}")
            for p in pbrs(uid):
                lines.append(
                    f"       PBR pri={p['priority']} {p['action']} "
                    f"match={(p['match'] or '')[:120]} nexthop={p['nexthop']}"
                )
            for r in rc_for_lr(g, uid):
                lines.append(
                    f"       RC chassis={r.get('chassis_name')} pri={r.get('priority')}"
                )
            for n in nats(uid):
                lines.append(
                    f"       NAT {n['type']} ext={n['external_ip']} "
                    f"log={n['logical_ip']} port={n['logical_port']}"
                )
            hop += 1
    if end_vif.get("kind") == "vif":
        lines.append(f"  {hop}. VIF {fmt_ep(end_vif)}")
    elif dst.get("kind") == "external" and not reverse:
        lines.append(f"  {hop}. EXTERNAL (NAT / ext GW)")

    hops, from_uniq, to_uniq, acls_by_ls, nats_by_lr, pbrs_by_lr = build_hops(
        g, nodes, start_vif, end_vif, dst, reverse
    )
    lines.append("")
    lines.append(f"## Mermaid {title} composite")
    lines.append(
        mermaid_topology(
            title,
            kind,
            start_vif,
            end_vif,
            hops,
            from_uniq,
            to_uniq,
            acls_by_ls,
            nats_by_lr,
            pbrs_by_lr,
        )
    )
    return "\n".join(lines)


def external_targets(g: Dict[str, Any]) -> List[Node]:
    """NAT / ext-GW routers only. Skip localnet-on-same-LS (that is still L2)."""
    out: List[Node] = []
    seen = set()
    for uid, rec in g["lr"].items():
        if rec.get("has_nat") in (1, "1"):
            node = ("lr", uid)
            if node not in seen:
                seen.add(node)
                out.append(node)
    for p in g["lrp"]:
        if p.get("is_ext_gw") in (1, "1"):
            node = ("lr", p["lr_uuid"])
            if node not in seen:
                seen.add(node)
                out.append(node)
    return out


def start_node(ep: Dict[str, Any]) -> Node:
    if ep.get("kind") == "vif" or ep.get("kind") == "ls":
        return ("ls", ep["ls_uuid"])
    return ("lr", ep["lr_uuid"])


def dest_nodes(g: Dict[str, Any], ep: Dict[str, Any]) -> List[Node]:
    if ep.get("kind") == "external":
        t = external_targets(g)
        if not t:
            raise SystemExit("no external/NAT router in dump")
        return t
    if ep.get("kind") in ("vif", "ls"):
        return [("ls", ep["ls_uuid"])]
    return [("lr", ep["lr_uuid"])]


def pg_names_for_lsp(lsp_uuid: str) -> List[str]:
    if not lsp_uuid or lsp_uuid == ZERO:
        return []
    return [
        r["name"]
        for r in ch(
            "SELECT pg.name AS name FROM ovn_pg_port AS pp "
            "INNER JOIN ovn_pg AS pg ON pg.pg_uuid = pp.pg_uuid "
            f"WHERE pp.lsp_uuid = '{lsp_uuid}'"
        )
    ]


def _ip_in_spec(ip: str, spec: str) -> bool:
    raw = (ip or "").split("/")[0]
    spec = (spec or "").strip()
    if not raw or not spec:
        return False
    try:
        addr = ipaddress.ip_address(raw)
        if "/" in spec:
            return addr in ipaddress.ip_network(spec, strict=False)
        return addr == ipaddress.ip_address(spec.split("/")[0])
    except ValueError:
        return raw == spec.split("/")[0]


def _port_in_match(match: str, kind: str, dport: Optional[int]) -> bool:
    if dport is None:
        return False
    for a, b in re.findall(
        rf"{kind}\.dst\s*>=\s*(\d+)\s*&&\s*{kind}\.dst\s*<=\s*(\d+)", match
    ):
        if int(a) <= dport <= int(b):
            return True
    for x in re.findall(rf"{kind}\.dst\s*==\s*(\d+)", match):
        if int(x) == dport:
            return True
    return False


def acl_matches(acl: dict, pkt: Dict[str, Any]) -> bool:
    """Conservative OVN match for one IPv4 packet (internet / east-west)."""
    match = acl.get("match") or ""
    if "udp.src == 67" in match:
        return False
    ip_ver = pkt.get("ip_ver") or "ip4"
    if ip_ver == "ip4" and "ip6" in match and "ip4" not in match:
        return False
    if ip_ver == "ip6" and "ip4" in match and "ip6" not in match:
        return False
    in_pgs = set(pkt.get("inport_pgs") or [])
    out_pgs = set(pkt.get("outport_pgs") or [])
    for pg in re.findall(r"inport\s*==\s*@(port_group_[0-9a-fA-F_]+)", match):
        if pg not in in_pgs:
            return False
    for pg in re.findall(r"outport\s*==\s*@(port_group_[0-9a-fA-F_]+)", match):
        if pg not in out_pgs:
            return False
    src_ip = pkt.get("src_ip") or ""
    dst_ip = pkt.get("dst_ip") or ""
    for aset in re.findall(r"ip4\.dst\s*==\s*\$(address_set_[0-9a-fA-F_]+)", match):
        if not ip_in_address_set(dst_ip, aset):
            return False
    for aset in re.findall(r"ip4\.src\s*==\s*\$(address_set_[0-9a-fA-F_]+)", match):
        if not ip_in_address_set(src_ip, aset):
            return False
    proto = pkt.get("proto")
    dport = pkt.get("dport")
    locked = any(
        x in match
        for x in ("ip.proto", "tcp.dst", "udp.dst", "icmp4", "icmp6", "tcp.src", "udp.src")
    )
    if locked:
        if proto == 1:
            if "icmp" not in match and "ip.proto == 1" not in match:
                return False
        elif proto == 6:
            if "tcp || udp || icmp" in match and "tcp.dst" not in match:
                return True
            if "ip.proto == 6" not in match and "tcp.dst" not in match:
                return False
            if "tcp.dst" in match and not _port_in_match(match, "tcp", dport):
                return False
        elif proto == 17:
            if "tcp || udp || icmp" in match and "udp.dst" not in match:
                return True
            if "ip.proto == 17" not in match and "udp.dst" not in match:
                return False
            if "udp.dst" in match and not _port_in_match(match, "udp", dport):
                return False
    return True


def first_acl_hit(acls: List[dict], pkt: Dict[str, Any]) -> Optional[dict]:
    rows = sorted(acls, key=lambda a: int(a.get("priority") or 0), reverse=True)
    for a in rows:
        if acl_matches(a, pkt):
            return a
    return None


def _acl_one_liner(a: Optional[dict]) -> str:
    if not a:
        return "(no matching ACL — implicit allow / next hop)"
    match = rewrite_match(a.get("match") or "")
    if len(match) > 160:
        match = match[:157] + "..."
    return (
        f"pri {a.get('priority')} **{a.get('action')}** `{a.get('direction')}` "
        f"[{a.get('src')}] `{match}`"
    )


def chassis_label(name: str) -> str:
    if not name:
        return ""
    info = chassis_info(name)
    host = info.get("hostname") or ""
    uid = info.get("chassis_uuid") or name
    if host and host != uid:
        return f"{host} ({uid})"
    return host or uid or name


def render_story(
    g: Dict[str, Any],
    src: Dict[str, Any],
    dst: Dict[str, Any],
    path: List[Tuple[Node, Optional[dict]]],
) -> str:
    """Open every trace with a hop-by-hop RCA, not a table dump."""
    dest_ip = dst.get("dest_ip") or ""
    hops, _from, _to, acls_by_ls, nats_by_lr, pbrs_by_lr = build_hops(
        g, path, src, dst, dst, reverse=False
    )
    card = vif_card(src) if src.get("kind") == "vif" else {}
    lsp_uuid = (src.get("lsp") or {}).get("lsp_uuid") or card.get("lsp_uuid") or ""
    src_pgs = pg_names_for_lsp(lsp_uuid)
    vm_ip = card.get("ip") or ""
    vm_name = card.get("vm") or ""
    nic_uuid = card.get("nic") or ""
    vm_uuid = (src.get("nic") or {}).get("vm_uuid") or ""
    mac = card.get("mac") or (src.get("nic") or {}).get("mac") or ""
    ls_uuid = card.get("ls_uuid") or ""
    tap = card.get("tap") or "(missing)"
    ofp = card.get("ofport") or "?"
    host = card.get("hostname") or card.get("host_ip") or ""
    dip = dest_ip or (vm_ip if dst.get("kind") == "vif" else "dst")
    dcard: Dict[str, str] = {}
    dst_pgs: List[str] = []
    if dst.get("kind") == "vif":
        dcard = vif_card(dst)
        dip = dcard.get("ip") or dip
        dst_pgs = pg_names_for_lsp(
            (dst.get("lsp") or {}).get("lsp_uuid") or dcard.get("lsp_uuid") or ""
        )

    pkt_up = {
        "ip_ver": "ip4",
        "src_ip": vm_ip,
        "dst_ip": dest_ip or dip,
        "inport_pgs": src_pgs,
        "outport_pgs": dst_pgs,
        "proto": 1,
        "dport": None,
    }
    pkt_dn = {
        "ip_ver": "ip4",
        "src_ip": dest_ip or dip,
        "dst_ip": vm_ip,
        "inport_pgs": dst_pgs,
        "outport_pgs": src_pgs,
        "proto": 1,
        "dport": None,
    }

    up_drop_ls = ""
    up_hit = None
    for ls_name, fr, _to_ls in acls_by_ls:
        hit = first_acl_hit(fr, pkt_up)
        if hit:
            up_hit = hit
            up_drop_ls = ls_name
            if (hit.get("action") or "") == "drop":
                break
            # allow on this switch — keep going; a later switch may still drop
            if (hit.get("action") or "").startswith("allow"):
                continue

    dn_drop_ls = ""
    dn_hit = None
    for ls_name, _fr, to_ls in reversed(list(acls_by_ls)):
        hit = first_acl_hit(to_ls, pkt_dn)
        if hit:
            dn_hit = hit
            dn_drop_ls = ls_name
            if (hit.get("action") or "") == "drop":
                break

    up_action = (up_hit or {}).get("action") or ""
    dn_action = (dn_hit or {}).get("action") or ""
    up_drops = up_action == "drop"
    dn_drops = dn_action == "drop"

    # Routing / NAT / PBR (what would happen if policy allowed)
    routers = [h for h in hops if h.get("kind") == "router"]
    tenants = [
        h
        for h in routers
        if "gw-scale-out" not in (h.get("name") or "").lower()
    ]
    gws = [
        h
        for h in routers
        if h.get("is_ext_gw")
        or is_gw_router(h.get("name") or "", h)
    ]
    tenant = tenants[0] if tenants else (routers[0] if routers else {})
    dest_tenant = tenants[-1] if len(tenants) > 1 else {}
    gw = gws[0] if gws else {}
    pbr_hit = None
    for p in tenant.get("pbrs") or []:
        m = p.get("match") or ""
        if "0.0.0.0/0" in m or not m:
            pbr_hit = p
            break
    snat = None
    for n in gw.get("nats") or []:
        if n.get("type") in ("snat", "dnat_and_snat") and _ip_in_spec(
            vm_ip, n.get("logical_ip") or ""
        ):
            snat = n
            break
    gw_cidrs = [
        r.get("cidr")
        for r in (gw.get("routes") or [])
        if r.get("ext_gw")
    ]
    tenant_cidrs = [r.get("cidr") for r in (tenant.get("routes") or []) if r.get("cidr")]
    scale_nh = [
        c
        for c in tenant_cidrs
        if str(c).startswith("169.254.")
    ]
    rc_bits = []
    for r in gw.get("rc") or []:
        rc_bits.append(
            f"{r.get('hostname') or chassis_label(str(r.get('chassis_name') or ''))} "
            f"chassis `{r.get('chassis_uuid') or r.get('chassis_name')}` pri={r.get('priority')}"
        )
    gw_host = gw.get("gw_host") or {}
    gw_hn = gw_host.get("hostname") or ""
    gw_cu = gw_host.get("chassis_uuid") or ""
    ext_mac = gw.get("ext_mac") or ""
    ext_cidr = gw.get("ext_cidr") or ""
    ext_ip = gw.get("ext_ip") or (str(ext_cidr).split("/")[0] if ext_cidr else "")
    src_chassis = card.get("chassis_uuid") or ""

    def _first_from(pkt: Dict[str, Any]) -> Tuple[Optional[dict], str]:
        hit: Optional[dict] = None
        ls_n = ""
        for ls_name, fr, _to in acls_by_ls:
            h = first_acl_hit(fr, pkt)
            if h:
                hit, ls_n = h, ls_name
                if (h.get("action") or "") == "drop":
                    break
                if str(h.get("action") or "").startswith("allow"):
                    continue
        return hit, ls_n

    tcp_hit, _ = _first_from({**pkt_up, "proto": 6, "dport": 443})
    udp_hit, _ = _first_from({**pkt_up, "proto": 17, "dport": 53})

    def _pg_uuid(name: str) -> str:
        h = (name or "").replace("port_group_", "").replace("_", "")
        if len(h) == 32:
            return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
        return name

    pg_disp = []
    for pg in src_pgs:
        pretty = rewrite_match(f"@{pg}").lstrip("@")
        pg_disp.append(
            f"`{pretty}` uuid `{_pg_uuid(pg)}` (OVN `@{pg}`)"
        )

    pbr_txt = "(none)"
    if pbr_hit:
        nh = pbr_hit.get("nexthop") or "(empty — continue to connected/static routes)"
        pbr_txt = (
            f"pri {pbr_hit.get('priority')} {pbr_hit.get('action')} "
            f"`{pbr_hit.get('match')}` nexthop `{nh}`"
        )
    snat_ext = (snat or {}).get("external_ip") or ""
    snat_log = (snat or {}).get("logical_ip") or ""
    snat_txt = "(no SNAT covering this VM IP on the GW in path)"
    if snat:
        snat_txt = f"{snat.get('type')} `{snat_log}` → `{snat_ext}` (src `{vm_ip}` becomes `{snat_ext}`)"

    vm_cidr = ", ".join(
        f"`{c}`" for c in tenant_cidrs if vm_ip and _ip_in_spec(vm_ip, str(c))
    ) or "(no covering connected CIDR)"

    if up_drops:
        verdict = "dropped upstream"
        drop_line = (
            f"**dropped upstream** (src NIC → `{dest_ip or dip}`). "
            f"First match on Switch `{up_drop_ls}` **from-lport**: {_acl_one_liner(up_hit)}. "
            "The packet never reaches the tenant router, SNAT, or External. "
            "Downstream does not run (no conntrack)."
        )
    elif dn_drops:
        verdict = "allowed out but dropped on return (stateful)"
        drop_line = (
            f"**allowed out but dropped on return (stateful)** — downstream drop "
            f"( `{dest_ip or dip}` → src NIC ). Outbound ACLs allow; return hits "
            f"Switch `{dn_drop_ls}` **to-lport**: {_acl_one_liner(dn_hit)}."
        )
    else:
        verdict = "allowed both"
        drop_line = (
            f"**allowed both** for IPv4 ICMP `{vm_ip}` ↔ `{dest_ip or dip}`. "
            "Routing/NAT still must succeed; see Routing view."
        )

    route_fwd: List[str] = [
        f"1. VM `{vm_name}` uuid `{vm_uuid}`",
        f"2. NIC `{nic_uuid}` MAC `{mac}` IP `{vm_ip}` LSP `{lsp_uuid}`",
        f"3. TAP `{tap}`",
        f"4. OVS brAtlas ofport `{ofp}`"
        + (f" on Host `{host}` chassis `{src_chassis}`" if host else ""),
    ]
    n = 5
    for h in hops:
        hk = h.get("kind")
        if hk == "switch":
            if h.get("external_ls") or h.get("localnet"):
                tag = "Switch External localnet"
            elif h.get("transit"):
                tag = "Switch transit"
            else:
                tag = "Switch"
            route_fwd.append(
                f"{n}. {tag} `{h.get('name')}` uuid `{h.get('uuid')}`"
            )
            n += 1
        elif hk == "router":
            extra = []
            if h.get("has_nat"):
                extra.append("NAT")
            if h.get("is_ext_gw") or is_gw_router(h.get("name") or "", h):
                extra.append("ext-GW")
            lab = "Router" + ((" (" + ", ".join(extra) + ")") if extra else "")
            bit = f"{n}. {lab} `{h.get('name')}` uuid `{h.get('uuid')}`"
            cidrs = [r.get("cidr") for r in (h.get("routes") or []) if r.get("cidr")]
            cover = ", ".join(
                f"`{c}`" for c in cidrs if vm_ip and _ip_in_spec(vm_ip, str(c))
            ) or ", ".join(f"`{c}`" for c in cidrs[:8])
            pbrs_n = len(h.get("pbrs") or [])
            statics = h.get("static_routes") or []
            bit += f" — connected {cover or '(none)'}; PBR {pbrs_n} rows"
            if h.get("uuid") == tenant.get("uuid"):
                bit += f"; src PBR {pbr_txt}"
            for p in h.get("path_lrps") or []:
                bit += (
                    f"; {p.get('role')} `{p.get('lrp')}` "
                    f"MAC `{p.get('mac')}` `{p.get('cidr')}`"
                )
            if statics:
                bit += f"; static routes {len(statics)} (full table below)"
                for s in statics:
                    if (s.get("prefix") or "") in ("0.0.0.0/0", "::/0"):
                        bit += (
                            f"; default `{s.get('prefix')}` nexthop `{s.get('nexthop')}`"
                        )
                        break
            if is_gw_router(h.get("name") or "", h) or h.get("is_ext_gw"):
                gh = h.get("gw_host") or {}
                him = h.get("ext_mac") or ""
                hip = h.get("ext_cidr") or ""
                hip0 = h.get("ext_ip") or (str(hip).split("/")[0] if hip else "")
                bit += (
                    f" — External GW Host `{gh.get('hostname') or ''}` chassis "
                    f"`{gh.get('chassis_uuid') or ''}` (active RC); "
                    f"External GW MAC `{him}` IP `{hip}`"
                )
                hop_snat = None
                cover_ip = vm_ip
                if h.get("uuid") != gw.get("uuid") and dcard.get("ip"):
                    cover_ip = dcard.get("ip") or vm_ip
                for natr in h.get("nats") or []:
                    if natr.get("type") in ("snat", "dnat_and_snat") and _ip_in_spec(
                        cover_ip, natr.get("logical_ip") or ""
                    ):
                        hop_snat = natr
                        break
                if hop_snat:
                    sx = hop_snat.get("external_ip") or ""
                    sl = hop_snat.get("logical_ip") or ""
                    snat_note = (
                        f"; SNAT `{cover_ip}` → `{sx}` covering `{sl}`"
                    )
                    if hip0 and sx and sx != hip0:
                        snat_note += (
                            f" (SNAT external IP `{sx}` differs from LRP `{hip0}`)"
                        )
                    bit += snat_note
                ovs = h.get("ovs") or {}
                if ovs.get("tap") or ovs.get("ofport"):
                    bit += (
                        f"; TAP_GW `{ovs.get('tap') or '(missing)'}` "
                        f"OVS brAtlas ofport `{ovs.get('ofport') or '?'}`"
                    )
            route_fwd.append(bit)
            n += 1
            if is_gw_router(h.get("name") or "", h) or h.get("is_ext_gw"):
                for peer in h.get("scaleout_peers") or []:
                    ph = peer.get("gw_host") or {}
                    route_fwd.append(
                        f"{n}. External GW Host `{ph.get('hostname') or ''}` chassis "
                        f"`{ph.get('chassis_uuid') or ''}` (standby scale-out) "
                        f"router `{peer.get('name')}` MAC `{peer.get('ext_mac')}` "
                        f"IP `{peer.get('ext_cidr')}`"
                    )
                    n += 1
        elif hk == "external":
            route_fwd.append(f"{n}. External `{dest_ip or 'NAT GW'}`")
            n += 1
        elif hk == "overlay":
            route_fwd.append(
                f"{n}. Overlay {h.get('encap_type') or 'geneve'} "
                f"`{h.get('src')}` to `{h.get('dst')}` (compute host ≠ GW host)"
            )
            n += 1

    ret_snat = (
        f"replies to `{snat_ext}` are un-SNATed by conntrack (reverse of "
        f"`{snat.get('type')}` `{snat_log}` → `{snat_ext}`, not a separate DNAT row) "
        f"back to `{vm_ip}`"
        if snat
        else "no SNAT reverse on path"
    )

    icmp_same = (tcp_hit or {}).get("priority") == (up_hit or {}).get("priority") and (
        tcp_hit or {}
    ).get("action") == (up_hit or {}).get("action")

    scale_lines = []
    for gh_hop in gws:
        gh = gh_hop.get("gw_host") or {}
        scale_lines.append(
            f"- External GW Host `{gh.get('hostname') or ''}` chassis "
            f"`{gh.get('chassis_uuid') or ''}` (active RC) "
            f"router `{gh_hop.get('name')}` MAC `{gh_hop.get('ext_mac') or ''}` "
            f"IP `{gh_hop.get('ext_cidr') or ''}`"
        )
        for peer in gh_hop.get("scaleout_peers") or []:
            ph = peer.get("gw_host") or {}
            scale_lines.append(
                f"- External GW Host `{ph.get('hostname') or ''}` chassis "
                f"`{ph.get('chassis_uuid') or ''}` (standby scale-out) "
                f"router `{peer.get('name')}` MAC `{peer.get('ext_mac') or ''}` "
                f"IP `{peer.get('ext_cidr') or ''}`"
            )
    transit_lines = []
    for h in hops:
        if h.get("kind") != "switch":
            continue
        if h.get("transit"):
            transit_lines.append(
                f"- Transit LS `{h.get('name')}` uuid `{h.get('uuid')}`"
            )
        if h.get("external_ls") or h.get("localnet"):
            transit_lines.append(
                f"- External localnet `{h.get('name')}` uuid `{h.get('uuid')}`"
            )

    dest_header = (
        f"- Dest VM `{dcard.get('vm')}` uuid `{(dst.get('nic') or {}).get('vm_uuid') or ''}` "
        f"NIC `{dcard.get('nic')}` LSP `{dcard.get('lsp_uuid')}` MAC `{dcard.get('mac')}` "
        f"IP `{dcard.get('ip')}` VPC `{vpc_label(dcard.get('vm') or '')}`"
        if dst.get("kind") == "vif"
        else (
            f"- Dest `{dest_ip or dip}`"
            + (
                " (internet / northbound via OVN External)"
                if dst.get("kind") == "external"
                else ""
            )
        )
    )
    dst_host_line = ""
    if dst.get("kind") == "vif" and (dcard.get("hostname") or dcard.get("chassis_uuid")):
        dst_host_line = (
            f"- Dest compute Host `{dcard.get('hostname') or dcard.get('host_ip')}` "
            f"chassis `{dcard.get('chassis_uuid') or ''}`"
        )

    if dst.get("kind") == "vif":
        ret_body = (
            f"**Return (`{dip}` → src NIC):** dest VM `{dcard.get('vm')}` TAP "
            f"`{dcard.get('tap') or '(missing)'}` / OVS brAtlas on "
            f"`{dcard.get('hostname') or ''}` → dest Switch → dest tenant "
            f"`{(dest_tenant or tenant).get('name')}` → dest transit → dest External GW "
            f"→ External localnet → src External GW `{gw_hn}` chassis `{gw_cu}` "
            f"(un-SNAT: {ret_snat}; External GW MAC `{ext_mac}` IP `{ext_cidr}`) → "
            f"src transit → src tenant `{tenant.get('name')}` connected {vm_cidr} → "
            f"Switch → OVS brAtlas → TAP `{tap}` on `{host}` → NIC `{nic_uuid}` → "
            f"VM `{vm_name}`. Would-be return is drawn even if upstream ACL dropped."
        )
    else:
        ret_body = (
            f"**Return (`{dest_ip or dip}` → NIC):** External `{dest_ip or dip}` → "
            f"TAP_GW / OVS brAtlas on External GW Host `{gw_hn}` chassis `{gw_cu}` "
            f"(un-SNAT: {ret_snat}; External GW MAC `{ext_mac}` IP `{ext_cidr}`) → "
            f"transit → tenant Router `{tenant.get('name')}` connected {vm_cidr} → "
            f"Switch → OVS brAtlas → TAP `{tap}` on `{host}` → NIC `{nic_uuid}` → "
            f"VM `{vm_name}`. Would-be return is drawn even if upstream ACL dropped."
        )

    lines = [
        "## Traffic story / RCA",
        "",
        f"- Src VM `{vm_name}` uuid `{vm_uuid}` NIC `{nic_uuid}` LSP `{lsp_uuid}` "
        f"MAC `{mac}` IP `{vm_ip}` VPC `{vpc_label(vm_name)}`",
        dest_header,
        f"- Compute Host `{host}` chassis `{src_chassis}`",
    ]
    if dst_host_line:
        lines.append(dst_host_line)
    lines += [
        *scale_lines,
        *transit_lines,
        "",
        "### Drop / allow",
        "",
        drop_line,
        "",
        f"_Verdict: **{verdict}**. UPSTREAM = src NIC → dest. DOWNSTREAM = dest → src NIC._",
        "",
        "### Routing view (L2 → L3 → GW → NAT → External)",
        "",
        "Forward (what routing would do if policy allowed):",
        "",
        *route_fwd,
        "",
        ret_body,
        "",
    ]

    if up_drops:
        rca = (
            f"The packet left VM `{vm_name}` (`{vm_uuid}`) NIC `{nic_uuid}` IP `{vm_ip}` "
            f"on `{host}` via TAP `{tap}` / OVS brAtlas ofport `{ofp}` onto Switch "
            f"`{up_drop_ls}` (`{ls_uuid}`). **from-lport pri {(up_hit or {}).get('priority')} "
            f"{(up_hit or {}).get('action')}** on {pg_disp[0] if pg_disp else 'LS ACL'} "
            f"matched leftover IPv4 to `{dest_ip or dip}` — higher-pri 1060/1052 dest-isolation "
            f"and 1050 allow-related dest-sets are east-west, not `{dest_ip or dip}`; pri "
            f"1017/1015 and 500 `tcp || udp || icmp` never run. Tenant LR "
            f"`{tenant.get('name')}` / {snat_txt} never saw the packet. **Dropped upstream.**"
        )
    elif dn_drops:
        rca = (
            f"Outbound left VM `{vm_name}` NIC `{nic_uuid}` and would SNAT `{vm_ip}` → "
            f"`{snat_ext or '(none)'}` toward `{dest_ip or dip}`, but the return packet is "
            f"dropped on Switch `{dn_drop_ls}` **to-lport** ({_acl_one_liner(dn_hit)}). "
            f"**Allowed out but dropped on return.**"
        )
    else:
        rca = (
            f"VM `{vm_name}` NIC `{nic_uuid}` `{vm_ip}` is allowed from-lport and to-lport "
            f"toward `{dest_ip or dip}` ({_acl_one_liner(up_hit)}). Routing: tenant "
            f"`{tenant.get('name')}` {pbr_txt}, then {snat_txt} on `{gw.get('name')}`."
        )
    if up_drops:
        lines.append(
            f"The packet **dies on hop 5** (first Switch `{up_drop_ls}`, from-lport); "
            "hops 6+ (tenant LR / PBR / SNAT / External) are never reached."
        )
        lines.append("")
    lines += [
        "### Policy view (ACL)",
        "",
        f"- Applied-to (name display, UUID identity): "
        + ("; ".join(pg_disp) if pg_disp else "(none — LS ACLs only)"),
        f"- ICMP ping `{vm_ip}` → `{dest_ip or dip}` (proto 1): first hit "
        f"**from-lport** on `{up_drop_ls or 'src LS'}`: {_acl_one_liner(up_hit)}",
        f"- TCP :443 / UDP :53 to `{dest_ip or dip}`: "
        + (
            "same first hit as ICMP (1050 allow-related is dest-set + tcp/udp port ranges, "
            f"not `{dest_ip or dip}`)."
            if icmp_same
            else f"TCP {_acl_one_liner(tcp_hit)}; UDP {_acl_one_liner(udp_hit)}"
        ),
        f"- Downstream first hit (**to-lport**, `{dest_ip or dip}` → NIC) on "
        f"`{dn_drop_ls or 'src LS'}`: {_acl_one_liner(dn_hit)}",
        "- Walk: pri 31500 DHCP miss; 1060/1052 dest/src isolation miss for this dest; "
        "1050 allow-related miss (wrong dest-set / ports); **1045 IPv4 catch-all drop** "
        "wins on the secured group; 1017/1015 on the second group and 500 "
        "`tcp || udp || icmp` never run. Full tables under each mermaid "
        "(src LS, dest LS, every transit / localnet LS on the walk).",
        "",
        "### What exactly happened",
        "",
        rca,
        "",
        f"_Drop direction: **{verdict}**. "
        "Mermaid: [Mermaid Upstream composite](#mermaid-upstream-composite) "
        "and [Mermaid Downstream composite](#mermaid-downstream-composite)._",
        "",
    ]
    return "\n".join(lines) + "\n"


def trace_pair(g: Dict[str, Any], src_tok: str, dst_tok: str) -> str:
    src = resolve(g, src_tok)
    dst = resolve(g, dst_tok)
    src_key = start_node(src)
    dst_keys = dest_nodes(g, dst)
    if src_key in dst_keys:
        path = [(src_key, None)]
    else:
        path = bfs(g, src_key, dst_keys)
        if not path:
            return f"NO PATH {fmt_ep(src)} -> {fmt_ep(dst)}\n"
    story = render_story(g, src, dst, path)
    body = story
    body += render_path(g, src, dst, path, reverse=False)
    body += "\n"
    body += render_path(g, src, dst, path, reverse=True)
    body += "\n"
    return body


def _tok(n: dict) -> str:
    return n.get("lsp_uuid") or n.get("nic_uuid") or n.get("vm_name")


def find_scenarios(g: Dict[str, Any]) -> Dict[str, Tuple[str, str, str]]:
    vif_nics = [
        n
        for n in g["nics"]
        if n.get("ls_uuid") and n["ls_uuid"] != ZERO and n.get("lsp_uuid") != ZERO
    ]
    by_ls: Dict[str, List[dict]] = defaultdict(list)
    for n in vif_nics:
        by_ls[n["ls_uuid"]].append(n)
    out: Dict[str, Tuple[str, str, str]] = {}
    acl_ls = {r["ls_uuid"] for r in ch("SELECT DISTINCT ls_uuid FROM ovn_acl_on_ls")}
    localnet_ls = {p["ls_uuid"] for p in g["lsp"] if p.get("type") == "localnet"}
    for ls_uuid, nics in by_ls.items():
        if ls_uuid in localnet_ls:
            continue
        uniq = []
        seen_vm = set()
        for n in nics:
            vm = n.get("vm_uuid") or n.get("lsp_uuid")
            if vm in seen_vm:
                continue
            seen_vm.add(vm)
            uniq.append(n)
        if len(uniq) < 2:
            continue
        if ls_uuid not in acl_ls:
            continue
        a, b = uniq[0], uniq[1]
        lsn = g["ls"].get(ls_uuid, {}).get("name")
        out["same_l2"] = (
            _tok(a),
            _tok(b),
            f"VMs {a.get('vm_name')} <-> {b.get('vm_name')} on LS {lsn} uuid={ls_uuid}",
        )
        break
    ls_to_lrs: Dict[str, set] = defaultdict(set)
    for e in g["ls_lr"]:
        ls_to_lrs[e["ls_uuid"]].add(e["lr_uuid"])
    for lr_uuid, rec in g["lr"].items():
        name = rec.get("name") or ""
        if name.startswith("gw-scale-out"):
            continue
        lss = [
            ls
            for ls in ls_to_lrs
            if lr_uuid in ls_to_lrs[ls] and ls in by_ls and ls not in localnet_ls
        ]
        if len(lss) < 2:
            continue
        a = by_ls[lss[0]][0]
        b = None
        for cand in by_ls[lss[1]]:
            if cand.get("vm_uuid") != a.get("vm_uuid"):
                b = cand
                break
        if not b:
            continue
        out["l2_l3_l2"] = (
            _tok(a),
            _tok(b),
            f"VMs {a.get('vm_name')} <-> {b.get('vm_name')} via LR {name} uuid={lr_uuid} "
            f"LS {g['ls'].get(lss[0], {}).get('name')} / {g['ls'].get(lss[1], {}).get('name')}",
        )
        break
    by_vpc: Dict[str, List[dict]] = defaultdict(list)
    for n in vif_nics:
        if n["ls_uuid"] in localnet_ls:
            continue
        key = vpc_label(n.get("vm_name") or "")
        if key.startswith("Customer_"):
            by_vpc[key].append(n)
    vpcs = sorted(by_vpc)
    found_two = False
    for i, va in enumerate(vpcs):
        for vb in vpcs[i + 1 :]:
            a, b = by_vpc[va][0], by_vpc[vb][0]
            if a["ls_uuid"] == b["ls_uuid"]:
                continue
            path = bfs(g, ("ls", a["ls_uuid"]), [("ls", b["ls_uuid"])])
            if not path:
                continue
            names = [
                g["lr"].get(x[0][1], {}).get("name", "")
                for x in path
                if x[0][0] == "lr"
            ]
            tenants_n = [x for x in names if x.startswith("router_")]
            gws_n = [x for x in names if "gw-scale-out" in (x or "").lower()]
            transits = []
            for _node, meta in path:
                if not meta:
                    continue
                via = meta.get("via_ls_uuid") or ""
                lsn = (g["ls"].get(via) or {}).get("name") or ""
                if is_transit_ls(lsn):
                    transits.append(lsn)
            if len(tenants_n) < 2 or not gws_n or not transits:
                continue
            out["two_router"] = (
                _tok(a),
                _tok(b),
                f"VMs {a.get('vm_name')} ({va}) <-> {b.get('vm_name')} ({vb}) "
                f"via "
                + " -> ".join([x for x in names if x])
                + " transit "
                + ", ".join(dict.fromkeys(transits)),
            )
            found_two = True
            break
        if found_two:
            break
    ext = external_targets(g)
    if not found_two:
        for n in vif_nics:
            if n["ls_uuid"] in localnet_ls:
                continue
            path = bfs(g, ("ls", n["ls_uuid"]), ext)
            if not path:
                continue
            lrs = [x[0][1] for x in path if x[0][0] == "lr"]
            uniq = list(dict.fromkeys(lrs))
            if len(uniq) < 2:
                continue
            dest_lr = uniq[-1]
            names = [g["lr"].get(x, {}).get("name", x) for x in uniq]
            out["two_router"] = (
                _tok(n),
                dest_lr,
                f"no two-VIF overlay across two tenant routers; closest VM {n.get('vm_name')} "
                f"LS {g['ls'].get(n['ls_uuid'], {}).get('name')} via "
                + " -> ".join(names),
            )
            break
    for n in vif_nics:
        if n["ls_uuid"] in localnet_ls:
            continue
        path = bfs(g, ("ls", n["ls_uuid"]), ext)
        if not path:
            continue
        names = [g["lr"].get(x[0][1], {}).get("name", "") for x in path if x[0][0] == "lr"]
        out["northbound"] = (
            _tok(n),
            "external",
            f"VM {n.get('vm_name')} LS {g['ls'].get(n['ls_uuid'], {}).get('name')} via "
            + " -> ".join([x for x in names if x]),
        )
        break
    return out


def _slug(s: str) -> str:
    s = (s or "x").strip().replace("/", "-")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return (s[:80] or "x").strip("._")


def md_out_path(src: str, dst: str, out: str = "", scenario: str = "") -> str:
    if out:
        return out if out.endswith(".md") else out + ".md"
    os.makedirs(OUT_DIR, exist_ok=True)
    if scenario:
        return os.path.join(OUT_DIR, f"{_slug(scenario)}.md")
    return os.path.join(OUT_DIR, f"{_slug(src)}__{_slug(dst)}.md")


def write_md(path: str, body: str, title: str = "") -> str:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    bits = []
    if title:
        bits.extend([f"# {title}", ""])
    bits.append(body.rstrip() + "\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(bits))
    print(f"wrote {path}", file=sys.stderr)
    print(path)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Trace OVN paths from flow_ovn")
    ap.add_argument("--src")
    ap.add_argument(
        "--dst",
        help="VM/NIC/LSP UUID or name, IPv4 (treated as northbound), or 'external'",
    )
    ap.add_argument("--out", help="markdown file (always .md). default: clickhouse_ovn/out/")
    ap.add_argument("--find-scenarios", action="store_true")
    ap.add_argument("--run-scenarios", action="store_true")
    args = ap.parse_args()
    print("loading graph from ClickHouse flow_ovn…", file=sys.stderr)
    g = load_graph()
    print(
        f"  LS={len(g['ls'])} LR={len(g['lr'])} LSP={len(g['lsp'])} "
        f"LRP={len(g['lrp'])} NIC={len(g['nics'])} edges_ls_lr={len(g['ls_lr'])} "
        f"edges_lr_lr={len(g['lr_lr'])}",
        file=sys.stderr,
    )
    if args.find_scenarios or args.run_scenarios:
        sc = find_scenarios(g)
        lines = ["# OVN path scenarios", "", "## scenarios"]
        for k, (s, d, note) in sc.items():
            lines.append(f"- {k}: `{s}` -> `{d}`  ({note})")
        if args.run_scenarios:
            for k, (s, d, note) in sc.items():
                body = trace_pair(g, s, d)
                p = md_out_path(s, d, scenario=k)
                write_md(p, body, title=f"OVN path `{k}`: {s} → {d}")
                lines.extend(["", f"## {k}", "", f"See `{p}`.", "", body])
        idx = args.out or os.path.join(OUT_DIR, "scenarios.md")
        if not idx.endswith(".md"):
            idx += ".md"
        write_md(idx, "\n".join(lines) + "\n", title="")
        return 0
    if not args.src or not args.dst:
        ap.error("need --src and --dst, or --find-scenarios / --run-scenarios")
    body = trace_pair(g, args.src, args.dst)
    path = md_out_path(args.src, args.dst, out=args.out or "")
    write_md(path, body, title=f"OVN path {args.src} → {args.dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
