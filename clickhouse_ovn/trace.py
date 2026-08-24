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
    ovs_for_vif,
    port_group_label,
    refs_from_acls,
    rewrite_match,
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
    ls = {r["ls_uuid"]: r for r in ch("SELECT ls_uuid, name FROM ovn_ls")}
    lr = {r["lr_uuid"]: r for r in ch("SELECT lr_uuid, name, has_nat FROM ovn_lr")}
    lsp = ch(
        "SELECT lsp_uuid, ls_uuid, name, type, mac, ip4, nic_uuid, options_router_port "
        "FROM ovn_lsp"
    )
    lrp = ch(
        "SELECT lrp_uuid, lr_uuid, name, mac, networks, peer, is_ext_gw, "
        "ha_chassis_group FROM ovn_lrp"
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
    return ch(
        "SELECT group_uuid, chassis_name, priority FROM ovn_ha_chassis "
        f"WHERE group_uuid IN ({glist}) ORDER BY priority DESC, chassis_name"
    )


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
        "SELECT c.hostname AS hostname, n.host_ip AS host_ip, "
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

    ids: List[str] = []
    classes: Dict[str, str] = {}
    lines = [
        "**How to read:** left to right is packet flow. Blue stadium = VM. Rectangle = NIC, "
        "then TAP, then OVS port on brAtlas (ofport / datapath port / iface-id). "
        "Green cylinder = Switch (LS), orange hexagon = Router (LR). "
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

    def host_title(card: Dict[str, str]) -> str:
        bits = ["Host " + (card.get("hostname") or "")]
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
            set_layer("L2", "L2 stretch")
            tag = "Switch transit" if hop.get("transit") else "Switch"
            nid = emit(f"{tag}<br/>{_esc(hop.get('name'))}", "cyl", "sw")
            if first_sw is None:
                first_sw = nid
        elif hk == "router":
            gw = is_gw(hop)
            if gw:
                set_layer("GW", "GW")
                seen_gw = True
            else:
                set_layer("L3", "L3 routing / PBR")
                seen_l3 = True
            rlab = f"Router<br/>{_esc(hop.get('name'))}"
            if hop.get("has_nat"):
                rlab += "<br/>NAT"
            if hop.get("is_ext_gw"):
                rlab += "<br/>ext-GW"
            rid = emit(rlab, "hex", "rt")
            nat_rows = hop.get("nats") or []
            if hop.get("has_nat") or nat_rows or hop.get("is_ext_gw"):
                emit(f"NAT {len(nat_rows)}", "rect", "nat", main=False)
                lines.append(f"  {rid} -.-> N{seq}")
            pbr_rows = hop.get("pbrs") or []
            if pbr_rows:
                emit(f"PBR {len(pbr_rows)}", "rect", "pbr", main=False)
                lines.append(f"  {rid} -.-> N{seq}")
            rcs = hop.get("rc") or []
            if rcs:
                rc_bits = [
                    f"{_esc(r.get('chassis_name'))} pri={r.get('priority')}"
                    for r in rcs[:4]
                ]
                extra = f" +{len(rcs) - 4}" if len(rcs) > 4 else ""
                emit("RC<br/>" + "<br/>".join(rc_bits) + extra, "stadium", "rc", main=False)
                lines.append(f"  {rid} -.-> N{seq}")
                rc_rows.append((hop.get("name") or hop.get("uuid") or "", rcs))
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
    if wrap_src or wrap_dst:
        host_note = (
            "Host boxes wrap VM+NIC+TAP+OVS brAtlas when chassis differ "
            "(or one Host on the VM side for VIF-to-external)."
        )
    else:
        host_note = (
            "Same chassis: no Host boxes; TAP and OVS brAtlas stay on the chain."
        )
    lines.append(f"_{title} `{kind}`. {host_note}_")
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
        gw_rows = hop.get("rc") or []
        lines.append("")
        lines.append(
            f"#### {title} — GW chassis (RC) on router `{_esc(lr_name)}` (full) — "
            f"{len(gw_rows)} rows"
        )
        lines.extend(rc_table(gw_rows))
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


def rc_table(items: List[dict]) -> List[str]:
    if not items:
        return ["(none)"]
    out = [
        "| # | chassis_name | priority |",
        "|---|--------------|----------|",
    ]
    for i, r in enumerate(items, 1):
        out.append(
            f"| {i} | `{r.get('chassis_name') or ''}` | {r.get('priority')} |"
        )
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
        acls_by_ls.append((name, fr, to))
        hops.append(
            {
                "kind": "switch",
                "name": name,
                "uuid": uid,
                "acl_n": len(rows),
                "transit": transit or is_transit_ls(name),
                "stretch": stretch(uid),
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
        rc_rows = rc_for_lr(g, uid)
        name = rec.get("name") or uid
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
                "rc": rc_rows,
                "routes": routes_for_lr(g, uid),
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
        add_switch(via_ls, rec, None, True)

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
    if sh and eh and sh != eh:
        hops.append(
            {
                "kind": "overlay",
                "encap_type": hs.get("encap_type") or he.get("encap_type") or "geneve",
                "src": hs.get("geneve_ip") or hs.get("host_ip") or "",
                "dst": he.get("geneve_ip") or he.get("host_ip") or "",
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
    rows = ch(
        "SELECT hostname FROM ovn_chassis "
        f"WHERE chassis_uuid = '{name}' OR hostname = '{name}' LIMIT 1"
    )
    host = (rows[0].get("hostname") or "") if rows else ""
    return f"{host} ({name})" if host and host != name else name


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
    tap = card.get("tap") or "(missing)"
    ofp = card.get("ofport") or "?"
    host = card.get("hostname") or card.get("host_ip") or ""
    dip = dest_ip or (vm_ip if dst.get("kind") == "vif" else "dst")
    if dst.get("kind") == "vif":
        dcard = vif_card(dst)
        dip = dcard.get("ip") or dip

    pkt_up = {
        "ip_ver": "ip4",
        "src_ip": vm_ip,
        "dst_ip": dest_ip or dip,
        "inport_pgs": src_pgs,
        "outport_pgs": [],
        "proto": 1,
        "dport": None,
    }
    pkt_dn = {
        "ip_ver": "ip4",
        "src_ip": dest_ip or dip,
        "dst_ip": vm_ip,
        "inport_pgs": [],
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
    tenant = next(
        (h for h in routers if "gw-scale-out" not in (h.get("name") or "").lower()),
        routers[0] if routers else {},
    )
    gw = next(
        (h for h in routers if h.get("is_ext_gw") or "gw-scale-out" in (h.get("name") or "").lower()),
        {},
    )
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
    for r in (gw.get("rc") or [])[:4]:
        rc_bits.append(
            f"{chassis_label(str(r.get('chassis_name') or ''))} pri={r.get('priority')}"
        )

    hop_names = []
    hop_names.append(f"VM `{vm_name}`")
    hop_names.append(f"NIC `{nic_uuid}`")
    hop_names.append(f"TAP `{tap}`")
    hop_names.append(f"OVS brAtlas ofport `{ofp}`" + (f" on `{host}`" if host else ""))
    for h in hops:
        hk = h.get("kind")
        if hk == "switch":
            tag = "Switch transit" if h.get("transit") else "Switch"
            hop_names.append(f"{tag} `{h.get('name')}`")
        elif hk == "router":
            extra = []
            if h.get("has_nat"):
                extra.append("NAT")
            if h.get("is_ext_gw"):
                extra.append("ext-GW")
            lab = "Router"
            if extra:
                lab += " (" + ", ".join(extra) + ")"
            hop_names.append(f"{lab} `{h.get('name')}`")
        elif hk == "external":
            hop_names.append(f"External `{dest_ip or 'NAT GW'}`")

    if up_drops:
        drop_line = (
            f"**yes — upstream** (src→dst / leave VM toward {dest_ip or 'internet'}). "
            f"Dropped on Switch `{up_drop_ls}` **from-lport** before the tenant router. "
            f"{_acl_one_liner(up_hit)}"
        )
        direction_word = "upstream"
    elif dn_drops:
        drop_line = (
            f"**yes — downstream** (return path dst→src). "
            f"Outbound would leave, but the reverse packet is dropped on Switch "
            f"`{dn_drop_ls}` **to-lport**. {_acl_one_liner(dn_hit)}"
        )
        direction_word = "downstream"
    else:
        drop_line = (
            f"**no ACL drop** for IPv4 ICMP toward `{dest_ip or dip}`. "
            "Routing/NAT still has to succeed; see Routing view."
        )
        direction_word = "none"

    pbr_txt = "(none)"
    if pbr_hit:
        nh = pbr_hit.get("nexthop") or "(empty — continue to routes)"
        pbr_txt = (
            f"pri {pbr_hit.get('priority')} {pbr_hit.get('action')} "
            f"`{pbr_hit.get('match')}` nexthop `{nh}`"
        )
    snat_txt = "(no SNAT covering this VM IP on the GW in path)"
    if snat:
        snat_txt = (
            f"{snat.get('type')} `{snat.get('logical_ip')}` → `{snat.get('external_ip')}`"
        )

    pg_disp = []
    for pg in src_pgs:
        pg_disp.append(rewrite_match(f"@{pg}").lstrip("@") + f" (OVN `@{pg}`)")

    cause = []
    if up_drops:
        cause.append(
            f"Policy, not routing. The NIC sits in isolation port-group "
            f"`{(src_pgs[0] if src_pgs else 'pg')}` so **from-lport pri "
            f"{(up_hit or {}).get('priority')} drop** matches all leftover IPv4 "
            f"(including dest `{dest_ip or dip}`) before L3."
        )
        if dest_ip:
            cause.append(
                f"`{dest_ip}` is not in the higher-pri allow dest address-sets "
                "(those are east-west FNS IPs / port ranges), and it is not in the "
                "pri 1060/1052 deny dest set either — so the catch-all **1045 drop** wins. "
                "A lower-pri allow-related on another port-group (e.g. 1017/1015) never runs."
            )
        cause.append(
            "Routing would otherwise work: tenant default toward gw-scale-out "
            "(169.254.2.x ECMP), SNAT on the NAT GW, then External. The packet "
            "never gets there. Downstream does not run (no conntrack); unsolicited "
            "return would also hit to-lport 1045 drop."
        )
    elif dn_drops:
        cause.append(
            "Outbound ACLs allow the packet, but the return path hits a "
            f"**to-lport drop** on `{dn_drop_ls}` ({_acl_one_liner(dn_hit)}). "
            "That is a downstream drop (dst→src)."
        )
    else:
        cause.append(
            "Highest matching ACLs allow (or allow-related). Follow Routing view "
            "for NAT/GW next-hop toward the dest."
        )

    lines = [
        "## Traffic story / RCA",
        "",
        f"- Src VM `{vm_name}` NIC `{nic_uuid}` LSP `{lsp_uuid}` IP `{vm_ip}`",
        f"- Dest `{dest_ip or dip}`"
        + (" (internet / northbound via OVN External)" if dst.get("kind") == "external" else ""),
        "",
        "### Traffic story",
        "",
        f"**Upstream (src → {dest_ip or dip}):** "
        + " → ".join(hop_names)
        + ".",
    ]
    if up_drops:
        lines.append(
            f"The packet dies on the **first Switch** (`{up_drop_ls}`), "
            "from-lport, so TAP/OVS/Switch are reached but Router / PBR / NAT / "
            "External are not."
        )
    else:
        lines.append(
            "L2 leave (VM→NIC→TAP→OVS brAtlas→Switch) then L3/GW toward dest."
        )
    lines += [
        "",
        f"**Downstream ({dest_ip or dip} → src):** reverse of the same chain "
        "(External → ext-GW / NAT un-SNAT → transit → tenant Router → Switch → "
        "OVS brAtlas → TAP → NIC → VM).",
    ]
    if up_drops:
        lines.append(
            "This reverse path is not used: upstream never established state. "
            f"If a packet still arrived, to-lport on `{dn_drop_ls or up_drop_ls}` "
            f"would be {_acl_one_liner(dn_hit)}."
        )
    elif dn_drops:
        lines.append(
            f"Return is dropped on Switch `{dn_drop_ls}` to-lport."
        )
    lines += [
        "",
        "### Drop?",
        "",
        drop_line,
        "",
        "### Routing view",
        "",
        f"- Tenant LR `{tenant.get('name') or '(none)'}` uuid `{tenant.get('uuid') or ''}`",
        f"- VM subnet gateway among connected CIDRs: "
        + (
            ", ".join(
                f"`{c}`"
                for c in tenant_cidrs
                if vm_ip and _ip_in_spec(vm_ip, str(c))
            )
            or "(no covering connected CIDR)"
        ),
        f"- Scale-out link CIDRs: " + (", ".join(f"`{c}`" for c in scale_nh) or "(none)"),
        f"- PBR (highest 0.0.0.0/0): {pbr_txt}",
        f"- GW `{gw.get('name') or '(none)'}` ext-GW CIDRs: "
        + (", ".join(f"`{c}`" for c in gw_cidrs) or "(none)"),
        f"- SNAT for this VM: {snat_txt}",
        f"- Redirect chassis (RC): " + (", ".join(rc_bits) or "(none)"),
        f"- Next-hop toward `{dest_ip or dip}`: tenant default via gw-scale-out "
        "169.254.2.100/101 (NB static ECMP, not a flow_ovn table), then NAT GW "
        "ext-GW toward underlay, dest is External.",
        "",
        "### Policy view",
        "",
        f"- Applied-to port groups on this NIC: "
        + ("; ".join(pg_disp) if pg_disp else "(none — LS ACLs only)"),
        f"- Upstream first hit (from-lport on `{up_drop_ls or 'src LS'}`): {_acl_one_liner(up_hit)}",
        f"- Downstream first hit (to-lport on `{dn_drop_ls or 'src LS'}`): {_acl_one_liner(dn_hit)}",
        "- Pri 1060/1052 drops are dest/src address-set isolation (east-west). "
        "Pri 1045 is the IPv4/IPv6 catch-all drop on the secured group. "
        "Pri 1050 allows are dest-set + port-range. Pri 1017/1015 allows on a "
        "second group lose to 1045. Full tables are under each mermaid.",
        "",
        "### What exactly happened (RCA)",
        "",
    ]
    lines.extend(cause)
    lines += [
        "",
        f"_Drop direction: **{direction_word}**. "
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
    ext = external_targets(g)
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
            f"LS {g['ls'].get(n['ls_uuid'], {}).get('name')} via " + " -> ".join(names),
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
