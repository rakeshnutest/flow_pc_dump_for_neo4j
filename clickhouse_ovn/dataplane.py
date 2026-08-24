"""TAP / OVS / policy labels for OVN path mermaid. stdlib only.

Reads AHV dumpxml + OVS conf.db and the already-ingested policy jsonl.
Does not query or alter flow_policy ClickHouse.
"""
from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid5

DUMP_ROOT = "/home/rakeshkumar.r/panacea/flow_pc_dumps/ovn_ovs_verify"
POLICY_PORTSET = (
    "/home/rakeshkumar.r/panacea/flow_pc_dumps/clickhouse_all_dump/flow_policy/portset.jsonl"
)
POLICY_CATEGORY = (
    "/home/rakeshkumar.r/panacea/flow_pc_dumps/clickhouse_all_dump/flow_policy/category.jsonl"
)
NB_DUMP = os.path.join(DUMP_ROOT, "cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_nb.txt")

PG_RE = re.compile(r"@port_group_([0-9a-fA-F_]{32,})")
AS_RE = re.compile(r"\$address_set_([0-9a-fA-F_]{32,})")


def _underscores_to_uuid(blob: str) -> str:
    s = blob.replace("_", "-").lower()
    try:
        return str(UUID(s))
    except Exception:
        return s


@lru_cache(maxsize=1)
def _portsets() -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    if not os.path.isfile(POLICY_PORTSET):
        return out
    with open(POLICY_PORTSET) as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            uid = str(r.get("port_set_uuid") or "")
            if uid:
                out[uid] = r
    return out


@lru_cache(maxsize=1)
def _categories() -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not os.path.isfile(POLICY_CATEGORY):
        return out
    with open(POLICY_CATEGORY) as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            uid = str(r.get("category_uuid") or "")
            if uid:
                out[uid] = str(r.get("name") or uid)
    return out


@lru_cache(maxsize=1)
def _address_sets() -> Dict[str, List[str]]:
    """name -> addresses from NB Address_Set table."""
    out: Dict[str, List[str]] = {}
    if not os.path.isfile(NB_DUMP):
        return out
    in_as = False
    with open(NB_DUMP, errors="replace") as fh:
        for line in fh:
            if line.startswith("Address_Set table"):
                in_as = True
                continue
            if in_as and re.match(r"^[A-Za-z_]+ table", line):
                break
            if not in_as:
                continue
            if "address_set_" not in line:
                continue
            m = re.search(r"(address_set_[0-9a-fA-F_]+)", line)
            if not m:
                continue
            addrs = re.findall(r"\d+\.\d+\.\d+\.\d+(?:/\d+)?", line)
            out[m.group(1)] = addrs
    return out


def _conf_ifaces(host_ip: str) -> Dict[str, dict]:
    path = os.path.join(
        DUMP_ROOT, "ahv_gateway", host_ip, "files/etc/openvswitch/conf.db"
    )
    if not os.path.isfile(path):
        return {}
    merged: Dict[str, dict] = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            block = obj.get("Interface")
            if not isinstance(block, dict):
                continue
            for rec in block.values():
                name = rec.get("name")
                if not name:
                    continue
                ext = rec.get("external_ids")
                extmap: Dict[str, str] = {}
                if isinstance(ext, list) and len(ext) >= 2 and ext[0] == "map":
                    extmap = dict(ext[1])
                merged[name] = {
                    "ofport": rec.get("ofport"),
                    "iface_id": extmap.get("iface-id") or "",
                }
    return merged


def _dp_port(host_ip: str, tap: str) -> str:
    path = os.path.join(
        DUMP_ROOT, "ahv_gateway", host_ip, "commands/ovs-dpctl_-s_show.stdout"
    )
    if not os.path.isfile(path) or not tap:
        return ""
    needle = f": {tap}"
    with open(path, errors="replace") as fh:
        for line in fh:
            if needle in line:
                m = re.search(r"port\s+(\d+):", line)
                if m:
                    return m.group(1)
    return ""


def _tap_from_dumpxml(host_ip: str, vm_uuid: str, nic_uuid: str, mac: str) -> str:
    path = os.path.join(
        DUMP_ROOT,
        "ahv_gateway",
        host_ip,
        "commands",
        f"virsh_--readonly_dumpxml_{vm_uuid}.stdout",
    )
    if not os.path.isfile(path):
        return ""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return ""
    want_nic = (nic_uuid or "").lower()
    want_mac = (mac or "").lower()
    for iface in root.findall(".//interface"):
        alias = (iface.findtext("alias") or "") + "".join(
            iface.find("alias").get("name", "") if iface.find("alias") is not None else ""
        )
        mac_el = iface.find("mac")
        mac_addr = (mac_el.get("address") if mac_el is not None else "") or ""
        target = iface.find("target")
        tap = target.get("dev") if target is not None else ""
        if want_nic and want_nic in alias.lower():
            return tap or ""
        if want_mac and mac_addr.lower() == want_mac:
            return tap or ""
    return ""


def ovs_for_vif(nic: Dict[str, Any], lsp: Dict[str, Any]) -> Dict[str, str]:
    host_ip = str(nic.get("host_ip") or "")
    vm_uuid = str(nic.get("vm_uuid") or "")
    nic_uuid = str(nic.get("nic_uuid") or "")
    mac = str(nic.get("mac") or lsp.get("mac") or "")
    lsp_name = str(lsp.get("name") or "")
    tap = _tap_from_dumpxml(host_ip, vm_uuid, nic_uuid, mac)
    ifaces = _conf_ifaces(host_ip) if host_ip else {}
    rec = ifaces.get(tap) or {}
    if not rec and lsp_name:
        for name, info in ifaces.items():
            if info.get("iface_id") == lsp_name:
                rec = info
                tap = tap or name
                break
    ofport = rec.get("ofport")
    return {
        "tap": tap or "",
        "ofport": str(ofport) if ofport not in (None, "") else "",
        "dp_port": _dp_port(host_ip, tap) if tap else "",
        "bridge": "brAtlas",
        "iface_id": rec.get("iface_id") or lsp_name,
    }


def ovs_for_gw(host_ip: str, localnet_name: str) -> Dict[str, str]:
    """brAtlas patch for a GW localnet LSP (no VM TAP)."""
    host_ip = str(host_ip or "")
    localnet_name = str(localnet_name or "")
    out = {
        "tap": "",
        "ofport": "",
        "dp_port": "",
        "bridge": "brAtlas",
        "iface_id": localnet_name,
    }
    if not host_ip or not localnet_name:
        return out
    uid = (
        localnet_name[len("localnet_") :]
        if localnet_name.startswith("localnet_")
        else localnet_name
    )
    ifaces = _conf_ifaces(host_ip)
    want = [
        f"patch-brAtlas-to-localnet_{uid}",
        f"patch-localnet_{uid}-to-brAtlas",
        localnet_name,
    ]
    rec: Dict[str, Any] = {}
    tap = ""
    for name in want:
        if name in ifaces:
            rec = ifaces[name]
            tap = name
            break
    if not rec:
        for name, info in ifaces.items():
            if uid and uid in name:
                rec = info
                tap = name
                break
            if info.get("iface_id") == localnet_name:
                rec = info
                tap = name
                break
    ofport = rec.get("ofport")
    out["tap"] = tap
    out["ofport"] = str(ofport) if ofport not in (None, "") else ""
    out["dp_port"] = _dp_port(host_ip, tap) if tap else ""
    out["iface_id"] = rec.get("iface_id") or localnet_name
    return out


def port_group_label(pg_name: str) -> str:
    raw = pg_name[len("port_group_") :] if pg_name.startswith("port_group_") else pg_name
    uid = _underscores_to_uuid(raw)
    ps = _portsets().get(uid) or {}
    atlas = ps.get("atlas_name") or ""
    cats = ps.get("vm_category_names") or ps.get("reference_names") or []
    cat = cats[0] if cats else _categories().get(str((ps.get("vm_category_refs") or [""])[0]), "")
    role = ps.get("role") or "applied-to"
    nics = ps.get("atlas_nics") or ps.get("computed_nics") or []
    bits = ["Port group"]
    if cat:
        bits.append("category " + str(cat))
    if atlas:
        bits.append("policy " + str(atlas) + " (" + str(role) + ")")
    if nics:
        bits.append(str(len(nics)) + " NICs")
    bits.append("OVN @" + pg_name)
    return "<br/>".join(bits)


def address_set_label(as_name: str, sample: int = 4) -> str:
    addrs = _address_sets().get(as_name) or []
    dest_name = _match_portset_by_ips(addrs)
    bits = ["Address set"]
    if dest_name:
        bits.append(dest_name)
    if addrs:
        show = ", ".join(addrs[:sample])
        extra = f" +{len(addrs) - sample}" if len(addrs) > sample else ""
        bits.append(f"{len(addrs)} IPs: {show}{extra}")
    bits.append("OVN $" + as_name)
    return "<br/>".join(bits)


def _match_portset_by_ips(addrs: List[str]) -> str:
    if not addrs:
        return ""
    want = {a.split("/")[0] for a in addrs}
    best = ("", 0)
    for ps in _portsets().values():
        nics = ps.get("atlas_nics") or ps.get("computed_nics") or []
        ips = set()
        for n in nics:
            if isinstance(n, (list, tuple)) and len(n) > 4:
                ips.add(str(n[4]).split("/")[0])
            elif isinstance(n, dict) and n.get("ip"):
                ips.add(str(n["ip"]).split("/")[0])
        hit = len(want & ips)
        if hit > best[1]:
            cats = ps.get("vm_category_names") or ps.get("reference_names") or []
            cat = cats[0] if cats else ""
            atlas = ps.get("atlas_name") or ""
            role = ps.get("role") or ""
            label = " ".join(x for x in (str(cat), str(atlas), str(role)) if x)
            best = (label, hit)
    return best[0] if best[1] >= max(3, len(want) // 3) else ""


def rewrite_match(match: str) -> str:
    """Replace OVN @port_group / $address_set hashes with policy names + IPs."""
    if not match:
        return match

    def pg_sub(m: re.Match) -> str:
        uid = _underscores_to_uuid(m.group(1))
        ps = _portsets().get(uid) or {}
        cats = ps.get("vm_category_names") or ps.get("reference_names") or []
        cat = cats[0] if cats else "port-group"
        atlas = ps.get("atlas_name") or ""
        nice = f"@{cat}"
        if atlas:
            nice += f"/{atlas}"
        return nice

    def as_sub(m: re.Match) -> str:
        name = "address_set_" + m.group(1)
        addrs = _address_sets().get(name) or []
        dest = _match_portset_by_ips(addrs)
        if dest:
            return "$" + dest.replace(" ", "_")
        if addrs:
            return "$IPs(" + ",".join(addrs[:3]) + (f"+{len(addrs)-3}" if len(addrs) > 3 else "") + ")"
        return m.group(0)

    s = PG_RE.sub(pg_sub, match)
    s = AS_RE.sub(as_sub, s)
    return s


def refs_from_acls(acls: List[dict]) -> Tuple[List[str], List[str]]:
    pgs, sets = [], []
    seen_p, seen_s = set(), set()
    blob = " ".join(str(a.get("match") or "") for a in acls)
    for m in PG_RE.finditer(blob):
        name = "port_group_" + m.group(1)
        if name not in seen_p:
            seen_p.add(name)
            pgs.append(name)
    for m in AS_RE.finditer(blob):
        name = "address_set_" + m.group(1)
        if name not in seen_s:
            seen_s.add(name)
            sets.append(name)
    return pgs, sets


@lru_cache(maxsize=1)
def _nb_bundle() -> Dict[str, Any]:
    """Parse NB dump once: static routes + LS/LR options/external_ids/other_config."""
    empty: Dict[str, Any] = {"static": {}, "lr_meta": {}, "ls_meta": {}}
    if not os.path.isfile(NB_DUMP):
        return empty
    _dir = os.path.dirname(os.path.abspath(__file__))
    if _dir not in sys.path:
        sys.path.insert(0, _dir)
    try:
        from ingest import as_map, as_str, as_str_list, as_uuid, parse_dump
    except Exception:
        return empty
    tables = parse_dump(
        NB_DUMP,
        ["Logical_Router", "Logical_Router_Static_Route", "Logical_Switch"],
    )
    by_uid: Dict[str, dict] = {}
    for r in tables.get("Logical_Router_Static_Route") or []:
        uid = as_uuid(r.get("_uuid"))
        if not uid or uid == "00000000-0000-0000-0000-000000000000":
            continue
        by_uid[uid] = {
            "uuid": uid,
            "prefix": as_str(r.get("ip_prefix")),
            "nexthop": as_str(r.get("nexthop")),
            "policy": as_str(r.get("policy")),
            "output_port": as_str(r.get("output_port")),
        }
    static: Dict[str, List[dict]] = {}
    lr_meta: Dict[str, dict] = {}
    for r in tables.get("Logical_Router") or []:
        lr = as_uuid(r.get("_uuid"))
        if not lr or lr == "00000000-0000-0000-0000-000000000000":
            continue
        rows = []
        for sid in as_str_list(r.get("static_routes")):
            rec = by_uid.get(sid)
            if rec:
                rows.append(rec)
        if rows:
            static[lr] = rows
        lr_meta[lr] = {
            "name": as_str(r.get("name")),
            "enabled": r.get("enabled"),
            "options": as_map(r.get("options")),
            "external_ids": as_map(r.get("external_ids")),
        }
    ls_meta: Dict[str, dict] = {}
    for r in tables.get("Logical_Switch") or []:
        uid = as_uuid(r.get("_uuid"))
        if not uid or uid == "00000000-0000-0000-0000-000000000000":
            continue
        ls_meta[uid] = {
            "name": as_str(r.get("name")),
            "other_config": as_map(r.get("other_config")),
            "external_ids": as_map(r.get("external_ids")),
        }
    return {"static": static, "lr_meta": lr_meta, "ls_meta": ls_meta}


def static_routes_for_lr(lr_uuid: str) -> List[dict]:
    """All static routes on this LR (not first-match). Empty if dump has none."""
    return list(_nb_bundle()["static"].get(str(lr_uuid or ""), []) or [])


def nb_lr_meta(lr_uuid: str) -> dict:
    return dict(_nb_bundle()["lr_meta"].get(str(lr_uuid or ""), {}) or {})


def nb_ls_meta(ls_uuid: str) -> dict:
    return dict(_nb_bundle()["ls_meta"].get(str(ls_uuid or ""), {}) or {})


def ip_in_address_set(ip: str, as_name: str) -> bool:
    """True if ip is an exact member or is inside a CIDR listed on the set."""
    import ipaddress

    raw = (ip or "").split("/")[0]
    if not raw:
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    for a in _address_sets().get(as_name) or []:
        spec = (a or "").strip()
        if not spec:
            continue
        try:
            if "/" in spec:
                if addr in ipaddress.ip_network(spec, strict=False):
                    return True
            elif addr == ipaddress.ip_address(spec.split("/")[0]):
                return True
        except ValueError:
            if spec.split("/")[0] == raw:
                return True
    return False


# Names used by trace.py
ovs_for_vif = ovs_for_vif
ovs_for_gw = ovs_for_gw
port_group_label = port_group_label
address_set_label = address_set_label
refs_from_acls = refs_from_acls
rewrite_match = rewrite_match
ip_in_address_set = ip_in_address_set
static_routes_for_lr = static_routes_for_lr
nb_lr_meta = nb_lr_meta
nb_ls_meta = nb_ls_meta
