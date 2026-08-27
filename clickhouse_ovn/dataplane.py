"""TAP / OVS / policy labels for OVN path mermaid. stdlib only.

Reads AHV dumpxml + OVS conf.db and the already-ingested policy jsonl.
Does not query or alter flow_policy ClickHouse.
"""
from __future__ import annotations

import importlib.util
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
SB_DUMP = os.path.join(DUMP_ROOT, "cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_sb.txt")

PG_RE = re.compile(r"@port_group_([0-9a-fA-F_]{32,})")
AS_RE = re.compile(r"\$address_set_([0-9a-fA-F_]{32,})")
TCP_RANGE_RE = re.compile(
    r"(tcp|udp)\.dst\s*>=\s*(\d+)\s*&&\s*(?:tcp|udp)\.dst\s*<=\s*(\d+)"
)
TCP_EQ_RE = re.compile(r"(tcp|udp)\.dst\s*==\s*(\d+)")
ICMP_RE = re.compile(
    r"icmp4\.type\s*==\s*(\d+)(?:\s*&&\s*icmp4\.code\s*==\s*(\d+))?"
)
ICMP6_RE = re.compile(
    r"icmp6\.type\s*==\s*(\d+)(?:\s*&&\s*icmp6\.code\s*==\s*(\d+))?"
)


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


ICMP4_NAMES = {0: "echo-reply", 3: "dest-unreach", 8: "echo-request", 11: "time-exceeded"}
SAMPLE_IPS = 4
SAMPLE_NIC_IPS = 4


def _nic_fields(n: Any) -> Tuple[str, str, str]:
    """Return (nic_uuid, ip, vm_name) from a portset NIC dict/list."""
    if isinstance(n, dict):
        return (
            str(n.get("nic_uuid") or n.get("uuid") or "").lower(),
            str(n.get("ip") or "").split("/")[0],
            str(n.get("vm_name") or n.get("vm") or ""),
        )
    if isinstance(n, (list, tuple)) and n:
        uid = str(n[0]).lower() if n else ""
        ip = str(n[4]).split("/")[0] if len(n) > 4 else ""
        vm = str(n[1]) if len(n) > 1 else ""
        return uid, ip, vm
    if isinstance(n, str):
        return n.lower(), "", ""
    return "", "", ""


def _ps_nics(ps: dict) -> List[Any]:
    return list(ps.get("atlas_nics") or ps.get("computed_nics") or [])


def _ps_display(ps: dict, uid: str = "") -> Tuple[str, str, str]:
    cats = ps.get("vm_category_names") or ps.get("reference_names") or []
    cat = cats[0] if cats else ""
    atlas = str(ps.get("atlas_name") or "")
    role = str(ps.get("role") or "")
    if not cat and uid:
        cat = _categories().get(str((ps.get("vm_category_refs") or [""])[0]), "")
    return str(cat or ""), atlas, role


def expand_l4(match: str) -> str:
    """tcp/udp dest ranges and ICMP types as human text."""
    if not match:
        return ""
    tcp: List[str] = []
    udp: List[str] = []
    used = set()
    for m in TCP_RANGE_RE.finditer(match):
        used.add(m.group(0))
        bag = tcp if m.group(1) == "tcp" else udp
        a, b = m.group(2), m.group(3)
        bag.append(f"{a}-{b}" if a != b else a)
    for m in TCP_EQ_RE.finditer(match):
        if m.group(0) in used:
            continue
        bag = tcp if m.group(1) == "tcp" else udp
        bag.append(m.group(2))
    bits: List[str] = []
    if tcp:
        bits.append("tcp dest " + ", ".join(tcp))
    if udp:
        bits.append("udp dest " + ", ".join(udp))
    icmps: List[str] = []
    for m in ICMP_RE.finditer(match):
        t, c = m.group(1), m.group(2)
        name = ICMP4_NAMES.get(int(t), f"type {t}")
        icmps.append(name if not c else f"{name} code {c}")
    for m in ICMP6_RE.finditer(match):
        t, c = m.group(1), m.group(2)
        icmps.append(f"icmp6 type {t}" + (f" code {c}" if c else ""))
    if icmps:
        bits.append("icmp " + ", ".join(icmps))
    if "ip.proto == 6" in match and not tcp:
        bits.append("tcp")
    if "ip.proto == 17" in match and not udp:
        bits.append("udp")
    if "ip.proto == 1" in match and not icmps:
        bits.append("icmp")
    return "; ".join(bits)


def _pg_human(uid: str, nic_uuid: str, sample: int = SAMPLE_NIC_IPS) -> dict:
    ps = _portsets().get(uid) or {}
    cat, atlas, role = _ps_display(ps, uid)
    nics = _ps_nics(ps)
    ips: List[str] = []
    member = False
    want = {x.lower() for x in (nic_uuid or "").replace(",", " ").split() if x}
    for n in nics:
        nu, ip, _vm = _nic_fields(n)
        if nu and nu in want:
            member = True
        if ip and ip not in ips:
            ips.append(ip)
    label = "/".join(x for x in (cat, atlas) if x) or "port-group"
    if role:
        label += f" ({role})"
    return {
        "uid": uid,
        "label": label,
        "member": member,
        "nic_count": len(nics),
        "sample_ips": ips[:sample],
        "ip_count": len(ips),
    }


@lru_cache(maxsize=1024)
def _dest_label_for_as(as_name: str) -> str:
    addrs = tuple(_address_sets().get(as_name) or [])
    dest = _match_portset_by_ips(list(addrs))
    if dest:
        return dest.replace(" ", "_")
    return f"dest-set({len(addrs)} IPs)" if addrs else "dest-set"


def _as_human(
    as_name: str,
    src_ip: str = "",
    dst_ip: str = "",
    sample: int = SAMPLE_IPS,
) -> dict:
    addrs = _address_sets().get(as_name) or []
    in_src = ip_in_address_set(src_ip, as_name) if src_ip else False
    in_dst = ip_in_address_set(dst_ip, as_name) if dst_ip else False
    return {
        "name": as_name,
        "label": _dest_label_for_as(as_name),
        "count": len(addrs),
        "sample": addrs[:sample],
        "rest": addrs[sample:],
        "src_in": in_src,
        "dst_in": in_dst,
    }


def rewrite_match_human(
    match: str,
    nic_uuid: str = "",
    src_ip: str = "",
    dst_ip: str = "",
) -> str:
    """Human match: policy names, IPs, L4 ports. No hashed PG/AS as primary."""
    if not match:
        return match

    def pg_sub(m: re.Match) -> str:
        h = _pg_human(_underscores_to_uuid(m.group(1)), nic_uuid)
        mem = "member" if h["member"] else "not-member"
        ips = ", ".join(h["sample_ips"][:3])
        extra = f"+{h['ip_count'] - 3}" if h["ip_count"] > 3 else ""
        return f"@{h['label']} [{mem}, {h['nic_count']} NICs, {ips}{extra}]"

    def as_sub(m: re.Match) -> str:
        info = _as_human("address_set_" + m.group(1), src_ip, dst_ip)
        hit = []
        if src_ip:
            hit.append("src " + ("in" if info["src_in"] else "not-in"))
        if dst_ip:
            hit.append("dst " + ("in" if info["dst_in"] else "not-in"))
        samp = ", ".join(info["sample"])
        extra = f"+{info['count'] - len(info['sample'])}" if info["count"] > len(info["sample"]) else ""
        who = "; ".join(hit)
        return f"${info['label']} [{info['count']} IPs: {samp}{extra}; {who}]"

    s = PG_RE.sub(pg_sub, match)
    s = AS_RE.sub(as_sub, s)
    s = TCP_RANGE_RE.sub(lambda m: f"{m.group(1)}.dst {m.group(2)}-{m.group(3)}", s)
    return s


def fmt_hex(n: Any) -> str:
    try:
        v = int(n)
    except (TypeError, ValueError):
        return "(missing in dump)"
    return f"0x{v:x}"


def of_metadata(dp_key: Any, port_key: Any) -> Tuple[str, str]:
    """OpenFlow metadata = dp_key << 16 | port_key. Hex + decimal footnote."""
    try:
        dp = int(dp_key or 0)
        pk = int(port_key or 0)
    except (TypeError, ValueError):
        return "(missing in dump)", ""
    if not dp and not pk:
        return "(missing in dump)", ""
    meta = (dp << 16) | (pk & 0xFFFF)
    return fmt_hex(meta), str(meta)


_ACL_LABEL_RE = re.compile(
    r"^([0-9a-fA-F-]{36})\s+\S+\s+\S+\s+\{[^}]*\}\s+(\d+)\b"
)


@lru_cache(maxsize=1)
def _acl_labels() -> Dict[str, int]:
    """NB ACL._uuid -> label (integer). flow_ovn.ovn_acl has no label column."""
    out: Dict[str, int] = {}
    if not os.path.isfile(NB_DUMP):
        return out
    in_acl = False
    with open(NB_DUMP, errors="replace") as fh:
        for line in fh:
            if line.startswith("ACL table"):
                in_acl = True
                continue
            if in_acl and re.match(r"^[A-Za-z_]+ table", line):
                break
            if not in_acl:
                continue
            m = _ACL_LABEL_RE.match(line)
            if m:
                out[m.group(1).lower()] = int(m.group(2))
    return out


def acl_label_hex(acl_uuid: str) -> str:
    uid = str(acl_uuid or "").strip().lower()
    labs = _acl_labels()
    if uid not in labs:
        return "(missing in dump)"
    return fmt_hex(labs[uid])


def zone_from_options(opts: Any) -> str:
    if not isinstance(opts, dict):
        return ""
    for k, v in opts.items():
        lk = str(k).lower().replace("-", "_")
        if lk in ("ct_zone", "ctzone") or lk == "zone":
            s = str(v).strip().strip('"')
            if s:
                return s
    return ""


@lru_cache(maxsize=1)
def _sb_port_binding_offset() -> int:
    if not os.path.isfile(SB_DUMP):
        return -1
    needle = b"Port_Binding table\n"
    with open(SB_DUMP, "rb") as fh:
        pos = 0
        chunk = b""
        while True:
            more = fh.read(1 << 20)
            if not more:
                break
            data = chunk[-len(needle) :] + more
            i = data.find(needle)
            if i >= 0:
                return pos - min(len(chunk), len(needle)) + i
            pos += len(more)
            chunk = more[-len(needle) :]
    return -1


@lru_cache(maxsize=64)
def pb_ct_zone(logical_port: str) -> str:
    """SB Port_Binding.options ct_zone for this VIF. Else missing-in-dump."""
    name = str(logical_port or "")
    if not name or not os.path.isfile(SB_DUMP):
        return "(missing in dump)"
    off = _sb_port_binding_offset()
    if off < 0:
        return "(missing in dump)"
    zone_re = re.compile(
        r'(?:^|,\s*)ct[-_]?zone\s*=\s*"?([^,}\s"]+)"?', re.I
    )
    with open(SB_DUMP, errors="replace") as fh:
        fh.seek(off)
        next(fh, "")
        for line in fh:
            if re.match(r"^[A-Za-z_]+ table", line):
                break
            if name not in line:
                continue
            for blob in re.findall(r"\{([^}]*)\}", line):
                zm = zone_re.search(blob)
                if zm:
                    return zm.group(1)
            return "(missing in dump)"
    return "(missing in dump)"


def human_acl_row(
    acl: dict,
    nic_uuid: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    ct_zone: str = "",
    metadata_hex: str = "",
    sample: int = SAMPLE_IPS,
    full_ips: bool = False,
) -> dict:
    """One human ACL table row. Identity UUID stays in the footnote column."""
    match = acl.get("match") or ""
    pgs = [_pg_human(u, nic_uuid) for u in _pg_uuids(match)]
    sets = [_as_human(n, src_ip, dst_ip, sample) for n in _as_names(match)]
    applied = "; ".join(
        f"{p['label']} ({'member' if p['member'] else 'not-member'}, "
        f"{p['nic_count']} NICs, IPs {', '.join(p['sample_ips'][:3])})"
        for p in pgs
    ) or "-"
    peers_bits = []
    details: List[dict] = []
    for s in sets:
        hit = []
        if src_ip:
            hit.append("src-in" if s["src_in"] else "src-out")
        if dst_ip:
            hit.append("dst-in" if s["dst_in"] else "dst-out")
        show = ", ".join(s["sample"])
        extra = f"+{s['count'] - len(s['sample'])}" if s["count"] > len(s["sample"]) else ""
        peers_bits.append(
            f"{s['label']} ({s['count']} IPs; {', '.join(hit)}; {show}{extra})"
        )
        if s["rest"]:
            details.append(s)
    uid = str(acl.get("acl_uuid") or "")
    lab = acl_label_hex(uid)
    return {
        "pri": acl.get("priority"),
        "action": acl.get("action") or "",
        "direction": acl.get("direction") or "",
        "applied": applied,
        "peers": "; ".join(peers_bits) or "-",
        "l4": expand_l4(match) or "-",
        "ct_zone": ct_zone or "(missing in dump)",
        "metadata": metadata_hex or "(missing in dump)",
        "ct_label": lab,
        "match": rewrite_match_human(match, nic_uuid, src_ip, dst_ip),
        "uuid": uid,
        "ip_details": details if full_ips else details,
    }


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


ZERO_PS = "00000000-0000-0000-0000-000000000000"
LEFTOVER_MD = "/home/rakeshkumar.r/panacea/clickhouse_flow/leftover_observations.md"
LEFTOVER_IGNORE = "/home/rakeshkumar.r/panacea/clickhouse_flow/leftover_ignore.py"


@lru_cache(maxsize=1)
def _leftover_ignore():
    spec = importlib.util.spec_from_file_location("leftover_ignore", LEFTOVER_IGNORE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _nic_ids(ps: dict) -> Tuple[set, set, set, set]:
    def grab(key: str) -> set:
        out = set()
        for n in ps.get(key) or []:
            if isinstance(n, str) and len(n) >= 32:
                out.add(n.lower())
            elif isinstance(n, dict):
                u = str(n.get("nic_uuid") or n.get("uuid") or "")
                if u:
                    out.add(u.lower())
            elif isinstance(n, (list, tuple)) and n:
                out.add(str(n[0]).lower())
        return {x for x in out if x and x != ZERO_PS}

    atlas = grab("atlas_nic_uuids") | grab("atlas_nics")
    comp = grab("computed_nic_uuids") | grab("computed_nics")
    only_a = grab("only_atlas_nics") or (atlas - comp)
    only_c = grab("only_computed_nics") or (comp - atlas)
    return atlas, comp, only_a, only_c


def _pg_uuids(match: str) -> List[str]:
    return [_underscores_to_uuid(m.group(1)) for m in PG_RE.finditer(match or "")]


def _as_names(match: str) -> List[str]:
    return ["address_set_" + m.group(1) for m in AS_RE.finditer(match or "")]


def explain_drop_policy(acl: Optional[dict]) -> List[str]:
    """Name the Flow policy / port-set that owns the first-hit drop ACL."""
    if not acl:
        return ["- No matching ACL (implicit allow / next hop)."]
    match = acl.get("match") or ""
    pri = acl.get("priority")
    action = acl.get("action")
    direc = acl.get("direction")
    pretty = rewrite_match(match)
    lines = [
        f"- OVN first hit: **pri {pri} {action}** `{direc}`",
        f"- Match (rewritten): `{pretty}`",
        f"- Match (OVN raw): `{match}`",
    ]
    pg_names: List[str] = []
    for uid in _pg_uuids(match):
        ps = _portsets().get(uid) or {}
        cats = ps.get("vm_category_names") or ps.get("reference_names") or []
        cat = cats[0] if cats else ""
        name = ps.get("atlas_name") or uid
        role = ps.get("role") or ""
        pg_names.append(str(name))
        lines.append(
            f"- **Applied-to policy** `{cat}/{name}` "
            f"uuid `{uid}` role `{role}` "
            f"(OVN `@port_group_{uid.replace('-', '_')}`)"
        )
    dest_names: List[str] = []
    for as_name in _as_names(match):
        addrs = _address_sets().get(as_name) or []
        dest = _match_portset_by_ips(addrs)
        dest_disp = dest.replace(" ", "_") if dest else as_name
        dest_names.append(dest_disp)
        sample = ", ".join(addrs[:4])
        extra = f" +{len(addrs) - 4}" if len(addrs) > 4 else ""
        lines.append(
            f"- **Dest/src address-set** `${dest_disp}` "
            f"({len(addrs)} IPs: {sample}{extra}) OVN `${as_name}`"
        )
    if str(action) == "drop" and int(pri or 0) >= 1060:
        who = pg_names[0] if pg_names else "applied-to group"
        dest = dest_names[0] if dest_names else "the named secured address-set"
        lines.append(
            f"- **Why it drops:** isolation — `{who}` cannot send to `{dest}` "
            f"secured IPs, so pri {pri} drop wins before pri 1050 allow-related "
            "(wrong dest-set / ports) and before pri 1045 catch-all and "
            "pri 500 `tcp || udp || icmp`."
        )
    elif str(action) == "drop":
        lines.append(
            "- **Why it drops:** catch-all drop on the applied-to group "
            "(no higher-pri allow matched this dest/protocol)."
        )
    return lines


def portset_issues_md(nic_uuids: List[str]) -> List[str]:
    """Atlas-only leftovers + which port-sets the path NICs belong to.

    Reads dump jsonl (not flow_policy ClickHouse).
    """
    nics = {n.lower() for n in nic_uuids if n}
    leftover: List[dict] = []
    membership: List[str] = []
    nic_bugs: List[str] = []
    leftover_nics: List[str] = []
    skipped_k8s = 0
    skipped_quarantine = 0
    ignore_mod = _leftover_ignore()
    for uid, ps in _portsets().items():
        kind = str(ps.get("mismatch_kind") or "")
        status = str(ps.get("match_status") or "")
        atlas_uid = str(ps.get("atlas_port_set_uuid") or "")
        comp_uid = str(ps.get("computed_port_set_uuid") or "")
        atlas, comp, only_a, only_c = _nic_ids(ps)
        name = ps.get("atlas_name") or ""
        role = ps.get("role") or ""
        atlas_only = (
            kind in ("atlas_without_computed", "atlas_only")
            or status in ("atlas_without_computed", "atlas_only")
            or (
                atlas_uid
                and atlas_uid != ZERO_PS
                and (not comp_uid or comp_uid == ZERO_PS)
            )
        )
        ignore_reason = ignore_mod.leftover_ignore_reason(ps) if atlas_only else ""
        if atlas_only and ignore_reason == "k8s":
            skipped_k8s += 1
        elif atlas_only and ignore_reason == "empty_quarantine":
            skipped_quarantine += 1
        elif atlas_only:
            leftover.append(ps)
        disp_status = kind or status or "match"
        hit = nics & (atlas | comp | only_a | only_c)
        if hit:
            for nic in sorted(hit):
                membership.append(
                    f"- NIC `{nic}` in `{name}` uuid `{uid}` role `{role}` "
                    f"status `{disp_status}` "
                    f"(atlas {len(atlas)} NICs, computed {len(comp)})"
                )
            if atlas_only and not ignore_reason:
                leftover_nics.append(
                    f"- Path NIC `{sorted(hit)[0]}` is on leftover "
                    f"`atlas_without_computed` port-set `{uid}` `{name}`"
                )
            bad_a = only_a & nics
            bad_c = only_c & nics
            if bad_a:
                nic_bugs.append(
                    f"- Atlas-only NIC `{sorted(bad_a)[0]}` on port-set `{uid}` `{name}`"
                )
            if bad_c:
                nic_bugs.append(
                    f"- Computed-only NIC `{sorted(bad_c)[0]}` on port-set `{uid}` `{name}`"
                )
    leftover.sort(key=lambda p: str(p.get("port_set_uuid") or p.get("atlas_name")))
    out = [
        f"- Dump-wide **Atlas-only port-sets** (`mismatch_kind=atlas_without_computed`, "
        f"Atlas UUID, no computed UUID): **{len(leftover)}**",
        f"- ignored {skipped_k8s} K8s leftovers, "
        f"{skipped_quarantine} empty Quarantine leftovers",
    ]
    if leftover:
        out.append("")
        out.append("| port-set UUID | atlas name | role | mismatch_kind |")
        out.append("|---|---|---|---|")
        for ps in leftover:
            out.append(
                f"| `{ps.get('port_set_uuid')}` | `{ps.get('atlas_name') or ''}` | "
                f"`{ps.get('role') or ''}` | "
                f"`{ps.get('mismatch_kind') or ps.get('match_status') or ''}` |"
            )
        out.append("")
        out.append(
            "These UUIDs exist in Atlas `port_set.list` and are absent from computed "
            "hashes. Identity is UUID; a matching *name* on another UUID is a different object."
        )
    out.append("")
    out.append("Path NIC membership (jsonl, not leftover-by-name):")
    out.extend(membership or ["- (path NICs not found in portset.jsonl)"])
    out.append("")
    if leftover_nics:
        out.append("Path NICs on leftover (atlas-only) port-sets:")
        out.extend(leftover_nics)
    else:
        out.append(
            "- Path NICs are **not** members of dump-wide leftover "
            "`atlas_without_computed` port-sets."
        )
    if nic_bugs:
        out.append("")
        out.append("NIC UUID bugs on this path:")
        out.extend(nic_bugs)
    else:
        out.append("- No Atlas-vs-computed NIC UUID mismatch on the path port-sets.")
    if os.path.isfile(LEFTOVER_MD):
        out.append(f"- Leftover observer write-up: `{LEFTOVER_MD}`")
    return out


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
explain_drop_policy = explain_drop_policy
portset_issues_md = portset_issues_md
human_acl_row = human_acl_row
expand_l4 = expand_l4
rewrite_match_human = rewrite_match_human
of_metadata = of_metadata
acl_label_hex = acl_label_hex
pb_ct_zone = pb_ct_zone
fmt_hex = fmt_hex
