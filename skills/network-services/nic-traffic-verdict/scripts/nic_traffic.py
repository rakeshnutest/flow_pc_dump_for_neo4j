#!/usr/bin/env python3
"""Allowed or denied between two VM NICs on one L4 port.

Names the allow policy and the deny policy. Output uses policy names,
category names, and IPs. Address-set tokens and port-group tokens stay
out of the text.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

CH = ["clickhouse-client", "--host", "127.0.0.1", "--port", "19000", "--user", "default", "--query"]
NB_REL = ("cmsp_ovn", "anc-ovn", "commands", "ovsdb-client_dump_nb.txt")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PG_IN = re.compile(r"inport\s*==\s*@(port_group_[0-9a-fA-F_]+)")
PG_OUT = re.compile(r"outport\s*==\s*@(port_group_[0-9a-fA-F_]+)")
AS_FIELD = re.compile(r"ip[46]\.(src|dst)\s*==\s*\$(address_set_[0-9a-fA-F_]+)")
LIT_FIELD = re.compile(r"ip[46]\.(src|dst)\s*==\s*([0-9a-fA-F:.]+(?:/\d+)?)")
RANGE_RE = re.compile(
    r"(tcp|udp)\.(dst|src)\s*>=\s*(\d+)\s*&&\s*(tcp|udp)\.(dst|src)\s*<=\s*(\d+)")
EQ_RE = re.compile(r"(tcp|udp)\.(dst|src)\s*==\s*(\d+)")
ICMP_RE = re.compile(r"icmp[46]\.type\s*==\s*(\d+)")
ALLOW_PREFIX = "allow"


def ch(sql: str) -> str:
    proc = subprocess.run(CH + [sql], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or "clickhouse query failed")
    return proc.stdout


def rows(sql: str) -> list:
    out = []
    for line in ch(sql).splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def sql_str(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def port_group_uuid(token: str) -> str:
    body = token[len("port_group_"):] if token.startswith("port_group_") else token
    parts = body.split("_")
    if [len(part) for part in parts] != [8, 4, 4, 4, 12]:
        return ""
    uid = "-".join(parts).lower()
    return uid if UUID_RE.match(uid) else ""


def pg_token(uid: str) -> str:
    return "port_group_" + uid.replace("-", "_")


def ip_in_specs(ip: str, specs) -> bool:
    raw = (ip or "").split("/")[0]
    if not raw:
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    for spec in specs or []:
        spec = str(spec or "").strip()
        if not spec or spec.startswith("$"):
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


def l4_text(match: str) -> str:
    ports = []
    covered = []
    for found in RANGE_RE.finditer(match or ""):
        if found.group(1) != found.group(4) or found.group(2) != "dst":
            continue
        ports.append("%s %s-%s" % (found.group(1), found.group(3), found.group(6)))
        covered.append((found.start(), found.end()))
    for found in EQ_RE.finditer(match or ""):
        if found.group(2) != "dst":
            continue
        if any(start <= found.start() < end for start, end in covered):
            continue
        ports.append("%s %s" % (found.group(1), found.group(3)))
    for found in ICMP_RE.finditer(match or ""):
        ports.append("icmp type %s" % found.group(1))
    uniq = []
    for item in ports:
        if item not in uniq:
            uniq.append(item)
    return ", ".join(uniq) if uniq else "all ports"


def _port_in_match(match: str, kind: str, dport: int) -> bool:
    for start, end in re.findall(
        rf"{kind}\.dst\s*>=\s*(\d+)\s*&&\s*{kind}\.dst\s*<=\s*(\d+)", match
    ):
        if int(start) <= dport <= int(end):
            return True
    for item in re.findall(rf"{kind}\.dst\s*==\s*(\d+)", match):
        if int(item) == dport:
            return True
    return False


def field_ok(match: str, side: str, ip: str, address_sets: dict) -> bool:
    sets = [name for found_side, name in AS_FIELD.findall(match) if found_side == side]
    literals = [spec for found_side, spec in LIT_FIELD.findall(match) if found_side == side]
    if not sets and not literals:
        return True
    if any(ip_in_specs(ip, address_sets.get(name) or []) for name in sets):
        return True
    if any(ip_in_specs(ip, [spec]) for spec in literals):
        return True
    return False


def acl_matches(acl: dict, pkt: dict, address_sets: dict, skip_l4: bool = False) -> bool:
    match = acl.get("match") or ""
    if "udp.src == 67" in match:
        return False
    ip_ver = pkt["ip_ver"]
    has4 = "ip4" in match
    has6 = "ip6" in match
    if ip_ver == "ip4" and has6 and not has4:
        return False
    if ip_ver == "ip6" and has4 and not has6:
        return False
    for token in PG_IN.findall(match):
        if token not in pkt["inport_pgs"]:
            return False
    for token in PG_OUT.findall(match):
        if token not in pkt["outport_pgs"]:
            return False
    if not field_ok(match, "src", pkt["src_ip"], address_sets):
        return False
    if not field_ok(match, "dst", pkt["dst_ip"], address_sets):
        return False
    if skip_l4:
        return True
    proto = pkt["proto"]
    dport = pkt["dport"]
    locked = any(
        token in match
        for token in ("ip.proto", "tcp.dst", "udp.dst", "icmp4", "icmp6", "tcp.src", "udp.src")
    )
    if not locked:
        return True
    if proto == 1:
        if "icmp" not in match and "ip.proto == 1" not in match:
            return False
        types = [int(item) for item in ICMP_RE.findall(match)]
        if types and dport not in types:
            return False
        return True
    if proto == 6:
        if "tcp || udp || icmp" in match and "tcp.dst" not in match:
            return True
        if "ip.proto == 6" not in match and "tcp.dst" not in match:
            return False
        if "tcp.dst" in match and not _port_in_match(match, "tcp", dport):
            return False
        return True
    if proto == 17:
        if "tcp || udp || icmp" in match and "udp.dst" not in match:
            return True
        if "ip.proto == 17" not in match and "udp.dst" not in match:
            return False
        if "udp.dst" in match and not _port_in_match(match, "udp", dport):
            return False
        return True
    return False


def load_address_sets(nb_path: str, needed: set) -> dict:
    found = {}
    if not nb_path or not needed or not os.path.isfile(nb_path):
        return found
    in_table = False
    with open(nb_path, errors="replace") as handle:
        for line in handle:
            if line.startswith("Address_Set table"):
                in_table = True
                continue
            if in_table and re.match(r"^[A-Za-z_]+ table", line):
                break
            if not in_table:
                continue
            for name in needed:
                if name in line:
                    ips = []
                    for item in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?", line):
                        if item not in ips:
                            ips.append(item)
                    found[name] = ips
                    break
            if len(found) == len(needed):
                break
    return found


def policy_label(ps: dict) -> str:
    seen = []
    for rule in ps.get("rules") or []:
        name, kind, mode = rule[0], rule[1], rule[2]
        if not name:
            continue
        label = "%s (%s, %s)" % (name, kind or "policy", mode or "enforce")
        if label not in seen:
            seen.append(label)
    if seen:
        return "; ".join(seen)
    return ps.get("atlas_name") or "unnamed policy"


def category_label(ps: dict) -> str:
    cats = [item for item in (ps.get("vm_category_names") or []) if item]
    if cats:
        return cats[0]
    role = ps.get("role") or ""
    return role or ps.get("atlas_name") or "port-set"


def applied_portset(acl: dict, by_uuid: dict) -> dict:
    match = acl.get("match") or ""
    direction = acl.get("direction") or ""
    tokens = PG_IN.findall(match) if direction == "from-lport" else PG_OUT.findall(match)
    if not tokens:
        tokens = PG_IN.findall(match) + PG_OUT.findall(match)
    for token in tokens:
        uid = port_group_uuid(token)
        if uid and uid in by_uuid:
            return by_uuid[uid]
    return {}


def peer_side(direction: str) -> str:
    return "dst" if direction == "from-lport" else "src"


def peer_ips(match: str, side: str, address_sets: dict) -> list:
    specs = []
    for found_side, name in AS_FIELD.findall(match):
        if found_side == side:
            specs.extend(address_sets.get(name) or [])
    for found_side, spec in LIT_FIELD.findall(match):
        if found_side == side and not spec.startswith("$"):
            specs.append(spec)
    uniq = []
    for spec in specs:
        if spec and spec not in uniq:
            uniq.append(spec)
    return uniq


def host_of(spec: str) -> str:
    return (spec or "").split("/")[0]


def format_ips(ips: list) -> str:
    def sort_key(ip: str):
        parts = host_of(ip).split(".")
        try:
            return tuple(int(part) for part in parts)
        except ValueError:
            return (999999, ip)
    return ", ".join(sorted(ips, key=sort_key))


def name_peer(ips: list, by_uuid: dict, ip_index: dict, applied_uuid: str) -> str:
    if not ips:
        return ""
    scores = Counter()
    for ip in ips:
        ip = host_of(ip)
        for uid in ip_index.get(ip, ()):
            scores[uid] += 1
    if not scores:
        return ""
    best_id, _best_n = scores.most_common(1)[0]
    chosen = best_id
    if best_id == applied_uuid:
        for uid, count in scores.most_common(8):
            if uid == applied_uuid:
                continue
            role = (by_uuid.get(uid) or {}).get("role") or ""
            if count >= max(3, len(ips) // 2) and role != "secured":
                chosen = uid
                break
    ps = by_uuid.get(chosen) or {}
    cat = category_label(ps)
    pol = policy_label(ps)
    if cat and pol and cat not in pol:
        return "%s / %s" % (cat, pol)
    return pol or cat


def peer_label(peer_list, match: str, by_uuid: dict, ip_index: dict, applied_uuid: str) -> str:
    if not peer_list and not AS_FIELD.findall(match or "") and not LIT_FIELD.findall(match or ""):
        return "any"
    if not peer_list:
        return "no addresses in the OVN dump"
    named = name_peer(peer_list, by_uuid, ip_index, applied_uuid)
    if named:
        return named
    kind = "prefixes" if any("/" in spec for spec in peer_list) else "addresses"
    return "%s (%d)" % (kind, len(peer_list))


def direction_phrase(acl: dict, both: bool) -> str:
    if both:
        return "both directions"
    if acl.get("direction") == "from-lport":
        return "out of the source"
    return "into the destination"


def describe(acl: dict, by_uuid: dict, ip_index: dict, address_sets: dict, both: bool = False) -> str:
    applied = applied_portset(acl, by_uuid)
    applied_uuid = applied.get("port_set_uuid") or ""
    peer_list = peer_ips(acl.get("match") or "", peer_side(acl.get("direction") or ""), address_sets)
    peer = peer_label(peer_list, acl.get("match") or "", by_uuid, ip_index, applied_uuid)
    return (
        "%s on %s, %s, priority %s %s, peer %s, ports %s"
        % (
            policy_label(applied),
            category_label(applied),
            direction_phrase(acl, both),
            acl.get("priority"),
            acl.get("action"),
            peer,
            l4_text(acl.get("match") or ""),
        )
    )


def same_rule(left: dict, right: dict, by_uuid: dict) -> bool:
    if not left or not right:
        return False
    return (
        int(left.get("priority") or 0) == int(right.get("priority") or 0)
        and left.get("action") == right.get("action")
        and policy_label(applied_portset(left, by_uuid)) == policy_label(applied_portset(right, by_uuid))
    )


def resolve_nic(bid: int, token: str) -> dict:
    token = token.strip()
    if UUID_RE.match(token):
        where = "toString(nic_uuid) = %s" % sql_str(token.lower())
    elif IP_RE.match(token):
        where = "ip = %s OR startsWith(ip, %s)" % (sql_str(token), sql_str(token + "/"))
    else:
        where = "vm_name = %s" % sql_str(token)
    found = rows(
        "SELECT vm_name, toString(nic_uuid) AS nic_uuid, ip, subnet, vpc, "
        "toString(subnet_uuid) AS subnet_uuid "
        "FROM flow_policy.vm_nic FINAL "
        "WHERE log_bundle_id = %d AND (%s) "
        "FORMAT JSONEachRow" % (bid, where)
    )
    if not found:
        raise SystemExit("No VM NIC matches %s" % token)
    if len(found) > 1:
        lines = ["%s matches %d NICs. Pass one NIC uuid:" % (token, len(found))]
        for item in found:
            lines.append("  %s  %s  %s" % (item.get("vm_name"), item.get("ip"), item.get("nic_uuid")))
        raise SystemExit("\n".join(lines))
    return found[0]


def load_portsets(bid: int) -> list:
    return rows(
        "SELECT toString(port_set_uuid) AS port_set_uuid, atlas_name, role, "
        "vm_category_names, "
        "arrayMap(x -> (tupleElement(x,'policy_name'), tupleElement(x,'policy_type'), "
        "tupleElement(x,'policy_mode'), tupleElement(x,'type')), rule_u_sg) AS rules, "
        "arrayDistinct(arrayMap(n -> toString(tupleElement(n,'nic_uuid')), "
        "arrayConcat(atlas_nics, computed_nics))) AS nic_uuids, "
        "arrayDistinct(arrayMap(n -> splitByChar('/', tupleElement(n,'ip'))[1], "
        "arrayConcat(atlas_nics, computed_nics))) AS ips "
        "FROM flow_policy.portset FINAL "
        "WHERE log_bundle_id = %d FORMAT JSONEachRow" % bid
    )


def dump_dir(bid: int) -> str:
    found = rows(
        "SELECT dump_dir FROM flow_policy.bundle FINAL "
        "WHERE log_bundle_id = %d LIMIT 1 FORMAT JSONEachRow" % bid
    )
    if found:
        return found[0].get("dump_dir") or ""
    return ""


def ip_family(match: str) -> str:
    has4 = "ip4" in (match or "")
    has6 = "ip6" in (match or "")
    if has4 and has6:
        return "ip4 and ip6"
    if has4:
        return "ip4"
    if has6:
        return "ip6"
    return "any"


def cell(value) -> str:
    return str(value or "").replace("|", "/").replace("\n", " ")


def unique_ids(uids: list) -> list:
    seen = []
    for uid in uids:
        if uid and uid not in seen:
            seen.append(uid)
    return seen


def print_portsets(title, uids, by_uuid) -> None:
    print(title)
    print("| policy | category | role | port-set |")
    print("|---|---|---|---|")
    if not uids:
        print("| (none) | | | |")
        return
    for uid in uids:
        ps = by_uuid.get(uid) or {}
        print("| %s | %s | %s | %s |" % (
            cell(policy_label(ps)),
            cell(category_label(ps)),
            cell(ps.get("role") or ""),
            uid,
        ))
    print("")


def source_outgoing(acl: dict, src_pgs: set) -> bool:
    """from-lport whose inport is a port-set the source NIC belongs to."""
    if acl.get("direction") != "from-lport":
        return False
    return bool(set(PG_IN.findall(acl.get("match") or "")) & src_pgs)


def dest_incoming(acl: dict, dst_pgs: set) -> bool:
    """to-lport whose outport is a port-set the destination NIC belongs to."""
    if acl.get("direction") != "to-lport":
        return False
    return bool(set(PG_OUT.findall(acl.get("match") or "")) & dst_pgs)


def _q(sql: str) -> list:
    try:
        return rows(sql)
    except SystemExit:
        return []


def hex24(value) -> str:
    try:
        return "0x%06x" % int(value or 0)
    except (TypeError, ValueError):
        return "0x000000"


def acl_cookie(acl_uuid: str) -> str:
    """OVN OpenFlow cookie: stage-hint, the first 32 bits of the ACL uuid."""
    text = (acl_uuid or "").split("-")[0]
    if len(text) != 8:
        return ""
    try:
        int(text, 16)
    except ValueError:
        return ""
    return "0x" + text


def chassis_host(bid: int, token: str) -> dict:
    token = (token or "").strip()
    empty = {"hostname": "", "geneve_ip": "", "chassis_name": "", "chassis_uuid": ""}
    if not token or token == "00000000-0000-0000-0000-000000000000":
        return empty
    found = _q(
        "SELECT c.hostname AS hostname, c.name AS chassis_name, e.ip AS geneve_ip, "
        "toString(c.chassis_uuid) AS chassis_uuid "
        "FROM flow_ovn.ovn_chassis AS c FINAL "
        "LEFT JOIN flow_ovn.ovn_encap AS e FINAL "
        "ON c.log_bundle_id = e.log_bundle_id AND c.chassis_uuid = e.chassis_uuid "
        "WHERE c.log_bundle_id = %d AND (toString(c.chassis_uuid) = %s OR c.name = %s OR c.hostname = %s) "
        "LIMIT 1 FORMAT JSONEachRow" % (bid, sql_str(token), sql_str(token), sql_str(token))
    )
    if not found:
        return empty
    row = found[0]
    return {
        "hostname": row.get("hostname") or "",
        "geneve_ip": row.get("geneve_ip") or "",
        "chassis_name": row.get("chassis_name") or "",
        "chassis_uuid": row.get("chassis_uuid") or "",
    }


def redirect_chassis(bid: int, group_uuid: str) -> dict:
    group_uuid = (group_uuid or "").strip()
    if not group_uuid or group_uuid == "00000000-0000-0000-0000-000000000000":
        return {}
    rows = _q(
        "SELECT chassis_name, priority, group_name "
        "FROM flow_ovn.ovn_ha_chassis FINAL "
        "WHERE log_bundle_id = %d AND toString(group_uuid) = %s "
        "ORDER BY priority DESC FORMAT JSONEachRow" % (bid, sql_str(group_uuid))
    )
    if not rows:
        return {}
    top = rows[0]
    host = chassis_host(bid, top.get("chassis_name") or "")
    host["priority"] = int(top.get("priority") or 0)
    host["group_name"] = top.get("group_name") or ""
    return host


def endpoint_path(bid: int, nic: dict) -> dict:
    """Switch, subnet, and the VM port binding for one NIC."""
    nic_uuid = (nic.get("nic_uuid") or "").lower()
    ip = (nic.get("ip") or "").split("/")[0]
    subnet_uuid = (nic.get("subnet_uuid") or "").lower()
    port_name = "port_%s" % nic_uuid if nic_uuid else ""
    lsp = _q(
        "SELECT name, toString(lsp_uuid) AS lsp_uuid, toString(ls_uuid) AS ls_uuid, mac, tag "
        "FROM flow_ovn.ovn_lsp FINAL "
        "WHERE log_bundle_id = %d AND (name = %s OR toString(nic_uuid) = %s) "
        "FORMAT JSONEachRow" % (bid, sql_str(port_name), sql_str(nic_uuid))
    )
    chosen = lsp[0] if lsp else {}
    if not chosen and ip:
        lsp = _q(
            "SELECT name, toString(lsp_uuid) AS lsp_uuid, toString(ls_uuid) AS ls_uuid, mac, tag "
            "FROM flow_ovn.ovn_lsp FINAL "
            "WHERE log_bundle_id = %d AND has(ip4, %s) AND type = '' "
            "FORMAT JSONEachRow" % (bid, sql_str(ip))
        )
        chosen = lsp[0] if lsp else {}
    ls_uuid = chosen.get("ls_uuid") or "00000000-0000-0000-0000-000000000000"
    switch_rows = _q(
        "SELECT nb_name, nb_requested_tnl_key, nb_interconn, "
        "toString(ls_uuid) AS ls_uuid, toString(sb_datapath_uuid) AS sb_datapath_uuid, "
        "sb_tunnel_key, sb_egress_tunnel_key, sb_name "
        "FROM flow_ovn.ovn_switch FINAL "
        "WHERE log_bundle_id = %d AND toString(ls_uuid) = %s "
        "FORMAT JSONEachRow" % (bid, sql_str(ls_uuid))
    )
    switch = switch_rows[0] if switch_rows else {}
    subnet_rows = _q(
        "SELECT toString(subnet_uuid) AS subnet_uuid, nb_cidr, nb_gateway_ip, nb_gateway_mac, "
        "nb_mtu, nb_ls_name, toString(nb_ls_uuid) AS nb_ls_uuid, "
        "toString(sb_datapath_uuid) AS sb_datapath_uuid, sb_tunnel_key, sb_egress_tunnel_key "
        "FROM flow_ovn.ovn_subnet FINAL "
        "WHERE log_bundle_id = %d AND (toString(subnet_uuid) = %s OR toString(nb_ls_uuid) = %s) "
        "FORMAT JSONEachRow" % (bid, sql_str(subnet_uuid), sql_str(ls_uuid))
    )
    subnet = {}
    for item in subnet_rows:
        if item.get("subnet_uuid") == subnet_uuid:
            subnet = item
            break
    if not subnet and subnet_rows:
        subnet = subnet_rows[0]
    port_number = 0
    port_up = 0
    chassis = ""
    if chosen.get("name"):
        binding = _q(
            "SELECT tunnel_key, up, toString(chassis_uuid) AS chassis_uuid "
            "FROM flow_ovn.ovn_port_binding FINAL "
            "WHERE log_bundle_id = %d AND logical_port = %s "
            "FORMAT JSONEachRow" % (bid, sql_str(chosen["name"]))
        )
        if binding:
            port_number = int(binding[0].get("tunnel_key") or 0)
            port_up = int(binding[0].get("up") or 0)
            chassis = binding[0].get("chassis_uuid") or ""
    return {
        "vm_name": nic.get("vm_name") or "",
        "nic_uuid": nic_uuid,
        "ip": ip,
        "vpc": nic.get("vpc") or "",
        "subnet_name": nic.get("subnet") or "",
        "vlan": int(chosen.get("tag") or 0),
        "host": chassis_host(bid, chassis),
        "subnet": subnet,
        "switch": {
            "nb": {
                "ls_uuid": switch.get("ls_uuid") or ls_uuid,
                "name": switch.get("nb_name") or "",
                "requested_tnl_key": int(switch.get("nb_requested_tnl_key") or 0),
                "interconn": int(switch.get("nb_interconn") or 0),
            },
            "sb": {
                "datapath_uuid": switch.get("sb_datapath_uuid") or "",
                "tunnel_key": int(switch.get("sb_tunnel_key") or 0),
                "egress_tunnel_key": int(switch.get("sb_egress_tunnel_key") or 0),
                "name": switch.get("sb_name") or "",
            },
        },
        "port": {
            "lsp_uuid": chosen.get("lsp_uuid") or "",
            "name": chosen.get("name") or "",
            "mac": chosen.get("mac") or "",
            "port_number": port_number,
            "up": port_up,
            "sb_chassis_uuid": chassis,
        },
    }


def _walk(src_ls: str, dst_ls: str, ls_edges: list, lr_edges: list) -> list:
    """Shortest switch/router hop list. Each hop is (kind, uuid)."""
    if not src_ls or src_ls == dst_ls:
        return [("switch", src_ls)] if src_ls else []
    ls_to_lr = defaultdict(list)
    lr_to_ls = defaultdict(list)
    for edge in ls_edges:
        ls_to_lr[edge["ls"]].append(edge["lr"])
        lr_to_ls[edge["lr"]].append(edge["ls"])
    lr_to_lr = defaultdict(list)
    for edge in lr_edges:
        via = edge.get("via_ls") or ""
        lr_to_lr[edge["a"]].append((edge["b"], via))
        lr_to_lr[edge["b"]].append((edge["a"], via))
    start = ("switch", src_ls)
    goal = ("switch", dst_ls)
    prev = {start: None}
    queue = [start]
    found = False
    while queue:
        node = queue.pop(0)
        if node == goal:
            found = True
            break
        kind, uid = node
        nxt = []
        if kind == "switch":
            nxt = [("router", lr) for lr in ls_to_lr.get(uid, [])]
        else:
            nxt = [("switch", ls) for ls in lr_to_ls.get(uid, [])]
            nxt += [("router", other) for other, _via in lr_to_lr.get(uid, [])]
        for item in nxt:
            if item not in prev and item[1]:
                prev[item] = node
                queue.append(item)
        if len(prev) > 4000:
            break
    if not found:
        return [("switch", src_ls)]
    chain = []
    cursor = goal
    while cursor:
        chain.append(cursor)
        cursor = prev[cursor]
    chain.reverse()
    return chain


def load_forwarding(bid: int, src: dict, dst: dict) -> dict:
    src_ep = endpoint_path(bid, src)
    dst_ep = endpoint_path(bid, dst)
    src_ls = src_ep["switch"]["nb"]["ls_uuid"]
    dst_ls = dst_ep["switch"]["nb"]["ls_uuid"]
    ls_edges = [
        {"ls": item.get("ls"), "lr": item.get("lr")}
        for item in _q(
            "SELECT toString(ls_uuid) AS ls, toString(lr_uuid) AS lr "
            "FROM flow_ovn.ovn_edge_ls_lr FINAL WHERE log_bundle_id = %d "
            "FORMAT JSONEachRow" % bid
        )
    ]
    lr_edges = [
        {"a": item.get("a"), "b": item.get("b"), "via_ls": item.get("via_ls")}
        for item in _q(
            "SELECT toString(lr_a) AS a, toString(lr_b) AS b, toString(via_ls_uuid) AS via_ls "
            "FROM flow_ovn.ovn_edge_lr_lr FINAL WHERE log_bundle_id = %d "
            "FORMAT JSONEachRow" % bid
        )
    ]
    chain = _walk(src_ls, dst_ls, ls_edges, lr_edges)
    router_ids = [uid for kind, uid in chain if kind == "router" and uid]
    switch_ids = []
    for kind, uid in chain:
        if kind == "switch" and uid and uid not in switch_ids:
            switch_ids.append(uid)
    for uid in (src_ls, dst_ls):
        if uid and uid not in switch_ids:
            switch_ids.append(uid)
    routers = []
    if router_ids:
        id_sql = ", ".join(sql_str(uid) for uid in router_ids)
        loaded = _q(
            "SELECT toString(lr_uuid) AS lr_uuid, nb_name, nb_enabled, nb_has_nat, "
            "nb_gw_external_ips, nb_gw_logical_ips, "
            "toString(sb_datapath_uuid) AS sb_datapath_uuid, sb_tunnel_key, sb_egress_tunnel_key, ports "
            "FROM flow_ovn.ovn_router FINAL "
            "WHERE log_bundle_id = %d AND toString(lr_uuid) IN (%s) "
            "FORMAT JSONEachRow" % (bid, id_sql)
        )
        by_id = {item.get("lr_uuid"): item for item in loaded}
        on_path = set(switch_ids)
        for uid in router_ids:
            item = by_id.get(uid) or {"lr_uuid": uid, "nb_name": "", "ports": []}
            ports = item.get("ports") or []
            kept = []
            for port in ports:
                if isinstance(port, dict):
                    ls = port.get("nb_ls_uuid") or ""
                    ext = int(port.get("nb_is_ext_gw") or 0)
                    view = port
                elif isinstance(port, list) and len(port) >= 13:
                    ls = str(port[7])
                    ext = int(port[5] or 0)
                    view = {
                        "lrp_uuid": port[0], "nb_name": port[1], "nb_mac": port[2],
                        "nb_networks": port[3], "nb_is_ext_gw": ext,
                        "nb_ls_uuid": ls, "nb_lsp_name": port[9],
                        "nb_ha_chassis_group": str(port[6]),
                        "sb_chassis_uuid": port[10], "sb_tunnel_key": port[11], "sb_up": port[12],
                    }
                else:
                    continue
                if ext or ls in on_path:
                    kept.append(view)
            item = dict(item)
            item["ports"] = kept
            routers.append(item)
    gateways = []
    for item in routers:
        name = item.get("nb_name") or ""
        ext_port = any(
            int((port or {}).get("nb_is_ext_gw") or 0)
            for port in (item.get("ports") or [])
            if isinstance(port, dict)
        )
        if "gw-scale-out" in name or name.startswith("lrp-ext") or ext_port:
            ext = {}
            for port in item.get("ports") or []:
                if isinstance(port, dict) and int(port.get("nb_is_ext_gw") or 0):
                    ext = port
                    break
            rc = redirect_chassis(bid, (ext or {}).get("nb_ha_chassis_group") or "")
            if not rc.get("hostname"):
                rc = chassis_host(bid, (ext or {}).get("sb_chassis_uuid") or "")
            item = dict(item)
            item["external_port"] = ext
            item["rc"] = rc
            gateways.append(item)
    l2_rows = []
    if switch_ids:
        id_sql = ", ".join(sql_str(uid) for uid in switch_ids)
        l2_rows = _q(
            "SELECT kind, nb_name, nb_type, nb_network_name, nb_vlan, nb_mac, nb_ls_name, "
            "sb_hostname, sb_encap_type, sb_encap_ip, sb_tunnel_key, sb_up, sb_vif_count, "
            "toString(ls_uuid) AS ls_uuid, toString(lsp_uuid) AS lsp_uuid, "
            "toString(sb_chassis_uuid) AS sb_chassis_uuid, toString(sb_datapath_uuid) AS sb_datapath_uuid "
            "FROM flow_ovn.ovn_l2gw FINAL "
            "WHERE log_bundle_id = %d AND toString(ls_uuid) IN (%s) "
            "FORMAT JSONEachRow" % (bid, id_sql)
        )
    def switch_tunnel(ls_uuid):
        if not ls_uuid or ls_uuid == "00000000-0000-0000-0000-000000000000":
            return 0
        found = _q(
            "SELECT sb_tunnel_key FROM flow_ovn.ovn_switch FINAL "
            "WHERE log_bundle_id = %d AND toString(ls_uuid) = %s "
            "LIMIT 1 FORMAT JSONEachRow" % (bid, sql_str(ls_uuid))
        )
        return int(found[0].get("sb_tunnel_key") or 0) if found else 0

    def via_tunnel(left, right):
        if not left or not right:
            return 0
        found = _q(
            "SELECT toString(via_ls_uuid) AS via FROM flow_ovn.ovn_edge_lr_lr FINAL "
            "WHERE log_bundle_id = %d AND ("
            "(toString(lr_a) = %s AND toString(lr_b) = %s) OR "
            "(toString(lr_a) = %s AND toString(lr_b) = %s)) "
            "LIMIT 1 FORMAT JSONEachRow" % (
                bid, sql_str(left), sql_str(right), sql_str(right), sql_str(left))
        )
        if not found:
            return 0
        return switch_tunnel(found[0].get("via") or "")

    tenant_ids = [
        item.get("lr_uuid") or ""
        for item in routers
        if "gw-scale-out" not in (item.get("nb_name") or "")
    ]
    gw_ids = [item.get("lr_uuid") or "" for item in gateways]
    ext_ls = ""
    if gateways:
        ext_ls = (gateways[0].get("external_port") or {}).get("nb_ls_uuid") or ""
    tunnels = {
        "to_gateway": via_tunnel(tenant_ids[0], gw_ids[0]) if tenant_ids and gw_ids else 0,
        "external": switch_tunnel(ext_ls),
        "from_gateway": via_tunnel(gw_ids[-1], tenant_ids[-1]) if gw_ids and len(tenant_ids) > 1 else 0,
    }
    same = bool(src_ls) and src_ls == dst_ls
    external = bool(gateways) and not same
    if same:
        path_class = "same_switch"
    elif external:
        path_class = "external"
    elif routers:
        path_class = "routed"
    else:
        path_class = "unknown"
    return {
        "class": path_class,
        "source": src_ep,
        "destination": dst_ep,
        "routers": routers,
        "gateways": gateways if external or path_class == "external" else [],
        "l2gw": l2_rows,
        "tunnels": tunnels,
        "loaded": bool(src_ep["switch"]["nb"].get("name") or dst_ep["switch"]["nb"].get("name")),
    }


def _qmark(text) -> str:
    return str(text or "").replace('"', "'")


def _short(text, limit=42) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def _vm_label(endpoint: dict) -> str:
    name = endpoint.get("vm_name") or "vm"
    vpc = endpoint.get("vpc") or ""
    if vpc and name.startswith(vpc):
        name = name[len(vpc):].strip("_") or name
    return name


def _endpoint_box(node: str, title: str, endpoint: dict, router: dict, drop: dict = None) -> list:
    host = endpoint.get("host") or {}
    port = endpoint.get("port") or {}
    sub = endpoint.get("subnet") or {}
    sw = endpoint["switch"]
    tnl = sw["sb"].get("tunnel_key") or 0
    lines = [
        '  subgraph %s["%s"]' % (node, _qmark(_short(title, 48))),
        "    direction TB",
        '    %s_h["host %s<br>geneve %s"]' % (
            node, _qmark(host.get("hostname") or "unknown"), _qmark(host.get("geneve_ip") or "")),
        '    %s_v["%s<br>%s<br>%s"]' % (
            node,
            _qmark(_vm_label(endpoint)),
            _qmark(port.get("mac") or ""),
            _qmark(endpoint.get("ip") or "")),
        '    %s_s["switch %s<br>vlan %s%s"]' % (
            node, hex24(tnl), endpoint.get("vlan") or 0,
            ("<br>drop cookie %s<br>rule %s" % (drop.get("cookie") or "", drop.get("rule") or "")) if drop else ""),
    ]
    if router:
        mac = ""
        nets = ""
        gw_ip = (sub.get("nb_gateway_ip") or "").split("/")[0]
        chosen = {}
        for item in router.get("ports") or []:
            if not isinstance(item, dict) or int(item.get("nb_is_ext_gw") or 0):
                continue
            networks = item.get("nb_networks") or []
            text = " ".join(networks)
            if gw_ip and gw_ip in text:
                chosen = item
                break
            if not chosen:
                chosen = item
        if chosen:
            mac = chosen.get("nb_mac") or ""
            networks = chosen.get("nb_networks") or []
            nets = networks[0] if networks else ""
        lines.append('    %s_r["router %s<br>%s<br>%s"]' % (
            node, hex24(router.get("sb_tunnel_key") or 0), _qmark(mac), _qmark(nets)))
        lines.append("    %s_h --> %s_v --> %s_s --> %s_r" % (node, node, node, node))
    else:
        lines.append("    %s_h --> %s_v --> %s_s" % (node, node, node))
    lines.append("  end")
    return lines


def _gw_label(router: dict) -> str:
    rc = router.get("rc") or {}
    ext = router.get("external_port") or {}
    ips = router.get("nb_gw_external_ips") or []
    ip = ips[0] if ips else ""
    networks = ext.get("nb_networks") or []
    if networks:
        ip = networks[0]
    return "GW %s<br>RC %s<br>%s<br>router %s" % (
        _qmark(ip),
        _qmark(rc.get("hostname") or "unresolved"),
        _qmark(ext.get("nb_mac") or ""),
        hex24(router.get("sb_tunnel_key") or 0),
    )


def mermaid(path: dict, drop: dict = None) -> str:
    src = path["source"]
    dst = path["destination"]
    routers = path.get("routers") or []
    gateways = path.get("gateways") or []
    tenants = [item for item in routers if item not in gateways and "gw-scale-out" not in (item.get("nb_name") or "")]
    src_router = tenants[0] if tenants else {}
    dst_router = tenants[-1] if len(tenants) > 1 else {}
    if src.get("switch", {}).get("nb", {}).get("ls_uuid") == dst.get("switch", {}).get("nb", {}).get("ls_uuid"):
        dst_router = {}
    lines = ["flowchart LR"]
    src_drop = drop if drop and drop.get("where") == "source" else None
    dst_drop = drop if drop and drop.get("where") == "destination" else None
    lines.extend(_endpoint_box("SRC", src.get("vpc") or "source VPC", src, src_router, src_drop))
    lines.extend(_endpoint_box("DST", dst.get("vpc") or "dest VPC", dst, dst_router if dst_router is not src_router else {}, dst_drop))
    if gateways:
        lines.append('  subgraph GWX["external gateways"]')
        lines.append("    direction TB")
        ids = []
        for index, router in enumerate(gateways):
            node = "g%d" % index
            lines.append('    %s["%s"]' % (node, _gw_label(router)))
            ids.append(node)
        tunnels = path.get("tunnels") or {}
        ext = "tunnel %s" % hex24(tunnels.get("external") or 0)
        for left, right in zip(ids, ids[1:]):
            lines.append("    %s -->|%s| %s" % (left, ext, right))
        lines.append("  end")
        to_gw = "tunnel %s" % hex24(tunnels.get("to_gateway") or (src_router.get("sb_tunnel_key") if src_router else 0))
        from_gw = "tunnel %s" % hex24(tunnels.get("from_gateway") or (dst_router.get("sb_tunnel_key") if dst_router else 0))
        lines.append("  %s -->|%s| g0" % ("SRC_r" if src_router else "SRC_s", to_gw))
        last = "g%d" % (len(gateways) - 1)
        lines.append("  %s -->|%s| %s" % (last, from_gw, "DST_r" if dst_router else "DST_s"))
    elif src_router and dst_router:
        lines.append("  SRC_r -->|tunnel %s| DST_r" % hex24(src_router.get("sb_tunnel_key") or 0))
    elif src_router:
        lines.append("  SRC_r -->|tunnel %s| DST_s" % hex24(src_router.get("sb_tunnel_key") or 0))
    else:
        lines.append("  SRC_s --> DST_s")
    return "\n".join(lines)


def latest_bundle() -> int:
    text = ch("SELECT max(log_bundle_id) FROM flow_policy.portset").strip()
    if not text or text == "0":
        raise SystemExit("flow_policy.portset has no bundle")
    return int(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Allow or deny between two VM NICs on one port")
    parser.add_argument("--src", required=True, help="Source VM NIC uuid, IP, or VM name")
    parser.add_argument("--dst", required=True, help="Destination VM NIC uuid, IP, or VM name")
    parser.add_argument("--port", required=True, type=int, help="TCP/UDP destination port, or ICMP type")
    parser.add_argument("--proto", default="tcp", choices=("tcp", "udp", "icmp"))
    parser.add_argument("--log_bundle_id", type=int, default=0)
    parser.add_argument("--nb", default="", help="OVN northbound dump, for address-set IPs")
    parser.add_argument("--out", default="", help="Write analysis JSON and markdown to this stem")
    args = parser.parse_args()

    bid = args.log_bundle_id or latest_bundle()
    src = resolve_nic(bid, args.src)
    dst = resolve_nic(bid, args.dst)
    proto = {"tcp": 6, "udp": 17, "icmp": 1}[args.proto]
    portsets = load_portsets(bid)
    by_uuid = {item["port_set_uuid"]: item for item in portsets}
    nic_index = defaultdict(list)
    ip_index = defaultdict(list)
    for item in portsets:
        for nic in item.get("nic_uuids") or []:
            if nic:
                nic_index[nic.lower()].append(item["port_set_uuid"])
        for ip in item.get("ips") or []:
            if ip:
                ip_index[ip].append(item["port_set_uuid"])

    src_ids = nic_index.get(src["nic_uuid"].lower(), [])
    dst_ids = nic_index.get(dst["nic_uuid"].lower(), [])
    src_pgs = {pg_token(uid) for uid in src_ids}
    dst_pgs = {pg_token(uid) for uid in dst_ids}
    tokens = sorted(src_pgs | dst_pgs)
    acls = []
    if tokens:
        token_sql = ", ".join(sql_str(token) for token in tokens)
        acls = rows(
            "SELECT toString(acl_uuid) AS acl_uuid, priority, action, direction, match "
            "FROM flow_ovn.ovn_acl FINAL "
            "WHERE log_bundle_id = %d AND multiSearchAny(match, [%s]) "
            "FORMAT JSONEachRow" % (bid, token_sql)
        )
    needed = set()
    for acl in acls:
        needed.update(name for _side, name in AS_FIELD.findall(acl.get("match") or ""))
    nb_path = args.nb
    if not nb_path:
        nb_path = os.path.join(dump_dir(bid), *NB_REL)
    address_sets = load_address_sets(nb_path, needed)
    missing_nb = bool(needed) and not os.path.isfile(nb_path)

    pkt = {
        "ip_ver": "ip4",
        "src_ip": (src.get("ip") or "").split("/")[0],
        "dst_ip": (dst.get("ip") or "").split("/")[0],
        "inport_pgs": src_pgs,
        "outport_pgs": dst_pgs,
        "proto": proto,
        "dport": args.port,
    }

    def matching(direction: str, skip_l4: bool = False):
        hits = []
        for acl in acls:
            if acl.get("direction") != direction:
                continue
            if acl_matches(acl, pkt, address_sets, skip_l4=skip_l4):
                hits.append(acl)
        hits.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
        return hits

    from_hits = matching("from-lport")
    to_hits = matching("to-lport")
    from_hit = from_hits[0] if from_hits else None
    to_hit = to_hits[0] if to_hits else None
    stage_hits = [item for item in (from_hit, to_hit) if item]
    stage_drops = [item for item in stage_hits if item.get("action") == "drop"]
    full_allows = [
        acl for acl in acls
        if str(acl.get("action") or "").startswith(ALLOW_PREFIX)
        and acl_matches(acl, pkt, address_sets)
    ]
    full_allows.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
    full_drops = [
        acl for acl in acls
        if acl.get("action") == "drop" and acl_matches(acl, pkt, address_sets)
    ]
    full_drops.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
    near_allows = []
    if not full_allows:
        seen = set()
        for acl in acls:
            if not str(acl.get("action") or "").startswith(ALLOW_PREFIX):
                continue
            if not acl_matches(acl, pkt, address_sets, skip_l4=True):
                continue
            marker = (policy_label(applied_portset(acl, by_uuid)), l4_text(acl.get("match") or ""))
            if marker in seen:
                continue
            seen.add(marker)
            near_allows.append(acl)
        near_allows.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)

    monitor = False
    if stage_drops:
        modes = []
        for acl in stage_drops:
            for rule in (applied_portset(acl, by_uuid).get("rules") or []):
                if rule[2]:
                    modes.append(rule[2])
        monitor = bool(modes) and all(mode == "monitor" for mode in modes)
    verdict = "allowed" if not stage_drops or monitor else "denied"

    both_allow = same_rule(from_hit, to_hit, by_uuid) and from_hit and str(from_hit.get("action") or "").startswith(ALLOW_PREFIX)
    both_deny = same_rule(from_hit, to_hit, by_uuid) and from_hit and from_hit.get("action") == "drop"

    if full_allows:
        allow_text = describe(full_allows[0], by_uuid, ip_index, address_sets, both=both_allow)
        if verdict == "denied":
            allow_text += ". Does not apply; a higher-priority deny wins."
    elif near_allows:
        allow_text = (
            describe(near_allows[0], by_uuid, ip_index, address_sets)
            + ". %s/%s is outside this allow." % (args.proto, args.port)
        )
    else:
        allow_text = "No allow policy matches this source and destination."

    deny_acl = None
    if stage_drops:
        deny_acl = max(stage_drops, key=lambda item: int(item.get("priority") or 0))
        deny_text = describe(deny_acl, by_uuid, ip_index, address_sets, both=both_deny)
        if monitor:
            deny_text += ". Does not apply; the policy is in monitor mode."
    elif full_drops:
        deny_text = describe(full_drops[0], by_uuid, ip_index, address_sets)
        deny_text += ". Does not apply; the allow is higher priority."
    else:
        deny_text = "No deny policy matches this traffic."

    src_ids = unique_ids(src_ids)
    dst_ids = unique_ids(dst_ids)

    def acl_table(selected):
        selected = sorted(selected, key=lambda item: (
            -int(item.get("priority") or 0),
            str(item.get("action") or ""),
        ))
        table = []
        seen_rows = set()
        for acl in selected:
            applied = applied_portset(acl, by_uuid)
            match = acl.get("match") or ""
            peer_list = peer_ips(match, peer_side(acl.get("direction") or ""), address_sets)
            peer = peer_label(
                peer_list, match, by_uuid, ip_index, applied.get("port_set_uuid") or "")
            peer_specs = [] if peer in ("any", "no addresses in the OVN dump") else peer_list
            applies = "yes" if acl_matches(acl, pkt, address_sets) else "no"
            marker = (
                int(acl.get("priority") or 0),
                acl.get("acl_uuid") or "",
                acl.get("action") or "",
                ip_family(match),
                policy_label(applied),
                category_label(applied),
                peer,
                l4_text(match),
                applies,
                tuple(peer_specs),
            )
            if marker in seen_rows:
                continue
            seen_rows.add(marker)
            table.append(marker)
        return table

    def acl_records(table):
        out = []
        for rule, acl_uuid, action, family, policy, category, peer, ports, applies, specs in table:
            out.append({
                "rule": rule,
                "acl_uuid": acl_uuid,
                "action": action,
                "ip": family,
                "policy": policy,
                "category": category,
                "peer": peer,
                "ports": ports,
                "matches": applies,
                "peer_specs": list(specs),
            })
        return out

    def mapping_rows(records):
        grouped = {}
        for row in records:
            peer = row["peer"]
            specs = row["peer_specs"]
            if peer in ("any", "no addresses in the OVN dump") or not specs:
                continue
            bucket = grouped.setdefault(peer, [])
            for spec in specs:
                if spec not in bucket:
                    bucket.append(spec)
        return [{"peer": peer, "addresses": format_ips(specs).split(", ") if specs else []}
                for peer, specs in grouped.items()]

    outgoing = acl_table([acl for acl in acls if source_outgoing(acl, src_pgs)])
    incoming = acl_table([acl for acl in acls if dest_incoming(acl, dst_pgs)])
    src_ip = (src.get("ip") or "").split("/")[0]
    dst_ip = (dst.get("ip") or "").split("/")[0]
    forwarding = load_forwarding(bid, src, dst)
    src_acl = acl_records(outgoing)
    dst_acl = acl_records(incoming)
    ip_map = mapping_rows(src_acl + dst_acl)
    catalog = []
    catalog_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "..", "..", "clickhouse_ovn", "path_tables.py",
    )
    if os.path.isfile(os.path.abspath(catalog_path)):
        import importlib.util
        spec = importlib.util.spec_from_file_location("path_tables", os.path.abspath(catalog_path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        catalog = mod.CATALOG

    document = {
        "traffic": {
            "src": src_ip,
            "dst": dst_ip,
            "src_nic": src.get("nic_uuid"),
            "dst_nic": dst.get("nic_uuid"),
            "src_vm": src.get("vm_name") or "",
            "dst_vm": dst.get("vm_name") or "",
            "proto": args.proto,
            "port": args.port,
        },
        "tables": catalog,
        "path": forwarding,
        "acl_source": [{k: v for k, v in row.items() if k != "peer_specs"} for row in src_acl],
        "acl_destination": [{k: v for k, v in row.items() if k != "peer_specs"} for row in dst_acl],
        "verdict": {
            "verdict": verdict,
            "allow_policy": allow_text,
            "deny_policy": deny_text,
            "drop_cookie": acl_cookie(deny_acl.get("acl_uuid") or "") if verdict == "denied" and deny_acl else "",
            "drop_rule": int(deny_acl.get("priority") or 0) if verdict == "denied" and deny_acl else 0,
            "drop_where": (
                "destination switch" if deny_acl.get("direction") == "to-lport" else "source switch"
            ) if verdict == "denied" and deny_acl else "",
        },
        "ip_mapping": ip_map,
    }
    drop = None
    if verdict == "denied" and deny_acl:
        drop = {
            "cookie": acl_cookie(deny_acl.get("acl_uuid") or ""),
            "rule": int(deny_acl.get("priority") or 0),
            "where": "destination" if deny_acl.get("direction") == "to-lport" else "source",
        }
    chart = mermaid(forwarding, drop)

    def md_acl(title, records):
        lines = ["## %s" % title, ""]
        lines.append("| rule | action | ip | policy | category | peer | ports | matches |")
        lines.append("|---|---|---|---|---|---|---|---|")
        if not records:
            lines.append("| | | | | | | | |")
        for row in records:
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                row["rule"], cell(row["action"]), cell(row["ip"]), cell(row["policy"]),
                cell(row["category"]), cell(row["peer"]), cell(row["ports"]), row["matches"],
            ))
        lines.append("")
        return lines

    def side_block(title, endpoint):
        sw = endpoint["switch"]
        port = endpoint["port"]
        sub = endpoint.get("subnet") or {}
        host = endpoint.get("host") or {}
        tnl = sw["sb"].get("tunnel_key") or 0
        return [
            "### %s" % title,
            "",
            "| field | value |",
            "|---|---|",
            "| VPC | %s |" % cell(endpoint.get("vpc") or ""),
            "| subnet | %s |" % cell(endpoint.get("subnet_name") or ""),
            "| prefix | %s |" % cell(sub.get("nb_cidr") or ""),
            "| VLAN | %s |" % (endpoint.get("vlan") or 0),
            "| VM MAC | %s |" % cell(port.get("mac") or ""),
            "| DHCP gateway | %s %s |" % (cell(sub.get("nb_gateway_ip") or ""), cell(sub.get("nb_gateway_mac") or "")),
            "| host | %s |" % cell(host.get("hostname") or ""),
            "| host Geneve IP | %s |" % cell(host.get("geneve_ip") or ""),
            "| switch tunnel | %s %s |" % (tnl, hex24(tnl)),
            "| port tunnel | %s %s |" % (port.get("port_number") or 0, hex24(port.get("port_number") or 0)),
            "| logical port | %s |" % cell(port.get("name") or ""),
            "",
        ]

    def capture_lines(forwarding):
        src_ep = forwarding["source"]
        dst_ep = forwarding["destination"]
        lines = ["## Capture", ""]
        lines.append("TAP is the VM port on that host. Geneve is UDP 6081 on the host uplink. `eth0` is that uplink; use the bond on this host when the uplink is not eth0.")
        lines.append("")
        for title, endpoint in (("Source TAP", src_ep), ("Destination TAP", dst_ep)):
            host = (endpoint.get("host") or {}).get("hostname") or "the VM host"
            port = (endpoint.get("port") or {}).get("name") or ""
            lines.append("**%s on %s**" % (title, host))
            lines.append("")
            lines.append("```bash")
            lines.append("ovs-vsctl --columns=name find interface external_ids:iface-id=%s" % port)
            lines.append('tcpdump -nne -B 4096 -i <that-tap> "host %s and host %s"' % (src_ep.get("ip") or "", dst_ep.get("ip") or ""))
            lines.append("```")
            lines.append("")
        peers = []
        src_geneve = (src_ep.get("host") or {}).get("geneve_ip") or ""
        dst_geneve = (dst_ep.get("host") or {}).get("geneve_ip") or ""
        gw_hosts = []
        for gw in forwarding.get("gateways") or []:
            rc = gw.get("rc") or {}
            if rc.get("geneve_ip"):
                gw_hosts.append((rc.get("hostname") or "gateway host", rc.get("geneve_ip")))
        if gw_hosts:
            peers.append(((src_ep.get("host") or {}).get("hostname") or "source host", gw_hosts[0][1]))
            peers.append((gw_hosts[-1][0], dst_geneve))
            if len(gw_hosts) > 1 and gw_hosts[0][1] != gw_hosts[-1][1]:
                peers.append((gw_hosts[0][0], gw_hosts[-1][1]))
        elif dst_geneve:
            peers.append(((src_ep.get("host") or {}).get("hostname") or "source host", dst_geneve))
        lines.append("**Geneve on the host NIC**")
        lines.append("")
        for host_name, peer in peers:
            if not peer:
                continue
            lines.append("On %s, toward %s. Switch metadata in the Geneve VNI is the hex tunnel key above." % (host_name, peer))
            lines.append("")
            lines.append("```bash")
            lines.append('tcpdump -nne -B 4096 -i eth0 "udp port 6081 and host %s" | grep --line-buffered %s | grep --line-buffered %s' % (
                peer, src_ep.get("ip") or "", dst_ep.get("ip") or ""))
            lines.append("```")
            lines.append("")
        return lines

    md = []
    md.append("# NIC traffic")
    md.append("")
    md.append("%s %s → %s %s, %s/%s" % (
        src.get("vm_name") or "", src_ip, dst.get("vm_name") or "", dst_ip, args.proto, args.port))
    md.append("")
    md.append("## Path")
    md.append("")
    md.append("```mermaid")
    md.append(chart)
    md.append("```")
    md.append("")
    md.append("Class: %s" % forwarding["class"])
    md.append("")
    if drop:
        md.append("Drop cookie %s is rule %s on the %s switch." % (
            drop["cookie"], drop["rule"], drop["where"]))
        md.append("")
    hosts = []
    src_host = (forwarding["source"].get("host") or {}).get("hostname") or ""
    dst_host = (forwarding["destination"].get("host") or {}).get("hostname") or ""
    if src_host:
        hosts.append((src_host, "source VM"))
    if dst_host:
        hosts.append((dst_host, "destination VM"))
    for gw in forwarding.get("gateways") or []:
        rc_name = (gw.get("rc") or {}).get("hostname") or ""
        if rc_name:
            hosts.append((rc_name, "redirect chassis for %s" % (gw.get("nb_name") or "gateway")))
    by_host = {}
    for name, role in hosts:
        by_host.setdefault(name, []).append(role)
    for name, roles in by_host.items():
        if len(roles) > 1:
            md.append("%s is one host in two roles: %s." % (name, " and ".join(roles)))
            md.append("")
    md.extend(side_block("Source switch", forwarding["source"]))
    md.extend(side_block("Destination switch", forwarding["destination"]))
    md.append("## Routers and gateways")
    md.append("")
    md.append("Switch and router tunnel keys are the Geneve metadata. The hex column is that value.")
    md.append("")
    md.append("| role | name | MAC | address | tunnel | hex |")
    md.append("|---|---|---|---|---|---|")
    for router in forwarding["routers"]:
        role = "gateway" if router in forwarding["gateways"] or "gw-scale-out" in (router.get("nb_name") or "") else "router"
        ports = [p for p in (router.get("ports") or []) if isinstance(p, dict)] or [{}]
        first = True
        for port in ports:
            networks = port.get("nb_networks") or []
            net = ", ".join(networks) if isinstance(networks, list) else str(networks)
            key = (router.get("sb_tunnel_key") or 0) if first else (port.get("sb_tunnel_key") or 0)
            md.append("| %s | %s | %s | %s | %s | %s |" % (
                role if first else "",
                cell((router.get("nb_name") or "") if first else (port.get("nb_name") or "")),
                cell(port.get("nb_mac") or ""),
                cell(net),
                key,
                hex24(key),
            ))
            first = False
    if not forwarding["routers"]:
        md.append("| | | | | | |")
    md.append("")
    md.append("## External gateways")
    md.append("")
    if forwarding["gateways"]:
        for gw in forwarding["gateways"]:
            rc = gw.get("rc") or {}
            ext = gw.get("external_port") or {}
            networks = ext.get("nb_networks") or []
            net = ", ".join(networks) if isinstance(networks, list) else ""
            md.append("### %s" % (gw.get("nb_name") or "gateway"))
            md.append("")
            md.append("| field | value |")
            md.append("|---|---|")
            md.append("| external | %s |" % cell(net or ", ".join(gw.get("nb_gw_external_ips") or [])))
            md.append("| external MAC | %s |" % cell(ext.get("nb_mac") or ""))
            md.append("| router tunnel | %s %s |" % (gw.get("sb_tunnel_key") or 0, hex24(gw.get("sb_tunnel_key") or 0)))
            md.append("| host | %s |" % cell(rc.get("hostname") or ""))
            md.append("| host Geneve IP | %s |" % cell(rc.get("geneve_ip") or ""))
            md.append("| chassis | %s |" % cell(rc.get("chassis_uuid") or ""))
            md.append("| chassis name | %s |" % cell(rc.get("chassis_name") or ""))
            md.append("| HA group | %s |" % cell(rc.get("group_name") or ""))
            md.append("| HA priority | %s |" % (rc.get("priority") if rc.get("priority") is not None else ""))
            md.append("")
    else:
        md.append("The path does not leave through an external gateway.")
        md.append("")
    md.extend(capture_lines(forwarding))
    md.append("## L2 gateway")
    md.append("")
    md.append("| kind | NB switch | NB port | NB network | SB datapath | SB host | SB encap | SB port number |")
    md.append("|---|---|---|---|---|---|---|---|")
    path_hosts = set()
    for endpoint in (forwarding["source"], forwarding["destination"]):
        if (endpoint.get("host") or {}).get("hostname"):
            path_hosts.add(endpoint["host"]["hostname"])
    for gw in forwarding.get("gateways") or []:
        if (gw.get("rc") or {}).get("hostname"):
            path_hosts.add(gw["rc"]["hostname"])
    shown_l2 = []
    for row in forwarding["l2gw"]:
        if row.get("kind") != "geneve" or row.get("sb_hostname") in path_hosts:
            shown_l2.append(row)
    if not shown_l2:
        md.append("| | | | | | | | |")
    for row in shown_l2:
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            row.get("kind") or "",
            cell(row.get("nb_ls_name") or row.get("nb_name") or ""),
            cell(row.get("nb_name") or ""),
            cell(row.get("nb_network_name") or ""),
            cell(row.get("sb_datapath_uuid") or ""),
            cell(row.get("sb_hostname") or ""),
            cell(row.get("sb_encap_ip") or ""),
            row.get("sb_tunnel_key") or 0,
        ))
    md.append("")
    md.extend(md_acl("ACL source", src_acl))
    md.extend(md_acl("ACL destination", dst_acl))
    md.append("## Verdict")
    md.append("")
    md.append("| field | value |")
    md.append("|---|---|")
    md.append("| verdict | %s |" % verdict)
    md.append("| allow policy | %s |" % cell(allow_text))
    md.append("| deny policy | %s |" % cell(deny_text))
    md.append("")
    md.append("## IP mapping")
    md.append("")
    md.append("| peer | address |")
    md.append("|---|---|")
    if not ip_map:
        md.append("| | |")
    for group in ip_map:
        for address in group["addresses"]:
            md.append("| %s | %s |" % (cell(group["peer"]), cell(address)))
    md.append("")
    text = "\n".join(md)
    stem = args.out
    if not stem:
        safe_src = src_ip.replace(".", "_") or "src"
        safe_dst = dst_ip.replace(".", "_") or "dst"
        stem = os.path.join("/tmp", "nic_%s__%s_%s%s" % (safe_src, safe_dst, args.proto, args.port))
    json_path = stem if stem.endswith(".json") else stem + ".json"
    md_path = stem[:-5] + ".md" if stem.endswith(".json") else stem + ".md"
    with open(json_path, "w") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    with open(md_path, "w") as handle:
        handle.write(text)
        if missing_nb:
            handle.write("\nAddress sets were not resolved because the OVN northbound dump is missing.\n")
    print(text)
    print("JSON: %s" % json_path)
    print("Markdown: %s" % md_path)


if __name__ == "__main__":
    main()
