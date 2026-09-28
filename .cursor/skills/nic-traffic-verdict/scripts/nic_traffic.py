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
        host = spec.split("/")[0]
        if host and host not in uniq:
            uniq.append(host)
    return uniq


def name_peer(ips: list, by_uuid: dict, ip_index: dict, applied_uuid: str) -> str:
    if not ips:
        return "no addresses in the OVN dump"
    scores = Counter()
    for ip in ips:
        for uid in ip_index.get(ip, ()):
            scores[uid] += 1
    if not scores:
        sample = ", ".join(ips[:8])
        if len(ips) > 8:
            sample += " and %d more" % (len(ips) - 8)
        return sample
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
    if not peer_list and not AS_FIELD.findall(acl.get("match") or "") and not LIT_FIELD.findall(acl.get("match") or ""):
        peer = "any"
    else:
        peer = name_peer(peer_list, by_uuid, ip_index, applied_uuid)
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
        "SELECT vm_name, toString(nic_uuid) AS nic_uuid, ip, subnet, vpc "
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
            "SELECT priority, action, direction, match FROM flow_ovn.ovn_acl FINAL "
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
        shown = []
        for acl in near_allows[:3]:
            shown.append(
                describe(acl, by_uuid, ip_index, address_sets)
                + ". %s/%s is outside this allow." % (args.proto, args.port)
            )
        allow_text = " ".join(shown)
    else:
        allow_text = "No allow policy matches this source and destination."

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

    print("Verdict: %s" % verdict)
    print("Source: %s  %s" % (src.get("vm_name") or "", (src.get("ip") or "").split("/")[0]))
    print("Destination: %s  %s" % (dst.get("vm_name") or "", (dst.get("ip") or "").split("/")[0]))
    print("Traffic: %s/%s" % (args.proto, args.port))
    print("Allow policy: %s" % allow_text)
    print("Deny policy: %s" % deny_text)
    if missing_nb:
        print("Address sets were not resolved because the OVN northbound dump is missing.")
    print("NIC identity: %s -> %s" % (src.get("nic_uuid"), dst.get("nic_uuid")))


if __name__ == "__main__":
    main()
