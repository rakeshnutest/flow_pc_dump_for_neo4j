#!/usr/bin/env python3
"""Human-readable OVN in-port (from-lport) / out-port (to-lport) ACLs.

stdlib + clickhouse-client. Does not query flow_policy ClickHouse.
Run from anywhere; imports clickhouse_ovn (acls_on_ls, ch, dataplane).
Every from-lport / to-lport row on each path LS is printed (full list).
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

OVN_DIR = "/home/rakeshkumar.r/panacea/clickhouse_ovn"
if OVN_DIR not in sys.path:
    sys.path.insert(0, OVN_DIR)

from dataplane import (  # noqa: E402
    acl_label_hex,
    expand_l4,
    explain_drop_policy,
    human_acl_row,
    of_metadata,
    pb_ct_zone,
    rewrite_match_human,
)
from trace import (  # noqa: E402
    ZERO,
    acls_on_ls,
    bfs,
    ch,
    dest_nodes,
    first_acl_hit,
    ip_of_lsp,
    env_or_latest_bundle,
    load_graph,
    pg_names_for_lsp,
    resolve,
    set_log_bundle_id,
    split_acls,
    start_node,
)
import trace as ovn_trace  # noqa: E402

DEFAULT_SRC = "3468ac71-d670-41a0-93af-0ec34d43f7c3"
DEFAULT_DST = "22bce434-1ef5-4792-8e57-8fa2a5e3bd71"


def _esc(s: Any) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def _ep_ip(ep: dict) -> str:
    if ep.get("kind") == "external":
        return str(ep.get("dest_ip") or "")
    nic = ep.get("nic") or {}
    lsp = ep.get("lsp") or {}
    return str(nic.get("ip4") or ip_of_lsp(lsp) or "")


def _ep_nic(ep: dict) -> str:
    nic = ep.get("nic") or {}
    lsp = ep.get("lsp") or {}
    return str(nic.get("nic_uuid") or lsp.get("nic_uuid") or "")


def _ep_lsp(ep: dict) -> dict:
    return ep.get("lsp") or {}


def hop_ct(ep: dict) -> dict:
    """ct_zone, metadata hex from SB Port_Binding + ovn_datapath tunnel_key."""
    missing = "(missing in dump)"
    lsp = _ep_lsp(ep)
    name = str(lsp.get("name") or "")
    ls_uuid = str(ep.get("ls_uuid") or lsp.get("ls_uuid") or "")
    out = {
        "logical_port": name,
        "ct_zone": pb_ct_zone(name) if name else missing,
        "dp_key": 0,
        "port_key": 0,
        "metadata_hex": missing,
        "metadata_dec": "",
        "dp_uuid": "",
    }
    if not name:
        return out
    pb = ch(
        "SELECT pb.tunnel_key AS tunnel_key, pb.datapath_uuid AS datapath_uuid "
        "FROM ovn_port_binding AS pb "
        f"WHERE pb.logical_port = '{name.replace(chr(39), '')}' LIMIT 1"
    )
    dp_key = 0
    port_key = 0
    if pb:
        port_key = int(pb[0].get("tunnel_key") or 0)
        dpu = str(pb[0].get("datapath_uuid") or "")
        out["dp_uuid"] = dpu
        out["port_key"] = port_key
        if dpu and dpu != ZERO:
            dps = ch(
                "SELECT tunnel_key FROM ovn_datapath "
                f"WHERE datapath_uuid = '{dpu}' LIMIT 1"
            )
            if dps:
                dp_key = int(dps[0].get("tunnel_key") or 0)
        if not dp_key and ls_uuid and ls_uuid != ZERO:
            dps = ch(
                "SELECT tunnel_key, datapath_uuid FROM ovn_datapath "
                f"WHERE nb_uuid = '{ls_uuid}' AND kind = 'ls' LIMIT 1"
            )
            if dps:
                dp_key = int(dps[0].get("tunnel_key") or 0)
                out["dp_uuid"] = str(dps[0].get("datapath_uuid") or out["dp_uuid"])
    out["dp_key"] = dp_key
    hx, dec = of_metadata(dp_key, port_key)
    out["metadata_hex"] = hx
    out["metadata_dec"] = dec
    return out


def hop_ct_ls(ls_uuid: str, ep: Optional[dict] = None) -> dict:
    """Datapath metadata for a switch; VIF ct_zone when ep is a VIF on this LS."""
    missing = "(missing in dump)"
    out = {
        "logical_port": "",
        "ct_zone": missing,
        "dp_key": 0,
        "port_key": 0,
        "metadata_hex": missing,
        "metadata_dec": "",
        "dp_uuid": "",
    }
    if ep and str(ep.get("ls_uuid") or "") == ls_uuid:
        return hop_ct(ep)
    if not ls_uuid or ls_uuid == ZERO:
        return out
    dps = ch(
        "SELECT tunnel_key, datapath_uuid FROM ovn_datapath "
        f"WHERE nb_uuid = '{ls_uuid}' AND kind = 'ls' LIMIT 1"
    )
    if dps:
        dp_key = int(dps[0].get("tunnel_key") or 0)
        out["dp_key"] = dp_key
        out["dp_uuid"] = str(dps[0].get("datapath_uuid") or "")
        hx, dec = of_metadata(dp_key, 0)
        out["metadata_hex"] = hx
        out["metadata_dec"] = dec
    return out


def path_ls_uuids(
    g: Dict[str, Any], path: List[Tuple[Any, Optional[dict]]]
) -> List[str]:
    out: List[str] = []
    seen = set()

    def add(uid: str) -> None:
        u = str(uid or "")
        if not u or u == ZERO or u in seen:
            return
        seen.add(u)
        out.append(u)

    for node, meta in path or []:
        if node and node[0] == "ls":
            add(node[1])
        if meta:
            add(str(meta.get("via_ls_uuid") or ""))
            add(str(meta.get("ls_uuid") or ""))
    return out


def fmt_ep(ep: dict) -> List[str]:
    nic = ep.get("nic") or {}
    lsp = _ep_lsp(ep)
    kind = ep.get("kind") or ""
    lines = []
    if kind == "external":
        lines.append(f"- kind `external` dest IP `{ep.get('dest_ip') or ''}`")
        return lines
    vm = nic.get("vm_name") or ""
    ip = _ep_ip(ep)
    lines.append(
        f"- VM `{vm}` NIC `{nic.get('nic_uuid') or ''}` IP `{ip}` "
        f"LSP `{lsp.get('name') or ''}`"
    )
    lines.append(
        f"  - identity: nic `{nic.get('nic_uuid') or ''}` "
        f"lsp `{lsp.get('lsp_uuid') or ''}` ls `{ep.get('ls_uuid') or ''}`"
    )
    return lines


def table_rows(
    acls: List[dict],
    nic_uuid: str,
    src_ip: str,
    dst_ip: str,
    ct_zone: str,
    metadata_hex: str,
    full_ips: bool,
) -> Tuple[List[str], List[dict]]:
    if not acls:
        return ["(none) — zero ACLs on this hop"], []
    head = (
        "| pri | action | applied-to | peers (IPs) | L4 ports | "
        "ct_zone | metadata | ct_label | match | identity |"
    )
    sep = "|-----|--------|------------|-------------|----------|"
    sep += "---------|----------|----------|-------|----------|"
    out = [f"**{len(acls)} (full list)**", "", head, sep]
    details: List[dict] = []
    for a in acls:
        row = human_acl_row(
            a,
            nic_uuid=nic_uuid,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ct_zone=ct_zone,
            metadata_hex=metadata_hex,
            full_ips=full_ips,
        )
        act = row["action"]
        if act == "drop":
            act = "**drop**"
        out.append(
            "| {pri} | {act} | {app} | {peers} | {l4} | {zone} | {meta} | {lab} | `{m}` | `{uid}` |".format(
                pri=row["pri"],
                act=_esc(act),
                app=_esc(row["applied"]),
                peers=_esc(row["peers"]),
                l4=_esc(row["l4"]),
                zone=_esc(row["ct_zone"]),
                meta=_esc(row["metadata"]),
                lab=_esc(row["ct_label"]),
                m=_esc(row["match"]),
                uid=_esc(row.get("uuid") or ""),
            )
        )
        details.extend(row.get("ip_details") or [])
    return out, details


def ip_details_md(bags: List[dict], full_ips: bool) -> List[str]:
    if not bags:
        return []
    seen = set()
    lines = ["", "### Address-set IPs (samples; rest in details)"]
    for s in bags:
        key = s.get("name") or ""
        if key in seen:
            continue
        seen.add(key)
        rest = s.get("rest") or []
        lines.append(
            f"- `${s.get('label')}` count {s.get('count')} "
            f"sample `{', '.join(s.get('sample') or [])}`"
        )
        if not rest:
            continue
        lines.append("<details>")
        lines.append(f"<summary>remaining IPs for `${s.get('label')}` ({len(rest)})</summary>")
        lines.append("")
        if full_ips:
            lines.append(", ".join(rest))
        else:
            lines.append(f"{len(rest)} IPs omitted; rerun with `--full-ips`.")
        lines.append("")
        lines.append("</details>")
    return lines


def first_hit_md(title: str, hit: Optional[dict], pkt_note: str) -> List[str]:
    lines = [f"### First-hit {title}", "", pkt_note]
    if not hit:
        lines.append("- (no matching ACL — implicit allow / next hop)")
        return lines
    lines.extend(explain_drop_policy(hit))
    uid = str(hit.get("acl_uuid") or "")
    lines.append(
        f"- ct_label for this ACL: `{acl_label_hex(uid)}` "
        f"(NB `ACL.label`; northd `ct_label.label = reg3`)"
    )
    lines.append(f"- identity ACL uuid `{uid}`")
    return lines


def render(src_tok: str, dst_tok: str, full_ips: bool) -> str:
    g = load_graph()
    src = resolve(g, src_tok)
    dst = resolve(g, dst_tok)
    src_ip = _ep_ip(src)
    dst_ip = _ep_ip(dst)
    src_nic = _ep_nic(src)
    dst_nic = _ep_nic(dst)
    src_lsp = str((_ep_lsp(src).get("lsp_uuid") or ZERO))
    dst_lsp = str((_ep_lsp(dst).get("lsp_uuid") or ZERO))
    src_ls = str(src.get("ls_uuid") or ZERO)
    dst_ls = str(dst.get("ls_uuid") or ZERO)
    src_ct = hop_ct(src)
    dst_ct = hop_ct(dst)
    src_pgs = pg_names_for_lsp(src_lsp)
    dst_pgs = pg_names_for_lsp(dst_lsp) if dst.get("kind") == "vif" else []

    pkt_up = {
        "ip_ver": "ip4",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "inport_pgs": src_pgs,
        "outport_pgs": dst_pgs,
        "proto": 1,
        "dport": None,
    }
    pkt_dn = {
        "ip_ver": "ip4",
        "src_ip": dst_ip,
        "dst_ip": src_ip,
        "inport_pgs": dst_pgs,
        "outport_pgs": src_pgs,
        "proto": 1,
        "dport": None,
    }

    lines: List[str] = [
        "# Human-readable OVN in-port / out-port ACLs",
        "",
        "in-port = from-lport (ingress). out-port = to-lport (egress).",
        "Every ACL on each path Switch is listed (LS-attached and every "
        "port-group with a member on that LS). Allow, drop, DHCP, catch-all — "
        "no omitted rows, no `N more`.",
        "Identity is UUID (footnotes). Names, IPs, and ports are display.",
        "",
        f"log_bundle_id `{ovn_trace.LOG_BUNDLE_ID}`",
        "",
        "## Endpoints",
        "",
        "**Src**",
    ]
    lines.extend(fmt_ep(src))
    lines.append("")
    lines.append("**Dst**")
    lines.extend(fmt_ep(dst))
    lines.extend(
        [
            "",
            "## CT (this traffic)",
            "",
            f"- Packet: `{src_ip}` → `{dst_ip}` proto ICMP (unspecified L4 port; "
            "labels still shown on ACLs that match ip4).",
            f"- src in-port ct_zone: `{src_ct['ct_zone']}` "
            f"(SB Port_Binding.options for `{src_ct['logical_port']}`)",
            f"- dst out-port ct_zone: `{dst_ct['ct_zone']}` "
            f"(SB Port_Binding.options for `{dst_ct['logical_port']}`)",
            f"- src metadata: `{src_ct['metadata_hex']}` "
            f"(decimal `{src_ct['metadata_dec'] or '-'}`; "
            f"`dp_key<<16|port_key` = `{src_ct['dp_key']}<<16|{src_ct['port_key']}`; "
            "SB Datapath_Binding.tunnel_key + Port_Binding.tunnel_key)",
            f"- dst metadata: `{dst_ct['metadata_hex']}` "
            f"(decimal `{dst_ct['metadata_dec'] or '-'}`; "
            f"`{dst_ct['dp_key']}<<16|{dst_ct['port_key']}`)",
            "- Per-port `ct_zone` is not a column on `flow_ovn.ovn_acl` / "
            "`ovn_port_binding`; ofctl dumps have no `ct(zone=`. "
            "Chassis `other_config` has `ct-commit-to-zone=true` (flag, not a zone id).",
        ]
    )

    src_key = start_node(src)
    dst_keys = dest_nodes(g, dst)
    if src_key in dst_keys:
        path = [(src_key, None)]
    else:
        path = bfs(g, src_key, dst_keys) or [(src_key, None)]
    ls_uuids = path_ls_uuids(g, path)
    for extra in (src_ls, dst_ls):
        if extra and extra != ZERO and extra not in ls_uuids:
            ls_uuids.append(extra)
    nic_both = " ".join(x for x in (src_nic, dst_nic) if x)

    all_details: List[dict] = []
    up_hit = None
    dn_hit = None
    for ls_uuid in ls_uuids:
        rec = (g.get("ls") or {}).get(ls_uuid) or {}
        ls_name = rec.get("name") or ls_uuid
        acls = acls_on_ls(ls_uuid)
        from_l, to_l = split_acls(acls, reverse=False)
        hop = hop_ct_ls(ls_uuid, src if ls_uuid == src_ls else (dst if ls_uuid == dst_ls else None))
        hop_zone = hop["ct_zone"]
        hop_meta = hop["metadata_hex"]
        if ls_uuid == src_ls:
            h = first_acl_hit(from_l, pkt_up)
            if h:
                up_hit = h
            h = first_acl_hit(to_l, pkt_dn)
            if h:
                dn_hit = h
        elif ls_uuid == dst_ls:
            if not up_hit:
                up_hit = first_acl_hit(to_l, pkt_up)
            if not dn_hit:
                dn_hit = first_acl_hit(from_l, pkt_dn)
        lines.extend(
            [
                "",
                f"## LS `{ls_name}`",
                "",
                f"- identity ls `{ls_uuid}`",
                f"- in-port (from-lport) {len(from_l)} (full list); "
                f"out-port (to-lport) {len(to_l)} (full list)",
                "",
                "### in-port (from-lport) — ingress",
                "",
            ]
        )
        rows, det = table_rows(
            from_l, nic_both, src_ip, dst_ip, hop_zone, hop_meta, full_ips
        )
        lines.extend(rows)
        all_details.extend(det)
        lines.extend(["", "### out-port (to-lport) — egress", ""])
        rows, det = table_rows(
            to_l, nic_both, src_ip, dst_ip, hop_zone, hop_meta, full_ips
        )
        lines.extend(rows)
        all_details.extend(det)

    lines.extend(
        [
            "",
            *first_hit_md(
                "upstream (src→dst, from-lport)",
                up_hit,
                f"- 5-tuple `{src_ip}` → `{dst_ip}` ICMP (no L4 dest port).",
            ),
            "",
            *first_hit_md(
                "downstream (dst→src, to-lport)",
                dn_hit,
                f"- return `{dst_ip}` → `{src_ip}` ICMP.",
            ),
        ]
    )
    if up_hit:
        uid = str(up_hit.get("acl_uuid") or "")
        lines.extend(
            [
                "",
                "### ct_label applicable for THIS traffic",
                "",
                f"- First-hit ACL writes/checks **ct_label** `{acl_label_hex(uid)}` "
                f"(NB ACL.label → northd `ct_commit {{ ct_label.label = reg3 }}`).",
                f"- Action `{up_hit.get('action')}` pri `{up_hit.get('priority')}` "
                f"`{up_hit.get('direction')}`.",
                f"- Human match: `{rewrite_match_human(up_hit.get('match') or '', src_nic, src_ip, dst_ip)}`",
                f"- L4: `{expand_l4(up_hit.get('match') or '') or 'ip4 (ICMP / unspecified proto)'}`",
            ]
        )
    lines.extend(ip_details_md(all_details, full_ips))
    lines.extend(
        [
            "",
            "## Identity footnotes",
            "",
            f"- src metadata decimal `{src_ct['metadata_dec'] or '-'}` "
            f"dp `{src_ct['dp_uuid']}` port_key `{src_ct['port_key']}`",
            f"- dst metadata decimal `{dst_ct['metadata_dec'] or '-'}` "
            f"dp `{dst_ct['dp_uuid']}` port_key `{dst_ct['port_key']}`",
            "- Hashed `@port_group_*` / `$address_set_*` are not primary identifiers.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", default=DEFAULT_SRC, help="NIC UUID, LSP UUID, or name")
    ap.add_argument("--dst", default=DEFAULT_DST, help="NIC UUID, LSP UUID, name, or IP")
    ap.add_argument(
        "--out",
        default="/home/rakeshkumar.r/panacea/clickhouse_ovn/out/acl_readable.md",
        help="markdown file (default clickhouse_ovn/out/acl_readable.md). Empty string skips write.",
    )
    ap.add_argument(
        "--full-ips",
        action="store_true",
        help="expand address-set remainder inside <details>",
    )
    ap.add_argument(
        "--log_bundle_id",
        type=int,
        default=0,
        help="Panacea log_bundle_id (default: latest flow_ovn.bundle)",
    )
    args = ap.parse_args()
    bid = env_or_latest_bundle(args.log_bundle_id)
    set_log_bundle_id(bid)
    md = render(args.src, args.dst, args.full_ips)
    sys.stdout.write(md)
    if args.out:
        out_path = os.path.abspath(args.out)
        parent = os.path.dirname(out_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w") as fh:
            fh.write(md)


if __name__ == "__main__":
    main()
