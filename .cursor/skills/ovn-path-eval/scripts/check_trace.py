#!/usr/bin/env python3
"""Composite OVN eval: upstream/downstream × ACL, L2, L3, GW, External. stdlib only."""
from __future__ import annotations

import argparse
import re
import sys
from typing import Dict, List, Tuple

SCENARIOS = ("same_l2", "l2_l3_l2", "two_router", "northbound", "acl_drop")
DIRS = ("upstream", "downstream")
LAYERS = ("acl", "l2", "l3", "gw", "external")
L3_SCEN = ("l2_l3_l2", "two_router", "northbound")


def _blocks(text: str) -> List[str]:
    return re.findall(r"```mermaid\s*(.*?)```", text, re.S | re.I)


def _split_dirs(text: str) -> Dict[str, str]:
    up_h = re.search(
        r"^## (?:Upstream composite|Mermaid (?:Upstream composite|FORWARD))\b",
        text,
        re.M | re.I,
    )
    dn_h = re.search(
        r"^## (?:Downstream composite|Mermaid (?:Downstream composite|REVERSE))\b",
        text,
        re.M | re.I,
    )
    if up_h and dn_h and up_h.start() < dn_h.start():
        return {"upstream": text[up_h.start() : dn_h.start()], "downstream": text[dn_h.start() :]}
    if up_h and not dn_h:
        return {"upstream": text[up_h.start() :], "downstream": ""}
    mds = _blocks(text)
    if len(mds) >= 2:
        return {"upstream": mds[0], "downstream": mds[1]}
    return {"upstream": text, "downstream": text}


def _edge(md: str, a: str, b: str) -> bool:
    return re.search(rf"{re.escape(a)}\s*-->\s*{re.escape(b)}", md) is not None


def _md(chunk: str) -> str:
    bs = _blocks(chunk)
    return bs[0] if bs else chunk


def _need_l3(chunk: str, scenario: str) -> bool:
    if scenario in L3_SCEN:
        return True
    return bool(re.search(r"\bRouter\b", chunk)) and "L3 N/A" not in _md(chunk)


def _need_gw(chunk: str, scenario: str) -> bool:
    if scenario == "northbound":
        return True
    md = _md(chunk)
    return "ext-GW" in md or "subgraph GW" in md and "GW N/A" not in md


def _need_ext(chunk: str, scenario: str) -> bool:
    if scenario == "northbound":
        return True
    md = _md(chunk)
    return "External / NAT GW" in md or ("subgraph EXT" in md and "External N/A" not in md)


def layer_acl(chunk: str, scenario: str) -> List[str]:
    fails: List[str] = []
    low = chunk.lower()
    md = _md(chunk)
    if "subgraph ACL" not in md and "ACL Policy" not in md:
        fails.append("ACL composite subgraph missing")
    if "from-lport" not in low:
        fails.append("missing from-lport ACL table")
    if "to-lport" not in low:
        fails.append("missing to-lport ACL table")
    if not re.search(r"\|\s*pri\s*\|", chunk, re.I):
        fails.append("ACL table missing pri")
    if not re.search(r"\|\s*match\s*\|", chunk, re.I):
        fails.append("ACL table missing match")
    if re.search(r"\b\d+\s+more\b", chunk) or "LIMIT 80" in chunk:
        fails.append("ACL truncated")
    if scenario == "acl_drop" and "drop" not in low:
        fails.append("acl_drop missing drop rows")
    return fails


def layer_l2(chunk: str, north: bool, direction: str = "upstream") -> List[str]:
    fails: List[str] = []
    md = _md(chunk)
    if "subgraph L2" not in md and "L2 stretch" not in md:
        fails.append("L2 composite subgraph missing")
    # Northbound: upstream has the VM as _S (no dest VIF). Downstream has the VM
    # as _D (source is External — no TAP_S).
    need_src = not (north and direction == "downstream")
    need_dst = not (north and direction == "upstream")
    if need_src:
        for tok in ("TAP_S", "OVS_S"):
            if tok not in md:
                fails.append(f"missing {tok}")
        for a, b in (("VM_S", "NIC_S"), ("NIC_S", "TAP_S"), ("TAP_S", "OVS_S")):
            if not _edge(md, a, b):
                fails.append(f"missing hop {a} --> {b}")
    if need_dst:
        for tok in ("TAP_D", "OVS_D"):
            if tok not in md:
                fails.append(f"missing {tok}")
        for a, b in (("OVS_D", "TAP_D"), ("TAP_D", "NIC_D"), ("NIC_D", "VM_D")):
            if not _edge(md, a, b):
                fails.append(f"missing hop {a} --> {b}")
    if "brAtlas" not in md:
        fails.append("OVS missing brAtlas")
    if "Switch" not in md:
        fails.append("missing Switch")
    return fails


def layer_l3(chunk: str, scenario: str) -> Tuple[str, List[str]]:
    if not _need_l3(chunk, scenario):
        return "N/A", []
    fails: List[str] = []
    md = _md(chunk)
    if "Router" not in md:
        fails.append("L3 missing Router")
    if "PBR on router" not in chunk:
        fails.append("missing PBR table")
    if "connected routes on router" not in chunk.lower():
        fails.append("missing connected routes")
    if scenario == "two_router" and md.count("Router") < 2 and "transit" not in md.lower():
        fails.append("two_router needs two Routers or transit")
    return ("FAIL" if fails else "PASS"), fails


def layer_gw(chunk: str, scenario: str) -> Tuple[str, List[str]]:
    if not _need_gw(chunk, scenario):
        return "N/A", []
    fails: List[str] = []
    md = _md(chunk)
    if "NAT on router" not in chunk:
        fails.append("missing NAT table")
    if "GW chassis" not in chunk:
        fails.append("missing GW chassis (RC)")
    if "ext-GW" not in md and "NAT" not in md:
        fails.append("GW mermaid missing NAT/ext-GW")
    return ("FAIL" if fails else "PASS"), fails


def layer_ext(chunk: str, scenario: str) -> Tuple[str, List[str]]:
    if not _need_ext(chunk, scenario):
        return "N/A", []
    fails: List[str] = []
    md = _md(chunk)
    if "External" not in md and "ext-GW" not in md:
        fails.append("missing External / ext-GW")
    return ("FAIL" if fails else "PASS"), fails


def eval_dir(
    chunk: str, scenario: str, north: bool, direction: str = "upstream"
) -> List[Tuple[str, str, List[str]]]:
    acl_f = layer_acl(chunk, scenario)
    l2_f = layer_l2(chunk, north, direction)
    l3_s, l3_f = layer_l3(chunk, scenario)
    gw_s, gw_f = layer_gw(chunk, scenario)
    ex_s, ex_f = layer_ext(chunk, scenario)
    return [
        ("ACL Policy", "FAIL" if acl_f else "PASS", acl_f),
        ("L2 stretch", "FAIL" if l2_f else "PASS", l2_f),
        ("L3 routing/PBR", l3_s if not l3_f else "FAIL", l3_f),
        ("GW", gw_s if not gw_f else "FAIL", gw_f),
        ("External", ex_s if not ex_f else "FAIL", ex_f),
    ]


def composite(rows: List[Tuple[str, str, List[str]]]) -> str:
    if any(s == "FAIL" for _, s, _ in rows):
        return "FAIL"
    return "PASS"


def format_dir(name: str, rows: List[Tuple[str, str, List[str]]]) -> List[str]:
    out = [f"## {name} composite", "", "| Layer | Verdict |", "|---|---|"]
    for layer, status, fails in rows:
        out.append(f"| {layer} | {status} |")
        for f in fails:
            out.append(f"- `{layer}` FAIL: {f}")
    out.append("")
    out.append(f"**{name.upper()}: {composite(rows)}**")
    out.append("")
    return out


def check(text: str, scenario: str = "", direction: str = "", layer: str = "") -> Tuple[List[str], int]:
    north = scenario == "northbound" or bool(
        re.search(
            r"--dst\s+(external|ext|northbound|nat|\d{1,3}(?:\.\d{1,3}){3})\b",
            text,
            re.I,
        )
    ) or bool(re.search(r"\bnorthbound\b", text, re.I))
    chunks = _split_dirs(text)
    lines: List[str] = []
    rc = 0
    want_dirs = (direction,) if direction in DIRS else DIRS
    for d in want_dirs:
        chunk = chunks.get(d) or ""
        if not chunk.strip():
            lines.append(f"FAIL: missing {d} composite")
            rc = 1
            continue
        rows = eval_dir(chunk, scenario, north, d)
        if layer in LAYERS:
            key = {
                "acl": "ACL Policy",
                "l2": "L2 stretch",
                "l3": "L3 routing/PBR",
                "gw": "GW",
                "external": "External",
            }[layer]
            rows = [r for r in rows if r[0] == key]
        lines.extend(format_dir(d.capitalize(), rows))
        if composite(rows) == "FAIL":
            rc = 1
    if not direction and not layer:
        ups = "FAIL" if any("**UPSTREAM: FAIL**" == x for x in lines) else "PASS"
        dns = "FAIL" if any("**DOWNSTREAM: FAIL**" == x for x in lines) else "PASS"
        if any(x.startswith("FAIL: missing") for x in lines):
            ups = dns = "FAIL"
        final = "FAIL" if "FAIL" in (ups, dns) or rc else "PASS"
        lines.append(f"**COMPOSITE: {final}**")
        rc = 0 if final == "PASS" else 1
    return lines, rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Composite OVN upstream/downstream eval")
    ap.add_argument("file", nargs="?", help="trace .md; stdin if omitted")
    ap.add_argument("--scenario", choices=SCENARIOS, default="")
    ap.add_argument("--direction", choices=DIRS, default="")
    ap.add_argument("--layer", choices=LAYERS, default="")
    args = ap.parse_args()
    if args.file and not args.file.endswith(".md"):
        print("FAIL: output must be a .md file")
        return 1
    text = sys.stdin.read() if not args.file else open(args.file, errors="replace").read()
    lines, rc = check(text, args.scenario, args.direction, args.layer)
    print("\n".join(lines))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
