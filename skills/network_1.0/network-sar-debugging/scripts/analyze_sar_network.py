#!/usr/bin/env python3
"""Full logbay network RCA: SAR + iostat + ethtool CRC + host_nic_stats + ping.

Hard rule: every counter class is always present in JSON output. Missing
sources become status=EVIDENCE_INSUFFICIENT — never omit L1/CRC.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


TS_RE = re.compile(r"^#TIMESTAMP (\d+) : (.+)$")
WALL_TOD_RE = re.compile(
    r"(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})\s*(?P<p>[AP]M)",
    re.I,
)
# Standalone sar row: "01:37:26 PM      eth1 304813.77 ..."
SAR_WALL_IFACE_RE = re.compile(
    r"^(?P<tod>\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+(?P<iface>\S+)\s+(?P<rest>.+)$",
    re.I,
)
STAT_RE = re.compile(r"^\s*([a-zA-Z0-9_.-]+):\s*(\d+)\s*$")
IFACE_HDR_RE = re.compile(r"^From (\S+) NIC statistics:", re.I)
IFCONFIG_IFACE_RE = re.compile(r"^(\S+)\s*:?\s")
IFCONFIG_RX_RE = re.compile(
    r"RX errors\s+(\d+)\s+dropped\s+(\d+)\s+overruns\s+(\d+)\s+frame\s+(\d+)"
)
IFCONFIG_TX_RE = re.compile(
    r"TX errors\s+(\d+)\s+dropped\s+(\d+)\s+overruns\s+(\d+)\s+carrier\s+(\d+)\s+collisions\s+(\d+)"
)
PING_FAIL_RE = re.compile(
    r"(UNREACHABLE|Destination Host Unreachable|100% packet loss|LOST_PKT|timed out)",
    re.I,
)

L1_KEYS = (
    "rx_crc_errors",
    "rx_length_errors",
    "rx_frame_errors",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
    "collisions",
)


def _insufficient(reason: str, searched: list[str] | None = None) -> dict[str, Any]:
    return {
        "status": "EVIDENCE_INSUFFICIENT",
        "reason": reason,
        "searched": searched or [],
    }


def _ok(payload: dict[str, Any]) -> dict[str, Any]:
    out = {"status": "OK"}
    out.update(payload)
    return out


def _pick_latest(paths: list[Path]) -> Path | None:
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def discover_bundle(root: Path) -> dict[str, Any]:
    """Resolve primary cvm_logs/sysstats + ahv/*/commands under PE bundle."""
    sysstats = root / "cvm_logs" / "sysstats"
    ahv_cmds: list[Path] = []
    ahv = root / "ahv"
    if ahv.is_dir():
        for host_dir in sorted(ahv.iterdir()):
            cmd = host_dir / "commands"
            if cmd.is_dir():
                ahv_cmds.append(cmd)

    def glob_one(pattern: str) -> Path | None:
        if not sysstats.is_dir():
            return None
        return _pick_latest(list(sysstats.glob(pattern)))

    return {
        "bundle_root": root,
        "sysstats": sysstats if sysstats.is_dir() else None,
        "sar": glob_one("sar.INFO*"),
        "iostat": glob_one("iostat.INFO*"),
        "host_nic_stats": glob_one("host_nic_stats.INFO*"),
        "ping_all": glob_one("ping_all.INFO*"),
        "ping_remotes": glob_one("ping_remotes.INFO*"),
        "ethtool_dirs": ahv_cmds,
        "ifconfig": _pick_latest(
            [p for d in ahv_cmds for p in d.glob("ifconfig_-a.stdout")]
        ),
        "bond_show": _pick_latest(
            [p for d in ahv_cmds for p in d.glob("ovs-appctl_bond_show.stdout")]
        ),
        "dmesg": _pick_latest(
            [p for d in ahv_cmds for p in d.glob("dmesg_-T.stdout")]
        ),
        "ip_addr": _pick_latest(
            [p for d in ahv_cmds for p in d.glob("ip_addr_show.stdout")]
        ),
    }


def _parse_iface_line(parts: list[str]) -> tuple[str, list[float]] | None:
    if len(parts) < 6:
        return None
    try:
        if parts[1] in ("AM", "PM"):
            iface, nums = parts[2], parts[3:]
        else:
            iface, nums = parts[1], parts[2:]
        return iface, [float(x) for x in nums]
    except ValueError:
        return None


def parse_sar(path: Path, iface_filter: str | None = None) -> dict[str, Any]:
    walls: list[tuple[int, str]] = []
    traf: dict[str, list[dict[str, Any]]] = defaultdict(list)
    err: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cur_ts = 0
    cur_wall = ""
    mode = None

    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = TS_RE.match(line)
            if m:
                cur_ts = int(m.group(1))
                cur_wall = m.group(2).strip()
                walls.append((cur_ts, cur_wall))
                mode = None
                continue
            if "IFACE" in line and "rxpck/s" in line:
                mode = "traf"
                continue
            if "IFACE" in line and "rxerr/s" in line:
                mode = "err"
                continue
            # Host/sysstats paste without IFACE header (TOD + iface + counters)
            if mode is None:
                wm = SAR_WALL_IFACE_RE.match(line.strip())
                if wm and not line.lstrip().startswith("#"):
                    tod = wm.group("tod")
                    iface = wm.group("iface")
                    rest = wm.group("rest").split()
                    try:
                        nums = [float(x) for x in rest]
                    except ValueError:
                        nums = []
                    if (
                        iface not in ("lo", "IFACE")
                        and (not iface_filter or iface == iface_filter)
                        and len(nums) >= 8
                    ):
                        traf[iface].append(
                            {
                                "ts": float(cur_ts) if cur_ts else 0.0,
                                "rxpck": nums[0],
                                "txpck": nums[1],
                                "rxkB": nums[2],
                                "txkB": nums[3],
                                "ifutil": nums[7] if len(nums) > 7 else 0.0,
                                "wall": tod,
                                "tod": tod,
                            }
                        )
                continue
            if not mode:
                continue
            parsed = _parse_iface_line(line.split())
            if not parsed:
                continue
            iface, nums = parsed
            if iface_filter and iface != iface_filter:
                continue
            tod_m = WALL_TOD_RE.search(line)
            tod = tod_m.group(0) if tod_m else ""
            wall = cur_wall or tod
            if mode == "traf" and len(nums) >= 8:
                traf[iface].append(
                    {
                        "ts": float(cur_ts),
                        "rxpck": nums[0],
                        "txpck": nums[1],
                        "rxkB": nums[2],
                        "txkB": nums[3],
                        "ifutil": nums[7],
                        "wall": wall,
                        "tod": tod or wall,
                    }
                )
            elif mode == "err" and len(nums) >= 8:
                err[iface].append(
                    {
                        "ts": float(cur_ts),
                        "rxerr": nums[0],
                        "txerr": nums[1],
                        "rxdrop": nums[3],
                        "txdrop": nums[4],
                        "wall": wall,
                        "tod": tod or wall,
                    }
                )

    return {"walls": walls, "traf": dict(traf), "err": dict(err)}


def parse_iostat(path: Path) -> dict[str, Any]:
    cpu: list[dict[str, Any]] = []
    disk: list[dict[str, Any]] = []
    cur_wall = ""
    mode = None

    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = TS_RE.match(line)
            if m:
                cur_wall = m.group(2).strip()
                mode = None
                continue
            if line.startswith("avg-cpu:"):
                mode = "cpu_hdr"
                continue
            if mode == "cpu_hdr" and line.strip() and not line.startswith("Device"):
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        user, _nice, system, iowait, _steal, idle = (
                            float(x) for x in parts[:6]
                        )
                        cpu.append(
                            {
                                "wall": cur_wall,
                                "user": user,
                                "system": system,
                                "iowait": iowait,
                                "idle": idle,
                            }
                        )
                    except ValueError:
                        pass
                mode = None
                continue
            if line.startswith("Device"):
                mode = "disk"
                continue
            if mode == "disk" and line.strip():
                parts = line.split()
                if len(parts) < 22:
                    continue
                dev = parts[0]
                if not re.match(r"^(sd|nvme|md)", dev):
                    continue
                try:
                    disk.append(
                        {
                            "wall": cur_wall,
                            "dev": dev,
                            "r_await": float(parts[5]),
                            "w_await": float(parts[11]),
                            "util": float(parts[-1]),
                            "rMB": float(parts[2]),
                            "wMB": float(parts[8]),
                        }
                    )
                except ValueError:
                    continue
    return {"cpu": cpu, "disk": disk}


def parse_ethtool_stats(path: Path) -> dict[str, int]:
    stats: dict[str, int] = {}
    with path.open(errors="ignore") as fh:
        for line in fh:
            m = STAT_RE.match(line)
            if m:
                stats[m.group(1)] = int(m.group(2))
    return stats


def parse_ethtool_link(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("Speed:"):
                out["speed"] = line.split(":", 1)[1].strip()
            elif line.startswith("Duplex:"):
                out["duplex"] = line.split(":", 1)[1].strip()
            elif line.startswith("Link detected:"):
                out["link_detected"] = line.split(":", 1)[1].strip().lower() == "yes"
    return out


def parse_ethtool_offload(path: Path) -> dict[str, Any]:
    """Parse ethtool -k / --show-offload for TSO/GSO/GRO/LRO (and aliases)."""
    # Map common names → keys we always emit
    want = {
        "tcp-segmentation-offload": "tso",
        "generic-segmentation-offload": "gso",
        "generic-receive-offload": "gro",
        "large-receive-offload": "lro",
        "rx-checksumming": "rx_checksumming",
        "tx-checksumming": "tx_checksumming",
        "scatter-gather": "scatter_gather",
        "receive-hashing": "rss",
        "rx-vlan-offload": "rx_vlan_offload",
        "tx-vlan-offload": "tx_vlan_offload",
    }
    raw: dict[str, str] = {}
    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("Features for"):
                continue
            if ":" not in line:
                continue
            # skip indented sub-features unless useful; capture top-level only
            if line.startswith("\t") or line.startswith(" "):
                # still capture tx-tcp-segmentation etc.
                pass
            name, _, rest = line.partition(":")
            name = name.strip()
            val = rest.strip().split()[0].lower() if rest.strip() else ""
            if name in want or name.startswith("tx-tcp") or name in (
                "rx-gro-hw",
                "rx-gro-list",
            ):
                raw[name] = val
    summary = {short: raw.get(long) for long, short in want.items()}
    # LSO is not a Linux ethtool key; note TSO/GSO as the Linux equivalents
    summary["lso_note"] = "Linux ethtool has no LSO flag; use tso/gso"
    summary["raw_key_features"] = raw
    # Suspect only if expected-on features are unexpectedly off (not [fixed] offs we can't change)
    suspects = []
    for key in ("tso", "gso", "gro", "rx_checksumming", "tx_checksumming"):
        if summary.get(key) == "off":
            suspects.append(key)
    return {"features": summary, "suspect_off": suspects}


def parse_ethtool_ring(path: Path) -> dict[str, Any]:
    """Parse ethtool -g ring parameters."""
    out: dict[str, Any] = {"max": {}, "current": {}}
    section = None
    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("Pre-set maximums"):
                section = "max"
                continue
            if line.startswith("Current hardware settings"):
                section = "current"
                continue
            if section and ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k in ("RX", "TX", "RX Mini", "RX Jumbo") and v and v != "n/a":
                    try:
                        out[section][k] = int(v)
                    except ValueError:
                        out[section][k] = v
    # Flag tiny rings vs max (common drop amplifier)
    warn = []
    for k in ("RX", "TX"):
        cur, mx = out["current"].get(k), out["max"].get(k)
        if isinstance(cur, int) and isinstance(mx, int) and mx > 0 and cur < mx // 4:
            warn.append(f"{k}_ring_small_{cur}_of_max_{mx}")
    out["warnings"] = warn
    return out


def parse_host_nic_stats(path: Path) -> dict[str, Any]:
    """First and last snapshot per host NIC; compute deltas for L1 keys."""
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cur_ts = 0
    cur_wall = ""
    cur_iface: str | None = None
    cur_stats: dict[str, int] = {}

    def flush() -> None:
        nonlocal cur_iface, cur_stats
        if cur_iface and cur_stats:
            samples[cur_iface].append(
                {"ts": cur_ts, "wall": cur_wall, "stats": dict(cur_stats)}
            )
        cur_iface = None
        cur_stats = {}

    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = TS_RE.match(line)
            if m:
                flush()
                cur_ts = int(m.group(1))
                cur_wall = m.group(2).strip()
                continue
            hm = IFACE_HDR_RE.match(line.strip())
            if hm:
                flush()
                cur_iface = hm.group(1)
                continue
            sm = STAT_RE.match(line)
            if sm and cur_iface:
                key = sm.group(1)
                if key in L1_KEYS or key in (
                    "rx_packets",
                    "tx_packets",
                    "rx_bytes",
                    "tx_bytes",
                ):
                    cur_stats[key] = int(sm.group(2))
        flush()

    deltas: dict[str, Any] = {}
    for iface, snaps in samples.items():
        if len(snaps) < 2:
            first = last = snaps[0] if snaps else None
        else:
            first, last = snaps[0], snaps[-1]
        if not first or not last:
            continue
        d = {
            k: last["stats"].get(k, 0) - first["stats"].get(k, 0) for k in L1_KEYS
        }
        deltas[iface] = {
            "first_wall": first["wall"],
            "last_wall": last["wall"],
            "n_samples": len(snaps),
            "first": {k: first["stats"].get(k, 0) for k in L1_KEYS},
            "last": {k: last["stats"].get(k, 0) for k in L1_KEYS},
            "delta": d,
        }
    return {"ifaces": deltas}


def parse_ifconfig(path: Path) -> dict[str, Any]:
    ifaces: dict[str, Any] = {}
    cur: str | None = None
    with path.open(errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.startswith(" ") and ":" in line.split()[0] if line else False:
                name = line.split(":", 1)[0].split()[0]
                cur = name.rstrip(":")
                ifaces[cur] = {}
                continue
            # Classic: "eth0: flags=..." or "eth0 Link encap"
            if line and not line.startswith((" ", "\t")):
                parts = line.split()
                if parts:
                    cur = parts[0].rstrip(":")
                    ifaces.setdefault(cur, {})
            if not cur:
                continue
            rx = IFCONFIG_RX_RE.search(line)
            if rx:
                ifaces[cur].update(
                    {
                        "rx_errors": int(rx.group(1)),
                        "rx_dropped": int(rx.group(2)),
                        "rx_overruns": int(rx.group(3)),
                        "rx_frame": int(rx.group(4)),
                    }
                )
            tx = IFCONFIG_TX_RE.search(line)
            if tx:
                ifaces[cur].update(
                    {
                        "tx_errors": int(tx.group(1)),
                        "tx_dropped": int(tx.group(2)),
                        "tx_overruns": int(tx.group(3)),
                        "tx_carrier": int(tx.group(4)),
                        "collisions": int(tx.group(5)),
                    }
                )
    return {"ifaces": ifaces}


def parse_ping(path: Path, max_hits: int = 80) -> dict[str, Any]:
    """Parse timestamped ping_all / ping_remotes blocks with LOST_PKT/unreachable."""
    events: list[dict[str, Any]] = []
    cur_ts = 0
    cur_wall = ""
    cur_fails: list[dict[str, Any]] = []

    # cvm-10.1.20.104 : 0.20 ms  LOST_PKT
    # gw-10.1.20.1 : unreachable
    line_re = re.compile(
        r"^\s*(\S+)\s*:\s*(?:([\d.]+)\s*ms)?\s*(LOST_PKT|unreachable)?",
        re.I,
    )

    def flush() -> None:
        nonlocal cur_fails
        if cur_fails:
            events.append(
                {
                    "ts": cur_ts,
                    "wall": cur_wall,
                    "fails": list(cur_fails),
                    "n_fails": len(cur_fails),
                }
            )
        cur_fails = []

    with path.open(errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = TS_RE.match(line)
            if m:
                flush()
                cur_ts = int(m.group(1))
                cur_wall = m.group(2).strip()
                continue
            if "latency" in line and "threshold" in line:
                continue
            lm = line_re.match(line)
            if not lm:
                continue
            target, lat, kind = lm.group(1), lm.group(2), lm.group(3)
            if not kind and lat is None:
                continue
            # Only keep failure rows (LOST_PKT / unreachable) or high latency > 100ms
            high = False
            try:
                high = lat is not None and float(lat) >= 100.0
            except ValueError:
                pass
            if kind or high:
                cur_fails.append(
                    {
                        "target": target,
                        "latency_ms": float(lat) if lat else None,
                        "kind": (kind or "HIGH_LATENCY").upper(),
                    }
                )
        flush()

    sample = []
    for ev in events:
        if ev["n_fails"] > 0:
            sample.append(ev)
            if len(sample) >= max_hits:
                break

    return {
        "fail_event_count": sum(1 for e in events if e["n_fails"] > 0),
        "fail_hit_count_capped": len(sample),
        "fail_events": sample,
        "sample_fails": [
            f"{e['wall']} {f['target']} {f['kind']}"
            for e in sample[:20]
            for f in e["fails"][:3]
        ],
    }


def detect_rx_flood(
    sar: dict[str, Any],
    bond_roles: dict[str, str] | None = None,
    rxpck_thresh: float = 100_000.0,
    standby_rx_thresh: float = 100_000.0,
) -> dict[str, Any]:
    """Detect fabric RX flood across ALL SAR ifaces (not hardcoded names).

    Strong signal: standby/backup member with huge rxpck and ~0 txpck while
    ping path fails — L2 flood hitting both bond legs.
    """
    bond_roles = bond_roles or {}
    traf = sar.get("traf") or {}
    windows: list[dict[str, Any]] = []
    standby_flood = False
    multi_iface_flood = False

    # Index by wall time across ifaces
    by_wall: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for iface, rows in traf.items():
        if iface in ("lo", "sit0"):
            continue
        for r in rows:
            wall = str(r.get("wall") or "")
            by_wall[wall].append(
                {
                    "iface": iface,
                    "rxpck": r["rxpck"],
                    "txpck": r["txpck"],
                    "rxkB": r["rxkB"],
                    "role": bond_roles.get(iface, "unknown"),
                    "ts": r.get("ts") or 0.0,
                    "tod": r.get("tod") or wall,
                }
            )

    for wall, rows in by_wall.items():
        hot = [r for r in rows if r["rxpck"] >= rxpck_thresh]
        if not hot:
            continue
        standby_hot = [
            r
            for r in hot
            if (
                r["role"] in ("standby", "standby_heuristic")
                or (r["txpck"] < 1.0 and r["rxpck"] >= standby_rx_thresh)
            )
        ]
        if len(hot) >= 2:
            multi_iface_flood = True
        if standby_hot:
            standby_flood = True
        windows.append(
            {
                "wall": wall,
                "ts": max((r.get("ts") or 0.0) for r in hot),
                "tod": next((r.get("tod") for r in hot if r.get("tod")), wall),
                "hot": hot,
                "standby_rx_flood": standby_hot,
                "max_rxpck": max(r["rxpck"] for r in hot),
            }
        )

    windows.sort(key=lambda w: w["max_rxpck"], reverse=True)
    top = windows[:15]
    confirmed = bool(top) and (
        standby_flood
        or multi_iface_flood
        or (top and top[0]["max_rxpck"] >= 500_000)
    )
    return {
        "status": "OK" if traf else "EVIDENCE_INSUFFICIENT",
        "confirmed": confirmed,
        "standby_rx_flood": standby_flood,
        "multi_iface_flood": multi_iface_flood,
        "n_flood_windows": len(windows),
        "top_windows": top,
        "verdict": (
            "EXTERNAL_RX_FLOOD"
            if confirmed
            else ("RX_ELEVATED" if windows else "NO_RX_FLOOD")
        ),
        "note": (
            "Correlate flood windows with ping LOST_PKT/unreachable. "
            "Standby member high RX + ~0 TX ⇒ L2 flood on fabric, not 'NIC down'."
        ),
    }


def correlate_ping_flood(
    ping: dict[str, Any] | None,
    flood: dict[str, Any] | None,
    window_sec: float = 120.0,
) -> dict[str, Any]:
    """True when ping fail walls fall near SAR RX flood walls."""
    if not ping or not flood or not flood.get("confirmed"):
        return {
            "status": "SKIPPED",
            "correlated": False,
            "reason": "need ping fails + confirmed RX flood",
        }
    fail_ev = ping.get("fail_events") or []
    tops = flood.get("top_windows") or []
    if not fail_ev or not tops:
        return {"status": "OK", "correlated": False, "matches": []}

    matches = []
    for ev in fail_ev:
        ets = float(ev.get("ts") or 0) or None
        if ets is None:
            ets = _parse_wall_loose(ev.get("wall") or "")
        etod = _tod_seconds(ev.get("wall") or "")
        for w in tops:
            wts = float(w.get("ts") or 0) or None
            if wts is None:
                wts = _parse_wall_loose(w.get("wall") or "")
            wtod = _tod_seconds(w.get("tod") or w.get("wall") or "")
            delta = None
            if ets is not None and wts is not None and ets > 1_000_000 and wts > 1_000_000:
                delta = abs(ets - wts)
            elif etod is not None and wtod is not None:
                delta = min(abs(etod - wtod), 86400 - abs(etod - wtod))
            if delta is None or delta > window_sec:
                continue
            matches.append(
                {
                    "ping_wall": ev["wall"],
                    "flood_wall": w["wall"],
                    "delta_sec": delta,
                    "max_rxpck": w["max_rxpck"],
                    "ping_fails": ev["fails"][:6],
                    "standby_rx_flood": bool(w.get("standby_rx_flood")),
                }
            )
            break
    return {
        "status": "OK",
        "correlated": bool(matches),
        "n_matches": len(matches),
        "matches": matches[:20],
        "verdict": (
            "PING_LOSS_CORRELATES_WITH_RX_FLOOD"
            if matches
            else "PING_LOSS_NO_FLOOD_OVERLAP"
        ),
        # Remediations (trunk/VLAN/stop-source) are NOT in diamond logs — do not invent them.
        "note": (
            "Correlation is log-only (sar + ping). Do not emit switch trunk/VLAN "
            "or stop-source plans — those are outside the bundle."
        ),
    }



def _summary(vals: list[float]) -> dict[str, float]:
    if not vals:
        return {"n": 0}
    s = sorted(vals)
    n = len(s)
    return {
        "n": n,
        "min": s[0],
        "avg": sum(s) / n,
        "p50": s[n // 2],
        "p95": s[int(0.95 * (n - 1))],
        "max": s[-1],
    }


def parse_bond_show(path: Path) -> dict[str, Any]:
    """Parse ovs-appctl bond/show (active-backup member roles)."""
    bonds: dict[str, Any] = {}
    cur_bond: str | None = None
    cur_member: str | None = None
    with path.open(errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("---- ") and line.endswith(" ----"):
                cur_bond = line.strip("- ").strip()
                bonds[cur_bond] = {"members": {}, "mode": None, "active_member": None}
                cur_member = None
                continue
            if not cur_bond:
                continue
            b = bonds[cur_bond]
            if line.startswith("bond_mode:"):
                b["mode"] = line.split(":", 1)[1].strip()
            elif line.startswith("active member mac:"):
                # active member mac: aa:bb(eth1)
                m = re.search(r"\((\S+)\)\s*$", line)
                if m:
                    b["active_member"] = m.group(1)
            elif line.startswith("member "):
                # member eth1: enabled   OR   member eth2: disabled
                parts = line.replace(":", " ").split()
                cur_member = parts[1]
                enabled = True
                if "disabled" in line.lower():
                    enabled = False
                b["members"][cur_member] = {
                    "enabled": enabled,
                    "active": False,
                    "may_enable": None,
                }
            elif cur_member and line.strip() in ("enabled", "disabled"):
                b["members"][cur_member]["enabled"] = line.strip() == "enabled"
            elif cur_member and "active member" in line:
                b["members"][cur_member]["active"] = True
                b["active_member"] = cur_member
            elif cur_member and "may_enable:" in line:
                b["members"][cur_member]["may_enable"] = "true" in line.lower()
    # normalize roles
    for b in bonds.values():
        active = b.get("active_member")
        for name, mem in b["members"].items():
            if mem.get("active") or name == active:
                mem["role"] = "active"
            elif mem.get("enabled") is False or mem.get("may_enable") is False:
                mem["role"] = "disabled"
            else:
                mem["role"] = "standby"
    return {"bonds": bonds}


def parse_dmesg_nic_flaps(path: Path) -> dict[str, Any]:
    """Extract NIC Link Up/Down flaps from dmesg_-T."""
    flap_re = re.compile(
        r"\[(.*?)\]\s+\S+\s+\S+\s+(\S+):\s+NIC Link is (Up|Down)(.*)$",
        re.I,
    )
    # also: "eth2: Link is Down"
    alt_re = re.compile(
        r"\[(.*?)\]\s+.*\b(eth\d+|ens\S+|enp\S+):.*\bLink is (Up|Down)\b",
        re.I,
    )
    events: list[dict[str, str]] = []
    by_iface: dict[str, list[dict[str, str]]] = defaultdict(list)
    with path.open(errors="ignore") as fh:
        for line in fh:
            m = flap_re.search(line) or alt_re.search(line)
            if not m:
                continue
            wall, iface, state = m.group(1), m.group(2), m.group(3).lower()
            ev = {"wall": wall, "iface": iface, "state": state, "raw": line.strip()[:200]}
            events.append(ev)
            by_iface[iface].append(ev)
    downs = [e for e in events if e["state"] == "down"]
    return {
        "n_events": len(events),
        "n_downs": len(downs),
        "by_iface": dict(by_iface),
        "recent_downs": downs[-20:],
    }


def parse_ip_link_roles(path: Path) -> dict[str, Any]:
    """Parse ip addr / ip link for NO-CARRIER / DOWN / LOWER_UP."""
    ifaces: dict[str, Any] = {}
    # 3: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> ... state UP
    hdr = re.compile(
        r"^\d+:\s+(\S+):\s+<([^>]+)>\s+.*\bstate\s+(\S+)",
    )
    with path.open(errors="ignore") as fh:
        for line in fh:
            m = hdr.match(line.strip())
            if not m:
                continue
            name, flags, state = m.group(1), m.group(2), m.group(3)
            name = name.split("@", 1)[0]
            fl = {f.strip() for f in flags.split(",")}
            ifaces[name] = {
                "flags": sorted(fl),
                "state": state,
                "oper_up": state.upper() == "UP" and "LOWER_UP" in fl,
                "no_carrier": "NO-CARRIER" in fl,
                "admin_down": "UP" not in fl,
            }
    return {"ifaces": ifaces}


def analyze_l1(
    ethtool_dirs: list[Path],
    host_nic: dict[str, Any] | None,
    ifconfig: dict[str, Any] | None,
    bond: dict[str, Any] | None = None,
    dmesg_flaps: dict[str, Any] | None = None,
    ip_link: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Mandatory L1/CRC/drops/link/bond-role class.

    Hard rule: resolve bond active vs standby/disabled BEFORE treating
    rx_dropped as path evidence. Standby/down member drops are not the
    active datapath; dig each bond member's link + dmesg flaps.
    """
    ethtool_stats: dict[str, Any] = {}
    ethtool_link: dict[str, Any] = {}
    ethtool_offload: dict[str, Any] = {}
    ethtool_ring: dict[str, Any] = {}
    searched: list[str] = []

    for d in ethtool_dirs:
        searched.append(str(d))
        for link_path in sorted(d.glob("ethtool_*.stdout")):
            # Skip option dumps: ethtool_--statistics_*, --show-offload_*, --driver_*, etc.
            base = link_path.name[len("ethtool_") : -len(".stdout")]
            if base.startswith("--") or base.startswith("-"):
                continue
            ethtool_link[base] = parse_ethtool_link(link_path)
        for off_path in sorted(d.glob("ethtool_--show-offload_*.stdout")):
            name = off_path.name.replace("ethtool_--show-offload_", "").replace(
                ".stdout", ""
            )
            ethtool_offload[name] = parse_ethtool_offload(off_path)
        for ring_path in sorted(d.glob("ethtool_--show-ring_*.stdout")):
            name = ring_path.name.replace("ethtool_--show-ring_", "").replace(
                ".stdout", ""
            )
            ethtool_ring[name] = parse_ethtool_ring(ring_path)
        for stats_path in sorted(d.glob("ethtool_--statistics_*.stdout")):
            name = stats_path.name.replace("ethtool_--statistics_", "").replace(
                ".stdout", ""
            )
            ethtool_stats[name] = parse_ethtool_stats(stats_path)

    # Bond member role map
    role_by_iface: dict[str, str] = {}
    bond_issues: list[dict[str, Any]] = []
    if bond and bond.get("bonds"):
        for bname, b in bond["bonds"].items():
            for mname, mem in (b.get("members") or {}).items():
                role_by_iface[mname] = mem.get("role") or "unknown"
                if mem.get("role") in ("standby", "disabled"):
                    bond_issues.append(
                        {
                            "bond": bname,
                            "iface": mname,
                            "role": mem.get("role"),
                            "mode": b.get("mode"),
                            "active_member": b.get("active_member"),
                            "enabled": mem.get("enabled"),
                            "may_enable": mem.get("may_enable"),
                            "finding": (
                                "BOND_MEMBER_DISABLED"
                                if mem.get("role") == "disabled"
                                else "BOND_MEMBER_STANDBY_NOT_ACTIVE"
                            ),
                        }
                    )

    crc_any = False
    soft_drop_active = False
    soft_drop_standby = False
    link_down_ifaces: list[str] = []
    per_iface: dict[str, Any] = {}

    # Prefer ifaces discovered from bond members (never hardcode eth1/eth2/…).
    bond_members: set[str] = set(role_by_iface)
    all_ifaces = (
        bond_members
        | set(ethtool_stats)
        | set(ethtool_link)
        | set(ethtool_offload)
        | set(ethtool_ring)
    )
    if ip_link:
        all_ifaces |= {
            k
            for k in ip_link.get("ifaces", {})
            if re.match(r"^(eth|ens|enp|eno|em)\d", k)
        }
    # If bond exists, still evaluate every bond member even with no ethtool file
    if bond_members:
        all_ifaces |= bond_members

    active_members = [i for i, r in role_by_iface.items() if r == "active"]
    standby_members = [i for i, r in role_by_iface.items() if r == "standby"]
    disabled_members = [i for i, r in role_by_iface.items() if r == "disabled"]

    for iface in sorted(all_ifaces):
        st = ethtool_stats.get(iface, {})
        link = dict(ethtool_link.get(iface, {}))
        role = role_by_iface.get(iface, "unknown")
        ipinfo = (ip_link or {}).get("ifaces", {}).get(iface, {})

        # Link down signals
        speed = str(link.get("speed") or "")
        link_down = (
            link.get("link_detected") is False
            or "Unknown" in speed
            or ipinfo.get("no_carrier") is True
            or ipinfo.get("admin_down") is True
            or (ipinfo.get("state") or "").upper() == "DOWN"
        )
        if link_down:
            link_down_ifaces.append(iface)

        crc = st.get("rx_crc_errors", 0)
        dropped = st.get("rx_dropped", 0)
        length = st.get("rx_length_errors", 0)
        frame = st.get("rx_frame_errors", 0)
        collisions = st.get("collisions", 0)
        rx_err = st.get("rx_errors", 0)
        tx_packets = st.get("tx_packets", 0)
        rx_packets = st.get("rx_packets", 0)

        if crc > 0 or length > 0 or frame > 0 or collisions > 0:
            crc_any = True
        if dropped > 1000 and crc == 0:
            if role in ("standby", "disabled") or link_down:
                soft_drop_standby = True
            else:
                soft_drop_active = True

        # Inactive heuristic even without bond file: almost no TX vs huge RX
        inactive_heuristic = False
        if tx_packets is not None and rx_packets is not None and rx_packets > 1_000_000:
            if tx_packets < max(1000, rx_packets * 0.001):
                inactive_heuristic = True
                if role == "unknown":
                    role = "standby_heuristic"

        if link_down or role == "disabled":
            finding = "NIC_INACTIVE_OR_DOWN"
        elif role in ("standby", "standby_heuristic"):
            finding = "BOND_MEMBER_STANDBY_NOT_ACTIVE"
        elif crc or length or frame or collisions:
            finding = "L1_CRC_OR_LINK"
        elif dropped > 1000:
            finding = "SOFT_RX_DROPS"
        else:
            finding = "NO_L1_ISSUE"

        flaps = (dmesg_flaps or {}).get("by_iface", {}).get(iface, [])
        down_flaps = [e for e in flaps if e.get("state") == "down"]
        off = ethtool_offload.get(iface)
        ring = ethtool_ring.get(iface)

        per_iface[iface] = {
            "source": "ethtool+bond+dmesg+offload",
            "bond_role": role,
            "inactive_heuristic": inactive_heuristic,
            "rx_crc_errors": crc,
            "rx_length_errors": length,
            "rx_frame_errors": frame,
            "rx_errors": rx_err,
            "rx_dropped": dropped,
            "tx_dropped": st.get("tx_dropped", 0),
            "tx_packets": tx_packets,
            "rx_packets": rx_packets,
            "collisions": collisions,
            "link": link,
            "ip_link": ipinfo or None,
            "link_down": link_down,
            "offload": off,
            "ring": ring,
            "dmesg_link_downs": len(down_flaps),
            "dmesg_down_samples": down_flaps[-5:],
            "finding": finding,
            "note": (
                "Standby member in active-backup is expected when enabled; "
                "not a root cause by itself. Dig only if disabled/link-down/flapping. "
                "Do not attribute active-path loss to standby rx_dropped."
                if finding == "BOND_MEMBER_STANDBY_NOT_ACTIVE"
                else (
                    "Standby/down member: dig link flaps and bond health."
                    if finding == "NIC_INACTIVE_OR_DOWN"
                    else None
                )
            ),
        }

    host_nic_summary: dict[str, Any] | None = None
    if host_nic and host_nic.get("ifaces"):
        host_nic_summary = {}
        for iface, info in host_nic["ifaces"].items():
            d = info["delta"]
            role = role_by_iface.get(iface, per_iface.get(iface, {}).get("bond_role", "unknown"))
            if d.get("rx_crc_errors", 0) > 0:
                crc_any = True
            drop_delta = d.get("rx_dropped", 0)
            if drop_delta > 0 and d.get("rx_crc_errors", 0) == 0:
                if role in ("standby", "disabled", "standby_heuristic"):
                    soft_drop_standby = True
                else:
                    soft_drop_active = True
            finding = "NO_L1_ISSUE"
            if per_iface.get(iface, {}).get("link_down") or role == "disabled":
                finding = "NIC_INACTIVE_OR_DOWN"
            elif role in ("standby", "standby_heuristic"):
                finding = "BOND_MEMBER_STANDBY_NOT_ACTIVE"
            elif d.get("rx_crc_errors", 0) > 0:
                finding = "L1_CRC_OR_LINK"
            elif drop_delta > 0:
                finding = "SOFT_RX_DROPS"
            host_nic_summary[iface] = {
                "source": "host_nic_stats_delta",
                "bond_role": role,
                **info,
                "finding": finding,
            }

    ifconfig_summary = ifconfig.get("ifaces") if ifconfig else None

    if (
        not ethtool_stats
        and not host_nic_summary
        and not ifconfig_summary
        and not bond_issues
    ):
        return _insufficient(
            "No ethtool_-S, host_nic_stats, ifconfig, or bond evidence",
            searched,
        )

    inactive_or_down = [
        i
        for i, info in per_iface.items()
        if info["finding"]
        in ("NIC_INACTIVE_OR_DOWN", "BOND_MEMBER_STANDBY_NOT_ACTIVE")
    ]
    nic_down = bool(link_down_ifaces) or any(
        info["finding"] == "NIC_INACTIVE_OR_DOWN" for info in per_iface.values()
    )
    standby_only = bool(inactive_or_down) and not nic_down

    if nic_down:
        verdict = "NIC_INACTIVE_OR_DOWN"
    elif crc_any:
        verdict = "L1_CRC_OR_LINK"
    elif soft_drop_active:
        verdict = "SOFT_RX_DROPS"
    elif any(i.get("role") == "disabled" for i in bond_issues):
        verdict = "BOND_MEMBER_DISABLED"
    elif standby_only or bond_issues:
        # active-backup standby is expected — bond class still always emitted
        verdict = "BOND_OK_STANDBY_PRESENT"
    elif soft_drop_standby:
        verdict = "STANDBY_SOFT_RX_DROPS_IGNORE_FOR_PATH"
    else:
        verdict = "NO_L1_ISSUE"

    offload_suspects = {
        iface: off.get("suspect_off")
        for iface, off in ethtool_offload.items()
        if off.get("suspect_off")
    }
    ring_warns = {
        iface: ring.get("warnings")
        for iface, ring in ethtool_ring.items()
        if ring.get("warnings")
    }

    bond_summary: dict[str, Any] = {
        "status": "OK" if bond and bond.get("bonds") else "EVIDENCE_INSUFFICIENT",
        "bonds": (bond or {}).get("bonds"),
        "issues": bond_issues,
        "note": (
            "ALWAYS analyze LAG/bond: mode, active member, each member "
            "enabled/disabled/standby. active-backup standby is normal, not RC."
        ),
    }
    if not bond or not bond.get("bonds"):
        bond_summary["reason"] = "ovs-appctl_bond_show.stdout missing"

    return _ok(
        {
            "verdict": verdict,
            "crc_rising_or_nonzero": crc_any,
            "soft_rx_drops": soft_drop_active,
            "soft_rx_drops_on_standby_only": soft_drop_standby and not soft_drop_active,
            "link_down": nic_down,
            "link_down_ifaces": link_down_ifaces,
            "inactive_or_standby_ifaces": inactive_or_down,
            "bond_lag": bond_summary,
            "bond_issues": bond_issues,
            "bond_roles": {
                "active": active_members,
                "standby": standby_members,
                "disabled": disabled_members,
                "note": "Roles come only from bond/LAG parse — never hardcode iface names",
            },
            "offload_by_iface": ethtool_offload,
            "offload_suspects": offload_suspects,
            "ring_by_iface": ethtool_ring,
            "ring_warnings": ring_warns,
            "dmesg_flaps": {
                "status": "OK" if dmesg_flaps is not None else "EVIDENCE_INSUFFICIENT",
                "n_events": (dmesg_flaps or {}).get("n_events", 0),
                "n_downs": (dmesg_flaps or {}).get("n_downs", 0),
                "recent_downs": (dmesg_flaps or {}).get("recent_downs", []),
                "by_iface": (dmesg_flaps or {}).get("by_iface", {}),
            },
            "ethtool": per_iface,
            "host_nic_stats": host_nic_summary,
            "ifconfig": ifconfig_summary,
            "drive_next": [
                "ALWAYS: ovs-appctl bond/show — mode, active member, member roles",
                "ALWAYS: ethtool -k (TSO/GSO/GRO/LRO) and ethtool -g rings",
                "ALWAYS: dmesg NIC Link Up/Down flaps per member",
                "ALWAYS: ethtool -S CRC/drops on ACTIVE member first",
                "Standby in active-backup is expected — not RC by itself",
            ],
            "note": (
                "CRC=0 is a finding. Always emit bond/LAG + offload + dmesg. "
                "Standby drops ≠ active-path loss. Linux has no LSO flag — use TSO/GSO."
            ),
        }
    )


def analyze_sar_block(sar: dict[str, Any] | None, iface: str) -> dict[str, Any]:
    if not sar:
        return _insufficient("sar.INFO missing")
    traf = sar["traf"].get(iface, [])
    err = sar["err"].get(iface, [])
    walls = sar["walls"]
    if not traf and not err:
        return _insufficient(f"No SAR IFACE rows for {iface}")

    rxpck = [r["rxpck"] for r in traf]
    txpck = [r["txpck"] for r in traf]
    rxkB = [r["rxkB"] for r in traf]
    txkB = [r["txkB"] for r in traf]
    rxdrop = [r["rxdrop"] for r in err]
    rxerr = [r["rxerr"] for r in err]
    sizes = [
        (r["rxkB"] * 1024.0) / r["rxpck"] for r in traf if r["rxpck"] > 0
    ]
    flood_n = sum(1 for v in rxpck if v > 100_000)
    drop_nz = sum(1 for v in rxdrop if v > 0)
    asym = sum(1 for r in traf if r["rxpck"] > 100_000 and r["txpck"] < 1_000)

    iface_findings = {
        "iface": iface,
        "rxpck/s": _summary(rxpck),
        "txpck/s": _summary(txpck),
        "rxkB/s": _summary(rxkB),
        "txkB/s": _summary(txkB),
        "rxdrop/s": _summary(rxdrop),
        "rxerr/s": _summary(rxerr),
        "avg_rx_pkt_bytes": _summary(sizes),
        "pct_samples_rxpck_gt_100k": 100.0 * flood_n / max(len(rxpck), 1),
        "pct_samples_rxdrop_gt_0": 100.0 * drop_nz / max(len(rxdrop), 1),
        "high_rx_low_tx_samples": asym,
    }
    softnet_flood = (
        iface_findings["pct_samples_rxpck_gt_100k"] > 20
        and (iface_findings["avg_rx_pkt_bytes"].get("p50") or 999) < 200
        and iface_findings["pct_samples_rxdrop_gt_0"] > 50
        and (iface_findings["rxerr/s"].get("max") or 0) < 0.1
    )
    return _ok(
        {
            "window": {
                "first": walls[0][1] if walls else None,
                "last": walls[-1][1] if walls else None,
                "n_timestamps": len(walls),
            },
            "iface": iface_findings,
            "softnet_flood": softnet_flood,
            "sar_rxerr_elevated": (iface_findings["rxerr/s"].get("max") or 0) >= 1.0,
        }
    )


def _parse_wall_loose(wall: str) -> float | None:
    """Best-effort epoch for overlap checks (local wall string from iostat)."""
    from datetime import datetime

    for fmt in (
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%I:%M:%S %p",
    ):
        try:
            return datetime.strptime(wall.strip(), fmt).timestamp()
        except ValueError:
            continue
    return None


def _tod_seconds(wall: str) -> float | None:
    """Seconds since midnight from a wall / TOD string (12h clock)."""
    m = WALL_TOD_RE.search(wall or "")
    if not m:
        return None
    h = int(m.group("h")) % 12
    if m.group("p").upper() == "PM":
        h += 12
    return h * 3600 + int(m.group("m")) * 60 + int(m.group("s"))


def confirm_disk_latency(
    iostat: dict[str, Any],
    dnd_times: list[str] | None = None,
    overlap_minutes: float = 15.0,
) -> dict[str, Any]:
    """Explicit SSD/disk latency confirmation (not just 'host pressure' flag).

    Thresholds (NCC-aligned intent):
      - elevated: await >= 30ms or util >= 90 or iowait >= 20
      - confirmed: await >= 100ms (w) / 50ms (r) or iowait >= 20 with hot disk
      - severe: await >= 500ms or iowait >= 40
    """
    cpu = iostat.get("cpu") or []
    disk = iostat.get("disk") or []
    if not cpu and not disk:
        return {
            "status": "EVIDENCE_INSUFFICIENT",
            "confirmed": False,
            "severity": "NONE",
            "reason": "empty iostat samples",
        }

    peak_iowait = max((c["iowait"] for c in cpu), default=0.0)
    peak_iowait_row = max(cpu, key=lambda c: c["iowait"]) if cpu else None
    peak_w = max((d["w_await"] for d in disk), default=0.0)
    peak_r = max((d["r_await"] for d in disk), default=0.0)
    peak_util = max((d["util"] for d in disk), default=0.0)
    peak_disk = (
        max(disk, key=lambda d: max(d["w_await"], d["r_await"], d["util"]))
        if disk
        else None
    )

    if peak_w >= 500 or peak_r >= 500 or peak_iowait >= 40:
        severity = "SEVERE"
        confirmed = True
    elif peak_w >= 100 or peak_r >= 50 or (
        peak_iowait >= 20 and (peak_util >= 90 or peak_w >= 30 or peak_r >= 30)
    ):
        severity = "CONFIRMED"
        confirmed = True
    elif peak_w >= 30 or peak_r >= 30 or peak_util >= 90 or peak_iowait >= 20:
        severity = "ELEVATED"
        confirmed = False
    else:
        severity = "NONE"
        confirmed = False

    overlap: dict[str, Any] = {
        "checked": bool(dnd_times),
        "overlap": False,
        "dnd_times": dnd_times or [],
        "matched": [],
    }
    if dnd_times and peak_disk:
        peak_ts = _parse_wall_loose(peak_disk["wall"])
        if peak_iowait_row:
            iow_ts = _parse_wall_loose(peak_iowait_row["wall"])
        else:
            iow_ts = None
        window_s = overlap_minutes * 60.0
        for raw in dnd_times:
            cleaned = raw.strip().replace("Z", "")
            if "T" in cleaned and cleaned.count("-") >= 2:
                cleaned = cleaned.replace("T", " ")[:19]
            dts = _parse_wall_loose(cleaned)
            if dts is None:
                continue
            for label, ts in (("peak_disk", peak_ts), ("peak_iowait", iow_ts)):
                if ts is not None and abs(ts - dts) <= window_s:
                    overlap["overlap"] = True
                    overlap["matched"].append(
                        {"dnd": raw, "signal": label, "delta_sec": abs(ts - dts)}
                    )

    return {
        "status": "OK",
        "confirmed": confirmed,
        "severity": severity,
        "verdict": (
            "SSD_DISK_LATENCY_CONFIRMED"
            if confirmed
            else (
                "SSD_DISK_LATENCY_ELEVATED"
                if severity == "ELEVATED"
                else "NO_SSD_DISK_LATENCY"
            )
        ),
        "thresholds": {
            "elevated_await_ms": 30,
            "confirmed_w_await_ms": 100,
            "confirmed_r_await_ms": 50,
            "severe_await_ms": 500,
            "iowait_confirmed_pct": 20,
            "iowait_severe_pct": 40,
            "util_pct": 90,
        },
        "peaks": {
            "iowait_pct": peak_iowait,
            "iowait_wall": peak_iowait_row["wall"] if peak_iowait_row else None,
            "w_await_ms": peak_w,
            "r_await_ms": peak_r,
            "util_pct": peak_util,
            "disk": peak_disk["dev"] if peak_disk else None,
            "disk_wall": peak_disk["wall"] if peak_disk else None,
        },
        "dnd_overlap": overlap,
        "note": (
            "This confirms *disk/SSD IO latency* from iostat, not network RTT. "
            "Pass --dnd-time to require ±15m overlap with DND/peer-score events."
        ),
    }


def analyze_storage(
    iostat: dict[str, Any] | None,
    dnd_times: list[str] | None = None,
) -> dict[str, Any]:
    if not iostat:
        return _insufficient("iostat.INFO missing")
    cpu_hot = sorted(iostat["cpu"], key=lambda r: r["iowait"], reverse=True)[:5]
    disk_hot = sorted(
        [
            d
            for d in iostat["disk"]
            if d["util"] >= 90 or d["r_await"] >= 30 or d["w_await"] >= 30
        ],
        key=lambda d: max(d["util"], d["r_await"], d["w_await"]),
        reverse=True,
    )[:10]
    latency = confirm_disk_latency(iostat, dnd_times=dnd_times)
    host_storage = bool(latency.get("confirmed")) or bool(
        cpu_hot and cpu_hot[0]["iowait"] >= 20
    ) or bool(
        disk_hot
        and (
            disk_hot[0]["util"] >= 90
            or disk_hot[0]["w_await"] >= 100
            or disk_hot[0]["r_await"] >= 50
        )
    )
    return _ok(
        {
            "host_storage_pressure": host_storage,
            "latency_confirmation": latency,
            "cpu_top_iowait": cpu_hot,
            "disk_hot_top": disk_hot,
            "hot_disk_counts": dict(Counter(d["dev"] for d in disk_hot)),
        }
    )


def analyze_path(ping: dict[str, Any] | None) -> dict[str, Any]:
    if not ping:
        return _insufficient("ping_all/ping_remotes missing")
    return _ok(ping)


def classify(
    l1: dict[str, Any],
    sar_b: dict[str, Any],
    storage: dict[str, Any],
    path: dict[str, Any],
    flood: dict[str, Any] | None = None,
    corr: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    contributors: list[str] = []
    primary = "INCONCLUSIVE"

    lat = (storage or {}).get("latency_confirmation") or {}
    latency_confirmed = storage.get("status") == "OK" and bool(lat.get("confirmed"))
    latency_severe = lat.get("severity") in ("CONFIRMED", "SEVERE")

    flood_confirmed = bool(flood and flood.get("confirmed"))
    ping_flood_corr = bool(corr and corr.get("correlated"))

    # Fabric RX flood correlated with ping loss is the network RCA for this pattern
    if flood_confirmed:
        contributors.append("EXTERNAL_RX_FLOOD")
        if flood.get("standby_rx_flood"):
            contributors.append("STANDBY_MEMBER_RX_FLOOD")
        primary = "EXTERNAL_RX_FLOOD"
    if ping_flood_corr:
        contributors.append("PING_LOSS_CORRELATES_WITH_RX_FLOOD")
        primary = "EXTERNAL_RX_FLOOD"

    if latency_confirmed or (
        storage.get("status") == "OK" and storage.get("host_storage_pressure")
    ):
        contributors.append("HOST_STORAGE_PRESSURE")
        if latency_confirmed:
            contributors.append("SSD_DISK_LATENCY_CONFIRMED")
        if primary == "INCONCLUSIVE":
            primary = "HOST_STORAGE_PRESSURE"

    if sar_b.get("status") == "OK" and sar_b.get("softnet_flood"):
        contributors.append("SOFTNET_FLOOD")
        if primary == "INCONCLUSIVE":
            primary = "SOFTNET_FLOOD"

    if l1.get("status") == "OK":
        bl = l1.get("bond_lag") or {}
        if bl.get("status") == "OK" and bl.get("bonds"):
            has_standby = any(
                mi.get("role") == "standby"
                for b in bl["bonds"].values()
                for mi in (b.get("members") or {}).values()
            )
            if has_standby:
                contributors.append("BOND_OK_STANDBY_PRESENT")
            else:
                contributors.append("BOND_LAG_PARSED")

        v = l1.get("verdict")
        if v == "NIC_INACTIVE_OR_DOWN":
            contributors.append("NIC_INACTIVE_OR_DOWN")
            if primary == "INCONCLUSIVE":
                primary = "NIC_INACTIVE_OR_DOWN"
        elif v == "L1_CRC_OR_LINK":
            contributors.append("L1_CRC_OR_LINK")
            if primary == "INCONCLUSIVE":
                primary = "L1_CRC_OR_LINK"
        elif v == "SOFT_RX_DROPS":
            contributors.append("SOFT_RX_DROPS")
            if primary == "INCONCLUSIVE":
                primary = "SOFT_RX_DROPS"
        elif v == "STANDBY_SOFT_RX_DROPS_IGNORE_FOR_PATH":
            contributors.append("STANDBY_SOFT_RX_DROPS_IGNORED")

    if path.get("status") == "OK" and (
        path.get("fail_hit_count_capped", 0) > 0
        or path.get("fail_event_count", 0) > 0
    ):
        contributors.append("PATH_EDGE_OR_PEER_LOSS")
        if primary == "INCONCLUSIVE":
            primary = "PATH_EDGE"

    # Ping↔flood correlation beats storage as the *network* root cause narrative
    if ping_flood_corr:
        primary = "EXTERNAL_RX_FLOOD"
        if latency_confirmed:
            contributors.append("HOST_STORAGE_ALSO_PRESENT")
    elif flood_confirmed and not latency_confirmed:
        primary = "EXTERNAL_RX_FLOOD"
    elif latency_confirmed and not ping_flood_corr:
        primary = "HOST_STORAGE_PRESSURE"

    return primary, sorted(set(contributors))


def build_report(
    *,
    iface: str,
    sources: dict[str, Any],
    l1: dict[str, Any],
    sar_b: dict[str, Any],
    storage: dict[str, Any],
    path: dict[str, Any],
    flood: dict[str, Any] | None = None,
    corr: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root, contributors = classify(l1, sar_b, storage, path, flood=flood, corr=corr)
    evidence: list[str] = []

    if flood and flood.get("status") == "OK":
        evidence.append(
            f"RX flood: verdict={flood.get('verdict')} confirmed={flood.get('confirmed')} "
            f"standby_rx_flood={flood.get('standby_rx_flood')} "
            f"multi_iface={flood.get('multi_iface_flood')} "
            f"n_windows={flood.get('n_flood_windows')}"
        )
        for w in (flood.get("top_windows") or [])[:3]:
            evidence.append(
                f"  flood@{w['wall']} max_rxpck={w['max_rxpck']:.0f} "
                f"ifaces={[h['iface']+':'+str(int(h['rxpck'])) for h in w['hot']]}"
            )
    if corr and corr.get("status") == "OK":
        evidence.append(
            f"Ping↔flood: {corr.get('verdict')} correlated={corr.get('correlated')} "
            f"matches={corr.get('n_matches')}"
        )
        for m in (corr.get("matches") or [])[:3]:
            evidence.append(
                f"  match ping={m.get('ping_wall') or m.get('ping_wall')} "
                f"flood={m.get('flood_wall') or m.get('flood_wall')} "
                f"Δ={m.get('delta_sec', m.get('delta_sec', 0)):.0f}s "
                f"max_rx={m.get('max_rxpck', m.get('max_rxpck', 0)):.0f}"
            )

    if l1.get("status") == "OK":
        evidence.append(
            f"L1 verdict={l1['verdict']}; crc_nonzero={l1.get('crc_rising_or_nonzero')}; "
            f"soft_rx_drops_active={l1.get('soft_rx_drops')}; "
            f"standby_ifaces={l1.get('inactive_or_standby_ifaces')}"
        )
        bl = l1.get("bond_lag") or {}
        if bl.get("bonds"):
            for bn, b in bl["bonds"].items():
                mems = ", ".join(
                    f"{m}:{mi.get('role')}"
                    for m, mi in (b.get("members") or {}).items()
                )
                evidence.append(
                    f"BOND/LAG {bn}: mode={b.get('mode')} "
                    f"active={b.get('active_member')} members={{{mems}}}"
                )
        else:
            evidence.append(f"BOND/LAG: {bl.get('status')} {bl.get('reason', '')}")
        df = l1.get("dmesg_flaps") or {}
        evidence.append(
            f"dmesg NIC flaps: status={df.get('status')} downs={df.get('n_downs')} "
            f"events={df.get('n_events')}"
        )
        if l1.get("offload_suspects"):
            evidence.append(f"offload suspects (TSO/GSO/GRO.. off): {l1['offload_suspects']}")
        else:
            evidence.append("offload: no unexpected TSO/GSO/GRO/checksum offs on parsed ifaces")
        if l1.get("ring_warnings"):
            evidence.append(f"ring warnings: {l1['ring_warnings']}")
        for name, info in (l1.get("ethtool") or {}).items():
            off = (info.get("offload") or {}).get("features") or {}
            evidence.append(
                f"{name} role={info.get('bond_role')} link_down={info.get('link_down')} "
                f"crc={info.get('rx_crc_errors')} rx_drop={info.get('rx_dropped')} "
                f"tso={off.get('tso')} gso={off.get('gso')} gro={off.get('gro')} "
                f"lro={off.get('lro')} finding={info.get('finding')}"
            )
        for name, info in (l1.get("host_nic_stats") or {}).items():
            d = info["delta"]
            evidence.append(
                f"host_nic_stats {name} role={info.get('bond_role')} delta "
                f"{info['first_wall']}→{info['last_wall']}: "
                f"crc={d.get('rx_crc_errors', 0)} "
                f"rx_drop={d.get('rx_dropped', 0)}"
            )
    else:
        evidence.append(f"L1: {l1.get('reason')}")

    if sar_b.get("status") == "OK":
        f = sar_b["iface"]
        evidence.append(
            f"SAR {iface} rxpck avg={f['rxpck/s'].get('avg', 0):.0f} "
            f"max={f['rxpck/s'].get('max', 0):.0f}; "
            f"rxdrop>0 {f['pct_samples_rxdrop_gt_0']:.1f}%; "
            f"rxerr max={f['rxerr/s'].get('max', 0):.2f}"
        )
    else:
        evidence.append(f"SAR: {sar_b.get('reason')}")

    if storage.get("status") == "OK":
        lat = storage.get("latency_confirmation") or {}
        evidence.append(
            f"Latency confirmation: {lat.get('verdict')} "
            f"severity={lat.get('severity')} confirmed={lat.get('confirmed')} "
            f"peaks={lat.get('peaks')}"
        )
        if (lat.get("dnd_overlap") or {}).get("checked"):
            evidence.append(
                f"DND↔latency overlap={lat['dnd_overlap'].get('overlap')} "
                f"matched={lat['dnd_overlap'].get('matched')}"
            )
        if storage.get("cpu_top_iowait"):
            c0 = storage["cpu_top_iowait"][0]
            evidence.append(
                f"Peak iowait {c0['iowait']:.1f}% at {c0['wall']}"
            )
        if storage.get("disk_hot_top"):
            d0 = storage["disk_hot_top"][0]
            evidence.append(
                f"Hot disk {d0['dev']} util={d0['util']:.1f}% "
                f"r_await={d0['r_await']:.1f} w_await={d0['w_await']:.1f} "
                f"at {d0['wall']}"
            )
    else:
        evidence.append(f"Storage: {storage.get('reason')}")

    if path.get("status") == "OK":
        evidence.append(
            f"Ping fail events={path.get('fail_event_count', 0)} "
            f"samples_capped={path.get('fail_hit_count_capped', 0)}"
        )
        for s in (path.get("sample_fails") or [])[:8]:
            evidence.append(f"  ping: {s}")
    else:
        evidence.append(f"Path: {path.get('reason')}")

    classes = {
        "L1_CRC": l1,
        "NIC_ERRORS": l1,
        "DROPS": l1,
        "LINK": l1,
        "BOND_LAG": (l1 or {}).get("bond_lag")
        or _insufficient("bond/LAG not evaluated"),
        "OFFLOAD_TSO_GRO": {
            "status": "OK" if (l1 or {}).get("offload_by_iface") else "EVIDENCE_INSUFFICIENT",
            "by_iface": (l1 or {}).get("offload_by_iface"),
            "suspects": (l1 or {}).get("offload_suspects"),
            "note": "TSO/GSO/GRO/LRO (+ checksum). Linux has no LSO — use tso/gso.",
        },
        "RING": {
            "status": "OK" if (l1 or {}).get("ring_by_iface") else "EVIDENCE_INSUFFICIENT",
            "by_iface": (l1 or {}).get("ring_by_iface"),
            "warnings": (l1 or {}).get("ring_warnings"),
        },
        "DMESG_NIC": (l1 or {}).get("dmesg_flaps")
        or _insufficient("dmesg not evaluated"),
        "TRAFFIC_SAR": sar_b,
        "EXTERNAL_RX_FLOOD": flood or _insufficient("flood not evaluated"),
        "PING_FLOOD_CORRELATION": corr or _insufficient("correlation not evaluated"),
        "HOST_PRESSURE": storage,
        "SSD_DISK_LATENCY": (storage or {}).get("latency_confirmation")
        or _insufficient("latency not evaluated"),
        "PATH_PING": path,
    }

    sentence = None
    if root == "EXTERNAL_RX_FLOOD" or "PING_LOSS_CORRELATES_WITH_RX_FLOOD" in contributors:
        sentence = (
            "Diamond/logbay evidence: external/fabric RX flood (high rxpck/s on bond "
            "members; standby often high RX with ~0 TX) time-correlates with ping "
            "LOST_PKT/unreachable — peer/Cassandra timeouts are a consequence of that "
            "path loss (CRC may still be 0; soft rx_dropped may rise)"
        )
    elif "SSD_DISK_LATENCY_CONFIRMED" in contributors:
        sentence = (
            "Confirmed disk/SSD IO latency starved CVM/Cassandra → peer timeouts "
            "→ DND/Forwarding"
        )
    elif "NIC_INACTIVE_OR_DOWN" in contributors:
        sentence = "Bond/NIC member down or link-down on host datapath"
    elif root == "HOST_STORAGE_PRESSURE":
        sentence = "Host storage pressure overlapping network/DND symptoms"

    return {
        "skill": "network-sar-debugging",
        "root_class": root,
        "root_cause_sentence": sentence,
        "contributors": contributors,
        "classes": classes,
        "sources": {
            k: (str(v) if isinstance(v, Path) else v)
            for k, v in sources.items()
            if k != "ethtool_dirs"
        }
        | {"ethtool_dirs": [str(p) for p in sources.get("ethtool_dirs") or []]},
        "evidence": evidence,
        "coverage_notes": [
            "Every class above must be OK or EVIDENCE_INSUFFICIENT — never skipped",
            "CRC=0 is a finding; do not equate rx_dropped with CRC",
            "Always correlate ping fails with SAR RX flood windows from the bundle",
            "Never hardcode NIC names — discover from bond/LAG",
            "Do not emit trunk/VLAN/stop-source remediations — not present in diamond logs",
            "SAR may start after first DND — do not treat file start as trigger",
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bundle-root", type=Path, default=None)
    ap.add_argument("--sar", type=Path, default=None)
    ap.add_argument("--iostat", type=Path, default=None)
    ap.add_argument("--host-nic-stats", type=Path, default=None)
    ap.add_argument("--ethtool-dir", type=Path, action="append", default=[])
    ap.add_argument("--ifconfig", type=Path, default=None)
    ap.add_argument("--bond-show", type=Path, default=None)
    ap.add_argument("--dmesg", type=Path, default=None)
    ap.add_argument("--ip-addr", type=Path, default=None)
    ap.add_argument("--ping", type=Path, default=None)
    ap.add_argument("--iface", default="eth0", help="CVM SAR iface (usually eth0)")
    ap.add_argument(
        "--dnd-time",
        action="append",
        default=[],
        help="DND / peer-score wall time for latency overlap (repeatable). "
        "Examples: '08/31/2026 07:07:16 PM' or '2026-08-31 19:07:16'",
    )
    args = ap.parse_args()

    bond_path = None
    dmesg_path = None
    ip_addr_path = None

    if args.bundle_root:
        disc = discover_bundle(args.bundle_root)
        sar_path = args.sar or disc["sar"]
        iostat_path = args.iostat or disc["iostat"]
        hns_path = args.host_nic_stats or disc["host_nic_stats"]
        ethtool_dirs = args.ethtool_dir or disc["ethtool_dirs"]
        ifconfig_path = args.ifconfig or disc["ifconfig"]
        bond_path = args.bond_show or disc.get("bond_show")
        dmesg_path = args.dmesg or disc.get("dmesg")
        ip_addr_path = args.ip_addr or disc.get("ip_addr")
        ping_path = args.ping or disc["ping_all"] or disc["ping_remotes"]
        sources = {
            "mode": "bundle-root",
            "bundle_root": args.bundle_root,
            "sar": sar_path,
            "iostat": iostat_path,
            "host_nic_stats": hns_path,
            "ifconfig": ifconfig_path,
            "bond_show": bond_path,
            "dmesg": dmesg_path,
            "ip_addr": ip_addr_path,
            "ping": ping_path,
            "ethtool_dirs": ethtool_dirs,
        }
    else:
        if not args.sar:
            ap.error("--sar is required unless --bundle-root is set")
        sar_path = args.sar
        iostat_path = args.iostat
        hns_path = args.host_nic_stats
        ethtool_dirs = args.ethtool_dir
        ifconfig_path = args.ifconfig
        bond_path = args.bond_show
        dmesg_path = args.dmesg
        ip_addr_path = args.ip_addr
        ping_path = args.ping
        sources = {
            "mode": "explicit",
            "sar": sar_path,
            "iostat": iostat_path,
            "host_nic_stats": hns_path,
            "ifconfig": ifconfig_path,
            "bond_show": bond_path,
            "dmesg": dmesg_path,
            "ip_addr": ip_addr_path,
            "ping": ping_path,
            "ethtool_dirs": ethtool_dirs,
        }

    sar = parse_sar(sar_path, None) if sar_path and sar_path.exists() else None
    iostat = (
        parse_iostat(iostat_path)
        if iostat_path and iostat_path.exists()
        else None
    )
    host_nic = (
        parse_host_nic_stats(hns_path)
        if hns_path and hns_path.exists()
        else None
    )
    ifconfig = (
        parse_ifconfig(ifconfig_path)
        if ifconfig_path and ifconfig_path.exists()
        else None
    )
    bond = (
        parse_bond_show(bond_path)
        if bond_path and Path(bond_path).exists()
        else None
    )
    dmesg_flaps = (
        parse_dmesg_nic_flaps(dmesg_path)
        if dmesg_path and Path(dmesg_path).exists()
        else None
    )
    ip_link = (
        parse_ip_link_roles(ip_addr_path)
        if ip_addr_path and Path(ip_addr_path).exists()
        else None
    )
    ping = parse_ping(ping_path) if ping_path and ping_path.exists() else None

    l1 = analyze_l1(
        ethtool_dirs or [],
        host_nic,
        ifconfig,
        bond=bond,
        dmesg_flaps=dmesg_flaps,
        ip_link=ip_link,
    )
    sar_b = analyze_sar_block(sar, args.iface)
    roles = (l1.get("bond_roles") or {}) if l1.get("status") == "OK" else {}
    role_map: dict[str, str] = {}
    for rname in ("active", "standby", "disabled"):
        for iface_name in roles.get(rname) or []:
            role_map[iface_name] = rname
    # Also apply roles from bond_lag members
    bl = (l1.get("bond_lag") or {}).get("bonds") or {}
    for b in bl.values():
        for m, mi in (b.get("members") or {}).items():
            role_map[m] = mi.get("role") or role_map.get(m, "unknown")

    flood = detect_rx_flood(sar, bond_roles=role_map) if sar else _insufficient(
        "sar missing for flood detect"
    )
    path = analyze_path(ping)
    corr = correlate_ping_flood(
        path if path.get("status") == "OK" else ping,
        flood if flood.get("status") == "OK" else None,
    )
    storage = analyze_storage(iostat, dnd_times=args.dnd_time or None)

    report = build_report(
        iface=args.iface,
        sources=sources,
        l1=l1,
        sar_b=sar_b,
        storage=storage,
        path=path,
        flood=flood,
        corr=corr,
    )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
