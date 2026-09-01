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
            if not mode:
                continue
            parsed = _parse_iface_line(line.split())
            if not parsed:
                continue
            iface, nums = parsed
            if iface_filter and iface != iface_filter:
                continue
            if mode == "traf" and len(nums) >= 8:
                traf[iface].append(
                    {
                        "ts": float(cur_ts),
                        "rxpck": nums[0],
                        "txpck": nums[1],
                        "rxkB": nums[2],
                        "txkB": nums[3],
                        "ifutil": nums[7],
                        "wall": cur_wall,
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
                        "wall": cur_wall,
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


def parse_ping(path: Path, max_hits: int = 30) -> dict[str, Any]:
    hits: list[str] = []
    with path.open(errors="ignore") as fh:
        for line in fh:
            if PING_FAIL_RE.search(line):
                hits.append(line.strip()[:240])
                if len(hits) >= max_hits:
                    break
    return {"fail_hit_count_capped": len(hits), "sample_fails": hits}


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


def analyze_l1(
    ethtool_dirs: list[Path],
    host_nic: dict[str, Any] | None,
    ifconfig: dict[str, Any] | None,
) -> dict[str, Any]:
    """Mandatory L1/CRC/drops/link class."""
    ethtool_stats: dict[str, Any] = {}
    ethtool_link: dict[str, Any] = {}
    searched: list[str] = []

    for d in ethtool_dirs:
        searched.append(str(d))
        for stats_path in sorted(d.glob("ethtool_--statistics_*.stdout")):
            # ethtool_--statistics_eth1.stdout
            name = stats_path.name.replace("ethtool_--statistics_", "").replace(
                ".stdout", ""
            )
            ethtool_stats[name] = parse_ethtool_stats(stats_path)
        for link_path in sorted(d.glob("ethtool_eth*.stdout")):
            if "--" in link_path.name:
                continue
            name = link_path.name.replace("ethtool_", "").replace(".stdout", "")
            ethtool_link[name] = parse_ethtool_link(link_path)

    crc_any = False
    soft_drop_any = False
    link_down = False
    per_iface: dict[str, Any] = {}

    for iface, st in ethtool_stats.items():
        crc = st.get("rx_crc_errors", 0)
        dropped = st.get("rx_dropped", 0)
        length = st.get("rx_length_errors", 0)
        frame = st.get("rx_frame_errors", 0)
        collisions = st.get("collisions", 0)
        rx_err = st.get("rx_errors", 0)
        if crc > 0 or length > 0 or frame > 0 or collisions > 0:
            crc_any = True
        if dropped > 0 and crc == 0:
            soft_drop_any = True
        link = ethtool_link.get(iface, {})
        if link.get("link_detected") is False:
            link_down = True
        per_iface[iface] = {
            "source": "ethtool_-S",
            "rx_crc_errors": crc,
            "rx_length_errors": length,
            "rx_frame_errors": frame,
            "rx_errors": rx_err,
            "rx_dropped": dropped,
            "tx_dropped": st.get("tx_dropped", 0),
            "collisions": collisions,
            "link": link,
            "finding": (
                "L1_CRC_OR_LINK"
                if crc or length or frame or collisions or link.get("link_detected") is False
                else ("SOFT_RX_DROPS" if dropped > 1000 else "NO_L1_ISSUE")
            ),
        }

    host_nic_summary: dict[str, Any] | None = None
    if host_nic and host_nic.get("ifaces"):
        host_nic_summary = {}
        for iface, info in host_nic["ifaces"].items():
            d = info["delta"]
            if d.get("rx_crc_errors", 0) > 0:
                crc_any = True
            if d.get("rx_dropped", 0) > 0 and d.get("rx_crc_errors", 0) == 0:
                soft_drop_any = True
            host_nic_summary[iface] = {
                "source": "host_nic_stats_delta",
                **info,
                "finding": (
                    "L1_CRC_OR_LINK"
                    if d.get("rx_crc_errors", 0) > 0
                    or d.get("rx_length_errors", 0) > 0
                    or d.get("collisions", 0) > 0
                    else (
                        "SOFT_RX_DROPS"
                        if d.get("rx_dropped", 0) > 0
                        else "NO_L1_ISSUE"
                    )
                ),
            }

    ifconfig_summary = ifconfig.get("ifaces") if ifconfig else None

    if not ethtool_stats and not host_nic_summary and not ifconfig_summary:
        return _insufficient(
            "No ethtool_-S, host_nic_stats, or ifconfig evidence",
            searched,
        )

    verdict = "NO_L1_ISSUE"
    if crc_any or link_down:
        verdict = "L1_CRC_OR_LINK"
    elif soft_drop_any:
        verdict = "SOFT_RX_DROPS"

    return _ok(
        {
            "verdict": verdict,
            "crc_rising_or_nonzero": crc_any,
            "soft_rx_drops": soft_drop_any,
            "link_down": link_down,
            "ethtool": per_iface,
            "host_nic_stats": host_nic_summary,
            "ifconfig": ifconfig_summary,
            "note": (
                "CRC=0 with large rx_dropped is SOFT_RX_DROPS, not L1_CRC. "
                "Always report CRC explicitly."
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


def analyze_storage(iostat: dict[str, Any] | None) -> dict[str, Any]:
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
    host_storage = bool(cpu_hot and cpu_hot[0]["iowait"] >= 20) or bool(
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
) -> tuple[str, list[str]]:
    contributors: list[str] = []
    primary = "INCONCLUSIVE"

    if storage.get("status") == "OK" and storage.get("host_storage_pressure"):
        contributors.append("HOST_STORAGE_PRESSURE")
        primary = "HOST_STORAGE_PRESSURE"

    if sar_b.get("status") == "OK" and sar_b.get("softnet_flood"):
        contributors.append("SOFTNET_FLOOD")
        if primary == "INCONCLUSIVE":
            primary = "SOFTNET_FLOOD"

    if l1.get("status") == "OK":
        v = l1.get("verdict")
        if v == "L1_CRC_OR_LINK":
            contributors.append("L1_CRC_OR_LINK")
            primary = "L1_CRC_OR_LINK"
        elif v == "SOFT_RX_DROPS":
            contributors.append("SOFT_RX_DROPS")
            if primary in ("INCONCLUSIVE", "SOFTNET_FLOOD"):
                primary = "SOFT_RX_DROPS"

    if path.get("status") == "OK" and path.get("fail_hit_count_capped", 0) > 0:
        contributors.append("PATH_EDGE_OR_PEER_LOSS")
        if primary == "INCONCLUSIVE":
            primary = "PATH_EDGE"

    # Prefer storage as primary when it coexists with soft drops (DND driver)
    if (
        "HOST_STORAGE_PRESSURE" in contributors
        and ("SOFT_RX_DROPS" in contributors or "SOFTNET_FLOOD" in contributors)
    ):
        primary = "MIXED"

    if len(set(contributors)) > 1 and primary != "MIXED":
        if "HOST_STORAGE_PRESSURE" in contributors and primary != "L1_CRC_OR_LINK":
            primary = "MIXED"

    return primary, sorted(set(contributors))


def build_report(
    *,
    iface: str,
    sources: dict[str, Any],
    l1: dict[str, Any],
    sar_b: dict[str, Any],
    storage: dict[str, Any],
    path: dict[str, Any],
) -> dict[str, Any]:
    root, contributors = classify(l1, sar_b, storage, path)
    evidence: list[str] = []

    if l1.get("status") == "OK":
        evidence.append(
            f"L1 verdict={l1['verdict']}; crc_nonzero={l1.get('crc_rising_or_nonzero')}; "
            f"soft_rx_drops={l1.get('soft_rx_drops')}"
        )
        for name, info in (l1.get("ethtool") or {}).items():
            evidence.append(
                f"ethtool {name}: crc={info['rx_crc_errors']} "
                f"rx_err={info['rx_errors']} rx_drop={info['rx_dropped']} "
                f"link={info.get('link')}"
            )
        for name, info in (l1.get("host_nic_stats") or {}).items():
            d = info["delta"]
            evidence.append(
                f"host_nic_stats {name} delta "
                f"{info['first_wall']}→{info['last_wall']}: "
                f"crc={d.get('rx_crc_errors', 0)} "
                f"rx_err={d.get('rx_errors', 0)} "
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
            f"Ping fail samples (capped)={path.get('fail_hit_count_capped', 0)}"
        )
    else:
        evidence.append(f"Path: {path.get('reason')}")

    # Mandatory class map — never omit keys
    classes = {
        "L1_CRC": l1,
        "NIC_ERRORS": l1,
        "DROPS": l1,
        "LINK": l1,
        "TRAFFIC_SAR": sar_b,
        "HOST_PRESSURE": storage,
        "PATH_PING": path,
    }

    return {
        "skill": "network-sar-debugging",
        "root_class": root,
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
    ap.add_argument("--ping", type=Path, default=None)
    ap.add_argument("--iface", default="eth0", help="CVM SAR iface (usually eth0)")
    args = ap.parse_args()

    if args.bundle_root:
        disc = discover_bundle(args.bundle_root)
        sar_path = args.sar or disc["sar"]
        iostat_path = args.iostat or disc["iostat"]
        hns_path = args.host_nic_stats or disc["host_nic_stats"]
        ethtool_dirs = args.ethtool_dir or disc["ethtool_dirs"]
        ifconfig_path = args.ifconfig or disc["ifconfig"]
        ping_path = args.ping or disc["ping_all"] or disc["ping_remotes"]
        sources = {
            "mode": "bundle-root",
            "bundle_root": args.bundle_root,
            "sar": sar_path,
            "iostat": iostat_path,
            "host_nic_stats": hns_path,
            "ifconfig": ifconfig_path,
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
        ping_path = args.ping
        sources = {
            "mode": "explicit",
            "sar": sar_path,
            "iostat": iostat_path,
            "host_nic_stats": hns_path,
            "ifconfig": ifconfig_path,
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
    ping = parse_ping(ping_path) if ping_path and ping_path.exists() else None

    l1 = analyze_l1(ethtool_dirs or [], host_nic, ifconfig)
    sar_b = analyze_sar_block(sar, args.iface)
    storage = analyze_storage(iostat)
    path = analyze_path(ping)

    report = build_report(
        iface=args.iface,
        sources=sources,
        l1=l1,
        sar_b=sar_b,
        storage=storage,
        path=path,
    )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
