#!/usr/bin/env python3
"""Parse Nutanix/sysstat SAR text day files into InfluxDB 2.x."""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import urllib.request

LINUX_RE = re.compile(
    r"^Linux\s+\S+\s+\(([^)]+)\)\s+(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})"
)
# 24h "HH:MM:SS" or 12h "HH:MM:SS AM/PM"
TIME_RE = re.compile(
    r"^(\d{1,2}:\d{2}:\d{2})(?:\s+(AM|PM))?", re.IGNORECASE
)

INFLUX_URL = os.environ.get("INFLUX_URL", "http://influxdb:8086").rstrip("/")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "sar-admin-token-change-me")
INFLUX_ORG = os.environ.get("INFLUX_ORG", "sar")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sar")
SAR_DIR = Path(os.environ.get("SAR_DIR", "/sar"))
BATCH = int(os.environ.get("WRITE_BATCH", "4000"))


def wait_influx(timeout: int = 120) -> None:
    url = f"{INFLUX_URL}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    print("InfluxDB healthy", flush=True)
                    return
        except Exception as exc:
            print(f"waiting for InfluxDB: {exc}", flush=True)
        time.sleep(2)
    raise RuntimeError("InfluxDB not healthy in time")


def parse_date(s: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def classify(cols: List[str]) -> Optional[Tuple[str, str, List[str]]]:
    low = [c.lower() for c in cols]
    if "cpu" in low and ("%usr" in low or "%user" in low):
        # Normalize metric names so CVM (%usr/%sys) and AHV (%user/%system) share fields
        metrics = []
        for c in cols[1:]:
            cl = c.lower()
            if cl == "%user":
                metrics.append("%usr")
            elif cl == "%system":
                metrics.append("%sys")
            else:
                metrics.append(c)
        return "sar_cpu", "cpu", metrics
    if "iface" in low and "rxpck/s" in low:
        return "sar_net_dev", "iface", cols[1:]
    if "iface" in low and "rxerr/s" in low:
        return "sar_net_edev", "iface", cols[1:]
    if "kbmemfree" in low or "kbmemused" in low:
        return "sar_mem", "host", cols[:]
    if low and low[0] == "dev" and "tps" in low:
        return "sar_disk", "dev", cols[1:]
    if "runq-sz" in low or "ldavg-1" in low:
        return "sar_load", "host", cols[:]
    if "proc/s" in low and "cswch/s" in low:
        return "sar_task", "host", cols[:]
    if "pgpgin/s" in low:
        return "sar_paging", "host", cols[:]
    return None


def parse_row_time(parts: List[str]) -> Optional[Tuple[str, List[str]]]:
    """Return (HH:MM:SS 24h, remaining tokens) or None."""
    if not parts:
        return None
    m = TIME_RE.match(parts[0])
    if not m:
        return None
    # Case A: "12:00:10" "AM" "all" ...
    if len(parts) > 1 and parts[1].upper() in ("AM", "PM"):
        ampm = parts[1].upper()
        rest = parts[2:]
        hh, mm, ss = map(int, parts[0].split(":"))
    # Case B: TIME_RE captured AM/PM on same token (unlikely with split)
    elif m.group(2):
        ampm = m.group(2).upper()
        rest = parts[1:]
        hh, mm, ss = map(int, m.group(1).split(":"))
    else:
        # plain 24h
        return parts[0], parts[1:]

    if ampm == "AM":
        if hh == 12:
            hh = 0
    else:  # PM
        if hh != 12:
            hh += 12
    return f"{hh:02d}:{mm:02d}:{ss:02d}", rest


def esc_tag(v: str) -> str:
    return v.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def esc_field_key(v: str) -> str:
    return (
        v.replace("%", "pct_")
        .replace("/", "_")
        .replace("-", "_")
        .replace(".", "_")
    )


def to_float(tok: str) -> Optional[float]:
    try:
        return float(tok)
    except ValueError:
        return None


def role_from_source(source: str, text: str) -> str:
    """Prefer # SAR_ROLE header, then filename markers, else cvm."""
    for raw in text.splitlines()[:20]:
        if raw.startswith("# SAR_ROLE"):
            parts = raw.split()
            if len(parts) >= 3:
                return parts[2].strip().lower()
    base = Path(source).name.lower()
    if "__ahv__" in base or base.startswith("ahv-"):
        return "ahv"
    if "__cvm__" in base or "-cvm" in base:
        return "cvm"
    return "cvm"


def lines_from_text(text: str, source: str) -> Iterable[str]:
    hostname = "unknown"
    day: Optional[datetime] = None
    section: Optional[str] = None
    key_field = "host"
    metrics: List[str] = []
    role = role_from_source(source, text)

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("Average"):
            continue
        if line.startswith("#"):
            if line.startswith("# SAR_ROLE"):
                parts = line.split()
                if len(parts) >= 3:
                    role = parts[2].strip().lower()
            continue

        m = LINUX_RE.match(line)
        if m:
            hostname = m.group(1)
            day = parse_date(m.group(2))
            section = None
            metrics = []
            continue

        parts = line.split()
        parsed = parse_row_time(parts)
        if parsed is None:
            classified = classify(parts)
            if classified:
                section, key_field, metrics = classified
            continue

        tstr, rest = parsed
        classified = classify(rest)
        if classified:
            section, key_field, metrics = classified
            continue

        if not section or not metrics or day is None:
            continue

        try:
            hh, mm, ss = map(int, tstr.split(":"))
            ts = datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=timezone.utc)
        except Exception:
            continue
        ns = int(ts.timestamp() * 1_000_000_000)

        if section in ("sar_cpu", "sar_net_dev", "sar_net_edev", "sar_disk"):
            if not rest:
                continue
            key = rest[0]
            vals = rest[1:]
            if section == "sar_cpu" and key != "all":
                continue
            if section.startswith("sar_net") and key in ("lo", "dummy0"):
                continue
        else:
            key = hostname
            vals = rest

        fields = []
        for metric, tok in zip(metrics, vals):
            num = to_float(tok)
            if num is None:
                continue
            fields.append(f"{esc_field_key(metric)}={num}")
        if not fields:
            continue

        tags = (
            f"host={esc_tag(hostname)},role={esc_tag(role)},"
            f"source={esc_tag(source)}"
        )
        if key_field != "host":
            tags += f",{key_field}={esc_tag(key)}"
        yield f"{section},{tags} {','.join(fields)} {ns}"


PING_TS_RE = re.compile(r"^#TIMESTAMP\s+(\d+)\s*:")
PING_LINE_RE = re.compile(r"^\s*(\S+)\s*:\s*(.+?)\s*$")
PING_MS_RE = re.compile(r"^([\d.]+)\s*ms$", re.IGNORECASE)


def lines_from_ping(
    text: str,
    source: str,
    host: str,
    role: str = "cvm",
    kind: str = "unknown",
) -> Iterable[str]:
    """Parse Nutanix sysstats ping_{gateway,all,remotes}.INFO text."""
    epoch: Optional[int] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        m = PING_TS_RE.match(line)
        if m:
            epoch = int(m.group(1))
            continue
        if line.startswith("#"):
            continue
        # section banners / column headers
        low = line.lower()
        if "ip :" in low or "latency" in low or line.startswith("remote_"):
            continue
        if epoch is None:
            continue
        lm = PING_LINE_RE.match(line)
        if not lm:
            continue
        target = lm.group(1).strip()
        val = lm.group(2).strip()
        if not target or target.upper() == "IP":
            continue
        ns = int(epoch) * 1_000_000_000
        tags = (
            f"host={esc_tag(host)},role={esc_tag(role)},"
            f"ping_kind={esc_tag(kind)},target={esc_tag(target)},"
            f"source={esc_tag(source)}"
        )
        if val.lower() == "unreachable":
            yield f"ping,{tags} latency_ms=-1,drop=1i {ns}"
            continue
        mm = PING_MS_RE.match(val)
        if not mm:
            continue
        yield f"ping,{tags} latency_ms={mm.group(1)},drop=0i {ns}"


def write_batch(lines: List[str]) -> None:
    if not lines:
        return
    body = ("\n".join(lines) + "\n").encode("utf-8")
    url = (
        f"{INFLUX_URL}/api/v2/write"
        f"?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns"
    )
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {INFLUX_TOKEN}",
            "Content-Type": "text/plain; charset=utf-8",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status not in (204, 200):
            raise RuntimeError(f"write failed: {resp.status}")


def ingest_dir(root: Path) -> None:
    # Ping first so latency/drops are available even if SAR ingest is huge
    files = (
        sorted(root.glob("*__ping_*.txt"))
        + sorted(root.glob("*__sar*.txt"))
        + sorted(root.glob("sar*.txt"))
    )
    # de-dupe while preserving order
    seen = set()
    uniq = []
    for f in files:
        if f.resolve() in seen:
            continue
        seen.add(f.resolve())
        uniq.append(f)
    files = uniq
    if not files:
        files = (
            sorted(root.rglob("*__sar*.txt"))
            + sorted(root.rglob("sar*.txt"))
            + sorted(root.rglob("*__ping_*.txt"))
        )
    print(f"Found {len(files)} SAR/ping files under {root}", flush=True)
    hosts = set()
    total = 0
    batch: List[str] = []
    for path in files:
        text = path.read_text(errors="ignore")
        n = 0
        if "__ping_" in path.name.lower() or path.name.lower().startswith("ping_"):
            host = "unknown"
            role = "cvm"
            kind = "unknown"
            for raw in text.splitlines()[:30]:
                if raw.startswith("# PING_HOST"):
                    parts = raw.split(None, 2)
                    if len(parts) >= 3:
                        host = parts[2].strip()
                elif raw.startswith("# PING_KIND"):
                    parts = raw.split()
                    if len(parts) >= 3:
                        kind = parts[2].strip().lower()
                elif raw.startswith("# SAR_ROLE"):
                    parts = raw.split()
                    if len(parts) >= 3:
                        role = parts[2].strip().lower()
            if host == "unknown" and "__" in path.name:
                host = path.name.split("__", 1)[0]
            if kind == "unknown":
                m = re.search(r"ping_(gateway|all|remotes)", path.name, re.I)
                if m:
                    kind = m.group(1).lower()
            point_iter = lines_from_ping(text, path.name, host=host, role=role, kind=kind)
        else:
            point_iter = lines_from_text(text, path.name)

        for lp in point_iter:
            if "host=" in lp:
                try:
                    hosts.add(lp.split("host=", 1)[1].split(",", 1)[0].split(" ", 1)[0])
                except Exception:
                    pass
            batch.append(lp)
            n += 1
            if len(batch) >= BATCH:
                write_batch(batch)
                total += len(batch)
                batch = []
        print(f"  parsed {path.name}: {n} points", flush=True)
    if batch:
        write_batch(batch)
        total += len(batch)
    print(
        f"Ingested {total} points into bucket={INFLUX_BUCKET}; hosts={sorted(hosts)}",
        flush=True,
    )


def main() -> int:
    wait_influx()
    time.sleep(3)
    ingest_dir(SAR_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
