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
    r"^Linux\s+\S+\s+\(([^)]+)\)\s+(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})"
)
TIME_RE = re.compile(r"^(\d{2}:\d{2}:\d{2})")

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
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def classify(cols: List[str]) -> Optional[Tuple[str, str, List[str]]]:
    low = [c.lower() for c in cols]
    if "cpu" in low and ("%usr" in low or "%user" in low):
        return "sar_cpu", "cpu", cols[1:]
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


def lines_from_text(text: str, source: str) -> Iterable[str]:
    hostname = "unknown"
    day: Optional[datetime] = None
    section: Optional[str] = None
    key_field = "host"
    metrics: List[str] = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("Average") or line.startswith("#"):
            continue

        m = LINUX_RE.match(line)
        if m:
            hostname = m.group(1)
            day = parse_date(m.group(2))
            section = None
            metrics = []
            continue

        parts = line.split()
        if not TIME_RE.match(parts[0]):
            classified = classify(parts)
            if classified:
                section, key_field, metrics = classified
            continue

        tstr = parts[0]
        rest = parts[1:]
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

        tags = f"host={esc_tag(hostname)},source={esc_tag(source)}"
        if key_field != "host":
            tags += f",{key_field}={esc_tag(key)}"
        yield f"{section},{tags} {','.join(fields)} {ns}"


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
    files = sorted(root.glob("sar*.txt"))
    if not files:
        files = sorted(root.rglob("sar*.txt"))
    print(f"Found {len(files)} SAR files under {root}", flush=True)
    total = 0
    batch: List[str] = []
    for path in files:
        text = path.read_text(errors="ignore")
        n = 0
        for lp in lines_from_text(text, path.name):
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
    print(f"Ingested {total} points into bucket={INFLUX_BUCKET}", flush=True)


def main() -> int:
    wait_influx()
    time.sleep(3)
    ingest_dir(SAR_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
