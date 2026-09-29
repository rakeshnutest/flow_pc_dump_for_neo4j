#!/usr/bin/env python3
"""Ingest conntrack_rates_*.csv (60–90 hosts) into InfluxDB 2.x.

CSV columns (header optional):
  timestamp_utc,new_per_sec,destroy_per_sec,avg_new_per_sec,avg_destroy_per_sec
"""

from __future__ import annotations

import csv
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

INFLUX_URL = os.environ.get("INFLUX_URL", "http://influxdb:8086").rstrip("/")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "conntrack-admin-token")
INFLUX_ORG = os.environ.get("INFLUX_ORG", "conntrack")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "conntrack")
CSV_DIR = Path(os.environ.get("CSV_DIR", "/data"))
MAPPING_PATH = Path(os.environ.get("MAPPING_PATH", "/data/mapping.json"))
BATCH = int(os.environ.get("WRITE_BATCH", "5000"))
MEASUREMENT = "conntrack_rates"

COLUMNS = [
    "timestamp_utc",
    "new_per_sec",
    "destroy_per_sec",
    "avg_new_per_sec",
    "avg_destroy_per_sec",
]
ALIASES = {
    "time": "timestamp_utc",
    "timestamp": "timestamp_utc",
    "timestamp_utc": "timestamp_utc",
    "new": "new_per_sec",
    "new_per_sec": "new_per_sec",
    "destroy": "destroy_per_sec",
    "destroy_per_sec": "destroy_per_sec",
    "avg_new": "avg_new_per_sec",
    "avg_new_per_sec": "avg_new_per_sec",
    "avg_destroy": "avg_destroy_per_sec",
    "avg_destroy_per_sec": "avg_destroy_per_sec",
}


def wait_influx(timeout: int = 180) -> None:
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


def esc_tag(v: str) -> str:
    return v.replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def parse_ts_ns(ts: str) -> Optional[int]:
    """Parse ISO-ish UTC timestamp to nanoseconds."""
    s = ts.strip()
    if not s:
        return None
    # epoch seconds / ms
    try:
        if re.fullmatch(r"\d+(\.\d+)?", s):
            f = float(s)
            if f > 1e14:  # already ns-ish
                return int(f)
            if f > 1e11:  # ms
                return int(f * 1_000_000)
            return int(f * 1_000_000_000)
    except ValueError:
        pass
    # 2026-09-29T16:22:44Z or with fractional
    s2 = s.replace("Z", "+00:00")
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1_000_000_000)
    except ValueError:
        return None


def label_from_path(path: Path) -> str:
    """Series / legend name = CSV filename (stem)."""
    return path.stem


def build_mapping() -> Dict[str, Path]:
    """Map series label (CSV filename stem) -> path.

    Prefer every *.csv under CSV_DIR (recursive). mapping.json optional;
    labels are always the filename stem so each file is one line.
    """
    result: Dict[str, Path] = {}

    # Prefer explicit mapping files list, but re-key by filename stem.
    mapped_paths: List[Path] = []
    if MAPPING_PATH.is_file():
        try:
            raw = json.loads(MAPPING_PATH.read_text())
            hosts = raw.get("hosts", raw)
            if isinstance(hosts, dict):
                for rel in hosts.values():
                    p = Path(rel)
                    if not p.is_absolute():
                        p = CSV_DIR / p
                    if p.is_file():
                        mapped_paths.append(p.resolve())
        except (json.JSONDecodeError, OSError) as exc:
            print(f"warning: ignore mapping.json: {exc}", flush=True)

    if not mapped_paths:
        mapped_paths = [
            p.resolve()
            for p in sorted(CSV_DIR.rglob("*.csv"))
            if p.name not in ("mapping.json", "mapping.example.json")
            and not p.name.startswith("mapping")
        ]

    for p in mapped_paths:
        label = label_from_path(p)
        # Disambiguate duplicate stems from different subdirs
        if label in result and result[label] != p:
            rel = p.relative_to(CSV_DIR) if CSV_DIR in p.parents or p.parent == CSV_DIR else p
            label = str(rel).replace("/", "__").replace("\\", "__")
            if label.lower().endswith(".csv"):
                label = label[:-4]
        result[label] = p
    return dict(sorted(result.items()))


def normalize_header(row: List[str]) -> Optional[List[str]]:
    lows = [c.strip().lower() for c in row]
    if not lows:
        return None
    if lows[0] in ALIASES or lows[0] in ("timestamp_utc", "time"):
        out = []
        for c in lows:
            out.append(ALIASES.get(c, c))
        return out
    return None


def iter_points(path: Path, host: str) -> Iterable[str]:
    text = path.read_text(errors="ignore").splitlines()
    if not text:
        return
    reader = csv.reader(text)
    rows = list(reader)
    if not rows:
        return

    header = normalize_header(rows[0])
    start = 1 if header else 0
    if not header:
        header = COLUMNS[:]

    # map column index
    idx = {name: i for i, name in enumerate(header)}
    need = COLUMNS
    if any(n not in idx for n in need):
        # fall back to positional
        idx = {n: i for i, n in enumerate(COLUMNS)}
        start = 0 if not normalize_header(rows[0]) else 1

    host_tag = esc_tag(host)
    for row in rows[start:]:
        if not row or len(row) < 5:
            continue
        try:
            ts = row[idx["timestamp_utc"]].strip()
            new = float(row[idx["new_per_sec"]])
            destroy = float(row[idx["destroy_per_sec"]])
            avg_new = float(row[idx["avg_new_per_sec"]])
            avg_destroy = float(row[idx["avg_destroy_per_sec"]])
        except (KeyError, ValueError, IndexError):
            continue
        ns = parse_ts_ns(ts)
        if ns is None:
            continue
        yield (
            f"{MEASUREMENT},host={host_tag} "
            f"new_per_sec={new},destroy_per_sec={destroy},"
            f"avg_new_per_sec={avg_new},avg_destroy_per_sec={avg_destroy} {ns}"
        )


def write_batch(lines: List[str]) -> None:
    if not lines:
        return
    url = (
        f"{INFLUX_URL}/api/v2/write"
        f"?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns"
    )
    body = ("\n".join(lines) + "\n").encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {INFLUX_TOKEN}",
            "Content-Type": "text/plain; charset=utf-8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            if resp.status not in (204, 200):
                raise RuntimeError(f"write failed: {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"write failed: {exc.code} {detail}") from exc


def main() -> int:
    wait_influx()
    time.sleep(2)
    mapping = build_mapping()
    print(f"Mapped {len(mapping)} CSV file(s) under {CSV_DIR}", flush=True)
    if not mapping:
        print("ERROR: no CSVs found", flush=True)
        return 1

    total = 0
    batch: List[str] = []
    tmin: Optional[int] = None
    tmax: Optional[int] = None

    for host, path in mapping.items():
        n = 0
        for lp in iter_points(path, host):
            # extract ns from end for time window hint
            try:
                ns = int(lp.rsplit(" ", 1)[-1])
                tmin = ns if tmin is None else min(tmin, ns)
                tmax = ns if tmax is None else max(tmax, ns)
            except ValueError:
                pass
            batch.append(lp)
            n += 1
            if len(batch) >= BATCH:
                write_batch(batch)
                total += len(batch)
                batch = []
        print(f"  {host}: {n} points from {path.name}", flush=True)

    if batch:
        write_batch(batch)
        total += len(batch)

    print(f"Ingested {total} points into bucket={INFLUX_BUCKET}", flush=True)
    if tmin is not None and tmax is not None:
        from datetime import datetime, timezone

        print(
            "DATA_WINDOW "
            f"{datetime.fromtimestamp(tmin/1e9, tz=timezone.utc).isoformat()} "
            f"-> {datetime.fromtimestamp(tmax/1e9, tz=timezone.utc).isoformat()}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
