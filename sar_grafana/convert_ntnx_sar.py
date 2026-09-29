#!/usr/bin/env python3
"""Convert one or more Nutanix/Diamond PE zips (or SAR trees) into per-host day files.

Writes: data/preload/<hostname>__sarNN.txt
So multiple CVMs/hosts never overwrite each other.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path

HOST_RE = re.compile(r"^Linux\s+\S+\s+\(([^)]+)\)")


def _is_xz(data: bytes) -> bool:
    return data[:6] == b"\xfd7zXZ\x00"


def _decode_member(raw: bytes) -> str:
    if _is_xz(raw):
        raw = subprocess.check_output(["xz", "-dc", "--stdout"], input=raw)
    if b"\x00" in raw[:512]:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _hostname_from_text(text: str) -> str:
    for line in text.splitlines()[:20]:
        m = HOST_RE.match(line)
        if m:
            return m.group(1).strip()
    return "unknown-host"


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def _day_key(name: str) -> str:
    base = Path(name).name
    if base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit():
        return base[3:5]
    return base


def _is_sar_day(name: str) -> bool:
    base = Path(name).name
    return base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit()


def collect_from_zip(zip_path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    with zipfile.ZipFile(zip_path) as zf:
        names = [n for n in zf.namelist() if _is_sar_day(n)]
        kernel = [n for n in names if "kernel/var/" in n.replace("\\", "/")]
        selected = kernel if kernel else names
        for name in sorted(selected, key=_day_key):
            text = _decode_member(zf.read(name))
            if "CPU" in text or "%usr" in text or "%user" in text or "IFACE" in text:
                out.append((name, text))
    return out


def collect_from_dir(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in root.rglob("sar*"):
        if not path.is_file() or not _is_sar_day(path.name):
            continue
        # prefer kernel/var paths; still accept others if that's all we have
        text = _decode_member(path.read_bytes())
        if "CPU" in text or "%usr" in text or "IFACE" in text:
            out.append((str(path), text))
    # If both kernel/var and others exist, keep kernel/var only
    kernel = [c for c in out if "kernel/var/" in c[0].replace("\\", "/")]
    return sorted(kernel if kernel else out, key=lambda x: _day_key(x[0]))


def write_host_days(chunks: list[tuple[str, str]], out_dir: Path) -> tuple[int, set[str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    hosts: set[str] = set()
    written = 0
    for name, text in chunks:
        host = _hostname_from_text(text)
        hosts.add(host)
        day = _day_key(name)
        dest = out_dir / f"{_safe(host)}__sar{day}.txt"
        dest.write_text(text)
        written += 1
        print(f"  wrote {dest.name} ({len(text)} bytes) host={host}")
    return written, hosts


def convert_one(src: Path, out_dir: Path) -> tuple[int, set[str]]:
    if src.is_file() and zipfile.is_zipfile(src):
        chunks = collect_from_zip(src)
    elif src.is_dir():
        chunks = collect_from_dir(src)
    elif src.is_file() and src.suffix.lower() == ".zip":
        raise ValueError(f"not a zip: {src}")
    else:
        raise FileNotFoundError(src)
    if not chunks:
        print(f"WARNING: no SAR days in {src}", file=sys.stderr)
        return 0, set()
    return write_host_days(chunks, out_dir)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert one or more PE zips/dirs into per-host SAR day files"
    )
    ap.add_argument(
        "inputs",
        nargs="+",
        help="PE zip path(s) and/or directories containing extracted SAR",
    )
    ap.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="Output directory (e.g. data/preload)",
    )
    ap.add_argument(
        "--clean",
        action="store_true",
        help="Delete existing *__sar*.txt in output dir first",
    )
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.clean:
        for old in out_dir.glob("*__sar*.txt"):
            old.unlink()
        for old in out_dir.glob("sar*.txt"):
            # legacy single-host names
            old.unlink()

    total = 0
    all_hosts: set[str] = set()
    for item in args.inputs:
        src = Path(item)
        if not src.exists():
            print(f"ERROR: not found: {src}", file=sys.stderr)
            return 1
        print(f"==> converting {src}")
        n, hosts = convert_one(src, out_dir)
        total += n
        all_hosts |= hosts

    if total == 0:
        print("No SAR day files converted", file=sys.stderr)
        return 2

    print(f"Wrote {total} day file(s) for hosts: {', '.join(sorted(all_hosts))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
