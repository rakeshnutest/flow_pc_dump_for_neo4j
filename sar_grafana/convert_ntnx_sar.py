#!/usr/bin/env python3
"""Convert Nutanix / Diamond PE zip (or extracted SAR tree) into SARchart multi-day text.

Handles:
  - whole PE .zip
  - cvm_logs/kernel/var/sarNN (ASCII or XZ-compressed ASCII)
  - optional sysstats/sar.INFO* append for denser network samples
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path


def _is_xz(data: bytes) -> bool:
    return data[:6] == b"\xfd7zXZ\x00"


def _decode_member(raw: bytes) -> str:
    if _is_xz(raw):
        raw = subprocess.check_output(["xz", "-dc", "--stdout"], input=raw)
    if b"\x00" in raw[:512]:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _day_key(name: str) -> str:
    base = Path(name).name
    if base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit():
        return base[3:5]
    return base


def collect_from_zip(zip_path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            low = name.lower()
            base = Path(name).name
            if "/kernel/var/sar" in low or (
                base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit()
            ):
                text = _decode_member(zf.read(name))
                if "CPU" in text or "%usr" in text or "%user" in text or "IFACE" in text:
                    out.append((name, text))
    out.sort(key=lambda x: _day_key(x[0]))
    return out


def collect_from_dir(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in root.rglob("sar*"):
        if not path.is_file():
            continue
        base = path.name
        if not (base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit()):
            if "sar.INFO" not in base:
                continue
            # skip INFO here; full daily files preferred
            continue
        text = _decode_member(path.read_bytes())
        if "CPU" in text or "%usr" in text or "IFACE" in text:
            out.append((str(path), text))
    out.sort(key=lambda x: _day_key(x[0]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="PE zip path or directory with extracted SAR files")
    ap.add_argument("-o", "--output", required=True, help="Output multi-day .txt for SARchart")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        print(f"not found: {src}", file=sys.stderr)
        return 1

    if src.is_file() and zipfile.is_zipfile(src):
        chunks = collect_from_zip(src)
    else:
        chunks = collect_from_dir(src)

    if not chunks:
        print("No SAR day files found", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for name, text in chunks:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")

    print(f"Wrote {out} from {len(chunks)} day files ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
