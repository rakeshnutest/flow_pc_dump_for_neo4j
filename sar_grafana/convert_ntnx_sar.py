#!/usr/bin/env python3
"""Convert one or more Nutanix/Diamond PE zips (or SAR trees) into per-host day files.

Supports:
  - CVM: cvm_logs/kernel/var/sarNN (ASCII or XZ text)
  - AHV: ahv/<ip>/files/var/log/sa/saNN (sysstat binary -> sar)
  - CVM ping: cvm_logs/sysstats/ping_{gateway,all,remotes}.INFO*
    (latency ms + unreachable drops)

Writes:
  data/preload/<hostname>__<role>__sarNN.txt
  data/preload/<hostname>__cvm__ping_<kind>__<stamp>.txt
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HOST_RE = re.compile(r"^Linux\s+\S+\s+\(([^)]+)\)")
PING_KIND_RE = re.compile(r"ping_(gateway|all|remotes)", re.IGNORECASE)


def _is_xz(data: bytes) -> bool:
    return data[:6] == b"\xfd7zXZ\x00"


def _decode_textish(raw: bytes) -> str:
    if _is_xz(raw):
        raw = subprocess.check_output(["xz", "-dc", "--stdout"], input=raw)
    if b"\x00" in raw[:512]:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _scratch_parent(preferred: Path | None = None) -> Path:
    """Pick a writable temp parent with enough free space (/tmp is often tiny tmpfs)."""
    candidates: list[Path] = []
    if preferred is not None:
        candidates.append(preferred)
    env = os.environ.get("TMPDIR") or os.environ.get("TMP") or os.environ.get("TEMP")
    if env:
        candidates.append(Path(env))
    candidates.extend(
        [
            Path.home() / ".cache" / "sar_grafana_tmp",
            Path("/var/tmp"),
            Path(tempfile.gettempdir()),
            Path("/tmp"),
        ]
    )
    need = 256 * 1024 * 1024
    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            st = os.statvfs(cand)
            free = st.f_bavail * st.f_frsize
            if free < need:
                continue
            probe = cand / f".sar_grafana_write_{os.getpid()}"
            probe.write_bytes(b"x" * 4096)
            probe.unlink(missing_ok=True)
            return cand
        except OSError:
            continue
    return Path(tempfile.gettempdir())


def _binary_sa_to_text(raw: bytes, scratch: Path | None = None) -> str:
    """Convert classic sysstat binary saNN using local sar(1).

    Uses focused sections (CPU/load/mem/net/disk) rather than -A to keep
    output smaller while covering Grafana panels.
    """
    if not shutil_which("sar"):
        print("WARNING: sar not installed; cannot convert AHV binary sa files", file=sys.stderr)
        return ""
    parent = _scratch_parent(scratch)
    with tempfile.TemporaryDirectory(dir=str(parent)) as td:
        path = Path(td) / "safile"
        path.write_bytes(raw)
        cmds = [
            ["sar", "-u", "-f", str(path)],
            ["sar", "-q", "-f", str(path)],
            ["sar", "-r", "-f", str(path)],
            ["sar", "-n", "DEV", "-f", str(path)],
            ["sar", "-n", "EDEV", "-f", str(path)],
            ["sar", "-d", "-f", str(path)],
        ]
        chunks: list[str] = []
        for cmd in cmds:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env={**os.environ, "LC_ALL": "C"},
                )
            except Exception as exc:
                print(f"WARNING: sar convert failed ({cmd}): {exc}", file=sys.stderr)
                continue
            if proc.returncode != 0 or not proc.stdout.strip():
                err = (proc.stderr or "").strip()[:200]
                print(f"WARNING: {' '.join(cmd)} failed ({err})", file=sys.stderr)
                continue
            chunks.append(proc.stdout)
        return "\n".join(chunks)


def shutil_which(cmd: str) -> bool:
    from shutil import which

    return which(cmd) is not None


def _hostname_from_text(text: str, fallback: str = "unknown-host") -> str:
    for line in text.splitlines()[:30]:
        m = HOST_RE.match(line)
        if m:
            return m.group(1).strip()
    return fallback


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def _day_from_name(name: str) -> str:
    base = Path(name).name
    m = re.match(r"^(?:sar|sa)(\d{2})$", base)
    return m.group(1) if m else base


def _ip_fallback_from_member(name: str) -> str:
    m = re.search(r"/ahv/([^/]+)/", name.replace("\\", "/"))
    if m:
        return f"ahv-{m.group(1)}"
    m = re.search(r"PE-(\d+\.\d+\.\d+\.\d+)", name)
    if m:
        return f"cvm-{m.group(1)}"
    return "unknown-host"


def _is_cvm_sar_day(name: str) -> bool:
    return bool(re.match(r"^sar\d{2}$", Path(name).name))


def _is_ahv_sa_day(name: str) -> bool:
    base = Path(name).name
    norm = name.replace("\\", "/")
    return bool(re.match(r"^sa\d{2}$", base)) and ("/ahv/" in norm or "/var/log/sa/" in norm)


def _is_ping_info(name: str) -> bool:
    base = Path(name).name.lower()
    return base.startswith("ping_") and ".info" in base


def _ping_kind(name: str) -> str:
    m = PING_KIND_RE.search(Path(name).name)
    return m.group(1).lower() if m else "unknown"


def _ping_stamp(name: str) -> str:
    base = Path(name).name
    m = re.search(r"INFO\.(\d{8}-\d{6})", base)
    if m:
        return m.group(1)
    m = re.search(r"INFO\.(\d+)", base)
    return m.group(1) if m else "0"


def collect_from_zip(
    zip_path: Path,
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Return (sar_chunks, ping_chunks) as (member_name, text, role/kind)."""
    sar_out: list[tuple[str, str, str]] = []
    ping_out: list[tuple[str, str, str]] = []
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.namelist()
        cvm = [
            n
            for n in members
            if _is_cvm_sar_day(n) and "kernel/var/" in n.replace("\\", "/")
        ]
        if not cvm:
            cvm = [n for n in members if _is_cvm_sar_day(n)]
        ahv = [n for n in members if _is_ahv_sa_day(n)]
        pings = [n for n in members if _is_ping_info(n)]

        for name in sorted(cvm, key=lambda n: _day_from_name(n)):
            text = _decode_textish(zf.read(name))
            if "CPU" in text or "%usr" in text or "IFACE" in text:
                sar_out.append((name, text, "cvm"))

        for name in sorted(ahv, key=lambda n: _day_from_name(n)):
            raw = zf.read(name)
            text = _decode_textish(raw)
            if not text:
                text = _binary_sa_to_text(raw)
            if text and (
                "CPU" in text or "%usr" in text or "%user" in text or "IFACE" in text
            ):
                sar_out.append((name, text, "ahv"))

        for name in sorted(pings):
            text = _decode_textish(zf.read(name))
            if "#TIMESTAMP" in text or " ms" in text or "unreachable" in text.lower():
                ping_out.append((name, text, _ping_kind(name)))
    return sar_out, ping_out


def collect_from_dir(
    root: Path,
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    sar_out: list[tuple[str, str, str]] = []
    ping_out: list[tuple[str, str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = str(path)
        if _is_cvm_sar_day(path.name) and (
            "kernel/var" in name or path.name.startswith("sar")
        ):
            if "kernel/var" not in name.replace("\\", "/") and any(
                "kernel/var" in str(p) for p in root.rglob(path.name)
            ):
                continue
            text = _decode_textish(path.read_bytes())
            if "CPU" in text or "%usr" in text or "IFACE" in text:
                sar_out.append((name, text, "cvm"))
        elif _is_ahv_sa_day(name) or (
            re.match(r"^sa\d{2}$", path.name)
            and ("ahv" in name.lower() or "log/sa" in name)
        ):
            raw = path.read_bytes()
            text = _decode_textish(raw) or _binary_sa_to_text(raw)
            if text and (
                "CPU" in text or "%usr" in text or "%user" in text or "IFACE" in text
            ):
                sar_out.append((name, text, "ahv"))
        elif _is_ping_info(path.name):
            text = _decode_textish(path.read_bytes())
            if "#TIMESTAMP" in text or " ms" in text or "unreachable" in text.lower():
                ping_out.append((name, text, _ping_kind(path.name)))
    return sar_out, ping_out


def _cvm_host_from_sar(sar_chunks: list[tuple[str, str, str]], fallback: str) -> str:
    for _name, text, role in sar_chunks:
        if role == "cvm":
            return _hostname_from_text(text, fallback=fallback)
    return fallback


def write_host_days(
    chunks: list[tuple[str, str, str]], out_dir: Path
) -> tuple[int, set[str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    hosts: set[str] = set()
    written = 0
    for name, text, role in chunks:
        fallback = _ip_fallback_from_member(name)
        host = _hostname_from_text(text, fallback=fallback)
        hosts.add(f"{host}({role})")
        day = _day_from_name(name)
        dest = out_dir / f"{_safe(host)}__{role}__sar{day}.txt"
        header = f"# SAR_ROLE {role}\n# SAR_SOURCE {name}\n"
        dest.write_text(header + text)
        written += 1
        print(f"  wrote {dest.name} ({len(text)} bytes) host={host} role={role}")
    return written, hosts


def write_ping_files(
    ping_chunks: list[tuple[str, str, str]],
    out_dir: Path,
    host: str,
) -> tuple[int, set[str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    hosts: set[str] = set()
    for name, text, kind in ping_chunks:
        stamp = _ping_stamp(name)
        dest = out_dir / f"{_safe(host)}__cvm__ping_{kind}__{stamp}.txt"
        header = (
            f"# SAR_ROLE cvm\n"
            f"# PING_KIND {kind}\n"
            f"# PING_HOST {host}\n"
            f"# SAR_SOURCE {name}\n"
        )
        dest.write_text(header + text)
        hosts.add(f"{host}(cvm/ping:{kind})")
        written += 1
        print(f"  wrote {dest.name} ({len(text)} bytes) host={host} ping={kind}")
    return written, hosts


def convert_one(src: Path, out_dir: Path) -> tuple[int, set[str]]:
    if src.is_file() and zipfile.is_zipfile(src):
        sar_chunks, ping_chunks = collect_from_zip(src)
        fallback = _ip_fallback_from_member(str(src))
    elif src.is_dir():
        sar_chunks, ping_chunks = collect_from_dir(src)
        fallback = _ip_fallback_from_member(str(src))
    else:
        raise FileNotFoundError(src)

    if not sar_chunks and not ping_chunks:
        print(f"WARNING: no SAR/ping files in {src}", file=sys.stderr)
        return 0, set()

    total = 0
    all_hosts: set[str] = set()
    if sar_chunks:
        n, hosts = write_host_days(sar_chunks, out_dir)
        total += n
        all_hosts |= hosts
    if ping_chunks:
        host = _cvm_host_from_sar(sar_chunks, fallback=fallback)
        n, hosts = write_ping_files(ping_chunks, out_dir, host=host)
        total += n
        all_hosts |= hosts
    return total, all_hosts


def expand_inputs(inputs: list[str]) -> list[Path]:
    """Expand folders to contained PE zips (+ keep folder if it has extracted trees)."""
    out: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            zips = sorted(p.glob("*.zip")) + sorted(p.glob("**/*PE*.zip"))
            seen = set()
            for z in zips:
                rp = z.resolve()
                if rp in seen:
                    continue
                seen.add(rp)
                out.append(z)
            if (
                any(p.rglob("sar[0-9][0-9]"))
                or any(p.rglob("sa[0-9][0-9]"))
                or any(p.rglob("ping_*.INFO*"))
            ):
                out.append(p)
            if not out:
                out.append(p)
        else:
            out.append(p)
    seen = set()
    uniq = []
    for p in out:
        r = p.resolve()
        if r in seen:
            continue
        seen.add(r)
        uniq.append(p)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert PE zip(s)/dirs including CVM + AHV SAR + ping into preload"
    )
    ap.add_argument("inputs", nargs="+", help="PE zip path(s) and/or directories")
    ap.add_argument("-o", "--output-dir", required=True, help="Output dir (data/preload)")
    ap.add_argument("--clean", action="store_true", help="Clear previous preload texts")
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Prefer a roomy scratch dir; AHV sa conversion can need hundreds of MB.
    scratch = _scratch_parent(out_dir / ".tmp")
    os.environ.setdefault("TMPDIR", str(scratch))
    if args.clean:
        for pat in ("*__sar*.txt", "sar*.txt", "*__ping_*.txt"):
            for old in out_dir.glob(pat):
                old.unlink()

    inputs = expand_inputs(args.inputs)
    total = 0
    all_hosts: set[str] = set()
    for src in inputs:
        if not src.exists():
            print(f"ERROR: not found: {src}", file=sys.stderr)
            return 1
        print(f"==> converting {src}")
        n, hosts = convert_one(src, out_dir)
        total += n
        all_hosts |= hosts

    if total == 0:
        print("No SAR/ping files converted", file=sys.stderr)
        return 2

    print(f"Wrote {total} file(s) for: {', '.join(sorted(all_hosts))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
