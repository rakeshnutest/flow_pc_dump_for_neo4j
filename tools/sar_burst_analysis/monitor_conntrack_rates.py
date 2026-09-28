#!/usr/bin/env python3
"""Monitor conntrack NEW/DESTROY event rates via netlink and log them to CSV.

Subscribes to NFNLGRP_CONNTRACK_NEW and NFNLGRP_CONNTRACK_DESTROY on
NETLINK_NETFILTER, tallies events per second, and appends CSV rows. Optional
--print / --print-details emit rates (and parsed 5-tuples) to stdout.

CSV paths always include a host-IP suffix so allssh runs from multiple AHVs
do not collide. Default directory is /tmp; override with --output-dir.
"""

from __future__ import annotations

import argparse
import errno
import gzip
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

# --- netlink / nfnetlink / ctnetlink constants (linux/netfilter) ---
NETLINK_NETFILTER = 12
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03

NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_NEW = 0
IPCTNL_MSG_CT_DELETE = 2

NFNLGRP_CONNTRACK_NEW = 1
NFNLGRP_CONNTRACK_UPDATE = 2
NFNLGRP_CONNTRACK_DESTROY = 3

# Nested attribute types (linux/netfilter/nfnetlink_conntrack.h)
CTA_TUPLE_ORIG = 1
CTA_TUPLE_REPLY = 2
CTA_STATUS = 3
CTA_PROTOINFO = 4
CTA_HELP = 5
CTA_NAT_SRC = 6
CTA_TIMEOUT = 7
CTA_MARK = 8
CTA_COUNTERS_ORIG = 9
CTA_COUNTERS_REPLY = 10
CTA_USE = 11
CTA_ID = 12
CTA_NAT_DST = 13
CTA_TUPLE_ZONE = 18

CTA_TUPLE_IP = 1
CTA_TUPLE_PROTO = 2

CTA_IP_V4_SRC = 1
CTA_IP_V4_DST = 2
CTA_IP_V6_SRC = 3
CTA_IP_V6_DST = 4

CTA_PROTO_NUM = 1
CTA_PROTO_SRC_PORT = 2
CTA_PROTO_DST_PORT = 3
CTA_PROTO_ICMP_ID = 4
CTA_PROTO_ICMP_TYPE = 5
CTA_PROTO_ICMP_CODE = 6

PROTO_NAMES = {
    socket.IPPROTO_TCP: "tcp",
    socket.IPPROTO_UDP: "udp",
    socket.IPPROTO_ICMP: "icmp",
    socket.IPPROTO_ICMPV6: "icmpv6",
    socket.IPPROTO_SCTP: "sctp",
    socket.IPPROTO_GRE: "gre",
}

NLA_F_NESTED = 0x8000
NLA_TYPE_MASK = 0x3FFF

# Default rotate threshold (bytes) before gzip + open a fresh CSV.
DEFAULT_ROTATE_BYTES = 50 * 1024 * 1024
DEFAULT_RCVBUF_BYTES = 64 * 1024 * 1024  # 64 MiB netlink socket receive buffer
# linux/socket.h — bypasses net.core.rmem_max when running as root
SO_RCVBUFFORCE = 33
NETLINK_RECV_CHUNK = 1024 * 1024  # 1 MiB per recv call under burst


def get_host_ip() -> str:
    """Pick a stable host identifier for log/CSV path suffixes.

    Order:
      1. first non-loopback IPv4 from ``hostname -I``
      2. else first non-loopback IPv6 from ``hostname -I`` (colons -> ``_``)
      3. else UDP connect to 8.8.8.8:80 local address
      4. else hostname with dots -> ``_``
    """
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        out = ""

    ipv4: list[str] = []
    ipv6: list[str] = []
    for tok in out.split():
        tok = tok.strip()
        if not tok:
            continue
        if ":" in tok:
            if not tok.startswith("::1") and tok != "::1":
                ipv6.append(tok)
        else:
            if not tok.startswith("127."):
                ipv4.append(tok)

    if ipv4:
        return ipv4[0]
    if ipv6:
        return ipv6[0].replace(":", "_")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local = s.getsockname()[0]
            if local and not local.startswith("127."):
                return local
        finally:
            s.close()
    except OSError:
        pass

    return socket.gethostname().replace(".", "_")


def with_host_ip_suffix(path: str, host_ip: str) -> str:
    """Ensure ``_<host_ip>`` appears immediately before the file extension."""
    directory, base = os.path.split(path)
    root, ext = os.path.splitext(base)
    suffix = f"_{host_ip}"
    if root.endswith(suffix):
        return path
    return os.path.join(directory, f"{root}{suffix}{ext}") if directory else f"{root}{suffix}{ext}"


def rotate_and_compress_log(path: str, max_bytes: int = DEFAULT_ROTATE_BYTES) -> None:
    """If ``path`` exists and is >= max_bytes, rename with a UTC stamp and gzip it."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    if st.st_size < max_bytes:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rotated = f"{path}.{stamp}"
    os.rename(path, rotated)
    gz_path = rotated + ".gz"
    with open(rotated, "rb") as src, gzip.open(gz_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.remove(rotated)


def _align(n: int) -> int:
    return (n + 3) & ~3


def parse_nlattrs(buf: bytes, offset: int, end: int) -> dict[int, bytes]:
    """Parse a flat list of netlink attributes into {type: raw_value}."""
    attrs: dict[int, bytes] = {}
    while offset + 4 <= end:
        alen, atype = struct.unpack_from("=HH", buf, offset)
        if alen < 4 or offset + alen > end:
            break
        attrs[atype & NLA_TYPE_MASK] = buf[offset + 4 : offset + alen]
        offset += _align(alen)
    return attrs


def _parse_tuple(raw: bytes) -> dict[str, Any]:
    """Parse a nested CTA_TUPLE_* attribute into a flow dict."""
    info: dict[str, Any] = {}
    nested = parse_nlattrs(raw, 0, len(raw))
    ip_raw = nested.get(CTA_TUPLE_IP)
    if ip_raw:
        ip_attrs = parse_nlattrs(ip_raw, 0, len(ip_raw))
        if CTA_IP_V4_SRC in ip_attrs and len(ip_attrs[CTA_IP_V4_SRC]) >= 4:
            info["src"] = socket.inet_ntop(socket.AF_INET, ip_attrs[CTA_IP_V4_SRC][:4])
        if CTA_IP_V4_DST in ip_attrs and len(ip_attrs[CTA_IP_V4_DST]) >= 4:
            info["dst"] = socket.inet_ntop(socket.AF_INET, ip_attrs[CTA_IP_V4_DST][:4])
        if CTA_IP_V6_SRC in ip_attrs and len(ip_attrs[CTA_IP_V6_SRC]) >= 16:
            info["src"] = socket.inet_ntop(socket.AF_INET6, ip_attrs[CTA_IP_V6_SRC][:16])
        if CTA_IP_V6_DST in ip_attrs and len(ip_attrs[CTA_IP_V6_DST]) >= 16:
            info["dst"] = socket.inet_ntop(socket.AF_INET6, ip_attrs[CTA_IP_V6_DST][:16])
    proto_raw = nested.get(CTA_TUPLE_PROTO)
    if proto_raw:
        proto_attrs = parse_nlattrs(proto_raw, 0, len(proto_raw))
        if CTA_PROTO_NUM in proto_attrs and len(proto_attrs[CTA_PROTO_NUM]) >= 1:
            pnum = proto_attrs[CTA_PROTO_NUM][0]
            info["proto"] = PROTO_NAMES.get(pnum, str(pnum))
            info["proto_num"] = pnum
        if CTA_PROTO_SRC_PORT in proto_attrs and len(proto_attrs[CTA_PROTO_SRC_PORT]) >= 2:
            info["sport"] = struct.unpack("!H", proto_attrs[CTA_PROTO_SRC_PORT][:2])[0]
        if CTA_PROTO_DST_PORT in proto_attrs and len(proto_attrs[CTA_PROTO_DST_PORT]) >= 2:
            info["dport"] = struct.unpack("!H", proto_attrs[CTA_PROTO_DST_PORT][:2])[0]
        if CTA_PROTO_ICMP_TYPE in proto_attrs and len(proto_attrs[CTA_PROTO_ICMP_TYPE]) >= 1:
            info["icmp_type"] = proto_attrs[CTA_PROTO_ICMP_TYPE][0]
        if CTA_PROTO_ICMP_CODE in proto_attrs and len(proto_attrs[CTA_PROTO_ICMP_CODE]) >= 1:
            info["icmp_code"] = proto_attrs[CTA_PROTO_ICMP_CODE][0]
        if CTA_PROTO_ICMP_ID in proto_attrs and len(proto_attrs[CTA_PROTO_ICMP_ID]) >= 2:
            info["icmp_id"] = struct.unpack("!H", proto_attrs[CTA_PROTO_ICMP_ID][:2])[0]
    return info


def format_flow(tup: dict[str, Any]) -> str:
    proto = tup.get("proto", "?")
    src = tup.get("src", "?")
    dst = tup.get("dst", "?")
    if "sport" in tup and "dport" in tup:
        return f"{proto} {src}:{tup['sport']} -> {dst}:{tup['dport']}"
    if "icmp_type" in tup:
        return (
            f"{proto} {src} -> {dst} "
            f"type={tup.get('icmp_type')} code={tup.get('icmp_code')} id={tup.get('icmp_id')}"
        )
    return f"{proto} {src} -> {dst}"


def parse_ct_message(buf: bytes, offset: int, msglen: int) -> tuple[str, Optional[dict[str, Any]]]:
    """Return (event_name, orig_tuple_or_None) for one nlmsg."""
    # nlmsghdr: length(4) type(2) flags(2) seq(4) pid(4) = 16
    if msglen < 16:
        return ("?", None)
    _length, msg_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, offset)
    subsys = (msg_type >> 8) & 0xFF
    msg = msg_type & 0xFF
    if msg_type in (NLMSG_ERROR, NLMSG_DONE):
        return ("control", None)
    if subsys != NFNL_SUBSYS_CTNETLINK:
        return ("other", None)

    event = "new" if msg == IPCTNL_MSG_CT_NEW else "destroy" if msg == IPCTNL_MSG_CT_DELETE else "other"
    # nfgenmsg: family(1) version(1) res_id(2) = 4, then attributes
    attr_off = offset + 16 + 4
    attr_end = offset + msglen
    if attr_off > attr_end:
        return (event, None)
    attrs = parse_nlattrs(buf, attr_off, attr_end)
    orig = None
    if CTA_TUPLE_ORIG in attrs:
        orig = _parse_tuple(attrs[CTA_TUPLE_ORIG])
    return (event, orig)


def open_netlink_socket(rcvbuf_bytes: int = DEFAULT_RCVBUF_BYTES) -> socket.socket:
    """Bind a NETLINK_NETFILTER socket subscribed to NEW + DESTROY groups.

    Under high NEW/DESTROY CPS the kernel drops events into ENOBUFS if the
    userspace receive buffer is too small. Request a large SO_RCVBUF, and as
    root try SO_RCVBUFFORCE / raise net.core.rmem_max so the kernel actually
    grants the size.
    """
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    groups = (1 << (NFNLGRP_CONNTRACK_NEW - 1)) | (1 << (NFNLGRP_CONNTRACK_DESTROY - 1))
    sock.bind((0, groups))

    # Raise system max so SO_RCVBUF is not silently capped (best-effort).
    try:
        with open("/proc/sys/net/core/rmem_max", "r+") as f:
            cur = int(f.read().strip())
            if cur < rcvbuf_bytes:
                f.seek(0)
                f.write(str(rcvbuf_bytes))
                f.truncate()
    except OSError:
        pass

    for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, rcvbuf_bytes)
            break
        except OSError:
            continue

    try:
        granted = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        # Kernel doubles the requested value for bookkeeping on Linux.
        print(
            f"netlink SO_RCVBUF granted≈{granted} bytes (requested {rcvbuf_bytes})",
            file=sys.stderr,
        )
    except OSError:
        pass

    return sock


def open_csv(path: str):
    """Open CSV for append; write header if empty/new."""
    rotate_and_compress_log(path)
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    fh = open(path, "a", buffering=1)
    if not exists:
        fh.write(
            "timestamp_utc,new_per_sec,destroy_per_sec,"
            "new_avg_per_sec,destroy_avg_per_sec,"
            "new_total,destroy_total,enobuf_events\n"
        )
    return fh


def resolve_output_path(output: str | None, output_dir: str, host_ip: str) -> str:
    """Build CSV path under output_dir (default /tmp), always host-IP-suffixed.

    If --output is a full file path, that path is used (still host-IP-suffixed).
    Otherwise write conntrack_rates_<host_ip>.csv under --output-dir.
    """
    if output:
        path = with_host_ip_suffix(output, host_ip)
    else:
        path = os.path.join(output_dir, f"conntrack_rates_{host_ip}.csv")
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    return path


def main() -> int:
    host_ip = get_host_ip()
    parser = argparse.ArgumentParser(
        description=(
            "Netlink conntrack NEW/DESTROY rate monitor. "
            "Logs per-second rates to a host-IP-suffixed CSV "
            "(directory defaults to /tmp; override with --output-dir)."
        )
    )
    parser.add_argument(
        "--output-dir",
        default="/tmp",
        help="Directory for the CSV log (default: /tmp)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Full CSV path (optional). Overrides --output-dir for location; "
            "host IP is still inserted before the extension if missing"
        ),
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=24.0,
        help="Stop after this many hours (default: 24). Use 0 for unlimited.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Rate sample interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--rotate-bytes",
        type=int,
        default=DEFAULT_ROTATE_BYTES,
        help=f"Rotate+gzip CSV when size reaches this many bytes (default: {DEFAULT_ROTATE_BYTES})",
    )
    parser.add_argument(
        "--rcvbuf-mb",
        type=int,
        default=DEFAULT_RCVBUF_BYTES // (1024 * 1024),
        help="Netlink socket receive buffer in MiB (default: 64). Raises rmem_max if possible.",
    )
    parser.add_argument(
        "--avg-window",
        type=float,
        default=60.0,
        help=(
            "Also report a sliding-window average over this many seconds "
            "(default: 60). Set 0 to disable window avg (lifetime avg still printed)."
        ),
    )
    parser.add_argument(
        "--print",
        dest="do_print",
        action="store_true",
        help="Print per-interval NEW/DESTROY rates to stdout",
    )
    parser.add_argument(
        "--print-details",
        action="store_true",
        help="Print each NEW/DESTROY 5-tuple (very verbose under load)",
    )
    args = parser.parse_args()
    args.output = resolve_output_path(args.output, args.output_dir, host_ip)

    if args.interval <= 0:
        parser.error("--interval must be > 0")
    if args.max_hours < 0:
        parser.error("--max-hours must be >= 0")
    if args.rcvbuf_mb <= 0:
        parser.error("--rcvbuf-mb must be > 0")
    if args.avg_window < 0:
        parser.error("--avg-window must be >= 0")

    if os.geteuid() != 0:
        print(
            "warning: netlink conntrack groups usually require root; "
            "bind/recv may fail without CAP_NET_ADMIN",
            file=sys.stderr,
        )

    try:
        nl = open_netlink_socket(rcvbuf_bytes=args.rcvbuf_mb * 1024 * 1024)
    except OSError as exc:
        print(f"error: failed to open NETLINK_NETFILTER socket: {exc}", file=sys.stderr)
        return 1

    csv_fh = open_csv(args.output)
    print(
        f"conntrack rate monitor: host_ip={host_ip} output={args.output} "
        f"max_hours={args.max_hours} interval={args.interval} "
        f"rcvbuf_mb={args.rcvbuf_mb} avg_window={args.avg_window}",
        file=sys.stderr,
    )

    new_count = 0
    destroy_count = 0
    new_total = 0
    destroy_total = 0
    enobuf_count = 0
    enobuf_total = 0
    interval = args.interval
    # Sliding window of (mono_ts, new_events, destroy_events) per sample.
    window: list[tuple[float, int, int]] = []
    start_mono = time.monotonic()
    next_sample = start_mono + interval
    deadline = None if args.max_hours == 0 else (start_mono + args.max_hours * 3600.0)

    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                print("max-hours reached; exiting", file=sys.stderr)
                break

            timeout = max(0.0, next_sample - time.monotonic())
            if deadline is not None:
                timeout = min(timeout, max(0.0, deadline - time.monotonic()))

            readable, _, _ = select.select([nl], [], [], timeout)
            if readable:
                try:
                    data = nl.recv(NETLINK_RECV_CHUNK)
                except OSError as exc:
                    # ENOBUFS: kernel dropped netlink messages; rates are undercount —
                    # keep running instead of aborting under CPS bursts.
                    if getattr(exc, "errno", None) == errno.ENOBUFS:
                        enobuf_count += 1
                        enobuf_total += 1
                    else:
                        print(f"error: netlink recv failed: {exc}", file=sys.stderr)
                        break
                else:
                    off = 0
                    while off + 16 <= len(data):
                        (msglen,) = struct.unpack_from("=I", data, off)
                        if msglen < 16 or off + msglen > len(data):
                            break
                        event, orig = parse_ct_message(data, off, msglen)
                        if event == "new":
                            new_count += 1
                            new_total += 1
                            if args.print_details and orig is not None:
                                print(f"NEW     {format_flow(orig)}")
                        elif event == "destroy":
                            destroy_count += 1
                            destroy_total += 1
                            if args.print_details and orig is not None:
                                print(f"DESTROY {format_flow(orig)}")
                        off += _align(msglen)

            now = time.monotonic()
            if now >= next_sample:
                # Catch up if we fell behind under load.
                elapsed = now - (next_sample - interval)
                scale = elapsed if elapsed > 0 else interval
                new_rate = new_count / scale
                destroy_rate = destroy_count / scale

                life_elapsed = max(now - start_mono, interval)
                new_avg = new_total / life_elapsed
                destroy_avg = destroy_total / life_elapsed

                window.append((now, new_count, destroy_count))
                if args.avg_window > 0:
                    cutoff = now - args.avg_window
                    while window and window[0][0] < cutoff:
                        window.pop(0)
                    win_new = sum(n for _, n, _ in window)
                    win_destroy = sum(d for _, _, d in window)
                    win_span = max(now - window[0][0], interval) if window else interval
                    win_new_avg = win_new / win_span
                    win_destroy_avg = win_destroy / win_span
                else:
                    win_new_avg = new_avg
                    win_destroy_avg = destroy_avg

                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                csv_fh.write(
                    f"{ts},{new_rate:.3f},{destroy_rate:.3f},"
                    f"{new_avg:.3f},{destroy_avg:.3f},"
                    f"{new_total},{destroy_total},{enobuf_total}\n"
                )
                if args.do_print or args.print_details:
                    extra = f"  enobuf={enobuf_count}" if enobuf_count else ""
                    win_txt = ""
                    if args.avg_window > 0:
                        win_txt = (
                            f"  win{int(args.avg_window)}s_new/s={win_new_avg:.1f}"
                            f"  win{int(args.avg_window)}s_destroy/s={win_destroy_avg:.1f}"
                        )
                    print(
                        f"{ts}  new/s={new_rate:.1f}  avg_new/s={new_avg:.1f}  "
                        f"destroy/s={destroy_rate:.1f}  avg_destroy/s={destroy_avg:.1f}"
                        f"{win_txt}  totals new={new_total} destroy={destroy_total}{extra}"
                    )
                new_count = 0
                destroy_count = 0
                enobuf_count = 0
                next_sample += interval
                while next_sample <= time.monotonic():
                    next_sample += interval
                rotate_and_compress_log(args.output, max_bytes=args.rotate_bytes)
                if not os.path.exists(args.output) or os.path.getsize(args.output) == 0:
                    # Rotated out from under us — reopen with header.
                    csv_fh.close()
                    csv_fh = open_csv(args.output)
    except KeyboardInterrupt:
        print("interrupted; exiting", file=sys.stderr)
    finally:
        try:
            csv_fh.close()
        except Exception:
            pass
        try:
            nl.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
