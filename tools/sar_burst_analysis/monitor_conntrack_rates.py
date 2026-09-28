#!/usr/bin/env python3
"""Monitor conntrack NEW/DESTROY event rates via netlink and log them to CSV.

Subscribes to NFNLGRP_CONNTRACK_NEW and NFNLGRP_CONNTRACK_DESTROY on
NETLINK_NETFILTER, tallies events per second, and appends CSV rows. Optional
--print / --print-details emit rates (and parsed 5-tuples) to stdout.

CSV paths always include a host-IP suffix so allssh runs from multiple AHVs
do not collide under /tmp.
"""

from __future__ import annotations

import argparse
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


def open_netlink_socket() -> socket.socket:
    """Bind a NETLINK_NETFILTER socket subscribed to NEW + DESTROY groups."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    # pid=0 -> kernel assigns; groups bitmask for NEW|DESTROY
    groups = (1 << (NFNLGRP_CONNTRACK_NEW - 1)) | (1 << (NFNLGRP_CONNTRACK_DESTROY - 1))
    sock.bind((0, groups))
    # Larger receive buffer to reduce overrun under high CPS.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    except OSError:
        pass
    return sock


def open_csv(path: str):
    """Open CSV for append; write header if empty/new."""
    rotate_and_compress_log(path)
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    fh = open(path, "a", buffering=1)
    if not exists:
        fh.write("timestamp_utc,new_per_sec,destroy_per_sec,new_total,destroy_total\n")
    return fh


def main() -> int:
    host_ip = get_host_ip()
    parser = argparse.ArgumentParser(
        description=(
            "Netlink conntrack NEW/DESTROY rate monitor. "
            "Logs per-second rates to a host-IP-suffixed CSV under /tmp by default."
        )
    )
    parser.add_argument(
        "--output",
        default=f"/tmp/conntrack_rates_{host_ip}.csv",
        help="CSV output path (host IP is inserted before the extension if missing)",
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
    args.output = with_host_ip_suffix(args.output, host_ip)

    if args.interval <= 0:
        parser.error("--interval must be > 0")
    if args.max_hours < 0:
        parser.error("--max-hours must be >= 0")

    if os.geteuid() != 0:
        print(
            "warning: netlink conntrack groups usually require root; "
            "bind/recv may fail without CAP_NET_ADMIN",
            file=sys.stderr,
        )

    try:
        nl = open_netlink_socket()
    except OSError as exc:
        print(f"error: failed to open NETLINK_NETFILTER socket: {exc}", file=sys.stderr)
        return 1

    csv_fh = open_csv(args.output)
    print(
        f"conntrack rate monitor: host_ip={host_ip} output={args.output} "
        f"max_hours={args.max_hours} interval={args.interval}",
        file=sys.stderr,
    )

    new_count = 0
    destroy_count = 0
    new_total = 0
    destroy_total = 0
    interval = args.interval
    next_sample = time.monotonic() + interval
    deadline = None if args.max_hours == 0 else (time.monotonic() + args.max_hours * 3600.0)

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
                    data = nl.recv(65536)
                except OSError as exc:
                    print(f"error: netlink recv failed: {exc}", file=sys.stderr)
                    break
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
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                csv_fh.write(
                    f"{ts},{new_rate:.3f},{destroy_rate:.3f},{new_total},{destroy_total}\n"
                )
                if args.do_print or args.print_details:
                    print(
                        f"{ts}  new/s={new_rate:.1f}  destroy/s={destroy_rate:.1f}  "
                        f"totals new={new_total} destroy={destroy_total}"
                    )
                new_count = 0
                destroy_count = 0
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
