#!/usr/bin/env python3
"""Generate NetBIOS-ish UDP bursts across multiple destinations (new sport each send)."""

from __future__ import annotations

import argparse
import socket
import threading
import time


# Minimal NetBIOS name-query-ish payload (transaction id + flags + counts + padding).
NETBIOS_PAYLOAD = (
    b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
)


def worker(
    dsts: list[str],
    dport: int,
    payload: bytes,
    stop_at: float,
    interval: float,
    start_idx: int,
    counter: list[int],
    lock: threading.Lock,
) -> None:
    next_send = time.perf_counter()
    idx = start_idx
    n = len(dsts)
    local = 0
    while time.perf_counter() < stop_at:
        now = time.perf_counter()
        if now < next_send:
            time.sleep(min(0.0005, next_send - now))
            continue
        dst = dsts[idx % n]
        idx += 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(payload, (dst, dport))
            finally:
                sock.close()
            local += 1
        except OSError:
            pass
        next_send += interval
        if next_send < time.perf_counter() - 0.05:
            next_send = time.perf_counter()
    with lock:
        counter[0] += local


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "NetBIOS multi-destination UDP simulator: cycle --dsts, new ephemeral "
            "sport per packet, NetBIOS-ish name-query payload on UDP/137 by default."
        )
    )
    parser.add_argument(
        "--dsts",
        required=True,
        help="Comma-separated destination IP addresses to cycle",
    )
    parser.add_argument("--dport", type=int, default=137, help="Destination UDP port (default: 137)")
    parser.add_argument("--cps", type=int, default=22000, help="Target packets per second (default: 22000)")
    parser.add_argument("--duration", type=float, default=60.0, help="Run duration in seconds (default: 60)")
    parser.add_argument("--workers", type=int, default=16, help="Number of sender threads (default: 16)")
    args = parser.parse_args()

    dsts = [d.strip() for d in args.dsts.split(",") if d.strip()]
    if not dsts:
        parser.error("--dsts must include at least one IP")
    if args.cps < 1 or args.workers < 1 or args.duration <= 0:
        parser.error("--cps, --workers must be >= 1 and --duration > 0")

    per_worker_cps = max(args.cps / args.workers, 1e-9)
    interval = 1.0 / per_worker_cps
    counter = [0]
    lock = threading.Lock()
    stop_at = time.perf_counter() + args.duration

    print(
        f"Starting NetBIOS multi-dst burst: dsts={dsts} dport={args.dport} "
        f"target_cps={args.cps} workers={args.workers} duration={args.duration}s"
    )
    threads = [
        threading.Thread(
            target=worker,
            args=(dsts, args.dport, NETBIOS_PAYLOAD, stop_at, interval, i, counter, lock),
            daemon=True,
        )
        for i in range(args.workers)
    ]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = max(time.perf_counter() - t0, 1e-9)
    total = counter[0]
    achieved = total / elapsed
    print(f"sent={total} elapsed={elapsed:.3f}s achieved_cps={achieved:.1f} target_cps={args.cps}")


if __name__ == "__main__":
    main()
