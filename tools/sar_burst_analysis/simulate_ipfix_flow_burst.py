#!/usr/bin/env python3
"""Generate high-CPS UDP flow bursts (new 5-tuple per packet) for IPFIX / CT stress.

Each send opens a new UDP socket so the kernel assigns a fresh ephemeral source
port, producing a new conntrack 5-tuple per packet.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time


def worker(
    dst: str,
    dport: int,
    payload: bytes,
    stop_at: float,
    interval: float,
    counter: list[int],
    lock: threading.Lock,
) -> None:
    next_send = time.perf_counter()
    local = 0
    while time.perf_counter() < stop_at:
        now = time.perf_counter()
        if now < next_send:
            time.sleep(min(0.0005, next_send - now))
            continue
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
            # Fall behind under load: catch up without spinning forever.
            next_send = time.perf_counter()
    with lock:
        counter[0] += local


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "UDP flow-burst simulator: one new socket (ephemeral sport) per "
            "packet to create distinct CT 5-tuples for IPFIX stress tests."
        )
    )
    parser.add_argument("--dst", required=True, help="Destination IP address")
    parser.add_argument("--dport", type=int, default=12345, help="Destination UDP port (default: 12345)")
    parser.add_argument("--cps", type=int, default=150000, help="Target connections (packets) per second")
    parser.add_argument("--duration", type=float, default=90.0, help="Run duration in seconds (default: 90)")
    parser.add_argument("--workers", type=int, default=32, help="Number of sender threads (default: 32)")
    parser.add_argument(
        "--payload-size",
        type=int,
        default=64,
        help="UDP payload size in bytes (default: 64)",
    )
    args = parser.parse_args()

    if args.cps < 1 or args.workers < 1 or args.duration <= 0:
        parser.error("--cps, --workers must be >= 1 and --duration > 0")

    payload = b"F" * max(1, args.payload_size)
    per_worker_cps = max(args.cps / args.workers, 1e-9)
    interval = 1.0 / per_worker_cps
    counter = [0]
    lock = threading.Lock()
    stop_at = time.perf_counter() + args.duration

    print(
        f"Starting IPFIX flow burst: dst={args.dst}:{args.dport} "
        f"target_cps={args.cps} workers={args.workers} duration={args.duration}s"
    )
    threads = [
        threading.Thread(
            target=worker,
            args=(args.dst, args.dport, payload, stop_at, interval, counter, lock),
            daemon=True,
        )
        for _ in range(args.workers)
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
