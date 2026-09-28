#!/usr/bin/env python3
"""NetBIOS-like multi-destination UDP/137 generator (Axis ONCALL-24333 pattern).

Customer evidence: many short-lived UDP/137 flows from one source to several
nearby destinations (e.g. 10.9.191.168 -> .10-.13). Small packets + high
flow-create rate pressure ipfix-exporter queues more than bandwidth.

Run on a guest VM. Example (lab-style multi-dst fanout):
  python3 simulate_netbios_multidst.py \\
      --dsts 10.50.130.79,10.50.130.43,10.50.130.32 \\
      --dport 137 --cps 22000 --duration 60 --workers 16
"""

from __future__ import annotations

import argparse
import concurrent.futures
import itertools
import socket
import time


def parse_dsts(raw: str) -> list[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def worker(
    wid: int,
    dsts: list[str],
    dport: int,
    per_worker_cps: int,
    stop_at: float,
    sent: list,
) -> None:
    local = 0
    t0 = time.time()
    # Minimal NetBIOS name-service-ish payload (not a full NBNS packet).
    payload = b"\x00\x00\x00\x00\x00\x01\x00\x00" + b"NBNS"
    cycle = itertools.cycle(dsts)
    while time.time() < stop_at:
        due = int((time.time() - t0) * per_worker_cps) - local
        for _ in range(max(0, min(due, 500))):
            dst = next(cycle)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # New ephemeral sport each send → new 5-tuple per dst hop.
                s.sendto(payload, (dst, dport))
            finally:
                s.close()
            local += 1
        else:
            time.sleep(0.0001)
    sent[wid] = local


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dsts",
        required=True,
        help="Comma-separated destination IPs (NetBIOS name targets)",
    )
    p.add_argument("--dport", type=int, default=137, help="UDP port (default 137)")
    p.add_argument("--cps", type=int, default=22000, help="Target packets/sec across all dsts")
    p.add_argument("--duration", type=float, default=60.0, help="Seconds to run")
    p.add_argument("--workers", type=int, default=16, help="Parallel workers")
    args = p.parse_args()

    dsts = parse_dsts(args.dsts)
    if not dsts:
        raise SystemExit("--dsts must list at least one IP")

    per = max(1, args.cps // args.workers)
    stop = time.time() + args.duration
    sent = [0] * args.workers
    t0 = time.time()
    print(
        f"Starting NetBIOS multi-dst burst: dsts={dsts} dport={args.dport} "
        f"target_cps={args.cps} duration={args.duration}s workers={args.workers}"
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [
            ex.submit(worker, i, dsts, args.dport, per, stop, sent)
            for i in range(args.workers)
        ]
        concurrent.futures.wait(futs)
    elapsed = max(time.time() - t0, 1e-6)
    total = sum(sent)
    print(f"Done: sent={total} elapsed={elapsed:.2f}s achieved_cps={total / elapsed:.0f}")


if __name__ == "__main__":
    main()
