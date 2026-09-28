#!/usr/bin/env python3
"""High new-flow UDP generator for ipfix-exporter queue saturation labs.

Each datagram uses a fresh ephemeral source port so conntrack sees a new
5-tuple (high flow-create rate, low bandwidth). Lab (ONCALL-24333): sustained
~100k+ cps for ~90s moved IpfixEventQueueDrop / IpfixScannerQueueDrop; shorter
5–80k bursts often did not.

Run on a guest VM (not CVM/AHV). Example:
  python3 simulate_ipfix_flow_burst.py --dst 10.50.130.79 --dport 12345 \\
      --cps 150000 --duration 90 --workers 32
"""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
import time


def worker(wid: int, dst: str, dport: int, per_worker_cps: int, stop_at: float, sent: list) -> None:
    local = 0
    t0 = time.time()
    payload = b"IPFIX-FLOW-BURST"
    while time.time() < stop_at:
        due = int((time.time() - t0) * per_worker_cps) - local
        for _ in range(max(0, min(due, 500))):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(payload, (dst, dport))
            finally:
                s.close()
            local += 1
        else:
            time.sleep(0.0001)
    sent[wid] = local


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dst", required=True, help="Destination IP")
    p.add_argument("--dport", type=int, default=12345, help="Destination UDP port")
    p.add_argument("--cps", type=int, default=150000, help="Target new flows per second")
    p.add_argument("--duration", type=float, default=90.0, help="Seconds to run")
    p.add_argument("--workers", type=int, default=32, help="Parallel workers")
    args = p.parse_args()

    per = max(1, args.cps // args.workers)
    stop = time.time() + args.duration
    sent = [0] * args.workers
    t0 = time.time()
    print(
        f"Starting flow burst: dst={args.dst}:{args.dport} "
        f"target_cps={args.cps} duration={args.duration}s workers={args.workers}"
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [
            ex.submit(worker, i, args.dst, args.dport, per, stop, sent)
            for i in range(args.workers)
        ]
        concurrent.futures.wait(futs)
    elapsed = max(time.time() - t0, 1e-6)
    total = sum(sent)
    print(f"Done: sent={total} elapsed={elapsed:.2f}s achieved_cps={total / elapsed:.0f}")


if __name__ == "__main__":
    main()
