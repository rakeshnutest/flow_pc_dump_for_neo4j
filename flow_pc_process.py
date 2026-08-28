#!/usr/bin/env python
"""Process an idfcli + OVN + OVS + atlas + flow_cli dump off the PC. No live PC APIs.

Maps idfcli/*.json plus policy_get.json and service_group_get.json into prefetch JSON.
Does not call idfcli, kubectl, AHV Gateway, FlowInterfaces, atlas_cli, or flow_cli.
flow_cli policy.get is required for policies. v4 ServiceGroupGet is required
for service groups. No IDF zprotobuf.

  python3 flow_pc_process.py --dump_dir /path/to/dump
  python3 flow_pc_process.py --dump_dir /path/to/dump --ingest --log_bundle_id 2
"""
from __future__ import print_function

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _ingest(script, dump_dir, log_bundle_id):
  if not os.path.isfile(script):
    print("skip ingest (missing %s)" % script)
    return 0
  cmd = [sys.executable, script, "--dump_dir", dump_dir]
  if log_bundle_id:
    cmd.extend(["--log_bundle_id", str(log_bundle_id)])
  print("RUN %s" % " ".join(cmd))
  return subprocess.call(cmd)


def main(argv=None):
  ap = argparse.ArgumentParser(
      description="Process idfcli/OVN/OVS dump into JSON and ClickHouse.")
  ap.add_argument("--dump_dir", required=True)
  ap.add_argument(
      "--output_dir", default="",
      help="Prefetch JSON dest. Default: same as --dump_dir")
  ap.add_argument("--workers", type=int, default=16)
  ap.add_argument("--timeout_secs", type=int, default=600)
  ap.add_argument(
      "--ingest", action="store_true",
      help="Ingest OVN (and flow_policy if policies.json is non-empty).")
  ap.add_argument("--log_bundle_id", type=int, default=0)
  ap.add_argument(
      "--skip-convert", action="store_true",
      help="Do not map idfcli; ingest only.")
  args = ap.parse_args(argv)

  dump_dir = os.path.abspath(args.dump_dir)
  output_dir = os.path.abspath(args.output_dir or dump_dir)
  rc = 0
  if not args.skip_convert:
    if HERE not in sys.path:
      sys.path.insert(0, HERE)
    try:
      from flow_pc_map import process_dump
    except ImportError as exc:
      print(
          "Cannot import flow_pc_map (%s). Convert stays local "
          "(not on PC). Pass --skip-convert --ingest for OVN only." % exc)
      if not args.ingest:
        return 1
    else:
      rc = process_dump(
          dump_dir, output_dir, workers=args.workers,
          timeout_secs=args.timeout_secs) or 0

  if args.ingest:
    ovn = os.path.join(HERE, "clickhouse_ovn", "ingest.py")
    flow = os.path.join(HERE, "clickhouse_flow", "ingest.py")
    rc_ovn = _ingest(ovn, dump_dir, args.log_bundle_id)
    policies = os.path.join(output_dir, "policies.json")
    rc_flow = 0
    if os.path.isfile(policies):
      try:
        with open(policies) as handle:
          rows = json.load(handle) or []
      except Exception:
        rows = []
      if rows:
        rc_flow = _ingest(flow, output_dir, args.log_bundle_id)
      else:
        print("skip flow_policy ingest (policies.json empty)")
    else:
      print("skip flow_policy ingest (no policies.json)")
    rc = rc or rc_ovn or rc_flow
  return rc


if __name__ == "__main__":
  sys.exit(main())
