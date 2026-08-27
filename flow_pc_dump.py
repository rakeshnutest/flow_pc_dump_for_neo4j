#!/usr/bin/env python
"""PC dump CLI: FlowInterfaces + idfcli + atlas_cli + OVN + OVS.

Run on PCVM with the Flow venv (not system python3):

  /home/nutanix/.venvs/flow/bin/python3 /home/nutanix/data/flow_pc_dump.py \\
      --output_dir /home/nutanix/upgrade/flow_pc_dump

Collects:
  FlowInterfaces  AG / SG / EG / policies (convert on PC)
  idfcli/         VMs, NICs, subnets, categories, ...
  ahv_gateway/    OVS via AHV Gateway mTLS :7030
  cmsp_ovn/       OVN NB/SB via kubectl ovsdb-client dump
  port_set_list.json / port_set_get.json  (atlas_cli)

Ingest off-PC with flow_pc_process.py --skip-convert --ingest.
"""
from __future__ import print_function

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = "/home/nutanix/upgrade/flow_pc_dump"
FLOW_PYTHON = "/home/nutanix/.venvs/flow/bin/python3"


def build_parser():
  ap = argparse.ArgumentParser(
      prog="flow_pc_dump.py",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      description=(
          "Dump FlowInterfaces (AG/SG/EG/policies), idfcli, atlas_cli, "
          "AHV Gateway OVS, and CMSP OVN on the PCVM."),
      epilog="""
Must use the Flow venv so FlowInterfaces is collected:

  %(py)s %(prog)s --output_dir %(out)s

That interpreter is the same one live flow / microseg use. System python3
cannot import flow.common and will not collect AG/SG/EG/policies.

Writes under --output_dir:
  policies.json address_groups.json service_groups.json entity_groups.json
  vms.json subnets.json vpcs.json hosts.json clusters.json projects.json
  categories.json network_functions.json fqdn_to_ip_map.json
  idfcli/<entity_type>.json and .txt
  ahv_gateway/   (OVS via AHV Gateway mTLS :7030)
  cmsp_ovn/      (OVN NB/SB via kubectl ovsdb-client dump)
  port_set_list.json / port_set_get.json  (atlas_cli)
  all.json dump.log meta.json dump_errors.json

FLAGS(argv) is parsed before FlowInterfaces() is constructed. That is
required on PC (otherwise Zeus UnparsedFlagAccessError).

Examples:
  %(py)s %(prog)s --help
  %(py)s %(prog)s --output_dir %(out)s
  %(py)s %(prog)s --output_dir %(out)s --workers 16 --atlas_get_workers 32
  python3 %(prog)s --skip_flow --output_dir %(out)s
""" % {"py": FLOW_PYTHON, "prog": "flow_pc_dump.py", "out": DEFAULT_OUTPUT})
  ap.add_argument(
      "--output_dir", default=DEFAULT_OUTPUT,
      help="Directory for prefetch JSON, idfcli/, ahv_gateway/, cmsp_ovn/, "
           "atlas (default: %(default)s)")
  ap.add_argument(
      "--output", default="",
      help="Combined JSON path. Default: <output_dir>/all.json")
  ap.add_argument(
      "--log_file", default="",
      help="Log file path. Default: <output_dir>/dump.log")
  ap.add_argument(
      "--from_json", default="",
      help="Split an existing combined JSON into output_dir files; skip fetch")
  ap.add_argument(
      "--workers", type=int, default=16,
      help="Parallel workers for FlowInterfaces datasets and writes")
  ap.add_argument(
      "--dataset_timeout_secs", type=int, default=600,
      help="Timeout for the FlowInterfaces dataset batch and per-idfcli type")
  ap.add_argument(
      "--fail_on_error", action="store_true",
      help="Exit non-zero if any dataset fetch fails")
  ap.add_argument(
      "--skip_flow", action="store_true",
      help="Skip FlowInterfaces (AG/SG/EG/policies). Default collects them")
  ap.add_argument(
      "--skip_idfcli", action="store_true",
      help="Skip idfcli entity dumps")
  ap.add_argument(
      "--skip_ahv_gateway", action="store_true",
      help="Skip AHV Gateway host collect (OVS/virsh/tap/brAtlas)")
  ap.add_argument(
      "--skip_cmsp_ovn", action="store_true",
      help="Skip CMSP kubectl OVN Northbound/Southbound dump")
  ap.add_argument(
      "--skip_atlas", action="store_true",
      help="Skip atlas_cli port_set.list and port_set.get")
  ap.add_argument(
      "--ahv_gateway_timeout_secs", type=int, default=1800,
      help="Deadline for AHV Gateway collect across all hosts")
  ap.add_argument(
      "--ahv_gateway_class_timeout_secs", type=int, default=300,
      help="Per-class HTTP timeout when streaming a bugtool tarball")
  ap.add_argument(
      "--ahv_gateway_workers", type=int, default=8,
      help="Parallel PE hypervisor AHV Gateway collects")
  ap.add_argument(
      "--ahv_gateway_port", type=int, default=7030,
      help="AHV Gateway HTTPS port")
  ap.add_argument(
      "--ahv_gateway_cert_dir", default="/home/certs/ClusterHealthService",
      help="Directory with <name>.crt and <name>.key for AHV Gateway mTLS")
  ap.add_argument(
      "--cmsp_ovn_timeout_secs", type=int, default=1800,
      help="Retry budget for CMSP kubectl OVN NB/SB collect")
  ap.add_argument(
      "--cmsp_ovn_namespace", default="",
      help="Kubernetes namespace for ANC/OVN pods. Empty searches all")
  ap.add_argument(
      "--atlas_timeout_secs", type=int, default=1800,
      help="Timeout for atlas_cli port_set.list and the port_set.get batch")
  ap.add_argument(
      "--atlas_get_workers", type=int, default=32,
      help="Parallel atlas_cli port_set.get processes")
  return ap


def _need_flow_venv(script):
  sys.stderr.write(
      "FlowInterfaces is not importable. Collect AG/SG/EG/policies with:\n"
      "  %s %s --output_dir %s\n"
      "Use --skip_flow only for idfcli+OVN+OVS+atlas without policies.\n"
      % (FLOW_PYTHON, script, DEFAULT_OUTPUT))


def main(argv=None):
  argv = list(sys.argv if argv is None else argv)
  script = argv[0] if argv else "flow_pc_dump.py"
  parser = build_parser()
  args, _unknown = parser.parse_known_args(argv[1:])

  if HERE not in sys.path:
    sys.path.insert(0, HERE)
  from flow_pc_dump_for_neo4j import (
      FLAGS, FlowInterfaces, dump_pc, gflags, split_from_json)

  # Parse gflags before FlowInterfaces() (Zeus UnparsedFlagAccessError).
  if gflags is not None:
    try:
      parsed = False
      try:
        parsed = FLAGS.IsParsed()
      except Exception:
        parsed = False
      if not parsed:
        FLAGS(argv)
    except gflags.FlagsError as err:
      sys.stderr.write("%s\n%s\n" % (err, FLAGS))
      parser.print_help()
      return 1
  for name in (
      "ahv_gateway_class_timeout_secs", "ahv_gateway_workers",
      "ahv_gateway_port", "ahv_gateway_cert_dir", "cmsp_ovn_namespace"):
    setattr(FLAGS, name, getattr(args, name))

  if args.from_json:
    return split_from_json(
        args.from_json,
        args.output_dir or DEFAULT_OUTPUT,
        combined_path=args.output or "",
        log_file=args.log_file or "",
        workers=max(1, int(args.workers)))

  if not args.skip_flow and FlowInterfaces is None:
    _need_flow_venv(script)
    return 1

  flow_timeout = max(600, int(args.dataset_timeout_secs))
  return dump_pc(
      args.output_dir or DEFAULT_OUTPUT,
      workers=max(1, int(args.workers)),
      skip_idf=bool(args.skip_idfcli),
      skip_ahv=bool(args.skip_ahv_gateway),
      skip_cmsp=bool(args.skip_cmsp_ovn),
      skip_atlas=bool(args.skip_atlas),
      skip_flow=bool(args.skip_flow),
      ahv_gw_timeout=max(60, int(args.ahv_gateway_timeout_secs)),
      cmsp_ovn_timeout=max(60, int(args.cmsp_ovn_timeout_secs)),
      atlas_timeout=max(60, int(args.atlas_timeout_secs)),
      atlas_get_workers=max(1, int(args.atlas_get_workers)),
      idf_timeout=max(60, int(args.dataset_timeout_secs)),
      flow_timeout=flow_timeout,
      fail_on_error=bool(args.fail_on_error),
      log_file=args.log_file or "",
      combined_path=args.output or "")


if __name__ == "__main__":
  sys.exit(main(sys.argv))
