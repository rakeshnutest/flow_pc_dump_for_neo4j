#!/usr/bin/env python
"""Dump idfcli, OVN, OVS, and atlas_cli. No FlowInterfaces or convert.

Run on PCVM with system python3 (no flow venv):
  python3 flow_pc_dump.py --output_dir /home/nutanix/upgrade/flow_pc_dump

Writes:
  idfcli/<entity_type>.json and .txt
  ahv_gateway/   (OVS via AHV Gateway mTLS :7030)
  cmsp_ovn/      (OVN NB/SB via kubectl ovsdb-client dump)
  port_set_list.json / port_set_get.json  (atlas_cli)

Convert and ingest off-PC with flow_pc_process.py.
"""
import sys

from flow_pc_dump_for_neo4j import main

if __name__ == "__main__":
  sys.exit(main(sys.argv))
