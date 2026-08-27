#!/usr/bin/env python
#
# Copyright (c) 2026 Nutanix Inc. All rights reserved.
#
# PC dump (system python3, no flow venv): idfcli + OVN + OVS + atlas_cli.
#   python3 flow_pc_dump.py --output_dir /tmp/flow_pc_dump
# Outside PC (this workstation): parse/convert/ingest. Never FlowInterfaces
# on the PC. atlas_cli port_set.list/get run on the PC during dump.
#   python3 flow_pc_process.py --dump_dir /tmp/flow_pc_dump --ingest
#
# Host OVS/OVN/virsh is collected from PC via AHV Gateway (mTLS :7030),
# never SSH to AHV. Per PE hypervisor, the dump loops until these exist:
#   ovs-vsctl show, ovs-dpctl -s show, ovs-ofctl dump-flows brAtlas
#   (plus other brAtlas ofctl outputs), virsh list --all, virsh dumpxml
#   (tap/MAC), tap devices, OVN/OVS DB (ovn*.db / conf.db).
# Classes: networking + avm (+ ovn if the gateway advertises it).
# Cert: /home/certs/ClusterHealthService/ (ClusterHealthService).
#
# Where files land:
#   AHV Gateway: <output_dir>/ahv_gateway/<hypervisor_ip>/
#   CMSP OVN:    <output_dir>/cmsp_ovn/{anc-ovn,anc-ovn-ic-db,anc-policydb}/
# On CMSP, OVN Northbound/Southbound live in kubectl pods on the PC
# (anc-ovn-0 / container anc-ovn), not on AHV. Collect with:
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
# Do not pass -it (this dump has no TTY). Loop until both dumps exist.
#

import codecs
import hashlib
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import zlib
import tarfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
try:
  from urllib.request import Request, urlopen
except ImportError:
  from urllib2 import Request, urlopen

class _FlagBag(object):
  output_dir = "/tmp/flow_pc_dump"
  output = ""
  log_file = ""
  from_json = ""
  workers = 16
  dataset_timeout_secs = 180
  fail_on_error = False
  skip_atlas = False
  atlas_timeout_secs = 1800
  atlas_get_workers = 32
  skip_ahv_gateway = False
  ahv_gateway_timeout_secs = 1800
  ahv_gateway_class_timeout_secs = 300
  ahv_gateway_workers = 8
  ahv_gateway_port = 7030
  ahv_gateway_cert_dir = "/home/certs/ClusterHealthService"
  skip_idfcli = False
  skip_cmsp_ovn = False
  cmsp_ovn_timeout_secs = 1800
  cmsp_ovn_namespace = ""

  def __call__(self, argv):
    return argv


class _EnumStub(object):
  def __init__(self, **names):
    self.__dict__.update(names)

  def Name(self, value):
    for name, number in self.__dict__.items():
      if number == value:
        return name
    raise ValueError(value)


try:
  import gflags
  import flow.common.flags  # pylint: disable=unused-import
  from flow.common.interfaces import FlowInterfaces
  from flow.flow_types_pb2 import (
      AllowedEntity,
      CategoryEntitySelectionType,
      ExceptEntity,
      NetworkSecurityPolicyMode,
      NetworkSecurityPolicyScope,
      NetworkSecurityPolicyType,
      RegexMatchEntity,
  )
  FLAGS = gflags.FLAGS
  gflags.DEFINE_string(
      "output_dir", "/tmp/flow_pc_dump",
      "Directory for idfcli/, ahv_gateway/ (OVS), and cmsp_ovn/ (OVN).")
  gflags.DEFINE_string(
      "output", "",
      "Combined JSON path. Default: <output_dir>/all.json")
  gflags.DEFINE_string(
      "log_file", "",
      "Log file path. Default: <output_dir>/dump.log")
  gflags.DEFINE_string(
      "from_json", "",
      "If set, skip fetch and split this combined JSON into output_dir files.")
  gflags.DEFINE_integer(
      "workers", 16,
      "Parallel worker count for dataset fetch, conversion, and writes.")
  gflags.DEFINE_integer(
      "dataset_timeout_secs", 180,
      "Per-idfcli-type timeout.")
  gflags.DEFINE_boolean(
      "fail_on_error", False,
      "If true, exit non-zero when any dataset fetch fails.")
  gflags.DEFINE_boolean(
      "skip_atlas", False,
      "Skip atlas_cli port_set.list and port_set.get.")
  gflags.DEFINE_integer(
      "atlas_timeout_secs", 1800,
      "Timeout for atlas_cli port_set.list and the port_set.get batch.")
  gflags.DEFINE_integer(
      "atlas_get_workers", 32,
      "Parallel atlas_cli port_set.get processes.")
  gflags.DEFINE_boolean(
      "skip_ahv_gateway", False,
      "Skip AHV Gateway host collect (OVS/virsh/tap/brAtlas/OVN DB).")
  gflags.DEFINE_integer(
      "ahv_gateway_timeout_secs", 1800,
      "Deadline for AHV Gateway collect across all hosts.")
  gflags.DEFINE_integer(
      "ahv_gateway_class_timeout_secs", 300,
      "Per-class HTTP timeout when streaming a bugtool tarball.")
  gflags.DEFINE_integer(
      "ahv_gateway_workers", 8,
      "Parallel PE hypervisor AHV Gateway collects.")
  gflags.DEFINE_integer(
      "ahv_gateway_port", 7030,
      "AHV Gateway HTTPS port.")
  gflags.DEFINE_string(
      "ahv_gateway_cert_dir",
      "/home/certs/ClusterHealthService",
      "Directory with <name>.crt and <name>.key for AHV Gateway mTLS.")
  gflags.DEFINE_boolean(
      "skip_idfcli", False,
      "Skip idfcli entity dumps.")
  gflags.DEFINE_boolean(
      "skip_cmsp_ovn", False,
      "Skip CMSP kubectl OVN Northbound/Southbound dump.")
  gflags.DEFINE_integer(
      "cmsp_ovn_timeout_secs", 1800,
      "Retry budget for CMSP kubectl OVN NB/SB collect.")
  gflags.DEFINE_string(
      "cmsp_ovn_namespace", "",
      "Kubernetes namespace for ANC/OVN pods. Empty searches all namespaces.")
except ImportError:
  gflags = None
  FlowInterfaces = None
  FLAGS = _FlagBag()
  AllowedEntity = _EnumStub(
      kVmByCategoryUuid=1,
      kSubnetByCategoryUuid=2,
      kVpcByCategoryUuid=3,
      kKubeClusterByUuid=4,
      kKubeNamespaceByName=5,
      kKubePodsByLabels=6,
      kKubeServiceByName=7,
      kAddressGroupByUuid=8,
      kAddressGroupByValue=9,
      kAddressGroupByFqdn=10,
      kVmByUuid=11,
      kVmNameByRegex=12,
      kSubnetByUuid=13,
  )
  RegexMatchEntity = _EnumStub(
      kContains=1, kStartsWith=2, kEndsWith=3, kEquals=4)
  CategoryEntitySelectionType = _EnumStub(kVM=1, kVPC=2, kSubnet=3)
  ExceptEntity = _EnumStub(kAddressGroupByValue=1)
  NetworkSecurityPolicyType = _EnumStub(
      kAPPLICATION=1, kISOLATION=2, kQUARANTINE=3)
  NetworkSecurityPolicyMode = _EnumStub(
      kSAVE=1, kMONITOR=2, kENFORCE=3)
  NetworkSecurityPolicyScope = _EnumStub(
      kALL_VLAN=1, kVPC=2, kGLOBAL=3)

LOG = logging.getLogger("flow_pc_dump")

# neo4j_db_insert.py create_vpc_map / ALL_VLAN scope
ALL_VLAN_VPC_UUID = "00000000-0000-0000-0000-000000000001"
ALL_VLAN_VPC_NAME = "VLAN"
DEFAULT_PROJECT_UUID = "00000000-0000-0000-0000-000000000000"

# AtlasNetworkFunction insertion_type / ha_mode / fallback_mode ints.
NF_TRAFFIC = {1: "INLINE", 2: "VTAP"}
NF_HA = {1: "ACTIVE_PASSIVE", 2: "ACTIVE_ACTIVE"}
NF_FAIL = {1: "BLOCK", 2: "PASS"}

ALLOWED_SELECT = {
    AllowedEntity.kVmByCategoryUuid: ("VM", "CATEGORY_EXT_ID"),
    AllowedEntity.kSubnetByCategoryUuid: ("SUBNET", "CATEGORY_EXT_ID"),
    AllowedEntity.kVpcByCategoryUuid: ("VPC", "CATEGORY_EXT_ID"),
    AllowedEntity.kKubeClusterByUuid: ("KUBE_CLUSTER", "EXT_ID"),
    AllowedEntity.kKubeNamespaceByName: ("KUBE_NAMESPACE", "NAME"),
    AllowedEntity.kKubePodsByLabels: ("KUBE_PODS", "NAME"),
    AllowedEntity.kKubeServiceByName: ("KUBE_SERVICE", "NAME"),
    AllowedEntity.kAddressGroupByUuid: ("ADDRESS_GROUP", "EXT_ID"),
    AllowedEntity.kAddressGroupByValue: ("ADDRESS_GROUP", "NAME"),
    AllowedEntity.kAddressGroupByFqdn: ("ADDRESS_GROUP", "NAME"),
    AllowedEntity.kVmByUuid: ("VM", "EXT_ID"),
    AllowedEntity.kVmNameByRegex: ("VM", "REGEX"),
    AllowedEntity.kSubnetByUuid: ("SUBNET", "EXT_ID"),
}

REGEX_MATCH = {
    RegexMatchEntity.kContains: "CONTAINS",
    RegexMatchEntity.kStartsWith: "STARTS_WITH",
    RegexMatchEntity.kEndsWith: "ENDS_WITH",
    RegexMatchEntity.kEquals: "EQUALS",
}

CAT_ENTITY = {
    CategoryEntitySelectionType.kVM: "VM",
    CategoryEntitySelectionType.kVPC: "VPC",
    CategoryEntitySelectionType.kSubnet: "SUBNET",
}

FLEX_DIR = {1: "INBOUND", 2: "OUTBOUND", 3: "IN_OUT"}
FLEX_ACTION = {1: "ALLOW", 2: "DENY", 3: "REJECT"}
IP_VERSION = {1: "IPV4", 2: "IPV6", 3: "IPV4_IPV6"}
APP_DIR = {1: "INBOUND", 2: "OUTBOUND"}


def _setup_logging(log_file=None):
  log_format = logging.Formatter(
      "%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
  root = logging.getLogger()
  root.setLevel(logging.INFO)
  for handler in list(root.handlers):
    root.removeHandler(handler)
  stream = logging.StreamHandler(sys.stdout)
  stream.setFormatter(log_format)
  root.addHandler(stream)
  if log_file:
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(log_format)
    root.addHandler(file_handler)


def _uuid_str(value):
  if value is None or value == "" or value == b"":
    return None
  if hasattr(value, "hex"):
    hex_str = value.hex
    if len(hex_str) == 32:
      return "%s-%s-%s-%s-%s" % (
          hex_str[0:8], hex_str[8:12], hex_str[12:16],
          hex_str[16:20], hex_str[20:32])
    return str(value)
  if isinstance(value, (bytes, bytearray)):
    raw = bytes(value)
    if len(raw) == 16:
      return _uuid_str(uuid.UUID(bytes=raw))
    try:
      return _uuid_str(raw.decode("utf-8"))
    except Exception:
      return None
  text = str(value).strip()
  if not text:
    return None
  compact = text.replace("-", "")
  if len(compact) == 32:
    return "%s-%s-%s-%s-%s" % (
        compact[0:8], compact[8:12], compact[12:16],
        compact[16:20], compact[20:32])
  return text


def _uuid_list(values):
  out = []
  for value in values or []:
    converted = _uuid_str(value)
    if converted:
      out.append(converted)
  return out


def _camel_upper(raw, default=""):
  text = str(raw or "")
  if text.startswith("k") and len(text) > 1 and text[1].isupper():
    text = text[1:]
  pieces = []
  for idx, char in enumerate(text):
    if idx and char.isupper() and (
        text[idx - 1].islower() or
        (idx + 1 < len(text) and text[idx + 1].islower())):
      pieces.append("_")
    pieces.append(char.upper())
  return "".join(pieces) or default


def _enum_name(enum_cls, value, default=""):
  if value is None or value == 0:
    return default
  try:
    raw = enum_cls.Name(int(value))
  except Exception:
    return default
  return _camel_upper(raw, default)


def _enum_label(msg, *fields, default="unknown"):
  for field in fields:
    if msg is None or not hasattr(msg, field):
      continue
    value = getattr(msg, field)
    if value in (None, "", 0):
      continue
    try:
      enum_type = msg.DESCRIPTOR.fields_by_name[field].enum_type
      if enum_type is not None:
        raw = enum_type.values_by_number[int(value)].name
        return _camel_upper(raw, default)
    except Exception:
      pass
    text = str(value)
    if text.isdigit():
      continue
    return _camel_upper(text, default)
  return default


def _nf_enum(value, mapping, default="unknown"):
  if value in (None, ""):
    return default
  try:
    number = int(value)
    if number in mapping:
      return mapping[number]
  except (TypeError, ValueError):
    pass
  label = _camel_upper(value, default)
  if label in mapping.values():
    return label
  return default if label == default else label


def _has(msg, field):
  try:
    return msg.HasField(field)
  except Exception:
    return bool(getattr(msg, field, None))


def _item_proto(item):
  return getattr(item, "proto", item)


def _item_uuid(item, proto=None):
  if hasattr(item, "uuid") and item.uuid:
    return _uuid_str(item.uuid)
  proto = proto or _item_proto(item)
  return _uuid_str(getattr(proto, "uuid", None))


def _iter_manager(manager):
  if manager is None:
    return []
  for name in ("iter_all", "iter", "list", "get_all"):
    method = getattr(manager, name, None)
    if callable(method):
      result = method()
      if result is None:
        return []
      return list(result)
  return []


def _get_manager(interfaces, *names):
  for name in names:
    try:
      manager = getattr(interfaces, name)
      if manager is not None:
        return manager
    except Exception as err:
      LOG.debug("manager %s unavailable: %s", name, err)
  return None


def _log_matching_managers(interfaces, needle):
  names = []
  for name in dir(interfaces):
    if needle in name.lower() and not name.startswith("_"):
      names.append(name)
  LOG.info("FlowInterfaces matching %r: %s", needle, names or "<none>")


def _project_fields(proto):
  project_uuid = _uuid_str(
      getattr(proto, "project_uuid", None)
      or getattr(proto, "project_id", None)
      or getattr(proto, "projectExtId", None)
      or getattr(proto, "project_ext_id", None))
  shared = bool(
      getattr(proto, "shared_with_all_projects", False)
      or getattr(proto, "sharedWithAllProjects", False))
  data = {
      "shared_with_all_projects": shared,
      "sharedWithAllProjects": shared,
  }
  if project_uuid:
    data["project_ext_id"] = project_uuid
    data["projectExtId"] = project_uuid
    data["project"] = {"ext_id": project_uuid}
  return data


def _row_project_id(row):
  if not isinstance(row, dict):
    return None
  for name in ("project_uuid", "project_id", "project_reference"):
    uid = _uuid_str(row.get(name))
    if uid:
      return uid
  project = row.get("project")
  if isinstance(project, dict):
    return _uuid_str(project.get("ext_id") or project.get("uuid") or project.get("id"))
  return _uuid_str(project)


def _project_blob(entity):
  if not isinstance(entity, dict):
    return None
  blob = entity.get("project")
  if isinstance(blob, dict) and blob.get("ext_id"):
    data = dict(blob)
    uid = data["ext_id"]
    if not data.get("name"):
      name = entity.get("project_name")
      if name:
        data["name"] = name
    return data
  uid = _uuid_str(entity.get("project_ext_id") or entity.get("projectExtId"))
  if uid:
    return _project_ref(uid, entity.get("project_name") or "")
  return None


def _cidr_from_subnet(subnet_msg):
  if subnet_msg is None:
    return None
  value = getattr(subnet_msg, "network_address", None)
  prefix = getattr(subnet_msg, "prefix", None)
  if not value:
    return None
  return {"value": str(value), "prefix_length": int(prefix or 0)}


def _parse_cidr_string(cidr):
  if not cidr:
    return None
  text = str(cidr).strip()
  if "/" in text:
    value, prefix = text.split("/", 1)
    try:
      prefix_length = int(prefix)
    except ValueError:
      prefix_length = 0
    return {"value": value, "prefix_length": prefix_length}
  return {"value": text, "prefix_length": 0}


def _ip_group_to_v4(ip_group):
  ipv4_addresses = []
  ipv6_addresses = []
  ip_ranges = []
  ipv4_ranges = []
  if ip_group is None:
    return ipv4_addresses, ip_ranges, ipv6_addresses, ipv4_ranges
  for subnet in getattr(ip_group, "subnets", []) or []:
    converted = _cidr_from_subnet(subnet)
    if converted:
      ipv4_addresses.append(converted)
  for subnet in getattr(ip_group, "ipv6_subnets", []) or []:
    converted = _cidr_from_subnet(subnet)
    if converted:
      ipv6_addresses.append(converted)
  for ip_range in getattr(ip_group, "ranges", []) or []:
    start_ip = getattr(ip_range, "start_address", None)
    end_ip = getattr(ip_range, "end_address", None)
    if start_ip and end_ip:
      row = {"start_ip": str(start_ip), "end_ip": str(end_ip)}
      ip_ranges.append(row)
      ipv4_ranges.append(row)
  return ipv4_addresses, ip_ranges, ipv6_addresses, ipv4_ranges


def convert_address_group(item):
  proto = _item_proto(item)
  ipv4_addresses = []
  ipv6_addresses = []
  ip_ranges = []
  for subnet in getattr(proto, "subnets", []) or []:
    converted = _cidr_from_subnet(subnet)
    if converted:
      ipv4_addresses.append(converted)
  for block in getattr(proto, "ip_address_block_list", []) or []:
    converted = _parse_cidr_string(block)
    if converted:
      ipv4_addresses.append(converted)
  for subnet in getattr(proto, "ipv6_subnets", []) or []:
    converted = _cidr_from_subnet(subnet)
    if converted:
      ipv6_addresses.append(converted)
  for ip_range in getattr(proto, "ranges", []) or []:
    start_ip = getattr(ip_range, "start_address", None)
    end_ip = getattr(ip_range, "end_address", None)
    if start_ip and end_ip:
      ip_ranges.append({"start_ip": str(start_ip), "end_ip": str(end_ip)})
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "ipv4_addresses": ipv4_addresses,
      "ipv6_addresses": ipv6_addresses,
      "ip_ranges": ip_ranges,
      "fqdns": [str(fqdn) for fqdn in (
          getattr(proto, "fqdn_addresses", None)
          or getattr(proto, "fqdns", None) or [])],
  }
  data.update(_project_fields(proto))
  return data


def _port_row(start_port, end_port, all_allowed=False):
  row = {
      "start_port": int(start_port or 0),
      "end_port": int(end_port if end_port is not None else start_port or 0),
  }
  if all_allowed:
    row["is_all_allowed"] = True
  return row


def _icmp_row(icmp_type=None, icmp_code=None, all_allowed=False):
  row = {
      "type": icmp_type if icmp_type is not None else 0,
      "code": icmp_code if icmp_code is not None else 0,
      "start_port": icmp_type if icmp_type is not None else 0,
      "end_port": icmp_type if icmp_type is not None else 0,
  }
  if all_allowed:
    row["is_all_allowed"] = True
  return row


def _all_ports_spec_fields(action="DENY_ALL"):
  """neo4j parse_rule isolation / allow-all / INTRA_GROUP with no services."""
  return {
      "is_all_protocol_allowed": True,
      "tcp_services": [_port_row(0, 65535, True)],
      "udp_services": [_port_row(0, 65535, True)],
      "icmp_services": [_icmp_row(all_allowed=True)],
      "icmp_v6_services": [_icmp_row(all_allowed=True)],
      "secured_group_action": action,
  }


def _all_ports_service_detail(action="DENY_ALL"):
  return {
      "name": "ALL",
      "is_all_protocol_allowed": True,
      "tcpPort": ["0-65535"],
      "udpPort": ["0-65535"],
      "icmpTypes": ["any:any"],
      "icmpv6Types": ["any:any"],
      "tcp_services": [_port_row(0, 65535, True)],
      "udp_services": [_port_row(0, 65535, True)],
      "icmp_services": [_icmp_row(all_allowed=True)],
      "icmp_v6_services": [_icmp_row(all_allowed=True)],
      "secured_group_action": [action],
  }


def _service_lists_from_service_list(service_list):
  tcp_services = []
  udp_services = []
  icmp_services = []
  icmp_v6_services = []
  for service in service_list or []:
    protocol = getattr(service, "protocol", 0)
    protocol_name = str(protocol)
    try:
      protocol_name = service.Protocol.Name(protocol)
    except Exception:
      pass
    all_allowed = protocol_name in ("kALL", "kAll", "1") or protocol in (1,)
    port_ranges = list(getattr(service, "port_range_list", []) or [])
    tcp_ranges = list(getattr(service, "tcp_port_range_list", []) or []) or (
        port_ranges if protocol_name in ("kTCP", "3") or protocol == 3 else [])
    udp_ranges = list(getattr(service, "udp_port_range_list", []) or []) or (
        port_ranges if protocol_name in ("kUDP", "4") or protocol == 4 else [])
    if all_allowed:
      tcp_services.append(_port_row(0, 65535, True))
      udp_services.append(_port_row(0, 65535, True))
      icmp_services.append(_icmp_row(all_allowed=True))
      icmp_v6_services.append(_icmp_row(all_allowed=True))
      continue
    for port in tcp_ranges:
      tcp_services.append(_port_row(
          getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    for port in udp_ranges:
      udp_services.append(_port_row(
          getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    if protocol == 3 and not tcp_ranges and port_ranges:
      for port in port_ranges:
        tcp_services.append(_port_row(
            getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    if protocol == 4 and not udp_ranges and port_ranges:
      for port in port_ranges:
        udp_services.append(_port_row(
            getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    for icmp in getattr(service, "icmp_type_code_list", []) or []:
      icmp_services.append(_icmp_row(
          getattr(icmp, "icmp_type", 0), getattr(icmp, "icmp_code", 0)))
    for icmp in getattr(service, "icmp_v6_type_code_list", []) or []:
      icmp_v6_services.append(_icmp_row(
          getattr(icmp, "icmp_type", 0), getattr(icmp, "icmp_code", 0)))
  return tcp_services, udp_services, icmp_services, icmp_v6_services


def convert_service_group(item):
  proto = _item_proto(item)
  tcp_services, udp_services, icmp_services, icmp_v6_services = (
      _service_lists_from_service_list(getattr(proto, "service_list", [])))
  if not tcp_services:
    starts = list(getattr(proto, "tcp_start_port_list", []) or [])
    ends = list(getattr(proto, "tcp_end_port_list", []) or [])
    for idx, start in enumerate(starts):
      tcp_services.append(_port_row(start, ends[idx] if idx < len(ends) else start))
  if not udp_services:
    starts = list(getattr(proto, "udp_start_port_list", []) or [])
    ends = list(getattr(proto, "udp_end_port_list", []) or [])
    for idx, start in enumerate(starts):
      udp_services.append(_port_row(start, ends[idx] if idx < len(ends) else start))
  if not icmp_services:
    types = list(getattr(proto, "icmp_type_list", []) or [])
    codes = list(getattr(proto, "icmp_code_list", []) or [])
    for idx, icmp_type in enumerate(types):
      icmp_services.append(_icmp_row(
          icmp_type, codes[idx] if idx < len(codes) else 0))
  if not icmp_v6_services:
    types = list(getattr(proto, "icmp_v6_type_list", []) or [])
    codes = list(getattr(proto, "icmp_v6_code_list", []) or [])
    for idx, icmp_type in enumerate(types):
      icmp_v6_services.append(_icmp_row(
          icmp_type, codes[idx] if idx < len(codes) else 0))
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "tcp_services": tcp_services,
      "udp_services": udp_services,
      "icmp_services": icmp_services,
      "icmp_v6_services": icmp_v6_services,
  }
  data.update(_project_fields(proto))
  return data


def _convert_allowed_entity(entity):
  select_type = getattr(entity, "select_type_enum", None)
  entity_type, select_by = ALLOWED_SELECT.get(select_type, ("UNKNOWN", "EXT_ID"))
  raw_refs = list(getattr(entity, "reference_uuids", []) or [])
  uuids = []
  names = []
  for item in raw_refs:
    uid = _uuid_str(item)
    if uid:
      uuids.append(uid)
    else:
      text = str(item).strip() if item is not None else ""
      if text:
        names.append(text)
  for attr in ("reference_names", "names", "name_list"):
    extra = getattr(entity, attr, None)
    if extra:
      names.extend(str(item).strip() for item in extra if str(item).strip())
  row = {
      "type": entity_type,
      "select_by": select_by,
      "reference_ext_ids": uuids,
      "kube_entities": [str(item) for item in (getattr(entity, "kube_entities", []) or [])],
      "fqdns": [str(item) for item in (getattr(entity, "fqdn_addresses", []) or [])],
  }
  if names:
    row["reference_names"] = names
  regex = getattr(entity, "regex_match_entity", None)
  pattern = ""
  criteria = ""
  if regex is not None:
    pattern = (
        getattr(regex, "reference_string", None)
        or getattr(regex, "regex_string", None)
        or getattr(regex, "pattern", None)
        or "")
    match_type = getattr(regex, "match_type", None)
    criteria = REGEX_MATCH.get(match_type, "")
    if not criteria:
      try:
        criteria = REGEX_MATCH.get(int(match_type), "")
      except Exception:
        criteria = str(getattr(regex, "match_criteria", "") or "")
  if not pattern:
    pattern = str(getattr(entity, "reference_string", "") or "")
  if pattern:
    row["reference_string"] = str(pattern)
    row["match_criteria"] = str(criteria or "EQUALS")
  elif select_by == "REGEX":
    row["reference_string"] = ""
    row["match_criteria"] = str(criteria or "EQUALS")
  if _has(entity, "ip_address_group"):
    ipv4_addresses, ip_ranges, ipv6_addresses, ipv4_ranges = _ip_group_to_v4(
        entity.ip_address_group)
    row["addresses"] = {
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
    }
    row["ip_ranges"] = {"ipv4_ranges": ipv4_ranges}
  return row


def _convert_except_entity(entity):
  row = {
      "type": "ADDRESS_GROUP",
      "select_by": "EXT_ID",
      "reference_ext_ids": _uuid_list(getattr(entity, "reference_uuids", [])),
  }
  if getattr(entity, "select_type_enum", None) == ExceptEntity.kAddressGroupByValue:
    row["select_by"] = "NAME"
  if _has(entity, "ip_address_group"):
    ipv4_addresses, ip_ranges, ipv6_addresses, ipv4_ranges = _ip_group_to_v4(
        entity.ip_address_group)
    row["addresses"] = {
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
    }
    row["ip_ranges"] = {"ipv4_ranges": ipv4_ranges}
  return row


def convert_entity_group(item):
  proto = _item_proto(item)
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "is_system_eg": bool(getattr(proto, "is_system_eg", False)),
      "allowed_config": {
          "entities": [
              _convert_allowed_entity(entity)
              for entity in (getattr(proto, "allowed_entities", []) or [])
          ]
      },
      "except_config": {
          "entities": [
              _convert_except_entity(entity)
              for entity in (getattr(proto, "except_entities", []) or [])
          ]
      },
  }
  data.update(_project_fields(proto))
  return data


def _services_to_spec(services):
  spec = {
      "service_group_references": [],
      "tcp_services": [],
      "udp_services": [],
      "icmp_services": [],
      "icmp_v6_services": [],
      "is_all_protocol_allowed": False,
  }
  for service in services or []:
    sg_uuid = _uuid_str(getattr(service, "service_group_uuid", None))
    if sg_uuid:
      spec["service_group_references"].append(sg_uuid)
    protocol = getattr(service, "protocol", 0)
    if protocol in (1,):
      spec["is_all_protocol_allowed"] = True
      spec["tcp_services"].append(_port_row(0, 65535, True))
      spec["udp_services"].append(_port_row(0, 65535, True))
      spec["icmp_services"].append(_icmp_row(all_allowed=True))
      spec["icmp_v6_services"].append(_icmp_row(all_allowed=True))
      continue
    port_ranges = list(getattr(service, "port_range_list", []) or [])
    if protocol == 3:
      for port in port_ranges:
        spec["tcp_services"].append(_port_row(
            getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    elif protocol == 4:
      for port in port_ranges:
        spec["udp_services"].append(_port_row(
            getattr(port, "start_port", 0), getattr(port, "end_port", 0)))
    for icmp in getattr(service, "icmp_type_code_list", []) or []:
      spec["icmp_services"].append(_icmp_row(
          getattr(icmp, "icmp_type", 0), getattr(icmp, "icmp_code", 0)))
    for icmp in getattr(service, "icmp_v6_type_code_list", []) or []:
      spec["icmp_v6_services"].append(_icmp_row(
          getattr(icmp, "icmp_type", 0), getattr(icmp, "icmp_code", 0)))
  if not spec["service_group_references"]:
    spec.pop("service_group_references")
  return spec


def _endpoint_to_side(endpoint, side):
  spec = {}
  if endpoint is None:
    return spec
  allow_type = getattr(endpoint, "allow_type", 0)
  allow_name = ""
  try:
    allow_name = str(endpoint.AllowType.Name(allow_type) or "")
  except Exception:
    allow_name = str(allow_type)
  # Integer 1 is the first named proto value (often address-group), not
  # kAllowAll. Only the enum name is allow-any; that peer has no AG/EG/cat.
  if allow_name in ("kAllowAll", "kALL", "ALL", "kAllowAny"):
    spec["should_allow_any_src" if side == "src" else "should_allow_any_dst"] = True
    spec["src_allow_spec" if side == "src" else "dest_allow_spec"] = "ALL"
    return spec
  if allow_name in ("kAllowNone", "kNONE", "NONE"):
    spec["src_allow_spec" if side == "src" else "dest_allow_spec"] = "NONE"
    return spec
  ag_uuid = _uuid_str(getattr(endpoint, "address_group_uuid", None))
  if ag_uuid:
    spec["%s_address_group_references" % side] = [ag_uuid]
  eg_list = _uuid_list(getattr(endpoint, "entity_group_uuid_list", []))
  if eg_list:
    spec["%s_entity_group_references" % side] = eg_list
    spec["%s_entity_group_reference" % side] = eg_list[0]
  cidr = getattr(endpoint, "ip_subnet", None) or getattr(endpoint, "ipv6_subnet", None)
  parsed = _parse_cidr_string(cidr) if cidr else None
  if parsed:
    spec["%s_subnet" % side] = parsed
  if _has(endpoint, "endpoint_entity"):
    entity = endpoint.endpoint_entity
    categories = _uuid_list(getattr(entity, "category_uuid_list", []))
    if categories:
      spec["%s_category_references" % side] = categories
      spec["%s_category_associated_entity_type" % side] = CAT_ENTITY.get(
          getattr(entity, "category_selection_type", None), "VM")
  return spec


def _secured_group_to_spec(secured):
  spec = {}
  if secured is None:
    return spec
  eg_list = _uuid_list(getattr(secured, "entity_group_uuid_list", []))
  if eg_list:
    spec["secured_group_entity_group_reference"] = eg_list[0]
  categories = _uuid_list(getattr(secured, "category_uuid_list", []))
  if categories:
    spec["secured_group_category_references"] = categories
    spec["secured_group_category_associated_entity_type"] = CAT_ENTITY.get(
        getattr(secured, "category_selection_type", None), "VM")
  return spec


def _base_rule(rule_info, rule_type, spec):
  return {
      "ext_id": _uuid_str(getattr(rule_info, "uuid", None)) or _uuid_str(
          getattr(rule_info, "unique_id", None)) or str(uuid.uuid4()),
      "type": rule_type,
      "description": getattr(rule_info, "description", "") or "",
      "name": getattr(rule_info, "rule_name", "") or "",
      "spec": spec,
  }


def _set_ip_version(msg, spec):
  ip_version = IP_VERSION.get(getattr(msg, "rule_ip_version", 0) or 0)
  if not ip_version:
    ip_version = IP_VERSION.get(getattr(msg, "ip_version", 0) or 0)
  if ip_version:
    spec["ip_version"] = ip_version
  return spec


def _convert_application_rule(app_rule, fallback_type="APPLICATION"):
  rule_info = app_rule.rule_info if _has(app_rule, "rule_info") else None
  spec = {}
  spec.update(_secured_group_to_spec(
      app_rule.secured_group if _has(app_rule, "secured_group") else None))
  direction = APP_DIR.get(getattr(app_rule, "direction", 0), "INBOUND")
  spec["direction"] = direction
  side = "src" if direction == "INBOUND" else "dest"
  spec.update(_endpoint_to_side(
      app_rule.endpoint if _has(app_rule, "endpoint") else None, side))
  spec.update(_services_to_spec(getattr(app_rule, "services", [])))
  nf_uuid = _uuid_str(getattr(app_rule, "network_function_uuid", None))
  if nf_uuid:
    spec["network_function_reference"] = nf_uuid
  _set_ip_version(app_rule, spec)
  return _base_rule(rule_info, fallback_type, spec)


def _convert_flex_rule(flex_rule):
  rule_info = flex_rule.rule_info if _has(flex_rule, "rule_info") else None
  spec = {
      "direction": FLEX_DIR.get(getattr(flex_rule, "direction", 0), "IN_OUT"),
      "action": FLEX_ACTION.get(getattr(flex_rule, "action", 0), "ALLOW"),
      "priority": getattr(flex_rule, "rule_priority", 0) or 0,
  }
  _set_ip_version(flex_rule, spec)
  spec.update(_endpoint_to_side(
      flex_rule.src_endpoint if _has(flex_rule, "src_endpoint") else None, "src"))
  spec.update(_endpoint_to_side(
      flex_rule.dest_endpoint if _has(flex_rule, "dest_endpoint") else None, "dest"))
  if _has(flex_rule, "should_allow_any_src") and getattr(
      flex_rule, "should_allow_any_src", False):
    spec["should_allow_any_src"] = True
  if _has(flex_rule, "should_allow_any_dst") and getattr(
      flex_rule, "should_allow_any_dst", False):
    spec["should_allow_any_dst"] = True
  applied = _uuid_list(getattr(flex_rule, "applied_to_entity_group_uuid_list", []))
  if not applied:
    one = _uuid_str(getattr(flex_rule, "applied_to_entity_group_uuid", None))
    if one:
      applied = [one]
  if applied:
    spec["applied_to_entity_group_references"] = applied
  spec.update(_services_to_spec(getattr(flex_rule, "services", [])))
  nf_uuid = _uuid_str(getattr(flex_rule, "network_function_uuid", None))
  if nf_uuid:
    spec["network_function_reference"] = nf_uuid
  return _base_rule(rule_info, "FLEX", spec)


def _convert_secured_group_rule(sg_rule):
  rule_info = sg_rule.rule_info if _has(sg_rule, "rule_info") else None
  spec = _secured_group_to_spec(
      sg_rule.secured_group if _has(sg_rule, "secured_group") else None)
  spec["secured_group_action"] = str(getattr(sg_rule, "action", "") or "ALLOW")
  spec.update(_services_to_spec(getattr(sg_rule, "services", [])))
  if spec.get("service_group_references"):
    spec["secured_group_service_references"] = spec["service_group_references"]
  return _base_rule(rule_info, "INTRA_GROUP", spec)


def _convert_two_env_rule(iso_rule):
  rule_info = iso_rule.rule_info if _has(iso_rule, "rule_info") else None
  first = iso_rule.first_secured_group if _has(iso_rule, "first_secured_group") else None
  second = iso_rule.second_secured_group if _has(iso_rule, "second_secured_group") else None
  spec = {
      "first_isolation_group": _uuid_list(
          getattr(first, "category_uuid_list", []) if first else []),
      "second_isolation_group": _uuid_list(
          getattr(second, "category_uuid_list", []) if second else []),
  }
  spec.update(_all_ports_spec_fields("DENY_ALL"))
  return _base_rule(rule_info, "TWO_ENV_ISOLATION", spec)


def _convert_multi_env_rule(iso_rule):
  rule_info = iso_rule.rule_info if _has(iso_rule, "rule_info") else None
  groups = []
  if _has(iso_rule, "all_to_all_isolation_group"):
    for group in getattr(iso_rule.all_to_all_isolation_group, "isolation_group_list", []) or []:
      eg_list = _uuid_list(getattr(group, "entity_group_uuid_list", []))
      row = {
          "group_category_references": _uuid_list(
              getattr(group, "category_uuid_list", [])),
          "group_category_associated_entity_type": CAT_ENTITY.get(
              getattr(group, "category_selection_type", None), "VM"),
      }
      if eg_list:
        row["group_entity_group_reference"] = eg_list[0]
      groups.append(row)
  spec = {"spec": {"isolation_groups": groups}}
  spec.update(_all_ports_spec_fields("DENY_ALL"))
  return _base_rule(rule_info, "MULTI_ENV_ISOLATION", spec)


def convert_rule(rule):
  if _has(rule, "flex_policy_rule"):
    return _convert_flex_rule(rule.flex_policy_rule)
  if _has(rule, "secured_group_rule"):
    return _convert_secured_group_rule(rule.secured_group_rule)
  if _has(rule, "isolation_rule"):
    return _convert_two_env_rule(rule.isolation_rule)
  if _has(rule, "multi_env_isolation_rule"):
    return _convert_multi_env_rule(rule.multi_env_isolation_rule)
  if _has(rule, "quarantine_rule"):
    return _convert_application_rule(rule.quarantine_rule, "APPLICATION")
  if _has(rule, "shared_services_rule"):
    return _convert_application_rule(rule.shared_services_rule, "APPLICATION")
  if _has(rule, "application_rule"):
    return _convert_application_rule(rule.application_rule, "APPLICATION")
  return None


def _iter_rules_map(proto):
  rules_map = getattr(proto, "rules_map", None)
  if not rules_map:
    return []
  if hasattr(rules_map, "items"):
    try:
      return [value for _, value in rules_map.items()]
    except Exception:
      pass
  out = []
  for entry in rules_map:
    if hasattr(entry, "value"):
      out.append(entry.value)
    else:
      out.append(entry)
  return out


def convert_policy(item):
  proto = _item_proto(item)
  options = proto.options if _has(proto, "options") else None
  rules = []
  for rule in _iter_rules_map(proto):
    converted = convert_rule(rule)
    if converted:
      rules.append(converted)
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "type": _enum_name(NetworkSecurityPolicyType, getattr(proto, "policy_type", 0), "APPLICATION"),
      "state": _enum_name(NetworkSecurityPolicyMode, getattr(proto, "mode", 0), "SAVE"),
      "scope": _enum_name(NetworkSecurityPolicyScope, getattr(proto, "scope", 0), "ALL_VLAN"),
      "vpc_references": _uuid_list(getattr(proto, "vpc_uuid_list", [])),
      "scope_references": _uuid_list(getattr(proto, "reference_uuid_list", [])),
      "priority": getattr(proto, "policy_priority", 0) or 0,
      "is_ipv6_traffic_allowed": bool(
          getattr(options, "allow_ipv6_traffic", False) if options else False),
      "is_ipv4_address_scope": bool(
          getattr(options, "ipv4_address_scope", False) if options else False),
      "is_ipv6_address_scope": bool(
          getattr(options, "ipv6_address_scope", False) if options else False),
      "is_logging_enabled": bool(
          getattr(options, "is_policy_hitlog_enabled", False) if options else False),
      "rules": rules,
  }
  if getattr(proto, "vpc_uuid", None):
    vpc_uuid = _uuid_str(proto.vpc_uuid)
    if vpc_uuid and vpc_uuid not in data["vpc_references"]:
      data["vpc_references"].append(vpc_uuid)
  data.update(_project_fields(proto))
  return {"data": data}


def _dump_manager(label, manager, converter):
  LOG.info("DUMP start %s", label)
  items = _iter_manager(manager)
  LOG.info("DUMP listed %s raw %s objects", label, len(items))
  rows = [None] * len(items)

  def _convert_one(idx_item):
    idx, item = idx_item
    try:
      rows[idx] = converter(item)
    except Exception as err:
      LOG.error("DUMP convert failed %s idx=%s: %s", label, idx, err)
      LOG.debug(traceback.format_exc())

  if items:
    workers = min(max(1, int(getattr(FLAGS, "workers", 8))), len(items), 16)
    with ThreadPoolExecutor(max_workers=workers) as pool:
      list(pool.map(_convert_one, enumerate(items)))
  rows = [row for row in rows if row is not None]
  LOG.info("DUMP done %s count=%s", label, len(rows))
  return rows


def fetch_address_groups(interfaces):
  manager = _get_manager(interfaces, "address_group_manager")
  return _dump_manager("address_groups", manager, convert_address_group)


def fetch_service_groups(interfaces):
  manager = _get_manager(
      interfaces, "service_group_manager", "network_service_group_manager")
  return _dump_manager("service_groups", manager, convert_service_group)


def fetch_entity_groups(interfaces):
  manager = _get_manager(
      interfaces, "entity_group_manager", "network_entity_group_manager")
  return _dump_manager("entity_groups", manager, convert_entity_group)


def fetch_policies(interfaces):
  manager = _get_manager(
      interfaces, "network_security_policy_manager", "policy_manager")
  return _dump_manager("policies", manager, convert_policy)


def _run_timeout(func, timeout_secs, default, label):
  """Run func in a daemon thread; abandon it if it exceeds timeout_secs."""
  box = []

  def _target():
    try:
      box.append(("ok", func()))
    except Exception as err:
      box.append(("err", err))

  thread = threading.Thread(target=_target, name="dump-%s" % label)
  thread.daemon = True
  thread.start()
  thread.join(timeout_secs)
  if thread.is_alive():
    LOG.error("DUMP timeout %s after %ss; abandoning hung worker",
              label, timeout_secs)
    return default, "timeout after %ss" % timeout_secs
  if not box:
    return default, "no result"
  status, value = box[0]
  if status == "err":
    return default, str(value)
  return value, None


def _call_first(obj, names, *args, **kwargs):
  if obj is None:
    return None
  for name in names:
    method = getattr(obj, name, None)
    if callable(method):
      try:
        LOG.info("trying %s.%s", type(obj).__name__, name)
        return method(*args, **kwargs)
      except TypeError:
        try:
          return method()
        except Exception as err:
          LOG.debug("%s.%s failed: %s", type(obj).__name__, name, err)
      except Exception as err:
        LOG.debug("%s.%s failed: %s", type(obj).__name__, name, err)
  return None


def _unwrap_list(payload):
  if payload is None:
    return []
  if isinstance(payload, list):
    return payload
  if isinstance(payload, dict):
    for key in ("data", "entities", "items", "value", "results"):
      if key in payload and isinstance(payload[key], list):
        return payload[key]
  if hasattr(payload, "__iter__") and not isinstance(payload, (str, bytes, dict)):
    try:
      return list(payload)
    except Exception:
      return []
  return []


def _idfcli_bin():
  for path in (
      "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
      "/home/nutanix/bin/idfcli",
      "/usr/local/nutanix/bin/idfcli"):
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "idfcli"


_IDF_RESULTS = {}
_IDF_RAW = {}
_IDF_LOCKS = {}
_IDF_GUARD = threading.Lock()
# If set, _idfcli_one reads <dir>/<entity_type>.json instead of running idfcli.
_IDF_FILE_DIR = ""

# Every IDF entity type this dump collects. Process maps these later.
IDF_DUMP_TYPES = (
    "vm", "mh_vm", "ahv_vm", "virtual_nic",
    "virtual_network", "subnet", "vpc", "virtual_private_cloud",
    "node", "host", "ahv_host", "cluster",
    "project", "projects", "iam_project", "xi_project", "abac_project",
    "abac_category", "category",
    "abac_entity_capability", "volume_group_entity_capability",
    "atlas_network_function", "network_function", "flow_network_function",
    "fns_fqdn_to_ip_info",
    "address_group", "network_address_group",
    "service_group", "network_service_group",
    "entity_group", "network_entity_group",
    "network_security_policy", "security_policy",
)


def _idfcli_one(entity_type, timeout=180):
  with _IDF_GUARD:
    lock = _IDF_LOCKS.setdefault(entity_type, threading.Lock())
  with lock:
    cached = _IDF_RESULTS.get(entity_type)
    if cached is not None:
      parsed, err = cached
      LOG.info("DUMP idfcli entitytype %s cached=%s", entity_type, len(parsed))
      return cached
    file_dir = _IDF_FILE_DIR
    if file_dir:
      json_path = os.path.join(file_dir, "%s.json" % entity_type)
      txt_path = os.path.join(file_dir, "%s.txt" % entity_type)
      # Service groups only have ports in IDF __zprotobuf__; prefer .txt.
      prefer_txt = entity_type in (
          "network_service_group", "service_group",
          "network_security_policy", "security_policy")
      if prefer_txt and os.path.isfile(txt_path):
        try:
          with open(txt_path, "r") as handle:
            parsed = _parse_idf_entities(handle.read())
        except Exception as exc:
          parsed, err = [], "%s: %s" % (entity_type, exc)
          _IDF_RESULTS[entity_type] = (parsed, err)
          return _IDF_RESULTS[entity_type]
        LOG.info("DUMP idfcli entitytype %s from txt count=%s",
                 entity_type, len(parsed))
        _IDF_RESULTS[entity_type] = (parsed, None)
        return _IDF_RESULTS[entity_type]
      if os.path.isfile(json_path):
        try:
          with open(json_path, "r") as handle:
            parsed = _idf_loaded_rows(json.load(handle))
        except Exception as exc:
          parsed, err = [], "%s: %s" % (entity_type, exc)
          _IDF_RESULTS[entity_type] = (parsed, err)
          return _IDF_RESULTS[entity_type]
        LOG.info("DUMP idfcli entitytype %s from file count=%s",
                 entity_type, len(parsed))
        _IDF_RESULTS[entity_type] = (parsed, None)
        return _IDF_RESULTS[entity_type]
      if os.path.isfile(txt_path):
        try:
          with open(txt_path, "r") as handle:
            parsed = _parse_idf_entities(handle.read())
        except Exception as exc:
          parsed, err = [], "%s: %s" % (entity_type, exc)
          _IDF_RESULTS[entity_type] = (parsed, err)
          return _IDF_RESULTS[entity_type]
        LOG.info("DUMP idfcli entitytype %s from txt count=%s",
                 entity_type, len(parsed))
        _IDF_RESULTS[entity_type] = (parsed, None)
        return _IDF_RESULTS[entity_type]
      _IDF_RESULTS[entity_type] = ([], "%s: not in dump" % entity_type)
      return _IDF_RESULTS[entity_type]
    LOG.info("DUMP idfcli entitytype %s", entity_type)
    err = None
    parsed = []
    try:
      proc = subprocess.run(
          [_idfcli_bin(), "get", "entitytype", "-e", entity_type],
          capture_output=True, text=True, check=False, timeout=timeout)
      text = proc.stdout or ""
      _IDF_RAW[entity_type] = text
      if proc.returncode != 0 and not text:
        err = "%s: %s" % (entity_type, (proc.stderr or "").strip()[:200])
      else:
        parsed = _parse_idf_entities(text)
    except Exception as exc:
      err = "%s: %s" % (entity_type, exc)
    LOG.info("DUMP idfcli %s parsed=%s", entity_type, len(parsed))
    _IDF_RESULTS[entity_type] = (parsed, err)
    return _IDF_RESULTS[entity_type]


def _idf_loaded_rows(parsed):
  if isinstance(parsed, list):
    return parsed
  if isinstance(parsed, dict):
    for key in ("entities", "entity", "data"):
      val = parsed.get(key)
      if isinstance(val, list):
        return val
      if isinstance(val, dict) and val:
        return [val]
  return []


def _idf_unquote(raw):
  try:
    return codecs.decode(raw, "unicode_escape")
  except Exception:
    return raw


def _idf_bytes_raw(raw):
  text = _idf_unquote(raw)
  if isinstance(text, bytes):
    return text
  try:
    return text.encode("latin-1")
  except Exception:
    return text.encode("utf-8", "replace")


def _idf_bytes_to_value(raw):
  data = _idf_bytes_raw(raw)
  if len(data) == 16:
    return _uuid_str(data) or data.hex()
  decoded = data.decode("utf-8", "replace")
  return _uuid_str(decoded) or decoded


def _parse_idf_entities(text):
  entities = []
  blocks = re.split(r"^entity:\s*<", text or "", flags=re.MULTILINE)
  for block in blocks:
    if not block.strip():
      continue
    attrs = {}
    guid = re.search(r'entity_id:\s*"([^"]+)"', block)
    if not guid:
      guid = re.search(r'uuid:\s*"([^"]+)"', block)
    if guid:
      attrs["ext_id"] = _uuid_str(guid.group(1)) or guid.group(1)
    for match in re.finditer(
        r'attribute_data_map:\s*<\s*name:\s*"([^"]+)"(.*?)(?=attribute_data_map:|\Z)',
        block, re.DOTALL):
      name = match.group(1)
      body = match.group(2)
      str_list = re.findall(r'value_list:\s*"([^"]*)"', body)
      str_val = re.search(r'str_value:\s*"([^"]*)"', body)
      int_val = re.search(r'int64_value:\s*(-?\d+)', body)
      bool_val = re.search(r'bool_value:\s*(true|false)', body)
      bytes_list = re.findall(r'bytes_value:\s*"((?:\\.|[^"\\])*)"', body)
      if str_list:
        attrs[name] = [
            _uuid_str(item) or _idf_unquote(item) for item in str_list]
      elif len(bytes_list) > 1:
        attrs[name] = [_idf_bytes_to_value(item) for item in bytes_list]
      elif str_val:
        attrs[name] = _uuid_str(str_val.group(1)) or str_val.group(1)
      elif bytes_list:
        if name == "__zprotobuf__":
          attrs[name] = _idf_bytes_raw(bytes_list[0])
        else:
          attrs[name] = _idf_bytes_to_value(bytes_list[0])
      elif int_val:
        attrs[name] = int(int_val.group(1))
      elif bool_val:
        attrs[name] = bool_val.group(1) == "true"
    if attrs:
      entities.append(attrs)
  return entities


def _zprotobuf_bytes(value):
  if not value:
    return b""
  if isinstance(value, (bytes, bytearray)):
    return bytes(value)
  if isinstance(value, str):
    try:
      return value.encode("latin-1")
    except Exception:
      return value.encode("utf-8", "replace")
  return b""


def _zlib_decompress(data):
  if not data:
    return b""
  for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
    try:
      return zlib.decompress(data, wbits)
    except Exception:
      continue
  return data


def _proto_read_varint(buf, idx):
  value = 0
  shift = 0
  n = len(buf or b"")
  while idx < n:
    byte = buf[idx]
    idx += 1
    value |= (byte & 0x7F) << shift
    if byte < 0x80:
      return value, idx
    shift += 7
    if shift > 63:
      break
  return None, idx


def _proto_decode(buf):
  """Protobuf wire fields: field_number -> list of (wire_type, value)."""
  fields = {}
  idx = 0
  n = len(buf or b"")
  while idx < n:
    key, idx = _proto_read_varint(buf, idx)
    if key is None:
      break
    field_n = key >> 3
    wire = key & 7
    if wire == 0:
      val, idx = _proto_read_varint(buf, idx)
      if val is None:
        break
    elif wire == 1:
      val = buf[idx:idx + 8]
      idx += 8
    elif wire == 2:
      length, idx = _proto_read_varint(buf, idx)
      if length is None:
        break
      val = buf[idx:idx + length]
      idx += length
    elif wire == 5:
      val = buf[idx:idx + 4]
      idx += 4
    else:
      break
    fields.setdefault(field_n, []).append((wire, val))
  return fields


def _proto_varints(items):
  nums = []
  for wire, val in items or []:
    if wire == 0 and val is not None:
      nums.append(int(val))
    elif wire == 2 and val:
      idx = 0
      while idx < len(val):
        num, idx = _proto_read_varint(val, idx)
        if num is None:
          break
        nums.append(int(num))
  return nums


def _proto_bytes_list(fields, number):
  out = []
  for wire, val in fields.get(number) or []:
    if val and (wire == 2 or isinstance(val, (bytes, bytearray))):
      out.append(bytes(val))
  return out


def _proto_first_varint(fields, number, default=0):
  nums = _proto_varints(fields.get(number) or [])
  return nums[0] if nums else default


def _proto_str(fields, number):
  items = _proto_bytes_list(fields, number)
  if not items:
    return ""
  return items[0].decode("utf-8", "replace")


def _proto_str_list(fields, number):
  return [item.decode("utf-8", "replace") for item in _proto_bytes_list(fields, number)]


def _proto_first_bytes(fields, number):
  items = _proto_bytes_list(fields, number)
  return items[0] if items else b""


class _Attr(object):
  def __init__(self, **kwargs):
    self.__dict__.update(kwargs)


_NSG_PROTO_NAMES = {
    1: "kAll",
    2: "kICMP",
    3: "kTCP",
    4: "kUDP",
    5: "kICMPv6",
}


def _nsg_port_objs(fields, number):
  rows = []
  for raw in _proto_bytes_list(fields, number):
    inner = _proto_decode(raw)
    start = _proto_first_varint(inner, 1, 0)
    end = _proto_first_varint(inner, 2, start)
    rows.append(_Attr(start_port=start, end_port=end))
  return rows


def _nsg_icmp_objs(fields, number):
  rows = []
  for raw in _proto_bytes_list(fields, number):
    inner = _proto_decode(raw)
    rows.append(_Attr(
        icmp_type=_proto_first_varint(inner, 1, 0),
        icmp_code=_proto_first_varint(inner, 2, 0)))
  return rows


def _nsg_service_obj(raw):
  fields = _proto_decode(raw)
  protocol = _proto_first_varint(fields, 1, 0)

  def _proto_name(value, names=_NSG_PROTO_NAMES):
    return names.get(int(value or 0), str(value))

  return _Attr(
      protocol=protocol,
      Protocol=_Attr(Name=_proto_name),
      port_range_list=_nsg_port_objs(fields, 2),
      icmp_type_code_list=_nsg_icmp_objs(fields, 3),
      tcp_port_range_list=_nsg_port_objs(fields, 4),
      udp_port_range_list=_nsg_port_objs(fields, 5),
      icmp_v6_type_code_list=_nsg_icmp_objs(fields, 6),
  )


def _service_lists_from_zprotobuf(raw):
  data = _zprotobuf_bytes(raw)
  if not data:
    return [], [], [], []
  fields = _proto_decode(_zlib_decompress(data))
  services = [_nsg_service_obj(item) for item in _proto_bytes_list(fields, 6)]
  tcp, udp, icmp, icmp6 = _service_lists_from_service_list(services)
  if not tcp:
    starts = _proto_varints(fields.get(8) or [])
    ends = _proto_varints(fields.get(9) or [])
    for idx, start in enumerate(starts):
      tcp.append(_port_row(start, ends[idx] if idx < len(ends) else start))
  if not udp:
    starts = _proto_varints(fields.get(10) or [])
    ends = _proto_varints(fields.get(11) or [])
    for idx, start in enumerate(starts):
      udp.append(_port_row(start, ends[idx] if idx < len(ends) else start))
  if not icmp:
    types = _proto_varints(fields.get(12) or [])
    codes = _proto_varints(fields.get(13) or [])
    for idx, icmp_type in enumerate(types):
      icmp.append(_icmp_row(icmp_type, codes[idx] if idx < len(codes) else 0))
  if not icmp6:
    types = _proto_varints(fields.get(14) or [])
    codes = _proto_varints(fields.get(15) or [])
    for idx, icmp_type in enumerate(types):
      icmp6.append(_icmp_row(
          icmp_type, codes[idx] if idx < len(codes) else 0))
  return tcp, udp, icmp, icmp6


def _inflate_nsg_zprotobuf(row):
  if not isinstance(row, dict):
    return row
  has_ports = (
      row.get("tcp_services") or row.get("udp_services") or
      row.get("icmp_services") or row.get("icmp_v6_services") or
      row.get("tcp_start_port_list") or row.get("udp_start_port_list"))
  raw = row.get("__zprotobuf__")
  if has_ports or not raw:
    row.pop("__zprotobuf__", None)
    return row
  try:
    tcp, udp, icmp, icmp6 = _service_lists_from_zprotobuf(raw)
  except Exception:
    row.pop("__zprotobuf__", None)
    return row
  if tcp:
    row["tcp_services"] = tcp
  if udp:
    row["udp_services"] = udp
  if icmp:
    row["icmp_services"] = icmp
  if icmp6:
    row["icmp_v6_services"] = icmp6
  row.pop("__zprotobuf__", None)
  return row


class _AllowType(object):
  @staticmethod
  def Name(value):
    return {1: "kTypeAll", 2: "kTypeNone"}.get(int(value or 0), str(value))


def _attr_base_rule_info(raw):
  fields = _proto_decode(raw or b"")
  return _Attr(
      uuid=_proto_str(fields, 1),
      description=_proto_str(fields, 2),
      unique_id=_proto_first_varint(fields, 7, 0),
      rule_name=_proto_str(fields, 8),
  )


def _attr_secured_group(raw):
  if not raw:
    return None
  fields = _proto_decode(raw)
  return _Attr(
      category_uuid_list=_proto_str_list(fields, 1),
      uuid=_proto_str(fields, 2),
      unique_id=_proto_first_varint(fields, 3, 0),
      entity_group_uuid_list=_proto_str_list(fields, 4),
      category_selection_type=_proto_first_varint(fields, 5, 0),
  )


def _attr_endpoint(raw):
  if not raw:
    return None
  fields = _proto_decode(raw)
  entity = None
  ent_raw = _proto_first_bytes(fields, 1)
  if ent_raw:
    ent_fields = _proto_decode(ent_raw)
    entity = _Attr(
        category_uuid_list=_proto_str_list(ent_fields, 1),
        category_selection_type=_proto_first_varint(ent_fields, 2, 0),
    )
  return _Attr(
      endpoint_entity=entity,
      ip_subnet=_proto_str(fields, 2),
      address_group_uuid=_proto_str(fields, 3),
      allow_type=_proto_first_varint(fields, 4, 0),
      AllowType=_AllowType,
      entity_group_uuid_list=_proto_str_list(fields, 5),
      ipv6_subnet=_proto_str(fields, 6),
  )


def _attr_rule_services(raw):
  fields = _proto_decode(raw or b"")
  ports = []
  for item in _proto_bytes_list(fields, 2):
    inner = _proto_decode(item)
    ports.append(_Attr(
        start_port=_proto_first_varint(inner, 1, 0),
        end_port=_proto_first_varint(inner, 2, 0)))
  icmp = []
  for item in _proto_bytes_list(fields, 3):
    inner = _proto_decode(item)
    icmp.append(_Attr(
        icmp_type=_proto_first_varint(inner, 1, 0),
        icmp_code=_proto_first_varint(inner, 2, 0)))
  icmp6 = []
  for item in _proto_bytes_list(fields, 5):
    inner = _proto_decode(item)
    icmp6.append(_Attr(
        icmp_type=_proto_first_varint(inner, 1, 0),
        icmp_code=_proto_first_varint(inner, 2, 0)))
  return _Attr(
      protocol=_proto_first_varint(fields, 1, 0),
      port_range_list=ports,
      icmp_type_code_list=icmp,
      service_group_uuid=_proto_str(fields, 4),
      icmp_v6_type_code_list=icmp6,
  )


def _attr_application_rule(raw):
  fields = _proto_decode(raw or b"")
  return _Attr(
      rule_info=_attr_base_rule_info(_proto_first_bytes(fields, 1)),
      secured_group=_attr_secured_group(_proto_first_bytes(fields, 2)),
      endpoint=_attr_endpoint(_proto_first_bytes(fields, 3)),
      services=[_attr_rule_services(item) for item in _proto_bytes_list(fields, 4)],
      direction=_proto_first_varint(fields, 5, 0),
      network_function_uuid=_proto_str(fields, 7),
  )


def _attr_two_env_rule(raw):
  fields = _proto_decode(raw or b"")
  return _Attr(
      rule_info=_attr_base_rule_info(_proto_first_bytes(fields, 1)),
      first_secured_group=_attr_secured_group(_proto_first_bytes(fields, 2)),
      second_secured_group=_attr_secured_group(_proto_first_bytes(fields, 3)),
  )


def _attr_multi_env_rule(raw):
  fields = _proto_decode(raw or b"")
  groups = []
  all_raw = _proto_first_bytes(fields, 3)
  if all_raw:
    inner = _proto_decode(all_raw)
    groups = [
        _attr_secured_group(item) for item in _proto_bytes_list(inner, 1)]
  return _Attr(
      rule_info=_attr_base_rule_info(_proto_first_bytes(fields, 1)),
      isolation_type=_proto_first_varint(fields, 2, 0),
      all_to_all_isolation_group=_Attr(isolation_group_list=groups),
  )


def _attr_secured_group_rule(raw):
  fields = _proto_decode(raw or b"")
  return _Attr(
      rule_info=_attr_base_rule_info(_proto_first_bytes(fields, 1)),
      secured_group=_attr_secured_group(_proto_first_bytes(fields, 2)),
      action=bool(_proto_first_varint(fields, 3, 0)),
      services=[_attr_rule_services(item) for item in _proto_bytes_list(fields, 4)],
  )


def _attr_flex_rule(raw):
  fields = _proto_decode(raw or b"")
  return _Attr(
      rule_info=_attr_base_rule_info(_proto_first_bytes(fields, 1)),
      src_endpoint=_attr_endpoint(_proto_first_bytes(fields, 2)),
      dest_endpoint=_attr_endpoint(_proto_first_bytes(fields, 3)),
      services=[_attr_rule_services(item) for item in _proto_bytes_list(fields, 4)],
      action=_proto_first_varint(fields, 5, 0),
      direction=_proto_first_varint(fields, 6, 0),
      rule_priority=_proto_first_varint(fields, 7, 0),
      network_function_uuid=_proto_str(fields, 9),
      applied_to_entity_group_uuid_list=_proto_str_list(fields, 10),
      rule_ip_version=_proto_first_varint(fields, 11, 0),
  )


def _attr_rule(raw):
  fields = _proto_decode(raw or b"")
  kwargs = {}
  app = _proto_first_bytes(fields, 1)
  if app:
    kwargs["application_rule"] = _attr_application_rule(app)
  iso = _proto_first_bytes(fields, 2)
  if iso:
    kwargs["isolation_rule"] = _attr_two_env_rule(iso)
  quar = _proto_first_bytes(fields, 3)
  if quar:
    kwargs["quarantine_rule"] = _attr_application_rule(quar)
  sgr = _proto_first_bytes(fields, 4)
  if sgr:
    kwargs["secured_group_rule"] = _attr_secured_group_rule(sgr)
  multi = _proto_first_bytes(fields, 5)
  if multi:
    kwargs["multi_env_isolation_rule"] = _attr_multi_env_rule(multi)
  shared = _proto_first_bytes(fields, 6)
  if shared:
    kwargs["shared_services_rule"] = _attr_application_rule(shared)
  flex = _proto_first_bytes(fields, 7)
  if flex:
    kwargs["flex_policy_rule"] = _attr_flex_rule(flex)
  return _Attr(**kwargs)


def _rules_from_policy_zprotobuf(raw):
  data = _zprotobuf_bytes(raw)
  if not data:
    return None
  fields = _proto_decode(_zlib_decompress(data))
  rules = []
  for entry_raw in _proto_bytes_list(fields, 6):
    entry = _proto_decode(entry_raw)
    value = _proto_first_bytes(entry, 2)
    if not value:
      continue
    converted = convert_rule(_attr_rule(value))
    if converted:
      rules.append(converted)
  return rules


def _idfcli_entities(entity_types):
  rows = []
  errors = []
  for entity_type in entity_types:
    parsed, err = _idfcli_one(entity_type)
    if err:
      errors.append(err)
    if parsed:
      rows.extend(parsed)
      break
  return rows, errors


def dump_idfcli(output_dir, workers=8, timeout=180):
  """Run idfcli get entitytype for every IDF_DUMP_TYPES and write JSON."""
  dest = os.path.join(output_dir, "idfcli")
  os.makedirs(dest, exist_ok=True)
  index = {
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "entity_types": {},
  }
  errors = {}

  def _one(entity_type):
    parsed, err = _idfcli_one(entity_type, timeout=timeout)
    rows = parsed or []
    if entity_type in ("network_service_group", "service_group"):
      for row in rows:
        _inflate_nsg_zprotobuf(row)
    else:
      for row in rows:
        if isinstance(row, dict):
          row.pop("__zprotobuf__", None)
    path = os.path.join(dest, "%s.json" % entity_type)
    _write_json_file(path, rows)
    raw = _IDF_RAW.get(entity_type) or ""
    if raw:
      txt_path = os.path.join(dest, "%s.txt" % entity_type)
      with open(txt_path, "w") as handle:
        handle.write(raw)
    return entity_type, len(rows), err

  LOG.info("DUMP idfcli types=%s workers=%s", len(IDF_DUMP_TYPES), workers)
  with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
    futs = [pool.submit(_one, entity_type) for entity_type in IDF_DUMP_TYPES]
    for fut in futs:
      entity_type, count, err = fut.result()
      index["entity_types"][entity_type] = {
          "count": count,
          "error": err or "",
          "file": "%s.json" % entity_type,
      }
      if err:
        errors["idfcli:%s" % entity_type] = err
        LOG.warning("idfcli %s: %s", entity_type, err)
      else:
        LOG.info("idfcli %s count=%s", entity_type, count)
  _write_json_file(os.path.join(dest, "index.json"), index)
  LOG.info("DUMP idfcli wrote %s types under %s", len(IDF_DUMP_TYPES), dest)
  return index, errors


def _first_attr(row, *names, default=None):
  for name in names:
    if row.get(name) not in (None, "", []):
      return row.get(name)
  return default


def _as_list(value):
  if value is None:
    return []
  if isinstance(value, list):
    return value
  return [value]


def _as_bool(value, default=False):
  if value is None or value == "":
    return default
  if isinstance(value, bool):
    return value
  if isinstance(value, (int, float)):
    return bool(value)
  text = str(value).strip().lower()
  if text in ("true", "1", "yes"):
    return True
  if text in ("false", "0", "no"):
    return False
  return default


def _subnet_type_name(value, vpc_ref=None, vlan_id=None):
  text = "" if value in (None, "") else str(value).strip()
  upper = text.upper().lstrip("K")
  if upper in ("VLAN", "0"):
    return "VLAN"
  if upper in ("OVERLAY", "1"):
    return "OVERLAY"
  if vpc_ref:
    return "OVERLAY"
  if vlan_id not in (None, "", 0, "0"):
    return "VLAN"
  return text or "VLAN"


def _looks_uuid(text):
  text = str(text or "").strip()
  return len(text) == 36 and text.count("-") == 4


def _prefer_human_key(old, new):
  old = str(old or "").strip()
  new = str(new or "").strip()
  if new and not _looks_uuid(new):
    return new
  if old and not _looks_uuid(old):
    return old
  return new or old


def _category_ids_from_row(row):
  raw = _first_attr(row, "category_id_list", "category_ids", "categories", default=[])
  ids = []
  for item in _as_list(raw):
    if isinstance(item, dict):
      cat_id = _uuid_str(item.get("ext_id") or item.get("uuid")) or ""
    else:
      cat_id = _uuid_str(item) or str(item)
    if cat_id:
      ids.append(cat_id)
  return ids


def _category_name_map(categories):
  mapping = {}
  for cat in categories or []:
    ext_id = cat.get("ext_id")
    if not ext_id:
      continue
    key = str(cat.get("key") or "").strip()
    value = str(cat.get("value") or "").strip()
    if key and value:
      mapping[ext_id] = "%s:%s" % (key, value)
    elif key:
      mapping[ext_id] = key
    elif value:
      mapping[ext_id] = value
    else:
      mapping[ext_id] = ext_id
  return mapping


def _category_names(ids, cat_map):
  names = []
  seen = set()
  for cat_id in ids or []:
    uid = _uuid_str(cat_id) or str(cat_id)
    name = cat_map.get(uid) or uid
    if name in seen:
      continue
    seen.add(name)
    names.append(name)
  return names


def _vpc_name_from_subnet_name(name):
  text = str(name or "").strip()
  if not text:
    return ""
  lower = text.lower()
  for token in ("_subnet_", "-subnet-"):
    idx = lower.rfind(token)
    if idx > 0:
      return text[:idx]
  return ""


def _vpc_display_name(vpc_ref, subnet_name=None, existing=""):
  """Never return an empty VPC name. ALL_VLAN is VLAN; overlay is inferred."""
  if vpc_ref == ALL_VLAN_VPC_UUID:
    return ALL_VLAN_VPC_NAME
  name = str(existing or "").strip()
  if name and name.lower() not in ("unnamed", "(unnamed)", "none", "null"):
    return name
  inferred = _vpc_name_from_subnet_name(subnet_name)
  if inferred:
    return inferred
  ext = str(vpc_ref or "unknown")
  return "VPC_%s" % ext[:8]


def _all_vlan_vpc():
  return {
      "ext_id": ALL_VLAN_VPC_UUID,
      "name": ALL_VLAN_VPC_NAME,
      "vpc_type": "VLAN",
      "metadata": {"category_ids": []},
      "externally_routable_prefixes": [],
      "external_subnets": [],
  }


def _collect_ips(*groups):
  """Merge IP field lists from IDF, preserving order and dropping empties."""
  out = []
  seen = set()
  for group in groups:
    for ip in _as_list(group):
      text = str(ip).strip()
      if not text or text in seen:
        continue
      seen.add(text)
      out.append(text)
  return out


def _learned_ips(ips):
  ipv4 = []
  ipv6 = []
  for ip in ips or []:
    text = str(ip).strip()
    if not text:
      continue
    if ":" in text:
      ipv6.append({"value": text})
    else:
      ipv4.append({"value": text})
  return ipv4, ipv6


def _project_ref(ext_id, name=""):
  uid = _uuid_str(ext_id)
  if not uid:
    return None
  data = {"ext_id": uid}
  if name:
    data["name"] = str(name)
  return data


def _apply_project(entity, ext_id, name=""):
  blob = _project_ref(ext_id, name)
  if not blob or not isinstance(entity, dict):
    return
  entity["project"] = blob
  entity["project_ext_id"] = blob["ext_id"]
  entity["projectExtId"] = blob["ext_id"]


def _nic_payload(ext_id, mac, subnet_id, ips, project=None):
  ipv4, ipv6 = _learned_ips(ips)
  network = {
      "subnet": {"ext_id": subnet_id} if subnet_id else None,
  }
  if ipv4:
    network["ipv4_info"] = {"learned_ip_addresses": ipv4}
  if ipv6:
    network["ipv6_info"] = {"learned_ipv6_addresses": ipv6}
  if project:
    network["project"] = project
  payload = {
      "ext_id": ext_id or "",
      "nic_backing_info": {"mac_address": mac or ""},
      "nic_network_info": network,
  }
  if project:
    payload["project"] = project
  return payload


def _map_vm(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "vm_uuid", "uuid", "id")) or ""
  name = _first_attr(row, "vm_name", "name", "display_name") or ""
  power = str(_first_attr(row, "power_state", "powerState") or "ON").upper()
  if power in ("POWERED_ON", "ON", "1", "TRUE"):
    power = "ON"
  elif power in ("POWERED_OFF", "OFF", "0", "FALSE"):
    power = "OFF"
  host_id = _uuid_str(_first_attr(
      row, "node", "host_uuid", "node_uuid", "host"))
  project_id = _row_project_id(row)
  nics = []
  ips = _collect_ips(
      row.get("ip_addresses"),
      row.get("ipv4_addresses"),
      row.get("vm_ipv4_addresses"),
      row.get("ipv6_addresses"),
      row.get("vm_ipv6_addresses"))
  subnet_id = _uuid_str(_first_attr(row, "subnet_uuid", "virtual_network_uuid"))
  mac = _first_attr(row, "mac_address", "mac")
  nic_ids = _as_list(_first_attr(row, "virtual_nic_uuids", "nic_uuid", default=[]))
  if ips or subnet_id:
    nics.append(_nic_payload(
        _uuid_str(nic_ids[0]) if nic_ids else "", mac, subnet_id, ips,
        project=_project_ref(project_id)))
  data = {
      "ext_id": ext_id,
      "name": name,
      "power_state": power,
      "metadata": {"category_ids": _category_ids_from_row(row)},
      "categories": [],
      "nics": nics,
  }
  if host_id:
    data["host"] = {"ext_id": host_id}
  if project_id:
    _apply_project(data, project_id)
  return data


def _map_virtual_nic(row):
  project_id = _row_project_id(row)
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "vm": _uuid_str(_first_attr(row, "vm", "vm_uuid")),
      "subnet_id": _uuid_str(_first_attr(
          row, "virtual_network", "subnet_uuid", "network_uuid")),
      "mac": _first_attr(row, "mac_address", "mac") or "",
      "ips": _collect_ips(
          row.get("ipv4_addresses"),
          row.get("assigned_ipv4_addresses"),
          row.get("ipv6_addresses"),
          row.get("assigned_ipv6_addresses"),
          row.get("ip_addresses")),
      "project": _project_ref(project_id),
  }


def _attach_virtual_nics(vms, nic_rows=None, nic_errors=None):
  if nic_rows is None:
    nic_rows, nic_errors = _idf_mapped(("virtual_nic",), _map_virtual_nic)
  for err in nic_errors or []:
    LOG.warning("virtual_nic: %s", err)
  by_vm = {}
  with_subnet = 0
  with_ipv4 = 0
  with_ipv6 = 0
  for nic in nic_rows:
    vm_id = nic.get("vm")
    if not vm_id:
      continue
    payload = _nic_payload(
        nic.get("ext_id"), nic.get("mac"), nic.get("subnet_id"),
        nic.get("ips"), project=nic.get("project"))
    network = payload["nic_network_info"]
    if network.get("subnet"):
      with_subnet += 1
    if network.get("ipv4_info"):
      with_ipv4 += 1
    if network.get("ipv6_info"):
      with_ipv6 += 1
    by_vm.setdefault(vm_id, []).append(payload)
  attached = 0
  for vm in vms:
    nics = by_vm.get(vm.get("ext_id") or "")
    if nics:
      vm["nics"] = nics
      attached += 1
      blob = _project_blob(vm)
      if blob:
        for nic in nics:
          if not nic.get("project"):
            _apply_project(nic, blob["ext_id"], blob.get("name") or "")
            nic.setdefault("nic_network_info", {})["project"] = dict(
                nic.get("project") or blob)
  LOG.info(
      "DUMP virtual_nic mapped=%s vms_attached=%s nics_with_subnet=%s "
      "nics_with_ipv4=%s nics_with_ipv6=%s",
      len(nic_rows), attached, with_subnet, with_ipv4, with_ipv6)
  return vms


def _map_subnet(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  vpc_ref = _uuid_str(_first_attr(
      row, "overlay_network_uuid", "vpc_uuid", "vpc_reference"))
  vlan_id = _first_attr(row, "vlan_id", "vlan")
  cats = _category_ids_from_row(row)
  project_id = _row_project_id(row)
  advanced = _as_bool(_first_attr(
      row, "is_advanced_networking", "advanced_networking",
      "advance_vlan", "is_advanced"), False)
  subnet_type = _subnet_type_name(
      _first_attr(row, "subnet_type", "type"), vpc_ref, vlan_id)
  if not advanced:
    subnet_type = "VLAN"
    if not vpc_ref:
      vpc_ref = ALL_VLAN_VPC_UUID
  elif not vpc_ref and subnet_type == "VLAN":
    vpc_ref = ALL_VLAN_VPC_UUID
  data = {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "subnet_name") or "",
      "subnet_type": subnet_type,
      "vpc_reference": vpc_ref,
      "vlan_id": vlan_id,
      "is_advanced_networking": advanced,
      "metadata": {"category_ids": cats},
  }
  if project_id:
    _apply_project(data, project_id)
  return data


def _map_vpc(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  cats = _category_ids_from_row(row)
  project_id = _row_project_id(row)
  data = {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "vpc_name") or "",
      "vpc_type": _first_attr(row, "vpc_type", "type") or "REGULAR",
      "metadata": {"category_ids": cats},
      "externally_routable_prefixes": [],
      "external_subnets": [],
  }
  if project_id:
    _apply_project(data, project_id)
  return data


def _map_host(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id", "node_uuid")) or ""
  ip_addr = _first_attr(row, "ip_address", "hypervisor_ip", "external_ip") or ""
  cluster_id = _uuid_str(_first_attr(row, "cluster_uuid", "cluster_id", "cluster")) or ""
  return {
      "ext_id": ext_id,
      "host_name": _first_attr(row, "host_name", "name", "node_name") or "",
      "hypervisor": {"external_address": {"ipv4": {"value": str(ip_addr)}}},
      "cluster": {"uuid": cluster_id},
  }


def _map_cluster(row):
  ext_id = _uuid_str(_first_attr(
      row, "ext_id", "uuid", "id", "cluster_uuid", "clusterUuid")) or ""
  ip_addr = _first_attr(
      row,
      "ip_address", "external_ip", "cluster_external_ip",
      "cluster_external_ip_address", "external_ip_address",
      "cluster_external_address", "clusterExternalIPAddress",
      "cluster_ip", "external_address") or ""
  if isinstance(ip_addr, dict):
    nested = _first_attr(ip_addr, "ipv4", "value", "ip") or ""
    if isinstance(nested, dict):
      nested = nested.get("value") or ""
    ip_addr = nested
  return {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "cluster_name", "clusterName") or "",
      "network": {"external_address": {"ipv4": {"value": str(ip_addr or "")}}},
  }


def _map_project(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  vm_ids = _uuid_list(_as_list(_first_attr(
      row, "vm_uuids", "vm_uuid_list", "virtual_machine_uuids",
      "entity_uuids", "resource_uuids", default=[])))
  data = {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "project_name") or "",
      "vm_ext_ids": vm_ids,
  }
  if ext_id:
    _apply_project(data, ext_id, data.get("name") or "")
  return data


def _map_category(row):
  # abac_category.abac_category_key is the key UUID, not App16. Prefer
  # IDF `category.key` / fq_name (`App16:app5`) for the human key.
  fq = str(_first_attr(row, "fq_name") or "")
  key = _first_attr(row, "key", "category_key") or ""
  value = _first_attr(row, "value", "category_value") or ""
  name = str(_first_attr(row, "name", "user_specified_name") or "")
  if fq and ":" in fq:
    fq_key, fq_val = fq.split(":", 1)
    key = _prefer_human_key(key, fq_key)
    if fq_val and not value:
      value = fq_val
  elif name and ":" in name:
    nkey, nval = name.split(":", 1)
    key = _prefer_human_key(key, nkey)
    if nval and not value:
      value = nval
  elif not value and name and name != key and not _looks_uuid(name):
    value = name
  if not key and name and not _looks_uuid(name) and ":" not in name:
    key = name
  if _looks_uuid(key):
    key = ""
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "key": key,
      "value": value,
  }


def _maybe_json(value):
  if isinstance(value, (list, dict)):
    return value
  text = str(value or "").strip()
  if not text:
    return None
  if text[0] not in "[{":
    return None
  try:
    return json.loads(text)
  except Exception:
    return None


def _port_rows_from_idf(row, kind):
  rows = []
  parsed = _maybe_json(_first_attr(row, "%s_services" % kind, default=None))
  if isinstance(parsed, list):
    for item in parsed:
      if isinstance(item, dict):
        start = item.get("start_port", item.get("start"))
        end = item.get("end_port", item.get("end", start))
        rows.append(_port_row(start, end, bool(item.get("is_all_allowed"))))
      else:
        text = str(item)
        if "-" in text:
          start, end = text.split("-", 1)
          rows.append(_port_row(start, end))
        elif text.isdigit():
          rows.append(_port_row(text, text))
    return rows
  starts = _as_list(_first_attr(row, "%s_start_port_list" % kind, default=[]))
  ends = _as_list(_first_attr(row, "%s_end_port_list" % kind, default=[]))
  for idx, start in enumerate(starts):
    rows.append(_port_row(start, ends[idx] if idx < len(ends) else start))
  return rows


def _icmp_rows_from_idf(row, kind):
  rows = []
  parsed = _maybe_json(_first_attr(row, "%s_services" % kind, default=None))
  if isinstance(parsed, list):
    for item in parsed:
      if isinstance(item, dict):
        rows.append(_icmp_row(
            item.get("type"), item.get("code"),
            bool(item.get("is_all_allowed"))))
    return rows
  types = _as_list(_first_attr(row, "%s_type_list" % kind, default=[]))
  codes = _as_list(_first_attr(row, "%s_code_list" % kind, default=[]))
  for idx, icmp_type in enumerate(types):
    rows.append(_icmp_row(icmp_type, codes[idx] if idx < len(codes) else 0))
  return rows


def _map_address_group(row):
  ipv4 = []
  ipv6 = []
  fqdns = []
  ranges = []
  for item in _as_list(_first_attr(
      row, "ipv4_addresses", "ip_address_block_list", "cidr_list",
      "subnets", default=[])):
    text = str(item).strip()
    if text:
      ipv4.append(text)
  for item in _as_list(_first_attr(row, "ipv6_addresses", "ipv6_subnets", default=[])):
    text = str(item).strip()
    if text:
      ipv6.append(text)
  for item in _as_list(_first_attr(row, "fqdns", "fqdn_addresses", default=[])):
    text = str(item).strip()
    if text:
      fqdns.append(text)
  parsed_ranges = _maybe_json(_first_attr(row, "ip_ranges", "ranges", default=None))
  if isinstance(parsed_ranges, list):
    ranges = parsed_ranges
  elif isinstance(parsed_ranges, dict):
    ranges = parsed_ranges.get("ipv4_ranges") or []
  data = {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name") or "",
      "description": _first_attr(row, "description") or "",
      "ipv4_addresses": ipv4,
      "ipv6_addresses": ipv6,
      "ip_ranges": ranges,
      "fqdns": fqdns,
  }
  project_id = _row_project_id(row)
  if project_id:
    _apply_project(data, project_id)
  return data


def _map_service_group(row):
  if isinstance(row, dict):
    _inflate_nsg_zprotobuf(row)
  data = {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name") or "",
      "description": _first_attr(row, "description") or "",
      "tcp_services": _port_rows_from_idf(row, "tcp"),
      "udp_services": _port_rows_from_idf(row, "udp"),
      "icmp_services": _icmp_rows_from_idf(row, "icmp"),
      "icmp_v6_services": _icmp_rows_from_idf(row, "icmp_v6"),
  }
  project_id = _row_project_id(row)
  if project_id:
    _apply_project(data, project_id)
  return data


def _idf_entity_refs(row, *names):
  ids = []
  seen = set()
  for name in names:
    for item in _as_list(_first_attr(row, name, default=[])):
      uid = _uuid_str(item) or ""
      if uid and uid not in seen:
        seen.add(uid)
        ids.append(uid)
  return ids


def _map_entity_group(row):
  allowed = []
  parsed = _maybe_json(_first_attr(
      row, "allowed_entities", "allowed_config", default=None))
  if isinstance(parsed, dict):
    allowed = list(parsed.get("entities") or [])
  elif isinstance(parsed, list):
    allowed = parsed
  if not allowed:
    cats = _idf_entity_refs(
        row, "category_uuid_list", "allowed_category_uuid_list")
    if cats:
      allowed.append({
          "type": "VM",
          "select_by": "CATEGORY_EXT_ID",
          "reference_ext_ids": cats,
      })
    vms = _idf_entity_refs(row, "vm_uuid_list", "allowed_vm_uuid_list")
    if vms:
      allowed.append({
          "type": "VM",
          "select_by": "EXT_ID",
          "reference_ext_ids": vms,
      })
    subs = _idf_entity_refs(row, "subnet_uuid_list", "allowed_subnet_uuid_list")
    if subs:
      allowed.append({
          "type": "SUBNET",
          "select_by": "EXT_ID",
          "reference_ext_ids": subs,
      })
    ags = _idf_entity_refs(
        row, "address_group_uuid_list", "allowed_address_group_uuid_list")
    if ags:
      allowed.append({
          "type": "ADDRESS_GROUP",
          "select_by": "EXT_ID",
          "reference_ext_ids": ags,
      })
    kube = [
        str(item) for item in _as_list(_first_attr(
            row, "allowed_entity_kube_entities", default=[]))
        if item]
    refs = _idf_entity_refs(row, "allowed_entity_reference_uuids")
    if kube:
      allowed.append({
          "type": "KUBE_CLUSTER",
          "select_by": "EXT_ID",
          "reference_ext_ids": refs,
      })
    elif refs:
      allowed.append({
          "type": "UNTYPED_REF",
          "select_by": "EXT_ID",
          "reference_ext_ids": refs,
      })
  excepted = []
  parsed_ex = _maybe_json(_first_attr(
      row, "except_entities", "except_config", default=None))
  if isinstance(parsed_ex, dict):
    excepted = list(parsed_ex.get("entities") or [])
  elif isinstance(parsed_ex, list):
    excepted = parsed_ex
  data = {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name") or "",
      "description": _first_attr(row, "description") or "",
      "is_system_eg": _as_bool(_first_attr(row, "is_system_eg"), False),
      "allowed_config": {"entities": allowed},
      "except_config": {"entities": excepted},
  }
  project_id = _row_project_id(row)
  if project_id:
    _apply_project(data, project_id)
  return data


def _policy_enum_label(value, mapping, default):
  if value in (None, ""):
    return default
  text = str(value).strip().upper().lstrip("K")
  if text in mapping:
    return mapping[text]
  if text in mapping.values():
    return text
  try:
    number = int(value)
  except (TypeError, ValueError):
    return default
  for key, label in mapping.items():
    if str(number) == key or number == key:
      return label
  return default


def _map_policy(row):
  # Live IDF ints: type 1=APP 2=ISO 3=QUAR; mode 1=MONITOR 2=ENFORCE;
  # scope 1=ALL_VLAN 3=VPC 4=GLOBAL 5=VPC_AS_CATEGORY.
  type_map = {
      "1": "APPLICATION", "APPLICATION": "APPLICATION", "APP": "APPLICATION",
      "2": "ISOLATION", "ISOLATION": "ISOLATION",
      "3": "QUARANTINE", "QUARANTINE": "QUARANTINE",
  }
  mode_map = {
      "0": "SAVE", "SAVE": "SAVE",
      "1": "MONITOR", "MONITOR": "MONITOR",
      "2": "ENFORCE", "ENFORCE": "ENFORCE", "APPLY": "ENFORCE",
      "3": "SAVE",
  }
  scope_map = {
      "1": "ALL_VLAN", "ALL_VLAN": "ALL_VLAN", "VLAN": "ALL_VLAN",
      "2": "VPC", "3": "VPC", "VPC": "VPC", "VPC_LIST": "VPC",
      "4": "GLOBAL", "GLOBAL": "GLOBAL",
      "5": "VPC_AS_CATEGORY", "VPC_AS_CATEGORY": "VPC_AS_CATEGORY",
  }
  proto_rules = None
  if isinstance(row, dict) and row.get("__zprotobuf__"):
    try:
      proto_rules = _rules_from_policy_zprotobuf(row.get("__zprotobuf__"))
    except Exception as err:
      LOG.warning("policy zprotobuf rules failed name=%s: %s",
                  _first_attr(row, "name") or "", err)
      proto_rules = None
    row.pop("__zprotobuf__", None)
  rules = _first_attr(row, "rules", "rule_list", default=[])
  parsed_rules = _maybe_json(rules)
  if parsed_rules is not None:
    rules = parsed_rules
  if not isinstance(rules, list):
    rules = []
  wrapped = []
  if proto_rules is not None:
    wrapped = proto_rules
  else:
    for rule in rules:
      if not isinstance(rule, dict):
        continue
      if "spec" in rule or "data" in rule:
        wrapped.append(rule)
      else:
        wrapped.append({"spec": rule, "type": rule.get("type") or "APPLICATION"})
  if not wrapped and proto_rules is None:
    spec = {}
    src_cats = _idf_entity_refs(
        row, "source_category_uuid_list", "src_category_references")
    dst_cats = _idf_entity_refs(
        row, "destination_category_uuid_list", "dest_category_references")
    sec_cats = _idf_entity_refs(
        row, "secured_group_category_uuid_list",
        "secured_group_category_references")
    src_ag = _idf_entity_refs(
        row, "source_address_group_uuid_list", "src_address_group_references")
    dst_ag = _idf_entity_refs(
        row, "destination_address_group_uuid_list",
        "dest_address_group_references")
    sgs = _idf_entity_refs(row, "service_group_uuid_list", "service_group_references")
    sec_eg = _idf_entity_refs(
        row, "secured_group_entity_group_uuid_list",
        "secured_group_entity_group_reference")
    src_eg = _idf_entity_refs(
        row, "source_entity_group_uuid_list", "src_entity_group_reference")
    dst_eg = _idf_entity_refs(
        row, "destination_entity_group_uuid_list", "dest_entity_group_reference")
    pol_type = _policy_enum_label(
        _first_attr(row, "policy_type", "type"), type_map, "APPLICATION")
    if src_cats:
      spec["src_category_references"] = src_cats
    if dst_cats:
      spec["dest_category_references"] = dst_cats
    if sec_cats:
      spec["secured_group_category_references"] = sec_cats
    if src_ag:
      spec["src_address_group_references"] = src_ag
    if dst_ag:
      spec["dest_address_group_references"] = dst_ag
    if sgs:
      spec["service_group_references"] = sgs
    if sec_eg:
      spec["secured_group_entity_group_reference"] = sec_eg[0]
    if src_eg:
      spec["src_entity_group_reference"] = src_eg[0]
    if dst_eg:
      spec["dest_entity_group_reference"] = dst_eg[0]
    if pol_type == "ISOLATION" and sec_cats:
      spec["spec"] = {
          "isolation_groups": [
              {
                  "group_category_references": [cid],
                  "group_category_associated_entity_type": "VM",
              }
              for cid in sec_cats
          ]
      }
    rule_ids = _idf_entity_refs(row, "rule_uuid_list")
    rule_type = "MULTI_ENV_ISOLATION" if pol_type == "ISOLATION" else "APPLICATION"
    if spec or rule_ids:
      wrapped.append({
          "ext_id": rule_ids[0] if rule_ids else "",
          "type": rule_type,
          "spec": spec,
      })
  data = {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name", "policy_name") or "",
      "description": _first_attr(row, "description") or "",
      "type": _policy_enum_label(
          _first_attr(row, "policy_type", "type"), type_map, "APPLICATION"),
      "state": _policy_enum_label(
          _first_attr(row, "mode", "state", "policy_mode"), mode_map, "SAVE"),
      "scope": _policy_enum_label(
          _first_attr(row, "scope", "policy_scope"), scope_map, "ALL_VLAN"),
      "vpc_references": _idf_entity_refs(
          row, "vpc_uuid_list", "vpc_references", "vpc_uuid"),
      "scope_references": _idf_entity_refs(
          row, "reference_uuid_list", "scope_references"),
      "priority": _int_attr(row, "policy_priority", "priority", default=0),
      "is_ipv6_traffic_allowed": _as_bool(
          _first_attr(row, "allow_ipv6_traffic", "is_ipv6_traffic_allowed"),
          False),
      "is_logging_enabled": _as_bool(
          _first_attr(row, "is_policy_hitlog_enabled", "is_logging_enabled"),
          False),
      "rules": wrapped,
  }
  project_id = _row_project_id(row)
  if project_id:
    _apply_project(data, project_id)
  return {"data": data}


def _fetch_mapped(entity_types, mapper):
  rows, errors = _idf_mapped(entity_types, mapper)
  for err in errors:
    LOG.warning("%s: %s", entity_types, err)
  return rows


def _load_json_if_present(path, default):
  if not os.path.isfile(path):
    return default
  with open(path, "r") as handle:
    return json.load(handle) or default


def _int_attr(row, *names, default=0):
  value = _first_attr(row, *names, default=default)
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def _map_nf(row):
  ingress = _as_list(_first_attr(
      row, "vnic_pair_list.ingress_vnic_uuid", "ingress_vnic_uuid",
      "ingress_nic_reference", default=[]))
  egress = _as_list(_first_attr(
      row, "vnic_pair_list.egress_vnic_uuid", "egress_vnic_uuid",
      "egress_nic_reference", default=[]))
  vm_ids = _as_list(_first_attr(
      row, "vnic_pair_list.vm_uuid", "vm_uuid", "vm_reference", default=[]))
  ha_states = _as_list(_first_attr(
      row, "vnic_pair_list.ha_state", "high_availability_state", default=[]))
  healths = _as_list(_first_attr(
      row, "vnic_pair_list.datapath_health_status",
      "data_plane_health_status", default=[]))
  pairs = []
  count = max(len(ingress), len(egress), len(vm_ids), 0)
  for idx in range(count):
    pairs.append({
        "vm_reference": _uuid_str(vm_ids[idx] if idx < len(vm_ids) else None) or "",
        "ingress_nic_reference": _uuid_str(
            ingress[idx] if idx < len(ingress) else None) or "",
        "egress_nic_reference": _uuid_str(
            egress[idx] if idx < len(egress) else None) or "",
        "high_availability_state": str(
            ha_states[idx] if idx < len(ha_states) else ""),
        "data_plane_health_status": str(
            healths[idx] if idx < len(healths) else "UNKNOWN") or "UNKNOWN",
    })
  health = {
      "interval_secs": _int_attr(
          row, "datapath_health_check_config.interval_secs", "interval_secs",
          default=5),
      "timeout_secs": _int_attr(
          row, "datapath_health_check_config.timeout_secs", "timeout_secs",
          default=2),
      "success_threshold": _int_attr(
          row, "datapath_health_check_config.success_count",
          "success_threshold", "success_count", default=3),
      "failure_threshold": _int_attr(
          row, "datapath_health_check_config.failure_count",
          "failure_threshold", "failure_count", default=3),
  }
  data = {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name") or "",
      "description": _first_attr(row, "description") or "",
      "failure_handling": _nf_enum(
          _first_attr(row, "failure_handling", "fallback_mode"),
          NF_FAIL),
      "traffic_forwarding_mode": _nf_enum(
          _first_attr(row, "traffic_forwarding_mode", "insertion_type",
                      "traffic_mode"),
          NF_TRAFFIC),
      "high_availability_mode": _nf_enum(
          _first_attr(row, "high_availability_mode", "ha_mode"),
          NF_HA),
      "nic_pairs": pairs,
      "data_plane_health_check_config": health,
  }
  project_id = _row_project_id(row)
  if project_id:
    _apply_project(data, project_id)
  return data


def _nf_pair_row(pair):
  proto = _item_proto(pair)
  ha_state = _enum_label(proto, "high_availability_state", "ha_state", default="")
  health = _enum_label(
      proto, "data_plane_health_status", "datapath_health_status",
      default="UNKNOWN")
  return {
      "vm_reference": _uuid_str(getattr(proto, "vm_reference", None)
                                or getattr(proto, "vm_uuid", None)) or "",
      "ingress_nic_reference": _uuid_str(
          getattr(proto, "ingress_nic_reference", None)
          or getattr(proto, "ingress_vnic_uuid", None)) or "",
      "egress_nic_reference": _uuid_str(
          getattr(proto, "egress_nic_reference", None)
          or getattr(proto, "egress_vnic_uuid", None)) or "",
      "high_availability_state": ha_state,
      "data_plane_health_status": health or "UNKNOWN",
      "is_enabled": bool(getattr(proto, "is_enabled", True)),
  }


def _health_config(proto):
  health = (
      getattr(proto, "data_plane_health_check_config", None)
      or getattr(proto, "datapath_health_check_config", None)
      or getattr(proto, "health_check_config", None))
  if health is None:
    return {
        "interval_secs": 5,
        "timeout_secs": 2,
        "success_threshold": 3,
        "failure_threshold": 3,
    }
  success = (
      getattr(health, "success_threshold", None)
      or getattr(health, "success_count", None) or 3)
  failure = (
      getattr(health, "failure_threshold", None)
      or getattr(health, "failure_count", None) or 3)
  return {
      "interval_secs": int(getattr(health, "interval_secs", 5) or 5),
      "timeout_secs": int(getattr(health, "timeout_secs", 2) or 2),
      "success_threshold": int(success),
      "failure_threshold": int(failure),
  }


def convert_network_function(item):
  proto = _item_proto(item)
  pairs = []
  for pair in list(getattr(proto, "nic_pairs", None)
                   or getattr(proto, "vnic_pair_list", None) or []):
    pairs.append(_nf_pair_row(pair))
  fail = _enum_label(proto, "failure_handling", "fallback_mode")
  if fail == "unknown":
    fail = _nf_enum(getattr(proto, "fallback_mode", None), NF_FAIL)
  traffic = _enum_label(
      proto, "traffic_forwarding_mode", "insertion_type", "traffic_mode")
  if traffic == "unknown":
    traffic = _nf_enum(getattr(proto, "insertion_type", None), NF_TRAFFIC)
  ha = _enum_label(proto, "high_availability_mode", "ha_mode")
  if ha == "unknown":
    ha = _nf_enum(getattr(proto, "ha_mode", None), NF_HA)
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "failure_handling": fail,
      "traffic_forwarding_mode": traffic,
      "high_availability_mode": ha,
      "nic_pairs": pairs,
      "data_plane_health_check_config": _health_config(proto),
  }
  data.update(_project_fields(proto))
  return data


def convert_project(item):
  proto = _item_proto(item)
  vm_ids = _uuid_list(
      getattr(proto, "vm_uuid_list", None)
      or getattr(proto, "vm_uuids", None)
      or getattr(proto, "virtual_machine_uuids", None)
      or [])
  data = {
      "ext_id": _item_uuid(item, proto),
      "name": getattr(proto, "name", "") or "",
      "description": getattr(proto, "description", "") or "",
      "vm_ext_ids": vm_ids,
  }
  data.update(_project_fields(proto))
  if not data.get("project_ext_id") and data.get("ext_id"):
    _apply_project(data, data["ext_id"], data.get("name") or "")
  return data


def _idf_mapped(entity_types, mapper):
  raw, errors = _idfcli_entities(entity_types)
  rows = []
  for item in raw:
    try:
      rows.append(mapper(item))
    except Exception as err:
      LOG.debug("map failed %s: %s", entity_types, err)
  return rows, errors


def fetch_hosts(interfaces):
  LOG.info("DUMP start hosts")
  manager = _get_manager(interfaces, "host_manager")
  rows = []
  if manager:
    for item in _iter_manager(manager):
      proto = _item_proto(item)
      rows.append({
          "ext_id": _item_uuid(item, proto),
          "host_name": getattr(proto, "name", None) or getattr(item, "name", ""),
          "hypervisor": {
              "external_address": {
                  "ipv4": {"value": getattr(proto, "ip_address", "") or ""}
              }
          },
          "cluster": {
              "uuid": _uuid_str(getattr(proto, "cluster_uuid", None) or
                                getattr(proto, "cluster_id", None)) or ""
          },
      })
  if not rows:
    rows, errors = _idf_mapped(("node", "host", "ahv_host"), _map_host)
    for err in errors:
      LOG.warning("hosts fallback: %s", err)
  LOG.info("DUMP done hosts count=%s", len(rows))
  return rows


def fetch_vms(_interfaces):
  LOG.info("DUMP start vms")
  with ThreadPoolExecutor(max_workers=2) as pool:
    vm_fut = pool.submit(_idf_mapped, ("vm", "mh_vm", "ahv_vm"), _map_vm)
    nic_fut = pool.submit(_idf_mapped, ("virtual_nic",), _map_virtual_nic)
    rows, errors = vm_fut.result()
    nic_rows, nic_errors = nic_fut.result()
  for err in errors:
    LOG.warning("vms fallback: %s", err)
  rows = _attach_virtual_nics(rows, nic_rows, nic_errors)
  LOG.info("DUMP done vms count=%s", len(rows))
  return rows


def fetch_subnets(_interfaces):
  LOG.info("DUMP start subnets")
  rows, errors = _idf_mapped(("virtual_network", "subnet"), _map_subnet)
  for err in errors:
    LOG.warning("subnets fallback: %s", err)
  LOG.info("DUMP done subnets count=%s", len(rows))
  return rows


def fetch_vpcs(_interfaces):
  LOG.info("DUMP start vpcs")
  rows, errors = _idf_mapped(("vpc", "virtual_private_cloud"), _map_vpc)
  for err in errors:
    LOG.warning("vpcs fallback: %s", err)
  LOG.info("DUMP done vpcs count=%s", len(rows))
  return rows


def _map_entity_capability(row):
  # Join key is kind_id (the VM/subnet/VPC UUID). Capability uuid is a
  # different object and must not be treated as the entity id.
  ids = []
  uid = _uuid_str(_first_attr(row, "kind_id"))
  if uid:
    ids.append(uid)
  cats = _category_ids_from_row(row)
  mapping = []
  for item in _as_list(_first_attr(
      row, "categories_mapping_list", "category_mapping_list", default=[])):
    if isinstance(item, dict):
      key = item.get("key") or item.get("name") or ""
      value = item.get("value") or ""
      text = ("%s:%s" % (key, value)).strip(":") if key or value else ""
    else:
      text = str(item).strip()
    mapped = _uuid_str(text) if text else None
    if mapped:
      if mapped not in cats:
        cats.append(mapped)
      continue
    if text and text not in mapping:
      mapping.append(text)
  return {
      "kind": str(_first_attr(row, "kind") or "").lower(),
      "ids": ids,
      "category_ids": cats,
      "category_names": mapping,
  }


def fetch_entity_capabilities(_interfaces):
  LOG.info("DUMP start entity_capabilities")
  rows, errors = _idf_mapped(
      ("abac_entity_capability", "volume_group_entity_capability"),
      _map_entity_capability)
  for err in errors:
    LOG.warning("entity_capabilities fallback: %s", err)
  LOG.info("DUMP done entity_capabilities count=%s", len(rows))
  return rows


def _merge_entity_categories(entity, cats, extra_names):
  meta = entity.setdefault("metadata", {})
  have = list(meta.get("category_ids") or [])
  for cid in cats or []:
    if cid not in have:
      have.append(cid)
  meta["category_ids"] = have
  extra = list(entity.get("extra_category_names") or [])
  for name in extra_names or []:
    if name and name not in extra:
      extra.append(name)
  entity["extra_category_names"] = extra


def _cap_target(kind):
  compact = str(kind or "").lower().replace(" ", "").replace("-", "_").lstrip("k")
  if compact in ("vpc", "virtual_private_cloud") or (
      "vpc" in compact and "subnet" not in compact):
    return "vpc"
  if compact in ("subnet", "virtual_network", "overlay_subnet"):
    return "subnet"
  if compact in ("vm", "mh_vm", "ahv_vm", "virtual_machine"):
    return "vm"
  return "both"


def _enrich_nics_and_vlan_vpc(payload):
  """Fill NIC VPC/subnet/VM category fields for neo4j_db_insert.py.

  IDF `vm` has no category_id_list; VM categories come from
  abac_entity_capability. ALL_VLAN is 00000000-0000-0000-0000-000000000001
  named VLAN. Overlay VPC names are inferred from subnet prefixes.
  """
  cat_map = _category_name_map(payload.get("categories") or [])
  subnets = payload.get("subnets") or []
  vpcs = list(payload.get("vpcs") or [])
  vms = payload.get("vms") or []
  vpc_by_id = {vpc.get("ext_id"): vpc for vpc in vpcs if vpc.get("ext_id")}
  subnet_by_id = {
      subnet.get("ext_id"): subnet for subnet in subnets if subnet.get("ext_id")}
  vm_by_id = {vm.get("ext_id"): vm for vm in vms if vm.get("ext_id")}

  for subnet in subnets:
    vpc_ref = subnet.get("vpc_reference")
    if vpc_ref and vpc_ref not in vpc_by_id and vpc_ref != ALL_VLAN_VPC_UUID:
      stub = {
          "ext_id": vpc_ref,
          "name": _vpc_display_name(
              vpc_ref, subnet.get("name"), subnet.get("vpc_name")),
          "vpc_type": "REGULAR",
          "metadata": {"category_ids": []},
          "externally_routable_prefixes": [],
          "external_subnets": [],
      }
      vpcs.append(stub)
      vpc_by_id[vpc_ref] = stub

  if ALL_VLAN_VPC_UUID not in vpc_by_id:
    vlan_vpc = _all_vlan_vpc()
    vpcs.append(vlan_vpc)
    vpc_by_id[ALL_VLAN_VPC_UUID] = vlan_vpc
  payload["vpcs"] = vpcs

  applied_subnet_caps = 0
  applied_vpc_caps = 0
  applied_vm_caps = 0
  for cap in payload.pop("entity_capabilities", None) or []:
    cats = cap.get("category_ids") or []
    extra_names = cap.get("category_names") or []
    if not cats and not extra_names:
      continue
    target = _cap_target(cap.get("kind") or "")
    for eid in cap.get("ids") or []:
      if target in ("subnet", "both") and eid in subnet_by_id:
        _merge_entity_categories(subnet_by_id[eid], cats, extra_names)
        applied_subnet_caps += 1
      if target in ("vpc", "both") and eid in vpc_by_id:
        _merge_entity_categories(vpc_by_id[eid], cats, extra_names)
        applied_vpc_caps += 1
      if target in ("vm", "both") and eid in vm_by_id:
        _merge_entity_categories(vm_by_id[eid], cats, extra_names)
        applied_vm_caps += 1
  LOG.info(
      "DUMP category join subnet_caps=%s vpc_caps=%s vm_caps=%s",
      applied_subnet_caps, applied_vpc_caps, applied_vm_caps)

  names_by_vpc = {}
  for subnet in subnets:
    vpc_ref = subnet.get("vpc_reference")
    if not vpc_ref or vpc_ref == ALL_VLAN_VPC_UUID:
      continue
    inferred = (
        subnet.get("vpc_name") or
        _vpc_name_from_subnet_name(subnet.get("name")))
    if inferred:
      names_by_vpc.setdefault(vpc_ref, []).append(inferred)
  for vpc_id, names in names_by_vpc.items():
    vpc = vpc_by_id.get(vpc_id)
    if not vpc:
      continue
    counts = {}
    for name in names:
      counts[name] = counts.get(name, 0) + 1
    vpc["name"] = max(counts, key=counts.get)
  for vpc in vpcs:
    vpc["name"] = _vpc_display_name(
        vpc.get("ext_id"), existing=vpc.get("name"))

  def _resolved_cats(entity):
    cat_ids = ((entity.get("metadata") or {}).get("category_ids") or [])
    names = _category_names(cat_ids, cat_map)
    for extra in entity.get("extra_category_names") or []:
      if extra not in names:
        names.append(extra)
    return cat_ids, names

  vpc_subnet_cat_ids = {}
  for subnet in subnets:
    vpc_ref = subnet.get("vpc_reference") or ALL_VLAN_VPC_UUID
    vpc_subnet_cat_ids.setdefault(vpc_ref, [])
    for cid in (subnet.get("metadata") or {}).get("category_ids") or []:
      if cid not in vpc_subnet_cat_ids[vpc_ref]:
        vpc_subnet_cat_ids[vpc_ref].append(cid)
    _ids, names = _resolved_cats(subnet)
    subnet["categories"] = names
  for vpc in vpcs:
    _ids, names = _resolved_cats(vpc)
    vpc["categories"] = names
    if vpc.get("ext_id") == ALL_VLAN_VPC_UUID:
      vpc["subnet_categories"] = []
    else:
      vpc["subnet_categories"] = _category_names(
          vpc_subnet_cat_ids.get(vpc.get("ext_id") or "", []), cat_map)

  vlan_nics = 0
  overlay_nics = 0
  with_subnet_cats = 0
  with_vpc_subnet_cats = 0
  vms_with_cats = 0
  for vm in vms:
    vm_cat_ids, vm_cat_names = _resolved_cats(vm)
    vm["categories"] = vm_cat_names
    vm["category_ids"] = vm_cat_ids
    if vm_cat_names:
      vms_with_cats += 1
    for nic in vm.get("nics") or []:
      network = nic.setdefault("nic_network_info", {})
      subnet_obj = network.get("subnet")
      subnet_id = ""
      if isinstance(subnet_obj, dict):
        subnet_id = subnet_obj.get("ext_id") or ""
      subnet = subnet_by_id.get(subnet_id) or {}
      cat_ids, cat_names = _resolved_cats(subnet)
      if cat_names:
        with_subnet_cats += 1
      advanced = _as_bool(subnet.get("is_advanced_networking"), False)
      subnet_type = subnet.get("subnet_type") or ""
      vpc_ref = subnet.get("vpc_reference") or ""
      if not subnet_id:
        network["vpc"] = {
            "ext_id": "",
            "name": "",
            "categories": [],
            "category_ids": [],
            "subnet_categories": [],
        }
        network["vm_categories"] = vm_cat_names
        network["vm_category_ids"] = vm_cat_ids
        network["vm_subnet_categories"] = []
        network["vpc_categories"] = []
        network["vpc_subnet_categories"] = []
        continue
      if vpc_ref == ALL_VLAN_VPC_UUID or str(subnet_type).upper() == "VLAN":
        vpc_ref = ALL_VLAN_VPC_UUID
        vlan_nics += 1
        vpc_subnet_cats = cat_names
      else:
        overlay_nics += 1
        vpc_subnet_cats = _category_names(
            vpc_subnet_cat_ids.get(vpc_ref, []), cat_map)
      if vpc_subnet_cats:
        with_vpc_subnet_cats += 1
      vpc = vpc_by_id.get(vpc_ref) or _all_vlan_vpc()
      vpc_cat_ids, vpc_cat_names = _resolved_cats(vpc)
      vpc_name = _vpc_display_name(
          vpc_ref, subnet.get("name"), vpc.get("name"))
      vpc["name"] = vpc_name
      network["subnet"] = {
          "ext_id": subnet_id,
          "name": subnet.get("name") or "",
          "subnet_type": subnet_type,
          "is_advanced_networking": advanced,
          "categories": cat_names,
          "category_ids": cat_ids,
      }
      network["vpc"] = {
          "ext_id": vpc_ref,
          "name": vpc_name,
          "categories": vpc_cat_names,
          "category_ids": vpc_cat_ids,
          "subnet_categories": vpc_subnet_cats,
      }
      network["vm_categories"] = vm_cat_names
      network["vm_category_ids"] = vm_cat_ids
      network["vm_subnet_categories"] = cat_names
      network["vpc_categories"] = vpc_cat_names
      network["vpc_subnet_categories"] = vpc_subnet_cats
  LOG.info(
      "DUMP nic enrich vlan=%s overlay=%s vm_categories=%s "
      "vm_subnet_categories=%s vpc_subnet_categories=%s vpcs=%s",
      vlan_nics, overlay_nics, vms_with_cats, with_subnet_cats,
      with_vpc_subnet_cats, len(vpcs))


def _copy_project(target, blob):
  if not blob or not blob.get("ext_id") or not isinstance(target, dict):
    return
  _apply_project(target, blob["ext_id"], blob.get("name") or "")


def _note_project(store, entity):
  blob = _project_blob(entity)
  if not blob or not blob.get("ext_id"):
    return
  uid = blob["ext_id"]
  name = blob.get("name") or ""
  prev = store.get(uid) or ""
  if name and (not prev or prev == "Unknown"):
    store[uid] = name
  else:
    store.setdefault(uid, name)


def _enrich_projects(payload):
  """Copy VM/subnet/VPC project onto each NIC for neo4j extract_project_info.

  IDF `project` is often empty on PC. Harvest project UUIDs from dumped
  entities so projects.json is not []. NICs inherit the VM project.
  """
  projects = list(payload.get("projects") or [])
  by_id = {proj.get("ext_id"): proj for proj in projects if proj.get("ext_id")}
  name_by_id = {
      proj.get("ext_id"): proj.get("name") or ""
      for proj in projects if proj.get("ext_id")}
  vms = payload.get("vms") or []
  vm_by_id = {vm.get("ext_id"): vm for vm in vms if vm.get("ext_id")}
  subnet_by_id = {
      subnet.get("ext_id"): subnet
      for subnet in (payload.get("subnets") or []) if subnet.get("ext_id")}
  vpc_by_id = {
      vpc.get("ext_id"): vpc
      for vpc in (payload.get("vpcs") or []) if vpc.get("ext_id")}

  assigned = 0
  for proj in projects:
    uid = proj.get("ext_id")
    name = proj.get("name") or ""
    if uid and name:
      name_by_id[uid] = name
    for vm_id in proj.get("vm_ext_ids") or []:
      vm = vm_by_id.get(vm_id)
      if vm and not _project_blob(vm):
        _apply_project(vm, uid, name)
        assigned += 1

  inherited = 0
  nic_count = 0
  for vm in vms:
    blob = _project_blob(vm)
    if not blob:
      for nic in vm.get("nics") or []:
        network = nic.get("nic_network_info") or {}
        subnet_obj = network.get("subnet") or {}
        subnet_id = subnet_obj.get("ext_id") if isinstance(subnet_obj, dict) else ""
        subnet = subnet_by_id.get(subnet_id) or {}
        blob = _project_blob(subnet)
        if not blob:
          vpc_ref = ""
          if isinstance(network.get("vpc"), dict):
            vpc_ref = network["vpc"].get("ext_id") or ""
          blob = _project_blob(
              vpc_by_id.get(vpc_ref or subnet.get("vpc_reference") or "") or {})
        if blob:
          if not blob.get("name"):
            blob["name"] = name_by_id.get(blob["ext_id"], "")
          _copy_project(vm, blob)
          inherited += 1
          break
    blob = _project_blob(vm)
    if not blob:
      continue
    if not blob.get("name"):
      blob["name"] = name_by_id.get(blob["ext_id"], "")
      vm["project"] = blob
    for nic in vm.get("nics") or []:
      _copy_project(nic, blob)
      network = nic.setdefault("nic_network_info", {})
      network["project"] = dict(blob)
      nic_count += 1

  harvested = {}
  for key in ("projects", "address_groups", "service_groups", "entity_groups",
              "subnets", "vpcs", "vms", "network_functions"):
    for entity in payload.get(key) or []:
      _note_project(harvested, entity)
      if key == "vms":
        for nic in entity.get("nics") or []:
          _note_project(harvested, nic)
          _note_project(harvested, (nic.get("nic_network_info") or {}))
  for policy in payload.get("policies") or []:
    _note_project(harvested, policy.get("data") or policy)

  added = 0
  for uid, name in harvested.items():
    if uid in by_id:
      if name and not by_id[uid].get("name"):
        by_id[uid]["name"] = name
      continue
    stub = {
        "ext_id": uid,
        "name": name or ("default" if uid == DEFAULT_PROJECT_UUID else "Unknown"),
        "vm_ext_ids": [],
    }
    _apply_project(stub, uid, stub["name"])
    projects.append(stub)
    by_id[uid] = stub
    added += 1
  payload["projects"] = projects
  LOG.info(
      "DUMP project enrich vm_from_project=%s vm_inherited=%s nics=%s "
      "harvested=%s added=%s projects=%s",
      assigned, inherited, nic_count, len(harvested), added, len(projects))


def _sg_port_strings(services, kind):
  out = []
  for ports in services or []:
    if not isinstance(ports, dict):
      continue
    if ports.get("is_all_allowed"):
      out.append("0-65535" if kind in ("tcp", "udp") else "any:any")
      continue
    if kind in ("tcp", "udp"):
      start = ports.get("start_port", 0)
      end = ports.get("end_port", start)
      out.append(str(start) if start == end else "%s-%s" % (start, end))
    else:
      out.append("%s:%s" % (ports.get("type", 0), ports.get("code", 0)))
  return out


def _sg_detail(sg):
  return {
      "ext_id": sg.get("ext_id"),
      "name": sg.get("name") or "",
      "tcp_services": sg.get("tcp_services") or [],
      "udp_services": sg.get("udp_services") or [],
      "icmp_services": sg.get("icmp_services") or [],
      "icmp_v6_services": sg.get("icmp_v6_services") or [],
      "tcpPort": _sg_port_strings(sg.get("tcp_services"), "tcp"),
      "udpPort": _sg_port_strings(sg.get("udp_services"), "udp"),
      "icmpTypes": _sg_port_strings(sg.get("icmp_services"), "icmp"),
      "icmpv6Types": _sg_port_strings(sg.get("icmp_v6_services"), "icmpv6"),
      "project": sg.get("project"),
      "project_ext_id": sg.get("project_ext_id") or sg.get("projectExtId"),
      "projectExtId": sg.get("projectExtId") or sg.get("project_ext_id"),
      "shared_with_all_projects": bool(sg.get("shared_with_all_projects")),
  }


def _policy_nf_uuids(payload):
  uuids = []
  seen = set()
  for policy in payload.get("policies") or []:
    data = policy.get("data") or policy
    for rule in data.get("rules") or []:
      spec = rule.get("spec") or {}
      uid = _uuid_str(spec.get("network_function_reference"))
      if uid and uid not in seen:
        seen.add(uid)
        uuids.append(uid)
  return uuids


def _synthetic_all_ports_action(rule):
  """Match neo4j parse_rule all-port ServiceGroup cases.

  Isolation / TWO_ENV / MULTI_ENV always DENY_ALL on 0-65535.
  is_all_protocol_allowed is allow-all protocols.
  INTRA_GROUP with an action and no services is all ports.
  src/dest_allow_spec NONE is deny-all ports.
  SG refs overwrite all-port strings later, so return None when SG refs exist
  except isolation (isolation has no SG refs).
  """
  rule_type = str(rule.get("type") or "")
  spec = rule.get("spec") or {}
  if rule_type in ("TWO_ENV_ISOLATION", "MULTI_ENV_ISOLATION"):
    return "DENY_ALL"
  has_sg = bool(
      spec.get("service_group_references")
      or spec.get("secured_group_service_references"))
  has_ports = bool(
      spec.get("tcp_services") or spec.get("udp_services")
      or spec.get("icmp_services") or spec.get("icmp_v6_services"))
  if spec.get("src_allow_spec") == "NONE" or spec.get("dest_allow_spec") == "NONE":
    return "DENY"
  if spec.get("is_all_protocol_allowed") and not has_sg:
    return "allow"
  if spec.get("secured_group_action") and not has_sg and not has_ports:
    return spec.get("secured_group_action")
  return None


def _expand_service_and_function_details(payload):
  """Expand SG/NF UUID refs on rules the same way neo4j_db_insert.parse_rule does."""
  sg_map = {
      sg.get("ext_id"): sg
      for sg in (payload.get("service_groups") or []) if sg.get("ext_id")}
  nf_map = {}
  for nf in payload.get("network_functions") or []:
    if nf.get("ext_id"):
      nf_map[nf["ext_id"]] = nf
  for uid, wrapped in (payload.get("network_function_by_id") or {}).items():
    detailed = (wrapped or {}).get("data") or wrapped or {}
    if isinstance(detailed, dict) and detailed.get("ext_id"):
      nf_map[detailed["ext_id"]] = detailed
    elif isinstance(detailed, dict):
      nf_map[uid] = detailed

  sg_rules = 0
  nf_rules = 0
  missing_sg = 0
  all_port_rules = 0
  for policy in payload.get("policies") or []:
    data = policy.get("data") or policy
    for rule in data.get("rules") or []:
      spec = rule.get("spec")
      if not isinstance(spec, dict):
        continue
      refs = list(spec.get("service_group_references") or [])
      if spec.get("secured_group_service_references"):
        for uid in spec.get("secured_group_service_references") or []:
          if uid not in refs:
            refs.append(uid)
      details = []
      for uid in refs:
        sg = sg_map.get(uid)
        if sg:
          details.append(_sg_detail(sg))
        else:
          missing_sg += 1
          details.append({"ext_id": uid, "name": ""})
      if details:
        spec["service_group_details"] = details
        sg_rules += 1
      else:
        action = _synthetic_all_ports_action(rule)
        if action is not None:
          spec.update(_all_ports_spec_fields(action))
          spec["service_group_details"] = [_all_ports_service_detail(action)]
          all_port_rules += 1
      nf_uid = _uuid_str(spec.get("network_function_reference"))
      if nf_uid:
        nf = nf_map.get(nf_uid)
        spec["network_function_details"] = dict(nf) if nf else {"ext_id": nf_uid}
        nf_rules += 1
  LOG.info(
      "DUMP service details rules_with_sg=%s rules_with_all_ports=%s "
      "rules_with_nf=%s missing_sg_refs=%s service_groups=%s "
      "network_functions=%s",
      sg_rules, all_port_rules, nf_rules, missing_sg, len(sg_map), len(nf_map))


def _stringify_ips(values):
  out = []
  for item in _as_list(values):
    if isinstance(item, dict):
      text = str(item.get("value") or item.get("ip") or "").strip()
    else:
      text = str(getattr(item, "value", item) or "").strip()
    if text and text not in out:
      out.append(text)
  return out


def _add_fqdn_ips(mapping, fqdn, ips):
  key = str(fqdn or "").strip()
  if not key:
    return
  have = mapping.setdefault(key, [])
  for ip in _stringify_ips(ips):
    if ip not in have:
      have.append(ip)


def _fqdn_mapping_entry(fqdn, ips):
  return "%s:[%s]" % (fqdn, ",".join(ips or []))


def _nic_dump_ips(nic):
  network = nic.get("nic_network_info") or {}
  ipv4_info = network.get("ipv4_info") or {}
  ipv4_config = network.get("ipv4_config") or {}
  ipv6_info = network.get("ipv6_info") or {}
  ipv6_config = network.get("ipv6_config") or {}
  ips = []
  for group in (
      ipv4_info.get("learned_ip_addresses"),
      ipv4_config.get("ip_address"),
      ipv4_config.get("secondary_ip_address_list"),
      ipv6_info.get("learned_ipv6_addresses"),
      ipv6_config.get("ip_address"),
      ipv6_config.get("secondary_ipv6_address_list")):
    for ip in _stringify_ips(group):
      if ip not in ips:
        ips.append(ip)
  return ips


def _expand_fqdn_details(payload):
  """Resolve EG FQDNs into subnet_list and match those IPs onto NICs.

  neo4j_db_insert.create_entity_group_map puts resolved FQDN IPs on
  eg_subnet_list and fqdn_mapping ("fqdn:[ip1,ip2]"). PolicyRuleEvaluator
  then matches NIC learned_ips against that mapping.
  """
  fqdn_map = payload.get("fqdn_to_ip_map") or {}
  ip_to_fqdns = {}
  for fqdn, ips in fqdn_map.items():
    for ip in ips or []:
      ip_to_fqdns.setdefault(str(ip).strip(), []).append(fqdn)

  eg_with_fqdn = 0
  for eg in payload.get("entity_groups") or []:
    subnet_list = []
    fqdn_mapping = []
    found = False
    for cfg_name in ("allowed_config", "except_config"):
      is_except = cfg_name == "except_config"
      for entity in ((eg.get(cfg_name) or {}).get("entities") or []):
        fqdns = [str(item) for item in (entity.get("fqdns") or []) if item]
        if not fqdns:
          continue
        found = True
        details = []
        for fqdn in fqdns:
          ips = list(fqdn_map.get(fqdn) or [])
          entry = _fqdn_mapping_entry(fqdn, ips)
          details.append({
              "fqdn": fqdn,
              "resolved_ips": ips,
              "fqdn_mapping": entry,
          })
          if is_except:
            continue
          if entry not in fqdn_mapping:
            fqdn_mapping.append(entry)
          for ip in ips:
            if ip not in subnet_list:
              subnet_list.append(ip)
        entity["fqdn_details"] = details
        entity["resolved_ips"] = [
            ip for detail in details for ip in (detail.get("resolved_ips") or [])]
    if found:
      eg["fqdn_mapping"] = fqdn_mapping
      eg["subnet_list"] = subnet_list
      eg_with_fqdn += 1

  nics_with_fqdn = 0
  for vm in payload.get("vms") or []:
    for nic in vm.get("nics") or []:
      matched = []
      mapping = []
      for ip in _nic_dump_ips(nic):
        for fqdn in ip_to_fqdns.get(ip, []):
          if fqdn in matched:
            continue
          matched.append(fqdn)
          mapping.append(_fqdn_mapping_entry(fqdn, fqdn_map.get(fqdn) or []))
      if not matched:
        continue
      network = nic.setdefault("nic_network_info", {})
      network["fqdns"] = matched
      network["fqdn_mapping"] = mapping
      nic["fqdns"] = matched
      nics_with_fqdn += 1
  with_ips = sum(1 for ips in fqdn_map.values() if ips)
  LOG.info(
      "DUMP fqdn enrich egs=%s nics=%s fqdns=%s with_resolved_ips=%s",
      eg_with_fqdn, nics_with_fqdn, len(fqdn_map), with_ips)


def fetch_clusters(_interfaces):
  LOG.info("DUMP start clusters")
  rows, errors = _idf_mapped(("cluster",), _map_cluster)
  for err in errors:
    LOG.warning("clusters fallback: %s", err)
  ncli_rows = []
  if not _IDF_FILE_DIR:
    try:
      ncli_rows = _ncli_registered_clusters()
    except Exception as err:
      LOG.debug("clusters ncli vip enrich skipped: %s", err)
  by_uuid = {}
  by_name = {}
  for rec in ncli_rows:
    uid = rec.get("ext_id") or ""
    name = rec.get("name") or ""
    if uid:
      by_uuid[uid] = rec
    if name and name not in by_name:
      by_name[name] = rec
  have = set(row.get("ext_id") for row in rows if row.get("ext_id"))
  for row in rows:
    net = row.setdefault("network", {}).setdefault(
        "external_address", {}).setdefault("ipv4", {})
    if net.get("value"):
      continue
    rec = by_uuid.get(row.get("ext_id") or "") or by_name.get(row.get("name") or "")
    if rec and rec.get("vip"):
      net["value"] = rec["vip"]
  for rec in ncli_rows:
    uid = rec.get("ext_id") or ""
    if not uid or uid in have:
      continue
    rows.append({
        "ext_id": uid,
        "name": rec.get("name") or "",
        "network": {
            "external_address": {"ipv4": {"value": rec.get("vip") or ""}},
        },
    })
    have.add(uid)
  LOG.info("DUMP done clusters count=%s", len(rows))
  return rows


def fetch_projects(interfaces):
  LOG.info("DUMP start projects")
  # Skip FlowInterfaces.project_manager getattr: Zeus can FATAL the process.
  mapped, errors = _idf_mapped(
      ("project", "projects", "iam_project", "xi_project", "abac_project"),
      _map_project)
  for err in errors:
    LOG.warning("projects fallback: %s", err)
  LOG.info("DUMP done projects count=%s (idf)", len(mapped))
  return mapped


def fetch_network_functions(interfaces):
  LOG.info("DUMP start network_functions")
  # Skip FlowInterfaces.network_function_manager getattr: Zeus can FATAL.
  mapped, errors = _idf_mapped(
      ("atlas_network_function", "network_function", "flow_network_function"),
      _map_nf)
  for err in errors:
    LOG.warning("network_functions fallback: %s", err)
  LOG.info("DUMP done network_functions count=%s (idf)", len(mapped))
  return mapped


def fetch_network_function_by_id(interfaces, nf_rows, extra_uuids=None):
  manager = None
  by_id = {}
  seen = set()
  for nf in nf_rows or []:
    ext_id = nf.get("ext_id")
    if not ext_id:
      continue
    seen.add(ext_id)
    detailed = dict(nf)
    if manager:
      item = _call_first(manager, ("get", "get_by_id", "lookup"), ext_id)
      if item:
        try:
          detailed = convert_network_function(item)
        except Exception as err:
          LOG.debug("network_function get %s failed: %s", ext_id, err)
    by_id[ext_id] = {"data": detailed}
  for ext_id in extra_uuids or []:
    if not ext_id or ext_id in seen:
      continue
    detailed = {"ext_id": ext_id}
    if manager:
      item = _call_first(manager, ("get", "get_by_id", "lookup"), ext_id)
      if item:
        try:
          detailed = convert_network_function(item)
        except Exception as err:
          LOG.debug("network_function get %s failed: %s", ext_id, err)
    by_id[ext_id] = {"data": detailed}
    seen.add(ext_id)
  LOG.info("DUMP done network_function_by_id count=%s", len(by_id))
  return by_id


def fetch_categories(_interfaces):
  LOG.info("DUMP start categories")
  by_id = {}
  for entity_type in ("abac_category", "category"):
    rows, errors = _idf_mapped((entity_type,), _map_category)
    for err in errors:
      LOG.warning("categories fallback: %s", err)
    for row in rows:
      ext_id = row.get("ext_id")
      if not ext_id:
        continue
      prev = by_id.get(ext_id)
      if prev is None:
        by_id[ext_id] = row
        continue
      prev["key"] = _prefer_human_key(prev.get("key"), row.get("key"))
      if not prev.get("value"):
        prev["value"] = row.get("value") or ""
  rows = list(by_id.values())
  filled = sum(1 for row in rows if row.get("key") and row.get("value"))
  LOG.info("DUMP done categories count=%s key_value=%s", len(rows), filled)
  return rows


def fetch_unique_uuids():
  LOG.info("DUMP start vlan/global unique uuids")
  zkcats = (
      "/home/nutanix/cluster/bin/zkcat",
      "/usr/local/nutanix/cluster/bin/zkcat",
  )
  paths = {
      "vlan_unique_uuid": "/appliance/logical/flow/vlan_unique_uuid",
      "global_unique_uuid": "/appliance/logical/flow/global_unique_uuid",
  }
  out = {}
  for key, zk_path in paths.items():
    value = ""
    found_bin = False
    for zkcat in zkcats:
      if not (os.path.exists(zkcat) and os.access(zkcat, os.X_OK)):
        continue
      found_bin = True
      try:
        proc = subprocess.run(
            [zkcat, zk_path], capture_output=True, text=True, check=False,
            timeout=20)
      except Exception as err:
        LOG.error("DUMP %s failed: %s", key, err)
        continue
      text = (proc.stdout or "").strip()
      err_text = (proc.stderr or "").strip()
      if "no node" in ("%s %s" % (text, err_text)).lower():
        continue
      if proc.returncode == 0 and text:
        value = text.splitlines()[-1].strip()
        break
    if not found_bin:
      LOG.warning("zkcat missing; skip %s", key)
    out[key] = value
    LOG.info("DUMP %s=%s", key, value or "<empty>")
  return out


def fetch_fqdn_map(interfaces):
  """FQDN → resolved IPv4+IPv6, same as neo4j_db_insert.get_fqdn_to_ip_mapping.

  IDF entity type is fns_fqdn_to_ip_info (resolved_ipv4_addresses +
  resolved_ipv6_addresses). FlowInterfaces is merged on top so names
  without IDF rows are still listed.
  """
  LOG.info("DUMP start fqdn_to_ip_map")
  mapping = {}
  raw, errors = _idfcli_entities(("fns_fqdn_to_ip_info",))
  for err in errors:
    LOG.warning("fqdn idf: %s", err)
  for item in raw:
    fqdn = _first_attr(item, "fqdn")
    ips = list(_as_list(_first_attr(item, "resolved_ipv4_addresses", default=[])))
    ips.extend(_as_list(_first_attr(item, "resolved_ipv6_addresses", default=[])))
    _add_fqdn_ips(mapping, fqdn, ips)
  manager = _get_manager(
      interfaces, "fqdn_resolution_manager", "fqdn_manager")
  payload = _call_first(manager, [
      "iter_all", "get_all", "list", "get_fqdn_to_ip_mapping"])
  for item in _unwrap_list(payload) or (_iter_manager(manager) if manager else []):
    proto = _item_proto(item)
    fqdn = getattr(proto, "fqdn", None) or getattr(item, "fqdn", None)
    ips = []
    for attr in (
        "resolved_ipv4_addresses", "resolved_ipv6_addresses",
        "ip_list", "resolved_ips", "ipv4_addresses", "ip_addresses"):
      values = getattr(proto, attr, None)
      if values is None:
        values = getattr(item, attr, None)
      if values:
        ips.extend(_stringify_ips(values))
    _add_fqdn_ips(mapping, fqdn, ips)
  with_ips = sum(1 for ips in mapping.values() if ips)
  LOG.info(
      "DUMP done fqdn_to_ip_map count=%s with_resolved_ips=%s",
      len(mapping), with_ips)
  return mapping


def _atlas_cli_bin():
  for path in (
      "/usr/local/nutanix/bin/atlas_cli",
      "/home/nutanix/bin/atlas_cli",
      "/home/nutanix/atlas/bin/atlas_cli"):
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "atlas_cli"


def _safe_json_loads(text):
  if not text or not str(text).strip():
    return None
  text = str(text).strip()
  try:
    return json.loads(text)
  except Exception:
    pass
  start = text.find("{")
  end = text.rfind("}")
  if start >= 0 and end > start:
    try:
      return json.loads(text[start:end + 1])
    except Exception:
      pass
  start = text.find("[")
  end = text.rfind("]")
  if start >= 0 and end > start:
    try:
      return json.loads(text[start:end + 1])
    except Exception:
      pass
  return None


def _run_profile_cmd(cmd, timeout=30):
  full = "source /etc/profile >/dev/null 2>&1; %s" % cmd
  try:
    proc = subprocess.run(
        full, shell=True, executable="/bin/bash",
        capture_output=True, text=True, check=False, timeout=timeout)
  except Exception as err:
    LOG.debug("cmd failed (%s): %s", cmd, err)
    return "", str(err), 1
  return proc.stdout or "", proc.stderr or "", proc.returncode


def _mspctl_cluster_list():
  out, err, _rc = _run_profile_cmd("mspctl cluster list --output json")
  parsed = _safe_json_loads(out)
  if isinstance(parsed, list):
    return parsed
  if isinstance(parsed, dict):
    for key in ("clusters", "data", "ClusterList", "items"):
      if isinstance(parsed.get(key), list):
        return parsed[key]
  LOG.debug("mspctl cluster list not JSON: %s", (out or err)[:300])
  return []


def _mspctl_flow_cluster():
  out, err, _rc = _run_profile_cmd("mspctl cluster get flow --verbose")
  parsed = _safe_json_loads(out)
  if isinstance(parsed, dict) and parsed.get("ClusterUUID"):
    return parsed
  text = "%s\n%s" % (out, err)
  if re.search(r"msp cluster not found|getClusterStatusV2NotFound|\b404\b",
               text, re.I):
    return {"_not_found": True, "_raw": text[:300]}
  return None


def _flow_cluster_from_list(clusters):
  for cluster in clusters or []:
    if not isinstance(cluster, dict):
      continue
    name = str(cluster.get("cluster_name") or cluster.get("name") or "")
    if name.strip().lower() == "flow":
      return cluster
  return None


def _cluster_uuid(cluster):
  if not isinstance(cluster, dict):
    return ""
  return str(
      cluster.get("cluster_uuid") or cluster.get("ClusterUUID") or
      cluster.get("uuid") or "")


def _zk_node_exists(zk_path):
  for zkcat in (
      "/home/nutanix/cluster/bin/zkcat",
      "/usr/local/nutanix/cluster/bin/zkcat"):
    if not (os.path.exists(zkcat) and os.access(zkcat, os.X_OK)):
      continue
    try:
      proc = subprocess.run(
          [zkcat, zk_path], capture_output=True, text=True, check=False,
          timeout=15)
    except Exception:
      continue
    text = "%s%s" % (proc.stdout or "", proc.stderr or "")
    if "no node" in text.lower():
      return False
    if proc.returncode == 0:
      return True
  return False


def _genesis_atlas_pids():
  out, err, _rc = _run_profile_cmd("genesis status", timeout=45)
  text = out or err
  for line in text.splitlines():
    stripped = line.strip().lower()
    if not stripped.startswith("atlas:"):
      continue
    if "[" not in line:
      return []
    inner = line.split("[", 1)[1].split("]", 1)[0]
    return [part.strip() for part in inner.split(",") if part.strip().isdigit()]
  return []


def detect_msp_platform():
  """Detect Flow SMSP vs CMSP from the PC itself (no --platform flag).

  SMSP: mspctl has a cluster named flow (service MSP). atlas_cli needs
        -u ws://smsp-<uuid>.ntnx-ikat.svc:2060/atlas_cli
  CMSP: only the controller MSP (prism-central/msp); Atlas runs on the PCVM.
  """
  info = {
      "platform": "cmsp",
      "detection_method": "no_flow_smsp_signals",
      "smsp_cluster_uuid": "",
  }
  with ThreadPoolExecutor(max_workers=3) as pool:
    list_fut = pool.submit(_mspctl_cluster_list)
    get_fut = pool.submit(_mspctl_flow_cluster)
    zk_fut = pool.submit(_zk_node_exists, "/appliance/logical/flow_smsp")
    clusters = list_fut.result()
    flow_get = get_fut.result()
    zk_smsp = zk_fut.result()
  names = [
      str(item.get("cluster_name") or item.get("name") or "")
      for item in clusters if isinstance(item, dict)]
  LOG.info("mspctl clusters: %s", names or "<none>")
  flow = _flow_cluster_from_list(clusters)
  smsp_uuid = _cluster_uuid(flow)
  if not smsp_uuid and isinstance(flow_get, dict):
    smsp_uuid = _cluster_uuid(flow_get)

  if smsp_uuid:
    info["platform"] = "smsp"
    info["smsp_cluster_uuid"] = smsp_uuid
    info["detection_method"] = (
        "mspctl_cluster_list_flow" if flow else "mspctl_cluster_get_flow")
    LOG.info(
        "Detected SMSP via %s uuid=%s", info["detection_method"], smsp_uuid)
    return info

  not_found = isinstance(flow_get, dict) and flow_get.get("_not_found")
  no_flow = not_found or (clusters and not flow)
  atlas_pids = []
  if not no_flow:
    atlas_pids = _genesis_atlas_pids()
  LOG.info(
      "SMSP probes: flow_cluster=%s flow_404=%s genesis_atlas_pids=%s "
      "zk_flow_smsp=%s",
      bool(flow), bool(not_found), len(atlas_pids), zk_smsp)

  if zk_smsp and not not_found:
    info["platform"] = "smsp"
    info["detection_method"] = "zk_flow_smsp"
    LOG.warning(
        "ZK /appliance/logical/flow_smsp exists but no flow MSP UUID; "
        "atlas_cli -u cannot be formed")
    return info

  if no_flow and atlas_pids:
    info["detection_method"] = "mspctl_no_flow_cluster+genesis_atlas"
  elif no_flow:
    info["detection_method"] = "mspctl_no_flow_cluster"
  elif atlas_pids:
    info["detection_method"] = "genesis_atlas"
  info["platform"] = "cmsp"
  LOG.info("Detected CMSP via %s", info["detection_method"])
  return info


def _atlas_cli_argv(platform_info):
  argv = [_atlas_cli_bin()]
  if (platform_info.get("platform") == "smsp" and
      platform_info.get("smsp_cluster_uuid")):
    argv.extend([
        "-u",
        "ws://smsp-%s.ntnx-ikat.svc:2060/atlas_cli" % (
            platform_info["smsp_cluster_uuid"]),
    ])
  argv.extend(["-o", "json"])
  return argv


def _run_atlas_cli(platform_info, args, timeout_secs, log_cmd=True):
  cmd = _atlas_cli_argv(platform_info) + list(args)
  if log_cmd:
    LOG.info("DUMP atlas_cli: %s", " ".join(cmd))
  try:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False,
        timeout=timeout_secs)
  except subprocess.TimeoutExpired:
    raise RuntimeError(
        "atlas_cli %s timed out after %ss" % (" ".join(args), timeout_secs))
  parsed = _safe_json_loads(proc.stdout or "")
  if parsed is None:
    err = (proc.stderr or proc.stdout or "").strip()[:500]
    raise RuntimeError(
        "atlas_cli %s failed rc=%s: %s" % (
            " ".join(args), proc.returncode, err or "no JSON output"))
  return parsed, proc.returncode, cmd


def _port_set_list_rows(parsed):
  if isinstance(parsed, list):
    return parsed
  if not isinstance(parsed, dict):
    return []
  data = parsed.get("data")
  if isinstance(data, list):
    return data
  if isinstance(data, dict):
    rows = []
    for key, value in data.items():
      if isinstance(value, dict):
        row = dict(value)
        row.setdefault("uuid", key)
        rows.append(row)
      else:
        rows.append({"uuid": key, "value": value})
    return rows
  for key in ("entities", "items", "value", "results"):
    if isinstance(parsed.get(key), list):
      return parsed[key]
  return []


def _port_set_uuid(item):
  if isinstance(item, str):
    return _uuid_str(item)
  if not isinstance(item, dict):
    return None
  return _uuid_str(
      item.get("uuid") or item.get("ext_id") or item.get("UUID") or
      item.get("id"))


def fetch_port_set_list(platform_info, timeout_secs):
  LOG.info(
      "DUMP start port_set_list platform=%s method=%s smsp_uuid=%s",
      platform_info.get("platform"),
      platform_info.get("detection_method"),
      platform_info.get("smsp_cluster_uuid") or "<none>")
  parsed, _status, cmd = _run_atlas_cli(
      platform_info, ["port_set.list"], timeout_secs)
  if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
    raise RuntimeError(
        "atlas_cli port_set.list status=%s cmd=%s" % (
            parsed.get("status"), " ".join(cmd)))
  rows = _port_set_list_rows(parsed)
  LOG.info("DUMP done port_set_list count=%s", len(rows))
  return rows


def _port_set_get_record(parsed, ps_uuid):
  if not isinstance(parsed, dict):
    return parsed if parsed is not None else {}
  data = parsed.get("data", parsed)
  if isinstance(data, dict):
    if ps_uuid in data and isinstance(data[ps_uuid], dict):
      return data[ps_uuid]
    if data.get("uuid") == ps_uuid or data.get("ext_id") == ps_uuid:
      return data
    if "data" in parsed and isinstance(parsed["data"], dict):
      inner = parsed["data"]
      if ps_uuid in inner:
        return inner[ps_uuid]
      if len(inner) == 1:
        only = list(inner.values())[0]
        if isinstance(only, dict):
          return only
    return data
  if isinstance(data, list) and data and isinstance(data[0], dict):
    return data[0]
  return parsed


def _normalize_port_set_get(gets):
  """Unwrap atlas_cli {data: {uuid: rec}} accidentally stored as the rec."""
  if not isinstance(gets, dict):
    return gets or {}
  out = {}
  for uid, rec in gets.items():
    if not isinstance(rec, dict):
      continue
    inner = rec
    nested = rec.get(uid)
    if isinstance(nested, dict) and (
        "virtual_nic_uuid_list" in nested or nested.get("name") is not None):
      inner = nested
    elif "virtual_nic_uuid_list" not in rec:
      candidates = [
          value for key, value in rec.items()
          if key != "uuid" and isinstance(value, dict) and (
              "virtual_nic_uuid_list" in value or value.get("name") is not None)]
      if len(candidates) == 1:
        inner = candidates[0]
    if isinstance(inner, dict):
      inner = dict(inner)
      inner.setdefault("uuid", uid)
    out[uid] = inner
  return out


def fetch_port_set_get(platform_info, uuids, workers, timeout_secs, errors):
  gets = {}
  if not uuids:
    LOG.info("DUMP skip port_set_get (no UUIDs from port_set.list)")
    return gets
  per_timeout = max(15, min(45, int(timeout_secs)))
  LOG.info("DUMP start port_set_get count=%s workers=%s", len(uuids), workers)

  def _one(ps_uuid):
    parsed, _status, _cmd = _run_atlas_cli(
        platform_info, ["port_set.get", ps_uuid], per_timeout, log_cmd=False)
    if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
      raise RuntimeError("status=%s" % parsed.get("status"))
    rec = _port_set_get_record(parsed, ps_uuid)
    if isinstance(rec, dict):
      rec.setdefault("uuid", ps_uuid)
    return rec

  failed = []
  with ThreadPoolExecutor(max_workers=max(1, min(workers, len(uuids)))) as pool:
    future_map = {pool.submit(_one, ps_uuid): ps_uuid for ps_uuid in uuids}
    done, pending = wait(future_map.keys(), timeout=timeout_secs)
    for future in done:
      ps_uuid = future_map[future]
      try:
        gets[ps_uuid] = future.result(timeout=1)
      except Exception as err:
        failed.append(ps_uuid)
        LOG.error("DUMP port_set.get %s FAILED: %s", ps_uuid, err)
    for future in pending:
      ps_uuid = future_map[future]
      future.cancel()
      failed.append(ps_uuid)
      LOG.error("DUMP port_set.get %s TIMEOUT after %ss", ps_uuid, timeout_secs)
  if failed:
    errors["port_set_get"] = "failed %s of %s: %s" % (
        len(failed), len(uuids), ",".join(failed[:20]))
  LOG.info(
      "DUMP done port_set_get got=%s failed=%s", len(gets), len(failed))
  return gets


def dump_atlas_port_sets(output_dir, workers=32, timeout_secs=1800):
  """atlas_cli port_set.list + port_set.get into dump JSON files."""
  errors = {}
  info = detect_msp_platform()
  list_timeout = max(60, min(300, int(timeout_secs)))
  try:
    rows = fetch_port_set_list(info, list_timeout)
  except Exception as err:
    errors["port_set_list"] = str(err)
    LOG.error("DATASET port_set_list FAILED: %s", err)
    rows = []
  _write_json_file(os.path.join(output_dir, "port_set_list.json"), rows)
  uuids = []
  seen = set()
  for item in rows:
    uid = _port_set_uuid(item)
    if uid and uid not in seen:
      seen.add(uid)
      uuids.append(uid)
  try:
    gets = fetch_port_set_get(
        info, uuids, max(1, int(workers)), max(60, int(timeout_secs)), errors)
  except Exception as err:
    errors["port_set_get"] = str(err)
    LOG.error("DATASET port_set_get FAILED: %s", err)
    gets = {}
  gets = _normalize_port_set_get(gets)
  _write_json_file(os.path.join(output_dir, "port_set_get.json"), gets)
  rec = {
      "ran": True,
      "platform": info.get("platform") or "",
      "detection_method": info.get("detection_method") or "",
      "list_count": len(rows),
      "get_count": len(gets),
      "errors": errors,
  }
  LOG.info(
      "DUMP atlas port_set list=%s get=%s platform=%s",
      rec["list_count"], rec["get_count"], rec["platform"])
  return rec


# Host OVS via AHV Gateway mTLS; OVN NB/SB via kubectl on CMSP PC.
NCLI_BIN_CANDIDATES = (
    "/usr/local/nutanix/bin/ncli",
    "/home/nutanix/prism/cli/ncli",
    "/usr/local/nutanix/cluster/bin/ncli",
    "/usr/bin/ncli")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NCLI_CLUSTER_ID_RE = re.compile(
    r"Cluster Id\s*:\s*([0-9a-fA-F-]{36})", re.I)

def _ncli_bin():
  for path in NCLI_BIN_CANDIDATES:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "ncli"


def _run_cmd_argv(argv, timeout_secs, cwd=None, stdout_path=None, binary=False):
  if not argv:
    return -1, "", "empty argv"
  timeout_secs = max(5, int(timeout_secs))
  try:
    if stdout_path:
      os.makedirs(os.path.dirname(stdout_path) or ".", exist_ok=True)
      mode = "wb" if binary else "w"
      with open(stdout_path, mode) as handle:
        proc = subprocess.run(
            argv, stdout=handle, stderr=subprocess.PIPE, check=False,
            timeout=timeout_secs, stdin=subprocess.DEVNULL, cwd=cwd,
            text=not binary)
      stderr = proc.stderr or (b"" if binary else "")
      if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
      return proc.returncode, "", stderr
    proc = subprocess.run(
        argv, capture_output=True, text=True, check=False,
        timeout=timeout_secs, stdin=subprocess.DEVNULL, cwd=cwd)
  except subprocess.TimeoutExpired as err:
    out = err.stdout or ""
    if isinstance(out, bytes):
      out = out.decode("utf-8", "replace")
    return -1, out or "", "timed out after %ss: %s" % (
        timeout_secs, " ".join(str(x) for x in argv))
  except Exception as err:
    return -1, "", str(err)
  return proc.returncode, proc.stdout or "", proc.stderr or ""

def _clean_ipv4(raw):
  text = str(raw or "").strip().strip("[],;\"'")
  if text.lower() in ("", "-", "none", "null", "n/a"):
    return ""
  if isinstance(raw, dict):
    text = str(raw.get("value") or raw.get("ipv4") or raw.get("ip") or "")
    if isinstance(text, dict):
      text = str(text.get("value") or "")
    text = text.strip()
  if _IPV4_RE.match(text):
    return text
  return ""


def _ncli_run(args, timeout_secs=60):
  binary = _ncli_bin()
  argv = [binary] + list(args)
  rc, stdout, stderr = _run_cmd_argv(argv, timeout_secs)
  if rc == 0 or stdout:
    return rc, stdout, stderr
  cmd = " ".join(["ncli"] + list(args))
  out, err, prc = _run_profile_cmd(cmd, timeout=timeout_secs)
  return prc, out, err


def _ncli_local_cluster():
  rec = {"ext_id": "", "name": "", "vip": ""}
  for args in (
      ["cluster", "info"],
      ["cluster", "get-params", "json=true"],
      ["cluster", "get-params", "-json=true"],
  ):
    rc, stdout, stderr = _ncli_run(args, timeout_secs=45)
    text = "%s\n%s" % (stdout, stderr)
    parsed = _safe_json_loads(stdout)
    if isinstance(parsed, dict):
      data = parsed.get("data") or parsed.get("clusterInfo") or parsed
      if isinstance(data, list) and data:
        data = data[0]
      if isinstance(data, dict):
        rec["ext_id"] = rec["ext_id"] or _uuid_str(
            data.get("clusterUuid") or data.get("uuid") or
            data.get("id") or data.get("cluster_uuid")) or ""
        rec["name"] = rec["name"] or str(
            data.get("clusterName") or data.get("name") or "")
        rec["vip"] = rec["vip"] or _clean_ipv4(
            data.get("clusterExternalIPAddress")
            or data.get("clusterExternalIp")
            or data.get("externalIp"))
    uid_match = _NCLI_CLUSTER_ID_RE.search(text)
    if uid_match:
      rec["ext_id"] = rec["ext_id"] or (_uuid_str(uid_match.group(1)) or "")
    name_match = re.search(r"Cluster Name\s*:\s*(.+)", text, re.I)
    if name_match and not rec["name"]:
      rec["name"] = name_match.group(1).strip()
    vip_match = re.search(
        r"Cluster External IP(?: Address)?\s*:\s*(\S+)", text, re.I)
    if vip_match and not rec["vip"]:
      rec["vip"] = _clean_ipv4(vip_match.group(1))
    if rec["ext_id"]:
      break
  return rec


def _parse_ncli_multicluster_json(parsed):
  rows = []
  if isinstance(parsed, dict):
    data = parsed.get("data") or parsed.get("clusters") or parsed.get("items")
    if data is None:
      data = [parsed]
  elif isinstance(parsed, list):
    data = parsed
  else:
    return rows
  for entry in data:
    if not isinstance(entry, dict):
      continue
    details = entry.get("clusterDetails") or entry.get("cluster_details") or {}
    if not isinstance(details, dict):
      details = {}
    uid = _uuid_str(
        entry.get("clusterUuid") or entry.get("cluster_uuid")
        or entry.get("uuid") or entry.get("id")
        or details.get("clusterUuid") or details.get("uuid")) or ""
    if not uid:
      continue
    name = (
        entry.get("clusterName") or entry.get("cluster_name")
        or entry.get("name") or details.get("clusterName")
        or details.get("name") or "")
    vip = _clean_ipv4(
        entry.get("clusterExternalIPAddress")
        or entry.get("clusterExternalIp")
        or entry.get("externalIp")
        or details.get("clusterExternalIPAddress")
        or details.get("clusterExternalIp")
        or details.get("externalIp"))
    ips_raw = (
        details.get("ipAddresses") or details.get("ip_addresses")
        or entry.get("ipAddresses") or entry.get("controllerVmIps")
        or [])
    cvm_ips = []
    for ip in _as_list(ips_raw):
      cleaned = _clean_ipv4(ip)
      if cleaned and cleaned not in cvm_ips:
        cvm_ips.append(cleaned)
    rows.append({
        "ext_id": uid,
        "name": str(name or ""),
        "vip": vip,
        "cvm_ips": cvm_ips,
        "cluster_type": str(
            entry.get("clusterType") or entry.get("clusterFunction")
            or details.get("clusterType") or ""),
        "source": "ncli_multicluster_json",
    })
  return rows


def _parse_ncli_multicluster_text(text):
  rows = []
  blocks = re.split(r"(?=Cluster Id\s*:)", text or "", flags=re.I)
  for block in blocks:
    uid_match = _NCLI_CLUSTER_ID_RE.search(block)
    if not uid_match:
      continue
    uid = _uuid_str(uid_match.group(1)) or ""
    if not uid:
      continue
    name_match = re.search(r"Cluster Name\s*:\s*(.+)", block, re.I)
    vip_match = re.search(
        r"Cluster External IP(?: Address)?\s*:\s*(\S+)", block, re.I)
    if not vip_match:
      vip_match = re.search(
          r"External (?:or Masquerading )?IP(?: Address)?\s*:\s*(\S+)",
          block, re.I)
    cvm_match = re.search(
        r"Controller VM IP Addre[^:]*:\s*\[([^\]]*)\]", block, re.I)
    ctype_match = re.search(
        r"Cluster (?:Type|Function)\s*:\s*(\S+)", block, re.I)
    cvm_ips = []
    if cvm_match:
      for part in cvm_match.group(1).split(","):
        cleaned = _clean_ipv4(part)
        if cleaned and cleaned not in cvm_ips:
          cvm_ips.append(cleaned)
    rows.append({
        "ext_id": uid,
        "name": (name_match.group(1).strip() if name_match else ""),
        "vip": _clean_ipv4(vip_match.group(1) if vip_match else ""),
        "cvm_ips": cvm_ips,
        "cluster_type": (ctype_match.group(1).strip() if ctype_match else ""),
        "source": "ncli_multicluster_text",
    })
  return rows


def _ncli_registered_clusters():
  rows = []
  for args in (
      ["multicluster", "get-cluster-state", "json=true"],
      ["multicluster", "get-cluster-state", "--json=true"],
      ["multicluster", "get-cluster-state", "-json=true"],
      ["multicluster", "get-cluster-state"],
      ["cluster", "list"],
  ):
    rc, stdout, stderr = _ncli_run(args, timeout_secs=60)
    text = "%s\n%s" % (stdout, stderr)
    parsed = _safe_json_loads(stdout)
    found = []
    if parsed is not None:
      found = _parse_ncli_multicluster_json(parsed)
    if not found:
      found = _parse_ncli_multicluster_text(text)
    if found:
      rows = found
      break
  return rows


def _cluster_from_dump_row(row):
  if not isinstance(row, dict):
    return {}
  uid = _uuid_str(row.get("ext_id") or row.get("uuid") or row.get("id")) or ""
  name = row.get("name") or ""
  net = ((row.get("network") or {}).get("external_address") or {})
  ipv4 = net.get("ipv4") if isinstance(net, dict) else {}
  vip = ""
  if isinstance(ipv4, dict):
    vip = _clean_ipv4(ipv4.get("value"))
  elif ipv4:
    vip = _clean_ipv4(ipv4)
  if not vip:
    vip = _clean_ipv4(row.get("vip") or row.get("ip_address"))
  return {
      "ext_id": uid,
      "name": str(name or ""),
      "vip": vip,
      "cvm_ips": list(row.get("cvm_ips") or []),
      "cluster_type": str(row.get("cluster_type") or ""),
      "source": row.get("source") or "dump",
  }


def _is_pc_cluster(rec, local_uuid=""):
  uid = (rec.get("ext_id") or "").lower()
  if local_uuid and uid and uid == local_uuid.lower():
    return True
  name = str(rec.get("name") or "").strip()
  if re.match(r"^PC[_\-\s]", name, re.I):
    return True
  if name.lower() in ("prism central", "prism_central", "prismcentral"):
    return True
  ctype = str(rec.get("cluster_type") or rec.get("cluster_function") or "")
  if re.search(
      r"multicluster|prism.?central|kprismcentral|\bkpc\b", ctype, re.I):
    return True
  return False


def _merge_pe_rec(dst, src):
  if not dst:
    return dict(src)
  for key in ("name", "vip", "cluster_type", "source"):
    if not dst.get(key) and src.get(key):
      dst[key] = src[key]
  cvms = list(dst.get("cvm_ips") or [])
  for ip in src.get("cvm_ips") or []:
    if ip and ip not in cvms:
      cvms.append(ip)
  dst["cvm_ips"] = cvms
  return dst


def _discover_pe_clusters(dump_clusters=None):
  local = _ncli_local_cluster()
  local_uuid = local.get("ext_id") or ""
  found = {}
  errors = []
  sources = []

  def _add(rec, source):
    if not rec:
      return
    rec = dict(rec)
    rec["source"] = source
    uid = rec.get("ext_id") or ""
    if not uid:
      return
    if _is_pc_cluster(rec, local_uuid):
      return
    found[uid] = _merge_pe_rec(found.get(uid), rec)

  if dump_clusters:
    sources.append("dump_clusters")
    for row in dump_clusters:
      _add(_cluster_from_dump_row(row), "dump_clusters")
  try:
    ncli_rows = _ncli_registered_clusters()
    if ncli_rows:
      sources.append("ncli")
      for rec in ncli_rows:
        _add(rec, rec.get("source") or "ncli")
  except Exception as err:
    errors.append("ncli: %s" % err)
  try:
    idf_rows, idf_errs = _idf_mapped(("cluster",), _map_cluster)
    for err in idf_errs:
      errors.append("idf: %s" % err)
    if idf_rows:
      sources.append("idf")
      for row in idf_rows:
        _add(_cluster_from_dump_row(row), "idf")
  except Exception as err:
    errors.append("idf: %s" % err)
  pes = list(found.values())
  pes.sort(key=lambda item: item.get("ext_id") or "")
  LOG.info(
      "DUMP PE discovery count=%s local_pc=%s sources=%s",
      len(pes), local_uuid or "<none>", ",".join(sources) or "<none>")
  return pes, errors, sources, local


# AHV Gateway (PC → PE hypervisor :7030 mTLS). Never SSH to AHV.
AHV_GW_REQUIRED = (
    "ovs-vsctl_show",
    "ovs-dpctl_-s_show",
    "ovs-ofctl_dump-flows_brAtlas",
    "virsh_list",
    "virsh_dumpxml",
    "tap_interface",
    "ovn_or_ovs_db",
)
AHV_GW_CERT_FALLBACKS = (
    "/home/certs/ClusterHealthService",
    "/home/certs/PanaceaService",
    "/home/certs/GenesisService",
)


def _ahv_gw_port():
  try:
    return int(getattr(FLAGS, "ahv_gateway_port", 7030) or 7030)
  except (TypeError, ValueError):
    return 7030


def _ahv_gw_cert_pair():
  dirs = []
  flagged = str(getattr(FLAGS, "ahv_gateway_cert_dir", "") or "").strip()
  if flagged:
    dirs.append(flagged)
  dirs.extend(AHV_GW_CERT_FALLBACKS)
  seen = set()
  for directory in dirs:
    directory = os.path.abspath(directory)
    if directory in seen or not os.path.isdir(directory):
      continue
    seen.add(directory)
    name = os.path.basename(directory.rstrip("/"))
    crt = os.path.join(directory, name + ".crt")
    key = os.path.join(directory, name + ".key")
    if os.path.isfile(crt) and os.path.isfile(key):
      return crt, key, directory
  return "", "", ""


def _ahv_gw_ssl_context(crt, key):
  ctx = ssl._create_unverified_context()  # AHV GW SAN omits 192.168.5.1
  ctx.load_cert_chain(crt, key)
  return ctx


def _ahv_gw_open(host, path, crt, key, timeout_secs, accept="application/octet-stream"):
  if not path.startswith("/"):
    path = "/" + path
  url = "https://%s:%s/api%s" % (host, _ahv_gw_port(), path)
  req = Request(url, headers={"Accept": accept, "Accept-Encoding": "identity"})
  return urlopen(
      req, context=_ahv_gw_ssl_context(crt, key), timeout=timeout_secs)


def _ahv_gw_safe_relpath(member_name):
  text = str(member_name or "").replace("\\", "/").lstrip("/")
  parts = [p for p in text.split("/") if p and p not in (".", "..")]
  return os.path.join(*parts) if parts else ""


def _ahv_gw_write_member(dest_dir, member_name, data):
  rel = _ahv_gw_safe_relpath(member_name)
  if not rel:
    return ""
  path = os.path.join(dest_dir, rel)
  parent = os.path.dirname(path)
  if parent:
    os.makedirs(parent, exist_ok=True)
  with open(path, "wb") as handle:
    handle.write(data or b"")
  return path


def _ahv_gw_keep_networking(name):
  n = str(name or "").replace("\\", "/")
  base = n.split("/")[-1]
  low = n.lower()
  if "bratlas" in low and n.endswith((".stdout", ".stderr", ".rc", ".timeout")):
    return True
  if base in ("ovs-vsctl_show.stdout", "ovs-dpctl_-s_show.stdout"):
    return True
  if base.endswith(".db") and (
      "ovn" in low or "openvswitch" in low or base == "conf.db"):
    return True
  if any(tok in low for tok in (
      "ovn-nbctl", "ovn-sbctl", "ovnnb", "ovnsb", "ovn-controller")):
    return n.endswith(".stdout") or n.endswith(".db")
  return False


def _ahv_gw_keep_avm(name):
  n = str(name or "").replace("\\", "/").lower()
  if "virsh" in n and "list_--all" in n and n.endswith(
      (".stdout", ".stderr", ".rc")):
    return True
  if "dumpxml" in n and n.endswith(".stdout") and "net-dumpxml" not in n:
    return True
  if n.endswith(".stdout") and any(
      tok in n for tok in ("tuntap", "domiflist")):
    return True
  return False


def _ahv_gw_keep_ovn(name):
  n = str(name or "").replace("\\", "/").lower()
  return n.endswith(".db") or "ovn" in n


def _ahv_gw_keep_for_class(cls, name):
  if cls == "networking":
    return _ahv_gw_keep_networking(name)
  if cls == "avm":
    return _ahv_gw_keep_avm(name)
  if "ovn" in str(cls or "").lower():
    return _ahv_gw_keep_ovn(name)
  return False


def _ahv_gw_classify_saved(path, member_name):
  n = str(member_name or path or "").replace("\\", "/")
  low = n.lower()
  keys = []
  size = 0
  try:
    size = os.path.getsize(path) if path and os.path.isfile(path) else 0
  except OSError:
    size = 0
  if low.endswith("ovs-vsctl_show.stdout") and size > 0:
    keys.append("ovs-vsctl_show")
  if "ovs-dpctl_-s_show.stdout" in low and size > 0:
    keys.append("ovs-dpctl_-s_show")
  if "dump-flows_bratlas.stdout" in low and size > 100:
    keys.append("ovs-ofctl_dump-flows_brAtlas")
  if "virsh" in low and "list_--all.stdout" in low and size > 0:
    keys.append("virsh_list")
  if "dumpxml" in low and low.endswith(".stdout") and "net-dumpxml" not in low:
    if size > 0:
      keys.append("virsh_dumpxml")
      blob = b""
      try:
        blob = open(path, "rb").read(65536)
      except Exception:
        pass
      if b"<target" in blob and b"tap" in blob.lower():
        keys.append("tap_interface")
  if low.endswith(".stdout") and any(
      tok in low for tok in ("tuntap", "domiflist")) and size > 0:
    keys.append("tap_interface")
  if size > 0 and (
      (low.endswith(".db") and ("ovn" in low or "openvswitch" in low or
                                low.endswith("conf.db"))) or
      any(tok in low for tok in ("ovnnb", "ovnsb", "ovn-nb", "ovn-sb"))):
    keys.append("ovn_or_ovs_db")
  return keys


def _ahv_gw_scan_collected(host_dir):
  found = set()
  files = []
  if not host_dir or not os.path.isdir(host_dir):
    return found, files
  for root, _, names in os.walk(host_dir):
    for name in names:
      if name == "host.json":
        continue
      path = os.path.join(root, name)
      rel = os.path.relpath(path, host_dir).replace("\\", "/")
      files.append(rel)
      found.update(_ahv_gw_classify_saved(path, rel))
  return found, files


def _ahv_gw_list_classes(host, crt, key, timeout_secs):
  names = []
  try:
    resp = _ahv_gw_open(
        host, "/host/v1/bugtool-classes", crt, key, min(timeout_secs, 30),
        accept="application/json")
    raw = resp.read()
    resp.close()
    data = json.loads(raw.decode("utf-8", "replace") or "{}")
    for item in data.get("classes") or []:
      if isinstance(item, dict) and item.get("name"):
        names.append(str(item.get("name")))
      elif item:
        names.append(str(item))
  except Exception as err:
    LOG.debug("AHV GW class list %s failed: %s", host, err)
  return names


def _ahv_gw_extract_class(host, cls, dest_dir, crt, key, timeout_secs):
  saved = []
  resp = None
  try:
    resp = _ahv_gw_open(
        host, "/host/v1/bugtool/%s" % cls, crt, key, timeout_secs)
    tar = tarfile.open(fileobj=resp, mode="r|*")
    for member in tar:
      if not getattr(member, "isfile", lambda: False)():
        continue
      if not _ahv_gw_keep_for_class(cls, member.name):
        continue
      handle = tar.extractfile(member)
      data = handle.read() if handle is not None else b""
      path = _ahv_gw_write_member(dest_dir, member.name, data)
      if path:
        saved.append(path)
  finally:
    if resp is not None:
      try:
        resp.close()
      except Exception:
        pass
  return saved


def _host_hypervisor_ip(row):
  if not isinstance(row, dict):
    return ""
  hyp = row.get("hypervisor") or {}
  addr = hyp.get("external_address") if isinstance(hyp, dict) else {}
  ipv4 = addr.get("ipv4") if isinstance(addr, dict) else {}
  ip_addr = ""
  if isinstance(ipv4, dict):
    ip_addr = ipv4.get("value") or ""
  return _clean_ipv4(
      ip_addr
      or row.get("hypervisor_ip")
      or row.get("hypervisor_address")
      or row.get("host_ip"))


def _ncli_hypervisor_ips(cluster_uuid=""):
  ips = []
  arg_sets = []
  if cluster_uuid:
    arg_sets.extend((
        ["host", "list", "cluster-uuid=%s" % cluster_uuid],
        ["host", "list", "cluster-id=%s" % cluster_uuid],
    ))
  arg_sets.append(["host", "list"])
  for args in arg_sets:
    _rc, stdout, stderr = _ncli_run(args, timeout_secs=60)
    text = "%s\n%s" % (stdout, stderr)
    found = []
    for match in re.finditer(
        r"Hypervisor(?: IP)?(?: Address)?\s*:\s*(\S+)", text, re.I):
      ip_addr = _clean_ipv4(match.group(1))
      if ip_addr:
        found.append(ip_addr)
    if found:
      ips.extend(found)
      break
  out = []
  seen = set()
  for ip_addr in ips:
    if ip_addr not in seen:
      seen.add(ip_addr)
      out.append(ip_addr)
  return out


def _ahv_gw_discover_hosts(dump_hosts=None, dump_clusters=None):
  pes, disc_errors, disc_sources, local_pc = _discover_pe_clusters(
      dump_clusters)
  local_uuid = (local_pc or {}).get("ext_id") or ""
  pe_uuids = set(
      (rec.get("ext_id") or "").lower()
      for rec in pes if rec.get("ext_id"))
  hosts = {}

  def _add(ip_addr, name="", cluster_uuid="", source=""):
    ip_addr = _clean_ipv4(ip_addr)
    if not ip_addr:
      return
    rec = hosts.get(ip_addr) or {
        "ip": ip_addr, "name": "", "cluster_uuid": "", "sources": []}
    if name and not rec["name"]:
      rec["name"] = name
    if cluster_uuid and not rec["cluster_uuid"]:
      rec["cluster_uuid"] = cluster_uuid
    if source and source not in rec["sources"]:
      rec["sources"].append(source)
    hosts[ip_addr] = rec

  for row in dump_hosts or []:
    cluster_uuid = ""
    cluster = row.get("cluster") if isinstance(row, dict) else None
    if isinstance(cluster, dict):
      cluster_uuid = _uuid_str(
          cluster.get("uuid") or cluster.get("ext_id")) or ""
    if local_uuid and cluster_uuid and cluster_uuid.lower() == local_uuid.lower():
      continue
    if pe_uuids and cluster_uuid and cluster_uuid.lower() not in pe_uuids:
      continue
    _add(
        _host_hypervisor_ip(row),
        name=str((row or {}).get("host_name") or (row or {}).get("name") or ""),
        cluster_uuid=cluster_uuid,
        source="dump_hosts")
  for rec in pes:
    uid = rec.get("ext_id") or ""
    for ip_addr in _ncli_hypervisor_ips(uid):
      _add(ip_addr, cluster_uuid=uid, source="ncli_host_list")
  rows = list(hosts.values())
  rows.sort(key=lambda item: item.get("ip") or "")
  LOG.info(
      "DUMP AHV GW hosts=%s pe_clusters=%s sources=%s",
      len(rows), len(pes), ",".join(disc_sources) or "<none>")
  return rows, disc_errors, disc_sources, local_pc


def _ahv_gw_classes_for_missing(missing, advertised):
  classes = []
  if missing & set((
      "ovs-vsctl_show", "ovs-dpctl_-s_show",
      "ovs-ofctl_dump-flows_brAtlas", "ovn_or_ovs_db")):
    classes.append("networking")
  if missing & set(("virsh_list", "virsh_dumpxml", "tap_interface")):
    classes.append("avm")
  for name in advertised or []:
    if "ovn" in name.lower() and name not in classes:
      if "ovn_or_ovs_db" in missing:
        classes.append(name)
  out = []
  seen = set()
  for cls in classes:
    if cls not in seen:
      seen.add(cls)
      out.append(cls)
  return out or ["networking", "avm"]


def _ahv_gw_collect_one_host(host_rec, dest_root, crt, key, deadline):
  ip_addr = host_rec.get("ip") or ""
  host_dir = os.path.join(dest_root, ip_addr)
  os.makedirs(host_dir, exist_ok=True)
  rec = {
      "ip": ip_addr,
      "name": host_rec.get("name") or "",
      "cluster_uuid": host_rec.get("cluster_uuid") or "",
      "attempts": 0,
      "classes": [],
      "collected": [],
      "missing": list(AHV_GW_REQUIRED),
      "complete": False,
      "error": "",
      "files": [],
  }
  advertised = []
  class_timeout = max(30, int(getattr(
      FLAGS, "ahv_gateway_class_timeout_secs", 300) or 300))
  backoff = 5
  while time.time() < deadline:
    found, files = _ahv_gw_scan_collected(host_dir)
    missing = [key for key in AHV_GW_REQUIRED if key not in found]
    rec["collected"] = sorted(found)
    rec["missing"] = missing
    rec["files"] = files
    if not missing:
      rec["complete"] = True
      rec["error"] = ""
      return rec
    if not advertised:
      advertised = _ahv_gw_list_classes(
          ip_addr, crt, key, min(30, max(5, int(deadline - time.time()))))
      rec["advertised_classes"] = advertised
    rec["attempts"] += 1
    classes = _ahv_gw_classes_for_missing(set(missing), advertised)
    rec["classes"] = classes
    LOG.info(
        "DUMP AHV GW %s attempt=%s missing=%s classes=%s",
        ip_addr, rec["attempts"], ",".join(missing), ",".join(classes))
    errors = []
    for cls in classes:
      if time.time() >= deadline:
        break
      remain = max(15, int(deadline - time.time()))
      try:
        _ahv_gw_extract_class(
            ip_addr, cls, host_dir, crt, key, min(class_timeout, remain))
      except Exception as err:
        errors.append("%s:%s" % (cls, err))
        LOG.warning("DUMP AHV GW %s class %s failed: %s", ip_addr, cls, err)
    rec["error"] = "; ".join(errors)[:2000]
    found, files = _ahv_gw_scan_collected(host_dir)
    missing = [key for key in AHV_GW_REQUIRED if key not in found]
    rec["collected"] = sorted(found)
    rec["missing"] = missing
    rec["files"] = files
    if not missing:
      rec["complete"] = True
      rec["error"] = ""
      return rec
    sleep_for = min(backoff, max(0, int(deadline - time.time())))
    if sleep_for <= 0:
      break
    time.sleep(sleep_for)
    backoff = min(30, backoff * 2)
  rec["complete"] = False
  if not rec["error"]:
    rec["error"] = "deadline with missing: %s" % ",".join(
        rec.get("missing") or [])
  return rec


def fetch_ahv_gateway_host_state(output_dir, dump_hosts=None, dump_clusters=None,
                                 timeout_secs=1800):
  dest_root = os.path.join(output_dir, "ahv_gateway")
  os.makedirs(dest_root, exist_ok=True)
  timeout_secs = max(60, int(timeout_secs or 1800))
  payload = {
      "ran": False,
      "complete": False,
      "transport": "ahv_gateway_mtls",
      "ssh_to_ahv": False,
      "port": _ahv_gw_port(),
      "required": list(AHV_GW_REQUIRED),
      "hosts": [],
      "hosts_total": 0,
      "hosts_ok": 0,
      "error": "",
      "cert_dir": "",
  }
  crt, key, cert_dir = _ahv_gw_cert_pair()
  payload["cert_dir"] = cert_dir
  if not crt:
    payload["error"] = (
        "AHV Gateway client certs not found under %s" % (
            getattr(FLAGS, "ahv_gateway_cert_dir", "") or
            AHV_GW_CERT_FALLBACKS[0]))
    LOG.warning("DUMP AHV GW: %s", payload["error"])
    _write_json_file(os.path.join(dest_root, "index.json"), payload)
    return payload
  hosts, disc_errors, disc_sources, local_pc = _ahv_gw_discover_hosts(
      dump_hosts, dump_clusters)
  payload["discovery"] = {
      "sources": disc_sources,
      "errors": disc_errors,
      "local_pc": local_pc,
  }
  payload["hosts_total"] = len(hosts)
  if not hosts:
    payload["error"] = "no PE hypervisor IPs for AHV Gateway collect"
    LOG.warning("DUMP AHV GW: %s", payload["error"])
    _write_json_file(os.path.join(dest_root, "index.json"), payload)
    return payload
  payload["ran"] = True
  deadline = time.time() + timeout_secs
  workers = max(1, int(getattr(FLAGS, "ahv_gateway_workers", 8) or 8))
  LOG.info(
      "DUMP AHV GW start hosts=%s workers=%s timeout=%ss cert=%s",
      len(hosts), workers, timeout_secs, cert_dir)
  recs = []
  if workers == 1 or len(hosts) == 1:
    for host_rec in hosts:
      recs.append(_ahv_gw_collect_one_host(
          host_rec, dest_root, crt, key, deadline))
  else:
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
      futs = [
          pool.submit(
              _ahv_gw_collect_one_host, host_rec, dest_root, crt, key,
              deadline)
          for host_rec in hosts
      ]
      for fut in futs:
        recs.append(fut.result())
  recs.sort(key=lambda item: item.get("ip") or "")
  payload["hosts"] = recs
  payload["hosts_ok"] = sum(1 for rec in recs if rec.get("complete"))
  payload["complete"] = bool(recs) and payload["hosts_ok"] == len(recs)
  if not payload["complete"]:
    bad = [
        "%s:%s" % (rec.get("ip"), ",".join(rec.get("missing") or []))
        for rec in recs if not rec.get("complete")
    ]
    payload["error"] = (
        "AHV Gateway incomplete %s/%s hosts: %s" % (
            payload["hosts_ok"], len(recs), "; ".join(bad[:12])))
    LOG.warning("DUMP AHV GW: %s", payload["error"][:500])
  else:
    LOG.info("DUMP AHV GW complete hosts=%s", len(recs))
  _write_json_file(os.path.join(dest_root, "index.json"), payload)
  return payload


KUBECTL_BIN_CANDIDATES = (
    "/usr/bin/kubectl",
    "/usr/local/bin/kubectl",
    "/home/nutanix/bin/kubectl",
)

# CMSP: dump live OVN NB/SB from the ANC northd pod. Same as:
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
#   sudo kubectl exec anc-ovn-0 -c anc-ovn -- \
#     ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
CMSP_OVN_POD = "anc-ovn-0"
CMSP_OVN_CONTAINER = "anc-ovn"
CMSP_OVN_NB_SOCK = "unix:/var/run/ovn/ovnnb_db.sock"
CMSP_OVN_SB_SOCK = "unix:/var/run/ovn/ovnsb_db.sock"

CMSP_OVN_TARGETS = (
    {
        "key": "anc-ovn",
        "app": "anc-ovn",
        "pod": CMSP_OVN_POD,
        "container": CMSP_OVN_CONTAINER,
        "dumps": (
            ("ovsdb-client_dump_nb",
             ["ovsdb-client", "dump", CMSP_OVN_NB_SOCK],
             ("Logical_Switch", "ACL", "NB_Global", "Logical_Router")),
            ("ovsdb-client_dump_sb",
             ["ovsdb-client", "dump", CMSP_OVN_SB_SOCK],
             ("Chassis", "Port_Binding", "Datapath_Binding", "SB_Global")),
        ),
        "files": (
            ("/etc/openvswitch/ovnnb_db.db", "ovnnb_db.db"),
            ("/etc/openvswitch/ovnsb_db.db", "ovnsb_db.db"),
        ),
        "commands": (
            ("ovn-nbctl_show",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "show"]),
            ("ovn-nbctl_ls-list",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "ls-list"]),
            ("ovn-nbctl_lr-list",
             ["ovn-nbctl", "--db=%s" % CMSP_OVN_NB_SOCK, "lr-list"]),
            ("ovn-sbctl_show",
             ["ovn-sbctl", "--db=%s" % CMSP_OVN_SB_SOCK, "show"]),
            ("ovn-sbctl_list_Chassis",
             ["ovn-sbctl", "--db=%s" % CMSP_OVN_SB_SOCK, "list", "Chassis"]),
        ),
        "required": ("ovsdb-client_dump_nb", "ovsdb-client_dump_sb"),
    },
    {
        "key": "anc-ovn-ic-db",
        "app": "anc-ovn-ic-db",
        "pod": "anc-ovn-ic-db-0",
        "container": "anc-ovn-ic-db",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovn_ic_nb_db.db", "ovn_ic_nb_db.db"),
            ("/etc/openvswitch/ovn_ic_sb_db.db", "ovn_ic_sb_db.db"),
        ),
        "commands": (
            ("ovn-ic-nbctl_show",
             ["ovn-ic-nbctl",
              "--db=unix:/var/run/ovn/ovn_ic_nb_db.sock", "show"]),
            ("ovn-ic-sbctl_show",
             ["ovn-ic-sbctl",
              "--db=unix:/var/run/ovn/ovn_ic_sb_db.sock", "show"]),
        ),
        "required": (),
    },
    {
        "key": "anc-policydb",
        "app": "anc-policydb",
        "pod": "anc-policydb-0",
        "container": "anc-policydb",
        "dumps": (),
        "files": (
            ("/etc/openvswitch/ovs-policy-config.db",
             "ovs-policy-config.db"),
        ),
        "commands": (),
        "required": (),
    },
)

_KUBECTL_PREFIX_CACHE = []


def _kubectl_bin():
  for path in KUBECTL_BIN_CANDIDATES:
    if os.path.exists(path) and os.access(path, os.X_OK):
      return path
  return "kubectl"


def _kubectl_prefix():
  """Prefer passwordless sudo kubectl, matching the CMSP runbook command."""
  global _KUBECTL_PREFIX_CACHE
  if _KUBECTL_PREFIX_CACHE:
    return list(_KUBECTL_PREFIX_CACHE)
  kubectl = _kubectl_bin()
  for prefix in (["sudo", "-n", kubectl], ["sudo", kubectl], [kubectl]):
    rc, _stdout, _stderr = _run_cmd_argv(prefix + ["get", "ns"], 20)
    if rc == 0:
      _KUBECTL_PREFIX_CACHE = list(prefix)
      LOG.info("kubectl via %s", " ".join(prefix))
      return list(prefix)
  _KUBECTL_PREFIX_CACHE = ["sudo", "-n", kubectl]
  return list(_KUBECTL_PREFIX_CACHE)


def _kubectl_argv(extra):
  return _kubectl_prefix() + list(extra)


def _cmsp_ovn_namespace():
  return str(getattr(FLAGS, "cmsp_ovn_namespace", "") or "").strip()


def _kubectl_ns_args(namespace):
  if namespace:
    return ["-n", namespace]
  return []


def _kubectl_dump_looks_ok(path, markers):
  if not os.path.isfile(path) or os.path.getsize(path) < 64:
    return False
  try:
    with open(path, "r") as handle:
      head = handle.read(65536)
  except Exception:
    return False
  low = head.lower()
  if low.startswith("error") or "unable to connect" in low:
    return False
  if any(token in head for token in markers):
    return True
  return os.path.getsize(path) > 4096 and "table" in low


def _kubectl_find_pod(app, preferred_name, namespace=""):
  """Find a Running pod. Prefer anc-ovn-0 as in the runbook."""
  ns_flag = ["-n", namespace] if namespace else ["-A"]
  argv = _kubectl_argv([
      "get", "pods"] + ns_flag + [
      "-o",
      "jsonpath={range .items[*]}{.metadata.namespace}{\"\\t\"}"
      "{.metadata.name}{\"\\t\"}{.status.phase}{\"\\t\"}"
      "{.metadata.labels.app}{\"\\n\"}{end}",
  ])
  rc, stdout, stderr = _run_cmd_argv(argv, 45)
  if rc != 0:
    return "", "", (stderr or stdout or "kubectl get pods failed").strip()[:400]
  matches = []
  for line in (stdout or "").splitlines():
    parts = line.split("\t")
    if len(parts) < 3:
      continue
    ns, name, phase = parts[0].strip(), parts[1].strip(), parts[2].strip()
    label = parts[3].strip() if len(parts) > 3 else ""
    if phase != "Running":
      continue
    if name == preferred_name or label == app or name.startswith(app + "-"):
      matches.append((ns, name))
  if not matches:
    return "", "", "no Running pod %s / app=%s" % (preferred_name, app)
  for ns, name in matches:
    if name == preferred_name:
      return ns, name, ""
  for ns, name in matches:
    if name.endswith("-0"):
      return ns, name, ""
  return matches[0][0], matches[0][1], ""


def _kubectl_cp_file(namespace, pod, container, remote_path, dest_path,
                     timeout_secs):
  os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
  extra = ["cp"]
  extra.extend(_kubectl_ns_args(namespace))
  extra.extend(["%s:%s" % (pod, remote_path), dest_path, "-c", container])
  rc, stdout, stderr = _run_cmd_argv(_kubectl_argv(extra), timeout_secs)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  src = "%s/%s:%s" % (namespace or "default", pod, remote_path)
  rc, stdout, stderr = _run_cmd_argv(
      _kubectl_argv(["cp", src, dest_path, "-c", container]), timeout_secs)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  return False, (stderr or stdout or "kubectl cp failed rc=%s" % rc).strip()[:400]


def _kubectl_exec_to_file(namespace, pod, container, remote_argv, dest_path,
                          timeout_secs):
  """sudo kubectl exec POD -c CONTAINER -- CMD  (never -it)."""
  os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
  extra = ["exec"]
  extra.extend(_kubectl_ns_args(namespace))
  extra.extend([pod, "-c", container, "--"] + list(remote_argv))
  rc, _stdout, stderr = _run_cmd_argv(
      _kubectl_argv(extra), timeout_secs, stdout_path=dest_path)
  if rc == 0 and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return True, ""
  return False, (stderr or "kubectl exec failed rc=%s" % rc).strip()[:400]


def _cmsp_ovn_ovsdb_name(path):
  try:
    with open(path, "r") as handle:
      handle.readline()
      schema_line = handle.readline()
  except Exception:
    return ""
  try:
    schema = json.loads(schema_line)
  except Exception:
    return ""
  return str(schema.get("name") or "")


def _collect_cmsp_ovn_target(target, dest_root, namespace, timeout_secs):
  rec = {
      "key": target["key"],
      "app": target["app"],
      "namespace": namespace,
      "pod": "",
      "complete": False,
      "dumps": {},
      "files": {},
      "commands": {},
      "missing": [],
      "error": "",
  }
  dest_dir = os.path.join(dest_root, target["key"])
  cmd_dir = os.path.join(dest_dir, "commands")
  os.makedirs(cmd_dir, exist_ok=True)
  preferred = target.get("pod") or ""
  found_ns, pod, err = _kubectl_find_pod(
      target["app"], preferred, namespace)
  rec["namespace"] = found_ns or namespace
  rec["pod"] = pod or preferred
  if not rec["pod"]:
    rec["error"] = err or "pod not found"
    rec["missing"] = list(target.get("required") or [])
    rec["complete"] = not rec["missing"]
    return rec
  dump_timeout = max(60, min(600, int(timeout_secs)))
  for dump_name, remote_argv, markers in target.get("dumps") or ():
    dest = os.path.join(cmd_dir, dump_name + ".txt")
    ok, dump_err = _kubectl_exec_to_file(
        rec["namespace"], rec["pod"], target["container"], remote_argv,
        dest, dump_timeout)
    looks = bool(ok) and _kubectl_dump_looks_ok(dest, markers)
    rec["dumps"][dump_name] = {
        "ok": looks,
        "bytes": os.path.getsize(dest) if os.path.isfile(dest) else 0,
        "argv": list(remote_argv),
        "error": "" if looks else (
            dump_err or err or "dump missing expected OVN tables"),
    }
    rec["commands"][dump_name] = rec["dumps"][dump_name]
  per_cmd = max(30, min(180, int(timeout_secs)))
  for remote_path, local_name in target.get("files") or ():
    dest = os.path.join(dest_dir, local_name)
    ok, cp_err = _kubectl_cp_file(
        rec["namespace"], rec["pod"], target["container"], remote_path,
        dest, per_cmd)
    rec["files"][local_name] = {
        "ok": ok,
        "bytes": os.path.getsize(dest) if ok else 0,
        "ovsdb_name": _cmsp_ovn_ovsdb_name(dest) if ok else "",
        "error": "" if ok else cp_err,
    }
  for cmd_name, remote_argv in target.get("commands") or ():
    dest = os.path.join(cmd_dir, cmd_name + ".txt")
    ok, cmd_err = _kubectl_exec_to_file(
        rec["namespace"], rec["pod"], target["container"], remote_argv,
        dest, per_cmd)
    rec["commands"][cmd_name] = {
        "ok": ok,
        "bytes": os.path.getsize(dest) if os.path.isfile(dest) else 0,
        "argv": list(remote_argv),
        "error": "" if ok else cmd_err,
    }
  missing = []
  for name in target.get("required") or ():
    if name in rec["dumps"]:
      if not rec["dumps"][name].get("ok"):
        missing.append(name)
    elif name in rec["files"]:
      if not rec["files"][name].get("ok"):
        missing.append(name)
    elif name in rec["commands"]:
      if not rec["commands"][name].get("ok"):
        missing.append(name)
    else:
      missing.append(name)
  rec["missing"] = missing
  rec["complete"] = not missing
  if missing:
    rec["error"] = "missing: %s" % ",".join(missing)
  return rec


def fetch_cmsp_ovn_nb_sb(output_dir, timeout_secs=1800):
  """Dump OVN NB/SB via: sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump ..."""
  dest_root = os.path.join(output_dir, "cmsp_ovn")
  os.makedirs(dest_root, exist_ok=True)
  timeout_secs = max(60, int(timeout_secs or 1800))
  namespace = _cmsp_ovn_namespace()
  payload = {
      "ran": False,
      "complete": False,
      "transport": "kubectl",
      "platform": "cmsp",
      "namespace": namespace,
      "pod": CMSP_OVN_POD,
      "container": CMSP_OVN_CONTAINER,
      "method": (
          "sudo kubectl exec %s -c %s -- ovsdb-client dump %s"
          % (CMSP_OVN_POD, CMSP_OVN_CONTAINER, CMSP_OVN_NB_SOCK)),
      "ssh_to_ahv": False,
      "pods": [],
      "error": "",
      "bundle_dir": dest_root,
  }
  kubectl = _kubectl_bin()
  if not os.path.exists(kubectl) and kubectl == "kubectl":
    which_rc, which_out, _err = _run_cmd_argv(["which", "kubectl"], 10)
    if which_rc != 0 and not which_out.strip():
      payload["error"] = "kubectl not found on this node"
      _write_json_file(os.path.join(dest_root, "index.json"), payload)
      return payload

  deadline = time.time() + timeout_secs
  backoff = 2
  last = []
  while time.time() < deadline:
    last = []
    for target in CMSP_OVN_TARGETS:
      remain = max(60, int(deadline - time.time()))
      last.append(_collect_cmsp_ovn_target(
          target, dest_root, namespace, remain))
    payload["pods"] = last
    payload["ran"] = True
    if last:
      payload["namespace"] = last[0].get("namespace") or namespace
      payload["pod"] = last[0].get("pod") or CMSP_OVN_POD
    if all(rec.get("complete") for rec in last):
      payload["complete"] = True
      payload["error"] = ""
      _write_json_file(os.path.join(dest_root, "index.json"), payload)
      LOG.info(
          "CMSP OVN NB/SB dumped via sudo kubectl exec %s -c %s -- ovsdb-client dump",
          payload.get("pod"), CMSP_OVN_CONTAINER)
      return payload
    missing = []
    for rec in last:
      missing.extend(
          "%s:%s" % (rec.get("key"), name)
          for name in rec.get("missing") or [])
    LOG.info(
        "CMSP OVN collect incomplete (%s); retrying",
        ",".join(missing) or "unknown")
    sleep_for = min(backoff, max(0, int(deadline - time.time())))
    if sleep_for <= 0:
      break
    time.sleep(sleep_for)
    backoff = min(20, backoff * 2)

  payload["pods"] = last
  payload["ran"] = True
  payload["complete"] = False
  missing = []
  for rec in last:
    missing.extend(
        "%s:%s" % (rec.get("key"), name)
        for name in rec.get("missing") or [])
  payload["error"] = "deadline with missing: %s" % (
      ",".join(missing) or "unknown")
  _write_json_file(os.path.join(dest_root, "index.json"), payload)
  return payload


DATASET_FILES = (
    "address_groups", "service_groups", "entity_groups", "policies",
    "vms", "subnets", "vpcs", "hosts", "clusters", "projects",
    "categories", "network_functions", "network_function_by_id",
    "fqdn_to_ip_map", "port_set_list", "port_set_get",
    "ahv_gateway", "cmsp_ovn", "dump_errors")


def _json_default(value):
  if hasattr(value, "hex"):
    return _uuid_str(value)
  if isinstance(value, (bytes, bytearray)):
    return _uuid_str(value) or value.decode("utf-8", "replace")
  if hasattr(value, "isoformat"):
    return value.isoformat()
  return str(value)


def _write_json_file(path, value):
  parent = os.path.dirname(path)
  if parent:
    os.makedirs(parent, exist_ok=True)
  with open(path, "w") as handle:
    json.dump(value, handle, separators=(",", ":"), default=_json_default)
  size = os.path.getsize(path)
  LOG.info("Wrote %s (%s bytes)", path, size)
  return path, size


def _write_outputs(payload, output_dir, combined_path, workers,
                   skip_keys=None, write_combined=True):
  os.makedirs(output_dir, exist_ok=True)
  skip_keys = set(skip_keys or ())
  scalar = {
      "source": payload.get("source"),
      "dumped_at": payload.get("dumped_at"),
      "vlan_unique_uuid": payload.get("vlan_unique_uuid", ""),
      "global_unique_uuid": payload.get("global_unique_uuid", ""),
      "platform": payload.get("platform"),
      "platform_detection_method": payload.get("platform_detection_method"),
      "smsp_cluster_uuid": payload.get("smsp_cluster_uuid", ""),
  }
  jobs = [(os.path.join(output_dir, "meta.json"), scalar)]
  for key in DATASET_FILES:
    if key in payload and key not in skip_keys:
      jobs.append((os.path.join(output_dir, "%s.json" % key), payload[key]))
  if write_combined:
    jobs.append((combined_path, payload))

  LOG.info("Writing %s files under %s%s",
           len(jobs), output_dir,
           (" plus combined %s" % combined_path) if write_combined else "")
  with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
    list(pool.map(lambda item: _write_json_file(item[0], item[1]), jobs))


def _empty_for(name):
  if name == "unique_uuids":
    return {"vlan_unique_uuid": "", "global_unique_uuid": ""}
  if name in (
      "fqdn_to_ip_map", "network_function_by_id", "port_set_get",
      "ahv_gateway", "cmsp_ovn"):
    return {}
  return []


def _run_jobs_parallel(jobs, workers, timeout_secs, errors):
  results = {}
  LOG.info("Parallel batch: %s (workers=%s timeout=%ss)",
           [name for name, _ in jobs], workers, timeout_secs)
  with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
    future_map = {pool.submit(func): name for name, func in jobs}
    done, pending = wait(future_map.keys(), timeout=timeout_secs)
    for future in done:
      name = future_map[future]
      try:
        results[name] = future.result(timeout=1)
        value = results[name]
        if isinstance(value, list):
          LOG.info("DATASET %s dumped %s records", name, len(value))
        elif isinstance(value, dict):
          LOG.info("DATASET %s dumped %s keys", name, len(value))
        else:
          LOG.info("DATASET %s dumped type=%s", name, type(value).__name__)
      except Exception as err:
        errors[name] = str(err)
        results[name] = _empty_for(name)
        LOG.error("DATASET %s FAILED: %s", name, err)
    for future in pending:
      name = future_map[future]
      future.cancel()
      errors[name] = "timeout after %ss" % timeout_secs
      results[name] = _empty_for(name)
      LOG.error("DATASET %s TIMEOUT after %ss", name, timeout_secs)
  return results


def _merge_network_functions(payload):
  rows = list(payload.get("network_functions") or [])
  have = {nf.get("ext_id") for nf in rows if nf.get("ext_id")}
  extra = 0
  for uid, wrapped in (payload.get("network_function_by_id") or {}).items():
    detailed = (wrapped or {}).get("data") or {}
    ext_id = detailed.get("ext_id") or uid
    if ext_id and ext_id not in have:
      rows.append(detailed)
      have.add(ext_id)
      extra += 1
  payload["network_functions"] = rows
  if extra:
    LOG.info("DUMP merged %s network_functions from by_id lookups", extra)


def _enrich_entity_group_refs(payload):
  """IDF EG refs are untyped; join category UUIDs and EG name."""
  cat_ids = set()
  for row in payload.get("categories") or []:
    uid = row.get("ext_id") or ""
    if uid:
      cat_ids.add(uid)
  classified = 0
  for eg in payload.get("entity_groups") or []:
    ents = ((eg.get("allowed_config") or {}).get("entities")) or []
    name = str(eg.get("name") or "").lower()
    for ent in ents:
      if str(ent.get("type") or "") != "UNTYPED_REF":
        continue
      refs = list(ent.get("reference_ext_ids") or [])
      if any(uid in cat_ids for uid in refs):
        if "subnet" in name:
          ent["type"] = "SUBNET"
        elif "vpc" in name:
          ent["type"] = "VPC"
        else:
          ent["type"] = "VM"
        ent["select_by"] = "CATEGORY_EXT_ID"
      else:
        ent["type"] = "VM"
        ent["select_by"] = "EXT_ID"
      classified += 1
  LOG.info("DUMP entity_group refs classified=%s categories=%s",
           classified, len(cat_ids))


def _post_fetch_enrich(payload):
  _merge_network_functions(payload)
  _enrich_nics_and_vlan_vpc(payload)
  _enrich_projects(payload)
  _enrich_entity_group_refs(payload)
  _expand_service_and_function_details(payload)
  _expand_fqdn_details(payload)


def process_dump(dump_dir, output_dir=None, workers=16, timeout_secs=90,
                 fail_on_error=False):
  """Map idfcli JSON into prefetch files. No live PC APIs."""
  global _IDF_FILE_DIR
  dump_dir = os.path.abspath(dump_dir)
  output_dir = os.path.abspath(output_dir or dump_dir)
  idf_dir = os.path.join(dump_dir, "idfcli")
  if not os.path.isdir(idf_dir):
    raise SystemExit("process: no idfcli/ under %s" % dump_dir)
  os.makedirs(output_dir, exist_ok=True)
  log_file = os.path.join(output_dir, "process.log")
  _setup_logging(log_file)
  _IDF_FILE_DIR = idf_dir
  _IDF_RESULTS.clear()
  combined_path = os.path.join(output_dir, "all.json")
  errors = {}
  uuids = _load_json_if_present(
      os.path.join(dump_dir, "unique_uuids.json"), {})
  if not isinstance(uuids, dict):
    uuids = {}
  if not (uuids.get("vlan_unique_uuid") and uuids.get("global_unique_uuid")):
    meta = _load_json_if_present(os.path.join(dump_dir, "meta.json"), {})
    if isinstance(meta, dict):
      uuids.setdefault("vlan_unique_uuid", meta.get("vlan_unique_uuid") or "")
      uuids.setdefault(
          "global_unique_uuid", meta.get("global_unique_uuid") or "")
  payload = {
      "source": "flow_pc_process",
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "platform": "",
      "platform_detection_method": "process_idfcli",
      "smsp_cluster_uuid": "",
      "vlan_unique_uuid": uuids.get("vlan_unique_uuid") or "",
      "global_unique_uuid": uuids.get("global_unique_uuid") or "",
      "ahv_gateway": _load_json_if_present(
          os.path.join(dump_dir, "ahv_gateway.json"), {}),
      "cmsp_ovn": _load_json_if_present(
          os.path.join(dump_dir, "cmsp_ovn.json"), {}),
      "port_set_list": _load_json_if_present(
          os.path.join(dump_dir, "port_set_list.json"), []),
      "port_set_get": _normalize_port_set_get(_load_json_if_present(
          os.path.join(dump_dir, "port_set_get.json"), {})),
  }
  jobs = [
      ("hosts", lambda: fetch_hosts(None)),
      ("fqdn_to_ip_map", lambda: fetch_fqdn_map(None)),
      ("vms", lambda: fetch_vms(None)),
      ("subnets", lambda: fetch_subnets(None)),
      ("vpcs", lambda: fetch_vpcs(None)),
      ("clusters", lambda: fetch_clusters(None)),
      ("projects", lambda: fetch_projects(None)),
      ("categories", lambda: fetch_categories(None)),
      ("network_functions", lambda: fetch_network_functions(None)),
      ("entity_capabilities", lambda: fetch_entity_capabilities(None)),
      ("address_groups", lambda: _fetch_mapped(
          ("address_group", "network_address_group"), _map_address_group)),
      ("service_groups", lambda: _fetch_mapped(
          ("service_group", "network_service_group"), _map_service_group)),
      ("entity_groups", lambda: _fetch_mapped(
          ("entity_group", "network_entity_group"), _map_entity_group)),
      ("policies", lambda: _fetch_mapped(
          ("network_security_policy", "security_policy"), _map_policy)),
  ]
  payload.update(_run_jobs_parallel(jobs, workers, timeout_secs, errors))
  try:
    payload["network_function_by_id"] = fetch_network_function_by_id(
        None, payload.get("network_functions") or [], [])
    _post_fetch_enrich(payload)
  except Exception as err:
    errors["post_fetch_enrich"] = str(err)
    LOG.error("post_fetch_enrich FAILED: %s", err)
  payload["dump_errors"] = errors
  _write_outputs(payload, output_dir, combined_path, workers)
  LOG.info("PROCESS wrote prefetch JSON under %s", output_dir)
  LOG.info(
      "  policies=%s address_groups=%s service_groups=%s entity_groups=%s "
      "port_set_list=%s port_set_get=%s",
      len(payload.get("policies") or []),
      len(payload.get("address_groups") or []),
      len(payload.get("service_groups") or []),
      len(payload.get("entity_groups") or []),
      len(payload.get("port_set_list") or []),
      len(payload.get("port_set_get") or {}))
  if errors:
    LOG.warning("Process errors: %s", ", ".join(sorted(errors)))
    return 2 if fail_on_error else 0
  return 0


def dump_collect(output_dir, workers=8, skip_idf=False, skip_ahv=False,
                 skip_cmsp=False, skip_atlas=False, ahv_gw_timeout=1800,
                 cmsp_ovn_timeout=1800, atlas_timeout=1800,
                 atlas_get_workers=32, idf_timeout=180, fail_on_error=False,
                 log_file="", combined_path=""):
  """PC dump: idfcli + OVN + OVS + atlas_cli. No FlowInterfaces or convert."""
  os.makedirs(output_dir, exist_ok=True)
  combined_path = combined_path or os.path.join(output_dir, "all.json")
  log_file = log_file or os.path.join(output_dir, "dump.log")
  _setup_logging(log_file)
  workers = max(1, int(workers))
  LOG.info("logs=%s combined=%s output_dir=%s",
           log_file, combined_path, output_dir)
  LOG.info(
      "dump=idfcli+OVN+OVS+atlas skip_idfcli=%s skip_ahv_gateway=%s "
      "skip_cmsp_ovn=%s skip_atlas=%s workers=%s ahv_gw_timeout=%ss "
      "cmsp_ovn_timeout=%ss atlas_timeout=%ss",
      skip_idf, skip_ahv, skip_cmsp, skip_atlas, workers, ahv_gw_timeout,
      cmsp_ovn_timeout, atlas_timeout)

  errors = {}
  payload = {
      "source": "flow_pc_dump",
      "collects": ["idfcli", "ovn", "ovs", "atlas"],
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "idfcli": {},
      "ahv_gateway": {},
      "cmsp_ovn": {},
      "atlas": {},
  }

  LOG.info("Collecting idfcli + AHV Gateway OVS + CMSP OVN + atlas_cli")
  with ThreadPoolExecutor(max_workers=4) as pool:
    idf_fut = None
    ahv_gw_fut = None
    cmsp_ovn_fut = None
    atlas_fut = None
    if skip_idf:
      LOG.info("Skipping idfcli (--skip_idfcli)")
      payload["idfcli"] = {"ran": False, "error": "skipped (--skip_idfcli)"}
    else:
      idf_fut = pool.submit(
          dump_idfcli, output_dir, min(8, workers), idf_timeout)
    if skip_ahv:
      LOG.info("Skipping AHV Gateway collect (--skip_ahv_gateway)")
      payload["ahv_gateway"] = {
          "ran": False,
          "complete": False,
          "error": "skipped (--skip_ahv_gateway)",
          "ssh_to_ahv": False,
      }
    else:
      ahv_gw_fut = pool.submit(
          fetch_ahv_gateway_host_state, output_dir, None, None, ahv_gw_timeout)
    if skip_cmsp:
      LOG.info("Skipping CMSP OVN NB/SB kubectl dump (--skip_cmsp_ovn)")
      payload["cmsp_ovn"] = {
          "ran": False,
          "complete": False,
          "error": "skipped (--skip_cmsp_ovn)",
          "ssh_to_ahv": False,
          "transport": "kubectl",
      }
    else:
      cmsp_ovn_fut = pool.submit(
          fetch_cmsp_ovn_nb_sb, output_dir, cmsp_ovn_timeout)
    if skip_atlas:
      LOG.info("Skipping atlas_cli (--skip_atlas)")
      payload["atlas"] = {"ran": False, "error": "skipped (--skip_atlas)"}
    else:
      atlas_fut = pool.submit(
          dump_atlas_port_sets, output_dir,
          max(1, int(atlas_get_workers)), atlas_timeout)
    if idf_fut is not None:
      try:
        index, idf_errors = idf_fut.result()
        payload["idfcli"] = index
        errors.update(idf_errors)
      except Exception as err:
        errors["idfcli"] = str(err)
        payload["idfcli"] = {"ran": False, "error": str(err)}
        LOG.error("DATASET idfcli FAILED: %s", err)
    if ahv_gw_fut is not None:
      try:
        payload["ahv_gateway"] = ahv_gw_fut.result()
      except Exception as err:
        errors["ahv_gateway"] = str(err)
        payload["ahv_gateway"] = {
            "ran": False,
            "complete": False,
            "error": str(err),
            "ssh_to_ahv": False,
        }
        LOG.error("DATASET ahv_gateway FAILED: %s", err)
      else:
        gw = payload.get("ahv_gateway") or {}
        if gw.get("complete"):
          LOG.info("AHV Gateway complete; OVS/virsh/tap captured")
        elif gw.get("error"):
          errors["ahv_gateway"] = gw["error"]
    if cmsp_ovn_fut is not None:
      try:
        payload["cmsp_ovn"] = cmsp_ovn_fut.result()
      except Exception as err:
        errors["cmsp_ovn"] = str(err)
        payload["cmsp_ovn"] = {
            "ran": False,
            "complete": False,
            "error": str(err),
            "transport": "kubectl",
            "ssh_to_ahv": False,
        }
        LOG.error("DATASET cmsp_ovn FAILED: %s", err)
      else:
        cmsp = payload.get("cmsp_ovn") or {}
        if not cmsp.get("complete") and cmsp.get("error"):
          errors["cmsp_ovn"] = cmsp["error"]
    if atlas_fut is not None:
      try:
        payload["atlas"] = atlas_fut.result()
      except Exception as err:
        errors["atlas"] = str(err)
        payload["atlas"] = {"ran": False, "error": str(err)}
        LOG.error("DATASET atlas FAILED: %s", err)
      else:
        atlas_rec = payload.get("atlas") or {}
        errors.update(atlas_rec.get("errors") or {})

  uuids = fetch_unique_uuids()
  payload["vlan_unique_uuid"] = uuids.get("vlan_unique_uuid") or ""
  payload["global_unique_uuid"] = uuids.get("global_unique_uuid") or ""
  _write_json_file(os.path.join(output_dir, "unique_uuids.json"), uuids)

  payload["dump_errors"] = errors
  _write_json_file(
      os.path.join(output_dir, "ahv_gateway.json"),
      payload.get("ahv_gateway") or {})
  _write_json_file(
      os.path.join(output_dir, "cmsp_ovn.json"),
      payload.get("cmsp_ovn") or {})
  _write_json_file(os.path.join(output_dir, "dump_errors.json"), errors)
  _write_json_file(combined_path, payload)

  LOG.info("===== DUMP SUMMARY (idfcli + OVN + OVS + atlas) =====")
  types = (payload.get("idfcli") or {}).get("entity_types") or {}
  LOG.info("  %-22s %s types", "idfcli", len(types))
  for name, rec in sorted(types.items()):
    LOG.info(
        "  %-22s count=%s err=%s",
        name, rec.get("count"), rec.get("error") or "<none>")
  gw = payload.get("ahv_gateway") or {}
  LOG.info(
      "  %-22s ran=%s complete=%s hosts=%s/%s error=%s",
      "ahv_gateway",
      gw.get("ran"),
      gw.get("complete"),
      gw.get("hosts_ok"),
      gw.get("hosts_total"),
      (gw.get("error") or "")[:80] or "<none>")
  for host_rec in gw.get("hosts") or []:
    LOG.info(
        "  %-22s ip=%s name=%s ok=%s missing=%s err=%s",
        "",
        host_rec.get("ip") or "",
        host_rec.get("name") or "",
        host_rec.get("complete"),
        ",".join(host_rec.get("missing") or []) or "<none>",
        (host_rec.get("error") or "")[:50] or "<none>")
  cmsp = payload.get("cmsp_ovn") or {}
  LOG.info(
      "  %-22s ran=%s complete=%s pods=%s error=%s",
      "cmsp_ovn",
      cmsp.get("ran"),
      cmsp.get("complete"),
      len(cmsp.get("pods") or []),
      (cmsp.get("error") or "")[:80] or "<none>")
  for pod_rec in cmsp.get("pods") or []:
    LOG.info(
        "  %-22s key=%s pod=%s ok=%s missing=%s err=%s",
        "",
        pod_rec.get("key") or "",
        pod_rec.get("pod") or "",
        pod_rec.get("complete"),
        ",".join(pod_rec.get("missing") or []) or "<none>",
        (pod_rec.get("error") or "")[:50] or "<none>")
  atlas = payload.get("atlas") or {}
  LOG.info(
      "  %-22s ran=%s list=%s get=%s platform=%s error=%s",
      "atlas",
      atlas.get("ran"),
      atlas.get("list_count"),
      atlas.get("get_count"),
      atlas.get("platform") or "",
      (atlas.get("error") or "")[:80] or "<none>")
  if errors:
    LOG.warning("Failed datasets: %s", ", ".join(sorted(errors)))
    if fail_on_error:
      return 2
  LOG.info("Done. Index: %s", combined_path)
  LOG.info("idfcli=%s/idfcli  ovs=%s/ahv_gateway  ovn=%s/cmsp_ovn  atlas=%s",
           output_dir, output_dir, output_dir, output_dir)
  LOG.info("Convert off-PC with: python3 flow_pc_process.py --dump_dir %s",
           output_dir)
  return 0


def main(argv):
  if gflags is not None:
    try:
      argv = FLAGS(argv)
    except gflags.FlagsError as err:
      print("%s\nUsage: %s ARGS\n%s" % (err, sys.argv[0], FLAGS))
      return 1
    del argv
    if FLAGS.from_json:
      output_dir = FLAGS.output_dir or "/tmp/flow_pc_dump"
      os.makedirs(output_dir, exist_ok=True)
      combined_path = FLAGS.output or os.path.join(output_dir, "all.json")
      log_file = FLAGS.log_file or os.path.join(output_dir, "process.log")
      _setup_logging(log_file)
      LOG.info("from_json is process, not dump; splitting %s", FLAGS.from_json)
      with open(FLAGS.from_json, "r") as handle:
        payload = json.load(handle)
      _enrich_projects(payload)
      _expand_service_and_function_details(payload)
      _expand_fqdn_details(payload)
      _write_outputs(
          payload, output_dir, combined_path, max(1, int(FLAGS.workers)))
      LOG.info("Split complete under %s", output_dir)
      return 0
    return dump_collect(
        FLAGS.output_dir or "/tmp/flow_pc_dump",
        workers=max(1, int(FLAGS.workers)),
        skip_idf=getattr(FLAGS, "skip_idfcli", False),
        skip_ahv=getattr(FLAGS, "skip_ahv_gateway", False),
        skip_cmsp=getattr(FLAGS, "skip_cmsp_ovn", False),
        skip_atlas=getattr(FLAGS, "skip_atlas", False),
        ahv_gw_timeout=max(
            60, int(getattr(FLAGS, "ahv_gateway_timeout_secs", 1800) or 1800)),
        cmsp_ovn_timeout=max(
            60, int(getattr(FLAGS, "cmsp_ovn_timeout_secs", 1800) or 1800)),
        atlas_timeout=max(
            60, int(getattr(FLAGS, "atlas_timeout_secs", 1800) or 1800)),
        atlas_get_workers=max(
            1, int(getattr(FLAGS, "atlas_get_workers", 32) or 32)),
        idf_timeout=max(60, int(FLAGS.dataset_timeout_secs)),
        fail_on_error=bool(FLAGS.fail_on_error),
        log_file=FLAGS.log_file or "",
        combined_path=FLAGS.output or "")
  import argparse
  ap = argparse.ArgumentParser(
      description="Dump idfcli + OVN + OVS + atlas_cli. No FlowInterfaces.")
  ap.add_argument("--output_dir", default="/tmp/flow_pc_dump")
  ap.add_argument("--output", default="")
  ap.add_argument("--log_file", default="")
  ap.add_argument("--workers", type=int, default=16)
  ap.add_argument("--dataset_timeout_secs", type=int, default=180)
  ap.add_argument("--fail_on_error", action="store_true")
  ap.add_argument("--skip_idfcli", action="store_true")
  ap.add_argument("--skip_ahv_gateway", action="store_true")
  ap.add_argument("--skip_cmsp_ovn", action="store_true")
  ap.add_argument("--skip_atlas", action="store_true")
  ap.add_argument("--ahv_gateway_timeout_secs", type=int, default=1800)
  ap.add_argument("--cmsp_ovn_timeout_secs", type=int, default=1800)
  ap.add_argument("--atlas_timeout_secs", type=int, default=1800)
  ap.add_argument("--atlas_get_workers", type=int, default=32)
  args = ap.parse_args(list(argv[1:]) if argv else None)
  return dump_collect(
      args.output_dir,
      workers=args.workers,
      skip_idf=args.skip_idfcli,
      skip_ahv=args.skip_ahv_gateway,
      skip_cmsp=args.skip_cmsp_ovn,
      skip_atlas=args.skip_atlas,
      ahv_gw_timeout=args.ahv_gateway_timeout_secs,
      cmsp_ovn_timeout=args.cmsp_ovn_timeout_secs,
      atlas_timeout=args.atlas_timeout_secs,
      atlas_get_workers=args.atlas_get_workers,
      idf_timeout=args.dataset_timeout_secs,
      fail_on_error=args.fail_on_error,
      log_file=args.log_file,
      combined_path=args.output)


if __name__ == "__main__":
  sys.exit(main(sys.argv))
