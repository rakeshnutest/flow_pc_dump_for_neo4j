#!/usr/bin/env python
#
# Copyright (c) 2026 Nutanix Inc. All rights reserved.
#
# Dump Flow policy + infra objects for neo4j_db_insert.py prefetch JSON.
# Run on PCVM:
#   /home/nutanix/.venvs/flow/bin/python3 flow_pc_dump_for_neo4j.py \
#       --output_dir /tmp/flow_pc_neo4j_prefetch \
#       --workers 16 --atlas_get_workers 32
# Writes per-dataset JSON files plus compact all.json.
#

import codecs
import json
import logging
import os
import re
import subprocess
import sys
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime

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
    "output_dir", "/tmp/flow_pc_neo4j_prefetch",
    "Directory for per-dataset JSON files plus all.json (not the old "
    "/tmp/flow_neo4j_dump.json).")
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
    "dataset_timeout_secs", 90,
    "Per-dataset timeout. Hung v4/Zeus calls are abandoned.")
gflags.DEFINE_boolean(
    "fail_on_error", False,
    "If true, exit non-zero when any dataset fetch fails.")
gflags.DEFINE_boolean(
    "skip_atlas", False,
    "Skip atlas_cli port_set.list / port_set.get dumps.")
gflags.DEFINE_integer(
    "atlas_timeout_secs", 300,
    "Timeout for atlas_cli port_set.list and the port_set.get batch.")
gflags.DEFINE_integer(
    "atlas_get_workers", 32,
    "Parallel atlas_cli port_set.get processes.")

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
_IDF_LOCKS = {}
_IDF_GUARD = threading.Lock()


def _idfcli_one(entity_type, timeout=180):
  with _IDF_GUARD:
    lock = _IDF_LOCKS.setdefault(entity_type, threading.Lock())
  with lock:
    cached = _IDF_RESULTS.get(entity_type)
    if cached is not None:
      parsed, err = cached
      LOG.info("DUMP idfcli entitytype %s cached=%s", entity_type, len(parsed))
      return cached
    LOG.info("DUMP idfcli entitytype %s", entity_type)
    err = None
    parsed = []
    try:
      proc = subprocess.run(
          [_idfcli_bin(), "get", "entitytype", "-e", entity_type],
          capture_output=True, text=True, check=False, timeout=timeout)
      text = proc.stdout or ""
      if proc.returncode != 0 and not text:
        err = "%s: %s" % (entity_type, (proc.stderr or "").strip()[:200])
      else:
        parsed = _parse_idf_entities(text)
    except Exception as exc:
      err = "%s: %s" % (entity_type, exc)
    LOG.info("DUMP idfcli %s parsed=%s", entity_type, len(parsed))
    _IDF_RESULTS[entity_type] = (parsed, err)
    return _IDF_RESULTS[entity_type]


def _idf_unquote(raw):
  try:
    return codecs.decode(raw, "unicode_escape")
  except Exception:
    return raw


def _idf_bytes_to_value(raw):
  text = _idf_unquote(raw)
  if isinstance(text, bytes):
    data = text
  else:
    try:
      data = text.encode("latin-1")
    except Exception:
      data = text.encode("utf-8", "replace")
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
        attrs[name] = _idf_bytes_to_value(bytes_list[0])
      elif int_val:
        attrs[name] = int(int_val.group(1))
      elif bool_val:
        attrs[name] = bool_val.group(1) == "true"
    if attrs:
      entities.append(attrs)
  return entities


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
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  ip_addr = _first_attr(row, "ip_address", "external_ip", "cluster_external_ip") or ""
  return {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "cluster_name") or "",
      "network": {"external_address": {"ipv4": {"value": str(ip_addr)}}},
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
  LOG.info("DUMP done clusters count=%s", len(rows))
  return rows


def fetch_projects(interfaces):
  LOG.info("DUMP start projects")
  manager = _get_manager(
      interfaces, "project_manager", "projects_manager", "iam_project_manager")
  if manager is None:
    _log_matching_managers(interfaces, "project")
  rows = []
  if manager:
    rows = _dump_manager("projects", manager, convert_project)
  if not rows:
    mapped, errors = _idf_mapped(
        ("project", "projects", "iam_project", "xi_project", "abac_project"),
        _map_project)
    for err in errors:
      LOG.warning("projects fallback: %s", err)
    rows = mapped
    LOG.info("DUMP done projects count=%s (idf)", len(rows))
  return rows


def fetch_network_functions(interfaces):
  LOG.info("DUMP start network_functions")
  manager = _get_manager(
      interfaces, "network_function_manager", "service_function_manager")
  if manager is None:
    _log_matching_managers(interfaces, "function")
  rows = []
  if manager:
    rows = _dump_manager("network_functions", manager, convert_network_function)
  if not rows:
    mapped, errors = _idf_mapped(
        ("atlas_network_function", "network_function", "flow_network_function"),
        _map_nf)
    for err in errors:
      LOG.warning("network_functions fallback: %s", err)
    rows = mapped
    LOG.info("DUMP done network_functions count=%s (idf)", len(rows))
  return rows


def fetch_network_function_by_id(interfaces, nf_rows, extra_uuids=None):
  manager = _get_manager(
      interfaces, "network_function_manager", "service_function_manager")
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
  zkcat = "/usr/local/nutanix/cluster/bin/zkcat"
  paths = {
      "vlan_unique_uuid": "/appliance/logical/flow/vlan_unique_uuid",
      "global_unique_uuid": "/appliance/logical/flow/global_unique_uuid",
  }
  out = {}
  for key, zk_path in paths.items():
    if not os.path.exists(zkcat):
      LOG.warning("zkcat missing; skip %s", key)
      out[key] = ""
      continue
    try:
      proc = subprocess.run(
          [zkcat, zk_path], capture_output=True, text=True, check=False,
          timeout=20)
      value = (proc.stdout or "").strip()
      out[key] = value
      LOG.info("DUMP %s=%s", key, value or "<empty>")
    except Exception as err:
      LOG.error("DUMP %s failed: %s", key, err)
      out[key] = ""
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
  for item in _unwrap_list(payload) or _iter_manager(manager):
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
    return _port_set_get_record(parsed, ps_uuid)

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


DATASET_FILES = (
    "address_groups", "service_groups", "entity_groups", "policies",
    "vms", "subnets", "vpcs", "hosts", "clusters", "projects",
    "categories", "network_functions", "network_function_by_id",
    "fqdn_to_ip_map", "port_set_list", "port_set_get", "dump_errors")


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
  if name in ("fqdn_to_ip_map", "network_function_by_id", "port_set_get"):
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


def _post_fetch_enrich(payload):
  _merge_network_functions(payload)
  _enrich_nics_and_vlan_vpc(payload)
  _enrich_projects(payload)
  _expand_service_and_function_details(payload)
  _expand_fqdn_details(payload)


def main(argv):
  try:
    argv = FLAGS(argv)
  except gflags.FlagsError as err:
    print("%s\nUsage: %s ARGS\n%s" % (err, sys.argv[0], FLAGS))
    return 1
  del argv

  output_dir = FLAGS.output_dir or "/tmp/flow_pc_neo4j_prefetch"
  os.makedirs(output_dir, exist_ok=True)
  combined_path = FLAGS.output or os.path.join(output_dir, "all.json")
  log_file = FLAGS.log_file or os.path.join(output_dir, "dump.log")
  _setup_logging(log_file)
  workers = max(1, int(FLAGS.workers))

  LOG.info("logs=%s combined=%s output_dir=%s",
           log_file, combined_path, output_dir)

  if FLAGS.from_json:
    LOG.info("Splitting existing dump %s (no live fetch)", FLAGS.from_json)
    with open(FLAGS.from_json, "r") as handle:
      payload = json.load(handle)
    _enrich_projects(payload)
    _expand_service_and_function_details(payload)
    _expand_fqdn_details(payload)
    _write_outputs(payload, output_dir, combined_path, workers)
    LOG.info("Split complete under %s", output_dir)
    return 0

  timeout_secs = max(15, int(FLAGS.dataset_timeout_secs))
  atlas_timeout_secs = max(30, int(FLAGS.atlas_timeout_secs))
  atlas_get_workers = max(1, int(FLAGS.atlas_get_workers))
  LOG.info("FlowInterfaces + platform detect in parallel (no v4_client)")
  LOG.info(
      "workers=%s atlas_get_workers=%s timeout=%ss atlas_timeout=%ss "
      "skip_atlas=%s",
      workers, atlas_get_workers, timeout_secs, atlas_timeout_secs,
      FLAGS.skip_atlas)
  with ThreadPoolExecutor(max_workers=1) as pool:
    plat_fut = pool.submit(detect_msp_platform)
    interfaces = FlowInterfaces()
    platform_info = plat_fut.result()
  LOG.info(
      "Platform %s (method=%s smsp_uuid=%s)",
      platform_info.get("platform"),
      platform_info.get("detection_method"),
      platform_info.get("smsp_cluster_uuid") or "<none>")
  LOG.info("FlowInterfaces ready")

  errors = {}
  jobs = [
      ("address_groups", lambda: fetch_address_groups(interfaces)),
      ("service_groups", lambda: fetch_service_groups(interfaces)),
      ("entity_groups", lambda: fetch_entity_groups(interfaces)),
      ("policies", lambda: fetch_policies(interfaces)),
      ("hosts", lambda: fetch_hosts(interfaces)),
      ("unique_uuids", fetch_unique_uuids),
      ("fqdn_to_ip_map", lambda: fetch_fqdn_map(interfaces)),
      ("vms", lambda: fetch_vms(interfaces)),
      ("subnets", lambda: fetch_subnets(interfaces)),
      ("vpcs", lambda: fetch_vpcs(interfaces)),
      ("clusters", lambda: fetch_clusters(interfaces)),
      ("projects", lambda: fetch_projects(interfaces)),
      ("categories", lambda: fetch_categories(interfaces)),
      ("network_functions", lambda: fetch_network_functions(interfaces)),
      ("entity_capabilities", lambda: fetch_entity_capabilities(interfaces)),
  ]

  def _atlas_list_and_get():
    rows = fetch_port_set_list(platform_info, atlas_timeout_secs)
    uuids = []
    seen = set()
    for item in rows or []:
      ps_uuid = _port_set_uuid(item)
      if ps_uuid and ps_uuid not in seen:
        seen.add(ps_uuid)
        uuids.append(ps_uuid)
    gets = {}
    if uuids:
      gets = fetch_port_set_get(
          platform_info, uuids, atlas_get_workers, atlas_timeout_secs, errors)
    else:
      LOG.info("Skipping port_set.get (no UUIDs from port_set.list)")
    return rows or [], gets

  payload = {
      "source": "flow_pc_dump_for_neo4j",
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "platform": platform_info.get("platform"),
      "platform_detection_method": platform_info.get("detection_method"),
      "smsp_cluster_uuid": platform_info.get("smsp_cluster_uuid") or "",
  }
  payload["port_set_list"] = []
  payload["port_set_get"] = {}
  write_fut = None

  with ThreadPoolExecutor(max_workers=3) as coordinator:
    fetch_fut = coordinator.submit(
        _run_jobs_parallel, jobs, workers, timeout_secs, errors)
    atlas_fut = None
    if FLAGS.skip_atlas:
      LOG.info("Skipping atlas_cli port_set dumps (--skip_atlas)")
    else:
      atlas_fut = coordinator.submit(_atlas_list_and_get)
    payload.update(fetch_fut.result())

    unique = payload.pop("unique_uuids", {}) or {}
    payload["vlan_unique_uuid"] = unique.get("vlan_unique_uuid", "")
    payload["global_unique_uuid"] = unique.get("global_unique_uuid", "")
    payload["network_function_by_id"] = fetch_network_function_by_id(
        interfaces, payload.get("network_functions") or [],
        _policy_nf_uuids(payload))
    _post_fetch_enrich(payload)

    skip_late = ("port_set_list", "port_set_get", "dump_errors")
    write_fut = None
    if atlas_fut is not None and not atlas_fut.done():
      write_fut = coordinator.submit(
          _write_outputs, payload, output_dir, combined_path, workers,
          skip_late, False)
    if atlas_fut is not None:
      try:
        payload["port_set_list"], payload["port_set_get"] = atlas_fut.result()
      except Exception as err:
        errors["port_set_list"] = str(err)
        LOG.error("DATASET port_set_list/get FAILED: %s", err)
    if write_fut is not None:
      write_fut.result()

  payload["dump_errors"] = errors
  if write_fut is not None:
    _write_json_file(
        os.path.join(output_dir, "port_set_list.json"),
        payload.get("port_set_list") or [])
    _write_json_file(
        os.path.join(output_dir, "port_set_get.json"),
        payload.get("port_set_get") or {})
    _write_json_file(os.path.join(output_dir, "dump_errors.json"), errors)
    _write_json_file(combined_path, payload)
  else:
    _write_outputs(payload, output_dir, combined_path, workers)

  LOG.info("===== DUMP SUMMARY =====")
  for key in (
      "address_groups", "service_groups", "entity_groups", "policies",
      "vms", "subnets", "vpcs", "hosts", "clusters", "projects",
      "categories", "network_functions"):
    value = payload.get(key) or []
    LOG.info("  %-22s %s", key, len(value) if isinstance(value, list) else value)
  LOG.info("  %-22s %s", "vlan_unique_uuid", payload.get("vlan_unique_uuid") or "<empty>")
  LOG.info("  %-22s %s", "global_unique_uuid", payload.get("global_unique_uuid") or "<empty>")
  LOG.info("  %-22s %s", "fqdn_to_ip_map", len(payload.get("fqdn_to_ip_map") or {}))
  fqdn_map = payload.get("fqdn_to_ip_map") or {}
  LOG.info(
      "  %-22s %s", "fqdn_with_resolved_ips",
      sum(1 for ips in fqdn_map.values() if ips))
  nic_fqdn = 0
  for vm in payload.get("vms") or []:
    for nic in vm.get("nics") or []:
      if nic.get("fqdns") or (nic.get("nic_network_info") or {}).get("fqdns"):
        nic_fqdn += 1
  LOG.info("  %-22s %s", "nics_with_fqdn", nic_fqdn)
  eg_fqdn = sum(
      1 for eg in (payload.get("entity_groups") or [])
      if eg.get("fqdn_mapping") or eg.get("subnet_list"))
  LOG.info("  %-22s %s", "egs_with_fqdn_subnet", eg_fqdn)
  LOG.info("  %-22s %s", "network_function_by_id",
           len(payload.get("network_function_by_id") or {}))
  vms = payload.get("vms") or []
  vm_proj = sum(1 for vm in vms if _project_blob(vm))
  nic_proj = 0
  nic_total = 0
  for vm in vms:
    for nic in vm.get("nics") or []:
      nic_total += 1
      if nic.get("project") or (nic.get("nic_network_info") or {}).get("project"):
        nic_proj += 1
  sg_rules = 0
  nf_rules = 0
  for policy in payload.get("policies") or []:
    data = policy.get("data") or policy
    for rule in data.get("rules") or []:
      spec = rule.get("spec") or {}
      if spec.get("service_group_details"):
        sg_rules += 1
      if spec.get("network_function_details"):
        nf_rules += 1
  LOG.info("  %-22s %s / %s", "vms_with_project", vm_proj, len(vms))
  LOG.info("  %-22s %s / %s", "nics_with_project", nic_proj, nic_total)
  LOG.info("  %-22s %s", "rules_with_sg_details", sg_rules)
  LOG.info("  %-22s %s", "rules_with_nf_details", nf_rules)
  LOG.info("  %-22s %s", "platform", payload.get("platform") or "<empty>")
  LOG.info("  %-22s %s", "port_set_list", len(payload.get("port_set_list") or []))
  LOG.info("  %-22s %s", "port_set_get", len(payload.get("port_set_get") or {}))
  if errors:
    LOG.warning("Failed datasets: %s", ", ".join(sorted(errors)))
    if FLAGS.fail_on_error:
      return 2
  LOG.info("Done. Combined file: %s", combined_path)
  LOG.info("Per-dataset files: %s/*.json", output_dir)
  return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv))
