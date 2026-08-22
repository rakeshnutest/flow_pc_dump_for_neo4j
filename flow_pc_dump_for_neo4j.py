#!/usr/bin/env python
#
# Copyright (c) 2026 Nutanix Inc. All rights reserved.
#
# Dump Flow policy + infra objects for neo4j_db_insert.py prefetch JSON.
# Run on PCVM:
#   /home/nutanix/.venvs/flow/bin/python3 flow_pc_dump_for_neo4j.py \
#       --output_dir /tmp/flow_pc_neo4j_prefetch
# Writes per-dataset JSON files plus all.json (not /tmp/flow_neo4j_dump.json).
#

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
    "workers", 12,
    "Parallel worker count for dataset fetch and conversion.")
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

LOG = logging.getLogger("flow_pc_dump")

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


def _enum_name(enum_cls, value, default=""):
  if value is None or value == 0:
    return default
  try:
    raw = enum_cls.Name(int(value))
  except Exception:
    return default
  if raw.startswith("k"):
    raw = raw[1:]
  pieces = []
  for idx, char in enumerate(raw):
    if idx and char.isupper() and (
        raw[idx - 1].islower() or
        (idx + 1 < len(raw) and raw[idx + 1].islower())):
      pieces.append("_")
    pieces.append(char.upper())
  return "".join(pieces) or default


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


def _project_fields(proto):
  project_uuid = _uuid_str(getattr(proto, "project_uuid", None))
  shared = bool(getattr(proto, "shared_with_all_projects", False))
  data = {
      "shared_with_all_projects": shared,
      "sharedWithAllProjects": shared,
  }
  if project_uuid:
    data["project_ext_id"] = project_uuid
    data["projectExtId"] = project_uuid
    data["project"] = {"ext_id": project_uuid}
  return data


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
  row = {
      "type": entity_type,
      "select_by": select_by,
      "reference_ext_ids": _uuid_list(getattr(entity, "reference_uuids", [])),
      "kube_entities": [str(item) for item in (getattr(entity, "kube_entities", []) or [])],
      "fqdns": [str(item) for item in (getattr(entity, "fqdn_addresses", []) or [])],
  }
  if _has(entity, "regex_match_entity"):
    regex = entity.regex_match_entity
    row["reference_string"] = getattr(regex, "reference_string", "") or ""
    row["match_criteria"] = REGEX_MATCH.get(
        getattr(regex, "match_type", None), "EQUALS")
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
  if allow_type == 1:
    spec["should_allow_any_src" if side == "src" else "should_allow_any_dst"] = True
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
  return _base_rule(rule_info, fallback_type, spec)


def _convert_flex_rule(flex_rule):
  rule_info = flex_rule.rule_info if _has(flex_rule, "rule_info") else None
  spec = {
      "direction": FLEX_DIR.get(getattr(flex_rule, "direction", 0), "IN_OUT"),
      "action": FLEX_ACTION.get(getattr(flex_rule, "action", 0), "ALLOW"),
      "priority": getattr(flex_rule, "rule_priority", 0) or 0,
  }
  ip_version = IP_VERSION.get(getattr(flex_rule, "rule_ip_version", 0))
  if ip_version:
    spec["ip_version"] = ip_version
  spec.update(_endpoint_to_side(
      flex_rule.src_endpoint if _has(flex_rule, "src_endpoint") else None, "src"))
  spec.update(_endpoint_to_side(
      flex_rule.dest_endpoint if _has(flex_rule, "dest_endpoint") else None, "dest"))
  applied = _uuid_list(getattr(flex_rule, "applied_to_entity_group_uuid_list", []))
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
      str_val = re.search(r'str_value:\s*"([^"]*)"', body)
      int_val = re.search(r'int64_value:\s*(-?\d+)', body)
      bool_val = re.search(r'bool_value:\s*(true|false)', body)
      str_list = re.findall(r'value_list:\s*"([^"]*)"', body)
      if str_list:
        attrs[name] = str_list
      elif str_val:
        attrs[name] = str_val.group(1)
      elif int_val:
        attrs[name] = int(int_val.group(1))
      elif bool_val:
        attrs[name] = bool_val.group(1) == "true"
    if attrs:
      entities.append(attrs)
  return entities


def _idfcli_entities(entity_types):
  binary = _idfcli_bin()
  rows = []
  errors = []
  for entity_type in entity_types:
    try:
      LOG.info("DUMP idfcli entitytype %s", entity_type)
      proc = subprocess.run(
          [binary, "get", "entitytype", "-e", entity_type],
          capture_output=True, text=True, check=False, timeout=90)
      text = proc.stdout or ""
      if proc.returncode != 0 and not text:
        errors.append("%s: %s" % (entity_type, (proc.stderr or "").strip()[:200]))
        continue
      parsed = _parse_idf_entities(text)
      LOG.info("DUMP idfcli %s parsed=%s", entity_type, len(parsed))
      if parsed:
        rows.extend(parsed)
        break
    except Exception as err:
      errors.append("%s: %s" % (entity_type, err))
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


def _nic_payload(ext_id, mac, subnet_id, ips):
  ipv4, ipv6 = _learned_ips(ips)
  network = {
      "subnet": {"ext_id": subnet_id} if subnet_id else None,
  }
  if ipv4:
    network["ipv4_info"] = {"learned_ip_addresses": ipv4}
  if ipv6:
    network["ipv6_info"] = {"learned_ipv6_addresses": ipv6}
  return {
      "ext_id": ext_id or "",
      "nic_backing_info": {"mac_address": mac or ""},
      "nic_network_info": network,
  }


def _map_vm(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "vm_uuid", "uuid", "id")) or ""
  name = _first_attr(row, "vm_name", "name", "display_name") or ""
  power = str(_first_attr(row, "power_state", "powerState") or "ON").upper()
  if power in ("POWERED_ON", "ON", "1", "TRUE"):
    power = "ON"
  elif power in ("POWERED_OFF", "OFF", "0", "FALSE"):
    power = "OFF"
  cats = []
  for cat in _as_list(_first_attr(row, "category_id_list", "category_ids", "categories", default=[])):
    cat_id = _uuid_str(cat) or str(cat)
    cats.append({"ext_id": cat_id} if cat_id else cat)
  host_id = _uuid_str(_first_attr(
      row, "node", "host_uuid", "node_uuid", "host"))
  project_id = _uuid_str(_first_attr(row, "project_uuid", "project_reference", "project"))
  nics = []
  ips = _as_list(_first_attr(row, "ip_addresses", "ipv4_addresses", "vm_ipv4_addresses", default=[]))
  subnet_id = _uuid_str(_first_attr(row, "subnet_uuid", "virtual_network_uuid"))
  mac = _first_attr(row, "mac_address", "mac")
  nic_ids = _as_list(_first_attr(row, "virtual_nic_uuids", "nic_uuid", default=[]))
  if ips or subnet_id:
    nics.append(_nic_payload(
        _uuid_str(nic_ids[0]) if nic_ids else "", mac, subnet_id, ips))
  data = {
      "ext_id": ext_id,
      "name": name,
      "power_state": power,
      "categories": cats,
      "nics": nics,
  }
  if host_id:
    data["host"] = {"ext_id": host_id}
  if project_id:
    data["project"] = {"ext_id": project_id}
  return data


def _map_virtual_nic(row):
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "vm": _uuid_str(_first_attr(row, "vm", "vm_uuid")),
      "subnet_id": _uuid_str(_first_attr(
          row, "virtual_network", "subnet_uuid", "network_uuid")),
      "mac": _first_attr(row, "mac_address", "mac") or "",
      "ips": _as_list(_first_attr(
          row, "ipv4_addresses", "assigned_ipv4_addresses", default=[])),
  }


def _attach_virtual_nics(vms):
  nic_rows, errors = _idf_mapped(("virtual_nic",), _map_virtual_nic)
  for err in errors:
    LOG.warning("virtual_nic: %s", err)
  by_vm = {}
  with_subnet = 0
  for nic in nic_rows:
    vm_id = nic.get("vm")
    if not vm_id:
      continue
    payload = _nic_payload(
        nic.get("ext_id"), nic.get("mac"), nic.get("subnet_id"), nic.get("ips"))
    if payload["nic_network_info"].get("subnet"):
      with_subnet += 1
    by_vm.setdefault(vm_id, []).append(payload)
  attached = 0
  for vm in vms:
    nics = by_vm.get(vm.get("ext_id") or "")
    if nics:
      vm["nics"] = nics
      attached += 1
  LOG.info(
      "DUMP virtual_nic mapped=%s vms_attached=%s nics_with_subnet=%s",
      len(nic_rows), attached, with_subnet)
  return vms


def _map_subnet(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  vpc_ref = _uuid_str(_first_attr(row, "vpc_uuid", "vpc_reference", "virtual_network_uuid"))
  cats = _as_list(_first_attr(row, "category_id_list", "category_ids", default=[]))
  project_id = _uuid_str(_first_attr(row, "project_uuid", "project"))
  data = {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "subnet_name") or "",
      "subnet_type": _first_attr(row, "subnet_type", "type") or "OVERLAY",
      "vpc_reference": vpc_ref,
      "is_advanced_networking": bool(_first_attr(
          row, "is_advanced_networking", "advanced_networking", default=False)),
      "metadata": {"category_ids": [_uuid_str(cat) or str(cat) for cat in cats]},
  }
  if project_id:
    data["project"] = {"ext_id": project_id}
  return data


def _map_vpc(row):
  ext_id = _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or ""
  cats = _as_list(_first_attr(row, "category_id_list", "category_ids", default=[]))
  project_id = _uuid_str(_first_attr(row, "project_uuid", "project"))
  data = {
      "ext_id": ext_id,
      "name": _first_attr(row, "name", "vpc_name") or "",
      "vpc_type": _first_attr(row, "vpc_type", "type") or "REGULAR",
      "metadata": {"category_ids": [_uuid_str(cat) or str(cat) for cat in cats]},
      "externally_routable_prefixes": [],
      "external_subnets": [],
  }
  if project_id:
    data["project"] = {"ext_id": project_id}
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
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name", "project_name") or "",
  }


def _map_category(row):
  key = _first_attr(row, "key", "category_key", "name") or ""
  value = _first_attr(row, "value", "category_value") or ""
  if not value and ":" in str(key):
    key, value = str(key).split(":", 1)
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "key": key,
      "value": value,
  }


def _map_nf(row):
  return {
      "ext_id": _uuid_str(_first_attr(row, "ext_id", "uuid", "id")) or "",
      "name": _first_attr(row, "name") or "",
      "failure_handling": _first_attr(row, "failure_handling") or "unknown",
      "traffic_forwarding_mode": _first_attr(row, "traffic_forwarding_mode") or "unknown",
      "high_availability_mode": _first_attr(row, "high_availability_mode") or "unknown",
  }


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
  rows, errors = _idf_mapped(("mh_vm", "vm", "ahv_vm"), _map_vm)
  for err in errors:
    LOG.warning("vms fallback: %s", err)
  rows = _attach_virtual_nics(rows)
  LOG.info("DUMP done vms count=%s", len(rows))
  return rows


def fetch_subnets(_interfaces):
  LOG.info("DUMP start subnets")
  rows, errors = _idf_mapped(("subnet", "virtual_network"), _map_subnet)
  for err in errors:
    LOG.warning("subnets fallback: %s", err)
  LOG.info("DUMP done subnets count=%s", len(rows))
  return rows


def fetch_vpcs(_interfaces):
  LOG.info("DUMP start vpcs")
  rows, errors = _idf_mapped(("vpc", "virtual_private_cloud", "virtual_network"), _map_vpc)
  for err in errors:
    LOG.warning("vpcs fallback: %s", err)
  LOG.info("DUMP done vpcs count=%s", len(rows))
  return rows


def fetch_clusters(_interfaces):
  LOG.info("DUMP start clusters")
  rows, errors = _idf_mapped(("cluster",), _map_cluster)
  for err in errors:
    LOG.warning("clusters fallback: %s", err)
  LOG.info("DUMP done clusters count=%s", len(rows))
  return rows


def fetch_projects(_interfaces):
  LOG.info("DUMP start projects")
  rows, errors = _idf_mapped(("project",), _map_project)
  for err in errors:
    LOG.warning("projects fallback: %s", err)
  LOG.info("DUMP done projects count=%s", len(rows))
  return rows


def fetch_categories(_interfaces):
  LOG.info("DUMP start categories")
  rows, errors = _idf_mapped(("category", "abac_category", "category_key"), _map_category)
  for err in errors:
    LOG.warning("categories fallback: %s", err)
  LOG.info("DUMP done categories count=%s", len(rows))
  return rows


def fetch_network_functions(_interfaces):
  LOG.info("DUMP start network_functions")
  rows, errors = _idf_mapped(
      ("network_function", "flow_network_function"), _map_nf)
  for err in errors:
    LOG.warning("network_functions fallback: %s", err)
  LOG.info("DUMP done network_functions count=%s", len(rows))
  return rows


def fetch_network_function_by_id(_interfaces, nf_rows):
  by_id = {}
  for nf in nf_rows or []:
    ext_id = nf.get("ext_id")
    if ext_id:
      by_id[ext_id] = {"data": nf}
  LOG.info("DUMP done network_function_by_id count=%s", len(by_id))
  return by_id


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
  LOG.info("DUMP start fqdn_to_ip_map")
  mapping = {}
  manager = _get_manager(interfaces, "fqdn_resolution_manager")
  payload = _call_first(manager, [
      "iter_all", "get_all", "list", "get_fqdn_to_ip_mapping"])
  for item in _unwrap_list(payload) or _iter_manager(manager):
    proto = _item_proto(item)
    fqdn = getattr(proto, "fqdn", None) or getattr(item, "fqdn", None)
    ips = []
    for attr in ("ip_list", "resolved_ips", "ipv4_addresses", "ip_addresses"):
      values = getattr(proto, attr, None) or getattr(item, attr, None)
      if values:
        ips.extend([str(ip) for ip in values])
        break
    if fqdn:
      mapping[str(fqdn)] = ips
  if not mapping:
    raw, errors = _idfcli_entities(("fns_fqdn_to_ip_info",))
    for err in errors:
      LOG.warning("fqdn fallback: %s", err)
    for item in raw:
      fqdn = _first_attr(item, "fqdn")
      ips = _as_list(_first_attr(
          item, "resolved_ipv4_addresses", "resolved_ipv6_addresses",
          default=[]))
      if fqdn:
        mapping[str(fqdn)] = [str(ip) for ip in ips]
  LOG.info("DUMP done fqdn_to_ip_map count=%s", len(mapping))
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
  clusters = _mspctl_cluster_list()
  names = [
      str(item.get("cluster_name") or item.get("name") or "")
      for item in clusters if isinstance(item, dict)]
  LOG.info("mspctl clusters: %s", names or "<none>")
  flow = _flow_cluster_from_list(clusters)
  flow_get = _mspctl_flow_cluster()
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
  atlas_pids = _genesis_atlas_pids()
  zk_smsp = _zk_node_exists("/appliance/logical/flow_smsp")
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

  if (not_found or (clusters and not flow)) and atlas_pids:
    info["detection_method"] = "mspctl_no_flow_cluster+genesis_atlas"
  elif not_found or (clusters and not flow):
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
  per_timeout = max(30, min(90, int(timeout_secs)))
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
    json.dump(value, handle, indent=2, default=_json_default)
  size = os.path.getsize(path)
  LOG.info("Wrote %s (%s bytes)", path, size)
  return path, size


def _write_outputs(payload, output_dir, combined_path, workers):
  os.makedirs(output_dir, exist_ok=True)
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
    if key in payload:
      jobs.append((os.path.join(output_dir, "%s.json" % key), payload[key]))
  jobs.append((combined_path, payload))

  LOG.info("Writing %s dataset files under %s plus combined %s",
           len(jobs) - 1, output_dir, combined_path)
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
    _write_outputs(payload, output_dir, combined_path, workers)
    LOG.info("Split complete under %s", output_dir)
    return 0

  platform_info = detect_msp_platform()
  LOG.info(
      "Platform %s (method=%s smsp_uuid=%s)",
      platform_info.get("platform"),
      platform_info.get("detection_method"),
      platform_info.get("smsp_cluster_uuid") or "<none>")

  LOG.info("FlowInterfaces managers + parallel idfcli infra (no v4_client)")
  LOG.info("workers=%s timeout=%ss atlas_timeout=%ss skip_atlas=%s",
           workers, FLAGS.dataset_timeout_secs, FLAGS.atlas_timeout_secs,
           FLAGS.skip_atlas)
  interfaces = FlowInterfaces()
  LOG.info("FlowInterfaces ready")

  errors = {}
  timeout_secs = max(15, int(FLAGS.dataset_timeout_secs))
  atlas_timeout_secs = max(30, int(FLAGS.atlas_timeout_secs))
  workers = max(1, int(FLAGS.workers))

  flow_jobs = [
      ("address_groups", lambda: fetch_address_groups(interfaces)),
      ("service_groups", lambda: fetch_service_groups(interfaces)),
      ("entity_groups", lambda: fetch_entity_groups(interfaces)),
      ("policies", lambda: fetch_policies(interfaces)),
      ("hosts", lambda: fetch_hosts(interfaces)),
      ("unique_uuids", fetch_unique_uuids),
      ("fqdn_to_ip_map", lambda: fetch_fqdn_map(interfaces)),
  ]
  infra_jobs = [
      ("vms", lambda: fetch_vms(interfaces)),
      ("subnets", lambda: fetch_subnets(interfaces)),
      ("vpcs", lambda: fetch_vpcs(interfaces)),
      ("clusters", lambda: fetch_clusters(interfaces)),
      ("projects", lambda: fetch_projects(interfaces)),
      ("categories", lambda: fetch_categories(interfaces)),
      ("network_functions", lambda: fetch_network_functions(interfaces)),
  ]

  payload = {
      "source": "flow_pc_dump_for_neo4j",
      "dumped_at": datetime.utcnow().isoformat() + "Z",
      "platform": platform_info.get("platform"),
      "platform_detection_method": platform_info.get("detection_method"),
      "smsp_cluster_uuid": platform_info.get("smsp_cluster_uuid") or "",
  }
  payload.update(_run_jobs_parallel(flow_jobs, workers, timeout_secs, errors))
  payload.update(_run_jobs_parallel(infra_jobs, workers, timeout_secs, errors))

  unique = payload.pop("unique_uuids", {}) or {}
  payload["vlan_unique_uuid"] = unique.get("vlan_unique_uuid", "")
  payload["global_unique_uuid"] = unique.get("global_unique_uuid", "")
  payload["network_function_by_id"] = fetch_network_function_by_id(
      interfaces, payload.get("network_functions") or [])

  payload["port_set_list"] = []
  payload["port_set_get"] = {}
  if FLAGS.skip_atlas:
    LOG.info("Skipping atlas_cli port_set dumps (--skip_atlas)")
  else:
    try:
      payload["port_set_list"] = fetch_port_set_list(
          platform_info, atlas_timeout_secs)
    except Exception as err:
      errors["port_set_list"] = str(err)
      LOG.error("DATASET port_set_list FAILED: %s", err)
    uuids = []
    seen = set()
    for item in payload.get("port_set_list") or []:
      ps_uuid = _port_set_uuid(item)
      if ps_uuid and ps_uuid not in seen:
        seen.add(ps_uuid)
        uuids.append(ps_uuid)
    try:
      payload["port_set_get"] = fetch_port_set_get(
          platform_info, uuids, workers, atlas_timeout_secs, errors)
    except Exception as err:
      errors["port_set_get"] = str(err)
      LOG.error("DATASET port_set_get FAILED: %s", err)

  payload["dump_errors"] = errors

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
  LOG.info("  %-22s %s", "network_function_by_id",
           len(payload.get("network_function_by_id") or {}))
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
