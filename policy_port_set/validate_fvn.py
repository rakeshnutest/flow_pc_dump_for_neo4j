#!/usr/bin/env python3
"""Check Flow Virtual Networking config against Atlas, OVN-NB, and OVN-SB.

IDF is the config. Each object must show up in Atlas, then in the
Northbound table that programs it, then in the Southbound datapath.

  atlas_subnet            -> atlas subnet.list, Logical_Switch network_<uuid>,
                             SB datapath name=network_<uuid>
  atlas_virtual_network   -> atlas network.list, Logical_Router whose name
                             contains the uuid, SB datapath name contains it
  atlas_route_table       -> atlas route_table.list, each active prefix on
                             that VPC router in Logical_Router_Static_Route.
                             SB has the VPC router datapath.
  layer2_stretch          -> atlas layer2_stretch.list, an NB switch or port
                             whose name contains the uuid, an SB datapath or
                             port binding that contains it
  bgp_session             -> atlas bgp_session.list, an NB router or route
                             external_id that contains the uuid, and the SB
                             datapath for that router

Redirect chassis: each external gateway port on
gw-scale-out-router_nat_<vpc> selects options:redirect-chassis. That value
must equal the port status hosting-chassis, the Southbound
l3gateway-chassis on ext_gw_port_<id>, and a node in the IDF candidate
list external_subnet_list.gateway_node_uuid_list. The number of selected
ports must equal external_subnet_list.active_gateway_count. A transit
port lrp-transit-switch_*_router_<vpc> uses the same redirect-chassis
and hosting-chassis. Its Southbound cr-lrp-* chassisredirect port must
sit on the Chassis whose name is that node. Transit selection is not
taken from the external-subnet candidate list.

Placement: every NB_Global row has nb_cfg == sb_cfg == hv_cfg, and every
Chassis_Private nb_cfg equals that number.

Learned routes: a Northbound Logical_Router_Static_Route with
external_ids:ic-learned-route=<uuid> is not in the IDF route table. The
uuid is the Route row in ovn-ic-sb, and the ip_prefix must match. Every
learned route is printed with the router, the VPC, the prefix, the
nexthop, the origin, and the IC route uuid. An IC route that no router
learned is a miss.

Stale taps: a tap<N> device on a hypervisor that no VM NIC on that host
names. CVM vnet devices are not taps. Each stale tap is a row in the
output and a miss.

An empty BGP or L2 gateway table is a pass. Stdout is the summary plus
tables for cfg, learned routes, and stale taps. A failed fetch or a
failed host is one error line for that check. The other checks still
run. Exit 0 when nothing is missing.

  python3 validate_fvn.py
  python3 validate_fvn.py --self-test
"""

from __future__ import print_function

import argparse
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen

LOG = logging.getLogger("validate_fvn")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
RC_RE = re.compile(r"redirect-chassis=([0-9a-fA-F-]{36})")
HOST_RE = re.compile(r"hosting-chassis=([0-9a-fA-F-]{36})")
L3_RE = re.compile(r"l3gateway-chassis=([0-9a-fA-F-]{36})")
LEARN_RE = re.compile(r"ic-learned-route=([0-9a-fA-F-]{36})")
ORIGIN_RE = re.compile(r"origin=([A-Za-z0-9_]+)")
NH_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/usr/local/nutanix/bin/idfcli",
    "/home/nutanix/bin/idfcli",
    "idfcli",
)
ATLAS_BINS = (
    "/usr/local/nutanix/bin/atlas_cli",
    "/home/nutanix/bin/atlas_cli",
    "atlas_cli",
)
NCLI_BINS = (
    "/home/nutanix/prism/cli/ncli",
    "/usr/local/nutanix/bin/ncli",
    "ncli",
)
AHV_PORT = 7030
HEALTH_CERT = "/home/certs/ClusterHealthService/ClusterHealthService.crt"
HEALTH_KEY = "/home/certs/ClusterHealthService/ClusterHealthService.key"
GENESIS_CERT = "/home/certs/GenesisService/GenesisService.crt"
GENESIS_KEY = "/home/certs/GenesisService/GenesisService.key"


def _which(paths):
    for path in paths:
        if path == "idfcli" or path == "atlas_cli":
            return path
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return paths[-1]


def _run(argv, timeout, input_text=None):
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=max(5, int(timeout)),
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return 1, "", str(err)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _json_blob(text):
    raw = text or ""
    start = raw.find("{")
    if start < 0:
        start = raw.find("[")
    if start < 0:
        return None
    try:
        return json.loads(raw[start:])
    except ValueError:
        return None


def _unpack(value):
    if not isinstance(value, dict):
        return value
    for key in ("str_value", "int64_value", "uint64_value", "bool_value"):
        if key in value:
            return value[key]
    for key in ("str_list", "int64_list", "uint64_list", "bool_list"):
        listed = value.get(key)
        if isinstance(listed, dict):
            return list(listed.get("value_list") or [])
        if isinstance(listed, list):
            return listed
    return None


def _attrs(entity):
    out = {}
    for item in (entity or {}).get("attribute_data_map") or []:
        name = item.get("name") or ""
        if not name or name == "__zprotobuf__":
            continue
        value = _unpack(item.get("value"))
        if name not in out:
            out[name] = value
            continue
        prev = out[name]
        if not isinstance(prev, list):
            prev = [prev]
        if isinstance(value, list):
            prev.extend(value)
        else:
            prev.append(value)
        out[name] = prev
    return out


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _entity_id(entity):
    guid = (entity or {}).get("entity_guid") or {}
    return str(guid.get("entity_id") or "").strip().lower()


def idf_entities(entity, timeout):
    """Rows for one IDF type. A missing type is an empty list."""
    binary = _which(IDF_BINS)
    rc, out, err = _run(
        [binary, "get", "entity", "-e", entity, "--all", "-o", "json"],
        timeout)
    blob = _json_blob(out)
    if not isinstance(blob, dict):
        text = (err or out or "")
        if "not found" in text.lower() or rc != 0:
            LOG.info("idf %s absent", entity)
            return []
        raise SystemExit("idfcli %s failed: %s" % (entity, text[:300]))
    rows = blob.get("entity") or blob.get("entities") or []
    if isinstance(rows, dict):
        rows = [rows]
    LOG.info("idf %s count=%s", entity, len(rows))
    return rows


def atlas_rows(command, timeout):
    binary = _which(ATLAS_BINS)
    rc, out, err = _run([binary, "-o", "json"] + command.split(), timeout)
    blob = _json_blob(out)
    if not isinstance(blob, dict):
        raise SystemExit("atlas_cli %s failed: %s" % (command, (err or out)[:300]))
    if blob.get("status") not in (None, 0, "0"):
        raise SystemExit("atlas_cli %s status=%s %s" % (
            command, blob.get("status"), blob.get("error")))
    data = blob.get("data") or []
    if isinstance(data, dict):
        data = data.get("data") or data.get("entities") or []
    if not isinstance(data, list):
        data = []
    LOG.info("atlas %s count=%s", command, len(data))
    return data


def _kubectl_prefix():
    rc, _out, _err = _run(["kubectl", "get", "pods", "-n", "default"], 20)
    if rc == 0:
        return ["kubectl"]
    return ["sudo", "-n", "kubectl"]


def ovn_csv(which, columns, table, timeout):
    tool = "ovn-nbctl" if which == "nb" else "ovn-sbctl"
    sock = "/var/run/ovn/ovn%sb_db.sock" % ("n" if which == "nb" else "s")
    args = ["--format=csv", "--data=bare", "--no-heading",
            "--columns=" + columns, "list", table]
    if os.path.exists(sock):
        rc, out, err = _run([tool, "--db=unix:" + sock] + args, timeout)
    else:
        cmd = _kubectl_prefix() + [
            "exec", "-n", "default", "anc-ovn-0", "-c", "anc-ovn", "--", tool]
        rc, out, err = _run(cmd + args, timeout)
        if rc != 0:
            cmd = _kubectl_prefix() + [
                "exec", "-n", "default", "anc-ovn-0", "--", tool]
            rc, out, err = _run(cmd + args, timeout)
    if rc != 0:
        raise SystemExit("%s %s failed: %s" % (tool, table, (err or out)[:300]))
    return out or ""


def ovn_ic_csv(columns, table, timeout):
    """Route rows from the OVN IC southbound database."""
    rc, out, _err = _run(
        _kubectl_prefix() + ["get", "pods", "-n", "default", "-o", "name"], 20)
    pod = "anc-ovn-ic-db-0"
    for line in (out or "").splitlines():
        name = line.strip().split("/")[-1]
        if name.startswith("anc-ovn-ic-db"):
            pod = name
            break
    args = ["--format=csv", "--data=bare", "--no-heading",
            "--columns=" + columns, "list", table]
    cmd = _kubectl_prefix() + [
        "exec", "-n", "default", pod, "--", "ovn-ic-sbctl"]
    rc, out, err = _run(cmd + args, timeout)
    if rc != 0:
        raise SystemExit("ovn-ic-sbctl %s failed: %s" % (table, (err or out)[:300]))
    return out or ""


def _uuids_from(rows, *keys):
    found = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        for key in keys:
            text = str(row.get(key) or "")
            for match in UUID_RE.findall(text):
                found.add(match.lower())
        if not keys:
            for match in UUID_RE.findall(json.dumps(row)):
                found.add(match.lower())
    return found


def _names(text):
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _contains(names, token):
    token = (token or "").lower()
    for name in names:
        if token and token in name.lower():
            return name
    return ""


def _sb_names(text):
    """external_ids name= values from Datapath_Binding or Port_Binding."""
    names = set()
    for match in re.finditer(r"name=([^\s,}]+)", text or ""):
        names.add(match.group(1).strip().strip('"').lower())
    return names


def _route_maps(router_text, prefix_text):
    """router name -> set of ip prefixes."""
    prefixes = {}
    for line in (prefix_text or "").splitlines():
        parts = [item.strip().strip('"') for item in line.split(",", 1)]
        if len(parts) < 2:
            continue
        prefixes[parts[0].lower()] = parts[1]
    by_router = {}
    for line in (router_text or "").splitlines():
        if "," not in line:
            continue
        name, rest = line.split(",", 1)
        name = name.strip()
        owned = set()
        for uid in UUID_RE.findall(rest):
            prefix = prefixes.get(uid.lower())
            if prefix:
                owned.add(prefix.strip().strip('"'))
        by_router[name] = owned
    return by_router


def _aligned(row, key):
    return _as_list((row or {}).get(key))


def _active_prefixes(row):
    prefixes = [str(item).strip() for item in _aligned(row, "route_list.destination_prefix")]
    active = _aligned(row, "route_list.is_active")
    kinds = [str(item) for item in _aligned(row, "route_list.route_type")]
    out = []
    for idx, prefix in enumerate(prefixes):
        if not prefix:
            continue
        flag = active[idx] if idx < len(active) else True
        if flag in (False, 0, "false", "False", "0"):
            continue
        kind = kinds[idx] if idx < len(kinds) else ""
        out.append((prefix, kind))
    return out


def _miss(kind, uid, name, where, expected, detail):
    return {
        "kind": kind,
        "uuid": uid,
        "name": name,
        "where": where,
        "expected": expected,
        "detail": detail,
    }


def check_subnets(rows, atlas, switches, sb_names):
    misses = []
    for entity in rows:
        uid = _entity_id(entity)
        attrs = _attrs(entity)
        name = str(attrs.get("name") or "")
        if not uid:
            continue
        expect = "network_" + uid
        if uid not in atlas:
            misses.append(_miss(
                "subnet", uid, name, "atlas", expect,
                "atlas subnet.list has no %s" % uid))
        if expect not in switches and not _contains(switches, uid):
            misses.append(_miss(
                "subnet", uid, name, "nb", expect,
                "Logical_Switch %s is missing" % expect))
        if expect not in sb_names and not _contains(sb_names, uid):
            misses.append(_miss(
                "subnet", uid, name, "sb", expect,
                "SB datapath %s is missing" % expect))
    return misses


def check_routers(rows, atlas, routers, sb_names):
    misses = []
    names = list(routers)
    for entity in rows:
        uid = _entity_id(entity)
        attrs = _attrs(entity)
        name = str(attrs.get("name") or "")
        if not uid:
            continue
        expect = "router_" + uid
        if uid not in atlas:
            misses.append(_miss(
                "router", uid, name, "atlas", expect,
                "atlas network.list has no %s" % uid))
        if not _contains(names, uid):
            misses.append(_miss(
                "router", uid, name, "nb", expect,
                "Logical_Router name does not contain %s" % uid))
        if not _contains(sb_names, uid):
            misses.append(_miss(
                "router", uid, name, "sb", expect,
                "SB datapath name does not contain %s" % uid))
    return misses


def check_routes(rows, atlas_tables, routers, sb_names):
    misses = []
    for entity in rows:
        uid = _entity_id(entity)
        attrs = _attrs(entity)
        vpc = str(attrs.get("virtual_network_uuid") or "").strip().lower()
        if not uid:
            continue
        if uid not in atlas_tables:
            misses.append(_miss(
                "route", uid, vpc, "atlas", "route_table " + uid,
                "atlas route_table.list has no %s" % uid))
        owned = set()
        router_name = ""
        for name, prefixes in routers.items():
            if vpc and vpc in name.lower():
                router_name = router_name or name
                owned.update(prefixes)
        if vpc and not _contains(sb_names, vpc):
            misses.append(_miss(
                "route", uid, vpc, "sb", "router_" + vpc,
                "SB datapath for VPC %s is missing" % vpc))
        for prefix, kind in _active_prefixes(attrs):
            if prefix not in owned:
                misses.append(_miss(
                    "route", uid, vpc, "nb", prefix,
                    "prefix %s route_type=%s is not on router %s" % (
                        prefix, kind or "?", router_name or vpc)))
    return misses


def _rc_by_name(text):
    """lrp name -> (redirect-chassis, hosting-chassis)."""
    found = {}
    for line in (text or "").splitlines():
        if "redirect-chassis" not in line:
            continue
        name = line.split(",", 1)[0].strip().strip('"')
        selected = RC_RE.search(line)
        if not name or not selected:
            continue
        hosted = HOST_RE.search(line)
        found[name] = (
            selected.group(1).lower(),
            hosted.group(1).lower() if hosted else "",
        )
    return found


def _sb_gateway(text):
    """ext_gw_port name -> l3gateway-chassis."""
    found = {}
    for line in (text or "").splitlines():
        selected = L3_RE.search(line)
        if not selected:
            continue
        port = line.split(",", 1)[0].strip().strip('"')
        found[port] = selected.group(1).lower()
    return found


def _lrp_names(text):
    """Logical_Router_Port uuid -> name."""
    found = {}
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        uid, name = line.split(",", 1)
        found[uid.strip().lower()] = name.strip().strip('"')
    return found


def _scaleout_ports(text):
    """VPC uuid -> port uuids on gw-scale-out-router_nat_<vpc>_*."""
    found = {}
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        name, rest = line.split(",", 1)
        if not name.startswith("gw-scale-out-router_nat_"):
            continue
        vpcs = UUID_RE.findall(name)
        if not vpcs:
            continue
        bucket = found.setdefault(vpcs[0].lower(), [])
        bucket.extend(item.lower() for item in UUID_RE.findall(rest))
    return found


def _gateway_choice(entity):
    attrs = _attrs(entity)
    nodes = [
        str(item).strip().lower()
        for item in _as_list(attrs.get("external_subnet_list.gateway_node_uuid_list"))
        if str(item).strip()
    ]
    total = 0
    for item in _as_list(attrs.get("external_subnet_list.active_gateway_count")):
        try:
            total += int(item)
        except (TypeError, ValueError):
            continue
    return nodes, total


def check_rc(routers, lrp_names, rc_by_name, sb_by_port, scaleout):
    """Selected redirect chassis must match NB hosting, SB placement, and IDF."""
    misses = []
    checked = 0
    for entity in routers:
        vpc = _entity_id(entity)
        name = str(_attrs(entity).get("name") or "")
        if not vpc:
            continue
        candidates, want = _gateway_choice(entity)
        if want <= 0 and not candidates:
            continue
        selected = []
        for port_uuid in scaleout.get(vpc, []):
            lrp_name = lrp_names.get(port_uuid, "")
            if not lrp_name.startswith("lrp-ext_gw_port_"):
                continue
            pair = rc_by_name.get(lrp_name)
            if not pair:
                misses.append(_miss(
                    "rc", vpc, name, "nb", "redirect-chassis",
                    "ext gw %s has no redirect-chassis" % lrp_name))
                continue
            chosen, hosted = pair
            checked += 1
            selected.append(chosen)
            logical = lrp_name[len("lrp-"):]
            if chosen != hosted:
                misses.append(_miss(
                    "rc", vpc, name, "nb", chosen,
                    "redirect-chassis=%s hosting-chassis=%s on %s" % (
                        chosen, hosted or "missing", lrp_name)))
            placed = sb_by_port.get(logical, "")
            if placed != chosen:
                misses.append(_miss(
                    "rc", vpc, name, "sb", chosen,
                    "l3gateway-chassis=%s on %s" % (placed or "missing", logical)))
            if candidates and chosen not in candidates:
                misses.append(_miss(
                    "rc", vpc, name, "idf", chosen,
                    "redirect-chassis %s is not in gateway_node_uuid_list" % chosen))
        if want and len(selected) != want:
            misses.append(_miss(
                "rc", vpc, name, "nb", "active_gateway_count=%s" % want,
                "selected redirect-chassis count=%s" % len(selected)))
    return misses, checked


def _sb_redirect(text):
    """cr-lrp logical port -> SB chassis uuid."""
    found = {}
    for line in (text or "").splitlines():
        parts = [item.strip().strip('"') for item in line.split(",", 2)]
        if len(parts) < 2 or not parts[0].startswith("cr-lrp-"):
            continue
        if UUID_RE.match(parts[1]):
            found[parts[0]] = parts[1].lower()
    return found


def _chassis_names(text):
    """SB Chassis uuid -> name, which is the node uuid."""
    found = {}
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        uid, name = line.split(",", 1)
        found[uid.strip().lower()] = name.strip().strip('"').lower()
    return found


def check_transit(rc_by_name, sb_redirect, chassis_names):
    """Transit redirect chassis must match hosting and the cr-lrp chassis."""
    misses = []
    checked = 0
    for lrp_name, pair in rc_by_name.items():
        if not lrp_name.startswith("lrp-transit-switch_"):
            continue
        chosen, hosted = pair
        checked += 1
        uuids = UUID_RE.findall(lrp_name)
        vpc = uuids[-1].lower() if uuids else ""
        if chosen != hosted:
            misses.append(_miss(
                "rc", vpc, lrp_name, "nb", chosen,
                "redirect-chassis=%s hosting-chassis=%s on %s" % (
                    chosen, hosted or "missing", lrp_name)))
        placed = chassis_names.get(sb_redirect.get("cr-" + lrp_name, ""), "")
        if placed != chosen:
            misses.append(_miss(
                "rc", vpc, lrp_name, "sb", chosen,
                "cr-lrp chassis=%s" % (placed or "missing")))
    return misses, checked


def _cfg_rows(text):
    rows = []
    for line in (text or "").splitlines():
        parts = [item.strip() for item in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            rows.append({
                "uuid": parts[0],
                "nb_cfg": int(parts[1]),
                "sb_cfg": int(parts[2]),
                "hv_cfg": int(parts[3]),
            })
        except ValueError:
            continue
    return rows


def _chassis_rows(text):
    rows = []
    for line in (text or "").splitlines():
        parts = [item.strip() for item in line.split(",")]
        if len(parts) < 3:
            continue
        try:
            rows.append({
                "uuid": parts[0],
                "name": parts[1],
                "nb_cfg": int(parts[2]),
            })
        except ValueError:
            continue
    return rows


def check_cfg(rows, chassis):
    """nb_cfg, sb_cfg, and hv_cfg agree, and every chassis has that nb_cfg."""
    misses = []
    if not rows:
        return [_miss("cfg", "", "", "nb", "NB_Global", "no NB_Global row")]
    expected = rows[0]["nb_cfg"]
    for row in rows:
        if row["nb_cfg"] == row["sb_cfg"] == row["hv_cfg"] == expected:
            continue
        misses.append(_miss(
            "cfg", row["uuid"], "", "nb", str(expected),
            "nb_cfg=%s sb_cfg=%s hv_cfg=%s" % (
                row["nb_cfg"], row["sb_cfg"], row["hv_cfg"])))
    if not chassis:
        misses.append(_miss(
            "cfg", "", "", "sb", str(expected), "no Chassis_Private uuid"))
        return misses
    for row in chassis:
        if row["nb_cfg"] == expected:
            continue
        misses.append(_miss(
            "cfg", row["uuid"], row["name"], "sb", str(expected),
            "nb_cfg=%s expected=%s" % (row["nb_cfg"], expected)))
    return misses


def _learned_rows(text):
    """NB static routes that carry ic-learned-route, with prefix and nexthop."""
    found = []
    for line in (text or "").splitlines():
        match = LEARN_RE.search(line)
        if not match:
            continue
        fields = [item.strip().strip('"') for item in line.split(",")]
        route_uuid = fields[0].lower() if fields and UUID_RE.match(fields[0]) else ""
        prefix = ""
        nexthop = ""
        for field in fields[1:]:
            if not prefix and "/" in field and "ic-learned" not in field and "origin" not in field:
                prefix = field
                continue
            if not nexthop and NH_RE.match(field):
                nexthop = field
        origin = ORIGIN_RE.search(line)
        found.append({
            "route_uuid": route_uuid,
            "prefix": prefix,
            "nexthop": nexthop,
            "origin": origin.group(1) if origin else "",
            "ic_route": match.group(1).lower(),
        })
    return found


def _ic_routes(text):
    """IC Route uuid -> prefix, plus nexthop and origin for the extra rows."""
    prefixes = {}
    rows = []
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        parts = [item.strip().strip('"') for item in line.split(",")]
        uid = parts[0].lower()
        prefix = parts[1] if len(parts) > 1 else ""
        prefixes[uid] = prefix
        rows.append({
            "ic_route": uid,
            "prefix": prefix,
            "nexthop": parts[2] if len(parts) > 2 else "",
            "origin": parts[3] if len(parts) > 3 else "",
        })
    return prefixes, rows


def _route_owners(text):
    """Logical_Router_Static_Route uuid -> router name."""
    owners = {}
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        name, rest = line.split(",", 1)
        name = name.strip().strip('"')
        for uid in UUID_RE.findall(rest):
            owners.setdefault(uid.lower(), name)
    return owners


def _vpc_from_router(name):
    if name.startswith("router_") or name.startswith("gw-scale-out-router_nat_"):
        found = UUID_RE.findall(name)
        if found:
            return found[0].lower()
    return ""


def _vpc_names(routers):
    names = {}
    for entity in routers or []:
        uid = _entity_id(entity)
        if uid:
            names[uid] = str(_attrs(entity).get("name") or "")
    return names


def learned_records(learned, ic_prefixes, owners, vpc_names):
    """One record per learned route: router, VPC, and the IC route it matched."""
    records = []
    misses = 0
    for row in learned or []:
        ic_route = row.get("ic_route") or ""
        prefix = row.get("prefix") or ""
        advertised = ic_prefixes.get(ic_route)
        router = owners.get(row.get("route_uuid") or "", "")
        vpc = _vpc_from_router(router)
        if advertised is None:
            matched = "no"
            detail = "ic-learned-route %s is not an IC Route" % ic_route
            misses += 1
        elif advertised != prefix:
            matched = "no"
            detail = "IC prefix %s does not match learned prefix %s" % (
                advertised, prefix)
            misses += 1
        else:
            matched = "yes"
            detail = ""
        records.append({
            "kind": "learned",
            "router": router,
            "vpc": vpc,
            "vpc_name": vpc_names.get(vpc, ""),
            "route_uuid": row.get("route_uuid") or "",
            "prefix": prefix,
            "nexthop": row.get("nexthop") or "",
            "origin": row.get("origin") or "",
            "ic_route": ic_route,
            "ic_prefix": advertised or "",
            "match": matched,
            "detail": detail,
        })
    return records, misses


def check_named(kind, rows, atlas, nb_blob, sb_blob, nb_expect, sb_expect):
    """L2 gateway and BGP. The uuid must appear in Atlas, NB text, and SB text."""
    misses = []
    for entity in rows:
        uid = _entity_id(entity)
        attrs = _attrs(entity)
        name = str(attrs.get("name") or attrs.get("local_gateway_name") or "")
        if not uid:
            continue
        if uid not in atlas:
            misses.append(_miss(
                kind, uid, name, "atlas", uid,
                "atlas %s.list has no %s" % (kind, uid)))
        if uid not in (nb_blob or "").lower():
            misses.append(_miss(
                kind, uid, name, "nb", nb_expect,
                "OVN-NB has no reference to %s" % uid))
        if uid not in (sb_blob or "").lower():
            misses.append(_miss(
                kind, uid, name, "sb", sb_expect,
                "OVN-SB has no reference to %s" % uid))
    return misses


def _count(rows):
    return len([entity for entity in rows if _entity_id(entity)])


def _tsv(handle, headers, rows):
    handle.write("\t".join(headers) + "\n")
    for row in rows:
        handle.write("\t".join(str(row.get(key, "")) for key in headers) + "\n")


def write_cfg_table(rows, chassis, handle):
    """Print NB_Global and every chassis. missing is rows that disagree."""
    misses = check_cfg(rows, chassis)
    expected = rows[0]["nb_cfg"] if rows else ""
    handle.write(
        "FVN cfg: nb_global=%s chassis=%s missing=%s\n" % (
            len(rows), len(chassis), len(misses)))
    if rows and chassis and len(misses) == 0:
        handle.write(
            "cfg note: one NB_Global row and %s chassis rows carry nb_cfg=%s. "
            "The counts differ because they are different tables.\n" % (
                len(chassis), expected))
    table = []
    for row in rows:
        same = row["nb_cfg"] == row["sb_cfg"] == row["hv_cfg"] == expected
        detail = "" if same else "nb_cfg=%s sb_cfg=%s hv_cfg=%s" % (
            row["nb_cfg"], row["sb_cfg"], row["hv_cfg"])
        table.append({
            "table": "NB_Global",
            "uuid": row["uuid"],
            "name": "",
            "nb_cfg": row["nb_cfg"],
            "sb_cfg": row["sb_cfg"],
            "hv_cfg": row["hv_cfg"],
            "expected": expected,
            "match": "yes" if same else "no",
            "detail": detail,
        })
    for row in chassis:
        same = bool(rows) and row["nb_cfg"] == expected
        table.append({
            "table": "Chassis_Private",
            "uuid": row["uuid"],
            "name": row["name"],
            "nb_cfg": row["nb_cfg"],
            "sb_cfg": "",
            "hv_cfg": "",
            "expected": expected,
            "match": "yes" if same else "no",
            "detail": "" if same else "nb_cfg=%s expected=%s" % (
                row["nb_cfg"], expected),
        })
    _tsv(handle, [
        "table", "uuid", "name", "nb_cfg", "sb_cfg", "hv_cfg",
        "expected", "match", "detail"], table)
    return len(misses)


def write_learned_tables(learned, ic_prefixes, ic_rows, owners, vpc_names, handle, ic_error=""):
    """Print every installed learned route, then IC routes no router learned.

    An IC fetch failure is one miss. It does not mark every installed
    route as a prefix mismatch.
    """
    if ic_error:
        handle.write(
            "FVN learned: installed=%s ic=0 not_installed=0 missing=1\n" % len(learned or []))
        handle.write("learned note: IC fetch failed: %s\n" % ic_error)
        skipped = []
        for row in learned or []:
            router = owners.get(row.get("route_uuid") or "", "")
            vpc = _vpc_from_router(router)
            skipped.append({
                "router": router,
                "vpc": vpc,
                "vpc_name": vpc_names.get(vpc, ""),
                "prefix": row.get("prefix") or "",
                "nexthop": row.get("nexthop") or "",
                "origin": row.get("origin") or "",
                "route_uuid": row.get("route_uuid") or "",
                "ic_route": row.get("ic_route") or "",
                "ic_prefix": "",
                "match": "not_checked",
                "detail": ic_error,
            })
        _tsv(handle, [
            "router", "vpc", "vpc_name", "prefix", "nexthop", "origin",
            "route_uuid", "ic_route", "ic_prefix", "match", "detail"], skipped)
        return 1
    records, mismatches = learned_records(learned, ic_prefixes, owners, vpc_names)
    installed = set(row.get("ic_route") or "" for row in records)
    extra = [row for row in ic_rows or [] if row.get("ic_route") not in installed]
    misses = mismatches + len(extra)
    handle.write(
        "FVN learned: installed=%s ic=%s not_installed=%s missing=%s\n" % (
            len(records), len(ic_prefixes), len(extra), misses))
    handle.write(
        "learned note: installed is Northbound routes with ic-learned-route. "
        "ic is ovn-ic-sbctl Route. not_installed means IC advertised the "
        "prefix and no router on this PC learned it. missing is that count "
        "plus any installed route whose IC prefix does not match.\n")
    _tsv(handle, [
        "router", "vpc", "vpc_name", "prefix", "nexthop", "origin",
        "route_uuid", "ic_route", "ic_prefix", "match", "detail"], records)
    if extra:
        handle.write("FVN learned_not_installed: count=%s\n" % len(extra))
        _tsv(handle, ["ic_route", "prefix", "nexthop", "origin"], extra)
    return misses


def write_report(label, idf_count, atlas_count, misses, handle):
    handle.write(
        "FVN %s: idf=%s atlas=%s missing=%s\n" % (
            label, idf_count, atlas_count, len(misses)))
    for rec in misses:
        handle.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
    return len(misses)


def _ssl_ctx(crt, key):
    ctx = ssl._create_unverified_context()
    ctx.load_cert_chain(crt, key)
    return ctx


def _gw_open(ip, path, crt, key, timeout, accept):
    req = Request(
        "https://%s:%s%s" % (ip, AHV_PORT, path),
        headers={"Accept": accept, "Accept-Encoding": "identity"})
    return urlopen(req, context=_ssl_ctx(crt, key), timeout=timeout)


def _ncli_hosts(timeout):
    binary = _which(NCLI_BINS)
    rc, out, err = _run([binary, "host", "list"], timeout)
    if rc != 0:
        raise SystemExit("ncli host list failed: %s" % (err or out)[:300])
    hosts = []
    for block in re.split(r"\n\s*\n", out or ""):
        def grab(key, text=block):
            match = re.search(
                r"^\s*%s\s*:\s*(.*)$" % re.escape(key), text, re.M)
            return match.group(1).strip() if match else ""
        name, ip = grab("Name"), grab("Hypervisor Address")
        if name and re.match(r"\d+\.\d+\.\d+\.\d+$", ip):
            hosts.append((name, ip))
    if not hosts:
        raise SystemExit("ncli host list returned no hypervisor addresses")
    return hosts


def _bugtool_member(ip, bug, suffix, crt, key, timeout):
    resp = _gw_open(
        ip, "/api/host/v1/bugtool/" + bug, crt, key, timeout,
        "application/octet-stream")
    try:
        tar = tarfile.open(fileobj=resp, mode="r|*")
        for info in tar:
            if info.name.endswith(suffix) and info.isfile():
                handle = tar.extractfile(info)
                return handle.read().decode("utf-8", "replace") if handle else ""
    finally:
        resp.close()
    return ""


def _parse_ip_taps(text):
    """tap name -> state and MAC from `ip -s link`."""
    found = {}
    lines = (text or "").splitlines()
    for idx, line in enumerate(lines):
        match = re.match(r"^\d+: (tap\d+): <([^>]*)>.*\bstate (\S+)", line)
        if not match:
            continue
        mac = ""
        if idx + 1 < len(lines):
            mac_match = re.search(r"link/ether ([0-9a-f:]+)", lines[idx + 1])
            if mac_match:
                mac = mac_match.group(1)
        found[match.group(1)] = {"state": match.group(3), "mac": mac}
    return found


def _vm_tapnames(ip, timeout):
    resp = _gw_open(
        ip, "/api/vmm/v1/vms", GENESIS_CERT, GENESIS_KEY, timeout,
        "application/json")
    vms = json.loads(resp.read().decode("utf-8", "replace") or "[]")
    resp.close()
    ids = [item.get("id") for item in vms if item.get("id")]

    def one(vid):
        body = _gw_open(
            ip, "/api/vmm/v1/vms/" + vid, GENESIS_CERT, GENESIS_KEY,
            timeout, "application/json")
        try:
            data = json.loads(body.read().decode("utf-8", "replace") or "{}")
        finally:
            body.close()
        names = set()
        for nic in ((data.get("devices") or {}).get("nics") or []):
            tap = ((nic.get("status") or {}).get("backend") or {}).get("tapname") or ""
            if str(tap).startswith("tap"):
                names.add(str(tap))
        return names

    owned = set()
    with ThreadPoolExecutor(max_workers=12) as pool:
        for names in pool.map(one, ids):
            owned.update(names)
    return owned


def _bridges(text, wanted):
    bridge = ""
    found = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("Bridge "):
            bridge = stripped.split()[-1].strip('"')
        elif stripped.startswith("Interface ") or stripped.startswith("Port "):
            name = stripped.split()[-1].strip('"')
            if name in wanted:
                found[name] = bridge
    return found


def _scan_host(item, timeout):
    name, ip = item
    try:
        return _scan_host_ok(item, timeout)
    except (Exception, SystemExit) as err:
        detail = "host check failed: %s" % str(err).split("\n", 1)[0][:200]
        LOG.warning("tap %s %s %s", name, ip, detail)
        return name, ip, 0, [{
            "host": name,
            "ip": ip,
            "tap": "",
            "bridge": "",
            "state": "",
            "mac": "",
            "detail": detail,
        }]


def _scan_host_ok(item, timeout):
    name, ip = item
    link = _bugtool_member(
        ip, "networking-lite", "commands/ip_-s_link.stdout",
        HEALTH_CERT, HEALTH_KEY, min(timeout, 60))
    live = _parse_ip_taps(link)
    owned = _vm_tapnames(ip, min(timeout, 30))
    stale = sorted(set(live) - owned)
    bridges = {}
    if stale:
        show = _bugtool_member(
            ip, "networking", "commands/ovs-vsctl_show.stdout",
            HEALTH_CERT, HEALTH_KEY, timeout)
        bridges = _bridges(show, set(stale))
    rows = []
    for tap in stale:
        info = live.get(tap) or {}
        rows.append({
            "host": name,
            "ip": ip,
            "tap": tap,
            "bridge": bridges.get(tap, ""),
            "state": info.get("state", ""),
            "mac": info.get("mac", ""),
            "detail": "no VM NIC has tapname %s" % tap,
        })
    return name, ip, len(live), rows


def scan_taps(timeout):
    """Taps present on a host and absent from every VM NIC on that host.

    A missing cert or a failed host list is an error string. One host
    that fails is one row. The other hosts are still checked.
    """
    for path in (HEALTH_CERT, HEALTH_KEY, GENESIS_CERT, GENESIS_KEY):
        if not os.path.isfile(path):
            return [], [], "AHV Gateway cert missing: %s" % path
    try:
        hosts = _ncli_hosts(timeout)
    except (Exception, SystemExit) as err:
        return [], [], str(err).split("\n", 1)[0][:300]
    rows = []
    LOG.info("tap hosts=%s", len(hosts))
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(_scan_host, host, timeout) for host in hosts]
        for fut in as_completed(futs):
            name, ip, count, stale = fut.result()
            LOG.info("tap %s %s devices=%s stale=%s", name, ip, count, len(stale))
            rows.extend(stale)
    rows.sort(key=lambda row: (row["host"], row["tap"]))
    return hosts, rows, ""


def write_tap_table(hosts, rows, handle, error=""):
    if error:
        handle.write("FVN tap: hosts=%s missing=1\n" % len(hosts))
        handle.write("tap note: %s\n" % error)
        return 1
    handle.write(
        "FVN tap: hosts=%s missing=%s\n" % (len(hosts), len(rows)))
    handle.write(
        "tap note: a row is a tap<N> device on the hypervisor that no VM "
        "NIC on that host names. CVM vnet devices are not taps.\n")
    _tsv(handle, ["host", "ip", "tap", "bridge", "state", "mac", "detail"], rows)
    return len(rows)


def _catch(errors, key, fn, default):
    """Run one fetch. A failure is recorded and the other fetches still run."""
    try:
        return fn()
    except (Exception, SystemExit) as err:
        errors[key] = str(err).split("\n", 1)[0][:240]
        LOG.warning("%s failed: %s", key, errors[key])
        return default


def collect(timeout):
    errors = {}

    def grab(key, fn, default):
        return _catch(errors, key, fn, default)

    subnets = grab("idf_subnet", lambda: idf_entities("atlas_subnet", timeout), [])
    routers = grab(
        "idf_router", lambda: idf_entities("atlas_virtual_network", timeout), [])
    routes = grab("idf_route", lambda: idf_entities("atlas_route_table", timeout), [])
    stretches = grab("idf_l2", lambda: idf_entities("layer2_stretch", timeout), [])
    if not stretches and "idf_l2" not in errors:
        stretches = grab(
            "idf_l2", lambda: idf_entities("atlas_layer2_stretch", timeout), [])
    sessions = grab("idf_bgp", lambda: idf_entities("bgp_session", timeout), [])
    if not sessions and "idf_bgp" not in errors:
        sessions = grab(
            "idf_bgp", lambda: idf_entities("atlas_bgp_session", timeout), [])
    atlas = {
        "subnet": grab(
            "atlas_subnet",
            lambda: _uuids_from(atlas_rows("subnet.list", timeout), "uuid"), set()),
        "router": grab(
            "atlas_router",
            lambda: _uuids_from(atlas_rows("network.list", timeout), "uuid"), set()),
        "route": grab(
            "atlas_route",
            lambda: _uuids_from(atlas_rows("route_table.list", timeout), "uuid"), set()),
        "l2gw": grab(
            "atlas_l2",
            lambda: _uuids_from(atlas_rows("layer2_stretch.list", timeout), "uuid"), set()),
        "bgp": grab(
            "atlas_bgp",
            lambda: _uuids_from(atlas_rows("bgp_session.list", timeout), "uuid"), set()),
    }
    switches = set(name.lower() for name in _names(grab(
        "nb_switch", lambda: ovn_csv("nb", "name", "Logical_Switch", timeout), "")))
    prefix_text = grab(
        "nb_learned",
        lambda: ovn_csv(
            "nb", "_uuid,ip_prefix,nexthop,options,external_ids",
            "Logical_Router_Static_Route", timeout),
        "")
    route_ids = grab(
        "nb_route_id",
        lambda: ovn_csv("nb", "_uuid,ip_prefix", "Logical_Router_Static_Route", timeout),
        "")
    router_text = grab(
        "nb_router",
        lambda: ovn_csv("nb", "name,static_routes", "Logical_Router", timeout), "")
    scaleout = _scaleout_ports(grab(
        "nb_router_ports",
        lambda: ovn_csv("nb", "name,ports", "Logical_Router", timeout), ""))
    lrp_names = _lrp_names(grab(
        "nb_lrp_name",
        lambda: ovn_csv("nb", "_uuid,name", "Logical_Router_Port", timeout), ""))
    rc_by_name = _rc_by_name(grab(
        "nb_lrp_opt",
        lambda: ovn_csv("nb", "name,options,status", "Logical_Router_Port", timeout), ""))
    sb_text = grab(
        "sb_dp", lambda: ovn_csv("sb", "external_ids", "Datapath_Binding", timeout), "")
    sb_names = _sb_names(sb_text)
    binding_text = grab(
        "sb_bind",
        lambda: ovn_csv("sb", "logical_port,chassis,options", "Port_Binding", timeout), "")
    sb_gateway = _sb_gateway(binding_text)
    sb_redirect = _sb_redirect(binding_text)
    chassis_names = _chassis_names(grab(
        "sb_chassis", lambda: ovn_csv("sb", "_uuid,name", "Chassis", timeout), ""))
    cfg_rows = _cfg_rows(grab(
        "nb_global",
        lambda: ovn_csv("nb", "_uuid,nb_cfg,sb_cfg,hv_cfg", "NB_Global", timeout), ""))
    chassis_rows = _chassis_rows(grab(
        "sb_private",
        lambda: ovn_csv("sb", "_uuid,name,nb_cfg", "Chassis_Private", timeout), ""))
    learned = _learned_rows(prefix_text)
    learned_uuids = set(row.get("route_uuid", "").lower() for row in learned)
    static_route_ids = "\n".join(
        line for line in (route_ids or "").splitlines()
        if line.strip() and line.split(",", 1)[0].strip().strip('"').lower()
        not in learned_uuids)
    router_map = _route_maps(router_text, static_route_ids)
    ic_text = grab(
        "ic",
        lambda: ovn_ic_csv("_uuid,ip_prefix,nexthop,origin", "Route", timeout), "")
    if "ic" in errors:
        ic_prefixes, ic_rows = {}, []
    else:
        ic_prefixes, ic_rows = _ic_routes(ic_text)
    route_owners = _route_owners(router_text)
    tap_hosts, taps, tap_error = scan_taps(timeout)
    if tap_error:
        errors["tap"] = tap_error
    LOG.info(
        "rc ports=%s learned=%s ic=%s cfg=%s chassis=%s taps=%s errors=%s",
        len(rc_by_name), len(learned), len(ic_prefixes),
        len(cfg_rows), len(chassis_rows), len(taps), len(errors))
    nb_extra = ""
    sb_extra = sb_text
    if stretches or sessions:
        nb_extra = grab(
            "nb_lsp",
            lambda: ovn_csv("nb", "name,external_ids", "Logical_Switch_Port", timeout),
            "")
        nb_extra += "\n" + router_text
        sb_extra += "\n" + grab(
            "sb_port",
            lambda: ovn_csv("sb", "logical_port,external_ids", "Port_Binding", timeout),
            "")
    return {
        "subnets": subnets,
        "routers": routers,
        "routes": routes,
        "stretches": stretches,
        "sessions": sessions,
        "atlas": atlas,
        "switches": switches,
        "router_map": router_map,
        "sb_names": sb_names,
        "nb_extra": nb_extra,
        "sb_extra": sb_extra,
        "lrp_names": lrp_names,
        "rc_by_name": rc_by_name,
        "sb_gateway": sb_gateway,
        "sb_redirect": sb_redirect,
        "chassis_names": chassis_names,
        "scaleout": scaleout,
        "cfg_rows": cfg_rows,
        "chassis_rows": chassis_rows,
        "learned": learned,
        "ic_prefixes": ic_prefixes,
        "ic_rows": ic_rows,
        "route_owners": route_owners,
        "vpc_names": _vpc_names(routers),
        "tap_hosts": tap_hosts,
        "taps": taps,
        "errors": errors,
    }


def _limit(misses, kind, errors, mapping):
    """Drop per-object misses for a fetch that failed, and keep one error."""
    out = []
    noted = set()
    for miss in misses:
        key = mapping.get(miss.get("where"))
        if key and errors.get(key):
            if key not in noted:
                noted.add(key)
                out.append(_miss(kind, "", "", miss.get("where"), "", errors[key]))
            continue
        out.append(miss)
    for where, key in mapping.items():
        if errors.get(key) and key not in noted:
            noted.add(key)
            out.append(_miss(kind, "", "", where, "", errors[key]))
    return out


def _safe(handle, label, fn):
    try:
        return fn()
    except (Exception, SystemExit) as err:
        handle.write(
            "FVN %s: missing=1 error=%s\n" % (
                label, str(err).split("\n", 1)[0][:240]))
        return 1


def run_checks(data, handle):
    atlas = data["atlas"]
    errors = data.get("errors") or {}
    total = 0

    def subnet():
        if errors.get("idf_subnet"):
            handle.write("FVN subnet: idf=0 atlas=0 missing=1\n")
            handle.write("FVN subnet fetch: error=%s\n" % errors["idf_subnet"])
            return 1
        misses = _limit(
            check_subnets(
                data["subnets"], atlas["subnet"], data["switches"], data["sb_names"]),
            "subnet", errors,
            {"atlas": "atlas_subnet", "nb": "nb_switch", "sb": "sb_dp"})
        return write_report(
            "subnet", _count(data["subnets"]), len(atlas["subnet"]), misses, handle)

    def router():
        if errors.get("idf_router"):
            handle.write("FVN router: idf=0 atlas=0 missing=1\n")
            handle.write("FVN router fetch: error=%s\n" % errors["idf_router"])
            return 1
        misses = _limit(
            check_routers(
                data["routers"], atlas["router"], data["router_map"], data["sb_names"]),
            "router", errors,
            {"atlas": "atlas_router", "nb": "nb_router", "sb": "sb_dp"})
        return write_report(
            "router", _count(data["routers"]), len(atlas["router"]), misses, handle)

    def route():
        if errors.get("idf_route"):
            handle.write("FVN route: idf=0 atlas=0 missing=1\n")
            handle.write("FVN route fetch: error=%s\n" % errors["idf_route"])
            return 1
        nb_key = "nb_route_id" if errors.get("nb_route_id") else "nb_router"
        misses = _limit(
            check_routes(
                data["routes"], atlas["route"], data["router_map"], data["sb_names"]),
            "route", errors,
            {"atlas": "atlas_route", "nb": nb_key, "sb": "sb_dp"})
        return write_report(
            "route", _count(data["routes"]), len(atlas["route"]), misses, handle)

    def named(label, rows, atlas_key, idf_key, atlas_err, nb_expect, sb_expect, nb_key, sb_key):
        if errors.get(idf_key):
            handle.write("FVN %s: idf=0 atlas=0 missing=1\n" % label)
            handle.write("FVN %s fetch: error=%s\n" % (label, errors[idf_key]))
            return 1
        misses = _limit(
            check_named(
                label, rows, atlas[atlas_key], data["nb_extra"], data["sb_extra"],
                nb_expect, sb_expect),
            label, errors, {"atlas": atlas_err, "nb": nb_key, "sb": sb_key})
        return write_report(label, _count(rows), len(atlas[atlas_key]), misses, handle)

    def rc():
        blocked = [errors[key] for key in (
            "idf_router", "nb_lrp_name", "nb_lrp_opt", "nb_router_ports")
            if errors.get(key)]
        if blocked:
            handle.write("FVN rc: idf=0 atlas=0 missing=1\n")
            handle.write("FVN rc fetch: error=%s\n" % blocked[0])
            return 1
        misses, checked = check_rc(
            data["routers"], data["lrp_names"], data["rc_by_name"],
            data["sb_gateway"], data["scaleout"])
        transit_misses, transit_checked = check_transit(
            data["rc_by_name"], data["sb_redirect"], data["chassis_names"])
        misses.extend(transit_misses)
        if errors.get("sb_bind"):
            misses = [m for m in misses if "l3gateway-chassis" not in m.get("detail", "")]
            misses.append(_miss("rc", "", "", "sb", "", errors["sb_bind"]))
        if errors.get("sb_chassis"):
            misses = [m for m in misses if "cr-lrp chassis" not in m.get("detail", "")]
            misses.append(_miss("rc", "", "", "sb", "", errors["sb_chassis"]))
        return write_report("rc", checked + transit_checked, checked + transit_checked, misses, handle)

    def cfg():
        blocked = [errors[key] for key in ("nb_global", "sb_private") if errors.get(key)]
        if blocked:
            handle.write("FVN cfg: nb_global=0 chassis=0 missing=1\n")
            handle.write("FVN cfg fetch: error=%s\n" % blocked[0])
            return 1
        return write_cfg_table(data["cfg_rows"], data["chassis_rows"], handle)

    def learned():
        if errors.get("nb_learned"):
            handle.write("FVN learned: installed=0 ic=0 not_installed=0 missing=1\n")
            handle.write("FVN learned fetch: error=%s\n" % errors["nb_learned"])
            return 1
        return write_learned_tables(
            data["learned"], data["ic_prefixes"], data.get("ic_rows") or [],
            data.get("route_owners") or {}, data.get("vpc_names") or {}, handle,
            ic_error=errors.get("ic") or "")

    def tap():
        return write_tap_table(
            data.get("tap_hosts") or [], data.get("taps") or [], handle,
            error=errors.get("tap") or "")

    total += _safe(handle, "subnet", subnet)
    total += _safe(handle, "router", router)
    total += _safe(handle, "route", route)
    total += _safe(handle, "l2gw", lambda: named(
        "l2gw", data["stretches"], "l2gw", "idf_l2", "atlas_l2",
        "Logical_Switch_Port", "Port_Binding", "nb_lsp", "sb_port"))
    total += _safe(handle, "bgp", lambda: named(
        "bgp", data["sessions"], "bgp", "idf_bgp", "atlas_bgp",
        "Logical_Router", "Datapath_Binding", "nb_router", "sb_dp"))
    total += _safe(handle, "rc", rc)
    total += _safe(handle, "cfg", cfg)
    total += _safe(handle, "learned", learned)
    total += _safe(handle, "tap", tap)
    return total


def _sample():
    subnet = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    vpc = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    table = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    port = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    gw = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    node = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    learned = "11111111-1111-4111-8111-111111111111"
    chassis = "22222222-2222-4222-8222-222222222222"
    data = {
        "subnets": [{
            "entity_guid": {"entity_id": subnet},
            "attribute_data_map": [
                {"name": "name", "value": {"str_value": "overlay-1"}},
                {"name": "subnet_type", "value": {"int64_value": 0}},
                {"name": "virtual_network_uuid", "value": {"str_value": vpc}},
            ],
        }],
        "routers": [{
            "entity_guid": {"entity_id": vpc},
            "attribute_data_map": [
                {"name": "name", "value": {"str_value": "vpc-1"}},
                {"name": "external_subnet_list.gateway_node_uuid_list", "value": {
                    "str_list": {"value_list": [node]}}},
                {"name": "external_subnet_list.active_gateway_count", "value": {
                    "int64_list": {"value_list": [1]}}},
            ],
        }],
        "routes": [{
            "entity_guid": {"entity_id": table},
            "attribute_data_map": [
                {"name": "virtual_network_uuid", "value": {"str_value": vpc}},
                {"name": "route_list.destination_prefix", "value": {
                    "str_list": {"value_list": ["192.168.1.0/24", "10.0.0.0/8"]}}},
                {"name": "route_list.is_active", "value": {
                    "bool_list": {"value_list": [True, False]}}},
                {"name": "route_list.route_type", "value": {
                    "str_list": {"value_list": ["1", "2"]}}},
            ],
        }],
        "stretches": [],
        "sessions": [],
        "atlas": {
            "subnet": {subnet},
            "router": {vpc},
            "route": {table},
            "l2gw": set(),
            "bgp": set(),
        },
        "switches": {"network_" + subnet},
        "router_map": {"router_" + vpc: {"192.168.1.0/24"}},
        "sb_names": {"network_" + subnet, "router_" + vpc},
        "nb_extra": "",
        "sb_extra": "",
        "lrp_names": {port: "lrp-ext_gw_port_" + gw},
        "rc_by_name": {
            "lrp-ext_gw_port_" + gw: (node, node),
            "lrp-transit-switch_44444444-4444-4444-8444-444444444444_router_" + vpc: (
                node, node),
        },
        "sb_gateway": {"ext_gw_port_" + gw: node},
        "sb_redirect": {
            "cr-lrp-transit-switch_44444444-4444-4444-8444-444444444444_router_" + vpc:
                "55555555-5555-4555-8555-555555555555",
        },
        "chassis_names": {"55555555-5555-4555-8555-555555555555": node},
        "scaleout": {vpc: [port]},
        "cfg_rows": [{
            "uuid": "33333333-3333-4333-8333-333333333333",
            "nb_cfg": 7, "sb_cfg": 7, "hv_cfg": 7,
        }],
        "chassis_rows": [{"uuid": chassis, "name": "h1", "nb_cfg": 7}],
        "learned": [{
            "route_uuid": "66666666-6666-4666-8666-666666666666",
            "prefix": "192.0.2.1/32",
            "nexthop": "169.254.3.2",
            "origin": "loadbalancer",
            "ic_route": learned,
        }],
        "ic_prefixes": {learned: "192.0.2.1/32"},
        "route_owners": {
            "66666666-6666-4666-8666-666666666666": "router_" + vpc,
        },
        "vpc_names": {vpc: "vpc-1"},
        "tap_hosts": [("host-1", "10.0.0.1")],
        "taps": [],
    }
    return data, subnet, vpc, node, learned, chassis


def self_test():
    import io
    data, subnet, vpc, node, learned, chassis = _sample()
    buf = io.StringIO()
    if run_checks(data, buf):
        raise SystemExit("clean sample failed:\n%s" % buf.getvalue())
    clean = buf.getvalue()
    for token in ("vpc-1", "192.0.2.1/32", "169.254.3.2", learned, "router_" + vpc):
        if token not in clean:
            raise SystemExit("learned route detail missing %s:\n%s" % (token, clean))
    isolated, iso_subnet, _vpc, _node, _learned, _chassis = _sample()
    isolated["errors"] = {
        "nb_switch": "ovn-nbctl Logical_Switch failed",
        "tap": "AHV Gateway cert missing",
    }
    isolated["switches"] = set()
    buf = io.StringIO()
    if run_checks(isolated, buf) < 2:
        raise SystemExit("a failed fetch should count for that check only:\n%s" % buf.getvalue())
    isolated_text = buf.getvalue()
    if iso_subnet in isolated_text:
        raise SystemExit("switch fetch failure became a per-subnet miss:\n%s" % isolated_text)
    if "Logical_Switch failed" not in isolated_text or "AHV Gateway cert missing" not in isolated_text:
        raise SystemExit("failed checks were not reported:\n%s" % isolated_text)
    if "FVN router: idf=1 atlas=1 missing=0" not in isolated_text:
        raise SystemExit("router check was affected by the switch failure:\n%s" % isolated_text)
    if "192.0.2.1/32" not in isolated_text:
        raise SystemExit("learned routes were dropped after the switch failure:\n%s" % isolated_text)
    saved = _scan_host_ok

    def boom(item, timeout):
        raise RuntimeError("gateway timeout")

    globals()["_scan_host_ok"] = boom
    try:
        name, ip, count, rows = _scan_host(("flashfire02-3", "10.116.29.174"), 1)
    finally:
        globals()["_scan_host_ok"] = saved
    if count != 0 or not rows or "gateway timeout" not in rows[0]["detail"]:
        raise SystemExit("one host failure was not contained: %s" % (rows,))
    data, _subnet, _vpc, _node, _learned, _chassis = _sample()
    data["ic_rows"] = [{
        "ic_route": "77777777-7777-4777-8777-777777777777",
        "prefix": "172.31.30.1/27",
        "nexthop": "169.254.3.1",
        "origin": "connected",
    }]
    buf = io.StringIO()
    if run_checks(data, buf) != 1 or "172.31.30.1/27" not in buf.getvalue():
        raise SystemExit("uninstalled IC route was not a miss:\n%s" % buf.getvalue())
    data["switches"] = set()
    data["sb_names"] = {"router_" + vpc}
    data["router_map"] = {"router_" + vpc: set()}
    buf = io.StringIO()
    missing = run_checks(data, buf)
    text = buf.getvalue()
    if missing < 3 or subnet not in text or "192.168.1.0/24" not in text:
        raise SystemExit("expected subnet nb/sb and route misses:\n%s" % text)
    if "10.0.0.0/8" in text:
        raise SystemExit("inactive prefix was required:\n%s" % text)
    data, _subnet, vpc, node, learned, chassis = _sample()
    lrp = "lrp-ext_gw_port_" + next(iter(data["lrp_names"].values())).split("lrp-ext_gw_port_")[1]
    data["rc_by_name"][lrp] = (node, "99999999-9999-4999-8999-999999999999")
    data["sb_gateway"] = {}
    data["cfg_rows"][0]["sb_cfg"] = 6
    data["chassis_rows"][0]["nb_cfg"] = 5
    data["ic_prefixes"] = {}
    data["taps"] = [{
        "host": "flashfire02-3",
        "ip": "10.116.29.174",
        "tap": "tap291",
        "bridge": "brAtlas",
        "state": "DOWN",
        "mac": "fe:6b:8d:59:1b:81",
        "detail": "no VM NIC has tapname tap291",
    }]
    buf = io.StringIO()
    missing = run_checks(data, buf)
    text = buf.getvalue()
    for token in (node, learned, "sb_cfg=6", chassis, "tap291", "brAtlas"):
        if token not in text:
            raise SystemExit("expected rc/cfg/learned detail %s:\n%s" % (token, text))
    if missing < 4:
        raise SystemExit("expected rc, sb placement, cfg, and learned misses:\n%s" % text)
    print("self-test ok missing=%s" % missing)


def main(argv):
    parser = argparse.ArgumentParser(description=(
        "Validate FVN subnets, routers, static routes, L2 gateway, and BGP."))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr)
    try:
        data = collect(args.timeout)
    except (Exception, SystemExit) as err:
        sys.stdout.write(
            "FVN collect: missing=1 error=%s\n" % str(err).split("\n", 1)[0][:240])
        return 1
    missing = run_checks(data, sys.stdout)
    sys.stdout.flush()
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
