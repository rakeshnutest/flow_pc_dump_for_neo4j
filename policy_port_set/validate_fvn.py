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
uuid is the Route row in ovn-ic-sb, and the ip_prefix must match.

An empty BGP or L2 gateway table is a pass. Stdout is the summary plus one
JSON object per miss. Exit 0 when nothing is missing.

  python3 validate_fvn.py
  python3 validate_fvn.py --self-test
"""

from __future__ import print_function

import argparse
import json
import logging
import os
import re
import subprocess
import sys

LOG = logging.getLogger("validate_fvn")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
RC_RE = re.compile(r"redirect-chassis=([0-9a-fA-F-]{36})")
HOST_RE = re.compile(r"hosting-chassis=([0-9a-fA-F-]{36})")
L3_RE = re.compile(r"l3gateway-chassis=([0-9a-fA-F-]{36})")
LEARN_RE = re.compile(r"ic-learned-route=([0-9a-fA-F-]{36})")
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


def _learned(text):
    """(prefix, ic route uuid) for routes OVN learned rather than configured."""
    found = []
    for line in (text or "").splitlines():
        match = LEARN_RE.search(line)
        if not match:
            continue
        prefix = line.split(",", 1)[0].strip().strip('"')
        found.append((prefix, match.group(1).lower()))
    return found


def _ic_prefixes(text):
    found = {}
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        uid, prefix = line.split(",", 1)
        found[uid.strip().lower()] = prefix.strip().strip('"')
    return found


def check_learned(learned, ic_prefixes):
    """Each ic-learned-route uuid is that prefix in the IC southbound DB."""
    misses = []
    for prefix, uid in learned:
        advertised = ic_prefixes.get(uid)
        if advertised is None:
            misses.append(_miss(
                "learned", uid, prefix, "ic", prefix,
                "ic-learned-route %s is not an IC Route" % uid))
            continue
        if advertised != prefix:
            misses.append(_miss(
                "learned", uid, prefix, "ic", advertised,
                "IC prefix %s does not match learned prefix %s" % (
                    advertised, prefix)))
    return misses


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


def write_report(label, idf_count, atlas_count, misses, handle):
    handle.write(
        "FVN %s: idf=%s atlas=%s missing=%s\n" % (
            label, idf_count, atlas_count, len(misses)))
    for rec in misses:
        handle.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
    return len(misses)


def collect(timeout):
    subnets = idf_entities("atlas_subnet", timeout)
    routers = idf_entities("atlas_virtual_network", timeout)
    routes = idf_entities("atlas_route_table", timeout)
    stretches = idf_entities("layer2_stretch", timeout)
    if not stretches:
        stretches = idf_entities("atlas_layer2_stretch", timeout)
    sessions = idf_entities("bgp_session", timeout)
    if not sessions:
        sessions = idf_entities("atlas_bgp_session", timeout)
    atlas = {
        "subnet": _uuids_from(atlas_rows("subnet.list", timeout), "uuid"),
        "router": _uuids_from(atlas_rows("network.list", timeout), "uuid"),
        "route": _uuids_from(atlas_rows("route_table.list", timeout), "uuid"),
        "l2gw": _uuids_from(atlas_rows("layer2_stretch.list", timeout), "uuid"),
        "bgp": _uuids_from(atlas_rows("bgp_session.list", timeout), "uuid"),
    }
    switches = set(name.lower() for name in _names(ovn_csv(
        "nb", "name", "Logical_Switch", timeout)))
    prefix_text = ovn_csv(
        "nb", "ip_prefix,external_ids", "Logical_Router_Static_Route", timeout)
    # _route_maps still keys prefixes by route uuid. Fetch that pair too.
    route_ids = ovn_csv(
        "nb", "_uuid,ip_prefix", "Logical_Router_Static_Route", timeout)
    router_text = ovn_csv("nb", "name,static_routes", "Logical_Router", timeout)
    router_map = _route_maps(router_text, route_ids)
    scaleout = _scaleout_ports(ovn_csv("nb", "name,ports", "Logical_Router", timeout))
    lrp_names = _lrp_names(ovn_csv("nb", "_uuid,name", "Logical_Router_Port", timeout))
    rc_by_name = _rc_by_name(ovn_csv(
        "nb", "name,options,status", "Logical_Router_Port", timeout))
    sb_text = ovn_csv("sb", "external_ids", "Datapath_Binding", timeout)
    sb_names = _sb_names(sb_text)
    binding_text = ovn_csv(
        "sb", "logical_port,chassis,options", "Port_Binding", timeout)
    sb_gateway = _sb_gateway(binding_text)
    sb_redirect = _sb_redirect(binding_text)
    chassis_names = _chassis_names(ovn_csv("sb", "_uuid,name", "Chassis", timeout))
    cfg_rows = _cfg_rows(ovn_csv(
        "nb", "_uuid,nb_cfg,sb_cfg,hv_cfg", "NB_Global", timeout))
    chassis_rows = _chassis_rows(ovn_csv(
        "sb", "_uuid,name,nb_cfg", "Chassis_Private", timeout))
    learned = _learned(prefix_text)
    ic_prefixes = _ic_prefixes(ovn_ic_csv("_uuid,ip_prefix", "Route", timeout))
    LOG.info(
        "rc ports=%s learned=%s ic=%s cfg=%s chassis=%s",
        len(rc_by_name), len(learned), len(ic_prefixes),
        len(cfg_rows), len(chassis_rows))
    nb_extra = ""
    sb_extra = sb_text
    if stretches or sessions:
        nb_extra = ovn_csv("nb", "name,external_ids", "Logical_Switch_Port", timeout)
        nb_extra += "\n" + router_text
        sb_extra += "\n" + ovn_csv(
            "sb", "logical_port,external_ids", "Port_Binding", timeout)
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
    }


def run_checks(data, handle):
    atlas = data["atlas"]
    total = 0
    total += write_report(
        "subnet", _count(data["subnets"]), len(atlas["subnet"]),
        check_subnets(data["subnets"], atlas["subnet"], data["switches"], data["sb_names"]),
        handle)
    total += write_report(
        "router", _count(data["routers"]), len(atlas["router"]),
        check_routers(data["routers"], atlas["router"], data["router_map"], data["sb_names"]),
        handle)
    total += write_report(
        "route", _count(data["routes"]), len(atlas["route"]),
        check_routes(data["routes"], atlas["route"], data["router_map"], data["sb_names"]),
        handle)
    total += write_report(
        "l2gw", _count(data["stretches"]), len(atlas["l2gw"]),
        check_named(
            "l2gw", data["stretches"], atlas["l2gw"], data["nb_extra"], data["sb_extra"],
            "Logical_Switch_Port", "Port_Binding"),
        handle)
    total += write_report(
        "bgp", _count(data["sessions"]), len(atlas["bgp"]),
        check_named(
            "bgp", data["sessions"], atlas["bgp"], data["nb_extra"], data["sb_extra"],
            "Logical_Router", "Datapath_Binding"),
        handle)
    rc_misses, rc_checked = check_rc(
        data["routers"], data["lrp_names"], data["rc_by_name"],
        data["sb_gateway"], data["scaleout"])
    transit_misses, transit_checked = check_transit(
        data["rc_by_name"], data["sb_redirect"], data["chassis_names"])
    rc_misses.extend(transit_misses)
    rc_checked += transit_checked
    total += write_report("rc", rc_checked, rc_checked, rc_misses, handle)
    cfg_misses = check_cfg(data["cfg_rows"], data["chassis_rows"])
    total += write_report(
        "cfg", len(data["cfg_rows"]), len(data["chassis_rows"]), cfg_misses, handle)
    learned_misses = check_learned(data["learned"], data["ic_prefixes"])
    total += write_report(
        "learned", len(data["learned"]), len(data["ic_prefixes"]),
        learned_misses, handle)
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
        "learned": [("192.0.2.1/32", learned)],
        "ic_prefixes": {learned: "192.0.2.1/32"},
    }
    return data, subnet, vpc, node, learned, chassis


def self_test():
    import io
    data, subnet, vpc, node, learned, chassis = _sample()
    buf = io.StringIO()
    if run_checks(data, buf):
        raise SystemExit("clean sample failed:\n%s" % buf.getvalue())
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
    buf = io.StringIO()
    missing = run_checks(data, buf)
    text = buf.getvalue()
    for token in (node, learned, "sb_cfg=6", chassis):
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
    data = collect(args.timeout)
    missing = run_checks(data, sys.stdout)
    sys.stdout.flush()
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
