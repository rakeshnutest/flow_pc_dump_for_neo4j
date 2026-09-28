#!/usr/bin/env python3
"""Fill switch, subnet, router, and L2 gateway tables from NB and SB.

Each row keeps the northbound object and the southbound binding together.
Called from ingest.py. --only-path-tables loads just these four tables and
does not drop the rest of the bundle.
"""
from __future__ import annotations

import os
import sys

PATH_TABLES = ("ovn_switch", "ovn_subnet", "ovn_router", "ovn_route", "ovn_l2gw")
PATH_NB = (
    "DHCP_Options",
    "Logical_Switch",
    "Logical_Switch_Port",
    "Logical_Router",
    "Logical_Router_Port",
    "Logical_Router_Static_Route",
    "NAT",
)
PATH_SB = (
    "Chassis",
    "Encap",
    "Datapath_Binding",
    "Port_Binding",
)

# How each column is used. The verdict JSON copies this list.
CATALOG = [
    {
        "table": "flow_ovn.ovn_switch",
        "grain": "one logical switch",
        "join": "ovn_subnet.nb_ls_uuid = ovn_switch.ls_uuid",
        "columns": [
            ["nb_name", "NB", "Display name of the logical switch"],
            ["nb_external_ids", "NB", "NB external_ids, key/value"],
            ["nb_other_config", "NB", "NB other_config, including requested-tnl-key and interconn-ts"],
            ["nb_requested_tnl_key", "NB", "Tunnel key requested on the switch"],
            ["nb_interconn", "NB", "1 when the switch is a transit / interconnect switch"],
            ["sb_datapath_uuid", "SB", "Datapath_Binding uuid for this switch"],
            ["sb_tunnel_key", "SB", "Datapath tunnel key programmed in SB"],
            ["sb_egress_tunnel_key", "SB", "SB egress tunnel key"],
            ["sb_name", "SB", "Name stored on the SB datapath"],
        ],
    },
    {
        "table": "flow_ovn.ovn_subnet",
        "grain": "one Atlas subnet, from DHCP_Options",
        "join": "flow_policy.vm_nic.subnet_uuid = ovn_subnet.subnet_uuid",
        "columns": [
            ["subnet_uuid", "NB", "Atlas subnet uuid from DHCP external_ids subnet_id"],
            ["nb_cidr", "NB", "Subnet prefix"],
            ["nb_gateway_ip", "NB", "DHCP router option, the subnet gateway IP"],
            ["nb_gateway_mac", "NB", "DHCP server_mac, the subnet gateway MAC"],
            ["nb_mtu", "NB", "DHCP mtu option"],
            ["nb_dhcp_uuid", "NB", "DHCP_Options row"],
            ["nb_ls_uuid", "NB", "Logical switch whose ports use this DHCP option"],
            ["nb_ls_name", "NB", "That switch's name"],
            ["sb_datapath_uuid", "SB", "SB datapath of nb_ls_uuid"],
            ["sb_tunnel_key", "SB", "SB datapath tunnel key of the switch"],
            ["sb_egress_tunnel_key", "SB", "SB egress tunnel key of the switch"],
        ],
    },
    {
        "table": "flow_ovn.ovn_router",
        "grain": "one logical router, ports nested",
        "join": "ports.nb_ls_uuid = ovn_switch.ls_uuid",
        "columns": [
            ["nb_name", "NB", "Logical router name"],
            ["nb_enabled", "NB", "1 when the router is enabled"],
            ["nb_external_ids", "NB", "NB external_ids, including neutron:router_name"],
            ["nb_has_nat", "NB", "1 when the router has NAT rows"],
            ["nb_gw_external_ips", "NB", "NAT external_ip values. Set when traffic is NATed outside"],
            ["nb_gw_logical_ips", "NB", "NAT logical_ip values"],
            ["sb_datapath_uuid", "SB", "Datapath_Binding uuid for this router"],
            ["sb_tunnel_key", "SB", "SB datapath tunnel key"],
            ["sb_egress_tunnel_key", "SB", "SB egress tunnel key"],
            ["ports.nb_name", "NB", "Router port name"],
            ["ports.nb_mac", "NB", "Router port MAC"],
            ["ports.nb_networks", "NB", "Router port CIDRs"],
            ["ports.nb_ls_uuid", "NB", "Switch this router port connects"],
            ["ports.nb_lsp_name", "NB", "Router-type switch port that points at this router port"],
            ["ports.nb_is_ext_gw", "NB", "1 on the external gateway port"],
            ["ports.sb_chassis_uuid", "SB", "Chassis that binds this router port"],
            ["ports.sb_tunnel_key", "SB", "SB port tunnel key, the port number"],
            ["ports.sb_up", "SB", "1 when the SB binding is up"],
        ],
    },
    {
        "table": "flow_ovn.ovn_route",
        "grain": "one connected or static route on a logical router",
        "join": "ovn_route.lr_uuid = ovn_router.lr_uuid",
        "columns": [
            ["kind", "NB", "connected, from a router port network, or static"],
            ["nb_prefix", "NB", "Destination prefix"],
            ["nb_nexthop", "NB", "Static nexthop. Empty on a connected route"],
            ["nb_policy", "NB", "dst-ip or src-ip"],
            ["nb_output_port", "NB", "Router port the route uses"],
            ["nb_route_table", "NB", "NB route_table name. Empty is the main table"],
            ["sb_datapath_uuid", "SB", "SB datapath of the router. This dump has no SB Route table"],
            ["sb_tunnel_key", "SB", "SB tunnel key of that router datapath"],
            ["sb_output_tunnel_key", "SB", "SB tunnel key of the output port binding"],
            ["sb_chassis_uuid", "SB", "Chassis of the output port binding"],
        ],
    },
    {
        "table": "flow_ovn.ovn_l2gw",
        "grain": "one localnet, l2gateway, or geneve stretch binding",
        "join": "ovn_l2gw.ls_uuid = ovn_switch.ls_uuid",
        "columns": [
            ["kind", "NB", "localnet, l2gateway, or geneve"],
            ["nb_name", "NB", "Switch port name. Empty on a geneve stretch row"],
            ["nb_type", "NB", "Logical switch port type"],
            ["nb_network_name", "NB", "options:network_name on a localnet / l2gateway port"],
            ["nb_vlan", "NB", "VLAN tag on the port"],
            ["nb_mac", "NB", "Port MAC"],
            ["nb_ls_name", "NB", "Logical switch name. Filled for localnet, l2gateway, and geneve"],
            ["sb_datapath_uuid", "SB", "Datapath_Binding for this port, or the switch datapath for geneve"],
            ["sb_chassis_uuid", "SB", "Chassis that hosts the binding. Empty when SB has no chassis, as on localnet"],
            ["sb_hostname", "SB", "Chassis hostname"],
            ["sb_encap_type", "SB", "Geneve or other encap type"],
            ["sb_encap_ip", "SB", "Encap IP of that chassis"],
            ["sb_tunnel_key", "SB", "Port tunnel key for a gateway port, else the switch tunnel key"],
            ["sb_up", "SB", "1 when the binding is up"],
            ["sb_vif_count", "SB", "VIF count on this chassis for kind=geneve"],
        ],
    },
]


def _ovn():
    import ingest as ovn
    return ovn


def _pairs(mapping) -> list:
    if not isinstance(mapping, dict):
        return []
    return [[str(key), str(value)] for key, value in sorted(mapping.items()) if str(value)]


def _ext_port(name: str, networks: list) -> int:
    if "ext_gw" in name or name.startswith("lrp-ext_") or name.endswith("_ext") or "localnet" in name:
        return 1
    for net in networks:
        if str(net).startswith("10.") and "/18" in str(net):
            return 1
    return 0


def _subnet_uuid(external_ids) -> str:
    ovn = _ovn()
    if not isinstance(external_ids, dict):
        return ovn.ZERO
    raw = external_ids.get("subnet_id") or external_ids.get("subnet-id") or ""
    raw = ovn.as_str(raw)
    if raw.startswith("subnet_"):
        raw = raw[len("subnet_"):]
    return ovn.as_uuid(raw)


def _index_sb(sb: dict):
    ovn = _ovn()
    by_nb = {}
    dp_to_ls = {}
    for row in sb.get("Datapath_Binding", []):
        ext = ovn.as_map(row.get("external_ids"))
        ls = ext.get("logical-switch") or ext.get("logical_switch") or ""
        lr = ext.get("logical-router") or ext.get("logical_router") or ""
        nb = ls if ovn.is_uuid(str(ls)) else lr if ovn.is_uuid(str(lr)) else ""
        if nb:
            by_nb[ovn.as_uuid(nb)] = row
        if ovn.is_uuid(str(ls)):
            dp_to_ls[ovn.as_uuid(row.get("_uuid"))] = ovn.as_uuid(ls)
    pb_by_name = {}
    for row in sb.get("Port_Binding", []):
        name = ovn.as_str(row.get("logical_port"))
        if not name:
            continue
        prev = pb_by_name.get(name)
        if prev is None or (
            ovn.as_uuid(prev.get("chassis")) == ovn.ZERO
            and ovn.as_uuid(row.get("chassis")) != ovn.ZERO
        ):
            pb_by_name[name] = row
    hostname = {}
    for row in sb.get("Chassis", []):
        hostname[ovn.as_uuid(row.get("_uuid"))] = ovn.as_str(row.get("hostname"))
    encap = {}
    for row in sb.get("Encap", []):
        ch = ovn.as_str(row.get("chassis_name"))
        # chassis uuid is filled later from Chassis.encaps; fall back to name via a second pass
        encap.setdefault(ch, {
            "encap_type": ovn.as_str(row.get("type")),
            "ip": ovn.as_str(row.get("ip")),
        })
    encap_by_uuid = {}
    for row in sb.get("Chassis", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        chosen = encap.get(ovn.as_str(row.get("name"))) or encap.get(hostname.get(uid, "")) or {}
        encap_by_uuid[uid] = chosen
    return by_nb, dp_to_ls, pb_by_name, hostname, encap_by_uuid


def _sb_of(by_nb, nb_uuid: str) -> dict:
    ovn = _ovn()
    row = by_nb.get(nb_uuid) or {}
    ext = ovn.as_map(row.get("external_ids"))
    return {
        "sb_datapath_uuid": ovn.as_uuid(row.get("_uuid")) if row else ovn.ZERO,
        "sb_tunnel_key": ovn.as_int(row.get("tunnel_key"), 0) if row else 0,
        "sb_egress_tunnel_key": ovn.as_int(row.get("egress_tunnel_key"), 0) if row else 0,
        "sb_name": ovn.as_str(ext.get("name")) if row else "",
    }


def build_path_tables(nb: dict, sb: dict) -> dict:
    ovn = _ovn()
    ts = ovn.now_iso()
    by_nb, dp_to_ls, pb_by_name, hostname, encap_by_uuid = _index_sb(sb)
    zero = ovn.ZERO

    lsp_to_ls = {}
    ls_name = {}
    switches = []
    for row in nb.get("Logical_Switch", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        name = ovn.as_str(row.get("name"))
        other = ovn.as_map(row.get("other_config"))
        ext = ovn.as_map(row.get("external_ids"))
        ls_name[uid] = name
        for port in ovn.as_str_list(row.get("ports")):
            if ovn.is_uuid(port):
                lsp_to_ls[port] = uid
        requested = ovn.as_int(other.get("requested-tnl-key") or other.get("requested_tnl_key"), 0)
        interconn = 1 if (
            "interconn-ts" in other or name.startswith("transit-switch") or name.startswith("gw-scale-out")
        ) else 0
        item = {
            "ls_uuid": uid,
            "nb_name": name,
            "nb_external_ids": _pairs(ext),
            "nb_other_config": _pairs(other),
            "nb_requested_tnl_key": requested,
            "nb_interconn": interconn,
            "updated_at": ts,
        }
        item.update(_sb_of(by_nb, uid))
        switches.append(item)

    lsp_by_uuid = {}
    dhcp_ls = {}
    dhcp_ls_router = {}
    for row in nb.get("Logical_Switch_Port", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        lsp_by_uuid[uid] = row
        dhcp = ovn.as_uuid(row.get("dhcpv4_options"))
        ls = lsp_to_ls.get(uid, zero)
        if dhcp == zero or ls == zero:
            continue
        if ovn.as_str(row.get("type")) == "router":
            dhcp_ls_router.setdefault(dhcp, ls)
        else:
            dhcp_ls[dhcp] = ls

    switch_by_name = {item["nb_name"]: item for item in switches if item.get("nb_name")}
    switch_by_uuid = {item["ls_uuid"]: item for item in switches}
    subnets = {}
    for row in nb.get("DHCP_Options", []):
        sid = _subnet_uuid(row.get("external_ids"))
        if sid == zero:
            continue
        opts = ovn.as_map(row.get("options"))
        dhcp = ovn.as_uuid(row.get("_uuid"))
        ls = dhcp_ls.get(dhcp) or dhcp_ls_router.get(dhcp, zero)
        if ls == zero:
            named = switch_by_name.get("network_%s" % sid)
            if named:
                ls = named["ls_uuid"]
        sb_ls = _sb_of(by_nb, ls) if ls != zero else {
            "sb_datapath_uuid": zero, "sb_tunnel_key": 0, "sb_egress_tunnel_key": 0, "sb_name": "",
        }
        subnets[sid] = {
            "subnet_uuid": sid,
            "nb_cidr": ovn.as_str(row.get("cidr")),
            "nb_gateway_ip": ovn.as_str(opts.get("router")),
            "nb_gateway_mac": ovn.as_str(opts.get("server_mac")),
            "nb_mtu": ovn.as_int(opts.get("mtu"), 0),
            "nb_dhcp_uuid": dhcp,
            "nb_ls_uuid": ls,
            "nb_ls_name": ls_name.get(ls, ""),
            "sb_datapath_uuid": sb_ls["sb_datapath_uuid"],
            "sb_tunnel_key": sb_ls["sb_tunnel_key"],
            "sb_egress_tunnel_key": sb_ls["sb_egress_tunnel_key"],
            "updated_at": ts,
        }

    lrp_to_lr = {}
    nat_to_lr = {}
    for row in nb.get("Logical_Router", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        for port in ovn.as_str_list(row.get("ports")):
            if ovn.is_uuid(port):
                lrp_to_lr[port] = uid
        for nat in ovn.as_str_list(row.get("nat")):
            if ovn.is_uuid(nat):
                nat_to_lr[nat] = uid

    router_lsp = {}
    for uid, row in lsp_by_uuid.items():
        if ovn.as_str(row.get("type")) != "router":
            continue
        opts = ovn.as_map(row.get("options"))
        lrp_name = opts.get("router-port") or opts.get("router_port") or ""
        if lrp_name:
            router_lsp[lrp_name] = row

    gw_ext = {}
    gw_log = {}
    for row in nb.get("NAT", []):
        lr = nat_to_lr.get(ovn.as_uuid(row.get("_uuid")), zero)
        if lr == zero:
            continue
        ext_ip = ovn.as_str(row.get("external_ip"))
        log_ip = ovn.as_str(row.get("logical_ip"))
        if ext_ip:
            gw_ext.setdefault(lr, [])
            if ext_ip not in gw_ext[lr]:
                gw_ext[lr].append(ext_ip)
        if log_ip:
            gw_log.setdefault(lr, [])
            if log_ip not in gw_log[lr]:
                gw_log[lr].append(log_ip)

    ports_by_lr = {}
    for row in nb.get("Logical_Router_Port", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        name = ovn.as_str(row.get("name"))
        networks = ovn.as_str_list(row.get("networks"))
        lsp = router_lsp.get(name, {})
        lsp_uuid = ovn.as_uuid(lsp.get("_uuid")) if lsp else zero
        ls = lsp_to_ls.get(lsp_uuid, zero)
        pb = pb_by_name.get(name) or pb_by_name.get(ovn.as_str(lsp.get("name"))) or {}
        ports_by_lr.setdefault(lrp_to_lr.get(uid, zero), []).append({
            "lrp_uuid": uid,
            "nb_name": name,
            "nb_mac": ovn.as_str(row.get("mac")).lower().strip('"'),
            "nb_networks": networks,
            "nb_peer": ovn.as_str(row.get("peer")),
            "nb_is_ext_gw": _ext_port(name, networks),
            "nb_ha_chassis_group": ovn.as_uuid(row.get("ha_chassis_group")),
            "nb_ls_uuid": ls,
            "nb_lsp_uuid": lsp_uuid,
            "nb_lsp_name": ovn.as_str(lsp.get("name")),
            "sb_chassis_uuid": ovn.as_uuid(pb.get("chassis")),
            "sb_tunnel_key": ovn.as_int(pb.get("tunnel_key"), 0),
            "sb_up": ovn.as_bool(pb.get("up"), 0),
        })

    routers = []
    for row in nb.get("Logical_Router", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        item = {
            "lr_uuid": uid,
            "nb_name": ovn.as_str(row.get("name")),
            "nb_enabled": ovn.as_bool(row.get("enabled"), 1),
            "nb_external_ids": _pairs(ovn.as_map(row.get("external_ids"))),
            "nb_has_nat": 1 if ovn.as_str_list(row.get("nat")) else 0,
            "nb_gw_external_ips": gw_ext.get(uid, []),
            "nb_gw_logical_ips": gw_log.get(uid, []),
            "ports": ports_by_lr.get(uid, []),
            "updated_at": ts,
        }
        sb_row = _sb_of(by_nb, uid)
        item["sb_datapath_uuid"] = sb_row["sb_datapath_uuid"]
        item["sb_tunnel_key"] = sb_row["sb_tunnel_key"]
        item["sb_egress_tunnel_key"] = sb_row["sb_egress_tunnel_key"]
        routers.append(item)

    l2_rows = []
    lsp_name_to_ls = {}
    for uid, row in lsp_by_uuid.items():
        name = ovn.as_str(row.get("name"))
        lsp_name_to_ls[name] = lsp_to_ls.get(uid, zero)
        ptype = ovn.as_str(row.get("type"))
        if ptype not in ("localnet", "l2gateway"):
            continue
        opts = ovn.as_map(row.get("options"))
        pb = pb_by_name.get(name, {})
        ch = ovn.as_uuid(pb.get("chassis"))
        enc = encap_by_uuid.get(ch, {})
        macs = ovn.as_str_list(row.get("addresses"))
        ls_uuid = lsp_to_ls.get(uid, zero)
        sw = switch_by_uuid.get(ls_uuid, {})
        l2_rows.append({
            "kind": ptype,
            "ls_uuid": ls_uuid,
            "lsp_uuid": uid,
            "nb_name": name,
            "nb_type": ptype,
            "nb_network_name": opts.get("network_name") or opts.get("network-name") or "",
            "nb_vlan": ovn.as_int(row.get("tag"), 0),
            "nb_mac": (macs[0].split()[0].lower() if macs else ""),
            "nb_ls_name": sw.get("nb_name", ""),
            "sb_datapath_uuid": ovn.as_uuid(pb.get("datapath")) if pb else sw.get("sb_datapath_uuid", zero),
            "sb_chassis_uuid": ch,
            "sb_hostname": hostname.get(ch, ""),
            "sb_encap_type": enc.get("encap_type", ""),
            "sb_encap_ip": enc.get("ip", ""),
            "sb_tunnel_key": ovn.as_int(pb.get("tunnel_key"), 0),
            "sb_up": ovn.as_bool(pb.get("up"), 0),
            "sb_vif_count": 0,
            "updated_at": ts,
        })

    stretch = {}
    for row in sb.get("Port_Binding", []):
        if ovn.as_str(row.get("type")) not in ("", "vif"):
            continue
        ch = ovn.as_uuid(row.get("chassis"))
        if ch == zero:
            continue
        ls = dp_to_ls.get(ovn.as_uuid(row.get("datapath")), zero)
        if ls == zero:
            ls = lsp_name_to_ls.get(ovn.as_str(row.get("logical_port")), zero)
        if ls == zero:
            continue
        key = (ls, ch)
        stretch[key] = stretch.get(key, 0) + 1
    for (ls, ch), count in stretch.items():
        enc = encap_by_uuid.get(ch, {})
        sb_ls = _sb_of(by_nb, ls)
        sw = switch_by_uuid.get(ls, {})
        l2_rows.append({
            "kind": "geneve",
            "ls_uuid": ls,
            "lsp_uuid": zero,
            "nb_name": "",
            "nb_type": "geneve",
            "nb_network_name": "",
            "nb_vlan": 0,
            "nb_mac": "",
            "nb_ls_name": sw.get("nb_name", ""),
            "sb_datapath_uuid": sb_ls["sb_datapath_uuid"],
            "sb_chassis_uuid": ch,
            "sb_hostname": hostname.get(ch, ""),
            "sb_encap_type": enc.get("encap_type", ""),
            "sb_encap_ip": enc.get("ip", ""),
            "sb_tunnel_key": sb_ls["sb_tunnel_key"],
            "sb_up": 1,
            "sb_vif_count": count,
            "updated_at": ts,
        })

    static_by_uuid = {}
    for row in nb.get("Logical_Router_Static_Route", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        if uid == zero:
            continue
        output = ovn.as_str_list(row.get("output_port"))
        static_by_uuid[uid] = {
            "route_uuid": uid,
            "nb_prefix": ovn.as_str(row.get("ip_prefix")),
            "nb_nexthop": ovn.as_str(row.get("nexthop")),
            "nb_policy": ovn.as_str(row.get("policy")) or "dst-ip",
            "nb_output_port": output[0] if output else "",
            "nb_route_table": ovn.as_str(row.get("route_table")),
        }
    port_by_name = {}
    for ports in ports_by_lr.values():
        for port in ports:
            if port.get("nb_name"):
                port_by_name[port["nb_name"]] = port
    routes = []
    for uid, ports in ports_by_lr.items():
        if uid == zero:
            continue
        sb_row = _sb_of(by_nb, uid)
        for port in ports:
            for network in port.get("nb_networks") or []:
                if not network:
                    continue
                routes.append({
                    "lr_uuid": uid,
                    "route_uuid": port["lrp_uuid"],
                    "kind": "connected",
                    "nb_prefix": network,
                    "nb_nexthop": "",
                    "nb_policy": "dst-ip",
                    "nb_output_port": port.get("nb_name") or "",
                    "nb_route_table": "",
                    "sb_datapath_uuid": sb_row["sb_datapath_uuid"],
                    "sb_tunnel_key": sb_row["sb_tunnel_key"],
                    "sb_output_tunnel_key": port.get("sb_tunnel_key") or 0,
                    "sb_chassis_uuid": port.get("sb_chassis_uuid") or zero,
                    "updated_at": ts,
                })
    for row in nb.get("Logical_Router", []):
        uid = ovn.as_uuid(row.get("_uuid"))
        sb_row = _sb_of(by_nb, uid)
        for sid in ovn.as_str_list(row.get("static_routes")):
            rec = static_by_uuid.get(sid)
            if not rec:
                continue
            port = port_by_name.get(rec["nb_output_port"], {})
            routes.append({
                "lr_uuid": uid,
                "route_uuid": rec["route_uuid"],
                "kind": "static",
                "nb_prefix": rec["nb_prefix"],
                "nb_nexthop": rec["nb_nexthop"],
                "nb_policy": rec["nb_policy"],
                "nb_output_port": rec["nb_output_port"],
                "nb_route_table": rec["nb_route_table"],
                "sb_datapath_uuid": sb_row["sb_datapath_uuid"],
                "sb_tunnel_key": sb_row["sb_tunnel_key"],
                "sb_output_tunnel_key": port.get("sb_tunnel_key") or 0,
                "sb_chassis_uuid": port.get("sb_chassis_uuid") or zero,
                "updated_at": ts,
            })

    return {
        "ovn_switch": switches,
        "ovn_subnet": list(subnets.values()),
        "ovn_router": routers,
        "ovn_route": routes,
        "ovn_l2gw": l2_rows,
    }


def ingest_only(nb_path: str, sb_path: str) -> int:
    ovn = _ovn()
    _add_columns(ovn)
    print(f"parsing NB {nb_path}")
    nb = ovn.parse_dump(nb_path, PATH_NB)
    for name, rows in sorted(nb.items()):
        print(f"  NB {name}: {len(rows)}")
    print(f"parsing SB {sb_path}")
    sb = ovn.parse_dump(sb_path, PATH_SB)
    for name, rows in sorted(sb.items()):
        print(f"  SB {name}: {len(rows)}")
    bid = int(ovn.LOG_BUNDLE_ID)
    for table in PATH_TABLES:
        try:
            ovn.ch_run(["--query", f"ALTER TABLE flow_ovn.{table} DROP PARTITION {bid}"])
            print(f"  dropped partition {bid} {table}")
        except RuntimeError as exc:
            text = str(exc)
            if any(s in text for s in ("doesn't exist", "does not exist", "Unknown table", "No such partition")):
                print(f"  no partition yet {table}")
            else:
                raise
    built = build_path_tables(nb, sb)
    for table, rows in built.items():
        ovn.insert_rows(table, rows)
    print("path tables done")
    return 0


def main() -> int:
    ovn = _ovn()
    import argparse
    ap = argparse.ArgumentParser(description="Load switch, subnet, router, and L2 gateway tables")
    ap.add_argument("--dump_dir", required=True)
    ap.add_argument("--log_bundle_id", type=int, required=True)
    args = ap.parse_args()
    ovn.LOG_BUNDLE_ID = args.log_bundle_id
    nb_path, sb_path, _ahv = ovn.find_dump(args.dump_dir)
    ovn.apply_schema()
    _add_columns(ovn)
    return ingest_only(nb_path, sb_path)


def _add_columns(ovn) -> None:
    statements = [
        "ALTER TABLE flow_ovn.ovn_l2gw ADD COLUMN IF NOT EXISTS nb_ls_name String DEFAULT ''",
        "ALTER TABLE flow_ovn.ovn_l2gw ADD COLUMN IF NOT EXISTS sb_datapath_uuid UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000')",
    ]
    for sql in statements:
        try:
            ovn.ch_run(["--query", sql])
        except RuntimeError as exc:
            if "does not exist" in str(exc) or "Unknown table" in str(exc):
                continue
            raise


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
