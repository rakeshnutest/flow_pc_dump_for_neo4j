# Path tables

These four tables are loaded while the OVN dump is ingested. Each row holds the northbound object and the southbound binding. Analysis reads them. It does not parse the dump again.

Join for a VM NIC:

`flow_policy.vm_nic` → `ovn_subnet` → `ovn_switch` → `ovn_router.ports` → external gateway or the next switch.

`ovn_l2gw` hangs off the switch (`ls_uuid`) for localnet, l2gateway, and geneve stretch.

`ovn_route` is one connected or static route. Connected prefixes are the router port networks. Static prefixes are `Logical_Router_Static_Route`. This dump has no southbound Route table, so the SB columns are the router datapath and the output port binding.

Server: `127.0.0.1:19000`, database `flow_ovn`. Every table is `ReplacingMergeTree(updated_at)`, `PARTITION BY log_bundle_id`. A missing UUID is the zero UUID.

```text
python3 clickhouse_ovn/path_tables.py \
  --dump_dir /path/to/dump --log_bundle_id <id>
```

That command reloads only these four tables. A full `ingest.py` run fills them with the rest of `flow_ovn`.

## `ovn_switch`

One logical switch.

| Column | Side | Use |
|---|---|---|
| `ls_uuid` | NB | Identity. `ovn_subnet.nb_ls_uuid` and `ovn_l2gw.ls_uuid` join here |
| `nb_name` | NB | Name drawn on the path |
| `nb_external_ids` | NB | NB `external_ids` |
| `nb_other_config` | NB | NB `other_config` |
| `nb_requested_tnl_key` | NB | Tunnel key the switch asked for |
| `nb_interconn` | NB | 1 for a transit or scale-out switch |
| `sb_datapath_uuid` | SB | `Datapath_Binding` uuid |
| `sb_tunnel_key` | SB | Tunnel key programmed in southbound |
| `sb_egress_tunnel_key` | SB | Southbound egress tunnel key |
| `sb_name` | SB | Name on the southbound datapath |

## `ovn_subnet`

One Atlas subnet, taken from `DHCP_Options`.

| Column | Side | Use |
|---|---|---|
| `subnet_uuid` | NB | `flow_policy.vm_nic.subnet_uuid` |
| `nb_cidr` | NB | Prefix |
| `nb_gateway_ip` | NB | DHCP `router` option |
| `nb_gateway_mac` | NB | DHCP `server_mac` |
| `nb_mtu` | NB | DHCP `mtu` |
| `nb_dhcp_uuid` | NB | `DHCP_Options` row |
| `nb_ls_uuid` | NB | Switch whose non-router ports use this DHCP option |
| `nb_ls_name` | NB | That switch's name. When no port references the DHCP option, the switch is `network_<subnet_uuid>` |
| `sb_datapath_uuid` | SB | Southbound datapath of `nb_ls_uuid` |
| `sb_tunnel_key` | SB | Southbound tunnel key of that switch |
| `sb_egress_tunnel_key` | SB | Southbound egress tunnel key |

## `ovn_router`

One logical router. Router ports are the `ports` array. Each port carries the switch it connects and the southbound binding.

| Column | Side | Use |
|---|---|---|
| `lr_uuid` | NB | Identity |
| `nb_name` | NB | Router name |
| `nb_enabled` | NB | 1 when the router is enabled |
| `nb_external_ids` | NB | Includes `neutron:router_name` |
| `nb_has_nat` | NB | 1 when NAT is configured |
| `nb_gw_external_ips` | NB | NAT `external_ip`. Printed when the path goes outside |
| `nb_gw_logical_ips` | NB | NAT `logical_ip` |
| `sb_datapath_uuid` | SB | Router datapath |
| `sb_tunnel_key` | SB | Southbound tunnel key |
| `sb_egress_tunnel_key` | SB | Southbound egress tunnel key |
| `ports.nb_name` | NB | Router port name |
| `ports.nb_mac` | NB | Router port MAC |
| `ports.nb_networks` | NB | Router port CIDRs |
| `ports.nb_ls_uuid` | NB | Switch this port connects |
| `ports.nb_lsp_name` | NB | Router-type switch port |
| `ports.nb_is_ext_gw` | NB | 1 on the external gateway port |
| `ports.sb_chassis_uuid` | SB | Chassis binding |
| `ports.sb_tunnel_key` | SB | Port number in southbound |
| `ports.sb_up` | SB | 1 when the binding is up |

## `ovn_l2gw`

One localnet port, one l2gateway port, or one geneve stretch chassis.

| Column | Side | Use |
|---|---|---|
| `kind` | NB | `localnet`, `l2gateway`, or `geneve` |
| `ls_uuid` | NB | Switch |
| `lsp_uuid` | NB | Switch port. Zero on a geneve row |
| `nb_name` | NB | Port name |
| `nb_type` | NB | Port type |
| `nb_network_name` | NB | `options:network_name` |
| `nb_vlan` | NB | VLAN tag |
| `nb_mac` | NB | Port MAC |
| `nb_ls_name` | NB | Switch name, including geneve stretch rows |
| `sb_datapath_uuid` | SB | Port datapath, or the switch datapath for geneve |
| `sb_chassis_uuid` | SB | Chassis. Localnet bindings in this dump have no chassis; the datapath and tunnel key are the SB record |
| `sb_hostname` | SB | Chassis hostname |
| `sb_encap_type` | SB | Encap type |
| `sb_encap_ip` | SB | Encap IP |
| `sb_tunnel_key` | SB | Port number, or the switch tunnel key for geneve |
| `sb_up` | SB | 1 when the binding is up |
| `sb_vif_count` | SB | VIF count for `kind=geneve` |

## What the verdict reads

`nic_traffic.py` writes one JSON document and one markdown file. How to run the ingest and the verdict, end to end or one stage at a time, is in [PORTSET_DESIGN.md](../PORTSET_DESIGN.md) under "How to trigger".

The JSON always has `tables` (this catalog), `path`, `acl_source`, `acl_destination`, `verdict`, and `ip_mapping`. `path.tunnels` has the transit-switch tunnel id into the gateway, the external-switch tunnel id, and the transit-switch tunnel id back to the destination router. `verdict.drop_cookie` is the OpenFlow cookie of an enforce drop: the first 32 bits of that ACL uuid. `verdict.drop_where` is `destination switch` for `to-lport` and `source switch` for `from-lport`.

The markdown draws one mermaid flowchart. Each hop label is that tunnel id. The drop cookie is written on the switch that enforces it. Then the file lists hosts, gateway redirect chassis, tcpdump commands, and four tables: ACL source, ACL destination, verdict, and IP mapping.
