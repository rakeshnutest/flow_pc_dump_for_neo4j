# FVN validation

`policy_port_set/validate_fvn.py` checks Flow Virtual Networking config on a Prism Central VM. The script is one file and uses the standard library only. It does not import the port-set scripts and it writes nothing to disk.

IDF is the configured intent. Each configured object must be present in Atlas, then in the OVN Northbound row that programs it, then in the OVN Southbound datapath that places it. Redirect-chassis selection, OVN version placement, and dynamically learned routes are checked in the same run. Learned routes are not IDF config; they are matched to the OVN IC southbound database.

```
idfcli
  atlas_subnet / atlas_virtual_network / atlas_route_table
  layer2_stretch / bgp_session
        |
        v
atlas_cli list
        |
        v
ovn-nbctl   Logical_Switch, Logical_Router, Logical_Router_Static_Route,
            Logical_Router_Port, NB_Global
        |
        v
ovn-sbctl   Datapath_Binding, Port_Binding, Chassis, Chassis_Private
        |
        v
ovn-ic-sbctl Route     printed per learned route: router, VPC, prefix,
                         nexthop, origin, ic-learned-route uuid
```

Run it on the PC with the system `python3`:

```
python3 validate_fvn.py
python3 validate_fvn.py --timeout 300
python3 validate_fvn.py --self-test
```

Stdout is one summary line per check, then one JSON object per learned route, then one JSON object per miss. Logging goes to stderr. Exit status is 0 when no miss is printed, and 1 when any miss is printed. Learned routes with `match` `yes` are printed and are not misses. An empty L2 gateway table or an empty BGP table is a pass.

The check direction is IDF toward Atlas, Northbound, and Southbound. An Atlas or OVN object that IDF does not list is not a failure. A missing IDF entity type (`NotFound`) is an empty list. An Atlas command whose status is not 0 stops the run.

## Where the commands run

| Tool | Path |
|---|---|
| `idfcli` | `/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli`, then `/usr/local/nutanix/bin/idfcli`, then `/home/nutanix/bin/idfcli` |
| `atlas_cli` | `/usr/local/nutanix/bin/atlas_cli`, then `/home/nutanix/bin/atlas_cli` |
| `ovn-nbctl` / `ovn-sbctl` | local socket `/var/run/ovn/ovnnb_db.sock` or `/var/run/ovn/ovnsb_db.sock` when it exists, otherwise `kubectl exec -n default anc-ovn-0 -c anc-ovn` |
| `ovn-ic-sbctl` | `kubectl exec -n default` on the pod whose name starts with `anc-ovn-ic-db` |

`idfcli` prints log lines before the JSON. Parsing starts at the first `{`. `kubectl` is tried on `PATH`, then as `sudo -n kubectl`. This path is the CMSP layout. SMSP is not implemented.

## Summary line

```
FVN <label>: idf=<n> atlas=<n> missing=<n>
```

| Label | `idf=` | `atlas=` |
|---|---|---|
| `subnet` | `atlas_subnet` rows | `subnet.list` uuids |
| `router` | `atlas_virtual_network` rows | `network.list` uuids |
| `route` | `atlas_route_table` rows | `route_table.list` uuids |
| `l2gw` | `layer2_stretch` rows | `layer2_stretch.list` uuids |
| `bgp` | `bgp_session` rows | `bgp_session.list` uuids |
| `rc` | redirect-chassis ports checked | same count |
| `cfg` | `NB_Global` rows | `Chassis_Private` rows |
| `learned` | Northbound routes with `ic-learned-route` | IC `Route` rows |

A miss is one JSON object:

| Field | Meaning |
|---|---|
| `kind` | `subnet`, `router`, `route`, `l2gw`, `bgp`, `rc`, `cfg`, or `learned` |
| `uuid` | IDF entity id, or the OVN/IC uuid when the row is not an IDF entity |
| `name` | IDF name, VPC uuid, port name, or prefix |
| `where` | `idf`, `atlas`, `nb`, `sb`, or `ic` |
| `expected` | the name, prefix, chassis, or cfg number that should have been there |
| `detail` | the comparison that failed |

## Subnets

IDF entity type `atlas_subnet`. The entity id is the subnet uuid. `virtual_network` is the Acropolis view of the same networks and is not the source.

| Store | Required row |
|---|---|
| Atlas | `subnet.list` contains the uuid |
| Northbound | `Logical_Switch` name `network_<uuid>`, or any switch name that contains the uuid |
| Southbound | `Datapath_Binding.external_ids` has `name=network_<uuid>`, or a name that contains the uuid |

Both overlay (`subnet_type` 0, a `virtual_network_uuid` is set) and VLAN (`subnet_type` 1) use the name `network_<uuid>`. Scale-out NAT switches are named `gw-scale-out-network_nat_<uuid>` and are not required for this check.

## Routers

IDF entity type `atlas_virtual_network`. One row is one VPC. Atlas lists these with `network.list`. `vpc.list` is not a command.

| Store | Required row |
|---|---|
| Atlas | `network.list` contains the VPC uuid |
| Northbound | some `Logical_Router` name contains the uuid |
| Southbound | some datapath `name=` contains the uuid |

The tenant router is `router_<vpc>`. North-south routers are `gw-scale-out-router_nat_<vpc>_<n>`. Either name satisfies the check.

## Static routes

IDF entity type `atlas_route_table`. The entity id is the table uuid. `virtual_network_uuid` is the VPC that owns the table. Atlas lists tables with `route_table.list`. `route.list` needs a uuid argument and is not used. There is no `atlas_route` entity type.

Indexed columns are `route_list.destination_prefix`, `route_list.is_active`, and `route_list.route_type`. The nexthop is inside `__zprotobuf__` and is not compared.

A prefix is required only when `is_active` is not false. An inactive prefix is skipped. `route_type` `1` and `route_type` `2` (the default `0.0.0.0/0`) are both required when they are active.

| Store | Required row |
|---|---|
| Atlas | `route_table.list` contains the table uuid |
| Northbound | the prefix is `ip_prefix` on a `Logical_Router_Static_Route` owned by a router whose name contains the VPC uuid |
| Southbound | a datapath name contains the VPC uuid |

`Logical_Router_Static_Route` has no parent column. The parent is the `static_routes` uuid list on `Logical_Router`. Routes that carry `ic-learned-route` are not part of this comparison; they are the learned-route check below.

## L2 gateway

IDF entity type `layer2_stretch`. If that type is absent, the script reads `atlas_layer2_stretch`. Atlas command is `layer2_stretch.list`.

When the table has rows, the stretch uuid must appear in Northbound `Logical_Switch_Port` `name` or `external_ids`, and in Southbound `Port_Binding` `logical_port` or `external_ids` (the datapath text is included as well). Zero rows is a pass. This PC had no stretches, so the live run did not exercise a populated L2 table.

## BGP

IDF entity type `bgp_session`. If that type is absent, the script reads `atlas_bgp_session`. Atlas command is `bgp_session.list`.

When the table has rows, the session uuid must appear in the Northbound router and switch-port text, and in the Southbound datapath and port-binding text. Zero rows is a pass. This PC had no BGP sessions. BGP-learned prefixes that OVN has already installed are covered by the learned-route check, not by this empty table.

## Redirect chassis

Two kinds of port carry `options:redirect-chassis`.

External gateway. The port is on `gw-scale-out-router_nat_<vpc>_<n>` and is named `lrp-ext_gw_port_<id>`. IDF stores the candidate nodes on `external_subnet_list.gateway_node_uuid_list` and the expected count on `external_subnet_list.active_gateway_count`. The selected node is not an indexed IDF column; OVN is the selection.

| Check | Pass |
|---|---|
| Northbound | `options:redirect-chassis` equals `status:hosting-chassis` |
| Southbound | `Port_Binding` `logical_port=ext_gw_port_<id>` has `options:l3gateway-chassis` equal to that node |
| IDF | the node is in `gateway_node_uuid_list` |
| Count | the number of such ports for the VPC equals the sum of `active_gateway_count` |

Transit. The port is named `lrp-transit-switch_<transit>_router_<vpc>`. It is the IC transit attachment, not an external-subnet gateway, so it is not compared with `gateway_node_uuid_list`.

| Check | Pass |
|---|---|
| Northbound | `redirect-chassis` equals `hosting-chassis` |
| Southbound | `Port_Binding` `logical_port=cr-lrp-transit-switch_...` is type chassisredirect, and `Chassis.name` for its `chassis` column is that same node |

`Chassis.name` is the node uuid. `Port_Binding.chassis` is the OVN chassis row uuid. The script joins those two.

## Placement

Placement is the OVN config version. A redirect chassis recorded in Southbound is only current when every chassis has applied the same Northbound version.

Every `NB_Global` row must have `nb_cfg`, `sb_cfg`, and `hv_cfg` equal to the same number. Timestamps (`nb_cfg_timestamp` and the rest) are not versions. Every `Chassis_Private` uuid must carry that `nb_cfg`. An empty `Chassis_Private` list is a miss.

`Chassis.nb_cfg` stays 0 on this OVN because the column moved to `Chassis_Private`. The script does not read it.

A miss names the uuid and the disagreeing values, for example `nb_cfg=7 sb_cfg=6 hv_cfg=7` or `nb_cfg=5 expected=7`.

## Redirect chassis, how the value is chosen

IDF does not store the selected node. `external_subnet_list.gateway_node_uuid_list` is the candidate list and `external_subnet_list.active_gateway_count` is how many gateways Atlas expects. The selected node is OVN `options:redirect-chassis` on the gateway port.

External gateway ports are found by walking `Logical_Router` rows named `gw-scale-out-router_nat_<vpc>_<n>`, then the `ports` uuid list, then `Logical_Router_Port` whose name is `lrp-ext_gw_port_<id>`. Transit ports are every `Logical_Router_Port` whose name starts with `lrp-transit-switch_` and ends with `_router_<vpc>`. They are not part of `active_gateway_count`.

Southbound placement for an external gateway is `options:l3gateway-chassis` on `Port_Binding` `logical_port=ext_gw_port_<id>`. For a transit port it is the chassisredirect binding `logical_port=cr-lrp-transit-switch_...`. That binding's `chassis` column is an OVN chassis uuid; `Chassis.name` for that uuid is the node uuid, and that name must equal `redirect-chassis`.

A redirect-chassis miss is a JSON object with `kind` `rc`, `where` `nb`, `sb`, or `idf`, and the node uuid that was expected.

## Dynamically learned routes

A configured static route is an IDF `atlas_route_table` prefix. A learned route is a Northbound `Logical_Router_Static_Route` whose `external_ids` contain `ic-learned-route=<uuid>`. That uuid is not the route row's own `_uuid`. It is the `_uuid` of a `Route` row in the OVN IC southbound database (`ovn-ic-sbctl list Route` on `anc-ovn-ic-db`). The prefix is installed on a VPC router with nexthop `169.254.3.2` (the transit link). `options:origin` is `loadbalancer`, `connected`, or `static`. The same prefix can be learned onto many VPC routers, each with its own `ic-learned-route` uuid.

The router is the `Logical_Router` whose `static_routes` list contains the Northbound route `_uuid`. `router_<vpc>` and `gw-scale-out-router_nat_<vpc>_<n>` both yield that VPC uuid. The VPC name is the IDF `atlas_virtual_network` name for that uuid.

The match is:

1. Read `_uuid`, `ip_prefix`, `nexthop`, `options:origin`, and `ic-learned-route` from Northbound `Logical_Router_Static_Route`.
2. Join `_uuid` to `Logical_Router.static_routes` to get the router and the VPC.
3. Read `_uuid,ip_prefix` from IC southbound `Route`.
4. The learned uuid must be an IC `Route` uuid, and the IC `ip_prefix` must equal the Northbound prefix.

Every learned route is printed, including the ones that match. A row with `match` `no` is a miss and makes the process exit 1. The learned prefix is not required to be in the IDF route table. An IC route that no Northbound router has installed is not a failure. Origin is printed and is not compared.

```
FVN learned: idf=680 atlas=740 missing=0
{"detail":"","ic_prefix":"192.168.210.190/32","ic_route":"f18ade14-b838-4ffc-a8b1-871dcdf119cc","kind":"learned","match":"yes","nexthop":"169.254.3.2","origin":"loadbalancer","prefix":"192.168.210.190/32","route_uuid":"6c647006-0415-4503-9b6d-e4cf68f0161e","router":"router_f1a6fb6d-02a7-4225-97d4-8fc2b725022b","vpc":"f1a6fb6d-02a7-4225-97d4-8fc2b725022b","vpc_name":"VPC_California_SJ_Pheonix_Customer_41"}
```

| Field | Meaning |
|---|---|
| `router` | Northbound `Logical_Router` name that owns the route |
| `vpc` / `vpc_name` | VPC uuid parsed from that router name, and the IDF name |
| `route_uuid` | Northbound `Logical_Router_Static_Route` `_uuid` |
| `prefix` / `nexthop` / `origin` | The installed route |
| `ic_route` / `ic_prefix` | `ovn-ic-sbctl` `Route` `_uuid` and `ip_prefix` |
| `match` | `yes` when `ic_route` exists and `ic_prefix` equals `prefix` |

## Stale tap interfaces

This is a host check, separate from the IDF-to-OVN script. A tap is stale when the host still has the device and OVS still has the port, but no VM NIC on that host names it.

For each of the 32 hypervisors from `ncli host list`:

1. AHV Gateway `networking-lite` gives `ip -s link`. Every `tap<number>` in that output is a live netdev.
2. The same host's full `networking` bugtool gives `ovs-vsctl show`. Every `Interface tap<number>` is an OVS port. An `error:` line on that interface is a tap whose netdev is already gone.
3. AHV Gateway `GET /api/vmm/v1/vms` and `GET /api/vmm/v1/vms/<id>` give each NIC `status.backend.tapname`. Those names are the taps a running VM still owns.

OVS tap names and `ip link` tap names were equal on all 32 hosts, and no interface had an `error:` line. The stale set is therefore `ip link` taps minus VM `tapname` values. CVM NICs are named `vnet<number>` (three per host, `vnet6`–`vnet8` or `vnet9`–`vnet11`). They are not taps and are not counted.

One host failed that set difference. `flashfire02-3` (`10.116.29.174`) has `tap291` on bridge `brAtlas`. `ip -s link` shows it `DOWN`, `NO-CARRIER`, zero RX and TX packets, MAC `fe:6b:8d:59:1b:81`. No VM NIC on that host has `tapname` `tap291`. The other 31 hosts have every `tap<number>` owned by a VM NIC.

## What the check does not decide

- Route nexthop. It is not an indexed IDF column.
- Extra Atlas, Northbound, or IC rows that IDF did not ask for.
- Inactive IDF prefixes.
- Whether a transit redirect chassis is a member of the external-subnet candidate list.
- SMSP pod layout. The kubectl names above are CMSP.

## Result on one CMSP PC

Exit status 0.

```
FVN subnet: idf=1883 atlas=1883 missing=0
FVN router: idf=100 atlas=100 missing=0
FVN route: idf=100 atlas=100 missing=0
FVN l2gw: idf=0 atlas=0 missing=0
FVN bgp: idf=0 atlas=0 missing=0
FVN rc: idf=210 atlas=210 missing=0
FVN cfg: idf=1 atlas=32 missing=0
FVN learned: idf=680 atlas=740 missing=0
```

The 210 redirect-chassis ports are 200 external gateway ports and 10 transit ports. `NB_Global` and all 32 `Chassis_Private` rows shared one cfg number. All 680 learned prefixes matched an IC route, and each of those 680 rows is printed with its router, VPC name, prefix, nexthop, origin, and IC route uuid. The IC database had 740 routes; the extra 60 are advertised routes that this Northbound has not installed. The stale-tap pass on the same PC found one leftover, `tap291` on `flashfire02-3`.
