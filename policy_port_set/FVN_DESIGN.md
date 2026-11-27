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

The check direction for subnets, routers, and static routes is IDF toward Atlas, Northbound, and Southbound. An Atlas object that IDF does not list is not a failure. An IC route that `ovn-ic` should have installed, and no router learned, is a failure. An IC route `ovn-ic` skips on purpose is not a failure. A missing IDF entity type (`NotFound`) is an empty list. A failed command is one error on the check that needed it. That check does not turn the failed fetch into a miss for every object, and the other checks still print. One hypervisor that fails the tap scan is one tap row. The other hosts are still checked.

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
| `cfg` | printed as `nb_global` and `chassis`, not as `idf` and `atlas` | a row is missing only when its cfg number disagrees |
| `learned` | printed as `installed` and `ic` | `missing` is an IC route `ovn-ic` should install and no router learned, plus an installed route whose IC prefix disagrees. The script still counts every uninstalled IC route, including this zone's own advertisements |

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

The script today reads IDF `bgp_session` (this type exists on this PC; `atlas_bgp_session` does not) and Atlas `bgp_session.list`. With rows, it only checks that the session uuid appears somewhere in Northbound router text and Southbound datapath text. That join is not how BGP is stored. OVN has no BGP table. On this PC the session list is empty, and none of the 300 routers or 4,634 static routes contain `bgp`.

The verification spec is `BGP_LB_DESIGN.md`. Session state and the advertised, received, and ignored prefix lists live on the IDF session. The local and remote gateways are `vpn_gateway` rows. A received prefix is a Northbound static route on that gateway's VPC, matched by prefix, not by the session uuid.

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

A configured static route is an IDF `atlas_route_table` prefix. A learned route is created by `ovn-ic` (`sync_learned_routes` in `ovn/ic/ovn-ic.c`). It copies an IC southbound `Route` onto a Northbound `Logical_Router_Static_Route`: `ip_prefix` and `nexthop` are copied, `external_ids:ic-learned-route` is set to the IC `Route` `_uuid`, and `options:origin` is set to the IC origin. That uuid is not the Northbound route's own `_uuid`. The nexthop is the advertising zone's transit-switch address, not the original nexthop. On this PC the installed rows use `169.254.3.2`.

`ovn-ic` writes four origins (`ovn/lib/ovn-util.h`): `static` from a non-learned static route, `connected` from a router-port network, `loadbalancer` from a `Load_Balancer` `vips` key when `NB_Global.options:ic-route-adv-lb` is set, and `connected-dynamic` from a Southbound `Learned_Route`. This PC has `loadbalancer`, `connected`, and `static`. It has no `connected-dynamic`. `origin=loadbalancer` is a remote VIP prefix (`/32` or `/128`). It is not a local `Load_Balancer` row. This PC has none.

`ovn-ic` does not learn its own advertisements. It skips an IC route whose `external_ids:lr-id` is the local router, and a legacy route with no `lr-id` whose `availability_zone` is the local zone. It also skips filtered prefixes, a prefix that already has a local static route, a prefix covered by a local load balancer VIP, and a prefix already in Southbound `Learned_Route`. The 60 IC routes with origin `connected` and nexthop `169.254.3.1` are this zone's own advertisements. They are not misses. The script currently counts them in `missing`. That does not match `sync_learned_routes`.

The same prefix can be learned onto many VPC routers, each with its own `ic-learned-route` uuid. The IC row also carries `external_ids:nb-id`, which is the advertised `Load_Balancer`, static route, or router port.

The router is the `Logical_Router` whose `static_routes` list contains the Northbound route `_uuid`. `router_<vpc>` and `gw-scale-out-router_nat_<vpc>_<n>` both yield that VPC uuid. The VPC name is the IDF `atlas_virtual_network` name for that uuid.

The match is:

1. Read `_uuid`, `ip_prefix`, `nexthop`, `options:origin`, and `ic-learned-route` from Northbound `Logical_Router_Static_Route`.
2. Join `_uuid` to `Logical_Router.static_routes` to get the router and the VPC.
3. Read `_uuid,ip_prefix` from IC southbound `Route`.
4. The learned uuid must be an IC `Route` uuid, and the IC `ip_prefix` must equal the Northbound prefix.
5. An IC `Route` is a miss only when `sync_learned_routes` would install it and no Northbound route has that uuid. A route this zone advertised (`lr-id` is a local router, or there is no `lr-id` and the availability zone is local) is not a miss.

Every learned route is printed, including the ones that match. A row with `match` `no` is a miss. Each IC route in `learned_not_installed` is also a miss. The learned prefix is not required to be in the IDF route table. Origin is printed and is not compared.

```
FVN learned: installed=680 ic=740 not_installed=60 missing=60
router	vpc	vpc_name	prefix	nexthop	origin	route_uuid	ic_route	ic_prefix	match	detail
router_f1a6fb6d-02a7-4225-97d4-8fc2b725022b	f1a6fb6d-02a7-4225-97d4-8fc2b725022b	VPC_California_SJ_Pheonix_Customer_41	192.168.210.190/32	169.254.3.2	loadbalancer	6c647006-0415-4503-9b6d-e4cf68f0161e	f18ade14-b838-4ffc-a8b1-871dcdf119cc	192.168.210.190/32	yes
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

The same run prints stale taps. A tap is stale when `ip -s link` on the hypervisor still has `tap<number>` and no VM NIC on that host has `status.backend.tapname` set to that name. CVM NICs are `vnet<number>` and are not counted.

For each hypervisor from `ncli host list`:

1. AHV Gateway `networking-lite` is `ip -s link`. Every `tap<number>` there is a live netdev.
2. `GET /api/vmm/v1/vms` and `GET /api/vmm/v1/vms/<id>` give each NIC `tapname`.
3. A name in the first set and not the second is a miss. For those names only, `ovs-vsctl show` from the networking bugtool supplies the bridge.

```
FVN tap: hosts=32 missing=1
host	ip	tap	bridge	state	mac	detail
flashfire02-3	10.116.29.174	tap291	brAtlas	DOWN	fe:6b:8d:59:1b:81	no VM NIC has tapname tap291
```

`tap291` is `DOWN` with `NO-CARRIER` and zero packets. The other 31 hosts had every `tap<number>` owned by a VM NIC. `missing` here is the number of stale taps, and it makes the process exit 1.

## What the check does not decide

- Route nexthop. It is not an indexed IDF column.
- Extra Atlas, Northbound, or IC rows that IDF did not ask for.
- Inactive IDF prefixes.
- Whether a transit redirect chassis is a member of the external-subnet candidate list.
- SMSP pod layout. The kubectl names above are CMSP.

## Result on one CMSP PC

Subnet, router, route, L2 gateway, BGP, and redirect chassis had nothing missing. Cfg was even on that read (`missing=0`). The 680 installed routes matched their IC prefixes. The script counted the 60 own-zone IC routes as `missing=60`. `ovn-ic` does not install those. The tap table had one more miss, so the process exited 1.

```
FVN subnet: idf=1883 atlas=1883 missing=0
FVN router: idf=100 atlas=100 missing=0
FVN route: idf=100 atlas=100 missing=0
FVN l2gw: idf=0 atlas=0 missing=0
FVN bgp: idf=0 atlas=0 missing=0
FVN rc: idf=210 atlas=210 missing=0
FVN cfg: nb_global=1 chassis=32 missing=0
FVN learned: installed=680 ic=740 not_installed=60 missing=60
FVN tap: hosts=32 missing=1
```

`nb_global=1` and `chassis=32` are different tables. One `NB_Global` row is the version the database has published. Each of the 32 `Chassis_Private` rows is one host. The counts are not supposed to be equal. `missing` is a row whose `nb_cfg`, `sb_cfg`, or `hv_cfg` disagrees. A later read caught a real lag, not the 1-versus-32 count. Northbound and southbound were `772424` and `hv_cfg` was still `772422`:

```
table	uuid	name	nb_cfg	sb_cfg	hv_cfg	expected	match	detail
NB_Global	9bc7b588-9d8d-4c86-b839-370f5228f2b2		772424	772424	772422	772424	no	nb_cfg=772424 sb_cfg=772424 hv_cfg=772422
Chassis_Private	476643a2-26d2-4655-a501-f269040e12d8	8d18b494-05db-4911-9272-28bff2114e0b	772423			772424	no	nb_cfg=772423 expected=772424
Chassis_Private	99360e88-24d6-4350-8243-e5742a6a0e45	5c350a5e-b9bc-42fa-8eaf-ff4cb98a8e66	772422			772424	no	nb_cfg=772422 expected=772424
Chassis_Private	b9f5395d-d78e-4ccd-8b93-968a596cdc22	ef355d92-dc3b-4dc4-aaf4-7c559db792d7	772423			772424	no	nb_cfg=772423 expected=772424
```

Those chassis names are `flashfire02-1` (`8d18b494-05db-4911-9272-28bff2114e0b`), `zadkiel04-4` (`5c350a5e-b9bc-42fa-8eaf-ff4cb98a8e66`), and `flashfire01-2` (`ef355d92-dc3b-4dc4-aaf4-7c559db792d7`). The other 29 chassis matched `772424`. The number was still moving, so a host can sit one or two versions behind for a short time.

`installed=680` and `ic=740` are different tables. Every installed route matched its IC prefix. The 60 routes with nexthop `169.254.3.1` are this zone's own IC advertisements, which `ovn-ic` does not learn back. The script still prints them as `missing=60`. One installed row:

```
router	vpc	vpc_name	prefix	nexthop	origin	ic_route	ic_prefix	match
router_f1a6fb6d-02a7-4225-97d4-8fc2b725022b	f1a6fb6d-02a7-4225-97d4-8fc2b725022b	VPC_California_SJ_Pheonix_Customer_41	192.168.210.190/32	169.254.3.2	loadbalancer	f18ade14-b838-4ffc-a8b1-871dcdf119cc	192.168.210.190/32	yes
```

The other 60 IC routes are printed under `FVN learned_not_installed` and counted in `missing`. All 60 are `origin=connected`, nexthop `169.254.3.1`, and a `/27` in `172.31.30.0` through `172.31.37.97`. IC advertised them and no router on this PC learned them.

```
FVN learned_not_installed: count=60
ic_route	prefix	nexthop	origin
df43e600-c646-44c6-bc0d-92881dc7ab8e	172.31.32.161/27	169.254.3.1	connected
71c40a03-9e5e-4cdc-8c83-ad87f90ebdc0	172.31.37.97/27	169.254.3.1	connected
0fa5d789-f745-4a3f-8650-9ef334c6153b	172.31.30.1/27	169.254.3.1	connected
```

The 210 redirect-chassis ports are 200 external gateway ports and 10 transit ports. The tap table from the same PC is the `tap291` row in the stale-tap section.
