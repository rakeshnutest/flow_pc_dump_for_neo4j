# BGP and load balancer verification

This spec is how `validate_fvn.py` should check BGP sessions and load balancer sessions. It follows the same direction as the other FVN checks: IDF config, then Atlas, then OVN Northbound, then OVN Southbound. A failed fetch is one error on that check. The other checks still print.

The OVN behavior below is from `ovn/ic/ovn-ic.c`, `ovn/northd/northd.c`, `ovn/northd/en-learned-route-sync.c`, `ovn/northd/en-advertised-route-sync.c`, and `ovn/controller/route-exchange.c` in the `ovs_code` tree. That `ovn-ic` is the one that matches this PC: learned routes carry `options:origin` of `loadbalancer`, `connected`, or `static`. The older copy under `ahv-ovn/ic/ovn-ic.c` does not set `origin` and does not advertise load balancer VIPs. Do not use that copy for this check.

## What ovn-ic does with a route

`ovn-ic` is the only program that creates a learned route. `sync_learned_routes` copies an IC southbound `Route` onto a Northbound `Logical_Router_Static_Route`. The new row is:

| Column | Value |
|---|---|
| `ip_prefix` | the IC route prefix, unchanged |
| `nexthop` | the IC route nexthop, unchanged |
| `route_table` | the IC route table |
| `external_ids:ic-learned-route` | the IC `Route` `_uuid` |
| `options:origin` | the IC `Route.origin` |

`ovn-nbctl` will not change or delete a static route that has `ic-learned-route`. The row belongs to `ovn-ic`.

The IC nexthop is not the route's original nexthop. While advertising, `get_nexthop_from_lport_addresses` replaces it with the address of this availability zone's transit-switch port. Every route one zone advertises shares that port address. On this PC the learned rows use `169.254.3.2`. A route whose nexthop is the other transit address was advertised by the other side.

`advertise_routes` writes the IC row and sets:

| `external_ids` key | Value |
|---|---|
| `nb-id` | the object that was advertised: `Load_Balancer` uuid for origin `loadbalancer`, static-route uuid for origin `static`, router-port uuid for origin `connected` |
| `lr-id` | the advertising `Logical_Router` uuid |
| `ic-route-tag` | the transit port's tag, when one is set |

`sync_learned_routes` does not install every IC route. It skips a route when any of these is true:

| Skip | Code |
|---|---|
| `external_ids:lr-id` is this router | own route, do not learn it back |
| no `lr-id`, and `availability_zone` is this zone | legacy own route |
| `ic-route-tag` equals the transit port's `ic-route-filter-tag` | tag filter |
| IC `route_table` is set and differs from the transit port `route_table` | table filter |
| `NB_Global.options:ic-route-learn` is not true | learning off |
| prefix length 0 and `ic-route-learn-default` is not true | default route |
| origin is `loadbalancer` and `ic-route-learn-lb` is not true | LB learning off |
| router disabled, prefix link-local, deny list, or allow list misses | filters |
| a non-learned static route already has this prefix | `route_has_local_gw` |
| nexthop is not in the transit port subnet | `lrp_has_neighbor_in_ts` |
| a local `Load_Balancer` VIP covers this prefix | `route_matches_local_lb` |
| Southbound `Learned_Route` already has this prefix | dynamic route already present |

A skipped IC route is not a miss. The 60 IC routes on this PC with origin `connected` and nexthop `169.254.3.1` are the routes this zone advertised. `ovn-ic` is required not to install them. The checker prints them as `skipped=own_az`. The current script counts them in `missing`. That count does not match `sync_learned_routes`.

A miss is an IC route that none of those skips apply to, and no Northbound route has `ic-learned-route` equal to that IC uuid. A Northbound learned route whose `ic-learned-route` uuid is not an IC `Route`, or whose prefix differs from that IC prefix, is still a miss.

## Where `origin=loadbalancer` comes from

`add_lb_vip_to_routes_ad` runs only when `NB_Global.options:ic-route-adv-lb` is true. For each `Load_Balancer` on the logical router, and each member of a `Load_Balancer_Group` on that router, it reads `vips`. The map key is `ip:port`. The advertised prefix is that IP with length 32 for IPv4 and 128 for IPv6. Origin is the constant `loadbalancer` (`ROUTE_ORIGIN_LB` in `ovn/lib/ovn-util.h`). The port in the key is not part of the prefix.

`northd` does not treat that origin as a load balancer route. In `parsed_routes_add_static`, origin `connected` becomes a connected route and origin `connected-dynamic` becomes an IC dynamic route. Every other origin, including `loadbalancer` and `static`, is installed as a static route. Priority is longest prefix, then connected above static above a route learned from `ovn-controller`.

The 500 `loadbalancer` rows on this PC are those IC copies. They are not local `Load_Balancer` rows. This PC has zero `Load_Balancer` rows, which is why the VIPs were learned: `route_matches_local_lb` had nothing local to match.

The other origins `ovn-ic` writes are `static` (a non-learned static route), `connected` (a router-port network, not the transit port itself), and `connected-dynamic` (a Southbound `Learned_Route`). This PC has 90 `static`, 90 `connected`, and no `connected-dynamic`.

## What OVN BGP is

OVN has no BGP session table and no BGP daemon. `ovn/controller/route-exchange.c` reads routes from the kernel and inserts Southbound `Learned_Route` rows: `datapath`, `logical_port`, `ip_prefix`, `nexthop`. A port with `options:dynamic-routing-no-learning` is skipped. `en-learned-route-sync.c` parses those rows into the routing pipeline at `ROUTE_SOURCE_LEARNED`, which is the lowest of the three priorities in `northd.c`.

`ovn-ic` advertises a `Learned_Route` with origin `connected-dynamic`. On the far side, `northd` installs that origin at connected priority, not at the learned priority.

A second path, `en-advertised-route-sync.c`, fills Southbound `Advertised_Route` when the router has dynamic routing enabled. What is redistributed depends on the port: connected, static, NAT, load balancer, or IC dynamic. `ovn-controller` is what announces those to the kernel. That is the OVN BGP route exchange. It never reads IDF `bgp_session`.

This PC has no `connected-dynamic` origin and no `bgp` string on a router or a static route, so neither OVN path is in use. An Atlas `bgp_session` still has to be checked from IDF and Atlas. OVN will not contain the session uuid. The only OVN evidence of that session, once it exists, is a received prefix installed as a static route, or a `Learned_Route` if the gateway injected it through `ovn-controller`. Until a live session shows which of those two happened, the checker requires the received prefix on the VPC router and prints `Learned_Route` when one exists. It does not require `options:origin=bgp`.

The live read was CMSP Prism Central `10.120.159.166` on 27 Nov 2026. SMSP was not read.

## What this PC actually has

| Object | IDF type | Count | Atlas command | OVN |
|---|---|---|---|---|
| BGP session | `bgp_session` (type present) | 0 | `bgp_session.list` status 0, 0 rows | no BGP table; no `bgp` string in 300 `Logical_Router` rows or 4,634 `Logical_Router_Static_Route` rows |
| BGP session, other name | `atlas_bgp_session` | type absent | | |
| Load balancer session | `atlas_load_balancer_session` | 0 | `load_balancer_session.list` status 0, 0 rows | `Load_Balancer` count 0 in Northbound and Southbound |
| Load balancer session, other name | `load_balancer_session` | type absent | | |
| Gateway | `vpn_gateway` | 2 | `vpn_gateway.list` status 0, 2 rows | both are VTEP gateways, `internal_state.has_bgp_service` false |
| Network gateway command | `atlas_network_gateway`, `network_gateway` | type absent | `network_gateway.list` status 1 | not a usable command on this PC |

`atlas_cli` accepts `bgp_session.list`, `load_balancer_session.list`, and `vpn_gateway.list`. It does not accept a bare `bgp_session` or `load_balancer_session` with `--help`.

Route `options:origin` on the 4,634 Northbound static routes:

| origin | rows |
|---|---|
| absent | 3,954 |
| `loadbalancer` | 500 |
| `connected` | 90 |
| `static` | 90 |
| anything containing `bgp` | 0 |

The 500 `loadbalancer` origins are learned VIP routes (`ic-learned-route` on the route, prefix matched in IC southbound). They are not local load balancer sessions. The local session table is empty on this PC. A learned VIP and a local session are two checks.

## What the script does today

BGP is a uuid substring. If `bgp_session` has rows, the session uuid must appear in Northbound router and switch-port text and in Southbound datapath and port-binding text. Zero rows is a pass. That substring cannot succeed for a real session: OVN does not store the session uuid on the router. The check needs to be replaced, not extended.

There is no load balancer section. `origin=loadbalancer` is printed on the learned-route table and is not compared.

## Shared rules

Identity is the entity uuid. Names are display.

An IDF type that returns NotFound is an empty list. A type that exists with zero rows is a pass for that section. An Atlas status other than 0 is an error for that section only.

Extra Atlas rows that IDF does not list are not misses. An IDF row missing from Atlas is a miss.

Do not read `__zprotobuf__`. Do not print passwords, communities, public IPs, or gateway credentials. Indexed columns are enough for the compares below. A field that is only inside the protobuf is named here and is not a compare.

One host, one command, or one section failing does not drop the other section. The same isolation as the rest of `validate_fvn.py` applies.

## BGP

### Objects

A session is IDF `bgp_session`. The entity id is the session uuid. Indexed columns:

| Column | Use |
|---|---|
| `name` | display |
| `local_gateway_uuid` | the VPC gateway that speaks BGP |
| `remote_gateway_uuid` | the peer gateway |
| `dynamic_route_priority` | printed, not compared to OVN |
| `status.state` | session state, Atlas only |
| `status.detail` | printed with the state |
| `advertised_route_list.network_address` | prefix address we advertise |
| `advertised_route_list.prefix_length` | joined with the address on the same index |
| `advertised_route_list.next_hop` | printed with the advertised prefix |
| `received_route_list.network_address` | prefix address we learned |
| `received_route_list.prefix_length` | joined with the address on the same index |
| `received_route_list.next_hop` | printed; not required to equal the OVN nexthop |
| `ignored_route_list.network_address` | prefix Atlas kept out of OVN |
| `ignored_route_list.prefix_length` | joined with the address on the same index |
| `service_node.active_node.uuid` | node that owns the session |
| `service_node.node_candidate_list` | candidate nodes |

`session_drop_rate`, `nh_filter.*`, `externally_routable_prefix_list`, `advertise_all_erps`, `autonomous_systems_to_prepend`, `advertised_route_communities.*`, `project_id`, `deployment_type`, and `gateway_vnic_idx` are printed only when a later change asks for them. They are not OVN joins.

Repeated list columns line up by index, the same way `route_list.destination_prefix` lines up with `route_list.is_active`. A prefix is `network_address/prefix_length`. An address with no length at that index is a miss on the session, not a fabricated `/32`.

The gateways are IDF `vpn_gateway`. Columns used:

| Column | Use |
|---|---|
| `name` | display |
| `virtual_network_uuid` | VPC for the gateway |
| `bgp_service_config.virtual_network_uuid` | VPC when the gateway is a BGP service |
| `internal_state.has_bgp_service` | the local gateway of a session must be true |
| `operational_status.state` | gateway state, printed |
| `is_active` | printed |
| `ebgp_config.asn` | printed, not compared to OVN |
| `ha_group.group_uuid` | printed when the gateway is HA |

On this PC both gateways are VTEP (`has_vtep_service` true, `has_bgp_service` false) and share VPC `fc433064-926d-4fc0-a1a3-7c089ad90343`. They are not BGP peers. A VTEP gateway is not a BGP miss by itself.

Atlas `vpn_gateway.list` returns `uuid`, `name`, `service`, `status`, `isActive`, `deployment_type`, `hastate`, `ips`, `fips`, `version`. The IDF uuid must be in that list. `ips` and `fips` are not printed.

`status.state` on this build is not a string `UP` for the gateway: the two VTEP gateways stored `operational_status.state` as `1`. The V4 API uses `UP`. Until a live `bgp_session` row is read, print the raw IDF value and do not treat a particular string as the only healthy value. A session with an empty `status.state` is a miss.

### Atlas

`bgp_session.list` must contain the session uuid. The list on this PC returns no keys because it is empty. When it has rows, compare uuid only. Route lists stay on the IDF read. Do not call `bgp_session.get` unless the list omits the uuid that IDF has.

### Northbound and Southbound

OVN has no BGP session table. The session uuid is not required in `Logical_Router`, `Logical_Switch_Port`, `Datapath_Binding`, or `Port_Binding`.

The dataplane check is the received prefix list:

1. Resolve the VPC. Prefer `bgp_service_config.virtual_network_uuid` on the local gateway, else `virtual_network_uuid`.
2. The VPC uuid must appear in a Northbound `Logical_Router` name (`router_<vpc>` or `gw-scale-out-router_nat_<vpc>_<n>`). Missing router is a miss.
3. Southbound must have a datapath whose name contains that VPC uuid. Missing datapath is a miss.
4. Each received prefix must be `ip_prefix` on a `Logical_Router_Static_Route` owned by one of those routers. Ownership is the same join as static routes: the route `_uuid` is in `Logical_Router.static_routes`.
5. An ignored prefix must not be required on that router. If it is installed anyway, print it and count it as a miss.
6. An advertised prefix is Atlas state. It is printed. It is not required to be a Northbound static route.

The origin string and `external_ids` are printed. This PC has no session and no route row containing `bgp`. `ovn-ic` never writes origin `bgp`. A received prefix may show up later as a plain static route or as a Southbound `Learned_Route`. The checker accepts either. It does not require a specific origin string.

`received_route_list.next_hop` is printed beside the OVN nexthop. They are not required to be equal. Gateway nexthops in OVN are often the transit address, as with learned routes (`169.254.3.2`).

`service_node.active_node.uuid` must be one of `service_node.node_candidate_list` when the candidate list is non-empty. That node is not required to equal a redirect chassis. Redirect chassis stays the external-gateway and transit check.

### BGP misses

| where | condition |
|---|---|
| `atlas` | session uuid missing from `bgp_session.list` |
| `idf` | `local_gateway_uuid` or `remote_gateway_uuid` is not a `vpn_gateway` |
| `idf` | local gateway `internal_state.has_bgp_service` is not true |
| `idf` | local gateway has no VPC uuid |
| `idf` | `status.state` is empty |
| `idf` | a route list address has no prefix length at the same index |
| `idf` | active node is set and is not in the candidate list |
| `nb` | no router name contains the VPC uuid |
| `nb` | a received prefix is not on one of those routers |
| `nb` | an ignored prefix is on one of those routers |
| `sb` | no datapath name contains the VPC uuid |

A remote gateway does not need `has_bgp_service`. The peer can be a remote `vpn_gateway` with only a name and uuid.

### BGP output

```
FVN bgp: idf=<sessions> atlas=<sessions> received=<prefixes> missing=<n>
```

Then a TSV, one row per session, then one row per received, advertised, and ignored prefix:

```
session  name  vpc  vpc_name  local_gw  remote_gw  state  detail  active_node
prefix   kind  session  vpc  nexthop_idf  nexthop_ovn  origin  match  detail
```

`kind` is `received`, `advertised`, or `ignored`. `match` is `yes`, `no`, or `not_checked`. Advertised rows are `not_checked` for OVN. `not_checked` is not a miss.

Zero sessions prints `idf=0 atlas=0 received=0 missing=0` and no table body.

## Load balancer

### Two checks

Local session. IDF `atlas_load_balancer_session` plus `atlas_load_balancer_session_target`, Atlas `load_balancer_session.list`, OVN `Load_Balancer`.

Learned VIP. Already the learned-route check. A Northbound route with `options:origin=loadbalancer` and `external_ids:ic-learned-route=<uuid>` must match an IC `Route` prefix. That route does not require a local `atlas_load_balancer_session`. On this PC those 500 routes are the learned-VIP case, and the local table is empty.

### Session columns

IDF `atlas_load_balancer_session`, entity id is the session uuid:

| Column | Use |
|---|---|
| `name` | display |
| `virtual_network_uuid` | VPC |
| `listener.virtual_ip_address` | VIP that OVN must expose |
| `listener.protocol` | printed; OVN `protocol` must equal it when both are set |
| `listener.subnet_uuid` | logical switch `network_<subnet>` |
| `listener.floating_ip_uuid` | printed, not an OVN join |
| `type` | printed |
| `algorithm` | printed |

The listener port is not an indexed column. It stays in `__zprotobuf__` and is not compared. The target entity carries its own `port`.

IDF `atlas_load_balancer_session_target`:

| Column | Use |
|---|---|
| `load_balancer_session_uuid` | parent session |
| `virtual_nic_uuid` | target identity |
| `vm_uuid` | display join, not an OVN key |
| `port` | target port, printed |
| `health` | Atlas health, not an OVN column |

A target whose `load_balancer_session_uuid` is not a session is a miss. A session with zero targets is a miss. Stats entities (`atlas_load_balancer_session_listener_stats`, `atlas_load_balancer_session_targets_stats`) are counters and are not compared.

### Atlas

`load_balancer_session.list` must contain the session uuid. This PC's empty list has no keys. Uuid is the compare. Do not require the list payload to repeat the VIP.

### Northbound

`ovn-ic` finds a load balancer only through `Logical_Router.load_balancer` and `Logical_Router.load_balancer_group`. The `Load_Balancer.name` is not read. The VIP is the address half of a `vips` key (`ip:port`). Protocol is the `protocol` column (`tcp`, `udp`, or `sctp`).

The match for a session is a `Load_Balancer` that is attached to the VPC router, directly or through a group, and whose `vips` has a key starting with `listener.virtual_ip_address` and a colon. A name or `external_ids` that contains the session uuid is recorded, not required. Atlas is what creates the row. This PC has no row, so the name Atlas chooses is still unknown. The attachment and the VIP key are what `add_lb_vip_to_routes_ad` uses, so those are the check.

When `NB_Global.options:ic-route-adv-lb` is true, IC southbound must contain a route with origin `loadbalancer`, prefix `<vip>/32` or `<vip>/128`, and `external_ids:nb-id` equal to that `Load_Balancer` uuid. When the option is false, no IC route is required. A learned `loadbalancer` route whose `nb-id` is not a local `Load_Balancer` is a remote VIP and belongs to the learned-route check.

Additional required rows once a `Load_Balancer` matches:

| Check | Pass |
|---|---|
| Protocol | empty, or equal to `listener.protocol` ignoring case |
| Logical switch | `listener.subnet_uuid` is present, and a `Logical_Switch` named `network_<subnet>` exists. The switch `load_balancer` column, if the fetch includes it, contains this Load_Balancer uuid |
| VPC router | a router name contains `virtual_network_uuid` |
| Southbound | a `Load_Balancer` row with the same name or the same uuid exists |

Backend IPs are not indexed on the target. Do not require each `virtual_nic_uuid` to appear in `vips`. Target health is IDF only: print `health` and do not invent a healthy enum. An empty `health` is a miss.

`listener.subnet_uuid` empty is a miss. VIP empty is a miss.

### Load balancer misses

| where | condition |
|---|---|
| `atlas` | session uuid missing from `load_balancer_session.list` |
| `idf` | no `virtual_network_uuid`, no VIP, or no `listener.subnet_uuid` |
| `idf` | no target row for the session |
| `idf` | a target points at a missing session |
| `idf` | a target `health` is empty |
| `nb` | no attached `Load_Balancer` has a `vips` key for this VIP |
| `nb` | protocol is set on both sides and differs |
| `nb` | no `Logical_Switch` named `network_<subnet>` |
| `nb` | no router name contains the VPC uuid |
| `sb` | no Southbound `Load_Balancer` with that name or uuid |

A learned route with `origin=loadbalancer` is not a local-session miss and is not a local-session pass.

### Load balancer output

```
FVN lb: idf=<sessions> atlas=<sessions> targets=<n> missing=<n>
```

TSV:

```
session  name  vpc  vpc_name  vip  protocol  subnet  ovn_lb  match  detail
target   session  nic  vm  port  health  detail
```

Zero sessions prints `idf=0 atlas=0 targets=0 missing=0`.

The learned-route table is unchanged. Its `origin` column already shows `loadbalancer`. Those rows stay in `FVN learned`.

## Empty tables on this PC

Both sections pass today if implemented as specified: `bgp_session` exists and has 0 rows, `atlas_load_balancer_session` exists and has 0 rows, Atlas status is 0 for both lists. That pass does not exercise a populated session. The first PC that has sessions needs a re-read of:

- one `bgp_session` row's `status.state` raw value
- one received prefix as it appears on `Logical_Router_Static_Route` (`options` and `external_ids` keys only)
- one `Load_Balancer` `name`, `protocol`, `vips` key shape, and `external_ids` keys

Those three observations close the open joins. They do not change the IDF columns above.

## Out of scope

SMSP. Listener port inside `__zprotobuf__`. BGP password and route-map communities. Equating IDF `next_hop` with the OVN nexthop. Treating `origin=loadbalancer` learned routes as local sessions. Redirect chassis selection, which stays the existing rc check.

The gateway VM is not logged in to. It may be powered off. Routes, L2 stretch, and VTEP state are read from IDF, Atlas, and OVN on Prism Central. A powered-off gateway is not a miss.
