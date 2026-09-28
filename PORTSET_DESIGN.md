# Port-set creation and verification

How a Flow port-set UUID is produced from a policy dump, how Atlas membership is joined to that UUID, how the two ClickHouse trees decide match, leftover, and path impact, and how two VM NICs plus one L4 port become an allow or deny verdict with the policy name on each side.

Sources: `clickhouse_flow` (`ingest.py`, `compare.py`, `observe_leftovers.py`, `update_policy_port_sets.py`, `portset_traffic.py`, `schema.sql`), `clickhouse_ovn` (`dataplane.py`, `trace.py`), and `skills/network-services/nic-traffic-verdict`. The ClickHouse schema for both databases is `CLICKHOUSE_DESIGN.md`. Identity is the port-set UUID. Names are display labels.

## What a port-set is

A port-set is the Atlas object that holds the NICs selected by one policy side: secured group, source, destination, FLEX applied-to, or an isolation group. OVN attaches the same UUID as a port group (`port_group_<uuid with underscores>`). Address groups are a different object (an address-set). They do not become port-sets.

`flow_policy.portset` stores one row per UUID:

| Column | Meaning |
|---|---|
| `port_set_uuid` | The identity. Computed hash when ingest emitted it, otherwise the Atlas UUID. |
| `computed_port_set_uuid` | Hash from the policy selector. Zero UUID when Atlas has the object and the dump did not emit it. |
| `atlas_port_set_uuid` | UUID from `port_set.list` / `port_set.get`. Zero UUID when the hash is absent from Atlas. |
| `applied_to_port_set_uuid` | Second UUID on a FLEX src/dest row: the applied-to entity group. |
| `computed_nic_uuids` / `atlas_nic_uuids` | NIC membership on each side. |
| `rule_u_sg` | Every policy+rule that uses this hash. The row itself has no policy or rule column. |

Zero UUID `00000000-0000-0000-0000-000000000000` means that side is absent.

## How a port-set UUID is created

Ingest does not call Atlas. It rebuilds the UUID Atlas stored, from the dump, with the same hash Atlas and Salus use.

### Scope namespace

The hash namespace comes from the policy scope and from `unique_uuids.json`.

| Policy scope | Security Policy namespace | FLEX namespace |
|---|---|---|
| `GLOBAL`, `kGlobal`, `ALL_VPC` | `global_unique_uuid` | literal `global-scope-unique-id` |
| `ALL_VLAN`, `kAllVlan` | `vlan_unique_uuid` | literal `vlan-scope-unique-id` |
| `VPC_AS_CATEGORY` | first `scope_references` UUID | same UUID |
| `VPC_LIST`, `VPC` | first `vpc_references` (else `scope_references`) | same UUID |

CMSP reads the two scope UUIDs with `zkcat`:

- `/appliance/logical/flow/vlan_unique_uuid`
- `/appliance/logical/flow/global_unique_uuid`

SMSP reads the same keys from ZooKeeper inside the Atlas pod. The dump records which source it used (`cmsp_pc_zk` or `smsp_atlas_zk`). A non-default `project_ext_id` is appended to the hash body as `:project:<uuid>`. The all-zero project is omitted.

Policies in `SAVE` are skipped. They are not programmed, so they do not create port-sets.

### Which selector becomes a port-set

`selectors_from_spec` walks each rule spec and emits `(role, selector)` pairs.

Secured group (either branch):

1. `secured_group_category_references`, typed by `secured_group_category_associated_entity_type` (`VM` / `SUBNET` / `VPC`).
2. Else `secured_group_entity_group_reference`.

Source and destination, FLEX (`rule.type` `FLEX` or `KFLEX`):

1. `src_` / `dest_entity_group_reference` (or the references list).
2. Else allow-any (`should_allow_any_src` / `should_allow_any_dst`, or `src_allow_spec` / `dest_allow_spec` in `ALL` or `NONE`).
3. Else a side subnet (`value` + `prefix_length`).
4. Else an address group, and only when the dump already expanded that group to CIDRs.

Source and destination, Security Policy (`APPLICATION`, intra-group, quarantine, isolation rules that are not FLEX):

1. Side subnet.
2. Else address group with dump CIDRs.
3. Else side category references, typed by `*_category_associated_entity_type`.
4. Else side entity group.
5. Else allow-any.

FLEX applied-to:

- `applied_to_entity_group_references` present and non-empty: one `applied_to` port-set, hashed in the policy scope.
- Key missing: UI Global applied-to. No port-set is emitted.
- Key present and empty: no applied-to selector.

Isolation:

- `first_isolation_group` / `second_isolation_group` as VM category refs (`isolation_a`, `isolation_b`).
- Nested `spec.isolation_groups[]`: category refs or an entity group (`isolation_0`, …). Isolation groups hash as secured entities, not as endpoint address-sets.

A FLEX rule with no hashable selector (Default Workload) is hashed as dest allow-any: the empty Go slice `[]`.

### Selectors that do not become a port-set

| Case | Result |
|---|---|
| Security Policy allow-any | Atlas token `all`. No hashed UUID. Counted as `allow_all`. |
| FLEX allow-any | Real port-set. Body is `[]`. |
| FLEX endpoint that is an entity group plus CIDRs | Address-set path. `port_set_uuid` returns empty. |
| Security Policy src/dest entity group with no VM, subnet, or VPC category and no direct VM or subnet | AG/NA. Counted as `ag_na`. |
| Kube-only entity group (`KUBE*` members and no VM/SUBNET/VPC) | Skipped. Counted as `kube`. |
| Address group or raw subnet with no category or entity-group refs | No port-set. Address-set UUID is `uuid5(entity UUID, "IPv4"\|"IPv6")`. |
| Missing scope namespace | Counted as `no_hash`. |

### Hash body

Refs are sorted. Category entity types other than `VM` and `EG` append the Atlas selection suffix: `:kVM` is not used for entity type `VM`; `SUBNET` appends `:kSubnet`; `VPC` appends `:kVPC`.

Security Policy (uuid5):

```text
body = Python list of refs with a u-prefix on each quoted token
       e.g. [u'<uuid-a>', u'<uuid-b>']
       + optional :kSubnet or :kVPC
       + optional :project:<project-uuid>
port_set_uuid = uuid5(UUID(scope namespace), body)
```

The `u` prefix matches the Python 2 `str(sorted(list))` form Atlas hashes (`u'…'`), applied by rewriting `'…'` tokens. Allow-any on this path is not hashed; the refs would have been `["all"]`.

FLEX (MD5, Salus):

```text
body = Go slice, space-separated, sorted
       e.g. [<uuid-a> <uuid-b>]   or   []
       + optional category suffix and :project:
port_set_uuid = UUID( MD5( "Salus" + scope_namespace + body ) )
```

`ingest.py` uses the Salus constant `Salus`. `update_policy_port_sets.py` uses `salus` and also runs the `u'` rewrite on the Go-slice body. Those two strings hash differently. ClickHouse verification follows `ingest.py`.

`update_policy_port_sets.py` is the on-PC annotator. It walks proto `rules_list` components (`endpoint`, `secured_group`, `src_endpoint`, `dest_endpoint`, isolation groups), skips `kTypeAll` / `kTypeNone`, writes `port_set` then `ip_list` into `/tmp/policy.json`, and can insert `port_set_uuid` into the proto text. IP lists come from `port_set_ips.json` / `vms_port_set.json` produced by `vm_host_collect_port_set.py`. That file is a catalog of the hash, not the Atlas-vs-computed check.

### Worked shapes

VM category, ALL_VLAN Security Policy, default project:

```text
uuid5(vlan_unique_uuid, "[u'<category-uuid>']")
```

Subnet category, same scope:

```text
uuid5(vlan_unique_uuid, "[u'<category-uuid>']:kSubnet")
```

Entity group, VPC_LIST:

```text
uuid5(<first vpc uuid>, "[u'<eg-uuid>']")
```

Same entity group on a FLEX rule in GLOBAL scope:

```text
UUID(MD5("Salus" + "global-scope-unique-id" + "[<eg-uuid>]"))
```

FLEX allow-any:

```text
UUID(MD5("Salus" + <flex scope id> + "[]"))
```

Non-default project appends `:project:<project-uuid>` before the hash in every case above.

### NIC membership on the computed side

After the UUID exists, `match_nics` fills `computed_nic_uuids` from `vms.json`.

| Selector contents | NICs |
|---|---|
| `vm_ext_ids` or `subnet_ext_ids` | Union of NICs on those VMs or subnets. |
| VM category refs only | Intersection of NICs tagged with every listed VM category. |
| Subnet category refs only | Intersection of NICs on subnets tagged with every listed subnet category. |
| Both VM and subnet categories | Intersection of the two sets. |
| VPC category refs only | NICs whose VPC carries every listed VPC category. |
| CIDRs (`subnet_list`) | NICs whose learned or configured IPs sit in the CIDRs and outside `exception_list`. |
| `all`, `any`, or allow-any | Empty computed NIC list. Compare treats category names `all` or `any` as NIC-equal. |

Entity groups are expanded first (`expand_entity_group`): category refs, direct VM/subnet ext ids (including NAME and REGEX), address-group CIDRs, FQDN resolutions, and except-config CIDRs.

Scope then clips the set:

- `applied_to`: no VPC/VLAN clip. Membership is global.
- `secured` and `isolation_*`: drop VLAN Basic NICs (`advance_vlan` / `is_advanced_networking` false). Overlay and advanced VLAN stay.
- `ALL_VLAN`: keep NICs in the placeholder VPC `00000000-0000-0000-0000-000000000001`.
- `GLOBAL`, `ALL_VPC`, `VPC_AS_CATEGORY`: no VPC clip.
- `VPC_LIST`: keep NICs in that VPC.

IP version follows the policy (`is_ipv4_address_scope`, `is_ipv6_address_scope`, `is_ipv6_traffic_allowed`) and the rule `ip_version`. Link-local addresses are kept unless the dump sets `link_local` false.

### Row assembly

1. Each successful selector is a component carrying `port_set_uuid`, role, selector columns, and one `rule_u_sg` tuple (`end_point_src`, `end_point_dst`, or `secured_entity`; policy type `app` / `isolation` / `quarantine`; mode `enforce` / `monitor` / `save`, with dump `APPLY` stored as `enforce`).
2. On a FLEX rule, the applied-to row is copied onto the src and dest rows as `applied_to_*`. Role `applied_to` remains its own row so Atlas can match that second UUID.
3. Components collapse to one row per `port_set_uuid`. NIC UUID lists are unioned. `rule_u_sg` keeps every policy+rule.
4. `port_set_list.json` and `port_set_get.json` are indexed by UUID. A hit sets `atlas_port_set_uuid` to the same UUID and copies `virtual_nic_uuid_list` into `atlas_nic_uuids`, plus `name` and `virtual_network_uuid`.
5. An Atlas UUID with no computed hash is inserted as its own row: `computed_port_set_uuid` is zero, `atlas_port_set_uuid` is the Atlas UUID, computed NICs are empty.

`flow_policy.vm_nic` and `flow_policy.category` are lookup tables. Re-ingest drops only that `log_bundle_id` partition.

## How a port-set is verified

Verification is UUID equality, then NIC-UUID set equality. A matching name on a different UUID is a different object.

### 1. Presence, written at ingest

| `computed_port_set_uuid` | `atlas_port_set_uuid` | Meaning |
|---|---|---|
| non-zero | same non-zero UUID | UUID match. NIC sets are checked next. |
| non-zero | zero | Computed hash missing from Atlas. Critical. |
| zero | non-zero | Atlas leftover. The dump did not emit this UUID. |

### 2. Scorecard (`compare.py`)

`compare.py` reads ClickHouse only. For each `port_set_uuid` it takes any non-zero computed UUID, any non-zero Atlas UUID, and compares the flattened NIC UUID arrays. NIC arrays also count as equal when `vm_category_names` or `vpc_category_names` contains `all` or `any`.

`match_fields` then stamps a replacement row (`ReplacingMergeTree`, not `ALTER UPDATE`):

| Condition | `match_status` | `mismatch_kind` |
|---|---|---|
| Both UUIDs present and NIC sets equal | `match` | empty |
| Computed present, Atlas zero | `mismatch` | `computed_without_atlas` |
| Atlas present, computed zero | `mismatch` | `atlas_without_computed` |
| Both present, NIC sets differ | `mismatch` | `nic_set` |

Overall **PASS** requires all of the following:

- Every comparable port-set is `match`.
- `computed_without_atlas` count is 0.
- `atlas_without_computed` count is 0 after the ignore class below.
- `nic_set` count is 0.
- Every `isolation*` row has the hash present in Atlas and `match_status = match`.
- At least one comparable port-set exists.

Ignore class (scorecard and leftover observer). These rows stay in the table and are excluded from the fail counts:

- Atlas name starts with `K8s_` (`compare.py`). The observer also ignores names matching `k8s`, `kubernetes`, or `cilium_vlan_scope`.
- Name starts with `Quarantine` and `atlas_nic_uuids` is empty.

`only_computed_nics` and `only_atlas_nics` are stored empty by the stamp. The scorecard uses `mismatch_kind` and UUID presence. NIC diffs are computed again by the leftover observer.

### 3. Leftover explanation (`observe_leftovers.py`)

This pass explains UUIDs that failed presence. It loads leftovers from ClickHouse (`mismatch` rows where exactly one side is zero) or from `portset.jsonl` without querying ClickHouse.

For each leftover UUID it reverse-hashes every dump category (as `VM`, `SUBNET`, and `VPC`), every entity group (as `EG`), FLEX allow-any (empty refs), and address-set hashes (`uuid5(entity, "IPv4"|"IPv6")`). Namespaces tried: VLAN uuid, global uuid, the FLEX scope literals, each VPC uuid, each policy `scope_references` uuid. Projects tried: the zero project and every policy project.

The note is one of:

- Reverse-hash hits an entity the dump policies never reference, so ingest cannot emit the UUID.
- Reverse-hash hits selector UUIDs that policies do reference, but no programmed rule emitted this exact hash (scope, FLEX vs Security Policy, or project differs).
- Reverse-hash hits an address-set, which is not a port-set row.
- No dump category, entity group, or address group produces this UUID.
- NIC UUID in computed and missing in Atlas, or the reverse: a NIC bug. Reported even when the port-set UUID itself is one-sided.

Atlas-missing (`computed_without_atlas`) is the critical class. Atlas leftover (`atlas_without_computed`) is the class OVN path reports call out.

### 4. Path check (`clickhouse_ovn`)

OVN verification does not recompute the hash. It reads the already-stamped `portset.jsonl` and asks whether the NICs on a traced path sit on a bad port-set.

`trace.py` walks VM NIC → LSP → logical switch → routers → destination, then calls `portset_issues_md` with the source NIC UUID and the destination NIC UUID. The section in the path markdown is "Port-set issues (Atlas-only leftovers)".

For those NICs, and for the whole dump:

- Count Atlas-only port-sets after dropping K8s and empty-Quarantine noise (`leftover_ignore.py`).
- List each leftover UUID, Atlas name, role, and `mismatch_kind`.
- List every port-set (match or mismatch) that contains a path NIC, with Atlas and computed NIC counts.
- Say whether a path NIC is a member of an `atlas_without_computed` port-set.
- Say whether a path NIC is Atlas-only or computed-only inside a port-set that otherwise matched.

ACL interpretation uses the same file:

- `@port_group_<underscored uuid>` is looked up as a port-set. The label is category, Atlas name, role, and NIC count. A drop ACL at priority 1060 or higher is described as isolation: that applied-to group cannot reach the secured address-set.
- `$address_set_…` is labeled by IP overlap with port-set NIC IPs (best overlap, at least 3 addresses or one third of the set). That label is a display join. The port-set match itself stays UUID-based.

`flow_ovn` is a separate database. Path tracking does not write `flow_policy`.

### 5. Path traversal (`nic_traffic.py`)

This is the OVN check for one forward packet. It does not recompute a port-set hash. It joins the NIC to the subnet, the switch, the routers, and the external gateway, then applies the ACLs.

Join, loaded at ingest into `ovn_switch`, `ovn_subnet`, `ovn_router`, and `ovn_l2gw`. Each of those rows keeps the northbound object and the southbound binding together.

`flow_policy.vm_nic` → `ovn_subnet` → `ovn_switch` → `ovn_edge_ls_lr` / `ovn_edge_lr_lr` → `ovn_router` → external gateway.

What the markdown verifies, in order:

| Check | Where it comes from |
|---|---|
| VPC, subnet, prefix, VLAN, VM MAC, DHCP gateway MAC | `vm_nic` and `ovn_subnet` |
| Host and Geneve IP | `ovn_chassis` and `ovn_encap` for the VM port binding |
| Switch tunnel key and port tunnel key, decimal and 6-digit hex | `ovn_switch.sb_tunnel_key`, `ovn_port_binding.tunnel_key` |
| Every router when the NICs are on different switches | Shortest path on `ovn_edge_ls_lr` and `ovn_edge_lr_lr` |
| Router port MAC and address, including the logical-router MAC, which is not the DHCP gateway MAC | `ovn_router.ports` |
| External gateway IP, MAC, redirect-chassis host, Geneve IP, chassis, chassis name, HA group, HA priority | External router port plus `ovn_ha_chassis` |
| Tunnel id on the hop into the gateway | Transit switch between the tenant router and the gateway router |
| Tunnel id on the external hop | External switch that both gateway ports sit on |
| Tunnel id on the hop back to the destination router | Transit switch between the destination gateway and the destination tenant router |
| Drop cookie and rule number, drawn on the switch that enforces it | First 32 bits of the ACL uuid (OVN stage-hint). `to-lport` is the destination switch. `from-lport` is the source switch. |
| TAP and Geneve capture commands | VM logical port on that host, and UDP 6081 toward the next Geneve IP |
| Source outgoing ACLs and destination incoming ACLs | `ovn_acl`. Peer addresses are a separate IP-mapping table. |
| Allow policy and deny policy | Highest matching row on each stage. An enforce drop denies. A monitor drop is reported and the verdict stays allowed. |

The mermaid is three boxes when the path leaves the VPC: source VPC, external gateways, destination VPC. A host that is both a VM host and a redirect chassis is named once and called out as two roles.

`trace.py` in section 4 is the older composite path and the Atlas-leftover note. `nic_traffic.py` is the traversal above. Commands for both, run together or one stage at a time, are under [How to trigger](#how-to-trigger).

## ClickHouse schema

Two databases on the same server. Native `127.0.0.1:19000`, HTTP `127.0.0.1:8123`, user `default`. `clickhouse_ovn` never writes `flow_policy`. `clickhouse_flow` never writes `flow_ovn`.

Shared rules, from `clickhouse_flow/schema.sql` and `clickhouse_ovn/schema.sql`:

- Every fact row carries `log_bundle_id` (`UInt64`). One Panacea dump is one id.
- `PARTITION BY log_bundle_id`. Re-ingest is `ALTER TABLE … DROP PARTITION <id>`, then insert. Other dumps stay.
- `ENGINE = ReplacingMergeTree(updated_at)`. A later insert of the same ORDER BY key replaces the older row at merge. `compare.py` stamps match columns this way. There is no `ALTER UPDATE` and no `ALTER DELETE`.
- No `Nullable`. A missing UUID is `00000000-0000-0000-0000-000000000000`. A missing string is `''`. A missing flag is `0`.
- `ORDER BY` starts with `log_bundle_id` (the filter), then a low-cardinality type or direction, then the UUID.
- Native types: `UUID`, `UInt64`, `UInt32`, `UInt16`, `UInt8`, `Int32`, `DateTime64(3)`, `LowCardinality(String)` for enums (`role`, `entity_type`, `direction`, `action`, `type`). IPv4 and IPv6 stay `String` because the same column holds addresses and CIDRs.
- Ingest is `CREATE DATABASE IF NOT EXISTS` plus `CREATE TABLE IF NOT EXISTS`. `--reset-schema` drops the database tables once, then recreates them. Inserts are JSONEachRow, 10k rows per batch (`flow_policy.portset` uses 50).

### `flow_policy` — port-set identity and the Atlas check

| Table | ORDER BY | Grain |
|---|---|---|
| `bundle` | `(log_bundle_id)` | Dump catalog: `dump_dir`, `cluster_uuid`, `cluster_name`, `pc_ip`, `nos_version`, `collected_at` |
| `portset` | `(log_bundle_id, entity_type, port_set_uuid)` | One port-set UUID |
| `u_sg` | `(log_bundle_id, u_sg_id)` | One unique service (dump SG, SG list, or inline ports) |
| `vm_nic` | `(log_bundle_id, nic_uuid)` | One VM NIC |
| `category` | `(log_bundle_id, category_uuid)` | One category display name |

`portset` is the only table the scorecard reads. Policy and rule identity live inside `rule_u_sg`, not as row columns. There is no `policy_uuid` or `rule_uuid` column on the row.

**Identity and presence**

| Column | Type | Role |
|---|---|---|
| `port_set_uuid` | `UUID` | Row identity. Computed hash, or the Atlas UUID when the hash was not emitted. |
| `computed_port_set_uuid` | `UUID` | Hash from `ingest.py`. Zero when the row is Atlas-only. |
| `atlas_port_set_uuid` | `UUID` | UUID from `port_set.list` / `port_set.get`. Zero when Atlas has no such object. |
| `applied_to_port_set_uuid` | `UUID` | FLEX applied-to hash copied onto src/dest. Zero on Security Policy rows and on the applied-to row itself. |
| `role` | `LowCardinality(String)` | `secured`, `src`, `dest`, `applied_to`, `isolation_a`, `isolation_b`, `isolation_<n>`. Empty on an Atlas-only row. |
| `entity_type` | `LowCardinality(String)` | `VM`, `SUBNET`, `VPC`, or `EG`. Part of the sort key. |
| `namespace_uuid` | `UUID` | Policy scope UUID stored on the row: VLAN unique UUID, global unique UUID, or the VPC UUID. The FLEX hash itself uses the literals `vlan-scope-unique-id` / `global-scope-unique-id` as the MD5 namespace. Those literals are not written in this column. |
| `virtual_network_uuid` | `UUID` | Atlas `virtual_network_uuid` when the list/get record has one. |

**Selector that was hashed**

| Column | Type |
|---|---|
| `entity_group_uuid`, `entity_group_name` | `UUID`, `String` |
| `reference_uuids`, `reference_names` | `Array(UUID)`, `Array(String)` |
| `vm_category_refs`, `subnet_category_refs`, `vpc_category_refs` | `Array(UUID)` |
| `vm_category_names`, `subnet_category_names`, `vpc_category_names` | `Array(String)` |
| `vm_ext_ids`, `subnet_ext_ids` | `Array(UUID)` |
| `subnet_list`, `exception_list` | `Array(String)` CIDRs |
| `eg_address_grp`, `eg_exception_address_grp` | `Array(String)` address-group names expanded into the EG |
| `effective_vpc_refs`, `effective_vpc_names` | VPCs whose categories contain every selector VPC category |
| `applied_to_entity_group_uuid` and `applied_to_*` refs, ext ids, lists, names | Same shape as the selector columns, copied from the FLEX applied-to entity group |

**Rules that use this hash.** `rule_u_sg` is `Array(Tuple(...))`:

| Tuple field | Type | Values |
|---|---|---|
| `rule_uuid` | `UUID` | Dump rule `ext_id` |
| `sg_id` | `Array(UUID)` | Dump service-group UUIDs. Inline and multi-SG lists keep this empty of a synthetic id; the lookup row in `u_sg` uses zero `sg_id` for those. |
| `sg_ports` | `Tuple(tcp, udp, icmp, icmpv6)` | Each element is `Array(String)` (`start-end` or `type:code`) |
| `policy_name`, `policy_uuid` | `String`, `UUID` | |
| `policy_type` | `LowCardinality(String)` | `app`, `isolation`, `quarantine` |
| `policy_mode` | `LowCardinality(String)` | `enforce`, `monitor`, `save`. Dump `APPLY` is stored as `enforce`. |
| `flex_policy` | `UInt8` | `1` when `rule.type` is `FLEX` or `KFLEX` |
| `rule_priority` | `Int32` | FLEX `spec.priority`. Security Policy stores `0`. |
| `type` | `LowCardinality(String)` | `secured_entity`, `end_point_src`, `end_point_dst` |

`u_sg` is the service lookup, keyed by `u_sg_id = uuid5(DNS namespace, "u_sg:" + kind + refs + inline ports + network-function UUID + action)`. Columns: `sg_id`, `kind` (`sg` / `sg_list` / `inline`), `sg_uuids`, `sg_names`, `tcp_ports`, `udp_ports`, `icmp_types`, `icmp_v6_types`, `is_inline`, `is_all_ports`, `secured_group_action`, and the network-function UUID, name, failure handling, forwarding mode, HA mode, and `nic_pairs` `(vm_uuid, ingress_nic_uuid, egress_nic_uuid, high_availability_state, data_plane_health_status)`.

**NIC membership and the verdict**

| Column | Type | Role |
|---|---|---|
| `computed_nic_uuids`, `atlas_nic_uuids` | `Array(UUID)` | Sets `compare.py` sorts and compares |
| `computed_nics`, `atlas_nics` | `Array(Tuple(vm_name, nic_uuid, subnet, vpc, ip, host_uuid, host, cluster_uuid, cluster))` | Display. Host from VM `host.ext_id`. Cluster from `hosts.json` → `clusters.json`. |
| `only_computed_nics`, `only_atlas_nics` | same 9-field tuple | Schema slot for the diff. The stamp writes them empty; the observer recomputes the UUID diff. |
| `match_status` | `LowCardinality(String)` | `match` or `mismatch`. Empty until `compare.py`. |
| `mismatch_kind` | `LowCardinality(String)` | `computed_without_atlas`, `atlas_without_computed`, `nic_set`, or empty on a match |
| `atlas_name`, `vpc_name` | `String`, `LowCardinality(String)` | Atlas display name and VPC name |
| `all_ports` | `UInt8` | `1` when the rule is isolation, allow-spec `NONE`, or all-protocol with no service group |
| `traffic_in` | `Array(Tuple(priority Int32, action LowCardinality(String), peers Array(String), ports Array(String)))` | Allow rules for traffic **into** this port-set |
| `traffic_out` | same tuple | Allow rules for traffic **out of** this port-set |
| `updated_at` | `DateTime64(3)` | ReplacingMergeTree version |

`traffic_in` and `traffic_out` are the port-set form of `policy_port_set/ovn_port_set_traffic.sh`. OVN names the port-set `port_group_<uuid with '-' turned into '_'>`.

| Direction | ACL match | Who the peer is |
|---|---|---|
| Into the port-set (`traffic_in`) | `outport == @port_group_<uuid>` | `ip4.src` / `ip6.src` |
| Out of the port-set (`traffic_out`) | `inport == @port_group_<uuid>` | `ip4.dst` / `ip6.dst` |

Stored actions are `allow`, `allow-related`, and `allow-stateless`. Drop ACLs stay in `flow_ovn.ovn_acl` and are not copied onto the port-set row. `peers` is `ANY` when the match has no address, the address-set name when the NB dump has no addresses for it, or the `Address_Set.addresses` list when the NB dump resolves `$address_set_…`. `ports` is `tcp.dst 22`, `tcp.dst 15981-15990`, `icmp4.type 8`, or `ALL`. `clickhouse_flow/portset_traffic.py` fills both columns during ingest from `dump_dir/cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_nb.txt`, or from `flow_ovn.ovn_acl` when that file is absent. `compare.py` copies the columns through the match stamp.

`vm_nic` is the NIC lookup used to fill those tuples: `nic_uuid`, `vm_uuid`, `vm_name`, `subnet_uuid`, `subnet`, `vpc_uuid`, `vpc`, `ip`, `host_uuid`, `host`, `cluster_uuid`, `cluster`. `category` is `category_uuid` → `name` (`key:value` when the dump has both).

Queries always filter `log_bundle_id` first, then `port_set_uuid`. `queries.sql` is that lookup: one port-set, FLEX rows that carry `applied_to_port_set_uuid`, `role = 'applied_to'`, `rule_u_sg` unnested with `ARRAY JOIN`, `u_sg`, and one `vm_nic`.

### `flow_ovn` — NB/SB path the port-set is enforced on

Port-set verification on a path does not join these tables in SQL. `trace.py` reads `flow_ovn` for the hop list and reads `flow_policy/portset.jsonl` for the UUID check. The join key in the report is the port-group name: `port_group_<port_set_uuid with '-' turned into '_'>` equals `flow_policy.portset.port_set_uuid`.

| Table | ORDER BY (after `log_bundle_id`) | Grain | What it holds |
|---|---|---|---|
| `bundle` | `(log_bundle_id)` | Dump catalog | Same catalog columns as `flow_policy.bundle` |
| `ovn_ls` | `(ls_uuid)` | Logical switch | Name, `other_config` pairs |
| `ovn_lsp` | `(type, ls_uuid, lsp_uuid)` | Switch port | `mac`, `ip4`, `ip6`, `addresses`, `options_router_port`, `options_network_name`, `peer`, `nic_uuid` |
| `ovn_lr` | `(lr_uuid)` | Logical router | `enabled`, `has_nat` |
| `ovn_lrp` | `(lr_uuid, lrp_uuid)` | Router port | `mac`, `networks`, `peer`, `ha_chassis_group`, `is_ext_gw` |
| `ovn_acl` | `(direction, action, acl_uuid)` | ACL body | `match`, `priority`, `log`. Direction is `from-lport` / `to-lport`. |
| `ovn_acl_on_ls` | `(ls_uuid, acl_uuid)` | LS → ACL | Edge. ACL body stays in `ovn_acl`. |
| `ovn_pg` | `(pg_uuid)` | Port group | `name`. This is the OVN face of a port-set when the name is `port_group_<uuid>`. |
| `ovn_acl_on_pg` | `(pg_uuid, acl_uuid)` | Port group → ACL | ACLs attached to the port-set's port group |
| `ovn_pg_port` | `(pg_uuid, lsp_uuid)` | Port-group membership | LSP UUIDs in that port group |
| `ovn_pbr` | `(lr_uuid, priority, pbr_uuid)` | Router policy | `match`, `action`, `nexthop`, `nexthops` |
| `ovn_nat` | `(lr_uuid, nat_uuid)` | NAT | `type`, `external_ip`, `logical_ip`, `logical_port`, `external_mac` |
| `ovn_vm` | `(vm_uuid)` | AHV domain | `name`, `host_ip` |
| `ovn_vm_nic` | `(vm_uuid, nic_uuid)` | NIC | `mac`, `ip4`, `host_ip`, `lsp_uuid`, `ls_uuid`. MAC joins the NIC to an LSP. LSP `name` `port_<uuid>` is not always the Acropolis NIC UUID. |
| `ovn_chassis` | `(chassis_uuid)` | Hypervisor | `name`, `hostname` |
| `ovn_encap` | `(chassis_uuid, encap_uuid)` | Tunnel endpoint | `ip`, `encap_type` (`geneve` in the reference dump) |
| `ovn_datapath` | `(kind, nb_uuid)` | SB datapath | `kind` is logical-switch or logical-router. `nb_uuid` is the NB UUID. `tunnel_key` is the datapath key. |
| `ovn_port_binding` | `(type, datapath_uuid, pb_uuid)` | SB port | `logical_port`, `chassis_uuid`, `mac`, `tunnel_key`, `up` |
| `ovn_mac_binding` | `(datapath_uuid, ip)` | ARP/ND cache | `logical_port`, `mac` |
| `ovn_ha_chassis` | `(group_uuid, chassis_name)` | Gateway HA | `group_name`, `priority`. Used because `Gateway_Chassis` is empty in the reference dump. |
| `ovn_edge_ls_lr` | `(ls_uuid, lr_uuid, lsp_uuid)` | LS–LR edge | Router LSP (`type=router`, `options:router-port=<LRP name>`) joined to the LRP |
| `ovn_edge_lr_lr` | `(via, lr_a, lr_b, via_ls_uuid)` | LR–LR edge | `via` is `peer` or a transit LS. This dump uses the transit LS (`gw-scale-out-network`); `LRP.peer` is empty. |
| `ovn_ls_stretch` | `(ls_uuid, chassis_uuid)` | L2 Geneve stretch | `hostname`, `encap_type`, `encap_ip`, `vif_count` |

NB join keys the ingest writes into those edges:

- `Logical_Switch.ports[]` = `ovn_lsp.lsp_uuid`. `Logical_Router.ports[]` = `ovn_lrp.lrp_uuid`.
- `Logical_Switch.acls[]` and `Port_Group.acls[]` land in `ovn_acl_on_ls` and `ovn_acl_on_pg`, not inside the ACL row.
- `Port_Group.ports[]` lands in `ovn_pg_port`.
- `Datapath_Binding.external_ids` `logical-switch` / `logical-router` = `ovn_datapath.nb_uuid`.
- `Port_Binding.logical_port` is the LSP or LRP name. `Port_Binding.datapath` and `.chassis` are the SB datapath and chassis UUIDs.
- `Chassis.encaps[]` = `ovn_encap.encap_uuid`.

`trace.py` BFS uses `ovn_edge_ls_lr` and `ovn_edge_lr_lr` only. VIF LSPs hang off `ovn_lsp` where `type` is empty. NAT and localnet mark a router or switch as external. The port-set section of the path report is filled from `portset.jsonl`, using NIC UUIDs from `ovn_vm_nic` and port-group UUIDs parsed out of `ovn_acl.match`.

## Traffic between two VM NICs

`skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py` answers one forward packet: source VM NIC, destination VM NIC, and one L4 port. It lists every port-set of the source NIC and the outgoing ACLs for that source, then every port-set of the destination NIC and the incoming ACLs for that destination, and then names the allow policy and the deny policy. TCP and UDP use the destination port. ICMP uses the type as `--port`. The skill is an atomic `network-services` skill (`skill_type`, `component`, `sub_component`, `keywords`) and lives under `skills/`, which is the corpus location.

The script reads the ingested bundle.

| Step | Source | What it contributes |
|---|---|---|
| Resolve the NIC | `flow_policy.vm_nic` | VM name and IP from a NIC uuid, an IP, or a VM name. A VM name that hits several NICs stops and lists the NIC uuids. |
| Membership | `flow_policy.portset` | Every port-set whose `atlas_nics` or `computed_nics` contain that NIC. `rule_u_sg` on that row supplies `policy_name`, `policy_type`, and `policy_mode`. |
| Rules | `flow_ovn.ovn_acl` | ACLs whose match names those port groups. |
| Peer addresses | Northbound `Address_Set` under the bundle `dump_dir` | IPs for each `$address_set_…` the candidate ACLs mention. An empty address list stays empty. |

Source port groups are the port-sets that contain the source NIC. Destination port groups are the port-sets that contain the destination NIC. The packet is source IP to destination IP.

| Stage | OVN direction | Port group that must match |
|---|---|---|
| Out of the source | `from-lport` | `inport == @port_group_…` of a source port-set |
| Into the destination | `to-lport` | `outport == @port_group_…` of a destination port-set |

On each stage the highest priority ACL whose addresses and port fit the packet wins. `allow`, `allow-related`, and `allow-stateless` allow it. `drop` denies it. A drop on either stage is the verdict when that port-set's `policy_mode` is `enforce`. A drop whose `policy_mode` is `monitor` is reported, and the verdict stays allowed. A lower-priority rule that also matches is reported on its own line and marked as not applying.

The policy name is `rule_u_sg.policy_name` on the port-set whose port group is in that ACL, together with `policy_type`, `policy_mode`, and the first `vm_category_names` entry. The peer is the port-set whose NIC addresses cover the address set on the other side of the match: `ip4.src` / `ip6.src` for traffic into the port-set, `ip4.dst` / `ip6.dst` for traffic out. When those addresses belong to no port-set, the peer is the IP list.

The allow line is the highest allow that matches both NICs and the port. When no allow covers the port, the line names the allow policy that matches the two NICs and states that this port is outside it. The deny line is the highest drop that matches. Both lines are printed for every verdict. When no allow matches the two NICs at all, the allow line says so. When no drop matches, the deny line says so.

Printed sections, in this order. Every port-set row and every ACL row is printed.

| Section | Content |
|---|---|
| Path | Mermaid. Each VPC is a box (host, VM MAC and IP, switch tunnel key, tenant router). External gateways are their own box (redirect-chassis host, external MAC, router tunnel key). Each hop is labeled with the tunnel id used on that hop. A denied verdict prints the OpenFlow cookie on the switch that drops the packet. |
| Endpoints | VPC, subnet, VLAN, VM MAC, DHCP gateway MAC, host, Geneve IP, switch tunnel key in hex, port tunnel key in hex |
| Routers and gateways | One row per router port on the path: MAC, address, tunnel key, hex |
| External gateways | One block per gateway: external IP and MAC, host, Geneve IP, chassis, chassis name, HA group, HA priority |
| Capture | TAP tcpdump on each VM host, and Geneve tcpdump (UDP 6081) on the host NIC toward the next Geneve IP |
| ACL source | Every `from-lport` rule. Columns: rule, action, ip, policy, category, peer, ports, matches. Peer addresses are not in this table. |
| ACL destination | Every `to-lport` rule. Same columns. |
| Verdict | Verdict, allow policy, deny policy. A deny also names the cookie, the rule number, and the switch. |
| IP mapping | One row per peer address. Prefix lengths stay on the address. |

The policy and peer text use the policy name and category. When the peer addresses belong to a port-set, the peer is that category and policy. When they belong to no port-set, the peer is the IP list. An address set whose OVN `addresses` list is empty is reported as having no addresses. The lines do not use `$address_set_…` or `@port_group_…` as the names.

The skill that runs this is `skills/network-services/nic-traffic-verdict/SKILL.md`. `scripts/nic_traffic.py` is the command.

Checked on bundle `159166`. Source NIC `192.168.254.130` (`inbound:inbound5`, VM `VPC_California_SJ_Pheonix_Customer_25_inbound_1`) to AppType:Apache_Spark NIC `192.168.1.23` (VM `VPC_California_SJ_Pheonix_Customer_29_FNS-L1-2_5`). `192.168.1.23` is also on two other NICs; this check uses `5620a7ae-7863-447f-8d94-cada1d746dad`. Both port-sets are `Global_Application_Policy1` (app, enforce).

Source outgoing ACLs are empty. The `inbound:inbound5` port-set has no `from-lport` rules. The decision is the destination incoming table on `AppType:Apache_Spark`:

| priority | action | peer | ports | tcp/5560 | tcp/5555 |
|---|---|---|---|---|---|
| 1060 | drop | AppType:Apache_Spark | all ports | no | no |
| 1052 | drop | AppType:Apache_Spark | all ports | no | no |
| 1050 | allow-related | inbound:inbound5 | tcp/udp ranges starting at `5558-5567` | yes | no |
| 1050 | allow-related | `192.168.253.133` and nine other addresses | tcp 22, tcp 80, tcp 1024, udp 22, icmp type 8 | no | no |
| 1045 | drop | any | all IPv4 ports | yes | yes |
| 1045 | drop | any | all IPv6 ports | no | no |

- `tcp/5560` is allowed. Allow policy: priority 1050 `allow-related` from `inbound:inbound5`. Deny policy: priority 1045 drop. The deny does not apply.
- `tcp/5555` is denied. Allow policy: the same priority 1050 allow, and `tcp/5555` is outside it (the first range starts at 5558). Deny policy: priority 1045 drop, all ports.

## How to trigger

ClickHouse is `127.0.0.1:19000`, user `default`. Databases are `flow_policy` and `flow_ovn`. A re-run of an ingest drops only that `log_bundle_id` partition. `--reset-schema` drops every bundle. Use it for the first migration, not for a refresh.

The verdict does not ingest. It reads tables that are already loaded. Load policy and OVN first, then run the verdict as many times as you want.

### End to end

One dump, then one verdict. Policy and OVN are separate ingests. The full OVN ingest also fills `ovn_switch`, `ovn_subnet`, `ovn_router`, and `ovn_l2gw`.

```text
python3 clickhouse_flow/ingest.py \
  --dump_dir /path/to/dump --log_bundle_id 159166

python3 clickhouse_ovn/ingest.py \
  --dump_dir /path/to/dump --log_bundle_id 159166

python3 skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py \
  --log_bundle_id 159166 \
  --src 192.168.254.130 \
  --dst b4e93b84-06ef-41bb-b834-061b2b65d632 \
  --port 80 --proto tcp \
  --out /tmp/nic_192_168_254_130__192_168_3_26_tcp80
```

`--out` writes `<stem>.json` and `<stem>.md`. Omit `--log_bundle_id` on the verdict to use the latest `flow_policy` bundle. `--src` and `--dst` take a NIC uuid, an IP, or a VM name. A VM name that matches several NICs prints the NIC uuids and exits. `--proto` is `tcp`, `udp`, or `icmp`. For icmp, `--port` is the ICMP type.

That run walks VM → subnet → switch → router → gateway, draws the mermaid, and prints the ACL tables. For the pair above the path is external, and tcp/80 is denied on the destination switch by rule 1045, cookie `0x65c25b48`.

### Part by part

Run only the stage you need. Later stages assume the earlier tables for that database are already loaded.

| Part | Command | Loads or answers | Leaves alone |
|---|---|---|---|
| Policy ingest | `python3 clickhouse_flow/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166` | `flow_policy` port-sets, VM NICs, categories | `flow_ovn` |
| Policy from JSONL | `python3 clickhouse_flow/ingest.py --from_jsonl /path/to/jsonl --log_bundle_id 159166` | Same tables when the PC JSON is absent | `flow_ovn` |
| Policy scorecard | `python3 clickhouse_flow/compare.py --log_bundle_id 159166` | PASS/FAIL on UUID and NIC match | No new rows |
| Leftover port-sets | `python3 clickhouse_flow/observe_leftovers.py --log_bundle_id 159166 --dump_dir /path/to/dump` | Why a computed port-set has no Atlas row | No verdict |
| OVN ingest | `python3 clickhouse_ovn/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166` | NB/SB tables, edges, and the four path tables | `flow_policy` |
| OVN without AHV | `python3 clickhouse_ovn/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166 --skip-ahv` | NB and SB | AHV host collect |
| OVN without SB | `python3 clickhouse_ovn/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166 --skip-sb` | Northbound only | Southbound bindings |
| Path tables only | `python3 clickhouse_ovn/path_tables.py --dump_dir /path/to/dump --log_bundle_id 159166` | `ovn_switch`, `ovn_subnet`, `ovn_router`, `ovn_l2gw` | Every other OVN table. Does not drop the bundle. |
| Path tables via ingest | `python3 clickhouse_ovn/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166 --only-path-tables` | Same four tables | Same as `path_tables.py` |
| Drop one bundle | `python3 clickhouse_ovn/ingest.py --drop-bundle 159166` | Removes that OVN partition and exits | Other bundles |
| Verdict only | `python3 skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py --log_bundle_id 159166 --src <nic-or-ip> --dst <nic-or-ip> --port 80 --proto tcp --out /tmp/verdict` | Mermaid, tunnel ids, gateway hosts, drop cookie, ACL tables | Does not ingest |
| Older path trace | `python3 clickhouse_ovn/trace.py --log_bundle_id 159166 --src <vm-or-mac-or-lsp> --dst <vm-or-mac-or-lsp-or-external>` | Composite upstream and downstream mermaid under `clickhouse_ovn/out/` | Not the NIC verdict |

`--nb /path/to/ovsdb-client_dump_nb.txt` on the verdict overrides the northbound dump used for address-set IPs. The default is `bundle.dump_dir` plus `cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_nb.txt`.

Column catalog for the four path tables: [clickhouse_ovn/PATH_TABLES.md](clickhouse_ovn/PATH_TABLES.md). The skill that runs the verdict is [skills/network-services/nic-traffic-verdict/SKILL.md](skills/network-services/nic-traffic-verdict/SKILL.md).
