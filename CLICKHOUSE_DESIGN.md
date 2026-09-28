# ClickHouse design

Two databases hold one Panacea dump. `flow_policy` is the Flow port-set and the policy that owns it. `flow_ovn` is the OVN northbound and southbound path that enforces it. Neither ingest writes the other database.

Server: native `127.0.0.1:19000`, HTTP `127.0.0.1:8123`, user `default`.

Sources: `clickhouse_flow/schema.sql`, `clickhouse_flow/ingest.py`, `clickhouse_flow/portset_traffic.py`, `clickhouse_flow/compare.py`, `clickhouse_ovn/schema.sql`, `clickhouse_ovn/ingest.py`. Port-set hashing and the NIC verdict are in `PORTSET_DESIGN.md`.

## Engine rules

Every fact row carries `log_bundle_id`. Every table is `ReplacingMergeTree(updated_at)`, `PARTITION BY log_bundle_id`, with no `Nullable` columns. A missing UUID is `00000000-0000-0000-0000-000000000000`. A missing string is `''`.

`ORDER BY` starts with `log_bundle_id`, then a low-cardinality column when the table has one, then the UUID. Queries filter `log_bundle_id` first and read `FINAL` when they need the latest replacement row.

Re-ingest of one bundle is `ALTER TABLE … DROP PARTITION` for that `log_bundle_id`, then insert. Other bundles stay. `compare.py` does not `ALTER UPDATE`. It inserts a replacement row. `--reset-schema` drops the tables once and recreates them from `schema.sql`.

Inserts are JSONEachRow, 10k rows per batch. `flow_policy.portset` uses 50 because each row carries the NIC arrays.

An existing table created before a new column is brought forward with `ALTER TABLE … ADD COLUMN IF NOT EXISTS`. Those columns land at the end of the physical row. Inserts that rebuild a row use `SELECT p.* REPLACE (...)` so column order stays the order of the table being written. A positional `INSERT` that appends columns in the `schema.sql` order mis-assigns `traffic_in` onto `all_ports` on a table that already existed.

## `flow_policy`

Five tables. Identity of a port-set is `port_set_uuid`. Names are display.

### `bundle`

Catalog for the dump. `ORDER BY log_bundle_id`.

| Column | Type | Meaning |
|---|---|---|
| `log_bundle_id` | `UInt64` | Partition and filter |
| `dump_dir` | `String` | Local dump. The northbound file used to resolve address sets is `dump_dir/cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_nb.txt` |
| `cluster_uuid` | `UUID` | |
| `cluster_name` | `LowCardinality(String)` | |
| `pc_ip` | `String` | |
| `nos_version` | `String` | |
| `collected_at` | `DateTime64(3)` | |
| `updated_at` | `DateTime64(3)` | ReplacingMergeTree version |

### `portset`

One row per port-set UUID after ingest collapses every policy that hashed to that UUID. `ORDER BY (log_bundle_id, entity_type, port_set_uuid)`.

The row has no top-level `policy_name`. Every policy and rule that uses the hash is one element of `rule_u_sg`.

**Identity**

| Column | Type | Meaning |
|---|---|---|
| `port_set_uuid` | `UUID` | The row identity. The computed hash when ingest emitted it, otherwise the Atlas UUID |
| `computed_port_set_uuid` | `UUID` | Hash from the policy selector. Zero when Atlas has the object and the dump did not emit it |
| `atlas_port_set_uuid` | `UUID` | UUID from `port_set.list` / `port_set.get`. Zero when the hash is absent from Atlas |
| `applied_to_port_set_uuid` | `UUID` | Second UUID on a FLEX src/dest row: the applied-to entity group |
| `role` | `LowCardinality(String)` | `secured`, `src`, `dest`, `applied_to`, or `isolation_<n>` |
| `entity_type` | `LowCardinality(String)` | `VM`, `SUBNET`, `VPC`, or empty |
| `namespace_uuid` | `UUID` | Scope namespace that the hash was computed in |
| `virtual_network_uuid` | `UUID` | VPC the selector was clipped to, when the scope is a VPC list |
| `atlas_name` | `String` | Atlas display name |
| `vpc_name` | `LowCardinality(String)` | |

**Selector**

`entity_group_uuid`, `entity_group_name`, `reference_uuids`, `reference_names`, `vm_category_refs`, `subnet_category_refs`, `vpc_category_refs`, `vm_category_names`, `subnet_category_names`, `vpc_category_names`, `vm_ext_ids`, `subnet_ext_ids`, `subnet_list`, `exception_list`, `eg_address_grp`, `eg_exception_address_grp`, `effective_vpc_refs`, `effective_vpc_names`.

FLEX applied-to is the same shape with the `applied_to_` prefix: `applied_to_entity_group_uuid`, category refs, ext ids, subnet and exception lists, and the applied-to names.

**`rule_u_sg`**

`Array(Tuple(...))`. One tuple per policy plus rule.

| Field | Type | Values |
|---|---|---|
| `rule_uuid` | `UUID` | Dump rule `ext_id` |
| `sg_id` | `Array(UUID)` | Service-group UUIDs. Inline and multi-SG rows leave this empty of a synthetic id |
| `sg_ports` | `Tuple(tcp, udp, icmp, icmpv6)` | Each element is `Array(String)` of `start-end` or `type:code` |
| `policy_name` | `String` | Display name of the policy |
| `policy_uuid` | `UUID` | |
| `policy_type` | `LowCardinality(String)` | `app`, `isolation`, `quarantine` |
| `policy_mode` | `LowCardinality(String)` | `enforce`, `monitor`, `save`. Dump `APPLY` is stored as `enforce` |
| `flex_policy` | `UInt8` | `1` when `rule.type` is `FLEX` or `KFLEX` |
| `rule_priority` | `Int32` | FLEX `spec.priority`. Security Policy stores `0` |
| `type` | `LowCardinality(String)` | `secured_entity`, `end_point_src`, `end_point_dst` |

**NIC membership**

| Column | Type | Meaning |
|---|---|---|
| `computed_nic_uuids`, `atlas_nic_uuids` | `Array(UUID)` | Sets `compare.py` sorts and compares |
| `computed_nics`, `atlas_nics` | `Array(Tuple(vm_name, nic_uuid, subnet, vpc, ip, host_uuid, host, cluster_uuid, cluster))` | Display. Host from the VM `host.ext_id`. Cluster from `hosts.json` → `clusters.json` |
| `only_computed_nics`, `only_atlas_nics` | same 9-field tuple | Schema slot for the diff. The compare stamp writes them empty; the observer recomputes the UUID diff |
| `match_status` | `LowCardinality(String)` | `match` or `mismatch`. Empty until `compare.py` |
| `mismatch_kind` | `LowCardinality(String)` | `computed_without_atlas`, `atlas_without_computed`, `nic_set`, or empty on a match |
| `all_ports` | `UInt8` | `1` when the rule is isolation, allow-spec `NONE`, or all-protocol with no service group |

**`traffic_in` and `traffic_out`**

These are the schema columns added for allowed traffic. Both are

```text
Array(Tuple(
    priority Int32,
    action   LowCardinality(String),
    peers    Array(String),
    ports    Array(String)
)) DEFAULT []
```

`portset_traffic.py` fills them during ingest.

| Column | OVN match | Peer |
|---|---|---|
| `traffic_in` | `outport == @port_group_<uuid>` | `ip4.src` / `ip6.src`. Traffic allowed into the port-set |
| `traffic_out` | `inport == @port_group_<uuid>` | `ip4.dst` / `ip6.dst`. Traffic allowed out of the port-set |

The port-group token is `port_group_` plus `port_set_uuid` with `-` turned into `_`.

Stored actions are `allow`, `allow-related`, and `allow-stateless`. Drop ACLs are not copied onto these columns. They remain on `flow_ovn.ovn_acl`.

`peers` is `ANY` when the match has no address. When the match names an address set, `peers` is the `Address_Set.addresses` list from the northbound dump. An empty address list is stored as the address-set name, because there is no IP to write. `ports` is `tcp.dst 22`, `tcp.dst 15981-15990`, `icmp4.type 8`, or `ALL`.

`compare.py` copies `traffic_in` and `traffic_out` through the match stamp with `SELECT p.* REPLACE (...)`. It replaces `match_status`, `mismatch_kind`, `only_computed_nics`, `only_atlas_nics`, and `updated_at`.

`queries.sql` selects port-sets where either array is non-empty.

### `u_sg`

Service lookup. `ORDER BY (log_bundle_id, u_sg_id)`. `u_sg_id = uuid5(DNS namespace, "u_sg:" + kind + refs + inline ports + network-function UUID + action)`.

Columns: `sg_id`, `kind` (`sg`, `sg_list`, `inline`), `sg_uuids`, `sg_names`, `tcp_ports`, `udp_ports`, `icmp_types`, `icmp_v6_types`, `is_inline`, `is_all_ports`, `secured_group_action`, and the network-function UUID, name, failure handling, forwarding mode, HA mode, and `nic_pairs` `(vm_uuid, ingress_nic_uuid, egress_nic_uuid, high_availability_state, data_plane_health_status)`. Lists and inline services keep `sg_id` at the zero UUID.

### `vm_nic`

One row per NIC. `ORDER BY (log_bundle_id, nic_uuid)`.

`nic_uuid`, `vm_uuid`, `vm_name`, `subnet_uuid`, `subnet`, `vpc_uuid`, `vpc`, `ip`, `host_uuid`, `host`, `cluster_uuid`, `cluster`.

The NIC verdict resolves its arguments here. A VM name that matches several NICs is returned as a list of `nic_uuid` values. The verdict is for one NIC.

### `category`

`category_uuid` → `name` (`key:value` when the dump has both). `ORDER BY (log_bundle_id, category_uuid)`.

## `flow_ovn`

Skinny entity tables plus edge tables. ACL bodies stay in `ovn_acl`. Logical-switch and port-group membership are `ovn_acl_on_ls` and `ovn_acl_on_pg`. There is no address-set table. Address-set members are read from the northbound dump named by `bundle.dump_dir`.

`ovn_acl` columns: `acl_uuid`, `name`, `direction` (`from-lport` or `to-lport`), `action`, `match`, `priority`, `log`. `name` is empty in the reference dump. The policy name for an ACL is `flow_policy.portset.rule_u_sg.policy_name` on the port-set whose UUID is inside the match, not a column of `ovn_acl`.

`ORDER BY` after `log_bundle_id`:

| Table | ORDER BY | Grain |
|---|---|---|
| `bundle` | `(log_bundle_id)` | Same catalog columns as `flow_policy.bundle` |
| `ovn_ls` | `(ls_uuid)` | Logical switch. Name and `other_config` |
| `ovn_lsp` | `(type, ls_uuid, lsp_uuid)` | Switch port. `mac`, `ip4`, `ip6`, `addresses`, router-port option, `peer`, `nic_uuid` |
| `ovn_lr` | `(lr_uuid)` | Logical router. `enabled`, `has_nat` |
| `ovn_lrp` | `(lr_uuid, lrp_uuid)` | Router port. `mac`, `networks`, `peer`, `ha_chassis_group`, `is_ext_gw` |
| `ovn_acl` | `(direction, action, acl_uuid)` | ACL body |
| `ovn_acl_on_ls` | `(ls_uuid, acl_uuid)` | Switch to ACL |
| `ovn_pg` | `(pg_uuid)` | Port group. `name` is `port_group_<uuid>` for a port-set |
| `ovn_acl_on_pg` | `(pg_uuid, acl_uuid)` | Port group to ACL |
| `ovn_pg_port` | `(pg_uuid, lsp_uuid)` | LSP membership of a port group |
| `ovn_pbr` | `(lr_uuid, priority, pbr_uuid)` | Router policy. `match`, `action`, `nexthop`, `nexthops` |
| `ovn_nat` | `(lr_uuid, nat_uuid)` | `type`, `external_ip`, `logical_ip`, `logical_port`, `external_mac` |
| `ovn_vm` | `(vm_uuid)` | AHV domain. `name`, `host_ip`. Empty when the AHV dump was not collected |
| `ovn_vm_nic` | `(vm_uuid, nic_uuid)` | `mac`, `ip4`, `host_ip`, `lsp_uuid`, `ls_uuid` |
| `ovn_chassis` | `(chassis_uuid)` | `name`, `hostname` |
| `ovn_encap` | `(chassis_uuid, encap_uuid)` | `ip`, `encap_type` |
| `ovn_datapath` | `(kind, nb_uuid)` | Southbound datapath. `kind` is `ls` or `lr`. `tunnel_key` is the datapath key |
| `ovn_port_binding` | `(type, datapath_uuid, pb_uuid)` | `logical_port`, `chassis_uuid`, `mac`, `tunnel_key`, `up` |
| `ovn_mac_binding` | `(datapath_uuid, ip)` | ARP/ND cache. `logical_port`, `mac` |
| `ovn_ha_chassis` | `(group_uuid, chassis_name)` | Gateway HA. `group_name`, `priority` |
| `ovn_edge_ls_lr` | `(ls_uuid, lr_uuid, lsp_uuid)` | Router LSP joined to the router port |
| `ovn_edge_lr_lr` | `(via, lr_a, lr_b, via_ls_uuid)` | Routers meeting by `peer` or by a transit switch |
| `ovn_ls_stretch` | `(ls_uuid, chassis_uuid)` | L2 Geneve stretch. `hostname`, `encap_type`, `encap_ip`, `vif_count` |

Join keys written by ingest:

- `Logical_Switch.ports[]` = `ovn_lsp.lsp_uuid`. `Logical_Router.ports[]` = `ovn_lrp.lrp_uuid`.
- `Logical_Switch.acls[]` and `Port_Group.acls[]` land in the edge tables.
- `Port_Group.ports[]` lands in `ovn_pg_port`.
- `Datapath_Binding.external_ids` `logical-switch` / `logical-router` = `ovn_datapath.nb_uuid`.
- `Port_Binding.logical_port` is the LSP or LRP name.
- `Chassis.encaps[]` = `ovn_encap.encap_uuid`.

`trace.py` walks `ovn_edge_ls_lr` and `ovn_edge_lr_lr`. The port-group name `port_group_<uuid with '-' as '_'>` is the same UUID as `flow_policy.portset.port_set_uuid`.

## What a NIC-to-NIC verdict reads

`skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py` does not add a table. It reads the tables above.

| Question | Read |
|---|---|
| Which NIC | `flow_policy.vm_nic` by NIC uuid, IP, or VM name |
| Which port-sets | `flow_policy.portset` rows whose `atlas_nics` or `computed_nics` contain that NIC |
| Policy name | `rule_u_sg.policy_name`, `policy_type`, `policy_mode` on that row, plus `vm_category_names` |
| Outgoing ACLs | `flow_ovn.ovn_acl` where `direction = from-lport` and `inport` is a port group of the source NIC |
| Incoming ACLs | `flow_ovn.ovn_acl` where `direction = to-lport` and `outport` is a port group of the destination NIC |
| Peer addresses | Northbound `Address_Set` under `bundle.dump_dir`. The peer label is the port-set whose NIC addresses cover that list |

`traffic_in` and `traffic_out` are the allow side of the same rules, already resolved to IPs, for a single port-set. The NIC verdict also needs the drops, so it reads `ovn_acl` rather than only those two columns. Highest priority on each stage wins. `allow`, `allow-related`, and `allow-stateless` allow the packet. `drop` denies it when `policy_mode` is `enforce`. A `monitor` drop is reported and the verdict stays allowed.

## Commands

End to end, and each stage on its own, are in [PORTSET_DESIGN.md](PORTSET_DESIGN.md) under "How to trigger".

```text
python3 clickhouse_flow/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166
python3 clickhouse_ovn/ingest.py --dump_dir /path/to/dump --log_bundle_id 159166
python3 skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py \
  --log_bundle_id 159166 --src <nic-or-ip> --dst <nic-or-ip> --port 80 --proto tcp \
  --out /tmp/verdict
```
