# OVN NB/SB path tracking (`flow_ovn`)

ClickHouse database **`flow_ovn`** (do not touch `flow_policy`). Source is
`ovsdb-client dump` text from the CMSP OVN pair, plus AHV `virsh dumpxml`
for VM display names.

Identity is UUID. Names are display only.

## Dump table mapping

OVN dump names (not the user's shorthand):

| User term | Dump table | Role |
|---|---|---|
| LS | `Logical_Switch` | L2 broadcast domain |
| LSP | `Logical_Switch_Port` | VIF / router / localnet port on an LS |
| LR | `Logical_Router` | L3 VRF |
| LRP | `Logical_Router_Port` | Router interface (MAC + CIDR) |
| ACL | `ACL` | Match / action / direction / priority |
| PBR | `Logical_Router_Policy` | Policy-based route on an LR |
| Port group | `Port_Group` | Extra ACL attachment + port membership |
| NAT | `NAT` | SNAT / DNAT on a gateway LR |
| SB datapath | `Datapath_Binding` | `external_ids:logical-switch\|logical-router` → NB UUID |
| SB port | `Port_Binding` | `logical_port` name, chassis, type, MAC |
| Chassis | `Chassis` | Hypervisor; `encaps` → `Encap` |
| Encap | `Encap` | Geneve (this dump: `type=geneve`) |
| MAC bind | `MAC_Binding` | IP → MAC on a datapath |
| HA GW | `HA_Chassis_Group` / `HA_Chassis` | Gateway chassis for LRPs |
| LB | `Load_Balancer` | Absent in this dump (header only) |
| Gateway_Chassis | `Gateway_Chassis` | Empty in this dump |

**Join keys**

- LS.ports[] = LSP._uuid; LR.ports[] = LRP._uuid.
- LS.acls[] and Port_Group.acls[] = ACL._uuid (edge tables, not nested blobs).
- Port_Group.ports[] = LSP._uuid.
- Router LSP: `type=router`, `options:router-port=<LRP.name>`.
- LRP.peer = peer LRP name (router-router). Empty in this dump; routers meet on a transit LS instead.
- NAT.external_ids / LR.nat[] = NAT._uuid.
- Datapath_Binding.external_ids `logical-switch` / `logical-router` = NB UUID.
- Port_Binding.logical_port = LSP/LRP name; .datapath = SB datapath UUID; .chassis = Chassis UUID.
- Chassis.encaps[] = Encap._uuid.
- VM NIC ↔ LSP: MAC (AHV `dumpxml` MAC / metadata IP). LSP `name` is `port_<uuid>` and is **not** always the Acropolis NIC UUID.

**ACL direction:** dump uses `from-lport` / `to-lport` (OVN names for out / in relative to the logical port).

## ClickHouse tables

Skinny entity tables + membership/edge tables. No giant Nested ACL blobs.

Per ClickHouse rules:

- `schema-pk-plan-before-creation` / `schema-pk-cardinality-order` / `schema-pk-prioritize-filters`: ORDER BY low-cardinality type/direction then UUID.
- `schema-types-native-types`: native `UUID`, `UInt8`, `Int32`, `IPv4` where it fits; IPs also kept as `String` because CIDRs mix with addresses.
- `schema-types-lowcardinality`: `type`, `direction`, `action`, `encap_type`.
- `schema-types-avoid-nullable`: empty string / zero UUID, never Nullable.
- `schema-partition-start-without`: no PARTITION BY.
- `insert-mutation-avoid-update`: `ReplacingMergeTree(updated_at)`.
- `insert-batch-size`: 10k JSONEachRow inserts.

| Table | ORDER BY | Grain |
|---|---|---|
| `ovn_ls` | `(ls_uuid)` | Logical switch |
| `ovn_lsp` | `(type, ls_uuid, lsp_uuid)` | Switch port |
| `ovn_lr` | `(lr_uuid)` | Router |
| `ovn_lrp` | `(lr_uuid, lrp_uuid)` | Router port |
| `ovn_acl` | `(direction, action, acl_uuid)` | ACL body |
| `ovn_acl_on_ls` | `(ls_uuid, acl_uuid)` | LS → ACL |
| `ovn_acl_on_pg` | `(pg_uuid, acl_uuid)` | Port group → ACL |
| `ovn_pg` | `(pg_uuid)` | Port group |
| `ovn_pg_port` | `(pg_uuid, lsp_uuid)` | PG membership |
| `ovn_pbr` | `(lr_uuid, priority, pbr_uuid)` | Router policy |
| `ovn_nat` | `(lr_uuid, nat_uuid)` | NAT |
| `ovn_vm` | `(vm_uuid)` | AHV domain |
| `ovn_vm_nic` | `(vm_uuid, nic_uuid)` | NIC + MAC + LSP join |
| `ovn_chassis` | `(chassis_uuid)` | Hypervisor |
| `ovn_encap` | `(chassis_uuid, encap_uuid)` | Geneve endpoint |
| `ovn_datapath` | `(kind, nb_uuid)` | SB datapath |
| `ovn_port_binding` | `(type, datapath_uuid, pb_uuid)` | SB port |
| `ovn_mac_binding` | `(datapath_uuid, ip)` | ARP/ND cache |
| `ovn_ha_chassis` | `(group_uuid, chassis_name)` | GW HA |
| `ovn_edge_ls_lr` | `(ls_uuid, lr_uuid)` | Router LSP ↔ LRP |
| `ovn_edge_lr_lr` | `(via, lr_a, lr_b)` | Peer or transit-LS |
| `ovn_ls_stretch` | `(ls_uuid, chassis_uuid)` | L2 Geneve stretch |

## How the four path types are walked

Graph nodes: LS and LR. Edges from `ovn_edge_ls_lr` (LS–LR) and `ovn_edge_lr_lr` (LR–LR via transit LS or `peer`). VIF LSPs hang off LS; NAT/localnet mark a router or switch as external.

`trace.py` BFS from src LS to dst LS (or to an external LR/localnet). Then it expands hops: VM NIC → LSP → LS → (LRP → LR → LRP → LS)* → LSP → VM. Reverse path is the hop list swapped; ACLs are re-selected with `from-lport` / `to-lport` flipped for the reversed in/out ports.

Mermaid is **composite per direction** (Upstream = src→dst, Downstream = dst→src). Each diagram wraps subgraphs **ACL Policy → L2 stretch → L3 routing/PBR → GW → External**. Main hops stay VM → NIC → TAP → OVS brAtlas → Switch → [Router → Switch …] → … . L3/GW/External may be `N/A` on same-L2. After each composite: full ACL, NAT, PBR, connected routes, GW chassis. Eval scores each layer, then UPSTREAM / DOWNSTREAM / COMPOSITE verdicts. Always a `.md` file.

1. **Same L2** — src and dst VIF on the same `ls_uuid`. Hops: NIC1, LSP1, LS, ACLs, LSP2, NIC2. Stretch from `ovn_ls_stretch`.
2. **L2–L3–L2, one router** — two VIF LSs that share one LR via `ovn_edge_ls_lr`. ACLs on each LS; PBR on the LR.
3. **Two routers / VPC via transit** — shortest LS–LR path with two tenant LRs. This dump has **zero** `LRP.peer`; routers meet on a per-VPC `gw-scale-out-network` (transit LS) and a shared External localnet. VM–VM across user VPCs: src LS → src tenant LR → src transit → src `gw-scale-out-router` (NAT, External GW MAC+IP) → External localnet → dest GW → dest transit → dest tenant LR → dest LS. `Gateway_Chassis` is empty; HA chassis groups + sibling `gw-scale-out-router_*` on the transit LS. `trace.py` prints every scale-out host. Fallback if no two-VIF pair: VIF → tenant LR → gw-scale-out-router.
4. **Northbound** — VIF LS → tenant LR → gw-scale-out-network → gw-scale-out-router with `ovn_nat` and/or `lrp-ext_gw_port` / localnet.

## Scripts

```text
python3 ingest.py --dump_dir /home/rakeshkumar.r/panacea/flow_pc_dumps/ovn_ovs_verify
python3 trace.py --find-scenarios
python3 trace.py --src <vm|mac|lsp-uuid> --dst <vm|mac|lsp-uuid|external>
# always writes clickhouse_ovn/out/<src>__<dst>.md (or --out FILE.md)
# each file: Upstream composite + Downstream composite mermaid (ACL|L2|L3|GW|External)
python3 trace.py --run-scenarios
# writes clickhouse_ovn/out/scenarios.md plus one .md per scenario
```
