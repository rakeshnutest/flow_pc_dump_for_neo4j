---
name: ovn-path-nodes
description: >-
  OVN path mermaid NODES. Every VIF must emit VM, NIC, TAP, and OVS brAtlas
  (never omit TAP or brAtlas, even if dump lookup failed). Also Switch, Router,
  NAT, PBR, RC, External, Overlay, port-group, address-set. Use with
  ovn-path-trace and ovn-path-edges when drawing OVN mermaid, TAP, brAtlas,
  or path diagrams.
---

# OVN path nodes

Read this **and** `ovn-path-edges` before drawing. Identity is UUID; names are display.

Do **not** redraw a shorter diagram than the CLI. If you redraw, every VIF still gets TAP + OVS brAtlas.

Wrap the whole direction in `Upstream composite` or `Downstream composite`. Nested subgraphs, in order: `ACL Policy`, `L2 stretch`, `L3 routing / PBR`, `GW`, `External`. Unused L3/GW/External still appear as `N/A`.

## Required IDs (every VIF)

| ID | Class | Shape | Label must include |
|---|---|---|---|
| `VM_S` / `VM_D` | `vm` | stadium | `VM <name>` |
| `NIC_S` / `NIC_D` | `nic` | rectangle | NIC UUID, MAC, IP |
| `TAP_S` / `TAP_D` | `tap` | rectangle | `TAP <tapN or missing>` |
| `OVS_S` / `OVS_D` | `ovs` | rectangle | **`OVS brAtlas`**, ofport, dp_port, iface-id |

Src uses `_S`. Dest VIF uses `_D`. External dest: no `_D` TAP/OVS.

**Never skip TAP or OVS** because Host boxes are off, lookup failed, or the chain “looks long”. Missing dump → still draw the node (`TAP missing`, `OVS brAtlas ofport ?`).

Host subgraph (when chassis differ) wraps **VM+NIC+TAP+OVS**, not VM+NIC only.

## Other nodes (when on path)

| ID prefix | Class | Shape | When |
|---|---|---|---|
| `SW*` | `sw` | cylinder | every LS; label `transit` for gw-scale-out-network |
| `RT*` | `rt` | hexagon | every LR; add `NAT` if NAT exists; add `ext-GW` if external GW |
| `EXT` | `ext` | stadium | northbound dest only |
| `NAT*` | `nat` | dashed rect | hangs off its router; not a hop |
| `PBR*` | `pbr` | dashed rect | hangs off its router |
| `RC*` | `rc` | dashed stadium | HA chassis_name + priority |
| `OVL` | `ovl` | dashed rect | chassis differ; not a Switch substitute |
| `PG*` | `pg` | dashed teal | applied-to; rewrite `@port_group_*` |
| `AS*` | `aset` | dashed gold | dest/src IPs; rewrite `$address_set_*` |

## Copy this node block

```mermaid
flowchart LR
  classDef vm fill:#4C8BF5,stroke:#1a4fa0,color:#fff
  classDef nic fill:#E8F0FE,stroke:#4C8BF5,color:#111
  classDef tap fill:#E0F2F1,stroke:#00796B,color:#111
  classDef ovs fill:#ECEFF1,stroke:#37474F,color:#111
  classDef sw fill:#34A853,stroke:#137333,color:#fff
  subgraph H1["Host src"]
    VM_S(["VM src"])
    NIC_S["NIC uuid"]
    TAP_S["TAP tapN"]
    OVS_S["OVS brAtlas"]
  end
  SW1[("Switch")]
  subgraph H2["Host dst"]
    OVS_D["OVS brAtlas"]
    TAP_D["TAP tapN"]
    NIC_D["NIC uuid"]
    VM_D(["VM dst"])
  end
```

Same chassis: drop `subgraph H1`/`H2`, **keep** TAP_* and OVS_*.

## Reject

Mermaid source lacks `TAP_S`, `OVS_S`, and (VIF dest) `TAP_D`, `OVS_D`, or any OVS label omits `brAtlas`. Redraw; do not send.
