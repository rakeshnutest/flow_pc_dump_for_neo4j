# Proc 1 — Bond/LAG first (no hardcoded NICs)

## Rule
**Do not assume `eth1`/`eth2`/any name.** Always:

1. Parse **`ovs-appctl bond/show`** (or equivalent LAG).
2. Build member list from that output only.
3. For **each member name returned by the bond**, check status.

## Per bond

| Field | Action |
|---|---|
| `bond_mode` | active-backup / balance-* / LACP |
| `active member` | datapath carrier — check CRC/drops/offload here first |
| each `member <name>` | enabled / disabled / standby / may_enable |

## Per member (dynamic name)

1. `ethtool <member>` — Link detected, Speed, Duplex  
2. `ethtool -S <member>` — CRC, errors, drops  
3. `ethtool -k <member>` — **TSO / GSO / GRO / LRO** (LSO ≡ TSO/GSO on Linux)  
4. `ethtool -g <member>` — rings  
5. `dmesg -T` — `NIC Link is Up/Down` for **that member name**  
6. `ip addr` — NO-CARRIER / DOWN / LOWER_UP  

## Decisions

| Bond status | Finding |
|---|---|
| member **disabled** or Link **no** / NO-CARRIER | `NIC_INACTIVE_OR_DOWN` |
| standby + enabled + link up (active-backup) | `BOND_OK_STANDBY_PRESENT` (expected) |
| CRC rising on **active** | `L1_CRC_OR_LINK` |
| soft drops on **active** only | `SOFT_RX_DROPS` |

Standby drops are **not** active-path loss.
