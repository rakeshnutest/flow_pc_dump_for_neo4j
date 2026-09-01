---
name: network-sar-debugging
description: >-
  Full host/CVM network+pressure RCA from logbay: SAR, iostat, ethtool CRC,
  host_nic_stats, ifconfig, and ping. MUST emit every counter class (CRC,
  errors, drops, collisions, link, disk/iowait) — never skip L1 checks.
skill_type: atomic
component: networking
sub_component: network_sar_debugging
keywords:
  - sar
  - iostat
  - sysstats
  - rxdrop
  - crc
  - ethtool
  - host_nic_stats
  - network-debugging
  - dnd
symptoms:
  - "Intermittent CVM/host connectivity or peer timeouts"
  - "Need SAR/iostat/CRC root-cause for DND or packet loss"
  - "sar_stats_threshold_check or host NIC drop signals"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-09-01
based_on: >-
  https://explainx.ai/skills/aj-geddes/useful-ai-prompts/network-debugging
  (aj-geddes/useful-ai-prompts network-debugging — remapped from browser
  DevTools waterfall to SAR / ethtool / iostat timelines)
---

# Network SAR Debugging (complete)

Adapted from [explainx.ai network-debugging](https://explainx.ai/skills/aj-geddes/useful-ai-prompts/network-debugging).
Remapped from browser Network tab to **Nutanix logbay** evidence.

## Hard rule — never skip these classes

Every run MUST report a status for **each** of the following. If a source
file is missing, set that class to `EVIDENCE_INSUFFICIENT` with the path
searched — do **not** omit the key.

| Class | Sources (logbay) | Key counters |
|---|---|---|
| **L1 / CRC** | `ahv/*/commands/ethtool_--statistics_*.stdout`, `host_nic_stats.INFO.*`, `ifconfig_-a.stdout` | `rx_crc_errors`, `rx_length_errors`, `rx_frame_errors`, `collisions`, `tx_carrier` / carrier, overruns |
| **NIC errors** | same + SAR err block | `rx_errors`, `tx_errors`, SAR `rxerr/s` `txerr/s` |
| **Drops** | ethtool / host_nic_stats / SAR / ifconfig | `rx_dropped`, `tx_dropped`, SAR `rxdrop/s` `txdrop/s` |
| **Link** | `ethtool_eth*.stdout`, dmesg | Speed, duplex, `Link detected` |
| **Traffic** | `sar.INFO.*` IFACE | `rxpck/s`, `txpck/s`, `rxkB/s`, `txkB/s`, avg pkt size |
| **Path** | `ping_all.INFO.*`, `ping_remotes.INFO.*` | unreachable, LOST_PKT (esp. 1472B) |
| **Host pressure** | `iostat.INFO.*` | `%iowait`, disk `%util`, `r_await`, `w_await` |

**CRC = 0 is a finding.** Report it explicitly. Do not equate `rx_dropped`
with CRC.

## When to Use

- DND / peer-score / intermittent loss
- NCC `sar_stats_threshold_check`, NIC flaps, SSD latency
- Separating **CRC/L1** vs **soft drop** vs **storage pressure**

## DevTools → logbay map

| Browser concept | Logbay analog |
|---|---|
| Waterfall | `#TIMESTAMP` ordered samples |
| Queueing | `rxdrop/s`, `rx_dropped`, softnet |
| L1 / bad cable | **`rx_crc_errors`**, frame, carrier, collisions |
| Initial connection | `ping_*.INFO` GW/PC/CVM |
| Waiting (TTFB) | RPC / Thrift / Medusa timeouts |
| Content download | SAR rates + avg pkt size |
| Throttling | sustained drops + disk await / iowait |

## Procedure (ReAct — mandatory order)

1. **Discover** bundle root (`NTNX-Log-*-PE-<cvm>/`).
2. **Act: L1/CRC** — parse ethtool `-S`, `host_nic_stats` first→last delta, ifconfig.
3. **Observe** — CRC rising? or drops-only with CRC=0?
4. **Act: SAR traffic+err** — eth0/eth1 rates, `rxdrop/s`, `rxerr/s`.
5. **Act: iostat** — iowait + hot disks near DND / fault wall times.
6. **Act: ping** — unreachable / LOST_PKT to peers vs GW/PC.
7. **Classify** (pick primary; list contributors):
   - `L1_CRC_OR_LINK` — CRC/frame/carrier/collisions rising or link flaps
   - `SOFT_RX_DROPS` — large `rx_dropped` / `rxdrop/s`, CRC≈0, rxerr≈0
   - `SOFTNET_FLOOD` — high pps + tiny pkts + soft drops
   - `HOST_STORAGE_PRESSURE` — high await/%util/iowait near DND
   - `PATH_EDGE` — GW/PC large-ping fail, peer CVM OK
   - `MIXED` — state which led peer-score climb
8. **Emit JSON** with every class present (see script schema).

## Decision thresholds

| Signal | Suspect |
|---|---|
| `rx_crc_errors` delta > 0 | `L1_CRC_OR_LINK` |
| `rx_dropped` large, CRC delta = 0 | `SOFT_RX_DROPS` |
| SAR `rxpck/s` > 100k + pkt size p50 < 200B | `SOFTNET_FLOOD` |
| SAR `rxdrop/s` > 0 on >50% samples, `rxerr/s`≈0 | soft drops |
| `%iowait` > 20 or disk await > 30ms / util > 90% | `HOST_STORAGE_PRESSURE` |

## Script

Prefer bundle-root mode (runs **all** checks):

```bash
python3 scripts/analyze_sar_network.py \
  --bundle-root /path/to/NTNX-Log-...-PE-10.1.20.104 \
  --iface eth0
```

Or explicit files:

```bash
python3 scripts/analyze_sar_network.py \
  --sar .../sar.INFO.* \
  --iostat .../iostat.INFO.* \
  --host-nic-stats .../host_nic_stats.INFO.* \
  --ethtool-dir .../ahv/<host>/commands \
  --ping .../ping_all.INFO.* \
  --iface eth0
```

## Common Pitfalls

- Reporting drops without stating **CRC=0** (or CRC>0).
- Treating post-DND SAR start as the trigger time.
- Blaming MTU/CRC when only soft drops + disk await exist.
- Skipping AHV ethtool because CVM SAR `rxerr/s` was 0.

## See also

- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
- [network-nic-mtu-ncc](../network-nic-mtu-ncc/SKILL.md)
- [network-host-pressure](../network-host-pressure/SKILL.md)
- [network-ping-tcp-baseline](../network-ping-tcp-baseline/SKILL.md)
- [references/sar_waterfall_checklist.md](references/sar_waterfall_checklist.md)

## Attribution

Methodology adapted from
[explainx.ai / aj-geddes useful-ai-prompts network-debugging](https://explainx.ai/skills/aj-geddes/useful-ai-prompts/network-debugging).
