# Design: network underlay nodes & edges

Keep this file for reading. Mermaid lives **only here**, not in SKILL.md files.

---

## Source files (implementation)

| Piece | Path |
|-------|------|
| Orchestrator | `skills/network-services/network-underlay-orchestrator/SKILL.md` |
| Nodes skill | `skills/network-services/network-underlay-nodes/SKILL.md` |
| Nodes script | `skills/network-services/network-underlay-nodes/scripts/check_network_underlay_nodes.py` |
| Edges skill | `skills/network-services/network-underlay-edges/SKILL.md` |
| Edges script (`EDGE_TABLE`) | `skills/network-services/network-underlay-edges/scripts/check_network_underlay_edges.py` |
| DB / ingest map | `docs/skills/network_underlay.md` |
| Summary template | `skills/network-services/network-underlay-orchestrator/prompts/summary.md` |

Read order: **nodes script → edges script → this design → orchestrator SKILL**.

---

## Idea in one line

**Nodes** = which ClickHouse evidence classes exist.  
**Edges** = which analyzer skills to run next (or only what to collect).

---

## Big picture

```mermaid
flowchart LR
  O["network-underlay-orchestrator"] --> N["network-underlay-nodes"]
  N -->|"nodes_present[]"| E["network-underlay-edges"]
  E -->|"next_skills[]"| A["Analyzer skills"]
  E -->|"collect_suggestions[]"| S["Suggest only — no script"]
  A --> R["Readable summary"]
  S --> R
```

1. Nodes probe ClickHouse for the bundle window.
2. Edges use `nodes_present` + symptom text.
3. Orchestrator runs only `next_skills`; collect path never runs a script.

---

## Evidence nodes

```mermaid
flowchart TB
  Nodes["network-underlay-nodes"]
  Nodes --> sar["sar_metrics<br/>nu_metrics_sysstats · sar_*"]
  Nodes --> ping["ping_metrics<br/>nu_metrics_sysstats · ping_all_*"]
  Nodes --> nic["nic_stats_logs<br/>nu_logs / host_nic / ethtool"]
  Nodes --> dmesg["dmesg_logs<br/>nu_logs_local · NIC Link / bond"]
  Nodes --> hitlog["hitlog_logs<br/>nu_logs_local · ACTION="]
  Nodes --> tcp["tcp_socket_metrics<br/>nu_metrics_sysstats · tcp_socket_*"]
```

| Node id | Table | Present when |
|---------|-------|--------------|
| `sar_metrics` | `nu_metrics_sysstats` | `sar_rx_*` / `sar_tx_*` |
| `ping_metrics` | `nu_metrics_sysstats` | `ping_all_*` / lost / unreachable |
| `nic_stats_logs` | `nu_logs_local` (+ metrics) | NIC / CRC / drop lines |
| `dmesg_logs` | `nu_logs_local` | kernel / dmesg needles |
| `hitlog_logs` | `nu_logs_local` | Flow `ACTION=` / `SRC=` / `DST=` |
| `tcp_socket_metrics` | `nu_metrics_sysstats` | tcp / retrans / rtt |

---

## Edges (symptom → next)

```mermaid
flowchart TD
  Edges["network-underlay-edges"]
  Edges -->|flood / sar / latency<br/>needs sar OR ping OR tcp| SAR["network-sar"]
  Edges -->|flood path also| NIC1["network-nic-stats"]
  Edges -->|crc / soft drop / ethtool<br/>needs nic OR sar| NIC2["network-nic-stats"]
  Edges -->|L1 path also| SAR2["network-sar"]
  Edges -->|dmesg / link flap / bond<br/>needs dmesg_logs| Dmesg["network-dmesg"]
  Edges -->|kernel path also| NIC3["network-nic-stats"]
  Edges -->|hitlog / DROP / microseg<br/>needs hitlog_logs| Hitlog["network-hitlog"]
  Edges -->|pcap / conversation / geneve<br/>needs hitlog OR tcp OR sar| Pcap["network-packetlens"]
  Edges -->|collect / ingest / coverage<br/>OR thin nodes| Suggest["collect_suggestions only<br/>NOT a runnable skill"]
```

| Condition | Symptom tokens | Required nodes (any) | Next |
|-----------|----------------|----------------------|------|
| `symptom_underlay_or_flood` | flood, sar, rx pps, latency, … | `sar_metrics`, `ping_metrics`, `tcp_socket_metrics` | `network-sar`, `network-nic-stats` |
| `symptom_nic_l1` | crc, fcs, soft drop, ethtool, … | `nic_stats_logs`, `sar_metrics` | `network-nic-stats`, `network-sar` |
| `symptom_kernel_link` | dmesg, link flap, bond, soft lockup | `dmesg_logs` | `network-dmesg`, `network-nic-stats` |
| `symptom_flow_acl` | hitlog, microseg, ACTION=DROP | `hitlog_logs` | `network-hitlog` |
| `symptom_pcap` | pcap, packetlens, geneve, … | `hitlog_logs`, `tcp_socket_metrics`, `sar_metrics` | `network-packetlens` |
| `symptom_collect` / thin coverage | collect logs, ingest, coverage, … | *(none)* | **suggestions only** |

If required nodes are missing for a condition, that edge is **skipped**.

---

## Full orchestrator chain

```mermaid
graph TD
  Entry --> Nodes["network-underlay-nodes"]
  Entry -->|missing bundle_id| Aborted

  Nodes -->|PASS / FAIL / EVIDENCE_GAP| Edges["network-underlay-edges"]
  Nodes -->|ERROR| Failed

  Edges -->|PASS| Dispatch{"edge conditions"}
  Edges -->|ERROR| Failed

  Dispatch -->|underlay or flood| SAR["network-sar"]
  Dispatch -->|nic L1 or CRC| NIC["network-nic-stats"]
  Dispatch -->|kernel or flap| Dmesg["network-dmesg"]
  Dispatch -->|flow or hitlog| Hitlog["network-hitlog"]
  Dispatch -->|pcap| Pcap["network-packetlens"]
  Dispatch -->|collect or thin coverage| Suggest["collect_suggestions only"]

  SAR -->|FAIL| NIC
  SAR -->|PASS / EVIDENCE_GAP| Synth["Readable summary"]
  SAR -->|ERROR| Failed

  NIC -->|not ERROR| Dmesg
  Dmesg -->|not ERROR| Synth
  Hitlog -->|not ERROR| Synth
  Pcap -->|not ERROR| Synth
  Suggest --> Synth
  Synth --> Completed
```

---

## Data handoff

```text
nodes.evaluate(bundle_id, window)
  → present = ["sar_metrics", "dmesg_logs", ...]

edges.evaluate(symptom_text, nodes_present)
  → next_skills = ["network-sar", ...]                 # runnable
  → collect_suggestions = [{artifact, lands_in, ...}]  # advisory
  → suggested_checks = next_skills only

orchestrator runs each next_skill via run_local_script(check_*_v1)
  → fills prompts/summary.md
```
