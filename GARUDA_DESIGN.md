# Design: How networking RCA works (with flow diagrams)

**Local only** (not in git):  
`/home/rakeshkumar.r/panacea/design-docs/network-underlay-nodes-edges-design.md`

Mermaid diagrams are **only in this file** — not in SKILL.md.

| Code piece | Path |
|------------|------|
| Master | `network-rca-orchestrator` |
| Scenarios (`scen`) | `_shared/network_symptom_triggers.py` |
| Evidence probes | `_shared/network_evidence_nodes.py` |
| Inventory | `network-underlay-nodes` |
| Planner | `network-underlay-edges` |

---

## Big picture (start here)

```mermaid
flowchart LR
  Ticket["Ticket / chat<br/>symptom_text"] --> Master["network-rca-orchestrator"]
  Bundle["Bundle in ClickHouse"] --> Master
  Master --> Inv["1 Inventory<br/>what evidence exists?"]
  Inv --> Sym["2 Find ALL symptoms"]
  Sym --> CF["3 CHECK FIRST<br/>depth 1"]
  CF --> TC["4 Then confirm<br/>depth 2"]
  TC --> DD["5 Dig deeper<br/>depth 3"]
  DD --> Sum["6 One summary"]
```

**In plain words**

1. See what data we have in ClickHouse.
2. List every matching smell (from ticket words + latent evidence).
3. **Check first** = run the main skill for each smell.
4. Then confirm.
5. Then dig deeper on the same paths.
6. Write one story. Never stop on the first FAIL.

---

## Master flow (detailed)

```mermaid
flowchart TD
  Start([Networking issue seen]) --> Nodes["network-underlay-nodes<br/>probe CH coverage"]
  Nodes --> Present{"Any evidence<br/>present?"}
  Present -->|none| Gap["Record EVIDENCE_GAP<br/>+ collect suggestions"]
  Present -->|some / all| Edges["network-underlay-edges<br/>discover symptoms + plan digs"]
  Gap --> Edges
  Edges --> Collect{"Only collect /<br/>ingest symptom?"}
  Collect -->|yes| Sug["Emit collect_suggestions<br/>SKIP all analyzers"]
  Collect -->|no| Wave1["WAVE 1 — CHECK FIRST<br/>all matched paths depth=1"]
  Wave1 --> Wave2["WAVE 2 — THEN CONFIRM<br/>depth=2"]
  Wave2 --> Wave3["WAVE 3 — DIG DEEPER<br/>depth=3"]
  Wave3 --> Extra["On FAIL: child suggested_checks<br/>once each if new"]
  Extra --> Summary["One readable RCA summary"]
  Sug --> Summary
```

---

## What CHECK FIRST means

```mermaid
flowchart TD
  Paths["Matched symptom paths<br/>e.g. flood + dnd + flow"] --> W1

  subgraph W1["WAVE 1 — check_first only"]
    direction LR
    A["path flood<br/>→ network-sar"]
    B["path dnd<br/>→ network-dnd-window"]
    C["path flow<br/>→ network-hitlog"]
  end

  W1 --> W2

  subgraph W2["WAVE 2 — then_confirm"]
    direction LR
    D["nic-stats / dmesg"]
    E["cassandra / firewall / ..."]
    F["firewall / packetlens"]
  end

  W2 --> W3

  subgraph W3["WAVE 3 — dig_deeper"]
    direction LR
    G["ping / firewall / packetlens"]
    H["sar / nic / dmesg / ping"]
  end

  W3 --> Done([Summary — each skill ran at most once])
```

**Rule:** for every path, **check_first runs before** that path's confirm/dig.  
Across paths, **all check_first finish before any then_confirm**.

---

## How a symptom is found

```mermaid
flowchart TD
  In["symptom_text + symptom_class<br/>+ nodes_present from inventory"] --> T

  subgraph Discover["discover_symptoms()"]
    T{"Ticket / class<br/>tokens match a scen?"}
    T -->|yes| Text["Add path<br/>source = text or class"]
    T -->|also check| Lat{"Present node listed in<br/>scen.latent_nodes?"}
    Lat -->|yes| Ev["Add path<br/>source = evidence"]
    Lat -->|no| Broad{"Still zero paths<br/>but some nodes present?"}
    Broad -->|yes| EB["Add underlay paths whose<br/>require_nodes_any hit<br/>source = evidence_broad"]
    Broad -->|no| None["No symptoms<br/>→ fallback shallow scan"]
  end

  Text --> Out["symptoms[] — ALL paths kept"]
  Ev --> Out
  EB --> Out
  None --> Out
```

| Input | Symptom(s) found |
|-------|------------------|
| Ticket `CRC on eth0` | `l1_nic` (text) |
| Ticket empty, CH has `dnd_logs` | `dnd` (evidence / latent) |
| Ticket `DND and CRC` | `dnd` + `l1_nic` (both) |
| Ticket `collect logs` | `collect` only → suggestions, no dig |

---

## One path dig (single smell) — CRC example

```mermaid
flowchart TD
  Smell["Smell: ethtool CRC"] --> Match["Match scen l1_nic"]
  Match --> CF["CHECK FIRST<br/>network-nic-stats"]
  CF --> R1{Result?}
  R1 -->|FAIL NIC_CRC| TC["THEN CONFIRM<br/>network-dmesg"]
  R1 -->|PASS| TC
  R1 -->|skip_no_evidence| Gap["Gap: need nic_stats ingest"]
  TC --> R2{dmesg?}
  R2 -->|FAIL flap/driver| Sum["Summary: L1 CRC + kernel confirm"]
  R2 -->|PASS| Sum2["Summary: CRC without kernel flap"]
  Gap --> Sum3["Summary: cannot dig — collect nic stats"]
```

---

## Multi-path merge — DND + CRC

```mermaid
flowchart TD
  Ticket["Ticket: DND + CRC"] --> S1["Symptom: dnd"]
  Ticket --> S2["Symptom: l1_nic"]

  S1 --> CF1["check_first:<br/>dnd-window"]
  S2 --> CF2["check_first:<br/>nic-stats"]

  CF1 --> Wave1["WAVE 1 runs both"]
  CF2 --> Wave1

  Wave1 --> Wave2["WAVE 2 then_confirm<br/>DND experts + dmesg"]
  Wave2 --> Wave3["WAVE 3 dig_deeper<br/>DND underlay dig<br/>skip skills already run"]
  Wave3 --> Sum["One summary:<br/>DND window + L1 CRC story"]
```

---

## Smell → CHECK FIRST map

```mermaid
flowchart LR
  subgraph Smells
    F["Flood / pps / underlay"]
    P["Ping loss / latency"]
    C["CRC / ethtool"]
    K["Link flap / bond"]
    H["ACTION=DROP / microseg"]
    D["DND / node down"]
    M["MTU / NCC / bond"]
    FW["iptables / REJECT"]
    Col["collect / ingest"]
  end

  subgraph CheckFirst["CHECK FIRST skill"]
    SF["network-sar"]
    SP["network-ping-tcp-baseline"]
    SN["network-nic-stats"]
    SD["network-dmesg"]
    SH["network-hitlog"]
    SDn["network-dnd-window"]
    SM["network-nic-mtu-ncc"]
    SFw["network-firewall-iptables"]
    SNone["none — suggestions only"]
  end

  F --> SF
  P --> SP
  C --> SN
  K --> SD
  H --> SH
  D --> SDn
  M --> SM
  FW --> SFw
  Col --> SNone
```

| If you see… | **CHECK FIRST** | Then confirm | Dig deeper |
|-------------|-----------------|--------------|------------|
| Flood / high pps / underlay | **sar** | nic-stats, dmesg | ping-tcp, firewall, packetlens |
| Ping loss / ping latency / unreachable / CQI / packet loss / network latency | **ping-tcp** | sar, nic-stats, dmesg, firewall, nic-mtu, cassandra, ovs | — |
| CRC / FCS / ethtool / soft drop | **nic-stats** | dmesg | — |
| Link flap / bond / soft lockup | **dmesg** | nic-stats | — |
| Flow DROP / microseg | **hitlog** | firewall, packetlens | ping-tcp, sar |
| PacketLens / Geneve / pcap | **packetlens** | hitlog | — |
| DND / degraded node | **dnd-window** | cassandra, firewall, nic-mtu, host, storage, ovs | sar, nic-stats, dmesg, ping-tcp |
| MTU / NCC / LACP / jumbo | **nic-mtu-ncc** | host, upgrade, ovs, nic-stats, dmesg | — |
| Firewall / iptables | **firewall** | hitlog, ping-tcp | — |
| Cassandra / pithos / zeus | **cassandra** | ping-tcp, host | — |
| OVS / upcall | **ovs** | nic-mtu, dmesg | — |
| Host pressure / OOM | **host-pressure** | storage, dmesg | — |
| Storage / stargate slow | **storage-io** | host, ping-tcp | — |
| Upgrade / LCM / config change | **upgrade-config** | nic-mtu, ovs | — |
| Collect / parallel_run | **(none)** | suggestions only | re-run after ingest |

---

## Planner internals

```mermaid
flowchart TD
  A["ticket + nodes_present"] --> B["discover_symptoms()"]
  B --> C["symptoms path_ids"]
  C --> D["For each path:<br/>schedule check_first @1<br/>then_confirm @2<br/>dig_deeper @3"]
  D --> E["Merge + de-dupe<br/>keep shallower depth"]
  E --> F["Evidence gate<br/>missing nodes → skip_no_evidence"]
  F --> G["Sort by depth, then SKILL_ORDER"]
  G --> H["execution_sequence[]"]
  H --> I["Orchestrator runs action=run steps"]
```

| `action` | Meaning |
|----------|---------|
| `run` | Execute the child skill |
| `skip_no_evidence` | No CH coverage — gap, continue |
| `skip_collect_only` | Collect ticket — suggestions only |

---

## Who calls what

```mermaid
flowchart TD
  U["NuRAG / user"] --> M["network-rca-orchestrator MASTER"]
  M --> N["network-underlay-nodes"]
  M --> E["network-underlay-edges"]
  M --> Dig["Children from execution_sequence<br/>dnd / ping / sar / nic / dmesg / hitlog / ..."]
  E -.->|reads| Cat["_shared/network_symptom_triggers.py<br/>scen catalog"]
  N -.->|reads| Ev["_shared/network_evidence_nodes.py"]
  Sub["network-underlay-orchestrator"] -.->|underlay-only sub-chain<br/>defers full RCA to master| M
```

---

# Worked examples with flows

---

## Example 1 — Latency / flood

**Input:** `Cluster latency, packet loss`  
**Evidence:** `sar_metrics`, `ping_metrics`

```mermaid
flowchart TD
  T["Ticket: latency + packet loss"] --> S1["Symptom flood_underlay"]
  T --> S2["Symptom ping_tcp"]
  S1 --> CF1["CHECK FIRST: sar"]
  S2 --> CF2["CHECK FIRST: ping-tcp"]
  CF1 --> TC["THEN CONFIRM:<br/>nic-stats, dmesg, firewall, ..."]
  CF2 --> TC
  TC --> DD["DIG DEEPER:<br/>packetlens, ..."]
  DD --> Sum["Summary: flood vs path-loss story"]
```

| Depth | Runs |
|------:|------|
| 1 check first | **sar**, **ping-tcp** |
| 2 confirm | nic-stats, dmesg, firewall, nic-mtu, cassandra, ovs |
| 3 dig deeper | packetlens (and any not already run) |

---

## Example 2 — DND after blip

**Input:** `Node went into DND after network blip`  
**Evidence:** `dnd_logs`, `sar_metrics`, `ping_metrics`

```mermaid
flowchart TD
  T["Ticket: DND"] --> S1["dnd text"]
  Ev["CH: sar + ping"] --> S2["flood + ping latent"]
  S1 --> CF["CHECK FIRST wave:<br/>dnd-window + sar + ping-tcp"]
  S2 --> CF
  CF --> Exp["THEN CONFIRM:<br/>cassandra, firewall, nic-mtu,<br/>host, storage, ovs"]
  Exp --> Under["DIG DEEPER DND path:<br/>nic-stats, dmesg<br/>sar/ping already done"]
  Under --> Sum["Summary: DND window + underlay blip"]
```

**CHECK FIRST** = `dnd-window` (+ latent sar / ping). Experts wait for wave 2.

---

## Example 3 — CRC climbing

**Input:** `ethtool CRC errors on eth2`  
**Evidence:** `nic_stats_logs`, `dmesg_logs`

```mermaid
flowchart TD
  T["CRC / ethtool"] --> CF["CHECK FIRST: nic-stats"]
  CF --> Fail["FAIL: NIC_CRC"]
  Fail --> TC["THEN CONFIRM: dmesg"]
  TC --> Sum["L1 CRC ± kernel flap"]
```

Does **not** open cassandra / upgrade.

---

## Example 4 — Flow ACTION=DROP

**Input:** `ACTION=DROP microseg denied`  
**Evidence:** `hitlog_logs`, `firewall_logs`

```mermaid
flowchart TD
  T["DROP / microseg"] --> CF1["CHECK FIRST: hitlog"]
  Ev["firewall_logs present"] --> CF2["CHECK FIRST: firewall latent"]
  CF1 --> TC["THEN CONFIRM: packetlens"]
  CF2 --> TC
  TC --> DD["DIG DEEPER: ping-tcp, sar"]
  DD --> Sum["Policy vs underlay"]
```

---

## Example 5 — Vague ticket, rich evidence

**Input:** `network broken, not sure why`  
**Evidence:** `sar_metrics`, `dnd_logs`, `hitlog_logs`

```mermaid
flowchart TD
  T["Useless ticket text"] --> Lat["Latent symptoms only"]
  Lat --> S1["flood ← sar_metrics"]
  Lat --> S2["dnd ← dnd_logs"]
  Lat --> S3["flow ← hitlog_logs"]
  S1 --> CF["CHECK FIRST wave:<br/>sar + dnd-window + hitlog"]
  S2 --> CF
  S3 --> CF
  CF --> Rest["Then confirm / dig each path"]
  Rest --> Sum["Summary from whatever FAILed"]
```

---

## Example 6 — Collect only

```mermaid
flowchart TD
  T["please collect logs / parallel_run"] --> C["Symptom: collect"]
  C --> Sug["collect_suggestions only"]
  Sug --> Skip["SKIP all analyzers"]
  Skip --> Wait["After ingest → restart at inventory"]
```

---

## Example 7 — Thin coverage

```mermaid
flowchart TD
  T["latency + packet loss"] --> Sym["Symptoms: flood + ping"]
  Sym --> Plan["Plan would check_first sar + ping-tcp"]
  Plan --> Gate["nodes_present = empty"]
  Gate --> Skip["action = skip_no_evidence"]
  Skip --> Sum["Summary = gaps + collect hints<br/>not a false PASS"]
```

---

## Example 8 — Add a scenario tomorrow

```mermaid
flowchart LR
  New["New smell tomorrow"] --> Scen["Append one scen(...)<br/>in network_symptom_triggers.py"]
  Scen --> CF["Set check_first = main skill"]
  CF --> Opt["Optional then_confirm / dig_deeper / latent_nodes"]
  Opt --> Auto["Edges + orchestrator<br/>pick it up automatically"]
```

```python
scen(
    "geneve_encap",
    title="Geneve / encap drops",
    match_any=("geneve drop", "encap drop"),
    latent_nodes=("hitlog_logs",),
    check_first=["network-packetlens"],      # CHECK FIRST
    then_confirm=["network-hitlog", "network-ovs-host-evidence"],
    dig_deeper=["network-sar"],
)
```

New **skill name**? Also add a gate in `network_evidence_nodes.py`.

---

## Evidence nodes (what inventory looks for)

| Node | Means | Helps open |
|------|-------|------------|
| `sar_metrics` | SAR pps / drops | sar, latent flood |
| `ping_metrics` | ping / CQI / loss | ping-tcp |
| `tcp_socket_metrics` | retrans / RTT | ping-tcp, packetlens |
| `nic_stats_logs` / `host_nic_metrics` | CRC / ethtool | nic-stats |
| `dmesg_logs` | link / bond / driver | dmesg |
| `hitlog_logs` | Flow ACTION= | hitlog, packetlens |
| `dnd_logs` | degraded node | dnd-window |
| `firewall_logs` | iptables | firewall |
| `ovs_*` | OVS datapath | ovs |
| `cassandra_meta_logs` | cassandra / pithos | cassandra |
| `host_pressure_metrics` | CPU / mem | host-pressure |
| `storage_io_metrics` | stargate / disk | storage-io |

---

## Rules (short)

1. Inventory → find **all** symptoms → **check first** → confirm → dig.
2. Check first = the main skill for that smell.
3. Multiple smells → merge waves; each skill runs **once**.
4. FAIL = finding; continue. Gap ≠ healthy.
5. Collect = suggestions only.
6. New scenario = one `scen(...)` with a clear `check_first`.

---

## Quick quiz

1. CRC ticket — check first? → **nic-stats**
2. DND ticket — check first? → **dnd-window** (experts later)
3. ACTION=DROP — check first? → **hitlog**
4. Flood / high pps — check first? → **sar**
5. Empty ticket + `dnd_logs` — still check dnd first? → **yes (latent)**
6. Collect ticket — check first? → **nothing**
