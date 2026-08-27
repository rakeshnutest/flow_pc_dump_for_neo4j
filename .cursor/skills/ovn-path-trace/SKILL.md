---
name: ovn-path-trace
description: >-
  Trace OVN paths into a .md file, then run composite UPSTREAM and DOWNSTREAM
  evals. Each composite invokes ACL Policy, L2 stretch, L3 routing/PBR, GW,
  and External as separate skills, then prints mermaid + a final verdict.
  Use for OVN path, mermaid, TAP, brAtlas, ACL, PBR, NAT, RC, northbound.
---

# OVN path trace (composite)

Identity is UUID. Names are display. DB `flow_ovn` `127.0.0.1:19000`. No `flow_policy`. Filter with `--log_bundle_id` (default: latest `flow_ovn.bundle`).

Always write a **`.md` file**. Never chat-only.

## Same-turn reads (order)

1. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-nodes/SKILL.md`
2. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-edges/SKILL.md`
3. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-upstream/SKILL.md`
4. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-downstream/SKILL.md`

Upstream/downstream each pull ACL, L2, L3, GW, External.

## Trace → md

```bash
python3 /home/rakeshkumar.r/panacea/clickhouse_ovn/trace.py \
  --log_bundle_id 1 --src '<vm-or-uuid>' --dst '<vm-or-uuid>'
# clickhouse_ovn/out/<src>__<dst>.md
```

`--dst` UUID, `external`, or an IP (`8.8.8.8` → northbound). `--out FILE.md` to name the file.

Two user VPCs via transit: src tenant LR → `gw-scale-out-network` → scale-out GW (all hosts, External GW MAC+IP) → External localnet → dest GW → dest tenant. Write `clickhouse_ovn/out/vpc_transit_vpc.md`.

Every `.md` **starts** with **## Summary** (verdict, one-paragraph RCA, endpoint table). Then Endpoints, a folded hop list, Policy. Then **two separate mermaids**: Upstream composite, then Downstream composite — never one combined chart.

Mermaid LS/LR nodes stay short: name, uuid, tunnel key, path MAC/IP. Full LS/LR JSON, ACL, NAT, PBR, routes live in a **folded `<details>`** under each mermaid. Subgraph ids are unique (`L21`, `GW3`, …) so hops do not merge into one box.

## Composites

| Direction | Packet | Skills invoked | Output |
|---|---|---|---|
| **Upstream** | src → dst | acl → l2 → l3 → gw → external | one mermaid + **UPSTREAM** verdict |
| **Downstream** | dst → src | same five | one mermaid + **DOWNSTREAM** verdict |

Each mermaid is a composite: subgraphs `ACL Policy`, `L2 stretch`, `L3 routing / PBR`, `GW`, `External`.

File verdict: **COMPOSITE: PASS** only if both directions PASS (layer N/A is OK).

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py FILE.md
```

Append both verdict tables to the `.md`.
