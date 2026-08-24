---
name: ovn-path-trace
description: >-
  Trace OVN paths into a .md file, then run composite UPSTREAM and DOWNSTREAM
  evals. Each composite invokes ACL Policy, L2 stretch, L3 routing/PBR, GW,
  and External as separate skills, then prints mermaid + a final verdict.
  Use for OVN path, mermaid, TAP, brAtlas, ACL, PBR, NAT, RC, northbound.
---

# OVN path trace (composite)

Identity is UUID. Names are display. DB `flow_ovn` `127.0.0.1:19000`. No `flow_policy`.

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
  --src '<vm-or-uuid>' --dst '<vm-or-uuid>'
# clickhouse_ovn/out/<src>__<dst>.md
```

`--dst external` for northbound. `--out FILE.md` to name the file.

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
