---
name: ovn-path-upstream
description: >-
  Composite OVN UPSTREAM (src to dst, FORWARD) eval. Invokes ovn-path-acl,
  ovn-path-l2, ovn-path-l3, ovn-path-gw, ovn-path-external in that order.
  Emits one mermaid (composite subgraphs) and a final UPSTREAM verdict.
  Use with ovn-path-downstream. Always a .md file.
---

# Upstream composite

Identity is UUID. Names are display. Always write `.md`.

**Read and apply (same turn, this direction only):**

1. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-acl/SKILL.md`
2. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-l2/SKILL.md`
3. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-l3/SKILL.md`
4. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-gw/SKILL.md`
5. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-external/SKILL.md`

Also `ovn-path-nodes` + `ovn-path-edges` for drawing.

Pipeline: **ACL Policy → L2 stretch → L3 routing/PBR → GW → External**.

Mermaid must nest those five subgraphs inside `Upstream composite`. L3/GW/External
may be `N/A` nodes when not on the path (same L2). Do not omit the subgraph.

## Checker + verdict

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream [--scenario …] FILE.md
```

Append to the `.md`:

| Layer | Verdict |
|---|---|
| ACL Policy | PASS/FAIL |
| L2 stretch | PASS/FAIL |
| L3 routing/PBR | PASS/FAIL/N/A |
| GW | PASS/FAIL/N/A |
| External | PASS/FAIL/N/A |

**UPSTREAM: PASS** only if no layer is FAIL (N/A allowed). One FAIL → **UPSTREAM: FAIL**.

Do not score downstream here.
