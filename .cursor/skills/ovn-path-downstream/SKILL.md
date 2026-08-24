---
name: ovn-path-downstream
description: >-
  Composite OVN DOWNSTREAM (dst to src, REVERSE) eval. Invokes ovn-path-acl,
  ovn-path-l2, ovn-path-l3, ovn-path-gw, ovn-path-external in that order.
  Emits one mermaid (composite subgraphs) and a final DOWNSTREAM verdict.
  Use with ovn-path-upstream. Always a .md file.
---

# Downstream composite

Identity is UUID. Names are display. Always write `.md`.

**Read and apply (same turn, this direction only):**

1. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-acl/SKILL.md`
2. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-l2/SKILL.md`
3. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-l3/SKILL.md`
4. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-gw/SKILL.md`
5. `/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-external/SKILL.md`

Also `ovn-path-nodes` + `ovn-path-edges`.

Same pipeline as upstream, reverse packet: **ACL Policy → L2 stretch → L3
routing/PBR → GW → External**.

Mermaid nests those subgraphs inside `Downstream composite`. N/A subgraphs when
that layer is not on the reverse path.

## Checker + verdict

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction downstream [--scenario …] FILE.md
```

Append the five-row layer table. **DOWNSTREAM: PASS** iff no layer FAIL.

Do not score upstream here. Final file verdict is both composites PASS
(`**COMPOSITE: PASS**`).
