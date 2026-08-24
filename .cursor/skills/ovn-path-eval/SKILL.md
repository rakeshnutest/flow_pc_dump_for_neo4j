---
name: ovn-path-eval
description: >-
  Run composite OVN eval on a .md trace: upstream and downstream each score
  ACL Policy, L2 stretch, L3 routing/PBR, GW, External. Use after ovn-path-trace
  or ovn-path-test. Follow ovn-path-upstream and ovn-path-downstream.
---

# Composite eval

Identity is UUID. Do not query `flow_policy`. Input must be `.md`.

**Read** `ovn-path-upstream` and `ovn-path-downstream` (they invoke the five
layer skills).

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  [--scenario same_l2|l2_l3_l2|two_router|northbound|acl_drop] \
  [--direction upstream|downstream] [--layer acl|l2|l3|gw|external] \
  FILE.md
```

No flags: both directions, all layers, **COMPOSITE** line.

| Composite | PASS when |
|---|---|
| UPSTREAM | no layer FAIL (N/A OK) |
| DOWNSTREAM | same |
| COMPOSITE | both PASS |

Paste the verdict tables into the `.md`. One FAIL → do not ship.
