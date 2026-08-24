---
name: ovn-path-external
description: >-
  Evaluate OVN External hop on one direction: External / NAT GW stadium,
  northbound dest. Use as a layer inside ovn-path-upstream and
  ovn-path-downstream. N/A for VM-to-VM paths with no External node.
---

# External layer

Identity is UUID. Names are display.

Invoked by the upstream and downstream composites. **N/A if dest is not External**.

## When External is on the path

- mermaid subgraph `EXT` / `External`
- `External / NAT GW` (or `ext-GW` on the GW router)
- dest is External: no dest TAP/OVS

Northbound upstream must PASS. Reverse may still show External as the far end.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer external FILE.md
```

Verdict: PASS, FAIL, or N/A.
