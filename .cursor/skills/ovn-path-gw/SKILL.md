---
name: ovn-path-gw
description: >-
  Evaluate OVN GW on one direction: ext-GW router, NAT, GW chassis (RC/HA).
  Use as a layer inside ovn-path-upstream and ovn-path-downstream. N/A when
  no gateway router is on the path. External dest hop is ovn-path-external.
---

# GW layer

Identity is UUID. Names are display.

Invoked by the upstream and downstream composites. **N/A if no GW router**.

## When GW is on the path

- mermaid subgraph `GW`
- GW router with `ext-GW` and/or `NAT`
- dashed NAT + RC (chassis_name + priority)
- full `NAT on router` (`type` `external_ip` `logical_ip` `logical_port`)
- full `GW chassis (RC)` (`chassis_name` `priority`)

`(none)` only if empty; heading required. Northbound must PASS this layer.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer gw FILE.md
```

Verdict: PASS, FAIL, or N/A.
