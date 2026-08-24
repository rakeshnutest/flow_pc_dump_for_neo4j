---
name: ovn-path-gw
description: >-
  Evaluate OVN GW on one direction: ext-GW router, NAT, GW chassis (RC/HA),
  every scale-out External GW Host. Use as a layer inside ovn-path-upstream
  and ovn-path-downstream. N/A when no gateway router is on the path.
---

# GW layer

Identity is UUID. Names are display.

Invoked by the upstream and downstream composites. **N/A if no GW router**.

## When GW is on the path

- mermaid subgraph `GW`
- **every** scale-out host as `External GW Host` (hostname + chassis UUID)
- active redirect chassis labeled `active RC`; other HA / sibling gw-scale-out hosts labeled `standby` / `standby scale-out` (never omit peers)
- External GW hexagon: **MAC** + **IP/CIDR** (`External GW` / `IP` / `MAC`)
- TAP_GW / OVS brAtlas on a GW host when dataplane has them
- dashed NAT + RC (hostname, chassis UUID, priority, role)
- full `NAT on router` and `GW chassis (RC)` tables

FAIL if northbound / gw-scale-out / two-VPC-via-transit has a GW router but mermaid/story has no External GW Host, hides a scale-out host (all sibling `gw-scale-out-router_*` + HA), or External GW lacks MAC or IP. Two-VPC with four GW router names needs four External GW Host lines. Node label: UUID, MAC, IP/CIDR, tunnel_key.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer gw FILE.md
```

Verdict: PASS, FAIL, or N/A.
