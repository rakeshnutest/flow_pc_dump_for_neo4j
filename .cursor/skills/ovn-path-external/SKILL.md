---
name: ovn-path-external
description: >-
  Evaluate OVN External hop on one direction: External dest stadium,
  northbound dest, External GW MAC/IP. Use as a layer inside
  ovn-path-upstream and ovn-path-downstream. N/A for VM-to-VM with no External.
---

# External layer

Identity is UUID. Names are display.

Invoked by the upstream and downstream composites. **N/A if dest is not External**.

## When External is on the path

- mermaid subgraph `EXT` / `External`
- dest stadium `External / NAT GW` (no dest TAP/OVS)
- External GW (gw-scale-out-router / ext-GW LRP) shows **MAC** and **IP/CIDR**
- SNAT external IP if it differs from the LRP IP
- External GW Host (RC/HA) is scored by ovn-path-gw, not omitted here

Northbound upstream must PASS. Reverse still shows External as the far end.

FAIL if northbound External hop has no dest node, or External GW MAC/IP is missing. Two-VPC via External localnet still needs MAC+IP on each GW (score N/A only when no External/localnet on the path).

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer external FILE.md
```

Verdict: PASS, FAIL, or N/A.
