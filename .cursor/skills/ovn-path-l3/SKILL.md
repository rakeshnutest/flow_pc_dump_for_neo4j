---
name: ovn-path-l3
description: >-
  Evaluate OVN L3 routing and PBR on one direction: tenant Router, every PBR
  row, every connected CIDR. Use as a layer inside ovn-path-upstream and
  ovn-path-downstream. N/A when the path has no Router (same L2). NAT/GW/
  External are other skills (ovn-path-gw, ovn-path-external).
---

# L3 routing / PBR layer

Identity is UUID. Names are display.

Invoked by the upstream and downstream composites. **N/A if no Router** (same L2).

## When a Router is involved

- mermaid subgraph `L3` / `L3 routing / PBR`
- `Router` hexagon on the solid chain (tenant LR)
- dashed `PBR` hang-off if any policy routes
- full `PBR on router` table (`pri` `action` `match` `nexthop`) — every row
- full `connected routes` (`lrp` `cidr` `ext_gw`) — every LRP CIDR
- full `static routes on router` (`prefix` `nexthop` `policy`) — every row
- `two_router` / VPC-via-transit: two tenant Routers **and** transit `gw-scale-out-network`; FAIL if transit LS is missing
- mermaid Router node: UUID, tunnel_key, path LRP MAC+CIDR, key options

`(none)` allowed only when empty; heading still required.
`two_router`: two Routers or a transit Switch.

Do **not** score NAT, RC, or External here.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer l3 FILE.md
```

Verdict: PASS, FAIL, or N/A.
