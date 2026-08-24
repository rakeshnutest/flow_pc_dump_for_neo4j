---
name: ovn-path-l2
description: >-
  Evaluate OVN L2 stretch on one direction: VM, NIC, TAP, OVS brAtlas, Switch,
  Geneve overlay when chassis differ. Use as a layer inside ovn-path-upstream
  and ovn-path-downstream. Same L2 still requires TAP/OVS/Switch.
---

# L2 stretch layer

Identity is UUID. Names are display.

Invoked by `ovn-path-upstream` and `ovn-path-downstream`.

## Must show (this direction)

- mermaid subgraph `L2` / `L2 stretch`
- `VM_S → NIC_S → TAP_S → OVS_S` (brAtlas) → Switch
- dest VIF: `OVS_D → TAP_D → NIC_D → VM_D` (skip `_D` if dest is External)
- Overlay Geneve dashed from Switch when chassis differ (L2 stretch)

Reject `VM → NIC → Switch`. Overlay is not a Switch substitute.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer l2 FILE.md
```

PASS / FAIL for L2 only.
