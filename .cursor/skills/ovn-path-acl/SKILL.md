---
name: ovn-path-acl
description: >-
  Evaluate OVN ACL Policy on one direction (upstream or downstream): full
  from-lport and to-lport tables, port-group, address-set, drop/allow. Use as
  a layer inside ovn-path-upstream and ovn-path-downstream. Never truncate ACLs.
---

# ACL Policy layer

Identity is UUID. Names are display. Do not query `flow_policy`.

Invoked by `ovn-path-upstream` and `ovn-path-downstream` (never skip a direction).

## Must show (this direction only)

- mermaid subgraph `ACL` / `ACL Policy`
- full `from-lport` table (`pri` `action` `match`)
- full `to-lport` table
- rewritten `@port_group_*` / `$address_set_*`
- no `N more` / `LIMIT 80`

`(none)` only if that direction has zero ACLs. `acl_drop` must include `drop` rows.

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py \
  --direction upstream|downstream --layer acl FILE.md
```

PASS / FAIL for this layer only. Composite skills combine layers.
