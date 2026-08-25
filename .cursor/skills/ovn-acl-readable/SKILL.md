---
name: ovn-acl-readable
description: >-
  Render OVN in-port/from-lport and out-port/to-lport ACLs in a human-readable
  way with IPs, L4 ports, ct_zone, metadata hex, and ct_label applicable for
  traffic. No hashed/encrypted OVN UUIDs (@port_group_*, $address_set_*) as
  primary identifiers. Use when the user asks for in-port and out-port ACL
  with IPs and ports, no encrypted UUIDs, ct zone, metadata in hex, or
  ct label applicable for traffic.
---

# Human-readable OVN in-port / out-port ACLs

Identity is UUID. Names are display. Do not query `flow_policy`. Do not replace
`ovn-path-acl` (path-eval layer). This skill is ACL view only.

in-port = from-lport (ingress). out-port = to-lport (egress). Use both terms.

## MUST RUN

```bash
python3 /home/rakeshkumar.r/panacea/.cursor/skills/ovn-acl-readable/scripts/show_acls.py \
  --src <nic-or-lsp> --dst <nic-or-lsp-or-ip>
```

Default pair if omitted: src NIC `3468ac71-d670-41a0-93af-0ec34d43f7c3`
(`192.168.2.186`) → dst LSP `22bce434-1ef5-4792-8e57-8fa2a5e3bd71`
(`192.168.1.51`). `--out FILE.md` optional. `--full-ips` for full address-set
lists in `<details>`. Imports: cwd `clickhouse_ovn` (`acls_on_ls`, `ch`,
`human_acl_row`). ClickHouse `flow_ovn` `127.0.0.1:19000`. Port-set jsonl (not
CH): `flow_pc_dumps/clickhouse_all_dump/flow_policy/portset.jsonl`.

Print **every** from-lport and to-lport row on **every path Switch** (LS ACLs
plus every port-group that has a member LSP on that LS). Allow, drop, DHCP,
catch-all — never omit non-hitting rules. Never truncate with `N more`.
Do not list leftover issues (K8s / empty Quarantine ignore classes).

## Output

- Endpoints: names display, UUID identity footnote
- Per path LS: **in-port (from-lport)** table and **out-port (to-lport)** table
  with count `(full list)` — all rules, not only the first-hit
- Columns: pri | action | applied-to | peers (IPs) | L4 ports | ct_zone |
  metadata | ct_label | match | identity (ACL uuid)
- First-hit ACL (drop vs allow) for this 5-tuple
- CT section: zone(s), metadata hex, ct_label for this traffic

Primary cells: policy/category names, IPs, ports. Hashed
`@port_group_*` / `$address_set_*` only in identity footnotes.

Missing dump fields: print `ct_zone=(missing in dump)` — do not invent.
