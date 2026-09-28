---
name: nic-traffic-verdict
description: >-
  List every port-set a source VM NIC and a destination VM NIC belong to,
  print the consolidated ACL table, and conclude whether that TCP, UDP, or
  ICMP port is allowed or denied, naming the allow policy and the deny policy.
  Use when the user gives two VM NICs and a port, asks which port-sets those
  VMs belong to, or asks which Flow policy allows or denies that traffic.
skill_type: atomic
component: network-services
sub_component: nic_traffic_verdict
keywords:
  - VM NIC
  - port-set
  - consolidated ACL
  - allow policy
  - deny policy
  - Flow policy
  - from-lport
  - to-lport
---

## When to use

A source VM NIC, a destination VM NIC, and one L4 port. The answer lists
every port-set of the source, every port-set of the destination, the full
consolidated ACL table, and then the conclusion.

## STEP 1: Run the verdict

```bash
python3 skills/network-services/nic-traffic-verdict/scripts/nic_traffic.py \
  --log_bundle_id <id> \
  --src <nic-uuid-or-ip-or-vm> \
  --dst <nic-uuid-or-ip-or-vm> \
  --port <n> \
  --proto tcp
```

`--proto` is `tcp` (default), `udp`, or `icmp`. For icmp, `--port` is the
ICMP type. Omit `--log_bundle_id` to use the latest `flow_policy` bundle.
ClickHouse is `127.0.0.1:19000`, user `default`.

## STEP 2: Emit the script output in full

Print these sections in order. Keep every row of each table.

1. Source and destination VM name, IP, and NIC uuid.
2. **Source port-sets** — every port-set whose NIC list contains the source NIC.
3. **Destination port-sets** — every port-set whose NIC list contains the destination NIC.
4. **Consolidated ACL table** — every ACL on those port-sets, one row each, sorted by priority. Columns: priority, action, direction, ip, policy, category, peer, ports, matches.
5. **Conclusion** — `Verdict`, `Allow policy`, and `Deny policy`.

`matches` is `yes` when that row fits this source, destination, and port.
The conclusion is the highest matching row on each stage. A drop in
`enforce` mode denies the packet. A drop in `monitor` mode is reported and
the verdict stays allowed.

Policy and peer cells use the policy name and category. When the peer
addresses belong to no port-set, the cell is the IP list. An empty address
set stays empty.

## Outcomes

- `allowed` — the winning rows are allow, allow-related, or allow-stateless.
- `denied` — a matching drop is in enforce mode.
- Several NICs for one VM name — the script lists the NIC uuids. Pass one uuid. That list is not a verdict.

## Design

Port-set creation, the two stages, and this verdict are recorded in
[PORTSET_DESIGN.md](../../../PORTSET_DESIGN.md).
