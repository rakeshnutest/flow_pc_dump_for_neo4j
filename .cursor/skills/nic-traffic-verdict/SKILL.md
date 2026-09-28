---
name: nic-traffic-verdict
description: >-
  Decide whether traffic between two VM NICs on a TCP, UDP, or ICMP port is
  allowed or denied, and name both the allow policy and the deny policy.
  Use when the user gives two VM NICs and a port, asks if traffic is allowed
  or denied, or asks which Flow policy allows or denies that traffic.
---

# NIC traffic verdict

Source is the first NIC. Destination is the second. `--port` is the destination
TCP/UDP port, or the ICMP type when `--proto icmp`.

## Run

```bash
python3 .cursor/skills/nic-traffic-verdict/scripts/nic_traffic.py \
  --log_bundle_id <id> \
  --src <nic-uuid-or-ip-or-vm> \
  --dst <nic-uuid-or-ip-or-vm> \
  --port <n> \
  --proto tcp
```

`--proto` is `tcp` (default), `udp`, or `icmp`. Omit `--log_bundle_id` to use
the latest `flow_policy` bundle. ClickHouse is `127.0.0.1:19000`, user
`default`. Address-set IPs come from the bundle `dump_dir` northbound dump.

## Answer

Repeat the script's lines. Keep all of these:

- **Verdict:** `allowed` or `denied`
- **Allow policy:** the policy that allows this pair and port. When the port
  is outside that policy, the line says so. When a higher-priority deny wins,
  the line says the allow does not apply.
- **Deny policy:** the policy that denies this pair and port. When a higher
  priority allow wins, the line says the deny does not apply.

Policy text is the policy name, type, mode, and category. Peer text is the
other policy and category, or the IPs when no port-set owns those addresses.
Do not print `$address_set_…` or `@port_group_…`.

A VM name that matches several NICs is not a verdict. Ask for one NIC uuid
from the script's list.
