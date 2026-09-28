---
name: nic-traffic-verdict
description: >-
  ACL plus path traversal for two VM NICs. Walk VM, subnet, switch, router,
  and gateway, then list the source outgoing ACLs and the destination
  incoming ACLs and say whether that TCP, UDP, or ICMP port is allowed or
  denied, naming the allow policy and the deny policy.
  Use when the user gives two VMs or VM NICs and a port.
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
  - path traversal
  - switch
  - router
  - gateway
---

## When to use

Two VMs, or two VM NICs, and one L4 port. The skill does both halves.

Traversal walks VM → subnet → switch → router → gateway, with northbound and southbound fields on each hop. ACL lists every port-set, the source outgoing rules, the destination incoming rules, and the allow policy and the deny policy.

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

## STEP 2: Read the JSON and the markdown

The script writes both. The JSON is the analysis record. The markdown is the rendering.

JSON keys, in order: `traffic`, `tables`, `path`, `acl_source`, `acl_destination`, `verdict`, `ip_mapping`.

`tables` lists `ovn_switch`, `ovn_subnet`, `ovn_router`, and `ovn_l2gw`, and how each column is used. Those tables are filled at ingest. See [PATH_TABLES.md](../../../clickhouse_ovn/PATH_TABLES.md).

`path` is always present. It has the source switch and the destination switch, each with northbound fields, southbound fields, and the VM port number. When the NICs are on different switches it lists every router on the path. When the path leaves through a gateway it includes that gateway's external IP. `l2gw` lists localnet, l2gateway, and geneve rows for those switches.

The markdown draws one mermaid diagram. Each VPC is its own box: host, VM MAC and IP, switch tunnel key in hex, and the tenant router. External gateways sit in their own box, labeled with the redirect-chassis host, the external MAC, and the router tunnel key in hex. Each hop is labeled with the tunnel id on that hop. A VPC-to-gateway hop uses the transit switch tunnel id. The external hop uses the external switch tunnel id. When the verdict is denied, the switch that enforces the drop shows the OpenFlow cookie. That cookie is the first 32 bits of the ACL uuid, which is the OVN stage-hint. A to-lport drop is on the destination switch. A from-lport drop is on the source switch.

Then the file lists VPC, subnet, VLAN, host, Geneve IP, MACs, and hex tunnel keys. Each external gateway has its own host block: hostname, Geneve IP, chassis, chassis name, HA group, and HA priority. The file also has tcpdump on the TAP and on the host NIC, and four tables:

1. **ACL source** — `from-lport` rules whose `inport` is a source port-set. Columns: rule, action, ip, policy, category, peer, ports, matches.
2. **ACL destination** — `to-lport` rules whose `outport` is a destination port-set. Same columns.
3. **Verdict** — verdict, allow policy, deny policy.
4. **IP mapping** — one row per peer address. Prefix lengths stay on the address.

`rule` is the OVN priority. Peer addresses are not repeated inside the ACL tables.

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
[PORTSET_DESIGN.md](../../../PORTSET_DESIGN.md). End to end and each stage on its own are under "How to trigger".
