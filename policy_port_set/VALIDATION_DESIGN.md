# Policy port-set and OVN-NB validation

Two standalone scripts. Each is one file, stdlib only, and neither imports the other. Nothing is written to disk. Stdout is the result.

| Script | Question it answers |
|---|---|
| `validate_port_sets.py` | Does the port-set UUID hashed from the Flow policy exist in Atlas `atlas_port_set`? |
| `verify_policy_ovn.py` | For port sets Atlas reports, does OVN-NB have the port group, the peer, and the service-group ACL? |

`validate_port_sets.py` runs on any Prism Central VM. `verify_policy_ovn.py` also starts on any PC VM. OVN-NB is reached from the Prism Central leader, so a follower copies that one file to the leader over the cluster SSH key and prints the leader's stdout. No password is stored in the script.

```
Flow policy.get
        |
        | hash each selector (uuid5, or FLEX MD5)
        v
validate_port_sets.py  ---- compare ---->  idfcli atlas_port_set
        |
        | same hash, copied into the OVN script (not imported)
        v
verify_policy_ovn.py
        | keep a row only when Atlas has the port set and the peer
        | drop Kubernetes names
        v
   1. PORT SET VERIFICATION     OVN-NB Port_Group
   2. SERVICE GROUP VERIFICATION
        Flow ServiceGroupGet + OVN-NB ACL priority and ports
```

## Port-set identity

The UUID is the identity. The Atlas entity id is that UUID. OVN names the port group `port_group_<uuid with dashes turned into underscores>`.

Security Policy rules use `uuid5(scope_uuid, python str(sorted(refs)))`, with a `u'...'` prefix on each UUID in the string. FLEX rules use `MD5("salus" + scope id + Go list "[uuid1 uuid2]")`. On a FIPS PC, MD5 is called with `usedforsecurity=False`.

| Scope | Security Policy namespace | FLEX namespace |
|---|---|---|
| Global | ZooKeeper `global_unique_uuid` | `global-scope-unique-id` |
| VLAN | ZooKeeper `vlan_unique_uuid` | `vlan-scope-unique-id` |
| VPC list or VPC as category | first VPC or scope reference UUID | same UUID |

VM and entity-group selectors have no type suffix. SUBNET appends `:kSubnet`. VPC appends `:kVPC`. A non-default project appends `:project:<uuid>` only when `--include-project` is set. The default is off.

CMSP reads the scope UUIDs with `zkcat` and reads `atlas_port_set` with the local `idfcli`. SMSP reads Atlas ZooKeeper and runs `idfcli` in the flow cluster. `port_set` itself is evictable, so Insights rejects `--all`. The list command is `idfcli get entity -e atlas_port_set --all -o json`.

Address groups are not port sets. Policies in SAVE mode are skipped. A missing FLEX `applied_to` field is UI Global and is not hashed. `should_allow_any_src`, `should_allow_any_dst`, or a FLEX rule with no selector hashes the empty VM list `[]`.

## Atlas check

`validate_port_sets.py` loads every policy with `flow_cli policy.list` and `policy.get`, hashes every selector, and loads every `atlas_port_set`. A UUID that is on both sides is not printed. Stdout is only the mismatches:

| mismatch | meaning | `nic_mismatch` |
|---|---|---|
| `computed_without_idf` | the policy hash is not an Atlas port set | `port_set_missing` |
| `idf_without_computed` | Atlas has a port set the policy walk did not emit | comma-separated NIC UUIDs |

Two Atlas-only rows are left out of `idf_without_computed`:

- The Atlas name starts with `K8s_`.
- The Atlas name starts with `Quarantine` and the NIC list is empty.

That exception does not hide a hash Atlas never created. Quarantine Forensic and Quarantine Strict are `computed_without_idf` when Atlas has no entity for them. An exclude selector hashed as its own port set is also `computed_without_idf` when Atlas does not create that UUID. Exit status is 1 when any mismatch row is printed.

## OVN-NB check

`verify_policy_ovn.py` hashes the same selectors in its own copy of the algorithm. For each port set it records the incoming peers and the outgoing peers.

An incoming ACL has `outport == @port_group_<owner>` and the peer in `ip4.src` or `ip6.src`. An outgoing ACL has `inport == @port_group_<owner>` and the peer in `ip4.dst` or `ip6.dst`. The peer may be a port group or an address set. The ACL priority is kept when that ACL covers the service ports. Otherwise the row keeps the policy rule priority.

The script prints two sections, in this order. Only failures are printed.

### 1. Port set verification

Columns: `policy`, `port_set`, `direction`, `peer_port_set`, `ovn`.

| `ovn` | meaning |
|---|---|
| `missing` | Atlas has this port set and OVN-NB has no port group |
| `peer_missing` | Atlas has the peer and OVN-NB has no port group for it |
| `present` | both port groups exist; the row is not printed |

A port set or peer that is absent from `atlas_port_set` is ignored. OVN is not asked to have a port group Atlas did not report. Kubernetes is ignored when the policy name or the Atlas name matches `k8s`, `kubernetes`, or `cilium_vlan_scope`. Those Cilium VLAN-scope port groups exist in OVN with no member ports and no ACL, so they are not an OVN failure.

### 2. Service group verification

This section runs only for rows whose port set and peer are already `present`. Columns add `service_group`, `service`, `priority`, and `ovn`.

Flow service groups come from `ServiceGroupGet` through the Flow virtualenv. The JSON stays in memory. A rule with no service group and service `ALL` is not a service-group row.

| `ovn` | meaning |
|---|---|
| `sg_missing` | Flow did not return this service group |
| `acl_missing` | no ACL for that owner, direction, and peer |
| `service_missing` | an ACL exists and does not cover the service ports |
| `present` | the ACL covers every port in the service; not printed |

`service` looks like `tcp/80`, `udp/53-53`, `icmp/8`, or a comma-separated list. Exit status is 1 when either section has a missing row.

## Completed OVN-NB check

The check finished on the CMSP Prism Central at `10.120.159.166`, with OVN-NB read from the leader `10.120.159.168`. Exit status 0.

| | count |
|---|---|
| policies | 651 |
| service groups | 2125 |
| policy edges | 13854 |
| Atlas `atlas_port_set` | 1291 |
| edges kept for OVN | 13820 |
| OVN port groups | 1291 |
| OVN ACLs | 16691 |
| port sets | checked 1184, present 1184, missing 0 |
| service groups | checked 12636, present 12636, missing 0 |

The same counts were produced before and after `verify_policy_ovn.py` stopped importing `validate_port_sets.py`.

The Atlas script on that same PC still reports its own mismatches. Those rows are outside the OVN sections because Atlas did not report the UUID, or because the Kubernetes name is ignored: 16 `EG_Exclude_Policy1` exclude port sets, Quarantine Forensic, Quarantine Strict, and the empty `K8s_App_*_Cilium_VLAN_Scope` port groups.
