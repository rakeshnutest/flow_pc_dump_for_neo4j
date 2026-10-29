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
   fetch OVN-NB Port_Group and ACL
        v
   one dict per port set
        incoming:  peer port_set, priority, service_group[], service[][]
        outgoing:  peer port_set, priority, service_group[], service[][]
        each entry verified against the fetched OVN-NB rows
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

`verify_policy_ovn.py` hashes the same selectors in its own copy of the algorithm. For each owner port set it builds one dict:

```json
{
  "policy": "App",
  "port_set": "917386ac-6978-5da1-91a6-3782ffebd275",
  "ovn": "present",
  "incoming": [
    {
      "port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      "priority": "100",
      "service_group": ["Web", "SSH"],
      "service": [["tcp/80"], ["tcp/22", "udp/22"]],
      "ovn": "present"
    }
  ],
  "outgoing": [
    {
      "port_set": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      "priority": "25",
      "service_group": ["mysql"],
      "service": [["tcp/3306", "udp/3306"]],
      "ovn": "present"
    }
  ]
}
```

`service_group` is the list of service groups on that peer. `service` is the matching list of port lists. One Flow rule carries a list of service groups, and one service group carries a list of protocol/port ranges, so neither field is a single string. `priority` is the number on the OVN-NB ACL row. Every ACL is priority-checked: a row with no integer priority fails as `priority_missing`. The check does not rank policy types.

OVN-NB is fetched on the Prism Central leader before any port set is checked. The data stays in memory. On CMSP the commands run inside the `anc-ovn-0` pod:

```
ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --format=csv --data=bare --no-heading --columns=name list Port_Group
ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock --format=csv --data=bare --no-heading --columns=priority,action,match list ACL
```

Stdout is the report. It names the fetch, then the check, then the missing rows, then the fetched port groups that were not part of the check:

```
OVN NB fetched: port_groups=1291 acls=16691
OVN NB report: port_sets=1184 present=1184 missing=0 not_checked=107
OVN NB missing: 0
OVN NB not_checked: 107
{"port_set":"07388d75-8498-5e07-813a-b007f27679a9","reason":"no_policy_uuid","detail":"No current policy UUID hashes to port set 07388d75-8498-5e07-813a-b007f27679a9."}
```

`missing` is a port set the policy check expected and OVN-NB did not confirm. Each missing row is the full incoming and outgoing dict. `not_checked` is an OVN port group whose UUID no current policy hash produced. A shared name string does not attach that port set to a policy. The row carries the port-set UUID only.

| reason | meaning |
|---|---|
| `no_policy_uuid` | No current policy UUID hashes to this port-set UUID. |
| `not_in_atlas` | OVN-NB has this port-set UUID. Atlas has no entity with that UUID. |
| `kubernetes` | This port set is skipped by the kubernetes name filter. |

`port_groups` is the number of `Port_Group` rows. `acls` is the number of `ACL` rows. Each checked dict is verified against those rows: the owner port group, the peer port group, the ACL direction, the priority, and every port in `service`.

An incoming ACL has `outport == @port_group_<owner>` and the peer in `ip4.src` or `ip6.src`. An outgoing ACL has `inport == @port_group_<owner>` and the peer in `ip4.dst` or `ip6.dst`.

| `ovn` | meaning |
|---|---|
| `missing` | this port group is not in OVN-NB |
| `peer_missing` | the peer port group is not in OVN-NB |
| `sg_missing` | Flow did not return a service group in the list |
| `acl_missing` | no ACL for that peer and direction |
| `service_missing` | an ACL exists and does not cover every port in the service lists |
| `present` | the port group, peer, and every service are covered by an ACL whose priority is an integer |
| `priority_missing` | the ACL row has no integer priority |

A port set or peer that is absent from `atlas_port_set` is ignored. Kubernetes is ignored when the policy name or the Atlas name matches `k8s`, `kubernetes`, or `cilium_vlan_scope`. Those ignored port groups still appear under `OVN NB not_checked`. Exit status is 1 when `missing` is not 0.

## Completed OVN-NB check

The check finished on the CMSP Prism Central at `10.120.159.166`, with OVN-NB read from the leader `10.120.159.168`. Exit status 0.

```
OVN NB acl: checked=28793 verified=28793 failed=0 priority_checked=28793 priority_failed=0
OVN NB acl kind: global=7406 incoming=8796 inport_only=2534 outgoing=7539 outport_only=2518
OVN NB acl priority: 31500=3762 1097=8 1095=24 1092=8 1090=8 1080=16 1065=40 1064=20 1060=2414 1055=8 1052=2422 1050=11355 1045=4844 1019=32 1018=32 1017=32 1015=64 1005=40 1004=20 1000=2 500=3640 100=2
OVN NB fetched: port_groups=1291 acls=28793
OVN NB report: port_sets=1184 present=1184 missing=0 not_checked=107
```

Of the 107 not checked, 4 are `kubernetes`: `bc82fa37-7265-5538-aa20-219c289683aa`, `39c086c2-f638-5ff6-a243-476b74f79e08`, `587c061b-1ce1-5cac-b0b4-e6687b4f32ea`, `ae312d44-626d-5369-b3f4-b7d6a782afb6`. The other 103 are `no_policy_uuid`. No current policy UUID hashes to those port-set UUIDs. The name string on the Atlas entity is not used.

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

The Atlas script on that same PC still reports its own mismatches. Those port sets stay out of the OVN dict because Atlas did not report the UUID, or because the Kubernetes name is ignored: 16 `EG_Exclude_Policy1` exclude port sets, Quarantine Forensic, Quarantine Strict, and the empty `K8s_App_*_Cilium_VLAN_Scope` port groups.
