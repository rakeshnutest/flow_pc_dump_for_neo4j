# Port-set leftover observations

Generated: 2026-08-24T15:41:13Z
Dump: `(none)`
Source: `/home/rakeshkumar.r/panacea/flow_pc_dumps/clickhouse_all_dump/flow_policy/portset.jsonl`
Identity is port-set UUID only. Names are display labels.
K8s / empty Quarantine names are ignore-class noise only, not identity.

## Counts

- Atlas leftover (this UUID in Atlas, not in computed): **4**
- Atlas missing (this UUID in computed, not in Atlas) **critical**: **0**
- NIC UUID bugs: **0**
- ignored 4 K8s leftovers, 2 empty Quarantine leftovers

Empty Quarantine means `atlas_nic_uuids`, `computed_nic_uuids`, `only_atlas_nics`, `atlas_nics`, and `computed_nics` are all empty.

## Atlas leftover

Each UUID below is present in Atlas and absent from computed.
A different UUID that already matches is a different object.

### `2e80f4fe-5534-5d44-b204-4b699fe2e005`

- kind: `atlas_without_computed`
- display atlas_name: `App_680_No_VMs`
- **UUID match**
  - verdict: **Atlas leftover (this UUID is Atlas-only)**
  - this UUID: `2e80f4fe-5534-5d44-b204-4b699fe2e005`
  - computed has this UUID: `no`
  - Atlas has this UUID: `yes`
  - computed NIC UUIDs (0): (none)
  - Atlas NIC UUIDs (0): (none)
  - NIC UUIDs in both: (none)
  - computed NIC UUIDs missing in Atlas: (none)
  - Atlas NIC UUIDs missing in computed: (none)
- entity_group_uuid: `00000000-0000-0000-0000-000000000000`
- entity_group_name: ``
- allowed entities:
  - (none)
- **components**
  - policy=`App_680_No_VMs` role=`` entity_type=``
    - namespace_uuid: `00000000-0000-0000-0000-000000000000` ()
    - virtual_network_uuid: `00000000-0000-0000-0000-000000000000` ()
- observation: This UUID is in Atlas and not in computed. Match is UUID identity, not name.
- observation: PC dump JSON not available; leftover classified from portset.jsonl only.
- observation: No NIC-UUID bug on this leftover (both NIC sets empty or equal).

### `464d384b-9dcc-5d1e-a7f0-52ecc27242b1`

- kind: `atlas_without_computed`
- display atlas_name: `App_680_No_VMs`
- **UUID match**
  - verdict: **Atlas leftover (this UUID is Atlas-only)**
  - this UUID: `464d384b-9dcc-5d1e-a7f0-52ecc27242b1`
  - computed has this UUID: `no`
  - Atlas has this UUID: `yes`
  - computed NIC UUIDs (0): (none)
  - Atlas NIC UUIDs (0): (none)
  - NIC UUIDs in both: (none)
  - computed NIC UUIDs missing in Atlas: (none)
  - Atlas NIC UUIDs missing in computed: (none)
- entity_group_uuid: `00000000-0000-0000-0000-000000000000`
- entity_group_name: ``
- allowed entities:
  - (none)
- **components**
  - policy=`App_680_No_VMs` role=`` entity_type=``
    - namespace_uuid: `00000000-0000-0000-0000-000000000000` ()
    - virtual_network_uuid: `00000000-0000-0000-0000-000000000000` ()
- observation: This UUID is in Atlas and not in computed. Match is UUID identity, not name.
- observation: PC dump JSON not available; leftover classified from portset.jsonl only.
- observation: No NIC-UUID bug on this leftover (both NIC sets empty or equal).

### `5a735f89-39ac-5620-b5ae-4651ced5e6a5`

- kind: `atlas_without_computed`
- display atlas_name: `App_681_No_VMs`
- **UUID match**
  - verdict: **Atlas leftover (this UUID is Atlas-only)**
  - this UUID: `5a735f89-39ac-5620-b5ae-4651ced5e6a5`
  - computed has this UUID: `no`
  - Atlas has this UUID: `yes`
  - computed NIC UUIDs (0): (none)
  - Atlas NIC UUIDs (0): (none)
  - NIC UUIDs in both: (none)
  - computed NIC UUIDs missing in Atlas: (none)
  - Atlas NIC UUIDs missing in computed: (none)
- entity_group_uuid: `00000000-0000-0000-0000-000000000000`
- entity_group_name: ``
- allowed entities:
  - (none)
- **components**
  - policy=`App_681_No_VMs` role=`` entity_type=``
    - namespace_uuid: `00000000-0000-0000-0000-000000000000` ()
    - virtual_network_uuid: `00000000-0000-0000-0000-000000000000` ()
- observation: This UUID is in Atlas and not in computed. Match is UUID identity, not name.
- observation: PC dump JSON not available; leftover classified from portset.jsonl only.
- observation: No NIC-UUID bug on this leftover (both NIC sets empty or equal).

### `5e2f89d7-a757-5df3-be0f-ef13f0ea6afb`

- kind: `atlas_without_computed`
- display atlas_name: `App_681_No_VMs`
- **UUID match**
  - verdict: **Atlas leftover (this UUID is Atlas-only)**
  - this UUID: `5e2f89d7-a757-5df3-be0f-ef13f0ea6afb`
  - computed has this UUID: `no`
  - Atlas has this UUID: `yes`
  - computed NIC UUIDs (0): (none)
  - Atlas NIC UUIDs (0): (none)
  - NIC UUIDs in both: (none)
  - computed NIC UUIDs missing in Atlas: (none)
  - Atlas NIC UUIDs missing in computed: (none)
- entity_group_uuid: `00000000-0000-0000-0000-000000000000`
- entity_group_name: ``
- allowed entities:
  - (none)
- **components**
  - policy=`App_681_No_VMs` role=`` entity_type=``
    - namespace_uuid: `00000000-0000-0000-0000-000000000000` ()
    - virtual_network_uuid: `00000000-0000-0000-0000-000000000000` ()
- observation: This UUID is in Atlas and not in computed. Match is UUID identity, not name.
- observation: PC dump JSON not available; leftover classified from portset.jsonl only.
- observation: No NIC-UUID bug on this leftover (both NIC sets empty or equal).

## Atlas missing (critical)

Each UUID below is present in computed and absent from Atlas.

None.
