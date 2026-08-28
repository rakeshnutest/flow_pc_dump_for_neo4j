# Port-set leftover observations

Generated: 2026-08-28T01:34:58Z
Dump: `/home/rakeshkumar.r/panacea/flow_pc_dumps/e2e_v4_smsp`
Source: `flow_policy ClickHouse log_bundle_id=11`
Identity is port-set UUID only. Names are display labels.
K8s / empty Quarantine names are ignore-class noise only, not identity.

## Counts

- Atlas leftover (this UUID in Atlas, not in computed): **0**
- Atlas missing (this UUID in computed, not in Atlas) **critical**: **0**
- NIC UUID bugs: **0**
- ignored 0 K8s leftovers, 0 empty Quarantine leftovers

Empty Quarantine means `atlas_nic_uuids`, `computed_nic_uuids`, `only_atlas_nics`, `atlas_nics`, and `computed_nics` are all empty.

## Atlas leftover

Each UUID below is present in Atlas and absent from computed.
A different UUID that already matches is a different object.

None.

## Atlas missing (critical)

Each UUID below is present in computed and absent from Atlas.

None.
