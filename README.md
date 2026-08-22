# flow_pc_dump_for_neo4j

Dump Prism Central Flow policy and infra objects into JSON that `neo4j_db_insert.py` can prefetch.

The script **must run on the PCVM**, using the Flow venv. It uses `FlowInterfaces` managers (address group, service group, entity group, policy) plus parallel `idfcli` for VMs, subnets, hosts, clusters, and categories. Do **not** use `/home/nutanix/.venvs/bin/bin/python3.9` — that venv has a different `flow` package and fails with `No module named 'flow.common'`.

## Python binary (PCVM)

```text
/home/nutanix/.venvs/flow/bin/python3
```

That is the same interpreter the live `flow` / `microseg` services use:

```text
/home/nutanix/.venvs/flow/bin/python3 /home/nutanix/flow/bin/flow
```

`flow_cli` also forces `PYTHON_TARGET_PATH` to this binary.

## Copy the script to the PC

From your laptop / jump host:

```bash
scp flow_pc_dump_for_neo4j.py nutanix@<PC_IP>:/tmp/flow_pc_dump_for_neo4j.py
ssh nutanix@<PC_IP>
```

Place it anywhere readable by `nutanix` (for example `/tmp`).

## Run

Writes **one file per dataset** under `--output_dir` (default `/tmp/flow_pc_neo4j_prefetch/`), plus a combined `all.json` and `dump.log`. This is **not** `/tmp/flow_neo4j_dump.json`.

```bash
/home/nutanix/.venvs/flow/bin/python3 /tmp/flow_pc_dump_for_neo4j.py \
  --output_dir /tmp/flow_pc_neo4j_prefetch \
  --workers 12 \
  --dataset_timeout_secs 90
```

Output layout:

```text
/tmp/flow_pc_neo4j_prefetch/
  all.json                 # combined prefetch payload
  dump.log                 # run log
  meta.json                # source, timestamps, unique uuids
  address_groups.json
  service_groups.json
  entity_groups.json
  policies.json
  vms.json
  subnets.json
  vpcs.json
  hosts.json
  clusters.json
  projects.json
  categories.json
  network_functions.json
  network_function_by_id.json
  fqdn_to_ip_map.json
  port_set_list.json          # atlas_cli -o json port_set.list
  port_set_get.json           # atlas_cli -o json port_set.get <uuid> (keyed by uuid)
  dump_errors.json
```

Combined file override:

```bash
--output /home/nutanix/flow_pc_neo4j_prefetch_all.json
```

Split an existing combined dump (no live fetch):

```bash
/home/nutanix/.venvs/flow/bin/python3 /tmp/flow_pc_dump_for_neo4j.py \
  --from_json /tmp/flow_neo4j_dump.json \
  --output_dir /tmp/flow_pc_neo4j_prefetch
```

Flags are parsed **before** `FlowInterfaces()` is created. That is required on PC; accessing Flow clients before `FLAGS(argv)` triggers `UnparsedFlagAccessError` and Zeus/ZK retry loops.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--output_dir` | `/tmp/flow_pc_neo4j_prefetch` | Directory for per-dataset JSON + `all.json` + `dump.log` |
| `--output` | `<output_dir>/all.json` | Combined JSON path |
| `--log_file` | `<output_dir>/dump.log` | Log file |
| `--from_json` | unset | Split an existing combined JSON; skip live fetch |
| `--workers` | `12` | Parallel workers for fetch + conversion + writes |
| `--dataset_timeout_secs` | `90` | Per-batch timeout; hung datasets are skipped |
| `--fail_on_error` | off | Exit non-zero if any dataset fails |
| `--skip_atlas` | off | Skip `atlas_cli port_set.list` / `port_set.get` |
| `--atlas_timeout_secs` | `300` | Timeout for `port_set.list` and the `port_set.get` batch |

**SMSP vs CMSP (auto-detected, no flag):** `mspctl cluster list` / `mspctl cluster get flow --verbose`. A cluster named `flow` with a UUID is SMSP → every `atlas_cli` uses `-u ws://smsp-<uuid>.ntnx-ikat.svc:2060/atlas_cli`. No `flow` cluster (404 / only `controller_msp`) plus a local `genesis status` Atlas process is CMSP → `atlas_cli` on the PCVM. `port_set.list` → `port_set_list.json`; each `port_set.get <uuid>` → `port_set_get.json`.

Help:

```bash
/home/nutanix/.venvs/flow/bin/python3 /tmp/flow_pc_dump_for_neo4j.py --help
```

## What it dumps

Logged as `DUMP start` / `DUMP done` / `DATASET … dumped N records`, then `===== DUMP SUMMARY =====`.

| JSON key | Source | Used by `neo4j_db_insert.py` |
|---|---|---|
| `address_groups` | `interfaces.address_group_manager.iter_all()` | `create_ag_map` |
| `service_groups` | `interfaces.service_group_manager.iter_all()` | `create_service_group_map` |
| `entity_groups` | `interfaces.entity_group_manager.iter_all()` | `create_entity_group_map` |
| `policies` | `interfaces.network_security_policy_manager.iter_all()` | `insert_policy_graph` (`policy["data"]`) |
| `hosts` | `host_manager`, else `idfcli` `node` | `load_infrastructure_data` |
| `vms` | `idfcli` `mh_vm` / `vm` | `_fetch_vms` |
| `subnets` | `idfcli` `subnet` / `virtual_network` | `_fetch_subnets` |
| `vpcs` | `idfcli` `vpc` (falls back to `virtual_network`) | `create_vpc_map` |
| `clusters` | `idfcli` `cluster` | `load_infrastructure_data` |
| `projects` | `idfcli` `project` | `load_projects_data` |
| `categories` | `idfcli` `category` | `create_category_map` |
| `network_functions` | `idfcli` `network_function` | `load_network_functions_data` |
| `vlan_unique_uuid` / `global_unique_uuid` | `zkcat` Flow ZK paths | `get_flow_unique_uuid` |
| `fqdn_to_ip_map` | `fqdn_resolution_manager` or `idfcli` `fns_fqdn_to_ip_info` | EG FQDN expansion |
| `port_set_list` | `atlas_cli -o json port_set.list` (SMSP/CMSP wrapped) | Atlas port-set inventory |
| `port_set_get` | `atlas_cli -o json port_set.get <uuid>` for each listed UUID | Atlas port-set details (`virtual_nic_uuid_list`, …) |

Two parallel batches:

1. Flow managers + hosts + zkcat + FQDN
2. VMs / subnets / VPCs / clusters / projects / categories / network functions

Manager object conversion also runs in a thread pool.

## Use with neo4j_db_insert.py

Copy the combined file off the PC, then run the inserter with prefetch:

```bash
ls -lh /tmp/flow_pc_neo4j_prefetch/
scp -r nutanix@<PC_IP>:/tmp/flow_pc_neo4j_prefetch .

python neo4j_db_insert.py \
  --pc-ip <PC_IP> \
  --neo4j-ip <NEO4J_IP> \
  --prefetch-json /tmp/flow_pc_neo4j_prefetch/all.json
```

Exact prefetch CLI flag names come from `neo4j_prefetcher.add_prefetch_cli_arguments` in your tree. The JSON keys above are what `PolicyGraphInserter` reads (`address_groups`, `service_groups`, `entity_groups`, `policies`, `vms`, …).

## Logs to expect

```text
INFO FlowInterfaces managers + parallel idfcli infra (no v4_client)
INFO FlowInterfaces ready
INFO Parallel batch: ['address_groups', 'service_groups', ...]
INFO DUMP start address_groups
INFO DUMP listed address_groups raw N objects
INFO DUMP done address_groups count=N
INFO DATASET address_groups dumped N records
INFO ===== DUMP SUMMARY =====
INFO   address_groups         N
```

Zeus messages such as `Zookeeper host port list is not set` / `Unable to read Zeus configuration` can appear and are usually non-fatal for Flow manager dumps.

## Do not

- Run with `/usr/bin/python3` or `/home/nutanix/.venvs/bin/bin/python3.9`
- Call Prism `v4_client` from this script on PC (it can loop on Zeus config forever)
- Run from `/tmp` with a shebang `python` and no Flow venv — always invoke the Flow binary explicitly

## Example collected on a lab PC

| Dataset | Count (example) |
|---|---|
| address_groups | 1368 |
| service_groups | 2125 |
| entity_groups | 85 |
| policies | 651 |
| vms | 6669 |
| subnets | 1887 |
| categories | 3273 |
| hosts | 32 |
| clusters | 3 |

`projects` / `network_functions` may be `0` if IDF entity-type names do not match this PC. `vpcs` may match `subnets` when `vpc` is missing and the script falls back to `virtual_network`.
