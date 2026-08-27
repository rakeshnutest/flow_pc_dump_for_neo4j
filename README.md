# flow_pc_dump.py

PC dump is **collect only**. Copy **only** `flow_pc_dump.py` to the PC (system python3, no Flow venv). Convert/enrich is `flow_pc_map.py` + `flow_pc_process.py` on this workstation — do not copy those to the PC.

On the PCVM:

```bash
python3 /home/nutanix/data/flow_pc_dump.py \
  --output_dir /home/nutanix/upgrade/flow_pc_dump
```

That collects `idfcli/`, `ahv_gateway/` (OVS), `cmsp_ovn/` (OVN), and atlas `port_set_list.json` / `port_set_get.json`. It does **not** call FlowInterfaces, convert policies, or write `policies.json`.

Locally, after you copy the dump off the PC:

```bash
python3 flow_pc_process.py --dump_dir /path/to/dump
python3 flow_pc_process.py --dump_dir /path/to/dump --ingest --log_bundle_id N
```

`flow_pc_process.py` calls `flow_pc_map.process_dump`, which maps `idfcli/*.json` into `policies.json`, AG/SG/EG, VMs, NICs (stdlib only; no Flow venv).

## Copy the script to the PC

From your laptop / jump host:

```bash
scp flow_pc_dump.py nutanix@<PC_IP>:/home/nutanix/data/
ssh nutanix@<PC_IP>
```

Place it in `/home/nutanix/data/` (do **not** use `/tmp`; it is a small loop on many PCs).

## Run (PC, dump only)

Writes under `--output_dir` (default `/home/nutanix/upgrade/flow_pc_dump/`).

```bash
python3 /home/nutanix/data/flow_pc_dump.py \
  --output_dir /home/nutanix/upgrade/flow_pc_dump \
  --workers 16 \
  --atlas_get_workers 32 \
  --dataset_timeout_secs 180 \
  --atlas_timeout_secs 1800
```

Output layout:

```text
/home/nutanix/upgrade/flow_pc_dump/
  all.json                 # dump index (not prefetch policies)
  dump.log
  unique_uuids.json
  idfcli/                  # raw idfcli get entitytype
  port_set_list.json
  port_set_get.json
  ahv_gateway.json
  ahv_gateway/<hypervisor_ip>/
  cmsp_ovn.json
  cmsp_ovn/anc-ovn/
  dump_errors.json
```

Combined file override:

```bash
--output /home/nutanix/flow_pc_neo4j_prefetch_all.json
```

Local convert (after rsync):

```bash
python3 flow_pc_process.py --dump_dir /path/to/dump
```

That writes `policies.json`, `address_groups.json`, `vms.json`, and the rest.

Flags are argparse on the dump CLI. Flow venv is **not** required for dump.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--output_dir` | `/home/nutanix/upgrade/flow_pc_dump` | Directory for per-dataset JSON + `all.json` + `dump.log` |
| `--output` | `<output_dir>/all.json` | Combined JSON path |
| `--log_file` | `<output_dir>/dump.log` | Log file |
| `--workers` | `16` | Parallel workers for idfcli types + writes |
| `--dataset_timeout_secs` | `180` | Per-idfcli-type timeout |
| `--fail_on_error` | off | Exit non-zero if any dataset fails |
| `--skip_atlas` | off | Skip `atlas_cli port_set.list` / `port_set.get` |
| `--atlas_timeout_secs` | `1800` | Timeout for `port_set.list` and the `port_set.get` batch |
| `--atlas_get_workers` | `32` | Parallel `atlas_cli port_set.get` processes |
| `--skip_ahv_gateway` | off | Skip AHV Gateway host collect (default **on**: OVS/virsh/tap/brAtlas from every PE hypervisor) |
| `--ahv_gateway_timeout_secs` | `1800` | Retry budget across all hosts until every required artifact exists |
| `--ahv_gateway_class_timeout_secs` | `300` | Per-class bugtool HTTP timeout |
| `--ahv_gateway_workers` | `8` | Parallel hypervisor collects |
| `--ahv_gateway_port` | `7030` | AHV Gateway HTTPS port |
| `--ahv_gateway_cert_dir` | `/home/certs/ClusterHealthService` | mTLS cert/key directory (`<name>.crt` + `<name>.key`) |
| `--skip_cmsp_ovn` | off | Skip CMSP kubectl OVN NB/SB dump (default **on**) |
| `--cmsp_ovn_timeout_secs` | `1800` | Retry budget until NB and SB `ovsdb-client dump` exist |
| `--cmsp_ovn_namespace` | empty | Kubernetes namespace; empty searches all namespaces |

**SMSP vs CMSP (auto-detected, no flag):** `mspctl cluster list` / `mspctl cluster get flow --verbose`. A cluster named `flow` with a UUID is SMSP → every `atlas_cli` uses `-u ws://smsp-<uuid>.ntnx-ikat.svc:2060/atlas_cli`. No `flow` cluster (404 / only `controller_msp`) plus a local `genesis status` Atlas process is CMSP → `atlas_cli` on the PCVM. `port_set.list` → `port_set_list.json`; each `port_set.get <uuid>` → `port_set_get.json`.

**AHV Gateway host collect (default on, never SSH to AHV):** The script mTLS-calls each PE hypervisor at `:7030` with the PC `ClusterHealthService` cert and **retries until all of these exist per host**:

- `ovs-vsctl show`
- `ovs-dpctl -s show`
- `ovs-ofctl dump-flows brAtlas` (and any other `brAtlas` ofctl outputs in the `networking` class)
- `virsh list --all` + `virsh dumpxml` (tap/MAC per VM)
- tap devices
- OVN/OVS DB (`ovn*.db` / `conf.db`, plus an `ovn` bugtool class if advertised)

Layout: `<output_dir>/ahv_gateway/<hypervisor_ip>/` plus `ahv_gateway.json`. Complete when **every** PE host has the required OVS/virsh/tap artifacts.

**CMSP OVN NB/SB (default on):** OVN Northbound/Southbound live in kubectl pods on the PC (`anc-ovn-0` / container `anc-ovn`), not on AHV. The dump runs (no `-it`):

```bash
sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
```

It retries until both dumps exist. Layout: `<output_dir>/cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_{nb,sb}.txt`.

**Where the files are:**

| Place | What you get |
|---|---|
| `<output_dir>/ahv_gateway/<hypervisor_ip>/` | Per-host OVS/virsh/tap/brAtlas/conf.db from AHV Gateway |
| `<output_dir>/ahv_gateway.json` | Per-host complete/missing index |
| `<output_dir>/cmsp_ovn/` | OVN NB/SB (+ IC/policy) from kubectl on CMSP PC |
| `<output_dir>/cmsp_ovn.json` | kubectl dump index |

Help:

```bash
python3 /home/nutanix/data/flow_pc_dump.py --help
```

## What process writes (local)

`flow_pc_process.py` / `flow_pc_map.py` map idfcli into prefetch JSON locally. Logged as `DUMP start` / `DUMP done` / `DATASET … dumped N records`. Source is **idfcli files**, not FlowInterfaces.

| JSON key | Source | Used by `neo4j_db_insert.py` |
|---|---|---|
| `address_groups` | `idfcli` `network_address_group` | `create_ag_map` |
| `service_groups` | `idfcli` `network_service_group` (`.txt` zprotobuf ports) | `create_service_group_map` |
| `entity_groups` | `idfcli` `network_entity_group` | `create_entity_group_map` |
| `policies` | `idfcli` `network_security_policy` (`.txt` zprotobuf rules) | `insert_policy_graph` (`policy["data"]`) |
| `hosts` | `idfcli` `node` | `load_infrastructure_data` |
| `vms` | `idfcli` `vm` / `mh_vm`; NIC join from `virtual_nic`; VM categories from `abac_entity_capability` (`kind=vm`) | `_fetch_vms` |
| `subnets` | `idfcli` `virtual_network` / `subnet` (`overlay_network_uuid`, `advanced_networking`); subnet categories from `abac_entity_capability` | `_fetch_subnets` |
| `vpcs` | Overlay stubs from `overlay_network_uuid` plus ALL_VLAN `00000000-0000-0000-0000-000000000001` named `VLAN` | `create_vpc_map` |
| `categories` | `idfcli` `abac_category` merged with `category` (`key:value`) | `create_category_map` |
| `clusters` | `idfcli` `cluster` | `load_infrastructure_data` |
| `projects` | `idfcli` `project` | `load_projects_data` |
| `categories` | `idfcli` `category` | `create_category_map` |
| `network_functions` | `idfcli` `network_function` | `load_network_functions_data` |
| `vlan_unique_uuid` / `global_unique_uuid` | `zkcat` Flow ZK paths | `get_flow_unique_uuid` |
| `fqdn_to_ip_map` | `idfcli` `fns_fqdn_to_ip_info` | EG FQDN expansion |
| `port_set_list` | `atlas_cli -o json port_set.list` (SMSP/CMSP wrapped) | Atlas port-set inventory |
| `port_set_get` | `atlas_cli -o json port_set.get <uuid>` for each listed UUID | Atlas port-set details (`virtual_nic_uuid_list`, …) |
| `ahv_gateway` | PC mTLS AHV Gateway `:7030` per hypervisor | Host OVS / virsh / tap / brAtlas |
| `cmsp_ovn` | `sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovn{nb,sb}_db.sock` | OVN Northbound + Southbound |

Each VM NIC `nic_network_info` includes:

- `vm_categories` / `vm_category_ids` — this VM's categories (`key:value`)
- `subnet.ext_id`, `subnet.name`, `subnet.subnet_type`, `subnet.is_advanced_networking`
- `subnet.categories` (`key:value`) and `subnet.category_ids`
- `vpc.ext_id`, `vpc.name` (never empty; overlay name inferred from subnet prefix), `vpc.categories`, `vpc.category_ids`

The IDF `vm` entity has no `category_id_list`. VM/subnet/VPC categories are joined from `idfcli abac_entity_capability` (`kind` + `kind_id` / `uuid` + `category_id_list`).

VLAN NICs use the same ALL_VLAN VPC as `neo4j_db_insert.py`: uuid `00000000-0000-0000-0000-000000000001`, name `VLAN`. Overlay NICs use `overlay_network_uuid`.

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
INFO FlowInterfaces + platform detect in parallel (no v4_client)
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

## ClickHouse port-set compare (local)

After a dump exists, ingest policy hashes vs Atlas `port_set.list` / `port_set.get` into local ClickHouse (`127.0.0.1:19000`, database `flow_policy`). Identity is **port-set UUID only**. Names are display.

Required files: `clickhouse_flow/ingest.py`, `compare.py`, `observe_leftovers.py`, `portset_hash.py`, `schema.sql`. Leftover analysis skill: `.cursor/skills/portset-leftover-observe/SKILL.md`.

```bash
python3 clickhouse_flow/ingest.py --dump_dir /path/to/dump
python3 clickhouse_flow/compare.py
python3 clickhouse_flow/observe_leftovers.py \
  --dump_dir /path/to/dump \
  --out clickhouse_flow/leftover_observations.md
```

- `ingest.py` loads every policy (APPLICATION, FLEX, kube), hashes port-sets the same way as `neo4j_db_insert.py`, and stores Atlas leftovers.
- `compare.py` stamps match/mismatch. A computed NIC UUID missing in Atlas, or an Atlas NIC UUID missing in computed, is a bug. Atlas leftover UUIDs stay mismatches.
- `observe_leftovers.py` writes UUID-only leftover notes (Atlas leftover vs Atlas missing). Do not group leftovers by display name.

## Do not

- Call Prism `v4_client` or construct `FlowInterfaces()` from the PC dump (Zeus)
- Run dump from `/tmp` (small loop filesystem on many PCs)
- Copy `flow_pc_map.py` or `flow_pc_process.py` to the PC (convert stays local)

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
