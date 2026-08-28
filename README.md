# flow_pc_dump

## Which script where

| Where | Script | What it does | How to invoke |
|---|---|---|---|
| **PCVM** | `flow_pc_dump.py` | Collect only (raw stdout/tarballs): idfcli, atlas_cli, flow_cli/kratos policy.list+get, AHV Gateway OVS, CMSP OVN | system `python3` on the PC (no Flow venv) |
| **This workstation** | `flow_pc_process.py` | Convert/enrich the dump, optional ClickHouse ingest | `python3 flow_pc_process.py --dump_dir …` |
| **This workstation** | `vm_host_inventory.py` | One row per NIC: VM, IP, subnet, host, cluster | `python3 vm_host_inventory.py --dump_dir …` |
| **This workstation** (not run by hand) | `flow_pc_map.py` | Maps `idfcli/` (and `policy_get.json`) into `policies.json` / AG / SG / EG / VMs | imported by `flow_pc_process.py` |

Copy **only** `flow_pc_dump.py` to the PC. Do **not** copy `flow_pc_process.py` or `flow_pc_map.py`.

## End-to-end: invoke in this order

Run these from a workstation that can SSH to the PC. ClickHouse is local
`127.0.0.1:19000`. Set the three values once:

```bash
PC_IP=<PC_IP>
DUMP=/path/to/dump          # local copy of the PC output
BUNDLE=1                    # flow_policy / flow_ovn log_bundle_id
REPO=/path/to/flow_pc_dump_github
```

Do **not** write the PC dump under `/tmp` (small loop). Use
`/home/nutanix/upgrade/…`. AHV Gateway extracts every networking/avm/ovn
tar member (~23G on a 32-host cluster). OVS/virsh/OVN alone is ~6G.

### 1. Copy the dump script to the PC

```bash
scp "$REPO/flow_pc_dump.py" nutanix@$PC_IP:/home/nutanix/data/flow_pc_dump.py
```

### 2. Collect on the PC (system python3, no Flow venv)

```bash
ssh nutanix@$PC_IP
python3 /home/nutanix/data/flow_pc_dump.py \
  --output_dir /home/nutanix/upgrade/flow_pc_dump \
  --workers 16 \
  --atlas_get_workers 32 \
  --dataset_timeout_secs 180 \
  --atlas_timeout_secs 1800 \
  --flow_cli_timeout_secs 1800 \
  --ahv_gateway_timeout_secs 1800 \
  --cmsp_ovn_timeout_secs 1800
```

Wait until `DUMP done` is in `/home/nutanix/upgrade/flow_pc_dump/dump.log`
and `all.json` exists. Convert is **not** run on the PC.

### 3. Copy the dump off the PC

```bash
mkdir -p "$DUMP"
rsync -a nutanix@$PC_IP:/home/nutanix/upgrade/flow_pc_dump/ "$DUMP/"
```

### 4. Optional: drop an existing ClickHouse bundle

Skip if `BUNDLE` is new. Re-ingest of the same id already drops that
partition first. To wipe one id and stop:

```bash
cd "$REPO"
python3 clickhouse_flow/ingest.py --drop-bundle "$BUNDLE"
python3 clickhouse_ovn/ingest.py --drop-bundle "$BUNDLE"
```

### 5. Convert locally, then ingest OVN + flow_policy

```bash
cd "$REPO"
python3 flow_pc_process.py \
  --dump_dir "$DUMP" \
  --timeout_secs 1800 \
  --ingest \
  --log_bundle_id "$BUNDLE"
```

That writes `policies.json` / `vms.json` / … under `$DUMP`, then:

- `clickhouse_ovn/ingest.py --dump_dir "$DUMP" --log_bundle_id "$BUNDLE"`
- `clickhouse_flow/ingest.py --dump_dir "$DUMP" --log_bundle_id "$BUNDLE"`

Ingest only (dump already converted):

```bash
python3 flow_pc_process.py --dump_dir "$DUMP" --skip-convert --ingest --log_bundle_id "$BUNDLE"
```

### 6. Compare computed port-sets to Atlas

```bash
cd "$REPO"
python3 clickhouse_flow/compare.py --log_bundle_id "$BUNDLE"
```

Identity is **port-set UUID**. Names are display. A FAIL with four Atlas
leftover empty-NIC UUIDs (`App_680_No_VMs` / `App_681_No_VMs`) is the
known leftover set, not a dump failure.

### 7. Optional: leftover observations

```bash
cd "$REPO"
python3 clickhouse_flow/observe_leftovers.py \
  --from_ch --log_bundle_id "$BUNDLE" \
  --dump_dir "$DUMP" \
  --out clickhouse_flow/leftover_observations.md
```

### PC — collect (flags and output layout)


From your laptop / jump host:

```bash
scp flow_pc_dump.py nutanix@<PC_IP>:/home/nutanix/data/
ssh nutanix@<PC_IP>
```

Put it in `/home/nutanix/data/` (do **not** use `/tmp`; it is a small loop on many PCs). Then on the PCVM:

```bash
python3 /home/nutanix/data/flow_pc_dump.py \
  --output_dir /home/nutanix/upgrade/flow_pc_dump
```

With typical timeouts:

```bash
python3 /home/nutanix/data/flow_pc_dump.py \
  --output_dir /home/nutanix/upgrade/flow_pc_dump \
  --workers 16 \
  --atlas_get_workers 32 \
  --dataset_timeout_secs 180 \
  --atlas_timeout_secs 1800
```

That writes **raw** command output: `idfcli/` (`idfcli get entity --all -o json` stdout as-is), `ahv_gateway/` (all AHV Gateway OVS/virsh tar members), `cmsp_ovn/` (OVN), atlas `port_set_list.json` / `port_set_get.json`, `policy_list.json` / `policy_get.json` from `flow_cli` (CMSP on the PC or kratos on SMSP), and `service_group_list.json` / `service_group_get.json` from v4 `ServiceGroupGet`. Dump does **not** flatten, unwrap, convert, or write `policies.json`. Help: `python3 /home/nutanix/data/flow_pc_dump.py --help`.

### Local — convert (after rsync)

Copy the dump off the PC, then from this repo:

```bash
rsync -a nutanix@<PC_IP>:/home/nutanix/upgrade/flow_pc_dump/ /path/to/dump/

python3 flow_pc_process.py --dump_dir /path/to/dump
```

That writes `policies.json`, `address_groups.json`, `vms.json`, and the rest (stdlib only; no Flow venv).

Convert and ingest into ClickHouse (`127.0.0.1:19000`):

```bash
python3 flow_pc_process.py --dump_dir /path/to/dump --ingest --log_bundle_id N
```

Help: `python3 flow_pc_process.py --help`. Do not run `flow_pc_map.py` directly.

## PC dump output

Writes under `--output_dir` (default `/home/nutanix/upgrade/flow_pc_dump/`).

```text
/home/nutanix/upgrade/flow_pc_dump/
  all.json                 # dump index (not prefetch policies)
  dump.log
  unique_uuids.json
  idfcli/                  # idfcli get entity --all -o json (raw stdout)
  port_set_list.json
  port_set_get.json
  policy_list.json
  policy_get.json
  ahv_gateway.json
  ahv_gateway/<hypervisor_ip>/
  cmsp_ovn.json
  cmsp_ovn/anc-ovn/
  dump_errors.json
```

Combined file override: `--output /home/nutanix/flow_pc_neo4j_prefetch_all.json`.

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
| `--skip_flow_cli` | off | Skip `flow_cli` / kratos `policy.list` / `policy.get` |
| `--flow_cli_timeout_secs` | `1800` | Timeout for `policy.list` and the `policy.get` batch |
| `--flow_cli_get_workers` | `32` | Parallel `policy.get` (capped at 8 inside the kratos pod) |
| `--skip_ahv_gateway` | off | Skip AHV Gateway host collect (default **on**: OVS/virsh/tap/brAtlas from every PE hypervisor) |
| `--ahv_gateway_timeout_secs` | `1800` | Unused for filtering; kept for CLI compatibility |
| `--ahv_gateway_class_timeout_secs` | `300` | Per-class bugtool HTTP timeout |
| `--ahv_gateway_workers` | `8` | Parallel hypervisor collects |
| `--ahv_gateway_port` | `7030` | AHV Gateway HTTPS port |
| `--ahv_gateway_cert_dir` | `/home/certs/ClusterHealthService` | mTLS cert/key directory (`<name>.crt` + `<name>.key`) |
| `--skip_cmsp_ovn` | off | Skip CMSP kubectl OVN NB/SB dump (default **on**) |
| `--cmsp_ovn_timeout_secs` | `1800` | Retry budget until NB and SB `ovsdb-client dump` exist |
| `--cmsp_ovn_namespace` | empty | Kubernetes namespace; empty searches all namespaces |
| `--skip_flow_proto` | **on** | No-op (Flow proto field map is not collected) |

**SMSP vs CMSP (auto-detected, no flag):** `mspctl cluster get flow --verbose` `ClusterUUID` (same as `AtlasCliHelper` / `FnsPortSetValidator`), with `mspctl cluster list` as fallback. A flow MSP UUID is SMSP → every `atlas_cli` uses `-u ws://smsp-<uuid>.ntnx-ikat.svc:2060/atlas_cli`. OVN kubectl uses `mspctl cluster kubeconfig flow` (pods such as `anc-ovn-0` live in the flow cluster, often `ntnx-flow`, not PC MSP kube). `vlan_unique_uuid` / `global_unique_uuid` also come from the flow Atlas pod ZooKeeper (`ZookeeperSession.get` of `/appliance/logical/flow/{vlan,global}_unique_uuid`), not PC `zkcat` — same as `MicrosegHelper.get_flow_unique_uuid` when `flow_smsp`. Policy details: `kubectl -n ntnx-flow exec <kratos-pod> -- bash -lc 'kratos_cli|flow_cli -o json policy.list|get <uuid>'` (never `-it`; this image's binary is `flow_cli`, runbook name `kratos_cli`). If the kratos exec fails, dump falls back to PC `flow_cli -u ws://smsp-<uuid>.ntnx-ikat.svc:2051/flow_cli`. No `flow` cluster (404 / only `controller_msp`) plus a local `genesis status` Atlas process is CMSP → `atlas_cli` on the PCVM, `bash -lc 'flow_cli -o json policy.list|get <uuid>'` on the PCVM, PC `zkcat` for unique UUIDs, and default PC kubectl for OVN. `port_set.list` → `port_set_list.json`; each `port_set.get <uuid>` → `port_set_get.json`. `policy.list` → `policy_list.json`; each `policy.get <uuid>` → `policy_get.json`. Convert requires `policy_get.json` for rules. Service groups: v4 `ServiceGroupGet` (not v3 `POST /service_groups/list`) → `service_group_list.json` / `service_group_get.json`; convert requires those files. SMSP runs that RPC inside the kratos pod.

**AHV Gateway host collect (default on, never SSH to AHV):** mTLS to each PE hypervisor at `:7030` with the PC `ClusterHealthService` cert. Downloads advertised networking / avm / ovn / ovs bugtool classes and **extracts every tar member** (no keep-filter). Convert/OVN tools read those files later.

Layout: `<output_dir>/ahv_gateway/<hypervisor_ip>/` plus `ahv_gateway.json`.

**OVN NB/SB (default on):** OVN Northbound/Southbound live in kubectl pods (`anc-ovn-0` / container `anc-ovn`), not on AHV. CMSP uses PC kubectl; SMSP uses the flow-cluster kubeconfig. The dump runs (no `-it`):

```bash
sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovnnb_db.sock
sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovnsb_db.sock
```

It retries until both dumps exist. Layout: `<output_dir>/cmsp_ovn/anc-ovn/commands/ovsdb-client_dump_{nb,sb}.txt`.

**Flow proto field map:** Not collected. Convert does not decode IDF `__zprotobuf__`. Policy rules come from `policy_get.json`; service-group ports come from `service_group_get.json`. `--skip_flow_proto` / `--collect_flow_proto` are accepted and ignored.

**Policy CLI (default on, always bash, never `-it`):** Required for convert. Writes `policy_list.json` / `policy_get.json`.

```bash
# CMSP — on the PCVM
bash -lc 'flow_cli -o json policy.list'
bash -lc 'flow_cli -o json policy.get <policy_uuid>'

# SMSP — kratos pod in the flow cluster (ntnx-flow)
kubectl -n ntnx-flow exec kratos-<pod-hash> -- bash -lc 'kratos_cli -o json policy.list'
# this SMSP image has flow_cli, not kratos_cli; dump tries kratos_cli then flow_cli
```

**Service groups (v4, not v3):** Intentgw `POST /api/nutanix/v3/service_groups/list` is the old list path and is blocked once next-gen/EPM is on. Dump does not call v3. It uses the same unauthenticated RPC as `policy.list` (`RpcRequestContext.should_authorize=False`) on **`ServiceGroupGet`** — the backend for `GET /api/microseg/v4.3/config/service-groups/{extId}`. An empty uuid list returns every group with decoded ports. Convert requires `service_group_get.json`.

**Where the files are:**

| Place | What you get |
|---|---|
| `<output_dir>/ahv_gateway/<hypervisor_ip>/` | Per-host OVS/virsh/tap/brAtlas/conf.db from AHV Gateway |
| `<output_dir>/ahv_gateway.json` | Per-host complete/missing index |
| `<output_dir>/cmsp_ovn/` | OVN NB/SB (+ IC/policy) from kubectl (CMSP PC kube or SMSP flow kube) |
| `<output_dir>/cmsp_ovn.json` | kubectl dump index |
| `<output_dir>/flow_proto/fields.json` | This PC's Flow protobuf messages/enums (field numbers) |
| `<output_dir>/flow_proto.json` | Proto-map collect index |
| `<output_dir>/policy_list.json` | `flow_cli` / kratos `policy.list` |
| `<output_dir>/policy_get.json` | each `policy.get <uuid>` (required for convert) |
| `<output_dir>/service_group_list.json` | v4 ServiceGroupGet (all groups; `tcpServices` / `udpServices`) |
| `<output_dir>/service_group_get.json` | same records keyed by UUID (required for convert) |

Help:

```bash
python3 /home/nutanix/data/flow_pc_dump.py --help
```

## What process writes (local)

`flow_pc_process.py` / `flow_pc_map.py` map idfcli plus required `policy_get.json` and `service_group_get.json` into prefetch JSON locally. Logged as `DUMP start` / `DUMP done` / `DATASET … dumped N records`. Source is **dump files**, not FlowInterfaces. Missing policy or service-group JSON exits 2.

| JSON key | Source | Used by `neo4j_db_insert.py` |
|---|---|---|
| `address_groups` | `idfcli` `network_address_group` | `create_ag_map` |
| `service_groups` | `service_group_get.json` (v4 ServiceGroupGet) | `create_service_group_map` |
| `entity_groups` | `idfcli` `network_entity_group` | `create_entity_group_map` |
| `policies` | `policy_get.json` (`flow_cli` / kratos `policy.get`) | `insert_policy_graph` (`policy["data"]`) |
| `hosts` | `idfcli` `node` | `load_infrastructure_data` |
| `vms` | `idfcli` `vm` / `mh_vm`; NIC join from `virtual_nic`; VM categories from `abac_entity_capability` (`kind=vm`) | `_fetch_vms` |
| `subnets` | `idfcli` `virtual_network` / `subnet` (`overlay_network_uuid`, `advanced_networking`); subnet categories from `abac_entity_capability` | `_fetch_subnets` |
| `vpcs` | Overlay stubs from `overlay_network_uuid` plus ALL_VLAN `00000000-0000-0000-0000-000000000001` named `VLAN` | `create_vpc_map` |
| `categories` | `idfcli` `abac_category` merged with `category` (`key:value`) | `create_category_map` |
| `clusters` | `idfcli` `cluster` | `load_infrastructure_data` |
| `projects` | `idfcli` `project` | `load_projects_data` |
| `categories` | `idfcli` `category` | `create_category_map` |
| `network_functions` | `idfcli` `network_function` | `load_network_functions_data` |
| `vlan_unique_uuid` / `global_unique_uuid` | CMSP: PC `zkcat` Flow ZK. SMSP: Atlas pod ZK in the flow cluster (`MicrosegHelper.get_flow_unique_uuid`) | `get_flow_unique_uuid` |
| `fqdn_to_ip_map` | `idfcli` `fns_fqdn_to_ip_info` | EG FQDN expansion |
| `port_set_list` | `atlas_cli -o json port_set.list` (SMSP/CMSP wrapped) | Atlas port-set inventory |
| `port_set_get` | `atlas_cli -o json port_set.get <uuid>` for each listed UUID | Atlas port-set details (`virtual_nic_uuid_list`, …) |
| `ahv_gateway` | PC mTLS AHV Gateway `:7030` per hypervisor | Host OVS / virsh / tap / brAtlas |
| `cmsp_ovn` | `sudo kubectl exec anc-ovn-0 -c anc-ovn -- ovsdb-client dump unix:/var/run/ovn/ovn{nb,sb}_db.sock` | OVN Northbound + Southbound |
| `flow_proto` | optional `--collect_flow_proto` (`flow_proto/fields.json`) | unused by convert |

Each VM NIC `nic_network_info` includes:

- `vm_categories` / `vm_category_ids` — this VM's categories (`key:value`)
- `subnet.ext_id`, `subnet.name`, `subnet.subnet_type`, `subnet.is_advanced_networking`
- `subnet.categories` (`key:value`) and `subnet.category_ids`
- `vpc.ext_id`, `vpc.name` (never empty; overlay name inferred from subnet prefix), `vpc.categories`, `vpc.category_ids`

The IDF `vm` entity has no `category_id_list`. VM/subnet/VPC categories are joined from `idfcli abac_entity_capability` (`kind` + `kind_id` / `uuid` + `category_id_list`).

**VMs / NICs / subnets / categories source:** dump collects Insights **JSON**, not proto-text and not Prism.

```bash
idfcli get entity -e vm --all -o json
idfcli get entity -e virtual_nic --all -o json
idfcli get entity -e virtual_network --all -o json
idfcli get entity -e abac_category --all -o json
idfcli get entity -e category --all -o json
idfcli get entity -e abac_entity_capability --all -o json
```

Dump writes that JSON **as-is**. Convert (`flow_pc_process.py`) flattens `entity_guid` + `attribute_data_map` into named-attribute dicts (`ext_id`, `vm_name`, `virtual_nic_uuids`, `connected`, `nic_index`, `advanced_networking`, `overlay_network_uuid`, `category_id_list`, …) and **drops `__zprotobuf__`**. Convert still reads older already-flat `idfcli/*.json` and proto-text `idfcli/*.txt` dumps.

Ways that do **not** work for this dump (no Prism user/pass, no SSH to AHV):

| Source | Why not |
|---|---|
| Prism v4 VMM / networking / categories | OIDC |
| v3 `/vms/list`, `/subnets/list`, `/categories/list` | Prism auth; next-gen/EPM blocks v3 |
| `ncli` / `acli` | Not a PC JSON inventory; would need AHV |
| `atlas_cli` | Port-sets only |
| `flow_cli` | Policies, not VM/NIC/subnet/category inventory |
| `idfcli get entitytype` proto-text | Named attrs plus `__zprotobuf__`; convert never needed the blob |

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
