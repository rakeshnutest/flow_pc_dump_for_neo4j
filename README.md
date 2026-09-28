# flow_pc_dump

Collect Flow / networking data from a Prism Central (PC), then convert and
load it on your laptop.

**Two places, two jobs:**

| Where | Script | Job |
|---|---|---|
| PC | `flow_pc_dump.py` | Collect raw data only |
| Your laptop | `flow_pc_process.py` | Convert + optional ClickHouse load |

Also on the PC: `vm_host_collect.py` (VM/NIC/host/cluster + `vm_cat` /
`subnet_cat` / `vpc_cat` / VPC → `/tmp/vms.json`).  
Also on the laptop: `vm_host_inventory.py`, `flow_pc_map.py` (used by process; do not run map by hand).

Copy only the dump scripts to the PC. Do **not** copy process/map to the PC.

---

## Quick start

Set these once on your laptop:

```bash
PC_IP=<PC_IP>
DUMP=/path/to/local/dump
BUNDLE=1
REPO=/path/to/flow_pc_dump_github
```

### 1. Copy scripts to the PC

```bash
scp "$REPO/flow_pc_dump.py" nutanix@$PC_IP:/home/nutanix/data/flow_pc_dump.py
scp "$REPO/vm_host_collect.py" nutanix@$PC_IP:/home/nutanix/data/vm_host_collect.py
```

Use `/home/nutanix/data/` or `/home/nutanix/upgrade/`. Do **not** use `/tmp`
(small disk on many PCs).

### 2. Collect on the PC

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

Use system `python3`. No Flow venv.

Wait until the log shows `DUMP done` and `all.json` exists. Convert does
**not** run on the PC.

Optional: only run on the Flow leader PCVM (other PCVMs exit 0 — safe for cron):

```bash
python3 /home/nutanix/data/flow_pc_dump.py \
  --leader_only \
  --output_dir /home/nutanix/upgrade/flow_pc_dump
```

### 3. Copy the dump to your laptop

```bash
mkdir -p "$DUMP"
rsync -a nutanix@$PC_IP:/home/nutanix/upgrade/flow_pc_dump/ "$DUMP/"
```

### 4. Convert (and optionally load ClickHouse)

ClickHouse is local at `127.0.0.1:19000`.

```bash
cd "$REPO"
python3 flow_pc_process.py \
  --dump_dir "$DUMP" \
  --timeout_secs 1800 \
  --ingest \
  --log_bundle_id "$BUNDLE"
```

That writes `policies.json`, `vms.json`, and related files under `$DUMP`, then
loads OVN + flow policy into ClickHouse.

Already converted? Load only:

```bash
python3 flow_pc_process.py \
  --dump_dir "$DUMP" \
  --skip-convert \
  --ingest \
  --log_bundle_id "$BUNDLE"
```

To wipe an old bundle first:

```bash
python3 clickhouse_flow/ingest.py --drop-bundle "$BUNDLE"
python3 clickhouse_ovn/ingest.py --drop-bundle "$BUNDLE"
```

### 5. Compare port-sets to Atlas

```bash
cd "$REPO"
python3 clickhouse_flow/compare.py --log_bundle_id "$BUNDLE"
```

Match by **port-set UUID** (names are display only).

### 6. Optional leftover notes

```bash
cd "$REPO"
python3 clickhouse_flow/observe_leftovers.py \
  --from_ch \
  --log_bundle_id "$BUNDLE" \
  --dump_dir "$DUMP" \
  --out clickhouse_flow/leftover_observations.md
```

---

## What the dump collects

Raw command output and files. No flatten, no unwrap, no convert on the PC.

| Area | What you get |
|---|---|
| IDF | Entity JSON under `idfcli/` |
| Atlas | Port-set list + get |
| Flow / kratos | Policy list + get |
| Service groups | v4 ServiceGroupGet (not the old v3 list API) |
| AHV Gateway | OVS / networking bugtool files per host (HTTPS, no SSH to AHV) |
| OVN | NB/SB dumps via kubectl (CMSP or SMSP flow cluster) |
| Unique UUIDs | VLAN + global Flow unique UUIDs |

Disk note: AHV Gateway can be large (tens of GB on big clusters). Prefer
`/home/nutanix/upgrade/…`.

---

## Output layout

If you omit `--output_dir`, files go to a timestamped folder under
`/home/nutanix/upgrade/flow_pc_dump`.

```text
all.json                 # index
dump.log
unique_uuids.json
idfcli/                  # raw idfcli JSON
port_set_list.json
port_set_get.json
policy_list.json
policy_get.json          # needed for convert
service_group_list.json
service_group_get.json   # needed for convert
ahv_gateway/             # per hypervisor IP
ahv_gateway.json
cmsp_ovn/                # OVN dumps (CMSP or SMSP)
cmsp_ovn.json
smsp_ovn.json            # same payload on SMSP (fail-fast index copy)
dump_errors.json
```

Override the index path with `--output /path/to/all.json`.

---

## Common dump flags

| Flag | Default | Meaning |
|---|---|---|
| `--output_dir` | timestamped under `/home/nutanix/upgrade/flow_pc_dump` | Where files go |
| `--leader_only` | off | Run only on Flow leader PCVM |
| `--workers` | `16` | General parallelism |
| `--dataset_timeout_secs` | `180` | Per idfcli type timeout |
| `--fail_on_error` | off | Exit non-zero if something failed |
| `--skip_idfcli` | off | Skip IDF |
| `--skip_atlas` | off | Skip Atlas port-sets |
| `--skip_flow_cli` | off | Skip policy list/get |
| `--skip_ahv_gateway` | off | Skip AHV Gateway |
| `--skip_cmsp_ovn` | off | Skip OVN kubectl dumps |
| `--atlas_timeout_secs` | `1800` | Atlas overall timeout |
| `--atlas_get_workers` | `32` | Parallel port-set get |
| `--flow_cli_timeout_secs` | `1800` | Policy overall timeout |
| `--flow_cli_get_workers` | `32` | Parallel policy get |
| `--ahv_gateway_timeout_secs` | `1800` | AHV overall budget |
| `--ahv_gateway_class_timeout_secs` | `300` | Per bugtool class HTTP timeout |
| `--ahv_gateway_workers` | `8` | Parallel hypervisors |
| `--ahv_gateway_port` | `7030` | AHV Gateway HTTPS port |
| `--ahv_gateway_cert_dir` | `/home/certs/ClusterHealthService` | Client cert/key dir |
| `--cmsp_ovn_timeout_secs` | `1800` | OVN collect budget |
| `--cmsp_ovn_namespace` | empty | Limit kubectl namespace |
| `--cmsp_ovn_wait` / `--ovn_wait` | off | Keep retrying OVN until timeout. **Default is fail-fast** for both CMSP and SMSP: stop if required `anc-ovn` pod is missing (or SMSP flow kubeconfig fails), with at most one quick retry for flaky dumps |

Full help:

```bash
python3 flow_pc_dump.py --help
python3 flow_pc_process.py --help
```

---

## CMSP vs SMSP

No flag. The dump detects platform automatically.

- **CMSP:** tools run on the PCVM (`atlas_cli`, `flow_cli`, local kubectl/ZK).
- **SMSP:** Flow runs in the MSP `flow` cluster. Dump uses
  `mspctl cluster kubeconfig flow` for OVN / kratos / atlas ZK, and can fall
  back to PC websocket CLIs.

**OVN fail-fast (default for both):** if the required `anc-ovn` pod is missing,
or SMSP cannot get the flow kubeconfig, OVN collection stops immediately
instead of waiting for `--cmsp_ovn_timeout_secs`. Optional pods
(`anc-ovn-ic-db`, `anc-policydb`) may be absent without forcing retries.
Use `--cmsp_ovn_wait` / `--ovn_wait` only when you want to wait for OVN to
come up.

Never use `kubectl -it`. Never SSH to AHV.

---

## Convert needs these files

| File | Why |
|---|---|
| `idfcli/` | VMs, NICs, subnets, categories, groups, … |
| `policy_get.json` | Policy rules |
| `service_group_get.json` | Service group ports (v4) |

Missing policy or service-group JSON → convert exits 2.

Identity for ClickHouse compare is **UUID**. Names are for display.

---

## Do not

- Run convert on the PC
- Put the dump under `/tmp`
- Call Prism APIs or build FlowInterfaces from this dump path
- Copy `flow_pc_process.py` / `flow_pc_map.py` to the PC
- Use interactive kubectl (`-it`)

---

## Example lab sizes

| Dataset | Example count |
|---|---|
| address groups | ~1400 |
| service groups | ~2100 |
| policies | ~650 |
| VMs | ~6700 |
| subnets | ~1900 |
| categories | ~3300 |
| hosts | ~30 |
| clusters | ~3 |
