# SAR Grafana stack (Diamond / NTNX zip logs)

Docker stack that turns Nutanix PE log-bundle SAR data into a **Grafana** dashboard backed by **InfluxDB**.

Supports:
- Multi-day SAR (zoom with Grafana time/date picker)
- **CVM** (`cvm_logs/kernel/var/sarNN`) and **AHV** (`ahv/<ip>/files/var/log/sa/saNN` binary → `sar`)
- **CVM ping** (`cvm_logs/sysstats/ping_{gateway,all,remotes}.INFO*`) — latency (ms) and unreachable drops
- Filters: **Role (CVM/AHV)**, **Host / CVM / AHV**, **Interface**, **Rx/Tx packets**, **Rx/Tx kB**, **errors/drops**, **Disk**, **Ping kind**, **Ping target**
- Panels: CPU, load, memory, network packets, network throughput, network errors, disk I/O, **ping latency**, **ping drops**

## Open the dashboard (where data is usually available)

After bring-up, use the **data-window link** printed by the script.

For the current host stack, open:

```text
http://10.111.60.97:3000/d/sar-overview?from=2026-08-09T00:00:00.000Z&to=2026-09-06T23:59:59.000Z
```

Or rolling window:

```text
http://10.111.60.97:3000/d/sar-overview?from=now-90d&to=now
```

Use the **Role (CVM / AHV)** and **Host / CVM / AHV** filters to select among all ingested hosts.

Do **not** use Grafana "Previous fiscal quarter" unless your SAR files fall in that quarter.
SAR from Diamond PE zips is usually a recent multi-week window.

## Multi-host bring-up

Pass **all PE zips** (or a folder containing them):

```bash
./bringup_sar_grafana.sh \
  ./2657578-...-PE-10.3.89.176-CW.zip \
  ./2657578-...-PE-10.3.89.177.zip \
  ./2657578-...-PE-10.3.89.178.zip

# or every zip in a Diamond date folder:
./bringup_sar_grafana.sh /path/to/2657578/2026-09-07/
```

Files are stored as `<hostname>__<role>__sarNN.txt` (legacy `<hostname>__sarNN.txt` still works).

## Quick links (after bring-up)

| Service | URL |
|--------|-----|
| Grafana dashboard | http://\<host\>:3000/d/sar-overview |
| Grafana login | `admin` / `saradmin123` (change via env) |
| InfluxDB UI | http://\<host\>:8086 |

Anonymous Grafana **Viewer** is enabled by default.

### Dashboard filters

At the top of the dashboard:

1. **Time range** (top-right) — filter by date/time across all ingested days  
2. **Role (CVM / AHV)** — show CVM, AHV, or both  
3. **Host / CVM / AHV** — e.g. `ntnx-…-cvm` or AHV hostname  
4. **Interface** — `eth0`, `eth1`, …  
5. **Packet metrics (Rx/Tx)** — `rxpck_s`, `txpck_s`  
6. **kB metrics (Rx/Tx)** — `rxkB_s`, `txkB_s`  
7. **Error / drop metrics** — `rxerr_s`, `txerr_s`, `rxdrop_s`, `txdrop_s`, `coll_s`  
8. **Disk** — block devices from SAR

### Independent ping dashboard

Ping latency / unreachable drops are on a **separate** dashboard (not tied to SAR role/iface filters):

```text
http://10.111.60.97:3000/d/sar-ping?from=2026-08-25T00:00:00.000Z&to=2026-09-07T23:59:59.000Z
```

Filters there: **CVM host**, **Ping kind** (`gateway` / `all` / `remotes`), **Ping target**.

## Prerequisites

- Docker Engine + Docker Compose v2
- Diamond / NTNX PE `.zip` (or already-extracted trees)
- `sysstat` (`sar`) on the host when PE zips include **AHV** binary `saNN` files
- `xz` for compressed CVM `sarNN` files

## 1. Prepare SAR text files (from PE zip)

From this folder (`sar_grafana/`):

```bash
# Option A: convert a PE zip (handles XZ-compressed and ASCII sarNN files)
python3 convert_ntnx_sar.py /path/to/PE.zip -o /tmp/out_dir/combined.txt

# Better for Grafana: write one file per day into data/preload/
mkdir -p data/preload
# If you already have extracted SAR day texts:
#   cp /path/to/converted/sar*.txt data/preload/

# Helper: extract SAR-only from zip, decompress XZ days, write per-day txt
python3 - <<'PY'
from pathlib import Path
import subprocess, zipfile, re
zip_path = Path("/path/to/PE.zip")  # <-- change me
out = Path("data/preload")
out.mkdir(parents=True, exist_ok=True)

def decode(raw: bytes) -> str:
    if raw[:6] == b"\xfd7zXZ\x00":
        raw = subprocess.check_output(["xz", "-dc", "--stdout"], input=raw)
    return raw.decode("utf-8", errors="ignore")

with zipfile.ZipFile(zip_path) as zf:
    for name in sorted(zf.namelist()):
        base = Path(name).name
        if not (base.startswith("sar") and len(base) >= 5 and base[3:5].isdigit()):
            continue
        if "/kernel/var/" not in name and "kernel/var" not in name:
            # keep only CVM kernel/var/sarNN when present
            if "kernel/var" not in name.replace("\\", "/"):
                continue
        text = decode(zf.read(name))
        if "CPU" not in text and "IFACE" not in text:
            continue
        (out / f"{base}.txt").write_text(text)
        print("wrote", base, len(text))
print("done ->", out)
PY

ls -lh data/preload/
```

You need files like:

```text
data/preload/sar01.txt
data/preload/sar02.txt
...
```

Each file is normal `sar -A` style text (CPU, memory, IFACE rx/tx/errors, disk, …).

## 2. Bring up with one script (recommended)

```bash
cd sar_grafana
chmod +x bringup_sar_grafana.sh
./bringup_sar_grafana.sh /path/to/PE.zip
# optional explicit port:
# ./bringup_sar_grafana.sh /path/to/PE.zip 3100
```

The script:
1. Extracts/converts SAR day files from the zip into `data/preload/`
2. Starts Docker on **0.0.0.0**
3. Prints **eth0 IP:port** and dashboard URL

Example output:

```text
 Listen:     0.0.0.0:3100
 eth0 open:  10.111.60.97:3100
 Dashboard:  http://10.111.60.97:3100/d/sar-overview
```

## 3. Manual Docker bring-up

```bash
cd sar_grafana

# optional bind address (example: only on one NIC)
# export GRAFANA_BIND=10.111.60.97:3000
# export INFLUX_BIND=10.111.60.97:8086

docker compose up -d --build
docker compose ps
docker compose logs -f ingest   # wait until "Ingested N points"
```

Open:

```text
http://localhost:3000/d/sar-overview
```

Or with bind IP:

```text
http://10.111.60.97:3000/d/sar-overview
```

## 3. Re-ingest after adding more SAR days / hosts

```bash
# add more sar*.txt under data/preload/ (other CVMs / days)
docker compose run --rm ingest
```

Then refresh Grafana; use **Host / CVM** filter if multiple hosts are present.

## 4. Stop / reset

```bash
docker compose down          # keep data volumes
docker compose down -v       # wipe InfluxDB + Grafana volumes
```

## Layout

```text
sar_grafana/
├── README.md
├── docker-compose.yml
├── convert_ntnx_sar.py
├── data/preload/          # put sarNN.txt here (gitignored content)
├── ingest/
│   ├── Dockerfile
│   └── sar_to_influx.py
└── grafana/
    ├── dashboards/sar-overview.json
    └── provisioning/...
```

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `GRAFANA_BIND` | `0.0.0.0:3000` | Host bind for Grafana |
| `INFLUX_BIND` | `0.0.0.0:8086` | Host bind for InfluxDB |
| `GRAFANA_USER` | `admin` | Grafana admin user |
| `GRAFANA_PASSWORD` | `saradmin123` | Grafana admin password |
| `INFLUX_TOKEN` | `sar-admin-token-change-me` | Must match datasource token |
| `INFLUX_PASSWORD` | `saradmin123` | Influx setup password |

## Notes

- Grafana is much better than browser SAR chart tools for multi-day scale: filter by time range instead of loading one giant text file.
- Nutanix `cvm_logs/kernel/var/sarNN` may be ASCII or XZ-compressed ASCII — `convert_ntnx_sar.py` handles both.
- High-resolution `sysstats/sar.INFO*` is network-focused; prefer `kernel/var/sar*` for full CPU/mem/disk/net.
