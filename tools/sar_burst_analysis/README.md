# SAR burst analysis & IPFIX traffic simulators

Tools for finding high packet-rate SAR windows on AHV/CVM hosts and generating
synthetic UDP flow bursts to stress IPFIX / conntrack (new 5-tuple per packet).

## Layout

| File | Purpose |
|------|---------|
| `scan_sar_packet_bursts.sh` | List interface samples with rx/tx ≥ threshold (default 50k pkts/s) |
| `analyze_sar_bursts.sh` | Top burst peaks + CPU `%sys` / `%soft` during ramp hour |
| `simulate_ipfix_flow_burst.py` | High-CPS UDP to one dest; new socket/sport each packet |
| `simulate_netbios_multidst.py` | NetBIOS-ish UDP cycling multiple dests (default UDP/137) |

## SAR scanners (AHV or CVM)

Defaults read `/var/log/sa/saNN`. Override with env vars:

```bash
# Single host
bash scan_sar_packet_bursts.sh
THRESHOLD=80000 SAR_DIR=/var/log/sa bash scan_sar_packet_bursts.sh

bash analyze_sar_bursts.sh
PKT_THRESHOLD=50000 TOP_BURST_FLOOR=10000 RAMP_HOUR_PREFIX=08: bash analyze_sar_bursts.sh
```

### Cluster-wide from a CVM (`allssh`)

```bash
allssh "bash -s" < scan_sar_packet_bursts.sh
allssh "bash -s" < analyze_sar_bursts.sh
```

## Correlate with AHV IPFIX exporter-cmd

After SAR timestamps look interesting, pull exporter stats on the AHV host and
look for **IpfixEventQueueDrop** / **IpfixScannerQueueDrop** (not ENOBUF):

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"IpfixExporter.HandleExporterCmd","params":[{"CommandType":1}]}' \
  http://127.0.0.1:1235/exporter-cmd
```

## Traffic simulators

Require Python 3. Prefer a lab/test path; these intentionally open many sockets.

### Single-destination IPFIX-style flow burst

```bash
python3 simulate_ipfix_flow_burst.py \
  --dst 10.0.0.20 \
  --dport 12345 \
  --cps 150000 \
  --duration 90 \
  --workers 32
```

Each UDP datagram uses a **new socket** so the kernel picks a new ephemeral
source port → a new CT 5-tuple. The script prints `achieved_cps`.

### Multi-destination NetBIOS-ish burst

```bash
python3 simulate_netbios_multidst.py \
  --dsts 10.0.0.21,10.0.0.22,10.0.0.23 \
  --dport 137 \
  --cps 22000 \
  --duration 60 \
  --workers 16
```

Cycles destinations round-robin; new sport per send; NetBIOS name-query-ish payload.

## Notes

- Do not embed passwords or cluster credentials in these scripts.
- Achieved CPS depends on host limits (`ulimit -n`, softirq, NIC). Raise workers
  gradually and watch `sar -n DEV 1` / exporter-cmd drops during the run.
