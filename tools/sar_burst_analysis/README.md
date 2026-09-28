# SAR burst analysis + IPFIX traffic simulators (ONCALL-24333)

Tools for finding host NIC packet bursts in SAR history and reproducing
ipfix-exporter userspace queue saturation (EventQueueDrop / ScannerQueueDrop).

## Layout

| File | Purpose |
|------|---------|
| `scan_sar_packet_bursts.sh` | Option 1 — list iface samples ≥ 50k pkts/s across `/var/log/sa/sa*` |
| `analyze_sar_bursts.sh` | Option 2 — top bursts + CPU `%sys`/`%soft` in ramp hour |
| `analyze_udp_conntrack_pattern.sh` | Live OVS CT sample: TCP/UDP mix, top UDP ports, NetBIOS zone audit |
| `simulate_ipfix_flow_burst.py` | High new-flow UDP generator (unique sport → new CT 5-tuple) |
| `simulate_netbios_multidst.py` | NetBIOS-like UDP/137 multi-destination fanout |

## Run SAR scanners on AHV / CVM

```bash
bash scan_sar_packet_bursts.sh
bash analyze_sar_bursts.sh
```

Optional env overrides: `THRESHOLD`, `SAR_DIR`, `PKT_THRESHOLD`, `TOP_BURST_FLOOR`,
`RAMP_HOUR_PREFIX` (default `08:` for 08:00–09:00).

### All AHV hosts from a CVM

```bash
allssh "bash -s" < scan_sar_packet_bursts.sh
allssh "bash -s" < analyze_sar_bursts.sh
allssh "bash -s" < analyze_udp_conntrack_pattern.sh
```

### Live OVS conntrack / UDP pattern (AHV root)

```bash
bash analyze_udp_conntrack_pattern.sh
# report also tee'd to /tmp/conntrack_analysis_<host>_<ts>.txt
```

Requires root (`ovs-appctl dpctl/dump-conntrack`). Section 5 diurnal ranges are
scaled from the current UDP snapshot (estimate, not historical CT).

SAR reports **pps/bytes**, not UDP flow-create rate. Correlate burst timestamps
with AHV `http://127.0.0.1:1235/exporter-cmd` (`IpfixExporter.HandleExporterCmd`
CommandType `1`).

## Traffic simulators (guest VMs only)

**High CPS new-flow burst** (lab: ~102k cps × 90s produced drops):

```bash
python3 simulate_ipfix_flow_burst.py --dst 10.50.130.79 --dport 12345 \
  --cps 150000 --duration 90 --workers 32
```

**NetBIOS multi-dst pattern** (customer-like UDP/137 fanout):

```bash
python3 simulate_netbios_multidst.py \
  --dsts 10.50.130.79,10.50.130.43 --dport 137 \
  --cps 22000 --duration 60 --workers 16
```

Do not commit lab passwords or customer tunnel credentials into these scripts.
