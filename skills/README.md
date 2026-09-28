# Network RCA skills (`network_1.0`)

Copied from Panacea `cursor-cli-agent` network skill pack, including the
SAR + L1 CRC / ethtool / host_nic_stats one-pass analyzer.

## One-pass analyzer (logbay PE bundle)

```bash
python3 skills/network_1.0/network-sar-debugging/scripts/analyze_sar_network.py \
  --bundle-root /path/to/NTNX-Log-...-PE-<cvm>
```

Emits JSON with mandatory classes: L1/CRC, drops, link, SAR traffic,
host pressure (iostat), ping. Missing sources → `EVIDENCE_INSUFFICIENT`.

Start with `network-rca-orchestrator/SKILL.md` for the full chain.

## Live SAR burst + IPFIX lab tools

See [`tools/sar_burst_analysis/`](../tools/sar_burst_analysis/README.md):

- `scan_sar_packet_bursts.sh` / `analyze_sar_bursts.sh` — AHV/CVM SAR scanners
- `simulate_ipfix_flow_burst.py` / `simulate_netbios_multidst.py` — guest traffic sims
