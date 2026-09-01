# Proc 1 Nic Bond Link + L1 CRC

1. Bond/member link state and speed (`ethtool_<iface>.stdout`).
2. Mandatory L1 counters from `ethtool_--statistics_<iface>.stdout` and
   `host_nic_stats.INFO*` first→last delta:
   `rx_crc_errors`, `rx_length_errors`, `rx_frame_errors`, `rx_errors`,
   `rx_dropped`, `collisions`, carrier.
3. **CRC=0 is a finding.** Large `rx_dropped` with CRC=0 → soft drops, not L1 CRC.
4. Cross-check `ifconfig_-a.stdout` RX/TX errors, dropped, overruns, carrier.
5. See [network-nic-mtu-ncc SKILL](../SKILL.md) and
   [network-sar-debugging](../../network-sar-debugging/SKILL.md) for the
   one-pass `--bundle-root` analyzer.
