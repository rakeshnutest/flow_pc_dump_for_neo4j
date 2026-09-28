# SAR / L1 Waterfall Checklist (mandatory)

Every run must tick **all** sections. Missing file → `EVIDENCE_INSUFFICIENT`, not skip.

## 0. Discover sources

- [ ] PE bundle root (`NTNX-Log-*-PE-<cvm>/`)
- [ ] `cvm_logs/sysstats/{sar,iostat,host_nic_stats,ping_all}.INFO*`
- [ ] `ahv/<host>/commands/ethtool_--statistics_*.stdout`
- [ ] `ahv/<host>/commands/ethtool_eth*.stdout` (link)
- [ ] `ahv/<host>/commands/ifconfig_-a.stdout`

## 1. L1 / CRC (do this first)

- [ ] Read `rx_crc_errors`, `rx_length_errors`, `rx_frame_errors`, `collisions`
- [ ] Read `rx_errors`, `tx_errors`
- [ ] Read `rx_dropped`, `tx_dropped`
- [ ] host_nic_stats: **first → last delta** for same keys
- [ ] Explicitly state **CRC=0** when true (finding, not omission)
- [ ] Link: Speed / Duplex / `Link detected`

| Pattern | Class |
|---|---|
| CRC / frame / carrier / collisions rising | `L1_CRC_OR_LINK` |
| Large `rx_dropped`, CRC=0 | `SOFT_RX_DROPS` |
| Link down / not 10G full | `L1_CRC_OR_LINK` |

## 2. SAR IFACE waterfall

- [ ] Timeline overlaps DND / FATAL (else `COVERAGE_GAP`)
- [ ] `rxpck/s`, `txpck/s`, `rxkB/s`, avg pkt size
- [ ] `rxerr/s`, `rxdrop/s`
- [ ] Tiny-pkt flood vs soft drops

## 3. Host pressure (iostat)

- [ ] `%iowait` peaks
- [ ] Disk `%util`, `r_await`, `w_await` for `sd*` / `nvme*`
- [ ] Overlap ±15 min with DND / peer score 100

## 4. Path (ping)

- [ ] Peer CVM vs GW/PC
- [ ] Large-ping / LOST_PKT / unreachable samples

## 5. Verdict

- [ ] Primary `root_class` + `contributors[]`
- [ ] All classes present in JSON (`L1_CRC`, `DROPS`, `LINK`, `TRAFFIC_SAR`, `HOST_PRESSURE`, `PATH_PING`)
- [ ] Gaps listed explicitly
