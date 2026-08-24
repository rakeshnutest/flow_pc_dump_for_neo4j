# OVN path 3468ac71-d670-41a0-93af-0ec34d43f7c3 → 22bce434-1ef5-4792-8e57-8fa2a5e3bd71

## Traffic story / RCA

- Src VM `VPC_California_SJ_Pheonix_Customer_1_subnet_2_139` uuid `989f9355-f15f-45eb-8006-07b9623ddafc` NIC `3468ac71-d670-41a0-93af-0ec34d43f7c3` LSP `915f1338-1aba-4c27-a016-cb9876cdc970` MAC `50:6b:8d:19:78:77` IP `192.168.2.186` VPC `Customer_1`
- Dest VM `VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4` uuid `b4de25e6-d469-44ea-831f-88d2247bf227` NIC `1d6e610d-f164-4f5d-a6f3-4be6a59a4819` LSP `22bce434-1ef5-4792-8e57-8fa2a5e3bd71` MAC `50:6b:8d:43:a5:90` IP `192.168.1.51` VPC `Customer_19`
- Compute Host `zadkiel05-3` chassis `a774c18b-7b6e-44f7-8661-6ac53c4607ca`
- Dest compute Host `spymaster01-2` chassis `bbd822da-f0b1-4a7d-a894-df4029cfb598`
- External GW Host `zadkiel04-1` chassis `b594f638-f4a0-439b-91d4-1c513f0c4529` (active RC) router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` MAC `e0:19:95:9b:58:bb` IP `10.116.246.55/18`
- External GW Host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20` (standby scale-out) router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` MAC `e0:19:95:c0:b3:04` IP `10.116.246.54/18`
- External GW Host `zadkiel04-3` chassis `e6226ec1-fa8f-41e5-8d0c-7a884b7f9634` (active RC) router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` MAC `e0:19:95:14:17:37` IP `10.116.246.47/18`
- External GW Host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20` (standby scale-out) router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` MAC `e0:19:95:5b:76:31` IP `10.116.246.48/18`
- Transit LS `gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `df8dadd4-7138-4ea7-95da-15fab0b6838c`
- External localnet `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` uuid `43a3a38a-89e1-4410-8101-b255757c2f28`
- Transit LS `gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `f7e6f4bb-0dfd-40a3-8023-270912e79985`

### Drop / allow

**dropped upstream** (src NIC → `192.168.1.51`). First match on Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` **from-lport**: pri 1060 **drop** `from-lport` [pg] `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)`. The packet never reaches the tenant router, SNAT, or External. Downstream does not run (no conntrack).

_Verdict: **dropped upstream**. UPSTREAM = src NIC → dest. DOWNSTREAM = dest → src NIC._

### Routing view (L2 → L3 → GW → NAT → External)

Forward (what routing would do if policy allowed):

1. VM `VPC_California_SJ_Pheonix_Customer_1_subnet_2_139` uuid `989f9355-f15f-45eb-8006-07b9623ddafc`
2. NIC `3468ac71-d670-41a0-93af-0ec34d43f7c3` MAC `50:6b:8d:19:78:77` IP `192.168.2.186` LSP `915f1338-1aba-4c27-a016-cb9876cdc970`
3. TAP `tap222`
4. OVS brAtlas ofport `288` on Host `zadkiel05-3` chassis `a774c18b-7b6e-44f7-8661-6ac53c4607ca`
5. Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` uuid `02d0de22-21a5-41f7-befd-75b6cb9c4cc7`
6. Router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `cb58bbb0-4bdc-429e-9378-838e204b99f1` — connected `192.168.2.1/24`; PBR 3 rows; src PBR pri 100 allow `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` nexthop `(empty — continue to connected/static routes)`; LR ↔ transit `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` MAC `e0:19:95:c9:5b:48` `169.254.2.20/24`; src LS ↔ LR `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` MAC `e0:19:95:08:22:c9` `192.168.2.1/24`; static routes 2 (full table below); default `0.0.0.0/0` nexthop `169.254.2.101`
7. Switch transit `gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `df8dadd4-7138-4ea7-95da-15fab0b6838c`
8. Router (NAT, ext-GW) `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` uuid `edba0385-d5d3-4d07-8ca5-f9253e4af298` — connected `10.116.246.55/18`, `169.254.2.101/24`; PBR 1 rows; GW ↔ external `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` MAC `e0:19:95:9b:58:bb` `10.116.246.55/18`; transit ↔ GW `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` MAC `e0:19:95:60:29:5b` `169.254.2.101/24`; static routes 104 (full table below); default `0.0.0.0/0` nexthop `10.116.192.1` — External GW Host `zadkiel04-1` chassis `b594f638-f4a0-439b-91d4-1c513f0c4529` (active RC); External GW MAC `e0:19:95:9b:58:bb` IP `10.116.246.55/18`; SNAT `192.168.2.186` → `10.116.246.55` covering `192.168.2.0/24`; TAP_GW `patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` OVS brAtlas ofport `372`
9. External GW Host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20` (standby scale-out) router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` MAC `e0:19:95:c0:b3:04` IP `10.116.246.54/18`
10. Switch External localnet `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` uuid `43a3a38a-89e1-4410-8101-b255757c2f28`
11. Router (NAT, ext-GW) `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` uuid `6572681a-8ffe-4fba-9263-8501622d7726` — connected `169.254.2.100/24`, `10.116.246.47/18`; PBR 0 rows; transit ↔ GW `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` MAC `e0:19:95:87:06:3b` `169.254.2.100/24`; GW ↔ external `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` MAC `e0:19:95:14:17:37` `10.116.246.47/18`; static routes 103 (full table below); default `0.0.0.0/0` nexthop `10.116.192.1` — External GW Host `zadkiel04-3` chassis `e6226ec1-fa8f-41e5-8d0c-7a884b7f9634` (active RC); External GW MAC `e0:19:95:14:17:37` IP `10.116.246.47/18`; SNAT `192.168.1.51` → `10.116.246.47` covering `192.168.1.0/24`; TAP_GW `patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` OVS brAtlas ofport `322`
12. External GW Host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20` (standby scale-out) router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` MAC `e0:19:95:5b:76:31` IP `10.116.246.48/18`
13. Switch transit `gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `f7e6f4bb-0dfd-40a3-8023-270912e79985`
14. Router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `a27e38bd-6c57-472f-80df-1a39723efe1a` — connected `192.168.2.1/24`; PBR 3 rows; LR ↔ transit `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` MAC `e0:19:95:8d:46:1a` `169.254.2.20/24`; src LS ↔ LR `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` MAC `e0:19:95:59:9f:05` `192.168.1.1/24`; static routes 2 (full table below); default `0.0.0.0/0` nexthop `169.254.2.101`
15. Switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` uuid `183da7a8-c33c-4247-912a-d4cb28ec8a5a`
16. Overlay geneve `10.116.26.235` to `10.116.26.72` (compute host ≠ GW host)

**Return (`192.168.1.51` → src NIC):** dest VM `VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4` TAP `tap42` / OVS brAtlas on `spymaster01-2` → dest Switch → dest tenant `router_818b2c20-4d1b-40b7-a951-5deb85316e68` → dest transit → dest External GW → External localnet → src External GW `zadkiel04-1` chassis `b594f638-f4a0-439b-91d4-1c513f0c4529` (un-SNAT: replies to `10.116.246.55` are un-SNATed by conntrack (reverse of `snat` `192.168.2.0/24` → `10.116.246.55`, not a separate DNAT row) back to `192.168.2.186`; External GW MAC `e0:19:95:9b:58:bb` IP `10.116.246.55/18`) → src transit → src tenant `router_fc433064-926d-4fc0-a1a3-7c089ad90343` connected `192.168.2.1/24` → Switch → OVS brAtlas → TAP `tap222` on `zadkiel05-3` → NIC `3468ac71-d670-41a0-93af-0ec34d43f7c3` → VM `VPC_California_SJ_Pheonix_Customer_1_subnet_2_139`. Would-be return is drawn even if upstream ACL dropped.

The packet **dies on hop 5** (first Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef`, from-lport); hops 6+ (tenant LR / PBR / SNAT / External) are never reached.

### Policy view (ACL)

- Applied-to (name display, UUID identity): `AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` uuid `4b7148bb-c13c-56be-9e17-95bceba2d71f` (OVN `@port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f`); `AppType/EG_Exclude_Policy1` uuid `85e8b5fc-03c6-53cb-97cb-b2535b556133` (OVN `@port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133`)
- ICMP ping `192.168.2.186` → `192.168.1.51` (proto 1): first hit **from-lport** on `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef`: pri 1060 **drop** `from-lport` [pg] `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)`
- TCP :443 / UDP :53 to `192.168.1.51`: same first hit as ICMP (1050 allow-related is dest-set + tcp/udp port ranges, not `192.168.1.51`).
- Downstream first hit (**to-lport**, `192.168.1.51` → NIC) on `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef`: pri 1060 **drop** `to-lport` [pg] `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1`
- Walk: pri 31500 DHCP miss; 1060/1052 dest/src isolation miss for this dest; 1050 allow-related miss (wrong dest-set / ports); **1045 IPv4 catch-all drop** wins on the secured group; 1017/1015 on the second group and 500 `tcp || udp || icmp` never run. Full tables under each mermaid (src LS, dest LS, every transit / localnet LS on the walk).

### What exactly happened

The packet left VM `VPC_California_SJ_Pheonix_Customer_1_subnet_2_139` (`989f9355-f15f-45eb-8006-07b9623ddafc`) NIC `3468ac71-d670-41a0-93af-0ec34d43f7c3` IP `192.168.2.186` on `zadkiel05-3` via TAP `tap222` / OVS brAtlas ofport `288` onto Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` (`02d0de22-21a5-41f7-befd-75b6cb9c4cc7`). **from-lport pri 1060 drop** on `AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` uuid `4b7148bb-c13c-56be-9e17-95bceba2d71f` (OVN `@port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f`) matched leftover IPv4 to `192.168.1.51` — higher-pri 1060/1052 dest-isolation and 1050 allow-related dest-sets are east-west, not `192.168.1.51`; pri 1017/1015 and 500 `tcp || udp || icmp` never run. Tenant LR `router_fc433064-926d-4fc0-a1a3-7c089ad90343` / snat `192.168.2.0/24` → `10.116.246.55` (src `192.168.2.186` becomes `10.116.246.55`) never saw the packet. **Dropped upstream.**

_Drop direction: **dropped upstream**. Mermaid: [Mermaid Upstream composite](#mermaid-upstream-composite) and [Mermaid Downstream composite](#mermaid-downstream-composite)._

## Upstream composite
=== Upstream (two_router) ===
src: vm=VPC_California_SJ_Pheonix_Customer_1_subnet_2_139 nic=3468ac71-d670-41a0-93af-0ec34d43f7c3 lsp=port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 lsp_uuid=915f1338-1aba-4c27-a016-cb9876cdc970 mac=50:6b:8d:19:78:77 ip=192.168.2.186
dst: vm=VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4 nic=1d6e610d-f164-4f5d-a6f3-4be6a59a4819 lsp=port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 lsp_uuid=22bce434-1ef5-4792-8e57-8fa2a5e3bd71 mac=50:6b:8d:43:a5:90 ip=192.168.1.51
  1. VIF vm=VPC_California_SJ_Pheonix_Customer_1_subnet_2_139 nic=3468ac71-d670-41a0-93af-0ec34d43f7c3 lsp=port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 lsp_uuid=915f1338-1aba-4c27-a016-cb9876cdc970 mac=50:6b:8d:19:78:77 ip=192.168.2.186
  2. LS network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef uuid=02d0de22-21a5-41f7-befd-75b6cb9c4cc7
       stretch flashfire01-1:geneve:10.116.29.154, flashfire01-2:geneve:10.116.29.155, flashfire01-3:geneve:10.116.29.156, flashfire01-4:geneve:10.116.29.157, flashfire02-1:geneve:10.116.29.172, flashfire02-2:geneve:10.116.29.173, flashfire02-3:geneve:10.116.29.174, flashfire02-4:geneve:10.116.29.175 (+22)
       ACLs from-lport (ingress on this hop): 13 (full list)
         pri=31500 allow-stateless from-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c)
         pri=1052 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c)
         pri=1050 allow-related from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_9c194c48_8c96_54a7_837a_81508c40ddae) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) || (tcp.dst >= 1429 && tcp.dst <= 1438) || (tcp.dst >= 1441 && tcp.dst <= 1450) || (tcp.dst >= 1455 && tcp.dst <= 1464) || (tcp.dst >= 1469 && tcp.dst <= 1478) || (tcp.dst >= 1483 && tcp.dst <= 1492) || (tcp.dst >= 1498 && tcp.dst <= 1507) || (tcp.dst >= 1511 && tcp.dst <= 1520) || (tcp.dst >= 1524 && tcp.dst <= 1533) || (tcp.dst >= 1539 && tcp.dst <= 1548))) || (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) || (udp.dst >= 1429 && udp.dst <= 1438) || (udp.dst >= 1441 && udp.dst <= 1450) || (udp.dst >= 1455 && udp.dst <= 1464) || (udp.dst >= 1469 && udp.dst <= 1478) || (udp.dst >= 1483 && udp.dst <= 1492) || (udp.dst >= 1498 && udp.dst <= 1507) || (udp.dst >= 1511 && udp.dst <= 1520) || (udp.dst >= 1524 && udp.dst <= 1533) || (udp.dst >= 1539 && udp.dst <= 1548))))
         pri=1050 allow-related from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_f412ba3b_b736_4b27_a0e6_4eeefc7220a4) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) || (tcp.dst >= 1297 && tcp.dst <= 1306) || (tcp.dst >= 1312 && tcp.dst <= 1321) || (tcp.dst >= 1324 && tcp.dst <= 1333) || (tcp.dst >= 1336 && tcp.dst <= 1345) || (tcp.dst >= 1350 && tcp.dst <= 1359) || (tcp.dst >= 1363 && tcp.dst <= 1372) || (tcp.dst >= 1378 && tcp.dst <= 1387) || (tcp.dst >= 1390 && tcp.dst <= 1399) || (tcp.dst >= 1403 && tcp.dst <= 1412))) || (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) || (udp.dst >= 1297 && udp.dst <= 1306) || (udp.dst >= 1312 && udp.dst <= 1321) || (udp.dst >= 1324 && udp.dst <= 1333) || (udp.dst >= 1336 && udp.dst <= 1345) || (udp.dst >= 1350 && udp.dst <= 1359) || (udp.dst >= 1363 && udp.dst <= 1372) || (udp.dst >= 1378 && udp.dst <= 1387) || (udp.dst >= 1390 && udp.dst <= 1399) || (udp.dst >= 1403 && udp.dst <= 1412))))
         pri=1045 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip6
         pri=1045 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4
         pri=1019 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4 && (ip4.dst == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506)
         pri=1018 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4 && (ip4.dst == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506)
         pri=1017 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4
         pri=1015 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4
         pri=1015 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip6
         pri=500 allow-related from-lport [ls] tcp || udp || icmp
       ACLs to-lport (egress on this hop): 14 (full list)
         pri=31500 allow-stateless to-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop to-lport [pg] ip4 && (ip4.src == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1052 drop to-lport [pg] ip4 && (ip4.src == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_e88c0d4d_73b0_486e_a3fb_d95baaa35ef1) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) || (tcp.dst >= 1037 && tcp.dst <= 1046) || (tcp.dst >= 1049 && tcp.dst <= 1058) || (tcp.dst >= 1062 && tcp.dst <= 1071) || (tcp.dst >= 1074 && tcp.dst <= 1083) || (tcp.dst >= 1086 && tcp.dst <= 1095) || (tcp.dst >= 1101 && tcp.dst <= 1110) || (tcp.dst >= 1113 && tcp.dst <= 1122) || (tcp.dst >= 1125 && tcp.dst <= 1134) || (tcp.dst >= 1140 && tcp.dst <= 1149))) || (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) || (udp.dst >= 1037 && udp.dst <= 1046) || (udp.dst >= 1049 && udp.dst <= 1058) || (udp.dst >= 1062 && udp.dst <= 1071) || (udp.dst >= 1074 && udp.dst <= 1083) || (udp.dst >= 1086 && udp.dst <= 1095) || (udp.dst >= 1101 && udp.dst <= 1110) || (udp.dst >= 1113 && udp.dst <= 1122) || (udp.dst >= 1125 && udp.dst <= 1134) || (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ca94bdb8_7cff_5c8c_858e_ca44207c5032) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) || (ip.proto == 6 && (tcp.dst == 22 || tcp.dst == 1024 || tcp.dst == 80)) || (ip.proto == 17 && (udp.dst == 22))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_09687af3_486d_5381_baff_78f78a00c4b3) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) || (tcp.dst >= 1166 && tcp.dst <= 1175) || (tcp.dst >= 1181 && tcp.dst <= 1190) || (tcp.dst >= 1193 && tcp.dst <= 1202) || (tcp.dst >= 1205 && tcp.dst <= 1214) || (tcp.dst >= 1218 && tcp.dst <= 1227) || (tcp.dst >= 1230 && tcp.dst <= 1239) || (tcp.dst >= 1242 && tcp.dst <= 1251) || (tcp.dst >= 1257 && tcp.dst <= 1266) || (tcp.dst >= 1271 && tcp.dst <= 1280))) || (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) || (udp.dst >= 1166 && udp.dst <= 1175) || (udp.dst >= 1181 && udp.dst <= 1190) || (udp.dst >= 1193 && udp.dst <= 1202) || (udp.dst >= 1205 && udp.dst <= 1214) || (udp.dst >= 1218 && udp.dst <= 1227) || (udp.dst >= 1230 && udp.dst <= 1239) || (udp.dst >= 1242 && udp.dst <= 1251) || (udp.dst >= 1257 && udp.dst <= 1266) || (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1045 drop to-lport [pg] ip4 && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1045 drop to-lport [pg] ip6 && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1019 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1018 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1017 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_25f83796_b668_50c1_a86f_741b6495cafe) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1015 allow-related to-lport [pg] ip4 && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1015 allow-related to-lport [pg] ip6 && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=500 allow-related to-lport [ls] tcp || udp || icmp
  3. LR router_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid=cb58bbb0-4bdc-429e-9378-838e204b99f1 has_nat=0
       LRP lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef mac=e0:19:95:08:22:c9 nets=['192.168.2.1/24']
       PBR pri=100 allow match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=10 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=1 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
  4. LR gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 uuid=edba0385-d5d3-4d07-8ca5-f9253e4af298 has_nat=1
       via transit_ls LS gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid=df8dadd4-7138-4ea7-95da-15fab0b6838c
       ACLs from-lport (ingress on this hop): (none)
       ACLs to-lport (egress on this hop): (none)
       PBR pri=1000 reroute match=ip4.src==100.64.1.6/32 nexthop=169.254.2.100
       RC chassis=bb49616e-e5ad-4dd7-9d98-ad529702d2df pri=100
       NAT dnat_and_snat ext=10.116.246.1 log=192.168.254.168 port=
       NAT dnat_and_snat ext=10.116.246.43 log=100.64.1.222 port=
       NAT snat ext=10.116.246.55 log=100.64.1.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.1.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.10.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.100.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.11.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.12.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.13.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.14.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.15.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.16.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.17.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.18.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.19.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.2.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.20.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.21.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.22.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.23.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.24.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.25.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.253.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.254.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.26.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.27.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.28.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.29.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.3.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.30.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.31.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.32.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.33.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.34.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.35.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.36.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.37.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.38.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.39.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.4.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.40.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.41.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.42.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.43.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.44.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.45.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.46.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.47.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.48.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.49.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.5.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.50.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.51.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.52.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.53.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.54.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.55.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.56.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.57.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.58.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.59.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.6.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.60.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.61.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.62.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.63.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.64.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.65.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.66.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.67.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.68.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.69.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.7.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.70.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.71.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.72.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.73.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.74.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.75.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.76.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.77.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.78.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.79.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.8.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.80.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.81.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.82.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.83.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.84.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.85.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.86.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.87.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.88.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.89.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.9.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.90.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.91.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.92.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.93.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.94.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.95.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.96.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.97.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.98.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.99.0/24 port=
  5. LR gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 uuid=6572681a-8ffe-4fba-9263-8501622d7726 has_nat=1
       via transit_ls LS network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a uuid=43a3a38a-89e1-4410-8101-b255757c2f28
       ACLs from-lport (ingress on this hop): 2 (full list)
         pri=1000 allow from-lport [ls] ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18
         pri=100 drop from-lport [ls] ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"
       ACLs to-lport (egress on this hop): (none)
       RC chassis=a109bd1b-b3d4-423d-8122-3fc3c80d4292 pri=100
       NAT dnat_and_snat ext=10.116.246.72 log=192.168.253.70 port=
       NAT snat ext=10.116.246.47 log=192.168.1.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.10.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.100.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.11.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.12.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.13.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.14.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.15.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.16.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.17.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.18.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.19.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.2.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.20.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.21.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.22.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.23.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.24.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.25.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.253.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.254.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.26.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.27.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.28.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.29.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.3.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.30.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.31.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.32.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.33.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.34.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.35.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.36.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.37.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.38.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.39.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.4.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.40.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.41.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.42.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.43.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.44.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.45.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.46.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.47.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.48.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.49.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.5.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.50.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.51.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.52.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.53.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.54.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.55.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.56.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.57.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.58.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.59.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.6.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.60.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.61.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.62.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.63.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.64.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.65.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.66.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.67.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.68.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.69.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.7.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.70.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.71.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.72.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.73.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.74.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.75.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.76.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.77.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.78.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.79.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.8.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.80.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.81.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.82.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.83.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.84.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.85.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.86.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.87.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.88.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.89.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.9.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.90.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.91.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.92.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.93.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.94.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.95.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.96.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.97.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.98.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.99.0/24 port=
  6. LR router_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid=a27e38bd-6c57-472f-80df-1a39723efe1a has_nat=0
       via transit_ls LS gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid=f7e6f4bb-0dfd-40a3-8023-270912e79985
       ACLs from-lport (ingress on this hop): (none)
       ACLs to-lport (egress on this hop): (none)
       PBR pri=100 allow match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=10 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=1 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
  7. LS network_17fe24db-e08b-4f81-969a-e06d6f23b35c uuid=183da7a8-c33c-4247-912a-d4cb28ec8a5a
       stretch flashfire01-3:geneve:10.116.29.156, flashfire03-2:geneve:10.116.29.191, flashfire04-1:geneve:10.116.29.208, spymaster01-2:geneve:10.116.26.72, spymaster02-3:geneve:10.116.26.91, zadkiel04-3:geneve:10.116.26.217, zadkiel04-4:geneve:10.116.26.218, zadkiel05-1:geneve:10.116.26.233 (+1)
       ACLs from-lport (ingress on this hop): 8 (full list)
         pri=31500 allow-stateless from-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406)
         pri=1052 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406)
         pri=1050 allow-related from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_b490212e_6951_43bf_a004_f47375039435) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) || (tcp.dst >= 18646 && tcp.dst <= 18655) || (tcp.dst >= 18661 && tcp.dst <= 18670) || (tcp.dst >= 18673 && tcp.dst <= 18682) || (tcp.dst >= 18685 && tcp.dst <= 18694) || (tcp.dst >= 18699 && tcp.dst <= 18708) || (tcp.dst >= 18712 && tcp.dst <= 18721) || (tcp.dst >= 18725 && tcp.dst <= 18734) || (tcp.dst >= 18737 && tcp.dst <= 18746) || (tcp.dst >= 18751 && tcp.dst <= 18760))) || (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) || (udp.dst >= 18646 && udp.dst <= 18655) || (udp.dst >= 18661 && udp.dst <= 18670) || (udp.dst >= 18673 && udp.dst <= 18682) || (udp.dst >= 18685 && udp.dst <= 18694) || (udp.dst >= 18699 && udp.dst <= 18708) || (udp.dst >= 18712 && udp.dst <= 18721) || (udp.dst >= 18725 && udp.dst <= 18734) || (udp.dst >= 18737 && udp.dst <= 18746) || (udp.dst >= 18751 && udp.dst <= 18760))))
         pri=1050 allow-related from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_17ae1270_33aa_5acd_94b7_65b09d6bf397) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) || (tcp.dst >= 18779 && tcp.dst <= 18788) || (tcp.dst >= 18794 && tcp.dst <= 18803) || (tcp.dst >= 18809 && tcp.dst <= 18818) || (tcp.dst >= 18821 && tcp.dst <= 18830) || (tcp.dst >= 18833 && tcp.dst <= 18842) || (tcp.dst >= 18847 && tcp.dst <= 18856) || (tcp.dst >= 18860 && tcp.dst <= 18869) || (tcp.dst >= 18874 && tcp.dst <= 18883) || (tcp.dst >= 18888 && tcp.dst <= 18897))) || (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) || (udp.dst >= 18779 && udp.dst <= 18788) || (udp.dst >= 18794 && udp.dst <= 18803) || (udp.dst >= 18809 && udp.dst <= 18818) || (udp.dst >= 18821 && udp.dst <= 18830) || (udp.dst >= 18833 && udp.dst <= 18842) || (udp.dst >= 18847 && udp.dst <= 18856) || (udp.dst >= 18860 && udp.dst <= 18869) || (udp.dst >= 18874 && udp.dst <= 18883) || (udp.dst >= 18888 && udp.dst <= 18897))))
         pri=1045 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip6
         pri=1045 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4
         pri=500 allow-related from-lport [ls] tcp || udp || icmp
       ACLs to-lport (egress on this hop): 9 (full list)
         pri=31500 allow-stateless to-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop to-lport [pg] ip4 && (ip4.src == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1052 drop to-lport [pg] ip4 && (ip4.src == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_205229df_97dd_4f48_8888_22f75df17032) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) || (tcp.dst >= 18376 && tcp.dst <= 18385) || (tcp.dst >= 18389 && tcp.dst <= 18398) || (tcp.dst >= 18401 && tcp.dst <= 18410) || (tcp.dst >= 18415 && tcp.dst <= 18424) || (tcp.dst >= 18429 && tcp.dst <= 18438) || (tcp.dst >= 18441 && tcp.dst <= 18450) || (tcp.dst >= 18455 && tcp.dst <= 18464) || (tcp.dst >= 18468 && tcp.dst <= 18477) || (tcp.dst >= 18483 && tcp.dst <= 18492))) || (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) || (udp.dst >= 18376 && udp.dst <= 18385) || (udp.dst >= 18389 && udp.dst <= 18398) || (udp.dst >= 18401 && udp.dst <= 18410) || (udp.dst >= 18415 && udp.dst <= 18424) || (udp.dst >= 18429 && udp.dst <= 18438) || (udp.dst >= 18441 && udp.dst <= 18450) || (udp.dst >= 18455 && udp.dst <= 18464) || (udp.dst >= 18468 && udp.dst <= 18477) || (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_8bd19f47_a216_502a_b5e5_00edc3b21853) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) || (ip.proto == 6 && (tcp.dst == 22 || tcp.dst == 1024 || tcp.dst == 80)) || (ip.proto == 17 && (udp.dst == 22))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_f96fe67d_5c12_5b66_b6a0_6e7e91be679b) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) || (tcp.dst >= 18512 && tcp.dst <= 18521) || (tcp.dst >= 18524 && tcp.dst <= 18533) || (tcp.dst >= 18537 && tcp.dst <= 18546) || (tcp.dst >= 18551 && tcp.dst <= 18560) || (tcp.dst >= 18564 && tcp.dst <= 18573) || (tcp.dst >= 18576 && tcp.dst <= 18585) || (tcp.dst >= 18590 && tcp.dst <= 18599) || (tcp.dst >= 18603 && tcp.dst <= 18612) || (tcp.dst >= 18618 && tcp.dst <= 18627))) || (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) || (udp.dst >= 18512 && udp.dst <= 18521) || (udp.dst >= 18524 && udp.dst <= 18533) || (udp.dst >= 18537 && udp.dst <= 18546) || (udp.dst >= 18551 && udp.dst <= 18560) || (udp.dst >= 18564 && udp.dst <= 18573) || (udp.dst >= 18576 && udp.dst <= 18585) || (udp.dst >= 18590 && udp.dst <= 18599) || (udp.dst >= 18603 && udp.dst <= 18612) || (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1045 drop to-lport [pg] ip6 && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1045 drop to-lport [pg] ip4 && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=500 allow-related to-lport [ls] tcp || udp || icmp
  8. VIF vm=VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4 nic=1d6e610d-f164-4f5d-a6f3-4be6a59a4819 lsp=port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 lsp_uuid=22bce434-1ef5-4792-8e57-8fa2a5e3bd71 mac=50:6b:8d:43:a5:90 ip=192.168.1.51

## Mermaid Upstream composite
**How to read:** left to right is packet flow. Blue stadium = VM. Rectangle = NIC, then TAP, then OVS port on brAtlas (ofport / datapath port / iface-id). Green cylinder = Switch (LS), orange hexagon = Router (LR) / External GW. Host subgraphs wrap compute VIF hops and every scale-out External GW Host (active RC vs standby). External GW label is MAC + IP/CIDR. Dashed yellow / pink / gray hang off a router = NAT / PBR / RC. Teal dashed = port group (policy applied-to). Gold dashed = address set (policy dest/src IPs). Purple dashed = Geneve when chassis differ. Red dashed = drop ACLs. Identity is UUID; names are display. `@port_group_*` and `$address_set_*` are rewritten to policy category / dest names in the ACL tables.

```mermaid
flowchart LR
  %% required VIF hops: TAP_S OVS_S TAP_D OVS_D (OVS label always brAtlas)
  classDef vm fill:#4C8BF5,stroke:#1a4fa0,color:#fff
  classDef nic fill:#E8F0FE,stroke:#4C8BF5,color:#111
  classDef sw fill:#34A853,stroke:#137333,color:#fff
  classDef rt fill:#FB8C00,stroke:#E65100,color:#111
  classDef nat fill:#FFF59D,stroke:#F9A825,color:#111,stroke-dasharray: 5 5
  classDef pbr fill:#F8BBD0,stroke:#C2185B,color:#111,stroke-dasharray: 5 5
  classDef rc fill:#BDBDBD,stroke:#616161,color:#111,stroke-dasharray: 5 5
  classDef ext fill:#EA4335,stroke:#B31412,color:#fff
  classDef ovl fill:#CE93D8,stroke:#7B1FA2,color:#111,stroke-dasharray: 5 5
  classDef dropacl fill:#FCE8E6,stroke:#C5221F,color:#111,stroke-dasharray: 5 5
  classDef tap fill:#E0F2F1,stroke:#00796B,color:#111
  classDef ovs fill:#ECEFF1,stroke:#37474F,color:#111
  classDef pg fill:#E0F7FA,stroke:#00838F,color:#111,stroke-dasharray: 5 5
  classDef aset fill:#FFF8E1,stroke:#FF8F00,color:#111,stroke-dasharray: 5 5
  subgraph UP["Upstream composite"]
  subgraph L2["L2 stretch"]
  subgraph H1["Host zadkiel05-3<br/>chassis a774c18b-7b6e-44f7-8661-6ac53c4607ca<br/>10.116.26.235<br/>geneve 10.116.26.235"]
  VM_S(["VM VPC_California_SJ_Pheonix_Customer_1_subnet_2_139"])
  NIC_S["NIC 3468ac71-d670-41a0-93af-0ec34d43f7c3<br/>MAC 50:6b:8d:19:78:77<br/>IP 192.168.2.186"]
  TAP_S["TAP tap222"]
  OVS_S["OVS brAtlas<br/>ofport 288 dp_port 242<br/>iface-id port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2"]
  end
  N1[("Switch<br/>network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef<br/>uuid 02d0de22-21a5-41f7-befd-75b6cb9c4cc7<br/>tunnel_key 10207<br/>datapath bd8492c8-3307-42fa-8a75-d484a87f4db7<br/>lb_vip_mac=e0:19:95:08:22:c9<br/>requested-tnl-key=10207<br/>neutron:network_name=network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef<br/>LSP vif port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 MAC 50:6b:8d:19:78:77 IP 192.168.2.186 chassis zadkiel05-3<br/>LSP router router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph L3["L3 routing / PBR"]
  N2{{"Router<br/>router_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>uuid cb58bbb0-4bdc-429e-9378-838e204b99f1<br/>tunnel_key 10110<br/>datapath 6ebe35ee-be81-4e57-8439-8fa1f83e557f<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>requested-tnl-key=10110<br/>neutron:router_name=router_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>LRP lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef uuid a962db06-7c7f-4a0b-8ca8-fe5ccfedf145 MAC e0:19:95:08:22:c9 192.168.2.1/24<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid 42734276-bf85-470b-a2bd-ddfeff3c11f4 MAC e0:19:95:c9:5b:48 169.254.2.20/24<br/>LRPs 104 total (path 2; full Metadata)<br/>routes connected 104 static 2 PBR 3 NAT 0"}}
  N3["PBR 3"]
  N2 -.-> N3
  end
  subgraph L2["L2 stretch"]
  N4[("Switch transit<br/>gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>uuid df8dadd4-7138-4ea7-95da-15fab0b6838c<br/>tunnel_key 13<br/>datapath 8ba15c30-c06f-4057-9b02-17415e5b45cd<br/>neutron:network_name=gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0 chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph GW["GW"]
  subgraph HGWp0["External GW Host flashfire01-2 (standby scale-out)<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20<br/>10.116.29.155<br/>geneve 10.116.29.155"]
  TAP_GWp0["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GWp0["OVS brAtlas<br/>ofport 406 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  RT_GW0{{"External GW<br/>gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0<br/>uuid f75fea9a-563e-474b-bdc0-08683ebd3842<br/>tunnel_key 63<br/>datapath 83526036-f5b1-463f-a72d-2363389bf512<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0 uuid 02a3eba2-e737-4eb0-85f6-2e7d203b7aaf MAC e0:19:95:8d:49:e8 169.254.2.100/24<br/>LRP lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26 uuid f0923e0b-40f2-49f3-bf4e-8dab34f0fb23 MAC e0:19:95:c0:b3:04 10.116.246.54/18 ext-GW<br/>LRPs 2<br/>routes connected 0 static 0 PBR 0 NAT 0<br/>IP 10.116.246.54/18 MAC e0:19:95:c0:b3:04<br/>HA flashfire01-2 pri=100<br/>standby scale-out"}}
  N5(["RC standby scale-out<br/>flashfire01-2<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20 pri=100"])
  RT_GW0 -.-> N5
  end
  subgraph HGW["External GW Host zadkiel04-1 (active RC)<br/>chassis b594f638-f4a0-439b-91d4-1c513f0c4529<br/>10.116.26.215<br/>geneve 10.116.26.215"]
  TAP_GW["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW["OVS brAtlas<br/>ofport 372 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  N6{{"External GW<br/>gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1<br/>uuid edba0385-d5d3-4d07-8ca5-f9253e4af298<br/>tunnel_key 33<br/>datapath 471c4d36-6dbb-49ed-8ff4-c4552d7a57a0<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1<br/>LRP lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212 uuid b3f1099a-b8ad-4bbe-962f-05cc5b4a3511 MAC e0:19:95:9b:58:bb 10.116.246.55/18 ext-GW<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 uuid 5d3e7d2c-6a4f-4f15-ac5d-f698ccb2162d MAC e0:19:95:60:29:5b 169.254.2.101/24<br/>LRPs 2<br/>routes connected 2 static 104 PBR 1 NAT 105<br/>IP 10.116.246.55/18 MAC e0:19:95:9b:58:bb<br/>NAT<br/>HA zadkiel04-1 pri=100<br/>active RC"}}
  N7["NAT 105"]
  N6 -.-> N7
  N8["PBR 1"]
  N6 -.-> N8
  N9(["RC active RC<br/>zadkiel04-1<br/>chassis b594f638-f4a0-439b-91d4-1c513f0c4529 pri=100"])
  N6 -.-> N9
  end
  N6 -.-> RT_GW0
  end
  subgraph EXT["External"]
  N10[("Switch External localnet<br/>network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a<br/>uuid 43a3a38a-89e1-4410-8101-b255757c2f28<br/>tunnel_key 10105<br/>datapath 068f23c5-b151-4b7c-b29e-3693db43765a<br/>fdb_age_threshold=300<br/>requested-tnl-key=10105<br/>use-gateway-chassis=true<br/>use-redirect-chassis=true<br/>neutron:network_name=network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a<br/>LSP localnet localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a chassis 00000000-0000-0000-0000-000000000000<br/>LSP router ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075 chassis spymaster01-3<br/>LSP router ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141 chassis flashfire01-3<br/>LSP router ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8 chassis spymaster01-1<br/>LSP router ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769 chassis spymaster01-4<br/>LSP router ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11 chassis spymaster01-2<br/>LSP router ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93 chassis flashfire01-2<br/>LSP router ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9 chassis spymaster01-4")]
  end
  subgraph GW["GW"]
  subgraph HGW1p0["External GW Host flashfire01-2 (standby scale-out)<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20<br/>10.116.29.155<br/>geneve 10.116.29.155"]
  TAP_GW1p0["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW1p0["OVS brAtlas<br/>ofport 406 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  RT_GW1p0{{"External GW<br/>gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1<br/>uuid ce75ff4c-456e-4154-bab4-add0f3c5401f<br/>tunnel_key 154<br/>datapath 343cd570-3b2c-4f79-a87f-81e7d877e697<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1<br/>LRP lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d uuid 7d613d5f-98e1-4cd8-9d33-21bf9b9e30b9 MAC e0:19:95:5b:76:31 10.116.246.48/18 ext-GW<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1 uuid 6d52f0b1-a274-40c1-ba60-9c15ea3eddd0 MAC e0:19:95:4b:de:17 169.254.2.101/24<br/>LRPs 2<br/>routes connected 0 static 0 PBR 0 NAT 0<br/>IP 10.116.246.48/18 MAC e0:19:95:5b:76:31<br/>HA flashfire01-2 pri=100<br/>standby scale-out"}}
  N11(["RC standby scale-out<br/>flashfire01-2<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20 pri=100"])
  RT_GW1p0 -.-> N11
  end
  subgraph HGW1["External GW Host zadkiel04-3 (active RC)<br/>chassis e6226ec1-fa8f-41e5-8d0c-7a884b7f9634<br/>10.116.26.217<br/>geneve 10.116.26.217"]
  TAP_GW1["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW1["OVS brAtlas<br/>ofport 322 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  N12{{"External GW<br/>gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0<br/>uuid 6572681a-8ffe-4fba-9263-8501622d7726<br/>tunnel_key 105<br/>datapath 5dbeea18-4571-4439-a5a7-f334ae8c699c<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 uuid 50e071f0-0ec8-4532-9132-241a776b2cde MAC e0:19:95:87:06:3b 169.254.2.100/24<br/>LRP lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0 uuid 9cc5a260-0c66-43b8-95be-0f18815bdda2 MAC e0:19:95:14:17:37 10.116.246.47/18 ext-GW<br/>LRPs 2<br/>routes connected 2 static 103 PBR 0 NAT 103<br/>IP 10.116.246.47/18 MAC e0:19:95:14:17:37<br/>NAT<br/>HA zadkiel04-3 pri=100<br/>active RC"}}
  N13["NAT 103"]
  N12 -.-> N13
  N14(["RC active RC<br/>zadkiel04-3<br/>chassis e6226ec1-fa8f-41e5-8d0c-7a884b7f9634 pri=100"])
  N12 -.-> N14
  end
  N12 -.-> RT_GW1p0
  end
  subgraph L2["L2 stretch"]
  N15[("Switch transit<br/>gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>uuid f7e6f4bb-0dfd-40a3-8023-270912e79985<br/>tunnel_key 45<br/>datapath 142ae345-5743-4655-b32e-857596482fb5<br/>neutron:network_name=gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1 chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph L3["L3 routing / PBR"]
  N16{{"Router<br/>router_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>uuid a27e38bd-6c57-472f-80df-1a39723efe1a<br/>tunnel_key 10124<br/>datapath 7494f7b0-3a05-40c9-ba1f-8a971b4e99da<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>requested-tnl-key=10124<br/>neutron:router_name=router_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>LRP lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c uuid 62ccf088-8c87-48ec-8b68-4c4a6ccff023 MAC e0:19:95:59:9f:05 192.168.1.1/24<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid 6ca4b6f3-615e-440b-9509-f0bae9fa92ae MAC e0:19:95:8d:46:1a 169.254.2.20/24<br/>LRPs 103 total (path 2; full Metadata)<br/>routes connected 103 static 2 PBR 3 NAT 0"}}
  N17["PBR 3"]
  N16 -.-> N17
  end
  subgraph L2["L2 stretch"]
  N18[("Switch<br/>network_17fe24db-e08b-4f81-969a-e06d6f23b35c<br/>uuid 183da7a8-c33c-4247-912a-d4cb28ec8a5a<br/>tunnel_key 11303<br/>datapath 82790df2-ba45-4e0e-9536-d37869adfce5<br/>lb_vip_mac=e0:19:95:59:9f:05<br/>requested-tnl-key=11303<br/>neutron:network_name=network_17fe24db-e08b-4f81-969a-e06d6f23b35c<br/>LSP vif port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 MAC 50:6b:8d:43:a5:90 IP 192.168.1.51 chassis spymaster01-2<br/>LSP router router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c chassis 00000000-0000-0000-0000-000000000000")]
  subgraph H2["Host spymaster01-2<br/>chassis bbd822da-f0b1-4a7d-a894-df4029cfb598<br/>10.116.26.72<br/>geneve 10.116.26.72"]
  OVS_D["OVS brAtlas<br/>ofport 91 dp_port 60<br/>iface-id port_ac6485b2-02b8-492e-84ca-1e4fa3e33360"]
  TAP_D["TAP tap42"]
  NIC_D["NIC 1d6e610d-f164-4f5d-a6f3-4be6a59a4819<br/>MAC 50:6b:8d:43:a5:90<br/>IP 192.168.1.51"]
  VM_D(["VM VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4"])
  end
  N19["Overlay geneve<br/>10.116.26.235 to 10.116.26.72"]
  N1 -.-> N19
  end
  subgraph ACL["ACL Policy"]
  N20["Port group<br/>category AppType<br/>policy VPC_California_SJ_Pheonix_Customer_1_App_1 (secured)<br/>2000 NICs<br/>OVN @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f"]
  N1 -.-> N20
  N21["Port group<br/>category AppType<br/>policy EG_Exclude_Policy1 (secured)<br/>2000 NICs<br/>OVN @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133"]
  N1 -.-> N21
  N22["Port group<br/>category App33<br/>policy VPC_California_SJ_Pheonix_Customer_19_App_33 (secured)<br/>10 NICs<br/>OVN @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0"]
  N1 -.-> N22
  N23["Address set<br/>AppType EG_Exclude_Policy1 secured<br/>2000 IPs: 192.168.1.10, 192.168.1.100, 192.168.1.101, 192.168.1.103 +1996<br/>OVN $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c"]
  N1 -.-> N23
  N24["Address set<br/>10 IPs: 192.168.254.11/32, 192.168.254.122/32, 192.168.254.149/32, 192.168.254.154/32 +6<br/>OVN $address_set_9c194c48_8c96_54a7_837a_81508c40ddae"]
  N1 -.-> N24
  N25["Address set<br/>outbound VPC_California_SJ_Pheonix_Customer_1_App_1 dest<br/>10 IPs: 192.168.254.127, 192.168.254.152, 192.168.254.18, 192.168.254.212 +6<br/>OVN $address_set_f412ba3b_b736_4b27_a0e6_4eeefc7220a4"]
  N1 -.-> N25
  N26["Address set<br/>AppType EG_Exclude_Policy1 secured<br/>2000 IPs: 192.168.1.10, 192.168.1.100, 192.168.1.101, 192.168.1.103 +1996<br/>OVN $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506"]
  N1 -.-> N26
  N27["Address set<br/>App33 VPC_California_SJ_Pheonix_Customer_19_App_33 secured<br/>10 IPs: 192.168.1.122, 192.168.1.141, 192.168.1.15, 192.168.1.153 +6<br/>OVN $address_set_1b11d438_5b2f_4b00_950b_3c355529d406"]
  N1 -.-> N27
  N28["Address set<br/>2 IPs: 192.168.254.164, 192.168.254.72<br/>OVN $address_set_b490212e_6951_43bf_a004_f47375039435"]
  N1 -.-> N28
  N29["Address set<br/>2 IPs: 192.168.254.117/32, 192.168.254.227/32<br/>OVN $address_set_17ae1270_33aa_5acd_94b7_65b09d6bf397"]
  N1 -.-> N29
  N30["Address set<br/>inbound VPC_California_SJ_Pheonix_Customer_1_App_1 src<br/>10 IPs: 192.168.254.102, 192.168.254.103, 192.168.254.144, 192.168.254.238 +6<br/>OVN $address_set_e88c0d4d_73b0_486e_a3fb_d95baaa35ef1"]
  N1 -.-> N30
  N31["Address set<br/>2 IPs: 192.168.254.168/32, 192.168.254.89/32<br/>OVN $address_set_ca94bdb8_7cff_5c8c_858e_ca44207c5032"]
  N1 -.-> N31
  N32["Address set<br/>10 IPs: 192.168.254.129/32, 192.168.254.132/32, 192.168.254.151/32, 192.168.254.159/32 +6<br/>OVN $address_set_09687af3_486d_5381_baff_78f78a00c4b3"]
  N1 -.-> N32
  N33["Address set<br/>17 IPs: 0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/9, 192.128.0.0/11 +13<br/>OVN $address_set_25f83796_b668_50c1_a86f_741b6495cafe"]
  N1 -.-> N33
  N34["Address set<br/>2 IPs: 192.168.254.151, 192.168.254.221<br/>OVN $address_set_205229df_97dd_4f48_8888_22f75df17032"]
  N1 -.-> N34
  N35["Address set<br/>1 IPs: 192.168.253.70/32<br/>OVN $address_set_8bd19f47_a216_502a_b5e5_00edc3b21853"]
  N1 -.-> N35
  N36["Address set<br/>2 IPs: 192.168.254.117/32, 192.168.254.227/32<br/>OVN $address_set_f96fe67d_5c12_5b66_b6a0_6e7e91be679b"]
  N1 -.-> N36
  N37["ACL drop pri=1060<br/>from-lport 9 / to-lport 8"]
  N1 -.-> N37
  end
  end
  VM_S --> NIC_S
  NIC_S --> TAP_S
  TAP_S --> OVS_S
  OVS_S --> N1
  N1 --> N2
  N2 --> N4
  N4 --> TAP_GW
  TAP_GW --> OVS_GW
  OVS_GW --> N6
  N6 --> N10
  N10 --> TAP_GW1
  TAP_GW1 --> OVS_GW1
  OVS_GW1 --> N12
  N12 --> N15
  N15 --> N16
  N16 --> N18
  N18 --> OVS_D
  OVS_D --> TAP_D
  TAP_D --> NIC_D
  NIC_D --> VM_D
  class VM_S vm
  class NIC_S nic
  class TAP_S tap
  class OVS_S ovs
  class N1 sw
  class N2 rt
  class N3 pbr
  class N4 sw
  class TAP_GWp0 tap
  class OVS_GWp0 ovs
  class RT_GW0 rt
  class N5 rc
  class TAP_GW tap
  class OVS_GW ovs
  class N6 rt
  class N7 nat
  class N8 pbr
  class N9 rc
  class N10 sw
  class TAP_GW1p0 tap
  class OVS_GW1p0 ovs
  class RT_GW1p0 rt
  class N11 rc
  class TAP_GW1 tap
  class OVS_GW1 ovs
  class N12 rt
  class N13 nat
  class N14 rc
  class N15 sw
  class N16 rt
  class N17 pbr
  class N18 sw
  class OVS_D ovs
  class TAP_D tap
  class NIC_D nic
  class VM_D vm
  class N19 ovl
  class N20 pg
  class N21 pg
  class N22 pg
  class N23 aset
  class N24 aset
  class N25 aset
  class N26 aset
  class N27 aset
  class N28 aset
  class N29 aset
  class N30 aset
  class N31 aset
  class N32 aset
  class N33 aset
  class N34 aset
  class N35 aset
  class N36 aset
  class N37 dropacl
```

_Upstream `two_router`. Host boxes wrap VM+NIC+TAP+OVS brAtlas when chassis differ. Scale-out draws every External GW Host (active RC vs standby), with TAP_GW / OVS brAtlas when dataplane has them. External GW node is MAC + IP/CIDR._

#### Upstream — Metadata (LS / LR from flow_ovn)

##### Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` uuid `02d0de22-21a5-41f7-befd-75b6cb9c4cc7`

```json
{
  "ls_uuid": "02d0de22-21a5-41f7-befd-75b6cb9c4cc7",
  "name": "network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
  "transit": false,
  "localnet": false,
  "datapath_uuid": "bd8492c8-3307-42fa-8a75-d484a87f4db7",
  "tunnel_key": 10207,
  "other_config": {
    "lb_vip_mac": "e0:19:95:08:22:c9",
    "requested-tnl-key": "10207"
  },
  "external_ids": {
    "neutron:network_name": "network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef"
  },
  "ports": [
    {
      "lsp_uuid": "915f1338-1aba-4c27-a016-cb9876cdc970",
      "name": "port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2",
      "type": "vif",
      "mac": "50:6b:8d:19:78:77",
      "ip": "192.168.2.186",
      "addresses": [
        "50:6b:8d:19:78:77 192.168.2.186"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "a774c18b-7b6e-44f7-8661-6ac53c4607ca",
      "hostname": "zadkiel05-3",
      "pb_tunnel_key": 160
    },
    {
      "lsp_uuid": "aa4764a1-7aca-4ccb-b52b-c97072e274ae",
      "name": "router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    }
  ]
}
```

Path LSPs — 2 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | vif | `port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2` | `915f1338-1aba-4c27-a016-cb9876cdc970` | `50:6b:8d:19:78:77` | `192.168.2.186` | `zadkiel05-3` |
| 2 | router | `router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `aa4764a1-7aca-4ccb-b52b-c97072e274ae` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `cb58bbb0-4bdc-429e-9378-838e204b99f1`

```json
{
  "lr_uuid": "cb58bbb0-4bdc-429e-9378-838e204b99f1",
  "name": "router_fc433064-926d-4fc0-a1a3-7c089ad90343",
  "has_nat": false,
  "datapath_uuid": "6ebe35ee-be81-4e57-8439-8fa1f83e557f",
  "tunnel_key": 10110,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400",
    "requested-tnl-key": "10110"
  },
  "external_ids": {
    "neutron:router_name": "router_fc433064-926d-4fc0-a1a3-7c089ad90343"
  },
  "lrp_count": 104
}
```

Every LRP — 104 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-router-port_8ca6f7a0-3f82-4de7-911b-f1e92b5ec140` | `64233e11-9c0b-4555-80ef-22cf6b6f4814` | `e0:19:95:56:6a:af` | `192.168.93.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-router-port_e03534c4-e36c-4067-9f9d-459ce653637d` | `a5b8e793-495b-4d7c-8116-6cf2bac22b97` | `e0:19:95:8b:c8:83` | `192.168.34.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 3 | `lrp-router-port_b4685b3f-31a1-4c96-9b30-a68ae1b0a272` | `694c9dc4-ea30-479d-812b-1487bd5ca7c3` | `e0:19:95:3e:c2:5f` | `192.168.61.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 4 | `lrp-router-port_d110f476-68a9-4d94-9911-5fc864464b43` | `fd790747-13c3-42c3-820d-0158b6a313a4` | `e0:19:95:9e:df:8d` | `192.168.72.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 5 | `lrp-router-port_bfbc4008-67c9-476c-966a-cf8465a909e3` | `1e86a625-ecbb-48bb-8219-f43de8bd052d` | `e0:19:95:ff:37:99` | `192.168.45.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 6 | `lrp-router-port_a7799f72-bad9-482e-9466-cbcdd59d7625` | `3672efca-9d87-491b-8466-9aaac1b523fe` | `e0:19:95:25:67:61` | `192.168.98.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 7 | `lrp-router-port_d4df28ac-20e5-40fe-b659-368c0d4f9698` | `437374f4-d008-42c2-847c-eaae13a01c4d` | `e0:19:95:fe:19:81` | `192.168.70.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 8 | `lrp-router-port_0c904e1b-e631-4f18-8acb-e3051368d3f9` | `897fc7b4-f272-4dc0-84e2-029be59f8df5` | `e0:19:95:14:82:0e` | `192.168.81.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 9 | `lrp-router-port_807ed90e-1fda-497f-9098-7958ef0d4990` | `dd0e4979-a149-49c1-8560-8773271ce258` | `e0:19:95:88:7d:95` | `192.168.4.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 10 | `lrp-router-port_c8d975d9-60b0-419c-b56d-f28f9200504f` | `55136155-be12-4a98-8563-21d12185c179` | `e0:19:95:d0:e5:4f` | `192.168.9.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 11 | `lrp-router-port_4bceacc5-ac6e-4008-8e70-97cfd30e5430` | `0cbf3173-108d-492f-85a2-4d0239a2a7d7` | `e0:19:95:ca:65:c1` | `192.168.32.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 12 | `lrp-router-port_8f8336aa-42da-43b7-8757-3997a975a07d` | `9b0ca561-7935-4667-85ed-68bb78a1fa84` | `e0:19:95:77:a4:ba` | `192.168.68.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 13 | `lrp-router-port_8dcafab3-5338-4114-9eef-0e6fa19605df` | `c5d49730-2e9f-41a0-8632-dc03b4108af0` | `e0:19:95:93:ab:9b` | `192.168.99.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 14 | `lrp-router-port_9dd293d7-0450-478d-980b-8b5bd08a89cb` | `cf63cbce-f5d2-413a-8673-13fe67460180` | `e0:19:95:6f:90:f9` | `192.168.87.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 15 | `lrp-router-port_4ea3c785-c4a9-498c-80f3-ed2aa55c29d9` | `03f7e95b-82fa-4672-881e-57b1d0056991` | `e0:19:95:b9:0c:9d` | `192.168.11.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 16 | `lrp-router-port_c307271a-0a3d-4325-8071-71b873bc3768` | `8646d92c-5c81-4cc6-8882-799442c809bd` | `e0:19:95:18:d4:6b` | `192.168.100.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 17 | `lrp-router-port_fa0c4784-a17e-4b1f-b4ff-220bca5b4cce` | `31e722c0-ec9e-4e24-899f-83ef276c6802` | `e0:19:95:e2:19:b8` | `192.168.14.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 18 | `lrp-router-port_e141bb39-f661-4c6f-95cd-63773a7db69d` | `1f01d52b-1db8-406e-8c37-1c57bea23203` | `e0:19:95:68:c7:41` | `192.168.48.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 19 | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `a962db06-7c7f-4a0b-8ca8-fe5ccfedf145` | `e0:19:95:08:22:c9` | `192.168.2.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 20 | `lrp-router-port_032fedb1-1e88-4849-bc5d-ad7f358ea600` | `ad13ede1-97ad-4037-8ce2-1e12ca1382f0` | `e0:19:95:cb:87:d1` | `192.168.73.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 21 | `lrp-router-port_2c1b4c9d-8fd5-4354-8205-62ef2d28cef8` | `f68c0d67-c7c5-46e0-8ce3-57440cb1db36` | `e0:19:95:56:0b:15` | `192.168.60.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 22 | `lrp-router-port_2dc24931-94e9-439b-986f-7a62a7bf92a1` | `539ecc8b-3c07-492c-8d4b-6210dec56a46` | `e0:19:95:28:39:6d` | `192.168.55.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 23 | `lrp-router-port_0743c6fc-5073-425e-9770-ead8c56c42e9` | `5423818c-753e-4123-8de0-67236f85704b` | `e0:19:95:5c:82:51` | `192.168.78.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 24 | `lrp-router-port_830e914f-389c-4171-a7be-8e0d1f94c96b` | `056cfc0f-d9db-494b-8e26-e1ad2a6d1be9` | `e0:19:95:90:d1:bf` | `192.168.33.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 25 | `lrp-router-port_d25f3dea-d19d-4c4c-a487-41613ce2eb61` | `c291e650-cabc-4738-8e9e-6c7457201f65` | `e0:19:95:31:ca:12` | `192.168.67.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 26 | `lrp-router-port_71d41765-890f-4b8d-895b-e82505096413` | `14262dba-7024-407b-8fb6-87aa8397da05` | `e0:19:95:dd:34:b6` | `192.168.46.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 27 | `lrp-router-port_675f2734-4826-467a-b43e-00698627a259` | `943232a2-0da1-4f2e-9089-93b0f878dab7` | `e0:19:95:80:ac:36` | `192.168.40.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 28 | `lrp-router-port_42ecfffe-0e34-4d14-85f7-5301de17cf69` | `ef431a7c-025b-483d-9105-c9ca3663d10e` | `e0:19:95:76:5c:04` | `192.168.90.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 29 | `lrp-router-port_fa896d0f-b0d0-4fa3-b688-331e9edc2a39` | `161655fa-d6ab-43e5-9139-c0999ec180c4` | `e0:19:95:6c:e3:fd` | `192.168.20.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 30 | `lrp-router-port_0ba9c57a-57c7-4ef9-8c24-4786c8f54d47` | `33155985-fe1d-4f89-916f-f816da6612ef` | `e0:19:95:20:df:2e` | `192.168.31.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 31 | `lrp-router-port_174db21e-8ba1-48eb-beb6-aa4ab68a2305` | `9651f6ea-731d-4ab4-9175-053456e3fd2b` | `e0:19:95:9c:97:00` | `192.168.76.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 32 | `lrp-router-port_4bdb92dc-d31e-46fb-89e9-88a99f403c29` | `3a37d6c9-bec2-47d1-91f1-fae7fe2792e2` | `e0:19:95:46:1a:15` | `192.168.57.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 33 | `lrp-router-port_ca086587-3fdb-41e7-8571-d01547cece9f` | `3aa8a711-0114-4ac4-9204-f3d709c8a166` | `e0:19:95:ac:cf:7e` | `192.168.17.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 34 | `lrp-router-port_2dac78de-9721-4a5b-8086-4c965dd6c619` | `f04df7ad-7eef-4e1f-932c-5ee1d2861ba4` | `e0:19:95:2b:aa:74` | `192.168.27.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 35 | `lrp-router-port_dae15e78-0138-406f-9c44-5931c2433eae` | `bb143bbf-1dd5-4758-939e-9693a95474b0` | `e0:19:95:99:e6:0d` | `192.168.253.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 36 | `lrp-router-port_f78566a0-d032-4d39-b160-26a846193005` | `e171de44-3da5-49e6-9510-263948c34e89` | `e0:19:95:c5:63:33` | `192.168.6.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 37 | `lrp-router-port_81097727-e648-454a-81df-ae0520caca2c` | `3bbbc8a4-9afa-478d-9551-07da22c5da2c` | `e0:19:95:6a:b4:16` | `192.168.74.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 38 | `lrp-router-port_1358d80d-13be-42f7-ac61-82d076a18135` | `51a681b0-c999-47a2-9564-dc5827ad9b08` | `e0:19:95:34:81:33` | `192.168.96.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 39 | `lrp-router-port_30c8fe9c-b42a-4e3e-a38a-cc11cb73d1e6` | `5fb293cb-4aaa-4c9d-9570-0f9c7a3820d5` | `e0:19:95:c7:1e:be` | `192.168.16.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 40 | `lrp-router-port_8b6751f8-979a-42f0-b64d-d71fea87beee` | `b7eb6b2c-877c-43f8-95ce-b5c5342bbc97` | `e0:19:95:a0:be:92` | `192.168.19.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 41 | `lrp-router-port_2f065e5c-a736-43f7-a8f9-ad969e733b13` | `d808dcb7-4bfc-43ac-95d7-590b1242bacc` | `e0:19:95:a7:19:d9` | `192.168.8.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 42 | `lrp-router-port_0f1f3f44-0fa0-45c4-918d-ac99e0d75e0d` | `66ed755b-200a-425d-9723-87881189eb5b` | `e0:19:95:c7:e4:05` | `192.168.95.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 43 | `lrp-router-port_e09f8b78-d094-4bdd-9f6d-18b0d14e50bf` | `68158f91-4874-4acd-973e-9f5c334ff84b` | `e0:19:95:e2:cb:26` | `192.168.63.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 44 | `lrp-router-port_80e90459-8298-4d6c-95bf-9deecc8c48fb` | `a2090153-8094-4b16-98a1-283a7a36cac3` | `e0:19:95:e3:3f:66` | `192.168.29.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 45 | `lrp-router-port_073a0cb1-e7cc-4b24-92f2-9c07ff0ab096` | `fdfb64dd-55e6-4c6d-98b3-599a934d791b` | `e0:19:95:a0:0f:1a` | `192.168.41.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 46 | `lrp-router-port_37fb764e-d0fa-457b-a216-43d9b11b3aed` | `f3f7daab-3a78-4bcb-98b9-744fa87dc752` | `e0:19:95:fa:ba:a0` | `192.168.65.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 47 | `lrp-router-port_b69e06e1-b184-4390-8cd6-f22044118b16` | `c22e6517-9139-4df6-990e-feba9f218988` | `e0:19:95:82:51:dc` | `100.64.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 48 | `lrp-router-port_75e16325-7223-4e38-a44c-a04509f4f777` | `27386bc2-49b8-4f66-9960-21aeac1f0407` | `e0:19:95:9d:2e:87` | `192.168.44.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 49 | `lrp-router-port_c0e67438-6eae-42c9-b6f2-6f6e470d4db8` | `e90cc4c6-2008-4f4f-9968-d28d5cae43ba` | `e0:19:95:6d:3a:78` | `192.168.89.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 50 | `lrp-router-port_de80667d-6f56-4481-ba8f-14be08b4a8fc` | `07da41d5-6b8e-4514-9ad1-9a680f47990a` | `e0:19:95:25:71:58` | `192.168.42.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 51 | `lrp-router-port_e8a882dc-a636-4b57-ab53-813694611e92` | `21d3bc09-a435-413b-9ad6-54248ecd643b` | `e0:19:95:2f:45:38` | `192.168.26.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 52 | `lrp-router-port_620e1ab8-b44e-4051-97b4-b3e73728664d` | `2c909093-c8ec-4818-9b5a-1446ce094ccc` | `e0:19:95:27:93:33` | `192.168.30.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 53 | `lrp-router-port_6e1383c1-5e63-46ea-b513-416115448c8e` | `da1703ff-d6bc-42da-9ba6-de6bfd61aacd` | `e0:19:95:02:91:54` | `192.168.80.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 54 | `lrp-router-port_195bf1a1-d7ab-44a9-987b-4e595a4c34e0` | `c3e621ce-c10f-4f2f-9cd7-75edbbda6e74` | `e0:19:95:51:42:af` | `192.168.58.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 55 | `lrp-router-port_e800940d-51e7-42e1-a338-647494e919db` | `f6d53175-5856-45d8-a043-a9aea6645785` | `e0:19:95:35:75:0e` | `192.168.47.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 56 | `lrp-router-port_e0002237-57a9-433f-9e82-938599b90a98` | `dab6f27c-3eb7-4332-a05d-166723f03a8e` | `e0:19:95:b0:f3:f9` | `192.168.83.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 57 | `lrp-router-port_48ef8369-ed7d-400a-b84c-c74e67a54347` | `79fba623-a2c0-4ab8-a19f-af56eb1e6e5a` | `e0:19:95:f1:59:a8` | `192.168.88.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 58 | `lrp-router-port_c275c897-fea0-434c-a9ab-fa02a5af893a` | `4fcb480b-2d45-4691-a1e7-31cb4ef035d7` | `e0:19:95:8c:48:8e` | `192.168.69.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 59 | `lrp-router-port_fe749a87-cf4d-42e1-b165-e5551acdb3c3` | `c2b65616-59ee-4206-a24c-5d689a1058b0` | `e0:19:95:4c:aa:79` | `192.168.21.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 60 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `42734276-bf85-470b-a2bd-ddfeff3c11f4` | `e0:19:95:c9:5b:48` | `169.254.2.20/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 61 | `lrp-router-port_da0d1e4f-cd5e-4d70-b6cb-76c26d3268ef` | `c00fb43f-5ad9-499c-a3c5-8798396a4207` | `e0:19:95:e8:bd:5e` | `192.168.36.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 62 | `lrp-router-port_a42276da-b029-4099-bc9d-c81a6c5c229d` | `a717f6de-4dba-488d-a3ed-35f40a0af6b3` | `e0:19:95:a9:61:71` | `192.168.56.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 63 | `lrp-router-port_baf0d081-ea93-4077-899d-f7e6dc63f539` | `bf84ed6b-a702-4a76-a438-d3b6ee9f3a6d` | `e0:19:95:f7:eb:9c` | `192.168.59.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 64 | `lrp-router-port_ebf08da2-c15c-473b-a1bd-8f5f871ad07a` | `55f2a571-2f98-4f84-a442-223d6e39dfa2` | `e0:19:95:90:3c:3f` | `192.168.71.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 65 | `lrp-router-port_c5422e1c-4aae-4e5f-9520-936bc881921d` | `47b50377-d52f-4a1b-a4c7-65c7c1ea04f1` | `e0:19:95:5e:f5:f1` | `192.168.28.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 66 | `lrp-router-port_b53ef258-faec-4995-b4e7-d2d4a061ddf2` | `a53c75c6-c3b1-4a93-a507-3592b164beed` | `e0:19:95:69:61:ea` | `192.168.18.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 67 | `lrp-router-port_d5d2d617-49ca-49a7-9665-f89f5ff8d0f2` | `fdc608a4-8603-4024-a53a-c90b431a02c1` | `e0:19:95:e3:14:7a` | `192.168.22.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 68 | `lrp-router-port_782ca68a-04b1-4fdc-a822-9d58215f7765` | `0d85ffb0-14c7-42de-a6bf-3660b7c80574` | `e0:19:95:bb:f4:cf` | `192.168.86.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 69 | `lrp-router-port_dbf060f4-6528-4cd8-8a68-f32313bb409a` | `93439c46-da3d-417b-a70d-be08c1001858` | `e0:19:95:b1:79:98` | `192.168.92.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 70 | `lrp-router-port_d1624e61-07ee-47a2-9816-691b67ad9a9b` | `17ae7a43-e7cd-435d-a76e-a418cd3d162b` | `e0:19:95:b0:94:7d` | `192.168.77.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 71 | `lrp-router-port_3ea92dc1-e13d-4e44-adad-e2adb944fd31` | `b6b01066-e41d-4ae9-a791-c74fbf0f00d2` | `e0:19:95:7f:30:ff` | `192.168.24.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 72 | `lrp-router-port_6c8f9dd7-4e03-4c2c-9fe5-da7eac887606` | `afcfcbe5-a1c8-4a46-a7ee-1c9b6e7e982c` | `e0:19:95:7c:02:0c` | `192.168.66.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 73 | `lrp-router-port_4124a4e2-3461-47f4-8612-377639eaaf87` | `3273c602-7eec-4752-aa44-d7569020eeb9` | `e0:19:95:e5:cb:45` | `192.168.64.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 74 | `lrp-router-port_3299d3a7-124a-4c43-9ae9-0f798040eae1` | `767d5a44-7559-4aa7-aa86-27200c5d0335` | `e0:19:95:98:b8:cc` | `192.168.49.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 75 | `lrp-router-port_93837b6a-1c71-47fe-a427-7b818c6874d7` | `4d71d847-edb0-4280-aaac-25d75a5810ce` | `e0:19:95:9a:19:81` | `192.168.43.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 76 | `lrp-router-port_9ec643a3-96ce-4ad1-b80d-708e8149f79d` | `5f9c5aa7-c8b6-43a2-abac-ae4483b20d9d` | `e0:19:95:c6:34:74` | `192.168.15.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 77 | `lrp-router-port_3d07fc33-53d7-4f9a-b853-449ef50a2eea` | `cdd687af-d3f6-42a8-ae63-f15be86f2cbc` | `e0:19:95:27:1e:73` | `192.168.94.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 78 | `lrp-router-port_6fef40cb-9010-4464-af83-fa6e75ec0b6d` | `2a05c567-dfe9-48e3-aeaf-869b44116993` | `e0:19:95:dd:bf:9c` | `192.168.7.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 79 | `lrp-router-port_5fd6becb-db5b-4c6f-bcdd-35e95888cc20` | `783bfc2a-8236-4d1d-b093-532163105e24` | `e0:19:95:66:94:35` | `192.168.254.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 80 | `lrp-router-port_455bebd3-3c1b-4e18-be7b-343d7350e90f` | `efde5afd-2364-42b7-b0c2-230394485c34` | `e0:19:95:52:ac:b4` | `192.168.39.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 81 | `lrp-router-port_a5627ef6-0b96-4e84-867a-3f257ea3dbf3` | `d7cff9d2-08f2-4c79-b0f8-9d3c59d0e80a` | `e0:19:95:a2:b1:49` | `192.168.97.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 82 | `lrp-router-port_88c50715-b1a5-4281-bee9-11dc6671f8ad` | `d739568b-b227-4f23-b2c9-bf8ebd0bfdc9` | `e0:19:95:21:8e:11` | `192.168.84.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 83 | `lrp-router-port_96d3605c-fe95-455b-83a6-dd2d3e52373a` | `92538731-a957-45a1-b2e3-673a1540c556` | `e0:19:95:30:5d:5d` | `192.168.52.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 84 | `lrp-router-port_ca6a8331-7e2a-4573-987c-4ef24353ee07` | `4479b60f-0384-4350-b336-09805472978b` | `e0:19:95:6b:43:45` | `192.168.13.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 85 | `lrp-router-port_865e3efc-d7dc-4861-93d5-68bf71423c8b` | `ad58477d-08a5-40b1-b36a-0417ec785185` | `e0:19:95:98:eb:88` | `192.168.53.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 86 | `lrp-router-port_39569c73-80df-40ac-ad18-7423d9cfb292` | `74fe2778-f060-4418-b371-8a6e6199ae71` | `e0:19:95:0a:05:d1` | `192.168.51.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 87 | `lrp-router-port_80f5715e-6fd6-4de3-9899-17770493824a` | `e25a3ec5-ca19-485d-b470-bb433fd33839` | `e0:19:95:f9:a3:97` | `192.168.91.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 88 | `lrp-router-port_6d7bd89d-5a0f-431e-84a4-309187eb3f7b` | `e78d4932-9bda-4ca8-b4cc-cc18cd794874` | `e0:19:95:1a:ca:99` | `192.168.38.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 89 | `lrp-router-port_dfc48fc2-f9a8-4586-bfec-4cd162977bfd` | `f320ef75-25f1-4be0-b536-8f908aac2ca7` | `e0:19:95:9c:71:23` | `192.168.62.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 90 | `lrp-router-port_52c2face-3b8d-477b-8b84-fa721e061794` | `2f0936bd-85b6-4aaf-b5f5-f83ddb39ed6f` | `e0:19:95:e9:10:ae` | `192.168.37.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 91 | `lrp-router-port_f472f5ad-5429-4b29-8044-19347c60d356` | `62c1baba-d3f6-4530-b641-5eb139002dcb` | `e0:19:95:aa:f8:6e` | `192.168.10.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 92 | `lrp-router-port_262750bb-7def-46a5-acd0-cd35df02f331` | `ea3d5522-6198-46eb-b726-65399892d456` | `e0:19:95:d6:98:39` | `192.168.82.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 93 | `lrp-router-port_cf479cc5-632e-4c40-ae45-4c316472ab1e` | `e546c7b3-705c-41ee-b74b-144bb62fcaa9` | `e0:19:95:19:f3:7f` | `192.168.79.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 94 | `lrp-router-port_fcd16e74-c7c6-4617-91f8-9d0bbc6aec9c` | `5e7e50b5-37df-4fdd-b750-5c3d337ecf41` | `e0:19:95:87:91:8d` | `192.168.85.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 95 | `lrp-router-port_133a16f9-8bc5-4d93-b4c3-b904e5104e8b` | `d41b831a-7dcf-418c-b823-b073717cf637` | `e0:19:95:2b:ee:2c` | `192.168.5.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 96 | `lrp-router-port_e89aafa4-4e4a-4f4e-a6c9-e41f1c13093d` | `5b641834-09cb-4f95-b832-4aac462a0c06` | `e0:19:95:60:b8:6f` | `192.168.50.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 97 | `lrp-router-port_e1e88e81-2f03-4004-b335-7db74953710d` | `b5500489-42ba-486d-b8cf-ef4360c6ad48` | `e0:19:95:46:16:b8` | `192.168.25.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 98 | `lrp-router-port_45329ac7-c80e-4968-9e81-1e8cc9e08d1b` | `6c0e10d5-cb00-4de2-b8e8-5ab4b2e4c4da` | `e0:19:95:06:43:d8` | `192.168.12.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 99 | `lrp-router-port_389a4d77-cf3f-48eb-98e2-ab825f6f637d` | `e85f8874-aef6-43d6-b989-e5fcb2c2dbdd` | `e0:19:95:87:cf:c0` | `192.168.35.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 100 | `lrp-router-port_450b41f1-6e7d-460d-a4fa-08aaa5673156` | `e373c0ab-453a-4c25-ba30-bf13c39471bf` | `e0:19:95:8e:3c:88` | `192.168.54.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 101 | `lrp-router-port_36add0c8-c730-4664-9aad-2da692db4a87` | `58760282-7056-40c7-bbbf-d94c6ced3dab` | `e0:19:95:0c:11:e7` | `192.168.23.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 102 | `lrp-router-port_bd6f114b-6dcd-4aae-8d1f-6c3a3058eeec` | `6a925c33-f0e9-4483-bdee-0a7fc9d3430a` | `e0:19:95:ef:4e:1c` | `192.168.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 103 | `lrp-router-port_fcf0b04e-dc57-4d88-accc-baf335985908` | `59e1f0f8-5c0e-4f15-bf9a-536db8005224` | `e0:19:95:b4:28:df` | `192.168.3.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 104 | `lrp-router-port_dc090365-4e0b-40cb-8b74-1f2c7fd6928b` | `744cff50-e538-4410-bfe1-308f13a52642` | `e0:19:95:78:cb:43` | `192.168.75.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `df8dadd4-7138-4ea7-95da-15fab0b6838c`

```json
{
  "ls_uuid": "df8dadd4-7138-4ea7-95da-15fab0b6838c",
  "name": "gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
  "transit": true,
  "localnet": false,
  "datapath_uuid": "8ba15c30-c06f-4057-9b02-17415e5b45cd",
  "tunnel_key": 13,
  "other_config": {},
  "external_ids": {
    "neutron:network_name": "gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343"
  },
  "ports": [
    {
      "lsp_uuid": "2e5f3f25-7a44-4e2d-8837-ec9ee315a26b",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "4d5e629c-a83e-49b6-a2df-e672399326b1",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "51e2887a-f678-466c-bee8-7a80e658e3d2",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 3
    }
  ]
}
```

Path LSPs — 3 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `2e5f3f25-7a44-4e2d-8837-ec9ee315a26b` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `4d5e629c-a83e-49b6-a2df-e672399326b1` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 3 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` | `51e2887a-f678-466c-bee8-7a80e658e3d2` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` uuid `edba0385-d5d3-4d07-8ca5-f9253e4af298`

```json
{
  "lr_uuid": "edba0385-d5d3-4d07-8ca5-f9253e4af298",
  "name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
  "has_nat": true,
  "datapath_uuid": "471c4d36-6dbb-49ed-8ff4-c4552d7a57a0",
  "tunnel_key": 33,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1"
  },
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `b3f1099a-b8ad-4bbe-962f-05cc5b4a3511` | `e0:19:95:9b:58:bb` | `10.116.246.55/18` | `` | yes | `4ed92972-5ec0-4c25-893d-6d5ef42551c7` |
| 2 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `5d3e7d2c-6a4f-4f15-ac5d-f698ccb2162d` | `e0:19:95:60:29:5b` | `169.254.2.101/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Router (standby scale-out) `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` uuid `f75fea9a-563e-474b-bdc0-08683ebd3842`

```json
{
  "lr_uuid": "f75fea9a-563e-474b-bdc0-08683ebd3842",
  "name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
  "datapath_uuid": "83526036-f5b1-463f-a72d-2363389bf512",
  "tunnel_key": 63,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0"
  },
  "ext_mac": "e0:19:95:c0:b3:04",
  "ext_cidr": "10.116.246.54/18",
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` | `02a3eba2-e737-4eb0-85f6-2e7d203b7aaf` | `e0:19:95:8d:49:e8` | `169.254.2.100/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26` | `f0923e0b-40f2-49f3-bf4e-8dab34f0fb23` | `e0:19:95:c0:b3:04` | `10.116.246.54/18` | `` | yes | `86d08eb2-d621-441e-bf3b-2cfb6e6d7595` |

##### Switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` uuid `43a3a38a-89e1-4410-8101-b255757c2f28`

```json
{
  "ls_uuid": "43a3a38a-89e1-4410-8101-b255757c2f28",
  "name": "network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a",
  "transit": false,
  "localnet": true,
  "datapath_uuid": "068f23c5-b151-4b7c-b29e-3693db43765a",
  "tunnel_key": 10105,
  "other_config": {
    "fdb_age_threshold": "300",
    "requested-tnl-key": "10105",
    "use-gateway-chassis": "true",
    "use-redirect-chassis": "true"
  },
  "external_ids": {
    "neutron:network_name": "network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"
  },
  "ports": [
    {
      "lsp_uuid": "f4fa863b-5594-45be-a7cc-5bf9f28a9ecd",
      "name": "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a",
      "type": "localnet",
      "mac": "",
      "ip": "",
      "addresses": [
        "unknown"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "b22162c5-e587-4890-8085-b76d293a76c2",
      "name": "ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 28
    },
    {
      "lsp_uuid": "04e3b382-2f5f-4040-8091-1e4312a40a4f",
      "name": "ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 36
    },
    {
      "lsp_uuid": "c2de99be-11a5-457f-8183-98226ad847ac",
      "name": "ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 57
    },
    {
      "lsp_uuid": "4405e7a2-e8a0-465f-8294-297c70606aae",
      "name": "ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 79
    },
    {
      "lsp_uuid": "4d199482-a59a-4e4a-8319-05e195ff321e",
      "name": "ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 72
    },
    {
      "lsp_uuid": "c4a2cf30-8309-4d49-8361-e2e488037ee6",
      "name": "ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 30
    },
    {
      "lsp_uuid": "c085d386-f0c8-4b7b-83c1-8a35a4a546f8",
      "name": "ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 101
    },
    {
      "lsp_uuid": "0e61cbbd-aab6-4884-83cf-2e78724f9b54",
      "name": "ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 40
    },
    {
      "lsp_uuid": "78aea322-f9b1-40af-8408-da0bed1cf133",
      "name": "ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 118
    },
    {
      "lsp_uuid": "82292c3d-d065-4e85-84ad-979b6cacac59",
      "name": "ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 10
    },
    {
      "lsp_uuid": "6cb9a15f-bd36-4b1b-84cb-700c64ab9f56",
      "name": "ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 32
    },
    {
      "lsp_uuid": "ab267d54-5904-4713-8537-ab044945cfc5",
      "name": "ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 113
    },
    {
      "lsp_uuid": "8158cd47-c722-46b3-854f-06c445d7d8f9",
      "name": "ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 83
    },
    {
      "lsp_uuid": "4455ba8e-a13a-4d92-856c-de3eb1e78a7d",
      "name": "ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 37
    },
    {
      "lsp_uuid": "9d5868fc-7ea8-407e-858e-cfed2707ad63",
      "name": "ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 112
    },
    {
      "lsp_uuid": "20f58a10-33ec-4de6-85bb-36165bfc4622",
      "name": "ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 20
    },
    {
      "lsp_uuid": "201b4c49-cd0a-4412-85cc-521bbb2f860d",
      "name": "ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 107
    },
    {
      "lsp_uuid": "99412605-21cd-4892-86a4-5176e78a7d2e",
      "name": "ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 33
    },
    {
      "lsp_uuid": "989e51e7-eaed-4cae-86eb-45d724d3ab4f",
      "name": "ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 49
    },
    {
      "lsp_uuid": "df4fe3e0-e864-4114-87e3-ab12c486461a",
      "name": "ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 120
    },
    {
      "lsp_uuid": "f43ea2e5-5f44-4199-8840-e49673530166",
      "name": "ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 51
    },
    {
      "lsp_uuid": "90088652-0ea3-46a5-8846-ee27f8322692",
      "name": "ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 105
    },
    {
      "lsp_uuid": "989f439e-ec40-4416-88e5-ec3aa44722c6",
      "name": "ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 103
    },
    {
      "lsp_uuid": "d6070400-dd17-4543-8926-fb3b1729f868",
      "name": "ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 50
    },
    {
      "lsp_uuid": "18bb547a-b8b1-4558-89d9-6b6a49014507",
      "name": "ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 106
    },
    {
      "lsp_uuid": "1583fc95-52a4-4160-8a3c-089dcb460db5",
      "name": "ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 54
    },
    {
      "lsp_uuid": "927dcc8b-a1f8-4da3-8bba-ec1b7de03407",
      "name": "ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 115
    },
    {
      "lsp_uuid": "36b08d86-9914-40fd-8bd8-3f2e7d998e25",
      "name": "ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 109
    },
    {
      "lsp_uuid": "1a3dfddd-497b-44d9-8d45-ffa6ffa9988c",
      "name": "ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 38
    },
    {
      "lsp_uuid": "66f4083d-010d-44bf-8d6c-39b30e075809",
      "name": "ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 5
    },
    {
      "lsp_uuid": "5d524534-92c4-475e-8df3-3b7087fe7b49",
      "name": "ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 61
    },
    {
      "lsp_uuid": "0d71ba7f-6a19-4cbe-8e95-2509fbc1e400",
      "name": "ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 74
    },
    {
      "lsp_uuid": "153ebc0e-92cf-4790-8eb9-52a23c0f98a1",
      "name": "ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5",
      "peer": "",
      "chassis_uuid": "2c14a1d7-8966-454c-add0-780ff2eb9e58",
      "hostname": "zadkiel04-2",
      "pb_tunnel_key": 22
    },
    {
      "lsp_uuid": "60b76970-d858-450a-8f25-32380ebc3395",
      "name": "ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 73
    },
    {
      "lsp_uuid": "e1a8e74b-a9db-455b-8f81-3b9717b6bdee",
      "name": "ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 58
    },
    {
      "lsp_uuid": "43331636-bf61-4f97-8fc9-96db066395dd",
      "name": "ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 42
    },
    {
      "lsp_uuid": "fe0ac9dc-0cc9-4604-90f4-20b749b552b1",
      "name": "ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 13
    },
    {
      "lsp_uuid": "e3ac9ca1-79c0-4d62-9202-5939fb359621",
      "name": "ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 29
    },
    {
      "lsp_uuid": "39e2d9a5-5b25-41b3-9241-11d065edaf58",
      "name": "ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 7
    },
    {
      "lsp_uuid": "0c341497-785b-4c04-929b-2a600d0dc4bd",
      "name": "ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 67
    },
    {
      "lsp_uuid": "d4f2a21c-172c-4b18-9308-cb5e1f51f916",
      "name": "ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 114
    },
    {
      "lsp_uuid": "e6460a46-863e-4eb3-9344-42fc2b298990",
      "name": "ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 27
    },
    {
      "lsp_uuid": "e43fcbec-a601-448d-9476-55b4ded3e871",
      "name": "ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 12
    },
    {
      "lsp_uuid": "27bd606d-2364-40ab-9537-7a9f4e60242c",
      "name": "ext_gw_port_304298e6-167f-4851-8079-de67d33a9012",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_304298e6-167f-4851-8079-de67d33a9012",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 102
    },
    {
      "lsp_uuid": "498c196d-ad22-4cb6-958c-3b7c43a2f4b5",
      "name": "ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 100
    },
    {
      "lsp_uuid": "d6c598db-0c85-452e-9670-776d1a6931b2",
      "name": "ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 121
    },
    {
      "lsp_uuid": "42f5ac1f-f9ba-415c-96ec-4caccf13dbde",
      "name": "ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 8
    },
    {
      "lsp_uuid": "b80685f3-c404-47c0-97de-4a5d277cbf5b",
      "name": "ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 70
    },
    {
      "lsp_uuid": "5c5e854a-ed46-49ef-98a0-5af79bdf16a1",
      "name": "ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 80
    },
    {
      "lsp_uuid": "021a0596-7f84-4e10-9988-056938036b3c",
      "name": "ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 16
    },
    {
      "lsp_uuid": "cff8f4b3-e387-476b-99d4-cedc44009909",
      "name": "ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 63
    },
    {
      "lsp_uuid": "20e8c7a4-8ca3-4208-9a51-6b5f87e9153e",
      "name": "ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 108
    },
    {
      "lsp_uuid": "b14ea735-a041-438c-9b8f-adcdb3ec8563",
      "name": "ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 77
    },
    {
      "lsp_uuid": "8b3826d1-e5c5-40fc-9c4e-4c9fa145813b",
      "name": "ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 17
    },
    {
      "lsp_uuid": "c9a732da-9258-4b46-9c80-0668c7f97895",
      "name": "ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 53
    },
    {
      "lsp_uuid": "3e7ff167-8192-4311-9cd4-7934c1ba62bd",
      "name": "ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 110
    },
    {
      "lsp_uuid": "8bf73314-806e-4676-9dab-efb758415c80",
      "name": "ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 11
    },
    {
      "lsp_uuid": "0adcc2d5-2ea3-4c07-9dc5-ef4a409b0109",
      "name": "ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 14
    },
    {
      "lsp_uuid": "d375a1a7-ffd7-44b6-9e71-157eb283d704",
      "name": "ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 65
    },
    {
      "lsp_uuid": "b170f977-8661-4642-9eca-297d78ae50d4",
      "name": "ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 35
    },
    {
      "lsp_uuid": "66d53fc9-2d9d-4de5-a093-00e34a346eed",
      "name": "ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 48
    },
    {
      "lsp_uuid": "32bb1d65-bd20-49e6-a0c1-180a8da45ea8",
      "name": "ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 24
    },
    {
      "lsp_uuid": "5ffd75ad-5796-4720-a0e3-4ac10529e035",
      "name": "ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 25
    },
    {
      "lsp_uuid": "e27a8b4d-d62d-472d-a14f-04a74712f6b2",
      "name": "ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 45
    },
    {
      "lsp_uuid": "a3537e9d-8e27-47fd-a1f3-3b708eed6e47",
      "name": "ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8",
      "peer": "",
      "chassis_uuid": "2c14a1d7-8966-454c-add0-780ff2eb9e58",
      "hostname": "zadkiel04-2",
      "pb_tunnel_key": 69
    },
    {
      "lsp_uuid": "241cca2e-41fc-4928-a44c-812ff094ddf8",
      "name": "ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 119
    },
    {
      "lsp_uuid": "88ba4c00-ee9e-4992-a4b8-1e48deed3350",
      "name": "ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 111
    },
    {
      "lsp_uuid": "617457c6-34a6-4687-a57d-d40d806a1c30",
      "name": "ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 62
    },
    {
      "lsp_uuid": "bd433961-36a5-44ba-a85a-a64e304b3069",
      "name": "ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 26
    },
    {
      "lsp_uuid": "d2abd2ee-06bd-4339-a8ca-51a4bbe40ff4",
      "name": "ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 116
    },
    {
      "lsp_uuid": "a6e4d0ac-66f7-4340-a964-884b44a27be0",
      "name": "ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 34
    },
    {
      "lsp_uuid": "2b111075-320b-4b57-a9de-7cf6d50ac0f1",
      "name": "ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 60
    },
    {
      "lsp_uuid": "26ea5e49-c7d5-4372-aa2c-1ee0b94f7f89",
      "name": "ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 104
    },
    {
      "lsp_uuid": "80161cf8-9a96-4b68-ab0a-4e2d8723e724",
      "name": "ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 46
    },
    {
      "lsp_uuid": "9d3664d7-13f9-481d-ab80-1692fb8d0d34",
      "name": "ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 15
    },
    {
      "lsp_uuid": "cdff6077-d9d8-4e90-ab9d-56227b2013c0",
      "name": "ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 4
    },
    {
      "lsp_uuid": "1ebad8ae-47f5-4386-abf0-c6b2fad83a5e",
      "name": "ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 6
    },
    {
      "lsp_uuid": "597ee0ed-1b85-4929-ac2c-6fd90946af0f",
      "name": "ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 75
    },
    {
      "lsp_uuid": "91e979fd-c82a-410c-aed0-694cf5fe4131",
      "name": "ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 117
    },
    {
      "lsp_uuid": "74ed9666-a7be-4d79-b110-80363b9ee5a8",
      "name": "ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 18
    },
    {
      "lsp_uuid": "fd67c739-b765-41c5-b177-209180c441fa",
      "name": "ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 3
    },
    {
      "lsp_uuid": "9ffbc63e-e6bd-40f0-b231-3eef6a634103",
      "name": "ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 84
    },
    {
      "lsp_uuid": "5eb5fc46-ebeb-4f44-b26f-faace424d0ad",
      "name": "ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 68
    },
    {
      "lsp_uuid": "9ba85068-2be3-4923-b3ce-1472a8a26f2b",
      "name": "ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 9
    },
    {
      "lsp_uuid": "4101c6f5-65a8-497c-b532-a0d6ec411bca",
      "name": "ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 52
    },
    {
      "lsp_uuid": "f2bad144-e0bb-4c43-b583-876d3080e7e6",
      "name": "ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 47
    },
    {
      "lsp_uuid": "7b5172c3-0539-4d1e-b5dc-614f3822ed02",
      "name": "ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 23
    },
    {
      "lsp_uuid": "b42ba710-d879-4c62-b755-28fab485a81e",
      "name": "ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 56
    },
    {
      "lsp_uuid": "edb66f57-a291-429b-b92d-4d064fbf6dd7",
      "name": "ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 59
    },
    {
      "lsp_uuid": "e6f40ce8-4bc8-47fb-b968-2d59a7d24b4a",
      "name": "ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 19
    },
    {
      "lsp_uuid": "90b97bb3-81e7-44e9-bb7a-ff26220a911e",
      "name": "ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 76
    },
    {
      "lsp_uuid": "58597c91-a41b-42e5-bcb4-e95dc760c6cb",
      "name": "ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 44
    },
    {
      "lsp_uuid": "ec6b0017-7cd4-4ad4-bd63-7cc7bb43af37",
      "name": "ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 31
    },
    {
      "lsp_uuid": "c753a8a3-9628-4c23-bd9c-f91732baa7eb",
      "name": "ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 43
    },
    {
      "lsp_uuid": "17c4e3d1-2ef2-4d7a-be2e-84d46f895f0b",
      "name": "ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 55
    },
    {
      "lsp_uuid": "e4f00edb-4fd5-4afd-be64-a16ab449a4db",
      "name": "ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 39
    },
    {
      "lsp_uuid": "1bd77ae1-06de-4cab-be8d-8a5c02067341",
      "name": "ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "d1571ad3-856f-406b-bef4-0defdd0874d8",
      "name": "ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 64
    },
    {
      "lsp_uuid": "34d56a59-83c0-4859-bf26-3bc428958697",
      "name": "ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 21
    },
    {
      "lsp_uuid": "1ab98f2a-f5ac-42b8-bfaa-543ce76a1a82",
      "name": "ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 41
    }
  ]
}
```

Path LSPs — 101 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | localnet | `localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` | `f4fa863b-5594-45be-a7cc-5bf9f28a9ecd` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075` | `b22162c5-e587-4890-8085-b76d293a76c2` | `` | `` | `spymaster01-3` |
| 3 | router | `ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141` | `04e3b382-2f5f-4040-8091-1e4312a40a4f` | `` | `` | `flashfire01-3` |
| 4 | router | `ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8` | `c2de99be-11a5-457f-8183-98226ad847ac` | `` | `` | `spymaster01-1` |
| 5 | router | `ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769` | `4405e7a2-e8a0-465f-8294-297c70606aae` | `` | `` | `spymaster01-4` |
| 6 | router | `ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11` | `4d199482-a59a-4e4a-8319-05e195ff321e` | `` | `` | `spymaster01-2` |
| 7 | router | `ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93` | `c4a2cf30-8309-4d49-8361-e2e488037ee6` | `` | `` | `flashfire01-2` |
| 8 | router | `ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9` | `c085d386-f0c8-4b7b-83c1-8a35a4a546f8` | `` | `` | `spymaster01-4` |
| 9 | router | `ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc` | `0e61cbbd-aab6-4884-83cf-2e78724f9b54` | `` | `` | `flashfire01-2` |
| 10 | router | `ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc` | `78aea322-f9b1-40af-8408-da0bed1cf133` | `` | `` | `flashfire01-3` |
| 11 | router | `ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a` | `82292c3d-d065-4e85-84ad-979b6cacac59` | `` | `` | `flashfire01-3` |
| 12 | router | `ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac` | `6cb9a15f-bd36-4b1b-84cb-700c64ab9f56` | `` | `` | `flashfire02-1` |
| 13 | router | `ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5` | `ab267d54-5904-4713-8537-ab044945cfc5` | `` | `` | `flashfire02-1` |
| 14 | router | `ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a` | `8158cd47-c722-46b3-854f-06c445d7d8f9` | `` | `` | `flashfire01-2` |
| 15 | router | `ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e` | `4455ba8e-a13a-4d92-856c-de3eb1e78a7d` | `` | `` | `flashfire02-1` |
| 16 | router | `ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb` | `9d5868fc-7ea8-407e-858e-cfed2707ad63` | `` | `` | `spymaster01-3` |
| 17 | router | `ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2` | `20f58a10-33ec-4de6-85bb-36165bfc4622` | `` | `` | `spymaster01-3` |
| 18 | router | `ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2` | `201b4c49-cd0a-4412-85cc-521bbb2f860d` | `` | `` | `flashfire01-1` |
| 19 | router | `ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd` | `99412605-21cd-4892-86a4-5176e78a7d2e` | `` | `` | `flashfire02-4` |
| 20 | router | `ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52` | `989e51e7-eaed-4cae-86eb-45d724d3ab4f` | `` | `` | `flashfire01-2` |
| 21 | router | `ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd` | `df4fe3e0-e864-4114-87e3-ab12c486461a` | `` | `` | `flashfire02-1` |
| 22 | router | `ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c` | `f43ea2e5-5f44-4199-8840-e49673530166` | `` | `` | `flashfire01-1` |
| 23 | router | `ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6` | `90088652-0ea3-46a5-8846-ee27f8322692` | `` | `` | `flashfire02-3` |
| 24 | router | `ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae` | `989f439e-ec40-4416-88e5-ec3aa44722c6` | `` | `` | `flashfire01-2` |
| 25 | router | `ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c` | `d6070400-dd17-4543-8926-fb3b1729f868` | `` | `` | `flashfire02-1` |
| 26 | router | `ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43` | `18bb547a-b8b1-4558-89d9-6b6a49014507` | `` | `` | `flashfire01-2` |
| 27 | router | `ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc` | `1583fc95-52a4-4160-8a3c-089dcb460db5` | `` | `` | `flashfire02-4` |
| 28 | router | `ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15` | `927dcc8b-a1f8-4da3-8bba-ec1b7de03407` | `` | `` | `zadkiel04-3` |
| 29 | router | `ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571` | `36b08d86-9914-40fd-8bd8-3f2e7d998e25` | `` | `` | `spymaster01-3` |
| 30 | router | `ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d` | `1a3dfddd-497b-44d9-8d45-ffa6ffa9988c` | `` | `` | `flashfire02-4` |
| 31 | router | `ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955` | `66f4083d-010d-44bf-8d6c-39b30e075809` | `` | `` | `spymaster01-1` |
| 32 | router | `ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd` | `5d524534-92c4-475e-8df3-3b7087fe7b49` | `` | `` | `flashfire01-1` |
| 33 | router | `ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526` | `0d71ba7f-6a19-4cbe-8e95-2509fbc1e400` | `` | `` | `flashfire01-3` |
| 34 | router | `ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5` | `153ebc0e-92cf-4790-8eb9-52a23c0f98a1` | `` | `` | `zadkiel04-2` |
| 35 | router | `ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b` | `60b76970-d858-450a-8f25-32380ebc3395` | `` | `` | `flashfire01-1` |
| 36 | router | `ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9` | `e1a8e74b-a9db-455b-8f81-3b9717b6bdee` | `` | `` | `flashfire01-2` |
| 37 | router | `ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d` | `43331636-bf61-4f97-8fc9-96db066395dd` | `` | `` | `flashfire01-1` |
| 38 | router | `ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b` | `fe0ac9dc-0cc9-4604-90f4-20b749b552b1` | `` | `` | `flashfire01-1` |
| 39 | router | `ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7` | `e3ac9ca1-79c0-4d62-9202-5939fb359621` | `` | `` | `flashfire02-4` |
| 40 | router | `ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda` | `39e2d9a5-5b25-41b3-9241-11d065edaf58` | `` | `` | `flashfire01-1` |
| 41 | router | `ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b` | `0c341497-785b-4c04-929b-2a600d0dc4bd` | `` | `` | `flashfire02-4` |
| 42 | router | `ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a` | `d4f2a21c-172c-4b18-9308-cb5e1f51f916` | `` | `` | `spymaster01-4` |
| 43 | router | `ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977` | `e6460a46-863e-4eb3-9344-42fc2b298990` | `` | `` | `zadkiel04-3` |
| 44 | router | `ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd` | `e43fcbec-a601-448d-9476-55b4ded3e871` | `` | `` | `flashfire01-1` |
| 45 | router | `ext_gw_port_304298e6-167f-4851-8079-de67d33a9012` | `27bd606d-2364-40ab-9537-7a9f4e60242c` | `` | `` | `flashfire02-1` |
| 46 | router | `ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268` | `498c196d-ad22-4cb6-958c-3b7c43a2f4b5` | `` | `` | `zadkiel04-1` |
| 47 | router | `ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50` | `d6c598db-0c85-452e-9670-776d1a6931b2` | `` | `` | `flashfire01-2` |
| 48 | router | `ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4` | `42f5ac1f-f9ba-415c-96ec-4caccf13dbde` | `` | `` | `spymaster01-3` |
| 49 | router | `ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5` | `b80685f3-c404-47c0-97de-4a5d277cbf5b` | `` | `` | `spymaster01-2` |
| 50 | router | `ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee` | `5c5e854a-ed46-49ef-98a0-5af79bdf16a1` | `` | `` | `flashfire02-3` |
| 51 | router | `ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423` | `021a0596-7f84-4e10-9988-056938036b3c` | `` | `` | `flashfire01-3` |
| 52 | router | `ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3` | `cff8f4b3-e387-476b-99d4-cedc44009909` | `` | `` | `flashfire02-2` |
| 53 | router | `ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7` | `20e8c7a4-8ca3-4208-9a51-6b5f87e9153e` | `` | `` | `spymaster01-4` |
| 54 | router | `ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0` | `b14ea735-a041-438c-9b8f-adcdb3ec8563` | `` | `` | `flashfire02-1` |
| 55 | router | `ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee` | `8b3826d1-e5c5-40fc-9c4e-4c9fa145813b` | `` | `` | `flashfire02-1` |
| 56 | router | `ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4` | `c9a732da-9258-4b46-9c80-0668c7f97895` | `` | `` | `flashfire02-1` |
| 57 | router | `ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1` | `3e7ff167-8192-4311-9cd4-7934c1ba62bd` | `` | `` | `flashfire02-1` |
| 58 | router | `ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b` | `8bf73314-806e-4676-9dab-efb758415c80` | `` | `` | `zadkiel04-3` |
| 59 | router | `ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26` | `0adcc2d5-2ea3-4c07-9dc5-ef4a409b0109` | `` | `` | `flashfire01-2` |
| 60 | router | `ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41` | `d375a1a7-ffd7-44b6-9e71-157eb283d704` | `` | `` | `spymaster01-4` |
| 61 | router | `ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2` | `b170f977-8661-4642-9eca-297d78ae50d4` | `` | `` | `spymaster01-1` |
| 62 | router | `ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5` | `66d53fc9-2d9d-4de5-a093-00e34a346eed` | `` | `` | `spymaster01-2` |
| 63 | router | `ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751` | `32bb1d65-bd20-49e6-a0c1-180a8da45ea8` | `` | `` | `spymaster01-4` |
| 64 | router | `ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71` | `5ffd75ad-5796-4720-a0e3-4ac10529e035` | `` | `` | `zadkiel04-1` |
| 65 | router | `ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4` | `e27a8b4d-d62d-472d-a14f-04a74712f6b2` | `` | `` | `flashfire02-3` |
| 66 | router | `ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8` | `a3537e9d-8e27-47fd-a1f3-3b708eed6e47` | `` | `` | `zadkiel04-2` |
| 67 | router | `ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d` | `241cca2e-41fc-4928-a44c-812ff094ddf8` | `` | `` | `flashfire01-2` |
| 68 | router | `ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3` | `88ba4c00-ee9e-4992-a4b8-1e48deed3350` | `` | `` | `flashfire01-2` |
| 69 | router | `ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813` | `617457c6-34a6-4687-a57d-d40d806a1c30` | `` | `` | `flashfire02-1` |
| 70 | router | `ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db` | `bd433961-36a5-44ba-a85a-a64e304b3069` | `` | `` | `flashfire02-1` |
| 71 | router | `ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81` | `d2abd2ee-06bd-4339-a8ca-51a4bbe40ff4` | `` | `` | `flashfire02-4` |
| 72 | router | `ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd` | `a6e4d0ac-66f7-4340-a964-884b44a27be0` | `` | `` | `flashfire01-2` |
| 73 | router | `ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509` | `2b111075-320b-4b57-a9de-7cf6d50ac0f1` | `` | `` | `flashfire01-1` |
| 74 | router | `ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995` | `26ea5e49-c7d5-4372-aa2c-1ee0b94f7f89` | `` | `` | `spymaster01-4` |
| 75 | router | `ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d` | `80161cf8-9a96-4b68-ab0a-4e2d8723e724` | `` | `` | `flashfire01-2` |
| 76 | router | `ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `9d3664d7-13f9-481d-ab80-1692fb8d0d34` | `` | `` | `zadkiel04-1` |
| 77 | router | `ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475` | `cdff6077-d9d8-4e90-ab9d-56227b2013c0` | `` | `` | `zadkiel04-1` |
| 78 | router | `ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10` | `1ebad8ae-47f5-4386-abf0-c6b2fad83a5e` | `` | `` | `flashfire02-1` |
| 79 | router | `ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6` | `597ee0ed-1b85-4929-ac2c-6fd90946af0f` | `` | `` | `flashfire02-1` |
| 80 | router | `ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252` | `91e979fd-c82a-410c-aed0-694cf5fe4131` | `` | `` | `flashfire01-2` |
| 81 | router | `ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad` | `74ed9666-a7be-4d79-b110-80363b9ee5a8` | `` | `` | `flashfire02-2` |
| 82 | router | `ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856` | `fd67c739-b765-41c5-b177-209180c441fa` | `` | `` | `spymaster01-1` |
| 83 | router | `ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c` | `9ffbc63e-e6bd-40f0-b231-3eef6a634103` | `` | `` | `zadkiel04-1` |
| 84 | router | `ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93` | `5eb5fc46-ebeb-4f44-b26f-faace424d0ad` | `` | `` | `zadkiel04-1` |
| 85 | router | `ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e` | `9ba85068-2be3-4923-b3ce-1472a8a26f2b` | `` | `` | `spymaster01-2` |
| 86 | router | `ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb` | `4101c6f5-65a8-497c-b532-a0d6ec411bca` | `` | `` | `flashfire01-1` |
| 87 | router | `ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `f2bad144-e0bb-4c43-b583-876d3080e7e6` | `` | `` | `zadkiel04-3` |
| 88 | router | `ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7` | `7b5172c3-0539-4d1e-b5dc-614f3822ed02` | `` | `` | `flashfire01-2` |
| 89 | router | `ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349` | `b42ba710-d879-4c62-b755-28fab485a81e` | `` | `` | `flashfire01-2` |
| 90 | router | `ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f` | `edb66f57-a291-429b-b92d-4d064fbf6dd7` | `` | `` | `spymaster01-1` |
| 91 | router | `ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91` | `e6f40ce8-4bc8-47fb-b968-2d59a7d24b4a` | `` | `` | `flashfire02-1` |
| 92 | router | `ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458` | `90b97bb3-81e7-44e9-bb7a-ff26220a911e` | `` | `` | `flashfire01-2` |
| 93 | router | `ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0` | `58597c91-a41b-42e5-bcb4-e95dc760c6cb` | `` | `` | `flashfire02-1` |
| 94 | router | `ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3` | `ec6b0017-7cd4-4ad4-bd63-7cc7bb43af37` | `` | `` | `zadkiel04-1` |
| 95 | router | `ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79` | `c753a8a3-9628-4c23-bd9c-f91732baa7eb` | `` | `` | `flashfire02-2` |
| 96 | router | `ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d` | `17c4e3d1-2ef2-4d7a-be2e-84d46f895f0b` | `` | `` | `flashfire02-1` |
| 97 | router | `ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738` | `e4f00edb-4fd5-4afd-be64-a16ab449a4db` | `` | `` | `flashfire01-3` |
| 98 | router | `ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97` | `1bd77ae1-06de-4cab-be8d-8a5c02067341` | `` | `` | `spymaster01-3` |
| 99 | router | `ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c` | `d1571ad3-856f-406b-bef4-0defdd0874d8` | `` | `` | `spymaster01-2` |
| 100 | router | `ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8` | `34d56a59-83c0-4859-bf26-3bc428958697` | `` | `` | `flashfire01-1` |
| 101 | router | `ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f` | `1ab98f2a-f5ac-42b8-bfaa-543ce76a1a82` | `` | `` | `flashfire02-4` |

##### Router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` uuid `6572681a-8ffe-4fba-9263-8501622d7726`

```json
{
  "lr_uuid": "6572681a-8ffe-4fba-9263-8501622d7726",
  "name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
  "has_nat": true,
  "datapath_uuid": "5dbeea18-4571-4439-a5a7-f334ae8c699c",
  "tunnel_key": 105,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0"
  },
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `50e071f0-0ec8-4532-9132-241a776b2cde` | `e0:19:95:87:06:3b` | `169.254.2.100/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `9cc5a260-0c66-43b8-95be-0f18815bdda2` | `e0:19:95:14:17:37` | `10.116.246.47/18` | `` | yes | `b74195ce-8332-4bca-8057-10dc9c20cc30` |

##### Router (standby scale-out) `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` uuid `ce75ff4c-456e-4154-bab4-add0f3c5401f`

```json
{
  "lr_uuid": "ce75ff4c-456e-4154-bab4-add0f3c5401f",
  "name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
  "datapath_uuid": "343cd570-3b2c-4f79-a87f-81e7d877e697",
  "tunnel_key": 154,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1"
  },
  "ext_mac": "e0:19:95:5b:76:31",
  "ext_cidr": "10.116.246.48/18",
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d` | `7d613d5f-98e1-4cd8-9d33-21bf9b9e30b9` | `e0:19:95:5b:76:31` | `10.116.246.48/18` | `` | yes | `8c9aaafe-1bc2-43d0-af84-ec1e3c4f6d2c` |
| 2 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` | `6d52f0b1-a274-40c1-ba60-9c15ea3eddd0` | `e0:19:95:4b:de:17` | `169.254.2.101/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `f7e6f4bb-0dfd-40a3-8023-270912e79985`

```json
{
  "ls_uuid": "f7e6f4bb-0dfd-40a3-8023-270912e79985",
  "name": "gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
  "transit": true,
  "localnet": false,
  "datapath_uuid": "142ae345-5743-4655-b32e-857596482fb5",
  "tunnel_key": 45,
  "other_config": {},
  "external_ids": {
    "neutron:network_name": "gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68"
  },
  "ports": [
    {
      "lsp_uuid": "69cb04a8-f3af-49c9-91da-856e0e850c52",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "18a748dc-09a5-42c5-9816-c6cb1f2a48a9",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "560df029-b486-43c8-b6bf-8efb33209f1c",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 3
    }
  ]
}
```

Path LSPs — 3 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `69cb04a8-f3af-49c9-91da-856e0e850c52` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `18a748dc-09a5-42c5-9816-c6cb1f2a48a9` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 3 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` | `560df029-b486-43c8-b6bf-8efb33209f1c` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `a27e38bd-6c57-472f-80df-1a39723efe1a`

```json
{
  "lr_uuid": "a27e38bd-6c57-472f-80df-1a39723efe1a",
  "name": "router_818b2c20-4d1b-40b7-a951-5deb85316e68",
  "has_nat": false,
  "datapath_uuid": "7494f7b0-3a05-40c9-ba1f-8a971b4e99da",
  "tunnel_key": 10124,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400",
    "requested-tnl-key": "10124"
  },
  "external_ids": {
    "neutron:router_name": "router_818b2c20-4d1b-40b7-a951-5deb85316e68"
  },
  "lrp_count": 103
}
```

Every LRP — 103 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-router-port_b0b648a3-fff9-40e9-b453-da9b575d26b2` | `08f05ea5-bff5-4495-800d-36095093d24c` | `e0:19:95:d4:1b:32` | `192.168.90.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-router-port_1b6eb248-5d85-45d1-80b0-bc85aea0d484` | `80506c49-d764-4629-806d-c58bcac7318e` | `e0:19:95:17:7f:52` | `192.168.47.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 3 | `lrp-router-port_5455f7ec-6475-4a62-ab71-dc28807bfb8d` | `f67f6365-f19e-4486-807c-22fdf779c2d7` | `e0:19:95:aa:95:8d` | `192.168.68.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 4 | `lrp-router-port_8cb9eba0-0473-49c4-acc6-d22df0813b16` | `e0538257-f2c6-48c9-807d-d5a767c2b790` | `e0:19:95:96:8b:99` | `192.168.87.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 5 | `lrp-router-port_fdff4156-a468-4b28-b6be-4165566ed91b` | `c4844ccd-957f-46b9-8093-ebed7f9bd7e2` | `e0:19:95:de:08:10` | `192.168.42.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 6 | `lrp-router-port_eaccfc3a-2676-4295-9403-96dc5f703e60` | `22e57219-d429-41ce-80a0-2b6d69e516ef` | `e0:19:95:9d:f8:6f` | `192.168.26.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 7 | `lrp-router-port_81e65b0f-4933-4648-8c05-d72c77d6455e` | `9110b84b-a5b8-4e52-8139-e871bc269f61` | `e0:19:95:da:39:a6` | `192.168.48.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 8 | `lrp-router-port_4b52ccc7-a78b-4768-a784-27e105367c96` | `e8aca05b-f5a9-4ff6-825b-94c78a805651` | `e0:19:95:b5:39:c2` | `192.168.54.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 9 | `lrp-router-port_a824f5f1-d59a-439d-a863-88a82e9f728f` | `3d9ec8aa-f3ed-49b8-84d1-9269d9212033` | `e0:19:95:0e:af:a5` | `192.168.80.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 10 | `lrp-router-port_237161d6-1f23-40b9-9126-41e50710a4aa` | `46f925a5-b43d-416b-8661-f9e0ccffa17d` | `e0:19:95:2c:0f:cc` | `192.168.25.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 11 | `lrp-router-port_a096b3ec-b472-4645-bb77-3889e617df1b` | `ca21d272-5ae2-4c08-86cb-52d43e6b185f` | `e0:19:95:72:d8:9a` | `192.168.28.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 12 | `lrp-router-port_130a0318-7e0d-4433-bc32-f60ebd4a69b6` | `2763f3e5-0336-4dc6-8793-ec7ee4da251f` | `e0:19:95:d9:36:97` | `192.168.38.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 13 | `lrp-router-port_4933d693-021b-4cdd-865b-e03ad35e38bc` | `3fc4095e-3805-4162-887c-71b9eaa90883` | `e0:19:95:76:79:1b` | `192.168.82.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 14 | `lrp-router-port_16454167-c055-409b-a40d-5ceb61fae279` | `8610d9f1-2572-4fc0-890b-100afda5600d` | `e0:19:95:be:a2:71` | `192.168.64.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 15 | `lrp-router-port_958e7d1d-cd00-4ddf-adc9-58bf9ec0616d` | `0545a833-0b59-4c18-8919-5640c7912ecc` | `e0:19:95:21:5d:99` | `192.168.49.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 16 | `lrp-router-port_72e62619-8a96-4f15-bf23-e14f602a7423` | `2ee233dd-4d99-4198-8a29-eacb91aa1bbe` | `e0:19:95:8b:bd:df` | `192.168.17.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 17 | `lrp-router-port_398e6097-726d-4417-8d4e-a5b0e15f3387` | `687af993-8f90-4d57-8a33-42188b111a29` | `e0:19:95:af:e4:55` | `192.168.53.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 18 | `lrp-router-port_09083e0f-1d76-4a6f-aef8-282667aa110e` | `f65ff748-0838-4271-8a68-2706bfdc5284` | `e0:19:95:5d:25:5c` | `192.168.100.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 19 | `lrp-router-port_e65429bf-d32a-4274-8b35-39156398a0bb` | `30427c24-dbca-4f41-8a91-96fbe13afc89` | `e0:19:95:39:80:d0` | `192.168.3.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 20 | `lrp-router-port_ee90ab74-e669-4214-a816-de31615f8f40` | `26b2cd4c-8694-43ed-8b01-9485cf61d758` | `e0:19:95:52:02:d1` | `192.168.18.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 21 | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `62ccf088-8c87-48ec-8b68-4c4a6ccff023` | `e0:19:95:59:9f:05` | `192.168.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 22 | `lrp-router-port_91565e00-afaf-4848-b6c8-aadf55a89177` | `df63142c-e14a-491a-8cb3-37ab3cf5a8dd` | `e0:19:95:89:f9:5f` | `192.168.12.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 23 | `lrp-router-port_bcd3c336-727d-4cff-8741-76b3ab62c5f0` | `a464601b-26ab-4e9c-8cd3-059103a020d2` | `e0:19:95:ee:c5:d6` | `192.168.79.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 24 | `lrp-router-port_b6d9bfd6-dcf4-4ad2-bec7-fdac3c8c0901` | `0648ea03-0536-4291-8d5e-35dbf69e81a6` | `e0:19:95:15:6e:33` | `192.168.6.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 25 | `lrp-router-port_b7bbab8b-6c91-4ba1-86a1-7cbc2862b47a` | `7700a0f7-61bf-49b0-8d92-8deb67cb8fd1` | `e0:19:95:56:68:15` | `192.168.60.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 26 | `lrp-router-port_a6a82a86-eb1c-4ed7-81a0-138e06ac03ed` | `a8a3dfa6-43b8-4c63-8def-129e71303a7a` | `e0:19:95:46:b9:db` | `192.168.10.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 27 | `lrp-router-port_f6ad4655-b1dc-4ac8-92be-fb23f95e6e5c` | `c32f35c9-98f0-4811-8e19-644a4dcb44a7` | `e0:19:95:f8:27:ef` | `192.168.73.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 28 | `lrp-router-port_b156442e-c14c-4cee-bcf9-df780d716265` | `cb322ac4-6a7d-4549-8e23-3c06da773e2f` | `e0:19:95:3e:7f:be` | `192.168.50.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 29 | `lrp-router-port_03c2ec09-65c6-439a-8878-b987580c3924` | `1302f241-0856-4c93-8e2b-7066e870f0db` | `e0:19:95:61:0b:fb` | `192.168.41.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 30 | `lrp-router-port_691b4004-10b5-45ee-bbaa-f455fd574caa` | `df61ba73-10f2-40bf-8ffc-a20007295519` | `e0:19:95:61:46:00` | `192.168.61.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 31 | `lrp-router-port_731e491b-f5c9-4a91-a1fa-e5a623312321` | `8be0edca-af0b-4e9b-90cb-d32e1ea52414` | `e0:19:95:2a:a7:ea` | `192.168.5.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 32 | `lrp-router-port_30af069f-3873-406c-b618-1910068e78f6` | `7ba051ea-2148-438f-9272-f56dc6d42318` | `e0:19:95:88:28:38` | `192.168.31.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 33 | `lrp-router-port_ad47fb2b-5cf5-413b-9c84-708688d9bd34` | `b0abc6ad-db4d-4a8d-93bf-12e86370fb04` | `e0:19:95:6f:cb:8d` | `192.168.4.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 34 | `lrp-router-port_f4227f2b-0e70-4a07-a5f7-85f8ee92d9a4` | `70eafc87-f2b3-44b1-943d-9bc53ac20b02` | `e0:19:95:6a:19:8e` | `192.168.21.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 35 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `6ca4b6f3-615e-440b-9509-f0bae9fa92ae` | `e0:19:95:8d:46:1a` | `169.254.2.20/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 36 | `lrp-router-port_f4954815-1f1b-4f5a-9cb1-fe89ccbfed8a` | `7cd4dd6d-8a60-4f81-9624-672d137594e4` | `e0:19:95:74:a7:99` | `192.168.81.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 37 | `lrp-router-port_6ff10629-2c72-4efb-901d-eac2f09ba7ba` | `69c11b2a-570b-4d3f-9675-e1e410812178` | `e0:19:95:26:86:0b` | `192.168.36.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 38 | `lrp-router-port_58903cc2-b80a-47e0-83b0-c10a12478545` | `bb4efea6-7779-4b61-967f-41210ee092e9` | `e0:19:95:1c:64:43` | `192.168.14.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 39 | `lrp-router-port_de78f2f1-94a3-42b5-8736-68541ff9142a` | `3a86aae5-e8f2-475c-977e-d937826ced86` | `e0:19:95:7e:56:be` | `192.168.63.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 40 | `lrp-router-port_4e3981a3-4f75-439c-a5fa-f5ab9e9a2809` | `c1d9c0b3-f723-4b94-978a-7e6756ec51f9` | `e0:19:95:99:7d:6d` | `192.168.59.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 41 | `lrp-router-port_4f4768cb-67cc-482a-bccb-054c3cb73cd3` | `a00283e9-9d49-4983-97c6-28ba0603962b` | `e0:19:95:5f:be:05` | `192.168.88.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 42 | `lrp-router-port_a2ff46ff-216a-484b-ae3c-fa005b99a422` | `607a43e7-69f2-45a4-97dd-11011f90b70f` | `e0:19:95:84:72:2e` | `192.168.70.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 43 | `lrp-router-port_7b7ecd3c-2b5c-49ca-936f-ab79b67aea63` | `7a6a831c-2458-4b8f-98e1-0288698bb258` | `e0:19:95:21:5f:10` | `192.168.52.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 44 | `lrp-router-port_7b5bb2c4-526f-4300-9d11-338fe4083c58` | `21152ff1-720d-4d32-9a07-2324cf086bff` | `e0:19:95:2a:ff:d3` | `192.168.22.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 45 | `lrp-router-port_4732a674-e2c3-4a32-8b98-8d04ad8981e0` | `17988d81-2928-45a9-9a80-2edf76faaf62` | `e0:19:95:05:43:ed` | `192.168.15.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 46 | `lrp-router-port_a6bdf8cc-6ed7-4989-b7f5-33fd250b3be8` | `0fd2e091-9ee3-4e88-9b8a-3641be17b0fc` | `e0:19:95:f3:3e:cf` | `192.168.45.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 47 | `lrp-router-port_bfdb0087-699f-4cda-968a-c83f5c59a0e3` | `8fe2c5e6-db95-400c-9c57-f7f76badcffc` | `e0:19:95:cf:05:22` | `192.168.74.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 48 | `lrp-router-port_ba2f2f7b-819b-48e8-9873-3a8d03a4ccd8` | `17cd03dc-e2c8-45aa-9ce5-b6d5819d3622` | `e0:19:95:36:d7:11` | `192.168.13.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 49 | `lrp-router-port_dd8bd26a-26ac-4dce-ba1a-b013a8a2eaeb` | `2b95718e-60a7-4d54-9cfb-4dae09bac113` | `e0:19:95:d6:bf:b8` | `192.168.40.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 50 | `lrp-router-port_aaacea27-4b19-408b-b2a8-3ea5e8563bd8` | `43bb7dfe-8d72-45ed-9d40-51665fc9de55` | `e0:19:95:e0:5a:3c` | `192.168.29.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 51 | `lrp-router-port_6056da2d-7903-441e-9bad-f694d7c6efd6` | `7ba29460-8bff-4f6c-9d8e-3288cae7024a` | `e0:19:95:d3:17:89` | `192.168.16.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 52 | `lrp-router-port_8e2c5018-5789-4e8d-a0ca-de2aef90b054` | `4715b57f-cb32-4ffa-9dbf-746dbdcfdb29` | `e0:19:95:c8:9c:48` | `192.168.24.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 53 | `lrp-router-port_8aedd6c8-e897-4611-978e-c968c15eda92` | `9d507d16-5bba-48bf-9f49-1a0db886eaa0` | `e0:19:95:e8:38:9b` | `192.168.86.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 54 | `lrp-router-port_31f2dffa-1a77-4667-9df5-96ddbbb25998` | `46dacec5-595a-4981-9fcb-d02764c53c0b` | `e0:19:95:ad:8e:80` | `192.168.7.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 55 | `lrp-router-port_a26841c2-d315-4598-9d4e-b722e6b0740e` | `80787dc8-89cd-4341-a0b5-c748926d4a56` | `e0:19:95:7e:07:2e` | `192.168.75.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 56 | `lrp-router-port_98b8a929-e141-402b-8abd-cbafab4aad11` | `b75c7fd8-b0ae-4a1a-a0e6-21f49ff45749` | `e0:19:95:a5:0a:df` | `192.168.35.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 57 | `lrp-router-port_b5ac7378-d238-4655-bbcf-21965877290b` | `80fce37e-b24f-4a00-a125-cffc58307756` | `e0:19:95:13:20:17` | `192.168.55.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 58 | `lrp-router-port_ee75b808-37c3-48e3-b951-323cd7ce8623` | `47ca54b7-bfb0-40cd-a13e-61677b2e360d` | `e0:19:95:9a:16:b3` | `192.168.57.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 59 | `lrp-router-port_ec0d7873-0cec-4e0f-b521-fb87d4b8a5a2` | `38be4b24-8dd6-4eee-a183-a7ee1042ec0d` | `e0:19:95:03:46:c3` | `192.168.9.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 60 | `lrp-router-port_cd95a7dd-3a73-4f75-bdb7-cca39a8c349f` | `dc5025e8-2706-4b3c-a184-a5ed191976ab` | `e0:19:95:a6:fd:89` | `192.168.2.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 61 | `lrp-router-port_5536566e-9f0e-4b24-a74a-23b37e1a4cc9` | `1d33b72e-0dac-4485-a48f-620f790d050c` | `e0:19:95:e8:28:e5` | `192.168.92.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 62 | `lrp-router-port_7fa8249e-89c7-436c-b73c-fc1c6c35c8a2` | `9066107c-9159-4ff3-a58d-2400ac332891` | `e0:19:95:cf:3a:72` | `192.168.44.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 63 | `lrp-router-port_a6099d81-d558-4801-a626-e4b67e523609` | `46198781-f26b-4330-a598-842ddd4e3f62` | `e0:19:95:bb:e9:84` | `192.168.89.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 64 | `lrp-router-port_75dc71e6-0677-49f6-a6fc-1aba0dbcd96e` | `964fe22e-17d1-4dbb-a59b-4e4f2f8201c9` | `e0:19:95:98:b3:da` | `192.168.95.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 65 | `lrp-router-port_5f201938-3047-4926-83e7-a2ce47cf5323` | `c8f66473-fd25-44a9-a6ce-6b5bb777763e` | `e0:19:95:10:0e:fc` | `192.168.85.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 66 | `lrp-router-port_a8f4c5b9-8ed3-49c0-95a3-9fd9a367f8d5` | `80c816af-7743-4fd3-a869-f3dc00eb38de` | `e0:19:95:96:eb:72` | `192.168.71.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 67 | `lrp-router-port_d2c5df99-e81d-40e4-98da-6faaf1e56f02` | `ae3b445e-192d-4a9b-a897-4dd32f07fdf8` | `e0:19:95:ac:88:24` | `192.168.253.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 68 | `lrp-router-port_c2884fa3-9c1b-4775-b3f5-1c1d4fa0545a` | `0295ad20-3242-4472-a9d4-fd6cf42e33b9` | `e0:19:95:98:26:10` | `192.168.78.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 69 | `lrp-router-port_91a6ac0f-3bd8-4902-b3b2-b24dc0cbe78c` | `12d04eef-e817-4903-a9f8-2bc3e2b3c9e4` | `e0:19:95:81:1f:2d` | `192.168.34.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 70 | `lrp-router-port_8ffb4745-7439-4c63-8557-ac89ee2a67c1` | `aeb92a2c-61c7-4300-aa08-8de26ed2f7e4` | `e0:19:95:7f:f0:1d` | `192.168.19.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 71 | `lrp-router-port_aef08078-d157-4726-81f9-89a0740b2b75` | `2ed0304e-7c2b-4d6a-aa37-cc7621e8af30` | `e0:19:95:2d:62:4c` | `192.168.56.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 72 | `lrp-router-port_d8fbdfbb-d700-4bb6-acfa-cf2a4496eb77` | `4a59ccaf-922b-43cb-aafd-090a05dc4b53` | `e0:19:95:97:04:00` | `192.168.93.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 73 | `lrp-router-port_c3be4831-ac8f-46c1-b915-e7ff36a141c7` | `7bcb9a50-95b3-482e-ab2f-6028f3f421d9` | `e0:19:95:4f:f7:72` | `192.168.72.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 74 | `lrp-router-port_ae3f429f-f5b2-419b-85d5-7604d80d17be` | `3c4c8ed0-7da4-492c-ab91-e0fe153cd534` | `e0:19:95:f0:0c:48` | `192.168.27.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 75 | `lrp-router-port_26655dc6-20c7-46fc-afa1-6854ebb737b9` | `29dc7752-6e9b-4207-ac16-6ca33d4b3f4c` | `e0:19:95:04:e1:cc` | `192.168.96.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 76 | `lrp-router-port_7adec254-a0fd-4908-a1c8-0a5f43bb0639` | `7256f97c-cc27-4463-ad0f-9ee7b92439fb` | `e0:19:95:3d:d5:df` | `192.168.66.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 77 | `lrp-router-port_7fe3e8df-402c-43a6-9b89-9f2518963842` | `8bfa16d5-6c10-4fc5-aede-f4de5d2a6833` | `e0:19:95:a2:52:2a` | `192.168.20.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 78 | `lrp-router-port_27af2774-c142-4a05-8739-d78d1f02d22e` | `e3980676-46ba-42c0-af1c-4df22f5e4bbf` | `e0:19:95:8a:1e:cf` | `192.168.8.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 79 | `lrp-router-port_d5a053c9-426c-486c-bdd0-fab8ea9febb7` | `f4a72d66-f266-4fd8-b0de-d4802a48a103` | `e0:19:95:5e:56:4e` | `192.168.77.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 80 | `lrp-router-port_b5e6667d-3a04-4a97-8772-bbed3136b58a` | `74f62dd6-fa11-42c1-b122-7979e09219d6` | `e0:19:95:6b:59:f0` | `192.168.51.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 81 | `lrp-router-port_d0d67ec6-bc34-4470-9c4d-ae668c5bf7a2` | `ec6831d8-11cf-4366-b15a-6ac089949ef3` | `e0:19:95:6e:fc:63` | `192.168.99.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 82 | `lrp-router-port_951af33a-3f9c-43df-9489-8295a785bfff` | `08ad9c24-9c42-4a45-b16f-bc75a0f935c5` | `e0:19:95:43:99:15` | `192.168.11.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 83 | `lrp-router-port_0d9118a5-635c-4128-a672-8da5544f07da` | `b2b8b548-bb39-44ca-b179-79e27c6e58f7` | `e0:19:95:7c:cd:aa` | `192.168.97.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 84 | `lrp-router-port_8c51f88f-84a9-4bc6-91a3-d86fba6000eb` | `572f0fa5-86fc-464e-b18c-07e8dc89ace2` | `e0:19:95:0a:7a:ff` | `192.168.67.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 85 | `lrp-router-port_20a2dea6-ce0a-4ed1-a7c2-487f61008c87` | `bbeb457a-5d11-47ae-b1f9-a809e99ae285` | `e0:19:95:3f:16:2e` | `192.168.98.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 86 | `lrp-router-port_e71f71b1-e394-4035-b892-5474f450f7d7` | `c02496ca-0774-4d74-b275-398637b1fa61` | `e0:19:95:b8:2c:ac` | `192.168.84.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 87 | `lrp-router-port_724f58ea-11b2-49b7-96c5-cdc7e540cde1` | `07ca5d3e-ebe0-479e-b45e-56ad0c9127e8` | `e0:19:95:3e:01:ff` | `192.168.37.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 88 | `lrp-router-port_9088b9d8-aea5-4f6f-94f3-ddb503d57c45` | `5aed614b-a6a6-4a26-b497-e6a4cb311cbb` | `e0:19:95:55:b0:34` | `192.168.46.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 89 | `lrp-router-port_d3474aa1-21ac-4614-98b3-9578f293491d` | `9c3e3f20-78ab-4953-b651-3c5c635e86aa` | `e0:19:95:a1:ba:e5` | `192.168.30.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 90 | `lrp-router-port_4da00f14-4b97-492c-98f8-7cdee12d3f89` | `d0015b9e-6b63-4e73-b6cd-35c0a9269fb7` | `e0:19:95:95:ec:2a` | `192.168.69.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 91 | `lrp-router-port_e92240e5-8825-4ecf-aced-98081cbc3483` | `981798f5-ba26-4ee7-b8e9-07963d1ec9d4` | `e0:19:95:5e:e3:54` | `192.168.58.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 92 | `lrp-router-port_86dbbc63-cec8-4f84-b7c4-297def9ce02a` | `a79bf5e9-a0c5-42b6-b9fd-393cb1feb815` | `e0:19:95:45:b7:d4` | `192.168.62.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 93 | `lrp-router-port_2c813b95-2ea6-4ae9-8943-4915dcb03bf1` | `f49a6290-92cc-46e0-ba1e-4ac54a78e934` | `e0:19:95:3e:9b:37` | `192.168.65.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 94 | `lrp-router-port_d12a033b-c4fa-40fe-86d5-59e0204b99df` | `8a92498e-892e-4562-bab1-3199afb61bf3` | `e0:19:95:06:bf:e4` | `192.168.33.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 95 | `lrp-router-port_12116e83-b0e3-4db1-9e07-5da35760bd0a` | `8d49e600-290f-498e-bb15-97f882610cc1` | `e0:19:95:f3:7b:9a` | `192.168.83.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 96 | `lrp-router-port_31d327ab-cdfa-4e6a-bb41-de932541ebb4` | `2ad20d26-f301-40ca-bbac-cb80e6aeec89` | `e0:19:95:fa:6e:92` | `192.168.76.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 97 | `lrp-router-port_47c2c0c7-8697-4c67-bb84-d41d887af480` | `3fd55c58-d434-4757-bc24-73621eeaf972` | `e0:19:95:ba:80:ef` | `192.168.39.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 98 | `lrp-router-port_9ccef8d3-00c6-4419-83b1-f1630f89f70e` | `6cc86baa-cb56-426b-bd1a-007e59cd2cf6` | `e0:19:95:7a:78:e3` | `192.168.91.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 99 | `lrp-router-port_6c0558f1-f3b2-48fc-9770-5f2536efabb9` | `5d76b4df-8d6c-41a7-bd30-ea2599ca0701` | `e0:19:95:d0:ee:21` | `192.168.254.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 100 | `lrp-router-port_19e53512-d5ca-4400-a202-b4ecf350398a` | `cab3c6d6-8a91-41f5-bd3d-19c9fe8453ae` | `e0:19:95:6c:80:d7` | `192.168.94.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 101 | `lrp-router-port_f77b955e-d890-4442-aa17-e54663100cfb` | `104d274c-1180-4c54-bd96-25fa3ef2c320` | `e0:19:95:d8:28:84` | `192.168.23.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 102 | `lrp-router-port_50dd6605-d26f-461a-a825-6a585a416d5e` | `28e83fd2-1890-4872-bf1a-72b50f4daaa2` | `e0:19:95:3e:ea:3f` | `192.168.32.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 103 | `lrp-router-port_d0bbe94e-c02c-4978-a52d-6a1c31468ef9` | `03e2e174-7651-4b49-bf92-4ca90ff66829` | `e0:19:95:3e:c1:b0` | `192.168.43.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` uuid `183da7a8-c33c-4247-912a-d4cb28ec8a5a`

```json
{
  "ls_uuid": "183da7a8-c33c-4247-912a-d4cb28ec8a5a",
  "name": "network_17fe24db-e08b-4f81-969a-e06d6f23b35c",
  "transit": false,
  "localnet": false,
  "datapath_uuid": "82790df2-ba45-4e0e-9536-d37869adfce5",
  "tunnel_key": 11303,
  "other_config": {
    "lb_vip_mac": "e0:19:95:59:9f:05",
    "requested-tnl-key": "11303"
  },
  "external_ids": {
    "neutron:network_name": "network_17fe24db-e08b-4f81-969a-e06d6f23b35c"
  },
  "ports": [
    {
      "lsp_uuid": "22bce434-1ef5-4792-8e57-8fa2a5e3bd71",
      "name": "port_ac6485b2-02b8-492e-84ca-1e4fa3e33360",
      "type": "vif",
      "mac": "50:6b:8d:43:a5:90",
      "ip": "192.168.1.51",
      "addresses": [
        "50:6b:8d:43:a5:90 192.168.1.51"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 25
    },
    {
      "lsp_uuid": "a5fba828-bd28-46fc-bd22-14327aacc2b9",
      "name": "router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    }
  ]
}
```

Path LSPs — 2 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | vif | `port_ac6485b2-02b8-492e-84ca-1e4fa3e33360` | `22bce434-1ef5-4792-8e57-8fa2a5e3bd71` | `50:6b:8d:43:a5:90` | `192.168.1.51` | `spymaster01-2` |
| 2 | router | `router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `a5fba828-bd28-46fc-bd22-14327aacc2b9` | `` | `` | `00000000-0000-0000-0000-000000000000` |


#### Upstream — full from-lport ACL list (leave source NIC) — 23 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $IPs(192.168.254.11/32,192.168.254.122/32,192.168.254.149/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) \|\| (tcp.dst >= 1429 && tcp.dst <= 1438) \|\| (tcp.dst >= 1441 && tcp.dst <= 1450) \|\| (tcp.dst >= 1455 && tcp.dst <= 1464) \|\| (tcp.dst >= 1469 && tcp.dst <= 1478) \|\| (tcp.dst >= 1483 && tcp.dst <= 1492) \|\| (tcp.dst >= 1498 && tcp.dst <= 1507) \|\| (tcp.dst >= 1511 && tcp.dst <= 1520) \|\| (tcp.dst >= 1524 && tcp.dst <= 1533) \|\| (tcp.dst >= 1539 && tcp.dst <= 1548))) \|\| (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) \|\| (udp.dst >= 1429 && udp.dst <= 1438) \|\| (udp.dst >= 1441 && udp.dst <= 1450) \|\| (udp.dst >= 1455 && udp.dst <= 1464) \|\| (udp.dst >= 1469 && udp.dst <= 1478) \|\| (udp.dst >= 1483 && udp.dst <= 1492) \|\| (udp.dst >= 1498 && udp.dst <= 1507) \|\| (udp.dst >= 1511 && udp.dst <= 1520) \|\| (udp.dst >= 1524 && udp.dst <= 1533) \|\| (udp.dst >= 1539 && udp.dst <= 1548))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $outbound_VPC_California_SJ_Pheonix_Customer_1_App_1_dest) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) \|\| (tcp.dst >= 1297 && tcp.dst <= 1306) \|\| (tcp.dst >= 1312 && tcp.dst <= 1321) \|\| (tcp.dst >= 1324 && tcp.dst <= 1333) \|\| (tcp.dst >= 1336 && tcp.dst <= 1345) \|\| (tcp.dst >= 1350 && tcp.dst <= 1359) \|\| (tcp.dst >= 1363 && tcp.dst <= 1372) \|\| (tcp.dst >= 1378 && tcp.dst <= 1387) \|\| (tcp.dst >= 1390 && tcp.dst <= 1399) \|\| (tcp.dst >= 1403 && tcp.dst <= 1412))) \|\| (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) \|\| (udp.dst >= 1297 && udp.dst <= 1306) \|\| (udp.dst >= 1312 && udp.dst <= 1321) \|\| (udp.dst >= 1324 && udp.dst <= 1333) \|\| (udp.dst >= 1336 && udp.dst <= 1345) \|\| (udp.dst >= 1350 && udp.dst <= 1359) \|\| (udp.dst >= 1363 && udp.dst <= 1372) \|\| (udp.dst >= 1378 && udp.dst <= 1387) \|\| (udp.dst >= 1390 && udp.dst <= 1399) \|\| (udp.dst >= 1403 && udp.dst <= 1412))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4` |
| 8 | 1019 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 9 | 1018 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 10 | 1017 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 11 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 12 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip6` |
| 13 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |
| 14 | 1000 | allow | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18` |
| 15 | 100 | **drop** | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"` |
| 16 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 17 | 1060 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 18 | 1052 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 19 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.164,192.168.254.72)) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) \|\| (tcp.dst >= 18646 && tcp.dst <= 18655) \|\| (tcp.dst >= 18661 && tcp.dst <= 18670) \|\| (tcp.dst >= 18673 && tcp.dst <= 18682) \|\| (tcp.dst >= 18685 && tcp.dst <= 18694) \|\| (tcp.dst >= 18699 && tcp.dst <= 18708) \|\| (tcp.dst >= 18712 && tcp.dst <= 18721) \|\| (tcp.dst >= 18725 && tcp.dst <= 18734) \|\| (tcp.dst >= 18737 && tcp.dst <= 18746) \|\| (tcp.dst >= 18751 && tcp.dst <= 18760))) \|\| (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) \|\| (udp.dst >= 18646 && udp.dst <= 18655) \|\| (udp.dst >= 18661 && udp.dst <= 18670) \|\| (udp.dst >= 18673 && udp.dst <= 18682) \|\| (udp.dst >= 18685 && udp.dst <= 18694) \|\| (udp.dst >= 18699 && udp.dst <= 18708) \|\| (udp.dst >= 18712 && udp.dst <= 18721) \|\| (udp.dst >= 18725 && udp.dst <= 18734) \|\| (udp.dst >= 18737 && udp.dst <= 18746) \|\| (udp.dst >= 18751 && udp.dst <= 18760))))` |
| 20 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) \|\| (tcp.dst >= 18779 && tcp.dst <= 18788) \|\| (tcp.dst >= 18794 && tcp.dst <= 18803) \|\| (tcp.dst >= 18809 && tcp.dst <= 18818) \|\| (tcp.dst >= 18821 && tcp.dst <= 18830) \|\| (tcp.dst >= 18833 && tcp.dst <= 18842) \|\| (tcp.dst >= 18847 && tcp.dst <= 18856) \|\| (tcp.dst >= 18860 && tcp.dst <= 18869) \|\| (tcp.dst >= 18874 && tcp.dst <= 18883) \|\| (tcp.dst >= 18888 && tcp.dst <= 18897))) \|\| (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) \|\| (udp.dst >= 18779 && udp.dst <= 18788) \|\| (udp.dst >= 18794 && udp.dst <= 18803) \|\| (udp.dst >= 18809 && udp.dst <= 18818) \|\| (udp.dst >= 18821 && udp.dst <= 18830) \|\| (udp.dst >= 18833 && udp.dst <= 18842) \|\| (udp.dst >= 18847 && udp.dst <= 18856) \|\| (udp.dst >= 18860 && udp.dst <= 18869) \|\| (udp.dst >= 18874 && udp.dst <= 18883) \|\| (udp.dst >= 18888 && udp.dst <= 18897))))` |
| 21 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip6` |
| 22 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4` |
| 23 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — full to-lport ACL list (enter dest NIC) — 23 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $inbound_VPC_California_SJ_Pheonix_Customer_1_App_1_src) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) \|\| (tcp.dst >= 1037 && tcp.dst <= 1046) \|\| (tcp.dst >= 1049 && tcp.dst <= 1058) \|\| (tcp.dst >= 1062 && tcp.dst <= 1071) \|\| (tcp.dst >= 1074 && tcp.dst <= 1083) \|\| (tcp.dst >= 1086 && tcp.dst <= 1095) \|\| (tcp.dst >= 1101 && tcp.dst <= 1110) \|\| (tcp.dst >= 1113 && tcp.dst <= 1122) \|\| (tcp.dst >= 1125 && tcp.dst <= 1134) \|\| (tcp.dst >= 1140 && tcp.dst <= 1149))) \|\| (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) \|\| (udp.dst >= 1037 && udp.dst <= 1046) \|\| (udp.dst >= 1049 && udp.dst <= 1058) \|\| (udp.dst >= 1062 && udp.dst <= 1071) \|\| (udp.dst >= 1074 && udp.dst <= 1083) \|\| (udp.dst >= 1086 && udp.dst <= 1095) \|\| (udp.dst >= 1101 && udp.dst <= 1110) \|\| (udp.dst >= 1113 && udp.dst <= 1122) \|\| (udp.dst >= 1125 && udp.dst <= 1134) \|\| (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.168/32,192.168.254.89/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.129/32,192.168.254.132/32,192.168.254.151/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) \|\| (tcp.dst >= 1166 && tcp.dst <= 1175) \|\| (tcp.dst >= 1181 && tcp.dst <= 1190) \|\| (tcp.dst >= 1193 && tcp.dst <= 1202) \|\| (tcp.dst >= 1205 && tcp.dst <= 1214) \|\| (tcp.dst >= 1218 && tcp.dst <= 1227) \|\| (tcp.dst >= 1230 && tcp.dst <= 1239) \|\| (tcp.dst >= 1242 && tcp.dst <= 1251) \|\| (tcp.dst >= 1257 && tcp.dst <= 1266) \|\| (tcp.dst >= 1271 && tcp.dst <= 1280))) \|\| (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) \|\| (udp.dst >= 1166 && udp.dst <= 1175) \|\| (udp.dst >= 1181 && udp.dst <= 1190) \|\| (udp.dst >= 1193 && udp.dst <= 1202) \|\| (udp.dst >= 1205 && udp.dst <= 1214) \|\| (udp.dst >= 1218 && udp.dst <= 1227) \|\| (udp.dst >= 1230 && udp.dst <= 1239) \|\| (udp.dst >= 1242 && udp.dst <= 1251) \|\| (udp.dst >= 1257 && udp.dst <= 1266) \|\| (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 7 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 8 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 9 | 1019 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 10 | 1018 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 11 | 1017 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(0.0.0.0/1,128.0.0.0/2,192.0.0.0/9+14)) && outport == @AppType/EG_Exclude_Policy1` |
| 12 | 1015 | allow-related | to-lport | pg | `ip4 && outport == @AppType/EG_Exclude_Policy1` |
| 13 | 1015 | allow-related | to-lport | pg | `ip6 && outport == @AppType/EG_Exclude_Policy1` |
| 14 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |
| 15 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 16 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 17 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 18 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.151,192.168.254.221)) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) \|\| (tcp.dst >= 18376 && tcp.dst <= 18385) \|\| (tcp.dst >= 18389 && tcp.dst <= 18398) \|\| (tcp.dst >= 18401 && tcp.dst <= 18410) \|\| (tcp.dst >= 18415 && tcp.dst <= 18424) \|\| (tcp.dst >= 18429 && tcp.dst <= 18438) \|\| (tcp.dst >= 18441 && tcp.dst <= 18450) \|\| (tcp.dst >= 18455 && tcp.dst <= 18464) \|\| (tcp.dst >= 18468 && tcp.dst <= 18477) \|\| (tcp.dst >= 18483 && tcp.dst <= 18492))) \|\| (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) \|\| (udp.dst >= 18376 && udp.dst <= 18385) \|\| (udp.dst >= 18389 && udp.dst <= 18398) \|\| (udp.dst >= 18401 && udp.dst <= 18410) \|\| (udp.dst >= 18415 && udp.dst <= 18424) \|\| (udp.dst >= 18429 && udp.dst <= 18438) \|\| (udp.dst >= 18441 && udp.dst <= 18450) \|\| (udp.dst >= 18455 && udp.dst <= 18464) \|\| (udp.dst >= 18468 && udp.dst <= 18477) \|\| (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 19 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.253.70/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 20 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) \|\| (tcp.dst >= 18512 && tcp.dst <= 18521) \|\| (tcp.dst >= 18524 && tcp.dst <= 18533) \|\| (tcp.dst >= 18537 && tcp.dst <= 18546) \|\| (tcp.dst >= 18551 && tcp.dst <= 18560) \|\| (tcp.dst >= 18564 && tcp.dst <= 18573) \|\| (tcp.dst >= 18576 && tcp.dst <= 18585) \|\| (tcp.dst >= 18590 && tcp.dst <= 18599) \|\| (tcp.dst >= 18603 && tcp.dst <= 18612) \|\| (tcp.dst >= 18618 && tcp.dst <= 18627))) \|\| (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) \|\| (udp.dst >= 18512 && udp.dst <= 18521) \|\| (udp.dst >= 18524 && udp.dst <= 18533) \|\| (udp.dst >= 18537 && udp.dst <= 18546) \|\| (udp.dst >= 18551 && udp.dst <= 18560) \|\| (udp.dst >= 18564 && udp.dst <= 18573) \|\| (udp.dst >= 18576 && udp.dst <= 18585) \|\| (udp.dst >= 18590 && udp.dst <= 18599) \|\| (udp.dst >= 18603 && udp.dst <= 18612) \|\| (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 21 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 22 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 23 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` from-lport (full) — 13 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $IPs(192.168.254.11/32,192.168.254.122/32,192.168.254.149/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) \|\| (tcp.dst >= 1429 && tcp.dst <= 1438) \|\| (tcp.dst >= 1441 && tcp.dst <= 1450) \|\| (tcp.dst >= 1455 && tcp.dst <= 1464) \|\| (tcp.dst >= 1469 && tcp.dst <= 1478) \|\| (tcp.dst >= 1483 && tcp.dst <= 1492) \|\| (tcp.dst >= 1498 && tcp.dst <= 1507) \|\| (tcp.dst >= 1511 && tcp.dst <= 1520) \|\| (tcp.dst >= 1524 && tcp.dst <= 1533) \|\| (tcp.dst >= 1539 && tcp.dst <= 1548))) \|\| (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) \|\| (udp.dst >= 1429 && udp.dst <= 1438) \|\| (udp.dst >= 1441 && udp.dst <= 1450) \|\| (udp.dst >= 1455 && udp.dst <= 1464) \|\| (udp.dst >= 1469 && udp.dst <= 1478) \|\| (udp.dst >= 1483 && udp.dst <= 1492) \|\| (udp.dst >= 1498 && udp.dst <= 1507) \|\| (udp.dst >= 1511 && udp.dst <= 1520) \|\| (udp.dst >= 1524 && udp.dst <= 1533) \|\| (udp.dst >= 1539 && udp.dst <= 1548))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $outbound_VPC_California_SJ_Pheonix_Customer_1_App_1_dest) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) \|\| (tcp.dst >= 1297 && tcp.dst <= 1306) \|\| (tcp.dst >= 1312 && tcp.dst <= 1321) \|\| (tcp.dst >= 1324 && tcp.dst <= 1333) \|\| (tcp.dst >= 1336 && tcp.dst <= 1345) \|\| (tcp.dst >= 1350 && tcp.dst <= 1359) \|\| (tcp.dst >= 1363 && tcp.dst <= 1372) \|\| (tcp.dst >= 1378 && tcp.dst <= 1387) \|\| (tcp.dst >= 1390 && tcp.dst <= 1399) \|\| (tcp.dst >= 1403 && tcp.dst <= 1412))) \|\| (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) \|\| (udp.dst >= 1297 && udp.dst <= 1306) \|\| (udp.dst >= 1312 && udp.dst <= 1321) \|\| (udp.dst >= 1324 && udp.dst <= 1333) \|\| (udp.dst >= 1336 && udp.dst <= 1345) \|\| (udp.dst >= 1350 && udp.dst <= 1359) \|\| (udp.dst >= 1363 && udp.dst <= 1372) \|\| (udp.dst >= 1378 && udp.dst <= 1387) \|\| (udp.dst >= 1390 && udp.dst <= 1399) \|\| (udp.dst >= 1403 && udp.dst <= 1412))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4` |
| 8 | 1019 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 9 | 1018 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 10 | 1017 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 11 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 12 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip6` |
| 13 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` to-lport (full) — 14 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $inbound_VPC_California_SJ_Pheonix_Customer_1_App_1_src) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) \|\| (tcp.dst >= 1037 && tcp.dst <= 1046) \|\| (tcp.dst >= 1049 && tcp.dst <= 1058) \|\| (tcp.dst >= 1062 && tcp.dst <= 1071) \|\| (tcp.dst >= 1074 && tcp.dst <= 1083) \|\| (tcp.dst >= 1086 && tcp.dst <= 1095) \|\| (tcp.dst >= 1101 && tcp.dst <= 1110) \|\| (tcp.dst >= 1113 && tcp.dst <= 1122) \|\| (tcp.dst >= 1125 && tcp.dst <= 1134) \|\| (tcp.dst >= 1140 && tcp.dst <= 1149))) \|\| (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) \|\| (udp.dst >= 1037 && udp.dst <= 1046) \|\| (udp.dst >= 1049 && udp.dst <= 1058) \|\| (udp.dst >= 1062 && udp.dst <= 1071) \|\| (udp.dst >= 1074 && udp.dst <= 1083) \|\| (udp.dst >= 1086 && udp.dst <= 1095) \|\| (udp.dst >= 1101 && udp.dst <= 1110) \|\| (udp.dst >= 1113 && udp.dst <= 1122) \|\| (udp.dst >= 1125 && udp.dst <= 1134) \|\| (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.168/32,192.168.254.89/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.129/32,192.168.254.132/32,192.168.254.151/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) \|\| (tcp.dst >= 1166 && tcp.dst <= 1175) \|\| (tcp.dst >= 1181 && tcp.dst <= 1190) \|\| (tcp.dst >= 1193 && tcp.dst <= 1202) \|\| (tcp.dst >= 1205 && tcp.dst <= 1214) \|\| (tcp.dst >= 1218 && tcp.dst <= 1227) \|\| (tcp.dst >= 1230 && tcp.dst <= 1239) \|\| (tcp.dst >= 1242 && tcp.dst <= 1251) \|\| (tcp.dst >= 1257 && tcp.dst <= 1266) \|\| (tcp.dst >= 1271 && tcp.dst <= 1280))) \|\| (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) \|\| (udp.dst >= 1166 && udp.dst <= 1175) \|\| (udp.dst >= 1181 && udp.dst <= 1190) \|\| (udp.dst >= 1193 && udp.dst <= 1202) \|\| (udp.dst >= 1205 && udp.dst <= 1214) \|\| (udp.dst >= 1218 && udp.dst <= 1227) \|\| (udp.dst >= 1230 && udp.dst <= 1239) \|\| (udp.dst >= 1242 && udp.dst <= 1251) \|\| (udp.dst >= 1257 && udp.dst <= 1266) \|\| (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 7 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 8 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 9 | 1019 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 10 | 1018 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 11 | 1017 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(0.0.0.0/1,128.0.0.0/2,192.0.0.0/9+14)) && outport == @AppType/EG_Exclude_Policy1` |
| 12 | 1015 | allow-related | to-lport | pg | `ip4 && outport == @AppType/EG_Exclude_Policy1` |
| 13 | 1015 | allow-related | to-lport | pg | `ip6 && outport == @AppType/EG_Exclude_Policy1` |
| 14 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` from-lport (full) — 2 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 1000 | allow | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18` |
| 2 | 100 | **drop** | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"` |

#### Upstream — switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` to-lport (full) — 0 rules
(none)

#### Upstream — switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` from-lport (full) — 8 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.164,192.168.254.72)) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) \|\| (tcp.dst >= 18646 && tcp.dst <= 18655) \|\| (tcp.dst >= 18661 && tcp.dst <= 18670) \|\| (tcp.dst >= 18673 && tcp.dst <= 18682) \|\| (tcp.dst >= 18685 && tcp.dst <= 18694) \|\| (tcp.dst >= 18699 && tcp.dst <= 18708) \|\| (tcp.dst >= 18712 && tcp.dst <= 18721) \|\| (tcp.dst >= 18725 && tcp.dst <= 18734) \|\| (tcp.dst >= 18737 && tcp.dst <= 18746) \|\| (tcp.dst >= 18751 && tcp.dst <= 18760))) \|\| (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) \|\| (udp.dst >= 18646 && udp.dst <= 18655) \|\| (udp.dst >= 18661 && udp.dst <= 18670) \|\| (udp.dst >= 18673 && udp.dst <= 18682) \|\| (udp.dst >= 18685 && udp.dst <= 18694) \|\| (udp.dst >= 18699 && udp.dst <= 18708) \|\| (udp.dst >= 18712 && udp.dst <= 18721) \|\| (udp.dst >= 18725 && udp.dst <= 18734) \|\| (udp.dst >= 18737 && udp.dst <= 18746) \|\| (udp.dst >= 18751 && udp.dst <= 18760))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) \|\| (tcp.dst >= 18779 && tcp.dst <= 18788) \|\| (tcp.dst >= 18794 && tcp.dst <= 18803) \|\| (tcp.dst >= 18809 && tcp.dst <= 18818) \|\| (tcp.dst >= 18821 && tcp.dst <= 18830) \|\| (tcp.dst >= 18833 && tcp.dst <= 18842) \|\| (tcp.dst >= 18847 && tcp.dst <= 18856) \|\| (tcp.dst >= 18860 && tcp.dst <= 18869) \|\| (tcp.dst >= 18874 && tcp.dst <= 18883) \|\| (tcp.dst >= 18888 && tcp.dst <= 18897))) \|\| (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) \|\| (udp.dst >= 18779 && udp.dst <= 18788) \|\| (udp.dst >= 18794 && udp.dst <= 18803) \|\| (udp.dst >= 18809 && udp.dst <= 18818) \|\| (udp.dst >= 18821 && udp.dst <= 18830) \|\| (udp.dst >= 18833 && udp.dst <= 18842) \|\| (udp.dst >= 18847 && udp.dst <= 18856) \|\| (udp.dst >= 18860 && udp.dst <= 18869) \|\| (udp.dst >= 18874 && udp.dst <= 18883) \|\| (udp.dst >= 18888 && udp.dst <= 18897))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4` |
| 8 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` to-lport (full) — 9 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.151,192.168.254.221)) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) \|\| (tcp.dst >= 18376 && tcp.dst <= 18385) \|\| (tcp.dst >= 18389 && tcp.dst <= 18398) \|\| (tcp.dst >= 18401 && tcp.dst <= 18410) \|\| (tcp.dst >= 18415 && tcp.dst <= 18424) \|\| (tcp.dst >= 18429 && tcp.dst <= 18438) \|\| (tcp.dst >= 18441 && tcp.dst <= 18450) \|\| (tcp.dst >= 18455 && tcp.dst <= 18464) \|\| (tcp.dst >= 18468 && tcp.dst <= 18477) \|\| (tcp.dst >= 18483 && tcp.dst <= 18492))) \|\| (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) \|\| (udp.dst >= 18376 && udp.dst <= 18385) \|\| (udp.dst >= 18389 && udp.dst <= 18398) \|\| (udp.dst >= 18401 && udp.dst <= 18410) \|\| (udp.dst >= 18415 && udp.dst <= 18424) \|\| (udp.dst >= 18429 && udp.dst <= 18438) \|\| (udp.dst >= 18441 && udp.dst <= 18450) \|\| (udp.dst >= 18455 && udp.dst <= 18464) \|\| (udp.dst >= 18468 && udp.dst <= 18477) \|\| (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.253.70/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) \|\| (tcp.dst >= 18512 && tcp.dst <= 18521) \|\| (tcp.dst >= 18524 && tcp.dst <= 18533) \|\| (tcp.dst >= 18537 && tcp.dst <= 18546) \|\| (tcp.dst >= 18551 && tcp.dst <= 18560) \|\| (tcp.dst >= 18564 && tcp.dst <= 18573) \|\| (tcp.dst >= 18576 && tcp.dst <= 18585) \|\| (tcp.dst >= 18590 && tcp.dst <= 18599) \|\| (tcp.dst >= 18603 && tcp.dst <= 18612) \|\| (tcp.dst >= 18618 && tcp.dst <= 18627))) \|\| (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) \|\| (udp.dst >= 18512 && udp.dst <= 18521) \|\| (udp.dst >= 18524 && udp.dst <= 18533) \|\| (udp.dst >= 18537 && udp.dst <= 18546) \|\| (udp.dst >= 18551 && udp.dst <= 18560) \|\| (udp.dst >= 18564 && udp.dst <= 18573) \|\| (udp.dst >= 18576 && udp.dst <= 18585) \|\| (udp.dst >= 18590 && udp.dst <= 18599) \|\| (udp.dst >= 18603 && udp.dst <= 18612) \|\| (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 7 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 8 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 9 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Upstream — router `router_fc433064-926d-4fc0-a1a3-7c089ad90343`

#### Upstream — NAT on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 0 rows
(none)

#### Upstream — PBR on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 3 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 100 | allow | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 2 | 10 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 3 | 1 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |

#### Upstream — connected routes on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 104 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-router-port_8ca6f7a0-3f82-4de7-911b-f1e92b5ec140` | `192.168.93.1/24` |  |
| 2 | `lrp-router-port_e03534c4-e36c-4067-9f9d-459ce653637d` | `192.168.34.1/24` |  |
| 3 | `lrp-router-port_b4685b3f-31a1-4c96-9b30-a68ae1b0a272` | `192.168.61.1/24` |  |
| 4 | `lrp-router-port_d110f476-68a9-4d94-9911-5fc864464b43` | `192.168.72.1/24` |  |
| 5 | `lrp-router-port_bfbc4008-67c9-476c-966a-cf8465a909e3` | `192.168.45.1/24` |  |
| 6 | `lrp-router-port_a7799f72-bad9-482e-9466-cbcdd59d7625` | `192.168.98.1/24` |  |
| 7 | `lrp-router-port_d4df28ac-20e5-40fe-b659-368c0d4f9698` | `192.168.70.1/24` |  |
| 8 | `lrp-router-port_0c904e1b-e631-4f18-8acb-e3051368d3f9` | `192.168.81.1/24` |  |
| 9 | `lrp-router-port_807ed90e-1fda-497f-9098-7958ef0d4990` | `192.168.4.1/24` |  |
| 10 | `lrp-router-port_c8d975d9-60b0-419c-b56d-f28f9200504f` | `192.168.9.1/24` |  |
| 11 | `lrp-router-port_4bceacc5-ac6e-4008-8e70-97cfd30e5430` | `192.168.32.1/24` |  |
| 12 | `lrp-router-port_8f8336aa-42da-43b7-8757-3997a975a07d` | `192.168.68.1/24` |  |
| 13 | `lrp-router-port_8dcafab3-5338-4114-9eef-0e6fa19605df` | `192.168.99.1/24` |  |
| 14 | `lrp-router-port_9dd293d7-0450-478d-980b-8b5bd08a89cb` | `192.168.87.1/24` |  |
| 15 | `lrp-router-port_4ea3c785-c4a9-498c-80f3-ed2aa55c29d9` | `192.168.11.1/24` |  |
| 16 | `lrp-router-port_c307271a-0a3d-4325-8071-71b873bc3768` | `192.168.100.1/24` |  |
| 17 | `lrp-router-port_fa0c4784-a17e-4b1f-b4ff-220bca5b4cce` | `192.168.14.1/24` |  |
| 18 | `lrp-router-port_e141bb39-f661-4c6f-95cd-63773a7db69d` | `192.168.48.1/24` |  |
| 19 | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `192.168.2.1/24` |  |
| 20 | `lrp-router-port_032fedb1-1e88-4849-bc5d-ad7f358ea600` | `192.168.73.1/24` |  |
| 21 | `lrp-router-port_2c1b4c9d-8fd5-4354-8205-62ef2d28cef8` | `192.168.60.1/24` |  |
| 22 | `lrp-router-port_2dc24931-94e9-439b-986f-7a62a7bf92a1` | `192.168.55.1/24` |  |
| 23 | `lrp-router-port_0743c6fc-5073-425e-9770-ead8c56c42e9` | `192.168.78.1/24` |  |
| 24 | `lrp-router-port_830e914f-389c-4171-a7be-8e0d1f94c96b` | `192.168.33.1/24` |  |
| 25 | `lrp-router-port_d25f3dea-d19d-4c4c-a487-41613ce2eb61` | `192.168.67.1/24` |  |
| 26 | `lrp-router-port_71d41765-890f-4b8d-895b-e82505096413` | `192.168.46.1/24` |  |
| 27 | `lrp-router-port_675f2734-4826-467a-b43e-00698627a259` | `192.168.40.1/24` |  |
| 28 | `lrp-router-port_42ecfffe-0e34-4d14-85f7-5301de17cf69` | `192.168.90.1/24` |  |
| 29 | `lrp-router-port_fa896d0f-b0d0-4fa3-b688-331e9edc2a39` | `192.168.20.1/24` |  |
| 30 | `lrp-router-port_0ba9c57a-57c7-4ef9-8c24-4786c8f54d47` | `192.168.31.1/24` |  |
| 31 | `lrp-router-port_174db21e-8ba1-48eb-beb6-aa4ab68a2305` | `192.168.76.1/24` |  |
| 32 | `lrp-router-port_4bdb92dc-d31e-46fb-89e9-88a99f403c29` | `192.168.57.1/24` |  |
| 33 | `lrp-router-port_ca086587-3fdb-41e7-8571-d01547cece9f` | `192.168.17.1/24` |  |
| 34 | `lrp-router-port_2dac78de-9721-4a5b-8086-4c965dd6c619` | `192.168.27.1/24` |  |
| 35 | `lrp-router-port_dae15e78-0138-406f-9c44-5931c2433eae` | `192.168.253.1/24` |  |
| 36 | `lrp-router-port_f78566a0-d032-4d39-b160-26a846193005` | `192.168.6.1/24` |  |
| 37 | `lrp-router-port_81097727-e648-454a-81df-ae0520caca2c` | `192.168.74.1/24` |  |
| 38 | `lrp-router-port_1358d80d-13be-42f7-ac61-82d076a18135` | `192.168.96.1/24` |  |
| 39 | `lrp-router-port_30c8fe9c-b42a-4e3e-a38a-cc11cb73d1e6` | `192.168.16.1/24` |  |
| 40 | `lrp-router-port_8b6751f8-979a-42f0-b64d-d71fea87beee` | `192.168.19.1/24` |  |
| 41 | `lrp-router-port_2f065e5c-a736-43f7-a8f9-ad969e733b13` | `192.168.8.1/24` |  |
| 42 | `lrp-router-port_0f1f3f44-0fa0-45c4-918d-ac99e0d75e0d` | `192.168.95.1/24` |  |
| 43 | `lrp-router-port_e09f8b78-d094-4bdd-9f6d-18b0d14e50bf` | `192.168.63.1/24` |  |
| 44 | `lrp-router-port_80e90459-8298-4d6c-95bf-9deecc8c48fb` | `192.168.29.1/24` |  |
| 45 | `lrp-router-port_073a0cb1-e7cc-4b24-92f2-9c07ff0ab096` | `192.168.41.1/24` |  |
| 46 | `lrp-router-port_37fb764e-d0fa-457b-a216-43d9b11b3aed` | `192.168.65.1/24` |  |
| 47 | `lrp-router-port_b69e06e1-b184-4390-8cd6-f22044118b16` | `100.64.1.1/24` |  |
| 48 | `lrp-router-port_75e16325-7223-4e38-a44c-a04509f4f777` | `192.168.44.1/24` |  |
| 49 | `lrp-router-port_c0e67438-6eae-42c9-b6f2-6f6e470d4db8` | `192.168.89.1/24` |  |
| 50 | `lrp-router-port_de80667d-6f56-4481-ba8f-14be08b4a8fc` | `192.168.42.1/24` |  |
| 51 | `lrp-router-port_e8a882dc-a636-4b57-ab53-813694611e92` | `192.168.26.1/24` |  |
| 52 | `lrp-router-port_620e1ab8-b44e-4051-97b4-b3e73728664d` | `192.168.30.1/24` |  |
| 53 | `lrp-router-port_6e1383c1-5e63-46ea-b513-416115448c8e` | `192.168.80.1/24` |  |
| 54 | `lrp-router-port_195bf1a1-d7ab-44a9-987b-4e595a4c34e0` | `192.168.58.1/24` |  |
| 55 | `lrp-router-port_e800940d-51e7-42e1-a338-647494e919db` | `192.168.47.1/24` |  |
| 56 | `lrp-router-port_e0002237-57a9-433f-9e82-938599b90a98` | `192.168.83.1/24` |  |
| 57 | `lrp-router-port_48ef8369-ed7d-400a-b84c-c74e67a54347` | `192.168.88.1/24` |  |
| 58 | `lrp-router-port_c275c897-fea0-434c-a9ab-fa02a5af893a` | `192.168.69.1/24` |  |
| 59 | `lrp-router-port_fe749a87-cf4d-42e1-b165-e5551acdb3c3` | `192.168.21.1/24` |  |
| 60 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `169.254.2.20/24` |  |
| 61 | `lrp-router-port_da0d1e4f-cd5e-4d70-b6cb-76c26d3268ef` | `192.168.36.1/24` |  |
| 62 | `lrp-router-port_a42276da-b029-4099-bc9d-c81a6c5c229d` | `192.168.56.1/24` |  |
| 63 | `lrp-router-port_baf0d081-ea93-4077-899d-f7e6dc63f539` | `192.168.59.1/24` |  |
| 64 | `lrp-router-port_ebf08da2-c15c-473b-a1bd-8f5f871ad07a` | `192.168.71.1/24` |  |
| 65 | `lrp-router-port_c5422e1c-4aae-4e5f-9520-936bc881921d` | `192.168.28.1/24` |  |
| 66 | `lrp-router-port_b53ef258-faec-4995-b4e7-d2d4a061ddf2` | `192.168.18.1/24` |  |
| 67 | `lrp-router-port_d5d2d617-49ca-49a7-9665-f89f5ff8d0f2` | `192.168.22.1/24` |  |
| 68 | `lrp-router-port_782ca68a-04b1-4fdc-a822-9d58215f7765` | `192.168.86.1/24` |  |
| 69 | `lrp-router-port_dbf060f4-6528-4cd8-8a68-f32313bb409a` | `192.168.92.1/24` |  |
| 70 | `lrp-router-port_d1624e61-07ee-47a2-9816-691b67ad9a9b` | `192.168.77.1/24` |  |
| 71 | `lrp-router-port_3ea92dc1-e13d-4e44-adad-e2adb944fd31` | `192.168.24.1/24` |  |
| 72 | `lrp-router-port_6c8f9dd7-4e03-4c2c-9fe5-da7eac887606` | `192.168.66.1/24` |  |
| 73 | `lrp-router-port_4124a4e2-3461-47f4-8612-377639eaaf87` | `192.168.64.1/24` |  |
| 74 | `lrp-router-port_3299d3a7-124a-4c43-9ae9-0f798040eae1` | `192.168.49.1/24` |  |
| 75 | `lrp-router-port_93837b6a-1c71-47fe-a427-7b818c6874d7` | `192.168.43.1/24` |  |
| 76 | `lrp-router-port_9ec643a3-96ce-4ad1-b80d-708e8149f79d` | `192.168.15.1/24` |  |
| 77 | `lrp-router-port_3d07fc33-53d7-4f9a-b853-449ef50a2eea` | `192.168.94.1/24` |  |
| 78 | `lrp-router-port_6fef40cb-9010-4464-af83-fa6e75ec0b6d` | `192.168.7.1/24` |  |
| 79 | `lrp-router-port_5fd6becb-db5b-4c6f-bcdd-35e95888cc20` | `192.168.254.1/24` |  |
| 80 | `lrp-router-port_455bebd3-3c1b-4e18-be7b-343d7350e90f` | `192.168.39.1/24` |  |
| 81 | `lrp-router-port_a5627ef6-0b96-4e84-867a-3f257ea3dbf3` | `192.168.97.1/24` |  |
| 82 | `lrp-router-port_88c50715-b1a5-4281-bee9-11dc6671f8ad` | `192.168.84.1/24` |  |
| 83 | `lrp-router-port_96d3605c-fe95-455b-83a6-dd2d3e52373a` | `192.168.52.1/24` |  |
| 84 | `lrp-router-port_ca6a8331-7e2a-4573-987c-4ef24353ee07` | `192.168.13.1/24` |  |
| 85 | `lrp-router-port_865e3efc-d7dc-4861-93d5-68bf71423c8b` | `192.168.53.1/24` |  |
| 86 | `lrp-router-port_39569c73-80df-40ac-ad18-7423d9cfb292` | `192.168.51.1/24` |  |
| 87 | `lrp-router-port_80f5715e-6fd6-4de3-9899-17770493824a` | `192.168.91.1/24` |  |
| 88 | `lrp-router-port_6d7bd89d-5a0f-431e-84a4-309187eb3f7b` | `192.168.38.1/24` |  |
| 89 | `lrp-router-port_dfc48fc2-f9a8-4586-bfec-4cd162977bfd` | `192.168.62.1/24` |  |
| 90 | `lrp-router-port_52c2face-3b8d-477b-8b84-fa721e061794` | `192.168.37.1/24` |  |
| 91 | `lrp-router-port_f472f5ad-5429-4b29-8044-19347c60d356` | `192.168.10.1/24` |  |
| 92 | `lrp-router-port_262750bb-7def-46a5-acd0-cd35df02f331` | `192.168.82.1/24` |  |
| 93 | `lrp-router-port_cf479cc5-632e-4c40-ae45-4c316472ab1e` | `192.168.79.1/24` |  |
| 94 | `lrp-router-port_fcd16e74-c7c6-4617-91f8-9d0bbc6aec9c` | `192.168.85.1/24` |  |
| 95 | `lrp-router-port_133a16f9-8bc5-4d93-b4c3-b904e5104e8b` | `192.168.5.1/24` |  |
| 96 | `lrp-router-port_e89aafa4-4e4a-4f4e-a6c9-e41f1c13093d` | `192.168.50.1/24` |  |
| 97 | `lrp-router-port_e1e88e81-2f03-4004-b335-7db74953710d` | `192.168.25.1/24` |  |
| 98 | `lrp-router-port_45329ac7-c80e-4968-9e81-1e8cc9e08d1b` | `192.168.12.1/24` |  |
| 99 | `lrp-router-port_389a4d77-cf3f-48eb-98e2-ab825f6f637d` | `192.168.35.1/24` |  |
| 100 | `lrp-router-port_450b41f1-6e7d-460d-a4fa-08aaa5673156` | `192.168.54.1/24` |  |
| 101 | `lrp-router-port_36add0c8-c730-4664-9aad-2da692db4a87` | `192.168.23.1/24` |  |
| 102 | `lrp-router-port_bd6f114b-6dcd-4aae-8d1f-6c3a3058eeec` | `192.168.1.1/24` |  |
| 103 | `lrp-router-port_fcf0b04e-dc57-4d88-accc-baf335985908` | `192.168.3.1/24` |  |
| 104 | `lrp-router-port_dc090365-4e0b-40cb-8b74-1f2c7fd6928b` | `192.168.75.1/24` |  |

#### Upstream — static routes on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 2 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `0.0.0.0/0` | `169.254.2.101` | `dst-ip` | `` |
| 2 | `0.0.0.0/0` | `169.254.2.100` | `dst-ip` | `` |

#### Upstream — GW chassis (RC) on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 0 rows
(none)

#### Upstream — path LRPs on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | LR ↔ transit | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `e0:19:95:c9:5b:48` | `169.254.2.20/24` |  |
| 2 | src LS ↔ LR | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `e0:19:95:08:22:c9` | `192.168.2.1/24` |  |

#### Upstream — router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` ext-GW

#### Upstream — NAT on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 105 rows
| # | type | external_ip | logical_ip | logical_port |
|---|------|-------------|------------|--------------|
| 1 | dnat_and_snat | `10.116.246.1` | `192.168.254.168` | `` |
| 2 | dnat_and_snat | `10.116.246.43` | `100.64.1.222` | `` |
| 3 | snat | `10.116.246.55` | `100.64.1.0/24` | `` |
| 4 | snat | `10.116.246.55` | `192.168.1.0/24` | `` |
| 5 | snat | `10.116.246.55` | `192.168.10.0/24` | `` |
| 6 | snat | `10.116.246.55` | `192.168.100.0/24` | `` |
| 7 | snat | `10.116.246.55` | `192.168.11.0/24` | `` |
| 8 | snat | `10.116.246.55` | `192.168.12.0/24` | `` |
| 9 | snat | `10.116.246.55` | `192.168.13.0/24` | `` |
| 10 | snat | `10.116.246.55` | `192.168.14.0/24` | `` |
| 11 | snat | `10.116.246.55` | `192.168.15.0/24` | `` |
| 12 | snat | `10.116.246.55` | `192.168.16.0/24` | `` |
| 13 | snat | `10.116.246.55` | `192.168.17.0/24` | `` |
| 14 | snat | `10.116.246.55` | `192.168.18.0/24` | `` |
| 15 | snat | `10.116.246.55` | `192.168.19.0/24` | `` |
| 16 | snat | `10.116.246.55` | `192.168.2.0/24` | `` |
| 17 | snat | `10.116.246.55` | `192.168.20.0/24` | `` |
| 18 | snat | `10.116.246.55` | `192.168.21.0/24` | `` |
| 19 | snat | `10.116.246.55` | `192.168.22.0/24` | `` |
| 20 | snat | `10.116.246.55` | `192.168.23.0/24` | `` |
| 21 | snat | `10.116.246.55` | `192.168.24.0/24` | `` |
| 22 | snat | `10.116.246.55` | `192.168.25.0/24` | `` |
| 23 | snat | `10.116.246.55` | `192.168.253.0/24` | `` |
| 24 | snat | `10.116.246.55` | `192.168.254.0/24` | `` |
| 25 | snat | `10.116.246.55` | `192.168.26.0/24` | `` |
| 26 | snat | `10.116.246.55` | `192.168.27.0/24` | `` |
| 27 | snat | `10.116.246.55` | `192.168.28.0/24` | `` |
| 28 | snat | `10.116.246.55` | `192.168.29.0/24` | `` |
| 29 | snat | `10.116.246.55` | `192.168.3.0/24` | `` |
| 30 | snat | `10.116.246.55` | `192.168.30.0/24` | `` |
| 31 | snat | `10.116.246.55` | `192.168.31.0/24` | `` |
| 32 | snat | `10.116.246.55` | `192.168.32.0/24` | `` |
| 33 | snat | `10.116.246.55` | `192.168.33.0/24` | `` |
| 34 | snat | `10.116.246.55` | `192.168.34.0/24` | `` |
| 35 | snat | `10.116.246.55` | `192.168.35.0/24` | `` |
| 36 | snat | `10.116.246.55` | `192.168.36.0/24` | `` |
| 37 | snat | `10.116.246.55` | `192.168.37.0/24` | `` |
| 38 | snat | `10.116.246.55` | `192.168.38.0/24` | `` |
| 39 | snat | `10.116.246.55` | `192.168.39.0/24` | `` |
| 40 | snat | `10.116.246.55` | `192.168.4.0/24` | `` |
| 41 | snat | `10.116.246.55` | `192.168.40.0/24` | `` |
| 42 | snat | `10.116.246.55` | `192.168.41.0/24` | `` |
| 43 | snat | `10.116.246.55` | `192.168.42.0/24` | `` |
| 44 | snat | `10.116.246.55` | `192.168.43.0/24` | `` |
| 45 | snat | `10.116.246.55` | `192.168.44.0/24` | `` |
| 46 | snat | `10.116.246.55` | `192.168.45.0/24` | `` |
| 47 | snat | `10.116.246.55` | `192.168.46.0/24` | `` |
| 48 | snat | `10.116.246.55` | `192.168.47.0/24` | `` |
| 49 | snat | `10.116.246.55` | `192.168.48.0/24` | `` |
| 50 | snat | `10.116.246.55` | `192.168.49.0/24` | `` |
| 51 | snat | `10.116.246.55` | `192.168.5.0/24` | `` |
| 52 | snat | `10.116.246.55` | `192.168.50.0/24` | `` |
| 53 | snat | `10.116.246.55` | `192.168.51.0/24` | `` |
| 54 | snat | `10.116.246.55` | `192.168.52.0/24` | `` |
| 55 | snat | `10.116.246.55` | `192.168.53.0/24` | `` |
| 56 | snat | `10.116.246.55` | `192.168.54.0/24` | `` |
| 57 | snat | `10.116.246.55` | `192.168.55.0/24` | `` |
| 58 | snat | `10.116.246.55` | `192.168.56.0/24` | `` |
| 59 | snat | `10.116.246.55` | `192.168.57.0/24` | `` |
| 60 | snat | `10.116.246.55` | `192.168.58.0/24` | `` |
| 61 | snat | `10.116.246.55` | `192.168.59.0/24` | `` |
| 62 | snat | `10.116.246.55` | `192.168.6.0/24` | `` |
| 63 | snat | `10.116.246.55` | `192.168.60.0/24` | `` |
| 64 | snat | `10.116.246.55` | `192.168.61.0/24` | `` |
| 65 | snat | `10.116.246.55` | `192.168.62.0/24` | `` |
| 66 | snat | `10.116.246.55` | `192.168.63.0/24` | `` |
| 67 | snat | `10.116.246.55` | `192.168.64.0/24` | `` |
| 68 | snat | `10.116.246.55` | `192.168.65.0/24` | `` |
| 69 | snat | `10.116.246.55` | `192.168.66.0/24` | `` |
| 70 | snat | `10.116.246.55` | `192.168.67.0/24` | `` |
| 71 | snat | `10.116.246.55` | `192.168.68.0/24` | `` |
| 72 | snat | `10.116.246.55` | `192.168.69.0/24` | `` |
| 73 | snat | `10.116.246.55` | `192.168.7.0/24` | `` |
| 74 | snat | `10.116.246.55` | `192.168.70.0/24` | `` |
| 75 | snat | `10.116.246.55` | `192.168.71.0/24` | `` |
| 76 | snat | `10.116.246.55` | `192.168.72.0/24` | `` |
| 77 | snat | `10.116.246.55` | `192.168.73.0/24` | `` |
| 78 | snat | `10.116.246.55` | `192.168.74.0/24` | `` |
| 79 | snat | `10.116.246.55` | `192.168.75.0/24` | `` |
| 80 | snat | `10.116.246.55` | `192.168.76.0/24` | `` |
| 81 | snat | `10.116.246.55` | `192.168.77.0/24` | `` |
| 82 | snat | `10.116.246.55` | `192.168.78.0/24` | `` |
| 83 | snat | `10.116.246.55` | `192.168.79.0/24` | `` |
| 84 | snat | `10.116.246.55` | `192.168.8.0/24` | `` |
| 85 | snat | `10.116.246.55` | `192.168.80.0/24` | `` |
| 86 | snat | `10.116.246.55` | `192.168.81.0/24` | `` |
| 87 | snat | `10.116.246.55` | `192.168.82.0/24` | `` |
| 88 | snat | `10.116.246.55` | `192.168.83.0/24` | `` |
| 89 | snat | `10.116.246.55` | `192.168.84.0/24` | `` |
| 90 | snat | `10.116.246.55` | `192.168.85.0/24` | `` |
| 91 | snat | `10.116.246.55` | `192.168.86.0/24` | `` |
| 92 | snat | `10.116.246.55` | `192.168.87.0/24` | `` |
| 93 | snat | `10.116.246.55` | `192.168.88.0/24` | `` |
| 94 | snat | `10.116.246.55` | `192.168.89.0/24` | `` |
| 95 | snat | `10.116.246.55` | `192.168.9.0/24` | `` |
| 96 | snat | `10.116.246.55` | `192.168.90.0/24` | `` |
| 97 | snat | `10.116.246.55` | `192.168.91.0/24` | `` |
| 98 | snat | `10.116.246.55` | `192.168.92.0/24` | `` |
| 99 | snat | `10.116.246.55` | `192.168.93.0/24` | `` |
| 100 | snat | `10.116.246.55` | `192.168.94.0/24` | `` |
| 101 | snat | `10.116.246.55` | `192.168.95.0/24` | `` |
| 102 | snat | `10.116.246.55` | `192.168.96.0/24` | `` |
| 103 | snat | `10.116.246.55` | `192.168.97.0/24` | `` |
| 104 | snat | `10.116.246.55` | `192.168.98.0/24` | `` |
| 105 | snat | `10.116.246.55` | `192.168.99.0/24` | `` |

#### Upstream — PBR on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 1 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 1000 | reroute | `ip4.src==100.64.1.6/32` | `169.254.2.100` |

#### Upstream — connected routes on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 2 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `10.116.246.55/18` | yes |
| 2 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `169.254.2.101/24` |  |

#### Upstream — static routes on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 104 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `192.168.49.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 2 | `192.168.65.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 3 | `192.168.4.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 4 | `192.168.59.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 5 | `192.168.78.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 6 | `192.168.254.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 7 | `192.168.98.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 8 | `192.168.28.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 9 | `192.168.16.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 10 | `192.168.84.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 11 | `192.168.25.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 12 | `192.168.39.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 13 | `192.168.12.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 14 | `192.168.81.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 15 | `192.168.91.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 16 | `192.168.43.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 17 | `192.168.42.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 18 | `192.168.40.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 19 | `192.168.86.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 20 | `192.168.64.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 21 | `192.168.67.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 22 | `192.168.13.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 23 | `0.0.0.0/0` | `10.116.192.1` | `dst-ip` | `` |
| 24 | `192.168.8.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 25 | `192.168.46.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 26 | `192.168.253.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 27 | `192.168.44.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 28 | `192.168.21.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 29 | `192.168.100.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 30 | `192.168.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 31 | `192.168.18.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 32 | `192.168.20.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 33 | `192.168.47.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 34 | `100.64.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 35 | `192.168.19.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 36 | `192.168.6.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 37 | `192.168.95.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 38 | `192.168.85.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 39 | `192.168.60.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 40 | `192.168.7.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 41 | `192.168.30.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 42 | `192.168.80.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 43 | `192.168.57.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 44 | `192.168.75.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 45 | `192.168.68.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 46 | `192.168.10.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 47 | `192.168.27.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 48 | `192.168.61.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 49 | `192.168.22.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 50 | `192.168.70.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 51 | `192.168.94.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 52 | `192.168.66.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 53 | `192.168.17.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 54 | `192.168.38.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 55 | `192.168.2.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 56 | `192.168.96.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 57 | `192.168.82.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 58 | `192.168.3.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 59 | `192.168.36.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 60 | `192.168.31.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 61 | `192.168.92.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 62 | `192.168.90.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 63 | `192.168.33.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 64 | `192.168.50.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 65 | `192.168.48.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 66 | `192.168.62.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 67 | `192.168.14.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 68 | `192.168.37.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 69 | `192.168.29.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 70 | `192.168.41.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 71 | `192.168.63.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 72 | `192.168.88.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 73 | `192.168.51.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 74 | `192.168.34.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 75 | `192.168.23.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 76 | `192.168.56.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 77 | `192.168.99.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 78 | `192.168.71.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 79 | `192.168.72.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 80 | `192.168.93.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 81 | `192.168.15.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 82 | `192.168.89.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 83 | `192.168.5.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 84 | `192.168.69.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 85 | `192.168.76.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 86 | `192.168.73.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 87 | `192.168.45.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 88 | `192.168.11.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 89 | `192.168.54.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 90 | `192.168.97.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 91 | `192.168.26.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 92 | `192.168.83.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 93 | `192.168.32.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 94 | `192.168.55.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 95 | `192.168.9.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 96 | `192.168.53.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 97 | `192.168.52.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 98 | `192.168.77.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 99 | `192.168.87.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 100 | `192.168.79.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 101 | `192.168.24.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 102 | `192.168.74.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 103 | `192.168.35.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 104 | `192.168.58.0/24` | `169.254.2.20` | `dst-ip` | `` |

#### Upstream — GW chassis (RC) on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 1 rows
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | active RC | `zadkiel04-1` | `b594f638-f4a0-439b-91d4-1c513f0c4529` | `bb49616e-e5ad-4dd7-9d98-ad529702d2df` | 100 |

#### Upstream — path LRPs on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | GW ↔ external | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `e0:19:95:9b:58:bb` | `10.116.246.55/18` | yes |
| 2 | transit ↔ GW | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `e0:19:95:60:29:5b` | `169.254.2.101/24` |  |

#### Upstream — External GW MAC/IP on `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1`

- LRP `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` MAC `e0:19:95:9b:58:bb` IP `10.116.246.55/18`

#### Upstream — scale-out peer `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` (standby) host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20`

- External GW MAC `e0:19:95:c0:b3:04` IP `10.116.246.54/18`
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | standby scale-out | `flashfire01-2` | `74e0be63-f78f-482a-b04e-a09ada933f20` | `ef355d92-dc3b-4dc4-aaf4-7c559db792d7` | 100 |

#### Upstream — router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` ext-GW

#### Upstream — NAT on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 103 rows
| # | type | external_ip | logical_ip | logical_port |
|---|------|-------------|------------|--------------|
| 1 | dnat_and_snat | `10.116.246.72` | `192.168.253.70` | `` |
| 2 | snat | `10.116.246.47` | `192.168.1.0/24` | `` |
| 3 | snat | `10.116.246.47` | `192.168.10.0/24` | `` |
| 4 | snat | `10.116.246.47` | `192.168.100.0/24` | `` |
| 5 | snat | `10.116.246.47` | `192.168.11.0/24` | `` |
| 6 | snat | `10.116.246.47` | `192.168.12.0/24` | `` |
| 7 | snat | `10.116.246.47` | `192.168.13.0/24` | `` |
| 8 | snat | `10.116.246.47` | `192.168.14.0/24` | `` |
| 9 | snat | `10.116.246.47` | `192.168.15.0/24` | `` |
| 10 | snat | `10.116.246.47` | `192.168.16.0/24` | `` |
| 11 | snat | `10.116.246.47` | `192.168.17.0/24` | `` |
| 12 | snat | `10.116.246.47` | `192.168.18.0/24` | `` |
| 13 | snat | `10.116.246.47` | `192.168.19.0/24` | `` |
| 14 | snat | `10.116.246.47` | `192.168.2.0/24` | `` |
| 15 | snat | `10.116.246.47` | `192.168.20.0/24` | `` |
| 16 | snat | `10.116.246.47` | `192.168.21.0/24` | `` |
| 17 | snat | `10.116.246.47` | `192.168.22.0/24` | `` |
| 18 | snat | `10.116.246.47` | `192.168.23.0/24` | `` |
| 19 | snat | `10.116.246.47` | `192.168.24.0/24` | `` |
| 20 | snat | `10.116.246.47` | `192.168.25.0/24` | `` |
| 21 | snat | `10.116.246.47` | `192.168.253.0/24` | `` |
| 22 | snat | `10.116.246.47` | `192.168.254.0/24` | `` |
| 23 | snat | `10.116.246.47` | `192.168.26.0/24` | `` |
| 24 | snat | `10.116.246.47` | `192.168.27.0/24` | `` |
| 25 | snat | `10.116.246.47` | `192.168.28.0/24` | `` |
| 26 | snat | `10.116.246.47` | `192.168.29.0/24` | `` |
| 27 | snat | `10.116.246.47` | `192.168.3.0/24` | `` |
| 28 | snat | `10.116.246.47` | `192.168.30.0/24` | `` |
| 29 | snat | `10.116.246.47` | `192.168.31.0/24` | `` |
| 30 | snat | `10.116.246.47` | `192.168.32.0/24` | `` |
| 31 | snat | `10.116.246.47` | `192.168.33.0/24` | `` |
| 32 | snat | `10.116.246.47` | `192.168.34.0/24` | `` |
| 33 | snat | `10.116.246.47` | `192.168.35.0/24` | `` |
| 34 | snat | `10.116.246.47` | `192.168.36.0/24` | `` |
| 35 | snat | `10.116.246.47` | `192.168.37.0/24` | `` |
| 36 | snat | `10.116.246.47` | `192.168.38.0/24` | `` |
| 37 | snat | `10.116.246.47` | `192.168.39.0/24` | `` |
| 38 | snat | `10.116.246.47` | `192.168.4.0/24` | `` |
| 39 | snat | `10.116.246.47` | `192.168.40.0/24` | `` |
| 40 | snat | `10.116.246.47` | `192.168.41.0/24` | `` |
| 41 | snat | `10.116.246.47` | `192.168.42.0/24` | `` |
| 42 | snat | `10.116.246.47` | `192.168.43.0/24` | `` |
| 43 | snat | `10.116.246.47` | `192.168.44.0/24` | `` |
| 44 | snat | `10.116.246.47` | `192.168.45.0/24` | `` |
| 45 | snat | `10.116.246.47` | `192.168.46.0/24` | `` |
| 46 | snat | `10.116.246.47` | `192.168.47.0/24` | `` |
| 47 | snat | `10.116.246.47` | `192.168.48.0/24` | `` |
| 48 | snat | `10.116.246.47` | `192.168.49.0/24` | `` |
| 49 | snat | `10.116.246.47` | `192.168.5.0/24` | `` |
| 50 | snat | `10.116.246.47` | `192.168.50.0/24` | `` |
| 51 | snat | `10.116.246.47` | `192.168.51.0/24` | `` |
| 52 | snat | `10.116.246.47` | `192.168.52.0/24` | `` |
| 53 | snat | `10.116.246.47` | `192.168.53.0/24` | `` |
| 54 | snat | `10.116.246.47` | `192.168.54.0/24` | `` |
| 55 | snat | `10.116.246.47` | `192.168.55.0/24` | `` |
| 56 | snat | `10.116.246.47` | `192.168.56.0/24` | `` |
| 57 | snat | `10.116.246.47` | `192.168.57.0/24` | `` |
| 58 | snat | `10.116.246.47` | `192.168.58.0/24` | `` |
| 59 | snat | `10.116.246.47` | `192.168.59.0/24` | `` |
| 60 | snat | `10.116.246.47` | `192.168.6.0/24` | `` |
| 61 | snat | `10.116.246.47` | `192.168.60.0/24` | `` |
| 62 | snat | `10.116.246.47` | `192.168.61.0/24` | `` |
| 63 | snat | `10.116.246.47` | `192.168.62.0/24` | `` |
| 64 | snat | `10.116.246.47` | `192.168.63.0/24` | `` |
| 65 | snat | `10.116.246.47` | `192.168.64.0/24` | `` |
| 66 | snat | `10.116.246.47` | `192.168.65.0/24` | `` |
| 67 | snat | `10.116.246.47` | `192.168.66.0/24` | `` |
| 68 | snat | `10.116.246.47` | `192.168.67.0/24` | `` |
| 69 | snat | `10.116.246.47` | `192.168.68.0/24` | `` |
| 70 | snat | `10.116.246.47` | `192.168.69.0/24` | `` |
| 71 | snat | `10.116.246.47` | `192.168.7.0/24` | `` |
| 72 | snat | `10.116.246.47` | `192.168.70.0/24` | `` |
| 73 | snat | `10.116.246.47` | `192.168.71.0/24` | `` |
| 74 | snat | `10.116.246.47` | `192.168.72.0/24` | `` |
| 75 | snat | `10.116.246.47` | `192.168.73.0/24` | `` |
| 76 | snat | `10.116.246.47` | `192.168.74.0/24` | `` |
| 77 | snat | `10.116.246.47` | `192.168.75.0/24` | `` |
| 78 | snat | `10.116.246.47` | `192.168.76.0/24` | `` |
| 79 | snat | `10.116.246.47` | `192.168.77.0/24` | `` |
| 80 | snat | `10.116.246.47` | `192.168.78.0/24` | `` |
| 81 | snat | `10.116.246.47` | `192.168.79.0/24` | `` |
| 82 | snat | `10.116.246.47` | `192.168.8.0/24` | `` |
| 83 | snat | `10.116.246.47` | `192.168.80.0/24` | `` |
| 84 | snat | `10.116.246.47` | `192.168.81.0/24` | `` |
| 85 | snat | `10.116.246.47` | `192.168.82.0/24` | `` |
| 86 | snat | `10.116.246.47` | `192.168.83.0/24` | `` |
| 87 | snat | `10.116.246.47` | `192.168.84.0/24` | `` |
| 88 | snat | `10.116.246.47` | `192.168.85.0/24` | `` |
| 89 | snat | `10.116.246.47` | `192.168.86.0/24` | `` |
| 90 | snat | `10.116.246.47` | `192.168.87.0/24` | `` |
| 91 | snat | `10.116.246.47` | `192.168.88.0/24` | `` |
| 92 | snat | `10.116.246.47` | `192.168.89.0/24` | `` |
| 93 | snat | `10.116.246.47` | `192.168.9.0/24` | `` |
| 94 | snat | `10.116.246.47` | `192.168.90.0/24` | `` |
| 95 | snat | `10.116.246.47` | `192.168.91.0/24` | `` |
| 96 | snat | `10.116.246.47` | `192.168.92.0/24` | `` |
| 97 | snat | `10.116.246.47` | `192.168.93.0/24` | `` |
| 98 | snat | `10.116.246.47` | `192.168.94.0/24` | `` |
| 99 | snat | `10.116.246.47` | `192.168.95.0/24` | `` |
| 100 | snat | `10.116.246.47` | `192.168.96.0/24` | `` |
| 101 | snat | `10.116.246.47` | `192.168.97.0/24` | `` |
| 102 | snat | `10.116.246.47` | `192.168.98.0/24` | `` |
| 103 | snat | `10.116.246.47` | `192.168.99.0/24` | `` |

#### Upstream — PBR on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 0 rows
(none)

#### Upstream — connected routes on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 2 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `169.254.2.100/24` |  |
| 2 | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `10.116.246.47/18` | yes |

#### Upstream — static routes on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 103 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `192.168.11.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 2 | `192.168.25.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 3 | `192.168.42.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 4 | `192.168.52.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 5 | `192.168.53.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 6 | `192.168.4.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 7 | `192.168.60.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 8 | `192.168.96.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 9 | `192.168.77.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 10 | `192.168.92.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 11 | `192.168.69.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 12 | `192.168.65.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 13 | `192.168.54.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 14 | `192.168.44.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 15 | `192.168.56.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 16 | `192.168.74.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 17 | `192.168.9.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 18 | `192.168.38.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 19 | `192.168.86.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 20 | `192.168.95.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 21 | `192.168.55.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 22 | `192.168.76.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 23 | `192.168.8.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 24 | `192.168.81.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 25 | `192.168.50.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 26 | `192.168.36.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 27 | `192.168.33.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 28 | `192.168.14.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 29 | `192.168.59.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 30 | `192.168.26.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 31 | `192.168.61.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 32 | `192.168.71.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 33 | `192.168.79.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 34 | `192.168.90.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 35 | `192.168.83.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 36 | `192.168.72.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 37 | `192.168.35.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 38 | `192.168.12.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 39 | `192.168.63.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 40 | `192.168.84.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 41 | `192.168.27.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 42 | `192.168.2.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 43 | `192.168.253.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 44 | `192.168.34.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 45 | `192.168.19.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 46 | `192.168.66.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 47 | `192.168.89.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 48 | `192.168.29.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 49 | `192.168.78.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 50 | `192.168.28.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 51 | `192.168.58.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 52 | `192.168.80.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 53 | `192.168.85.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 54 | `192.168.20.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 55 | `192.168.254.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 56 | `192.168.39.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 57 | `192.168.48.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 58 | `192.168.62.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 59 | `192.168.16.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 60 | `192.168.46.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 61 | `192.168.37.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 62 | `0.0.0.0/0` | `10.116.192.1` | `dst-ip` | `` |
| 63 | `192.168.68.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 64 | `192.168.45.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 65 | `192.168.10.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 66 | `192.168.49.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 67 | `192.168.6.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 68 | `192.168.7.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 69 | `192.168.73.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 70 | `192.168.57.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 71 | `192.168.70.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 72 | `192.168.18.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 73 | `192.168.22.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 74 | `192.168.43.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 75 | `192.168.87.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 76 | `192.168.3.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 77 | `192.168.98.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 78 | `192.168.93.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 79 | `192.168.17.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 80 | `192.168.99.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 81 | `192.168.75.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 82 | `192.168.31.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 83 | `192.168.64.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 84 | `192.168.51.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 85 | `192.168.21.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 86 | `192.168.88.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 87 | `192.168.91.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 88 | `192.168.24.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 89 | `192.168.30.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 90 | `192.168.100.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 91 | `192.168.94.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 92 | `192.168.15.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 93 | `192.168.5.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 94 | `192.168.32.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 95 | `192.168.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 96 | `192.168.67.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 97 | `192.168.23.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 98 | `192.168.41.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 99 | `192.168.82.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 100 | `192.168.47.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 101 | `192.168.40.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 102 | `192.168.13.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 103 | `192.168.97.0/24` | `169.254.2.20` | `dst-ip` | `` |

#### Upstream — GW chassis (RC) on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 1 rows
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | active RC | `zadkiel04-3` | `e6226ec1-fa8f-41e5-8d0c-7a884b7f9634` | `a109bd1b-b3d4-423d-8122-3fc3c80d4292` | 100 |

#### Upstream — path LRPs on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | transit ↔ GW | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `e0:19:95:87:06:3b` | `169.254.2.100/24` |  |
| 2 | GW ↔ external | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `e0:19:95:14:17:37` | `10.116.246.47/18` | yes |

#### Upstream — External GW MAC/IP on `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0`

- LRP `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` MAC `e0:19:95:14:17:37` IP `10.116.246.47/18`

#### Upstream — scale-out peer `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` (standby) host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20`

- External GW MAC `e0:19:95:5b:76:31` IP `10.116.246.48/18`
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | standby scale-out | `flashfire01-2` | `74e0be63-f78f-482a-b04e-a09ada933f20` | `ef355d92-dc3b-4dc4-aaf4-7c559db792d7` | 100 |

#### Upstream — router `router_818b2c20-4d1b-40b7-a951-5deb85316e68`

#### Upstream — NAT on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 0 rows
(none)

#### Upstream — PBR on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 3 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 100 | allow | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 2 | 10 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 3 | 1 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |

#### Upstream — connected routes on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 103 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-router-port_b0b648a3-fff9-40e9-b453-da9b575d26b2` | `192.168.90.1/24` |  |
| 2 | `lrp-router-port_1b6eb248-5d85-45d1-80b0-bc85aea0d484` | `192.168.47.1/24` |  |
| 3 | `lrp-router-port_5455f7ec-6475-4a62-ab71-dc28807bfb8d` | `192.168.68.1/24` |  |
| 4 | `lrp-router-port_8cb9eba0-0473-49c4-acc6-d22df0813b16` | `192.168.87.1/24` |  |
| 5 | `lrp-router-port_fdff4156-a468-4b28-b6be-4165566ed91b` | `192.168.42.1/24` |  |
| 6 | `lrp-router-port_eaccfc3a-2676-4295-9403-96dc5f703e60` | `192.168.26.1/24` |  |
| 7 | `lrp-router-port_81e65b0f-4933-4648-8c05-d72c77d6455e` | `192.168.48.1/24` |  |
| 8 | `lrp-router-port_4b52ccc7-a78b-4768-a784-27e105367c96` | `192.168.54.1/24` |  |
| 9 | `lrp-router-port_a824f5f1-d59a-439d-a863-88a82e9f728f` | `192.168.80.1/24` |  |
| 10 | `lrp-router-port_237161d6-1f23-40b9-9126-41e50710a4aa` | `192.168.25.1/24` |  |
| 11 | `lrp-router-port_a096b3ec-b472-4645-bb77-3889e617df1b` | `192.168.28.1/24` |  |
| 12 | `lrp-router-port_130a0318-7e0d-4433-bc32-f60ebd4a69b6` | `192.168.38.1/24` |  |
| 13 | `lrp-router-port_4933d693-021b-4cdd-865b-e03ad35e38bc` | `192.168.82.1/24` |  |
| 14 | `lrp-router-port_16454167-c055-409b-a40d-5ceb61fae279` | `192.168.64.1/24` |  |
| 15 | `lrp-router-port_958e7d1d-cd00-4ddf-adc9-58bf9ec0616d` | `192.168.49.1/24` |  |
| 16 | `lrp-router-port_72e62619-8a96-4f15-bf23-e14f602a7423` | `192.168.17.1/24` |  |
| 17 | `lrp-router-port_398e6097-726d-4417-8d4e-a5b0e15f3387` | `192.168.53.1/24` |  |
| 18 | `lrp-router-port_09083e0f-1d76-4a6f-aef8-282667aa110e` | `192.168.100.1/24` |  |
| 19 | `lrp-router-port_e65429bf-d32a-4274-8b35-39156398a0bb` | `192.168.3.1/24` |  |
| 20 | `lrp-router-port_ee90ab74-e669-4214-a816-de31615f8f40` | `192.168.18.1/24` |  |
| 21 | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `192.168.1.1/24` |  |
| 22 | `lrp-router-port_91565e00-afaf-4848-b6c8-aadf55a89177` | `192.168.12.1/24` |  |
| 23 | `lrp-router-port_bcd3c336-727d-4cff-8741-76b3ab62c5f0` | `192.168.79.1/24` |  |
| 24 | `lrp-router-port_b6d9bfd6-dcf4-4ad2-bec7-fdac3c8c0901` | `192.168.6.1/24` |  |
| 25 | `lrp-router-port_b7bbab8b-6c91-4ba1-86a1-7cbc2862b47a` | `192.168.60.1/24` |  |
| 26 | `lrp-router-port_a6a82a86-eb1c-4ed7-81a0-138e06ac03ed` | `192.168.10.1/24` |  |
| 27 | `lrp-router-port_f6ad4655-b1dc-4ac8-92be-fb23f95e6e5c` | `192.168.73.1/24` |  |
| 28 | `lrp-router-port_b156442e-c14c-4cee-bcf9-df780d716265` | `192.168.50.1/24` |  |
| 29 | `lrp-router-port_03c2ec09-65c6-439a-8878-b987580c3924` | `192.168.41.1/24` |  |
| 30 | `lrp-router-port_691b4004-10b5-45ee-bbaa-f455fd574caa` | `192.168.61.1/24` |  |
| 31 | `lrp-router-port_731e491b-f5c9-4a91-a1fa-e5a623312321` | `192.168.5.1/24` |  |
| 32 | `lrp-router-port_30af069f-3873-406c-b618-1910068e78f6` | `192.168.31.1/24` |  |
| 33 | `lrp-router-port_ad47fb2b-5cf5-413b-9c84-708688d9bd34` | `192.168.4.1/24` |  |
| 34 | `lrp-router-port_f4227f2b-0e70-4a07-a5f7-85f8ee92d9a4` | `192.168.21.1/24` |  |
| 35 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `169.254.2.20/24` |  |
| 36 | `lrp-router-port_f4954815-1f1b-4f5a-9cb1-fe89ccbfed8a` | `192.168.81.1/24` |  |
| 37 | `lrp-router-port_6ff10629-2c72-4efb-901d-eac2f09ba7ba` | `192.168.36.1/24` |  |
| 38 | `lrp-router-port_58903cc2-b80a-47e0-83b0-c10a12478545` | `192.168.14.1/24` |  |
| 39 | `lrp-router-port_de78f2f1-94a3-42b5-8736-68541ff9142a` | `192.168.63.1/24` |  |
| 40 | `lrp-router-port_4e3981a3-4f75-439c-a5fa-f5ab9e9a2809` | `192.168.59.1/24` |  |
| 41 | `lrp-router-port_4f4768cb-67cc-482a-bccb-054c3cb73cd3` | `192.168.88.1/24` |  |
| 42 | `lrp-router-port_a2ff46ff-216a-484b-ae3c-fa005b99a422` | `192.168.70.1/24` |  |
| 43 | `lrp-router-port_7b7ecd3c-2b5c-49ca-936f-ab79b67aea63` | `192.168.52.1/24` |  |
| 44 | `lrp-router-port_7b5bb2c4-526f-4300-9d11-338fe4083c58` | `192.168.22.1/24` |  |
| 45 | `lrp-router-port_4732a674-e2c3-4a32-8b98-8d04ad8981e0` | `192.168.15.1/24` |  |
| 46 | `lrp-router-port_a6bdf8cc-6ed7-4989-b7f5-33fd250b3be8` | `192.168.45.1/24` |  |
| 47 | `lrp-router-port_bfdb0087-699f-4cda-968a-c83f5c59a0e3` | `192.168.74.1/24` |  |
| 48 | `lrp-router-port_ba2f2f7b-819b-48e8-9873-3a8d03a4ccd8` | `192.168.13.1/24` |  |
| 49 | `lrp-router-port_dd8bd26a-26ac-4dce-ba1a-b013a8a2eaeb` | `192.168.40.1/24` |  |
| 50 | `lrp-router-port_aaacea27-4b19-408b-b2a8-3ea5e8563bd8` | `192.168.29.1/24` |  |
| 51 | `lrp-router-port_6056da2d-7903-441e-9bad-f694d7c6efd6` | `192.168.16.1/24` |  |
| 52 | `lrp-router-port_8e2c5018-5789-4e8d-a0ca-de2aef90b054` | `192.168.24.1/24` |  |
| 53 | `lrp-router-port_8aedd6c8-e897-4611-978e-c968c15eda92` | `192.168.86.1/24` |  |
| 54 | `lrp-router-port_31f2dffa-1a77-4667-9df5-96ddbbb25998` | `192.168.7.1/24` |  |
| 55 | `lrp-router-port_a26841c2-d315-4598-9d4e-b722e6b0740e` | `192.168.75.1/24` |  |
| 56 | `lrp-router-port_98b8a929-e141-402b-8abd-cbafab4aad11` | `192.168.35.1/24` |  |
| 57 | `lrp-router-port_b5ac7378-d238-4655-bbcf-21965877290b` | `192.168.55.1/24` |  |
| 58 | `lrp-router-port_ee75b808-37c3-48e3-b951-323cd7ce8623` | `192.168.57.1/24` |  |
| 59 | `lrp-router-port_ec0d7873-0cec-4e0f-b521-fb87d4b8a5a2` | `192.168.9.1/24` |  |
| 60 | `lrp-router-port_cd95a7dd-3a73-4f75-bdb7-cca39a8c349f` | `192.168.2.1/24` |  |
| 61 | `lrp-router-port_5536566e-9f0e-4b24-a74a-23b37e1a4cc9` | `192.168.92.1/24` |  |
| 62 | `lrp-router-port_7fa8249e-89c7-436c-b73c-fc1c6c35c8a2` | `192.168.44.1/24` |  |
| 63 | `lrp-router-port_a6099d81-d558-4801-a626-e4b67e523609` | `192.168.89.1/24` |  |
| 64 | `lrp-router-port_75dc71e6-0677-49f6-a6fc-1aba0dbcd96e` | `192.168.95.1/24` |  |
| 65 | `lrp-router-port_5f201938-3047-4926-83e7-a2ce47cf5323` | `192.168.85.1/24` |  |
| 66 | `lrp-router-port_a8f4c5b9-8ed3-49c0-95a3-9fd9a367f8d5` | `192.168.71.1/24` |  |
| 67 | `lrp-router-port_d2c5df99-e81d-40e4-98da-6faaf1e56f02` | `192.168.253.1/24` |  |
| 68 | `lrp-router-port_c2884fa3-9c1b-4775-b3f5-1c1d4fa0545a` | `192.168.78.1/24` |  |
| 69 | `lrp-router-port_91a6ac0f-3bd8-4902-b3b2-b24dc0cbe78c` | `192.168.34.1/24` |  |
| 70 | `lrp-router-port_8ffb4745-7439-4c63-8557-ac89ee2a67c1` | `192.168.19.1/24` |  |
| 71 | `lrp-router-port_aef08078-d157-4726-81f9-89a0740b2b75` | `192.168.56.1/24` |  |
| 72 | `lrp-router-port_d8fbdfbb-d700-4bb6-acfa-cf2a4496eb77` | `192.168.93.1/24` |  |
| 73 | `lrp-router-port_c3be4831-ac8f-46c1-b915-e7ff36a141c7` | `192.168.72.1/24` |  |
| 74 | `lrp-router-port_ae3f429f-f5b2-419b-85d5-7604d80d17be` | `192.168.27.1/24` |  |
| 75 | `lrp-router-port_26655dc6-20c7-46fc-afa1-6854ebb737b9` | `192.168.96.1/24` |  |
| 76 | `lrp-router-port_7adec254-a0fd-4908-a1c8-0a5f43bb0639` | `192.168.66.1/24` |  |
| 77 | `lrp-router-port_7fe3e8df-402c-43a6-9b89-9f2518963842` | `192.168.20.1/24` |  |
| 78 | `lrp-router-port_27af2774-c142-4a05-8739-d78d1f02d22e` | `192.168.8.1/24` |  |
| 79 | `lrp-router-port_d5a053c9-426c-486c-bdd0-fab8ea9febb7` | `192.168.77.1/24` |  |
| 80 | `lrp-router-port_b5e6667d-3a04-4a97-8772-bbed3136b58a` | `192.168.51.1/24` |  |
| 81 | `lrp-router-port_d0d67ec6-bc34-4470-9c4d-ae668c5bf7a2` | `192.168.99.1/24` |  |
| 82 | `lrp-router-port_951af33a-3f9c-43df-9489-8295a785bfff` | `192.168.11.1/24` |  |
| 83 | `lrp-router-port_0d9118a5-635c-4128-a672-8da5544f07da` | `192.168.97.1/24` |  |
| 84 | `lrp-router-port_8c51f88f-84a9-4bc6-91a3-d86fba6000eb` | `192.168.67.1/24` |  |
| 85 | `lrp-router-port_20a2dea6-ce0a-4ed1-a7c2-487f61008c87` | `192.168.98.1/24` |  |
| 86 | `lrp-router-port_e71f71b1-e394-4035-b892-5474f450f7d7` | `192.168.84.1/24` |  |
| 87 | `lrp-router-port_724f58ea-11b2-49b7-96c5-cdc7e540cde1` | `192.168.37.1/24` |  |
| 88 | `lrp-router-port_9088b9d8-aea5-4f6f-94f3-ddb503d57c45` | `192.168.46.1/24` |  |
| 89 | `lrp-router-port_d3474aa1-21ac-4614-98b3-9578f293491d` | `192.168.30.1/24` |  |
| 90 | `lrp-router-port_4da00f14-4b97-492c-98f8-7cdee12d3f89` | `192.168.69.1/24` |  |
| 91 | `lrp-router-port_e92240e5-8825-4ecf-aced-98081cbc3483` | `192.168.58.1/24` |  |
| 92 | `lrp-router-port_86dbbc63-cec8-4f84-b7c4-297def9ce02a` | `192.168.62.1/24` |  |
| 93 | `lrp-router-port_2c813b95-2ea6-4ae9-8943-4915dcb03bf1` | `192.168.65.1/24` |  |
| 94 | `lrp-router-port_d12a033b-c4fa-40fe-86d5-59e0204b99df` | `192.168.33.1/24` |  |
| 95 | `lrp-router-port_12116e83-b0e3-4db1-9e07-5da35760bd0a` | `192.168.83.1/24` |  |
| 96 | `lrp-router-port_31d327ab-cdfa-4e6a-bb41-de932541ebb4` | `192.168.76.1/24` |  |
| 97 | `lrp-router-port_47c2c0c7-8697-4c67-bb84-d41d887af480` | `192.168.39.1/24` |  |
| 98 | `lrp-router-port_9ccef8d3-00c6-4419-83b1-f1630f89f70e` | `192.168.91.1/24` |  |
| 99 | `lrp-router-port_6c0558f1-f3b2-48fc-9770-5f2536efabb9` | `192.168.254.1/24` |  |
| 100 | `lrp-router-port_19e53512-d5ca-4400-a202-b4ecf350398a` | `192.168.94.1/24` |  |
| 101 | `lrp-router-port_f77b955e-d890-4442-aa17-e54663100cfb` | `192.168.23.1/24` |  |
| 102 | `lrp-router-port_50dd6605-d26f-461a-a825-6a585a416d5e` | `192.168.32.1/24` |  |
| 103 | `lrp-router-port_d0bbe94e-c02c-4978-a52d-6a1c31468ef9` | `192.168.43.1/24` |  |

#### Upstream — static routes on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 2 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `0.0.0.0/0` | `169.254.2.101` | `dst-ip` | `` |
| 2 | `0.0.0.0/0` | `169.254.2.100` | `dst-ip` | `` |

#### Upstream — GW chassis (RC) on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 0 rows
(none)

#### Upstream — path LRPs on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | LR ↔ transit | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `e0:19:95:8d:46:1a` | `169.254.2.20/24` |  |
| 2 | src LS ↔ LR | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `e0:19:95:59:9f:05` | `192.168.1.1/24` |  |
## Downstream composite
=== Downstream (two_router) ===
src: vm=VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4 nic=1d6e610d-f164-4f5d-a6f3-4be6a59a4819 lsp=port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 lsp_uuid=22bce434-1ef5-4792-8e57-8fa2a5e3bd71 mac=50:6b:8d:43:a5:90 ip=192.168.1.51
dst: vm=VPC_California_SJ_Pheonix_Customer_1_subnet_2_139 nic=3468ac71-d670-41a0-93af-0ec34d43f7c3 lsp=port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 lsp_uuid=915f1338-1aba-4c27-a016-cb9876cdc970 mac=50:6b:8d:19:78:77 ip=192.168.2.186
  1. VIF vm=VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4 nic=1d6e610d-f164-4f5d-a6f3-4be6a59a4819 lsp=port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 lsp_uuid=22bce434-1ef5-4792-8e57-8fa2a5e3bd71 mac=50:6b:8d:43:a5:90 ip=192.168.1.51
  2. LS network_17fe24db-e08b-4f81-969a-e06d6f23b35c uuid=183da7a8-c33c-4247-912a-d4cb28ec8a5a
       stretch flashfire01-3:geneve:10.116.29.156, flashfire03-2:geneve:10.116.29.191, flashfire04-1:geneve:10.116.29.208, spymaster01-2:geneve:10.116.26.72, spymaster02-3:geneve:10.116.26.91, zadkiel04-3:geneve:10.116.26.217, zadkiel04-4:geneve:10.116.26.218, zadkiel05-1:geneve:10.116.26.233 (+1)
       ACLs from-lport (ingress on this hop): 9 (full list)
         pri=31500 allow-stateless to-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop to-lport [pg] ip4 && (ip4.src == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1052 drop to-lport [pg] ip4 && (ip4.src == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_205229df_97dd_4f48_8888_22f75df17032) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) || (tcp.dst >= 18376 && tcp.dst <= 18385) || (tcp.dst >= 18389 && tcp.dst <= 18398) || (tcp.dst >= 18401 && tcp.dst <= 18410) || (tcp.dst >= 18415 && tcp.dst <= 18424) || (tcp.dst >= 18429 && tcp.dst <= 18438) || (tcp.dst >= 18441 && tcp.dst <= 18450) || (tcp.dst >= 18455 && tcp.dst <= 18464) || (tcp.dst >= 18468 && tcp.dst <= 18477) || (tcp.dst >= 18483 && tcp.dst <= 18492))) || (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) || (udp.dst >= 18376 && udp.dst <= 18385) || (udp.dst >= 18389 && udp.dst <= 18398) || (udp.dst >= 18401 && udp.dst <= 18410) || (udp.dst >= 18415 && udp.dst <= 18424) || (udp.dst >= 18429 && udp.dst <= 18438) || (udp.dst >= 18441 && udp.dst <= 18450) || (udp.dst >= 18455 && udp.dst <= 18464) || (udp.dst >= 18468 && udp.dst <= 18477) || (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_8bd19f47_a216_502a_b5e5_00edc3b21853) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) || (ip.proto == 6 && (tcp.dst == 22 || tcp.dst == 1024 || tcp.dst == 80)) || (ip.proto == 17 && (udp.dst == 22))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_f96fe67d_5c12_5b66_b6a0_6e7e91be679b) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) || (tcp.dst >= 18512 && tcp.dst <= 18521) || (tcp.dst >= 18524 && tcp.dst <= 18533) || (tcp.dst >= 18537 && tcp.dst <= 18546) || (tcp.dst >= 18551 && tcp.dst <= 18560) || (tcp.dst >= 18564 && tcp.dst <= 18573) || (tcp.dst >= 18576 && tcp.dst <= 18585) || (tcp.dst >= 18590 && tcp.dst <= 18599) || (tcp.dst >= 18603 && tcp.dst <= 18612) || (tcp.dst >= 18618 && tcp.dst <= 18627))) || (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) || (udp.dst >= 18512 && udp.dst <= 18521) || (udp.dst >= 18524 && udp.dst <= 18533) || (udp.dst >= 18537 && udp.dst <= 18546) || (udp.dst >= 18551 && udp.dst <= 18560) || (udp.dst >= 18564 && udp.dst <= 18573) || (udp.dst >= 18576 && udp.dst <= 18585) || (udp.dst >= 18590 && udp.dst <= 18599) || (udp.dst >= 18603 && udp.dst <= 18612) || (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1045 drop to-lport [pg] ip6 && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=1045 drop to-lport [pg] ip4 && outport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0
         pri=500 allow-related to-lport [ls] tcp || udp || icmp
       ACLs to-lport (egress on this hop): 8 (full list)
         pri=31500 allow-stateless from-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406)
         pri=1052 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_1b11d438_5b2f_4b00_950b_3c355529d406)
         pri=1050 allow-related from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_b490212e_6951_43bf_a004_f47375039435) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) || (tcp.dst >= 18646 && tcp.dst <= 18655) || (tcp.dst >= 18661 && tcp.dst <= 18670) || (tcp.dst >= 18673 && tcp.dst <= 18682) || (tcp.dst >= 18685 && tcp.dst <= 18694) || (tcp.dst >= 18699 && tcp.dst <= 18708) || (tcp.dst >= 18712 && tcp.dst <= 18721) || (tcp.dst >= 18725 && tcp.dst <= 18734) || (tcp.dst >= 18737 && tcp.dst <= 18746) || (tcp.dst >= 18751 && tcp.dst <= 18760))) || (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) || (udp.dst >= 18646 && udp.dst <= 18655) || (udp.dst >= 18661 && udp.dst <= 18670) || (udp.dst >= 18673 && udp.dst <= 18682) || (udp.dst >= 18685 && udp.dst <= 18694) || (udp.dst >= 18699 && udp.dst <= 18708) || (udp.dst >= 18712 && udp.dst <= 18721) || (udp.dst >= 18725 && udp.dst <= 18734) || (udp.dst >= 18737 && udp.dst <= 18746) || (udp.dst >= 18751 && udp.dst <= 18760))))
         pri=1050 allow-related from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4 && (ip4.dst == $address_set_17ae1270_33aa_5acd_94b7_65b09d6bf397) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) || (tcp.dst >= 18779 && tcp.dst <= 18788) || (tcp.dst >= 18794 && tcp.dst <= 18803) || (tcp.dst >= 18809 && tcp.dst <= 18818) || (tcp.dst >= 18821 && tcp.dst <= 18830) || (tcp.dst >= 18833 && tcp.dst <= 18842) || (tcp.dst >= 18847 && tcp.dst <= 18856) || (tcp.dst >= 18860 && tcp.dst <= 18869) || (tcp.dst >= 18874 && tcp.dst <= 18883) || (tcp.dst >= 18888 && tcp.dst <= 18897))) || (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) || (udp.dst >= 18779 && udp.dst <= 18788) || (udp.dst >= 18794 && udp.dst <= 18803) || (udp.dst >= 18809 && udp.dst <= 18818) || (udp.dst >= 18821 && udp.dst <= 18830) || (udp.dst >= 18833 && udp.dst <= 18842) || (udp.dst >= 18847 && udp.dst <= 18856) || (udp.dst >= 18860 && udp.dst <= 18869) || (udp.dst >= 18874 && udp.dst <= 18883) || (udp.dst >= 18888 && udp.dst <= 18897))))
         pri=1045 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip6
         pri=1045 drop from-lport [pg] inport == @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0 && ip4
         pri=500 allow-related from-lport [ls] tcp || udp || icmp
  3. LR router_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid=a27e38bd-6c57-472f-80df-1a39723efe1a has_nat=0
       via transit_ls LS gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid=f7e6f4bb-0dfd-40a3-8023-270912e79985
       ACLs from-lport (ingress on this hop): (none)
       ACLs to-lport (egress on this hop): (none)
       PBR pri=100 allow match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=10 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=1 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
  4. LR gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 uuid=6572681a-8ffe-4fba-9263-8501622d7726 has_nat=1
       via transit_ls LS network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a uuid=43a3a38a-89e1-4410-8101-b255757c2f28
       ACLs from-lport (ingress on this hop): (none)
       ACLs to-lport (egress on this hop): 2 (full list)
         pri=1000 allow from-lport [ls] ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18
         pri=100 drop from-lport [ls] ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"
       RC chassis=a109bd1b-b3d4-423d-8122-3fc3c80d4292 pri=100
       NAT dnat_and_snat ext=10.116.246.72 log=192.168.253.70 port=
       NAT snat ext=10.116.246.47 log=192.168.1.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.10.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.100.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.11.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.12.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.13.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.14.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.15.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.16.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.17.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.18.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.19.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.2.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.20.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.21.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.22.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.23.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.24.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.25.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.253.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.254.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.26.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.27.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.28.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.29.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.3.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.30.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.31.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.32.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.33.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.34.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.35.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.36.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.37.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.38.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.39.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.4.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.40.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.41.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.42.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.43.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.44.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.45.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.46.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.47.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.48.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.49.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.5.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.50.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.51.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.52.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.53.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.54.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.55.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.56.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.57.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.58.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.59.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.6.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.60.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.61.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.62.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.63.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.64.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.65.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.66.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.67.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.68.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.69.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.7.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.70.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.71.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.72.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.73.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.74.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.75.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.76.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.77.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.78.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.79.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.8.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.80.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.81.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.82.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.83.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.84.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.85.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.86.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.87.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.88.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.89.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.9.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.90.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.91.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.92.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.93.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.94.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.95.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.96.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.97.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.98.0/24 port=
       NAT snat ext=10.116.246.47 log=192.168.99.0/24 port=
  5. LR gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 uuid=edba0385-d5d3-4d07-8ca5-f9253e4af298 has_nat=1
       via transit_ls LS gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid=df8dadd4-7138-4ea7-95da-15fab0b6838c
       ACLs from-lport (ingress on this hop): (none)
       ACLs to-lport (egress on this hop): (none)
       PBR pri=1000 reroute match=ip4.src==100.64.1.6/32 nexthop=169.254.2.100
       RC chassis=bb49616e-e5ad-4dd7-9d98-ad529702d2df pri=100
       NAT dnat_and_snat ext=10.116.246.1 log=192.168.254.168 port=
       NAT dnat_and_snat ext=10.116.246.43 log=100.64.1.222 port=
       NAT snat ext=10.116.246.55 log=100.64.1.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.1.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.10.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.100.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.11.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.12.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.13.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.14.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.15.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.16.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.17.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.18.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.19.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.2.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.20.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.21.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.22.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.23.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.24.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.25.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.253.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.254.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.26.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.27.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.28.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.29.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.3.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.30.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.31.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.32.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.33.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.34.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.35.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.36.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.37.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.38.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.39.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.4.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.40.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.41.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.42.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.43.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.44.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.45.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.46.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.47.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.48.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.49.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.5.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.50.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.51.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.52.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.53.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.54.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.55.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.56.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.57.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.58.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.59.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.6.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.60.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.61.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.62.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.63.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.64.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.65.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.66.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.67.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.68.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.69.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.7.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.70.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.71.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.72.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.73.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.74.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.75.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.76.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.77.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.78.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.79.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.8.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.80.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.81.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.82.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.83.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.84.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.85.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.86.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.87.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.88.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.89.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.9.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.90.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.91.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.92.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.93.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.94.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.95.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.96.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.97.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.98.0/24 port=
       NAT snat ext=10.116.246.55 log=192.168.99.0/24 port=
  6. LR router_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid=cb58bbb0-4bdc-429e-9378-838e204b99f1 has_nat=0
       LRP lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef mac=e0:19:95:08:22:c9 nets=['192.168.2.1/24']
       PBR pri=100 allow match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=10 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
       PBR pri=1 drop match=ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0 nexthop=
  7. LS network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef uuid=02d0de22-21a5-41f7-befd-75b6cb9c4cc7
       stretch flashfire01-1:geneve:10.116.29.154, flashfire01-2:geneve:10.116.29.155, flashfire01-3:geneve:10.116.29.156, flashfire01-4:geneve:10.116.29.157, flashfire02-1:geneve:10.116.29.172, flashfire02-2:geneve:10.116.29.173, flashfire02-3:geneve:10.116.29.174, flashfire02-4:geneve:10.116.29.175 (+22)
       ACLs from-lport (ingress on this hop): 14 (full list)
         pri=31500 allow-stateless to-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop to-lport [pg] ip4 && (ip4.src == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1052 drop to-lport [pg] ip4 && (ip4.src == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_e88c0d4d_73b0_486e_a3fb_d95baaa35ef1) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) || (tcp.dst >= 1037 && tcp.dst <= 1046) || (tcp.dst >= 1049 && tcp.dst <= 1058) || (tcp.dst >= 1062 && tcp.dst <= 1071) || (tcp.dst >= 1074 && tcp.dst <= 1083) || (tcp.dst >= 1086 && tcp.dst <= 1095) || (tcp.dst >= 1101 && tcp.dst <= 1110) || (tcp.dst >= 1113 && tcp.dst <= 1122) || (tcp.dst >= 1125 && tcp.dst <= 1134) || (tcp.dst >= 1140 && tcp.dst <= 1149))) || (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) || (udp.dst >= 1037 && udp.dst <= 1046) || (udp.dst >= 1049 && udp.dst <= 1058) || (udp.dst >= 1062 && udp.dst <= 1071) || (udp.dst >= 1074 && udp.dst <= 1083) || (udp.dst >= 1086 && udp.dst <= 1095) || (udp.dst >= 1101 && udp.dst <= 1110) || (udp.dst >= 1113 && udp.dst <= 1122) || (udp.dst >= 1125 && udp.dst <= 1134) || (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ca94bdb8_7cff_5c8c_858e_ca44207c5032) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) || (ip.proto == 6 && (tcp.dst == 22 || tcp.dst == 1024 || tcp.dst == 80)) || (ip.proto == 17 && (udp.dst == 22))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1050 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_09687af3_486d_5381_baff_78f78a00c4b3) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) || (tcp.dst >= 1166 && tcp.dst <= 1175) || (tcp.dst >= 1181 && tcp.dst <= 1190) || (tcp.dst >= 1193 && tcp.dst <= 1202) || (tcp.dst >= 1205 && tcp.dst <= 1214) || (tcp.dst >= 1218 && tcp.dst <= 1227) || (tcp.dst >= 1230 && tcp.dst <= 1239) || (tcp.dst >= 1242 && tcp.dst <= 1251) || (tcp.dst >= 1257 && tcp.dst <= 1266) || (tcp.dst >= 1271 && tcp.dst <= 1280))) || (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) || (udp.dst >= 1166 && udp.dst <= 1175) || (udp.dst >= 1181 && udp.dst <= 1190) || (udp.dst >= 1193 && udp.dst <= 1202) || (udp.dst >= 1205 && udp.dst <= 1214) || (udp.dst >= 1218 && udp.dst <= 1227) || (udp.dst >= 1230 && udp.dst <= 1239) || (udp.dst >= 1242 && udp.dst <= 1251) || (udp.dst >= 1257 && udp.dst <= 1266) || (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1045 drop to-lport [pg] ip4 && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1045 drop to-lport [pg] ip6 && outport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f
         pri=1019 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1018 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1017 allow-related to-lport [pg] ip4 && (ip4.src == $address_set_25f83796_b668_50c1_a86f_741b6495cafe) && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1015 allow-related to-lport [pg] ip4 && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=1015 allow-related to-lport [pg] ip6 && outport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133
         pri=500 allow-related to-lport [ls] tcp || udp || icmp
       ACLs to-lport (egress on this hop): 13 (full list)
         pri=31500 allow-stateless from-lport [ls] (udp.src == 67 && udp.dst == 68) || (udp.src == 68 && udp.dst == 67)
         pri=1060 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c)
         pri=1052 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c)
         pri=1050 allow-related from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_9c194c48_8c96_54a7_837a_81508c40ddae) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) || (tcp.dst >= 1429 && tcp.dst <= 1438) || (tcp.dst >= 1441 && tcp.dst <= 1450) || (tcp.dst >= 1455 && tcp.dst <= 1464) || (tcp.dst >= 1469 && tcp.dst <= 1478) || (tcp.dst >= 1483 && tcp.dst <= 1492) || (tcp.dst >= 1498 && tcp.dst <= 1507) || (tcp.dst >= 1511 && tcp.dst <= 1520) || (tcp.dst >= 1524 && tcp.dst <= 1533) || (tcp.dst >= 1539 && tcp.dst <= 1548))) || (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) || (udp.dst >= 1429 && udp.dst <= 1438) || (udp.dst >= 1441 && udp.dst <= 1450) || (udp.dst >= 1455 && udp.dst <= 1464) || (udp.dst >= 1469 && udp.dst <= 1478) || (udp.dst >= 1483 && udp.dst <= 1492) || (udp.dst >= 1498 && udp.dst <= 1507) || (udp.dst >= 1511 && udp.dst <= 1520) || (udp.dst >= 1524 && udp.dst <= 1533) || (udp.dst >= 1539 && udp.dst <= 1548))))
         pri=1050 allow-related from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4 && (ip4.dst == $address_set_f412ba3b_b736_4b27_a0e6_4eeefc7220a4) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) || (tcp.dst >= 1297 && tcp.dst <= 1306) || (tcp.dst >= 1312 && tcp.dst <= 1321) || (tcp.dst >= 1324 && tcp.dst <= 1333) || (tcp.dst >= 1336 && tcp.dst <= 1345) || (tcp.dst >= 1350 && tcp.dst <= 1359) || (tcp.dst >= 1363 && tcp.dst <= 1372) || (tcp.dst >= 1378 && tcp.dst <= 1387) || (tcp.dst >= 1390 && tcp.dst <= 1399) || (tcp.dst >= 1403 && tcp.dst <= 1412))) || (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) || (udp.dst >= 1297 && udp.dst <= 1306) || (udp.dst >= 1312 && udp.dst <= 1321) || (udp.dst >= 1324 && udp.dst <= 1333) || (udp.dst >= 1336 && udp.dst <= 1345) || (udp.dst >= 1350 && udp.dst <= 1359) || (udp.dst >= 1363 && udp.dst <= 1372) || (udp.dst >= 1378 && udp.dst <= 1387) || (udp.dst >= 1390 && udp.dst <= 1399) || (udp.dst >= 1403 && udp.dst <= 1412))))
         pri=1045 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip6
         pri=1045 drop from-lport [pg] inport == @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f && ip4
         pri=1019 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4 && (ip4.dst == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506)
         pri=1018 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4 && (ip4.dst == $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506)
         pri=1017 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4
         pri=1015 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip4
         pri=1015 allow-related from-lport [pg] inport == @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133 && ip6
         pri=500 allow-related from-lport [ls] tcp || udp || icmp
  8. VIF vm=VPC_California_SJ_Pheonix_Customer_1_subnet_2_139 nic=3468ac71-d670-41a0-93af-0ec34d43f7c3 lsp=port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 lsp_uuid=915f1338-1aba-4c27-a016-cb9876cdc970 mac=50:6b:8d:19:78:77 ip=192.168.2.186

## Mermaid Downstream composite
**How to read:** left to right is packet flow. Blue stadium = VM. Rectangle = NIC, then TAP, then OVS port on brAtlas (ofport / datapath port / iface-id). Green cylinder = Switch (LS), orange hexagon = Router (LR) / External GW. Host subgraphs wrap compute VIF hops and every scale-out External GW Host (active RC vs standby). External GW label is MAC + IP/CIDR. Dashed yellow / pink / gray hang off a router = NAT / PBR / RC. Teal dashed = port group (policy applied-to). Gold dashed = address set (policy dest/src IPs). Purple dashed = Geneve when chassis differ. Red dashed = drop ACLs. Identity is UUID; names are display. `@port_group_*` and `$address_set_*` are rewritten to policy category / dest names in the ACL tables.

```mermaid
flowchart LR
  %% required VIF hops: TAP_S OVS_S TAP_D OVS_D (OVS label always brAtlas)
  classDef vm fill:#4C8BF5,stroke:#1a4fa0,color:#fff
  classDef nic fill:#E8F0FE,stroke:#4C8BF5,color:#111
  classDef sw fill:#34A853,stroke:#137333,color:#fff
  classDef rt fill:#FB8C00,stroke:#E65100,color:#111
  classDef nat fill:#FFF59D,stroke:#F9A825,color:#111,stroke-dasharray: 5 5
  classDef pbr fill:#F8BBD0,stroke:#C2185B,color:#111,stroke-dasharray: 5 5
  classDef rc fill:#BDBDBD,stroke:#616161,color:#111,stroke-dasharray: 5 5
  classDef ext fill:#EA4335,stroke:#B31412,color:#fff
  classDef ovl fill:#CE93D8,stroke:#7B1FA2,color:#111,stroke-dasharray: 5 5
  classDef dropacl fill:#FCE8E6,stroke:#C5221F,color:#111,stroke-dasharray: 5 5
  classDef tap fill:#E0F2F1,stroke:#00796B,color:#111
  classDef ovs fill:#ECEFF1,stroke:#37474F,color:#111
  classDef pg fill:#E0F7FA,stroke:#00838F,color:#111,stroke-dasharray: 5 5
  classDef aset fill:#FFF8E1,stroke:#FF8F00,color:#111,stroke-dasharray: 5 5
  subgraph DOWN["Downstream composite"]
  subgraph L2["L2 stretch"]
  subgraph H1["Host spymaster01-2<br/>chassis bbd822da-f0b1-4a7d-a894-df4029cfb598<br/>10.116.26.72<br/>geneve 10.116.26.72"]
  VM_S(["VM VPC_California_SJ_Pheonix_Customer_19_FNS-L1-1_4"])
  NIC_S["NIC 1d6e610d-f164-4f5d-a6f3-4be6a59a4819<br/>MAC 50:6b:8d:43:a5:90<br/>IP 192.168.1.51"]
  TAP_S["TAP tap42"]
  OVS_S["OVS brAtlas<br/>ofport 91 dp_port 60<br/>iface-id port_ac6485b2-02b8-492e-84ca-1e4fa3e33360"]
  end
  N1[("Switch<br/>network_17fe24db-e08b-4f81-969a-e06d6f23b35c<br/>uuid 183da7a8-c33c-4247-912a-d4cb28ec8a5a<br/>tunnel_key 11303<br/>datapath 82790df2-ba45-4e0e-9536-d37869adfce5<br/>lb_vip_mac=e0:19:95:59:9f:05<br/>requested-tnl-key=11303<br/>neutron:network_name=network_17fe24db-e08b-4f81-969a-e06d6f23b35c<br/>LSP vif port_ac6485b2-02b8-492e-84ca-1e4fa3e33360 MAC 50:6b:8d:43:a5:90 IP 192.168.1.51 chassis spymaster01-2<br/>LSP router router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph L3["L3 routing / PBR"]
  N2{{"Router<br/>router_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>uuid a27e38bd-6c57-472f-80df-1a39723efe1a<br/>tunnel_key 10124<br/>datapath 7494f7b0-3a05-40c9-ba1f-8a971b4e99da<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>requested-tnl-key=10124<br/>neutron:router_name=router_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>LRP lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c uuid 62ccf088-8c87-48ec-8b68-4c4a6ccff023 MAC e0:19:95:59:9f:05 192.168.1.1/24<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 uuid 6ca4b6f3-615e-440b-9509-f0bae9fa92ae MAC e0:19:95:8d:46:1a 169.254.2.20/24<br/>LRPs 103 total (path 2; full Metadata)<br/>routes connected 103 static 2 PBR 3 NAT 0"}}
  N3["PBR 3"]
  N2 -.-> N3
  end
  subgraph L2["L2 stretch"]
  N4[("Switch transit<br/>gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>uuid f7e6f4bb-0dfd-40a3-8023-270912e79985<br/>tunnel_key 45<br/>datapath 142ae345-5743-4655-b32e-857596482fb5<br/>neutron:network_name=gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1 chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph GW["GW"]
  subgraph HGWp0["External GW Host flashfire01-2 (standby scale-out)<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20<br/>10.116.29.155<br/>geneve 10.116.29.155"]
  TAP_GWp0["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GWp0["OVS brAtlas<br/>ofport 406 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  RT_GW0{{"External GW<br/>gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1<br/>uuid ce75ff4c-456e-4154-bab4-add0f3c5401f<br/>tunnel_key 154<br/>datapath 343cd570-3b2c-4f79-a87f-81e7d877e697<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1<br/>LRP lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d uuid 7d613d5f-98e1-4cd8-9d33-21bf9b9e30b9 MAC e0:19:95:5b:76:31 10.116.246.48/18 ext-GW<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1 uuid 6d52f0b1-a274-40c1-ba60-9c15ea3eddd0 MAC e0:19:95:4b:de:17 169.254.2.101/24<br/>LRPs 2<br/>routes connected 0 static 0 PBR 0 NAT 0<br/>IP 10.116.246.48/18 MAC e0:19:95:5b:76:31<br/>HA flashfire01-2 pri=100<br/>standby scale-out"}}
  N5(["RC standby scale-out<br/>flashfire01-2<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20 pri=100"])
  RT_GW0 -.-> N5
  end
  subgraph HGW["External GW Host zadkiel04-3 (active RC)<br/>chassis e6226ec1-fa8f-41e5-8d0c-7a884b7f9634<br/>10.116.26.217<br/>geneve 10.116.26.217"]
  TAP_GW["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW["OVS brAtlas<br/>ofport 322 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  N6{{"External GW<br/>gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0<br/>uuid 6572681a-8ffe-4fba-9263-8501622d7726<br/>tunnel_key 105<br/>datapath 5dbeea18-4571-4439-a5a7-f334ae8c699c<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0<br/>LRP lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0 uuid 50e071f0-0ec8-4532-9132-241a776b2cde MAC e0:19:95:87:06:3b 169.254.2.100/24<br/>LRP lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0 uuid 9cc5a260-0c66-43b8-95be-0f18815bdda2 MAC e0:19:95:14:17:37 10.116.246.47/18 ext-GW<br/>LRPs 2<br/>routes connected 2 static 103 PBR 0 NAT 103<br/>IP 10.116.246.47/18 MAC e0:19:95:14:17:37<br/>NAT<br/>HA zadkiel04-3 pri=100<br/>active RC"}}
  N7["NAT 103"]
  N6 -.-> N7
  N8(["RC active RC<br/>zadkiel04-3<br/>chassis e6226ec1-fa8f-41e5-8d0c-7a884b7f9634 pri=100"])
  N6 -.-> N8
  end
  N6 -.-> RT_GW0
  end
  subgraph EXT["External"]
  N9[("Switch External localnet<br/>network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a<br/>uuid 43a3a38a-89e1-4410-8101-b255757c2f28<br/>tunnel_key 10105<br/>datapath 068f23c5-b151-4b7c-b29e-3693db43765a<br/>fdb_age_threshold=300<br/>requested-tnl-key=10105<br/>use-gateway-chassis=true<br/>use-redirect-chassis=true<br/>neutron:network_name=network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a<br/>LSP localnet localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a chassis 00000000-0000-0000-0000-000000000000<br/>LSP router ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075 chassis spymaster01-3<br/>LSP router ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141 chassis flashfire01-3<br/>LSP router ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8 chassis spymaster01-1<br/>LSP router ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769 chassis spymaster01-4<br/>LSP router ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11 chassis spymaster01-2<br/>LSP router ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93 chassis flashfire01-2<br/>LSP router ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9 chassis spymaster01-4")]
  end
  subgraph GW["GW"]
  subgraph HGW1p0["External GW Host flashfire01-2 (standby scale-out)<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20<br/>10.116.29.155<br/>geneve 10.116.29.155"]
  TAP_GW1p0["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW1p0["OVS brAtlas<br/>ofport 406 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  RT_GW1p0{{"External GW<br/>gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0<br/>uuid f75fea9a-563e-474b-bdc0-08683ebd3842<br/>tunnel_key 63<br/>datapath 83526036-f5b1-463f-a72d-2363389bf512<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0 uuid 02a3eba2-e737-4eb0-85f6-2e7d203b7aaf MAC e0:19:95:8d:49:e8 169.254.2.100/24<br/>LRP lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26 uuid f0923e0b-40f2-49f3-bf4e-8dab34f0fb23 MAC e0:19:95:c0:b3:04 10.116.246.54/18 ext-GW<br/>LRPs 2<br/>routes connected 0 static 0 PBR 0 NAT 0<br/>IP 10.116.246.54/18 MAC e0:19:95:c0:b3:04<br/>HA flashfire01-2 pri=100<br/>standby scale-out"}}
  N10(["RC standby scale-out<br/>flashfire01-2<br/>chassis 74e0be63-f78f-482a-b04e-a09ada933f20 pri=100"])
  RT_GW1p0 -.-> N10
  end
  subgraph HGW1["External GW Host zadkiel04-1 (active RC)<br/>chassis b594f638-f4a0-439b-91d4-1c513f0c4529<br/>10.116.26.215<br/>geneve 10.116.26.215"]
  TAP_GW1["TAP patch-brAtlas-to-localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  OVS_GW1["OVS brAtlas<br/>ofport 372 dp_port ?<br/>iface-id localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"]
  N11{{"External GW<br/>gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1<br/>uuid edba0385-d5d3-4d07-8ca5-f9253e4af298<br/>tunnel_key 33<br/>datapath 471c4d36-6dbb-49ed-8ff4-c4552d7a57a0<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>neutron:router_name=gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1<br/>LRP lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212 uuid b3f1099a-b8ad-4bbe-962f-05cc5b4a3511 MAC e0:19:95:9b:58:bb 10.116.246.55/18 ext-GW<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 uuid 5d3e7d2c-6a4f-4f15-ac5d-f698ccb2162d MAC e0:19:95:60:29:5b 169.254.2.101/24<br/>LRPs 2<br/>routes connected 2 static 104 PBR 1 NAT 105<br/>IP 10.116.246.55/18 MAC e0:19:95:9b:58:bb<br/>NAT<br/>HA zadkiel04-1 pri=100<br/>active RC"}}
  N12["NAT 105"]
  N11 -.-> N12
  N13["PBR 1"]
  N11 -.-> N13
  N14(["RC active RC<br/>zadkiel04-1<br/>chassis b594f638-f4a0-439b-91d4-1c513f0c4529 pri=100"])
  N11 -.-> N14
  end
  N11 -.-> RT_GW1p0
  end
  subgraph L2["L2 stretch"]
  N15[("Switch transit<br/>gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>uuid df8dadd4-7138-4ea7-95da-15fab0b6838c<br/>tunnel_key 13<br/>datapath 8ba15c30-c06f-4057-9b02-17415e5b45cd<br/>neutron:network_name=gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1 chassis 00000000-0000-0000-0000-000000000000<br/>LSP router gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0 chassis 00000000-0000-0000-0000-000000000000")]
  end
  subgraph L3["L3 routing / PBR"]
  N16{{"Router<br/>router_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>uuid cb58bbb0-4bdc-429e-9378-838e204b99f1<br/>tunnel_key 10110<br/>datapath 6ebe35ee-be81-4e57-8439-8fa1f83e557f<br/>always_learn_from_arp_request=false<br/>dynamic_neigh_routers=true<br/>mac_binding_age_threshold=10.116.192.1/32:0;169.254.2.0/24:0;14400<br/>requested-tnl-key=10110<br/>neutron:router_name=router_fc433064-926d-4fc0-a1a3-7c089ad90343<br/>LRP lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef uuid a962db06-7c7f-4a0b-8ca8-fe5ccfedf145 MAC e0:19:95:08:22:c9 192.168.2.1/24<br/>LRP lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343 uuid 42734276-bf85-470b-a2bd-ddfeff3c11f4 MAC e0:19:95:c9:5b:48 169.254.2.20/24<br/>LRPs 104 total (path 2; full Metadata)<br/>routes connected 104 static 2 PBR 3 NAT 0"}}
  N17["PBR 3"]
  N16 -.-> N17
  end
  subgraph L2["L2 stretch"]
  N18[("Switch<br/>network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef<br/>uuid 02d0de22-21a5-41f7-befd-75b6cb9c4cc7<br/>tunnel_key 10207<br/>datapath bd8492c8-3307-42fa-8a75-d484a87f4db7<br/>lb_vip_mac=e0:19:95:08:22:c9<br/>requested-tnl-key=10207<br/>neutron:network_name=network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef<br/>LSP vif port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2 MAC 50:6b:8d:19:78:77 IP 192.168.2.186 chassis zadkiel05-3<br/>LSP router router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef chassis 00000000-0000-0000-0000-000000000000")]
  subgraph H2["Host zadkiel05-3<br/>chassis a774c18b-7b6e-44f7-8661-6ac53c4607ca<br/>10.116.26.235<br/>geneve 10.116.26.235"]
  OVS_D["OVS brAtlas<br/>ofport 288 dp_port 242<br/>iface-id port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2"]
  TAP_D["TAP tap222"]
  NIC_D["NIC 3468ac71-d670-41a0-93af-0ec34d43f7c3<br/>MAC 50:6b:8d:19:78:77<br/>IP 192.168.2.186"]
  VM_D(["VM VPC_California_SJ_Pheonix_Customer_1_subnet_2_139"])
  end
  N19["Overlay geneve<br/>10.116.26.72 to 10.116.26.235"]
  N1 -.-> N19
  end
  subgraph ACL["ACL Policy"]
  N20["Port group<br/>category App33<br/>policy VPC_California_SJ_Pheonix_Customer_19_App_33 (secured)<br/>10 NICs<br/>OVN @port_group_ee4765ab_2f7d_5aa6_baef_2a4409dcd7a0"]
  N1 -.-> N20
  N21["Port group<br/>category AppType<br/>policy VPC_California_SJ_Pheonix_Customer_1_App_1 (secured)<br/>2000 NICs<br/>OVN @port_group_4b7148bb_c13c_56be_9e17_95bceba2d71f"]
  N1 -.-> N21
  N22["Port group<br/>category AppType<br/>policy EG_Exclude_Policy1 (secured)<br/>2000 NICs<br/>OVN @port_group_85e8b5fc_03c6_53cb_97cb_b2535b556133"]
  N1 -.-> N22
  N23["Address set<br/>App33 VPC_California_SJ_Pheonix_Customer_19_App_33 secured<br/>10 IPs: 192.168.1.122, 192.168.1.141, 192.168.1.15, 192.168.1.153 +6<br/>OVN $address_set_1b11d438_5b2f_4b00_950b_3c355529d406"]
  N1 -.-> N23
  N24["Address set<br/>2 IPs: 192.168.254.151, 192.168.254.221<br/>OVN $address_set_205229df_97dd_4f48_8888_22f75df17032"]
  N1 -.-> N24
  N25["Address set<br/>1 IPs: 192.168.253.70/32<br/>OVN $address_set_8bd19f47_a216_502a_b5e5_00edc3b21853"]
  N1 -.-> N25
  N26["Address set<br/>2 IPs: 192.168.254.117/32, 192.168.254.227/32<br/>OVN $address_set_f96fe67d_5c12_5b66_b6a0_6e7e91be679b"]
  N1 -.-> N26
  N27["Address set<br/>AppType EG_Exclude_Policy1 secured<br/>2000 IPs: 192.168.1.10, 192.168.1.100, 192.168.1.101, 192.168.1.103 +1996<br/>OVN $address_set_d8c26aac_c96e_46a2_a07a_a17fcd70313c"]
  N1 -.-> N27
  N28["Address set<br/>inbound VPC_California_SJ_Pheonix_Customer_1_App_1 src<br/>10 IPs: 192.168.254.102, 192.168.254.103, 192.168.254.144, 192.168.254.238 +6<br/>OVN $address_set_e88c0d4d_73b0_486e_a3fb_d95baaa35ef1"]
  N1 -.-> N28
  N29["Address set<br/>2 IPs: 192.168.254.168/32, 192.168.254.89/32<br/>OVN $address_set_ca94bdb8_7cff_5c8c_858e_ca44207c5032"]
  N1 -.-> N29
  N30["Address set<br/>10 IPs: 192.168.254.129/32, 192.168.254.132/32, 192.168.254.151/32, 192.168.254.159/32 +6<br/>OVN $address_set_09687af3_486d_5381_baff_78f78a00c4b3"]
  N1 -.-> N30
  N31["Address set<br/>AppType EG_Exclude_Policy1 secured<br/>2000 IPs: 192.168.1.10, 192.168.1.100, 192.168.1.101, 192.168.1.103 +1996<br/>OVN $address_set_ddb478f9_61bb_484c_aa10_5738fabfe506"]
  N1 -.-> N31
  N32["Address set<br/>17 IPs: 0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/9, 192.128.0.0/11 +13<br/>OVN $address_set_25f83796_b668_50c1_a86f_741b6495cafe"]
  N1 -.-> N32
  N33["Address set<br/>2 IPs: 192.168.254.164, 192.168.254.72<br/>OVN $address_set_b490212e_6951_43bf_a004_f47375039435"]
  N1 -.-> N33
  N34["Address set<br/>2 IPs: 192.168.254.117/32, 192.168.254.227/32<br/>OVN $address_set_17ae1270_33aa_5acd_94b7_65b09d6bf397"]
  N1 -.-> N34
  N35["Address set<br/>10 IPs: 192.168.254.11/32, 192.168.254.122/32, 192.168.254.149/32, 192.168.254.154/32 +6<br/>OVN $address_set_9c194c48_8c96_54a7_837a_81508c40ddae"]
  N1 -.-> N35
  N36["Address set<br/>outbound VPC_California_SJ_Pheonix_Customer_1_App_1 dest<br/>10 IPs: 192.168.254.127, 192.168.254.152, 192.168.254.18, 192.168.254.212 +6<br/>OVN $address_set_f412ba3b_b736_4b27_a0e6_4eeefc7220a4"]
  N1 -.-> N36
  N37["ACL drop pri=1060<br/>from-lport 8 / to-lport 9"]
  N1 -.-> N37
  end
  end
  VM_S --> NIC_S
  NIC_S --> TAP_S
  TAP_S --> OVS_S
  OVS_S --> N1
  N1 --> N2
  N2 --> N4
  N4 --> TAP_GW
  TAP_GW --> OVS_GW
  OVS_GW --> N6
  N6 --> N9
  N9 --> TAP_GW1
  TAP_GW1 --> OVS_GW1
  OVS_GW1 --> N11
  N11 --> N15
  N15 --> N16
  N16 --> N18
  N18 --> OVS_D
  OVS_D --> TAP_D
  TAP_D --> NIC_D
  NIC_D --> VM_D
  class VM_S vm
  class NIC_S nic
  class TAP_S tap
  class OVS_S ovs
  class N1 sw
  class N2 rt
  class N3 pbr
  class N4 sw
  class TAP_GWp0 tap
  class OVS_GWp0 ovs
  class RT_GW0 rt
  class N5 rc
  class TAP_GW tap
  class OVS_GW ovs
  class N6 rt
  class N7 nat
  class N8 rc
  class N9 sw
  class TAP_GW1p0 tap
  class OVS_GW1p0 ovs
  class RT_GW1p0 rt
  class N10 rc
  class TAP_GW1 tap
  class OVS_GW1 ovs
  class N11 rt
  class N12 nat
  class N13 pbr
  class N14 rc
  class N15 sw
  class N16 rt
  class N17 pbr
  class N18 sw
  class OVS_D ovs
  class TAP_D tap
  class NIC_D nic
  class VM_D vm
  class N19 ovl
  class N20 pg
  class N21 pg
  class N22 pg
  class N23 aset
  class N24 aset
  class N25 aset
  class N26 aset
  class N27 aset
  class N28 aset
  class N29 aset
  class N30 aset
  class N31 aset
  class N32 aset
  class N33 aset
  class N34 aset
  class N35 aset
  class N36 aset
  class N37 dropacl
```

_Downstream `two_router`. Host boxes wrap VM+NIC+TAP+OVS brAtlas when chassis differ. Scale-out draws every External GW Host (active RC vs standby), with TAP_GW / OVS brAtlas when dataplane has them. External GW node is MAC + IP/CIDR._

#### Downstream — Metadata (LS / LR from flow_ovn)

##### Switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` uuid `183da7a8-c33c-4247-912a-d4cb28ec8a5a`

```json
{
  "ls_uuid": "183da7a8-c33c-4247-912a-d4cb28ec8a5a",
  "name": "network_17fe24db-e08b-4f81-969a-e06d6f23b35c",
  "transit": false,
  "localnet": false,
  "datapath_uuid": "82790df2-ba45-4e0e-9536-d37869adfce5",
  "tunnel_key": 11303,
  "other_config": {
    "lb_vip_mac": "e0:19:95:59:9f:05",
    "requested-tnl-key": "11303"
  },
  "external_ids": {
    "neutron:network_name": "network_17fe24db-e08b-4f81-969a-e06d6f23b35c"
  },
  "ports": [
    {
      "lsp_uuid": "22bce434-1ef5-4792-8e57-8fa2a5e3bd71",
      "name": "port_ac6485b2-02b8-492e-84ca-1e4fa3e33360",
      "type": "vif",
      "mac": "50:6b:8d:43:a5:90",
      "ip": "192.168.1.51",
      "addresses": [
        "50:6b:8d:43:a5:90 192.168.1.51"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 25
    },
    {
      "lsp_uuid": "a5fba828-bd28-46fc-bd22-14327aacc2b9",
      "name": "router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    }
  ]
}
```

Path LSPs — 2 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | vif | `port_ac6485b2-02b8-492e-84ca-1e4fa3e33360` | `22bce434-1ef5-4792-8e57-8fa2a5e3bd71` | `50:6b:8d:43:a5:90` | `192.168.1.51` | `spymaster01-2` |
| 2 | router | `router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `a5fba828-bd28-46fc-bd22-14327aacc2b9` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `a27e38bd-6c57-472f-80df-1a39723efe1a`

```json
{
  "lr_uuid": "a27e38bd-6c57-472f-80df-1a39723efe1a",
  "name": "router_818b2c20-4d1b-40b7-a951-5deb85316e68",
  "has_nat": false,
  "datapath_uuid": "7494f7b0-3a05-40c9-ba1f-8a971b4e99da",
  "tunnel_key": 10124,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400",
    "requested-tnl-key": "10124"
  },
  "external_ids": {
    "neutron:router_name": "router_818b2c20-4d1b-40b7-a951-5deb85316e68"
  },
  "lrp_count": 103
}
```

Every LRP — 103 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-router-port_b0b648a3-fff9-40e9-b453-da9b575d26b2` | `08f05ea5-bff5-4495-800d-36095093d24c` | `e0:19:95:d4:1b:32` | `192.168.90.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-router-port_1b6eb248-5d85-45d1-80b0-bc85aea0d484` | `80506c49-d764-4629-806d-c58bcac7318e` | `e0:19:95:17:7f:52` | `192.168.47.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 3 | `lrp-router-port_5455f7ec-6475-4a62-ab71-dc28807bfb8d` | `f67f6365-f19e-4486-807c-22fdf779c2d7` | `e0:19:95:aa:95:8d` | `192.168.68.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 4 | `lrp-router-port_8cb9eba0-0473-49c4-acc6-d22df0813b16` | `e0538257-f2c6-48c9-807d-d5a767c2b790` | `e0:19:95:96:8b:99` | `192.168.87.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 5 | `lrp-router-port_fdff4156-a468-4b28-b6be-4165566ed91b` | `c4844ccd-957f-46b9-8093-ebed7f9bd7e2` | `e0:19:95:de:08:10` | `192.168.42.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 6 | `lrp-router-port_eaccfc3a-2676-4295-9403-96dc5f703e60` | `22e57219-d429-41ce-80a0-2b6d69e516ef` | `e0:19:95:9d:f8:6f` | `192.168.26.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 7 | `lrp-router-port_81e65b0f-4933-4648-8c05-d72c77d6455e` | `9110b84b-a5b8-4e52-8139-e871bc269f61` | `e0:19:95:da:39:a6` | `192.168.48.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 8 | `lrp-router-port_4b52ccc7-a78b-4768-a784-27e105367c96` | `e8aca05b-f5a9-4ff6-825b-94c78a805651` | `e0:19:95:b5:39:c2` | `192.168.54.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 9 | `lrp-router-port_a824f5f1-d59a-439d-a863-88a82e9f728f` | `3d9ec8aa-f3ed-49b8-84d1-9269d9212033` | `e0:19:95:0e:af:a5` | `192.168.80.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 10 | `lrp-router-port_237161d6-1f23-40b9-9126-41e50710a4aa` | `46f925a5-b43d-416b-8661-f9e0ccffa17d` | `e0:19:95:2c:0f:cc` | `192.168.25.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 11 | `lrp-router-port_a096b3ec-b472-4645-bb77-3889e617df1b` | `ca21d272-5ae2-4c08-86cb-52d43e6b185f` | `e0:19:95:72:d8:9a` | `192.168.28.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 12 | `lrp-router-port_130a0318-7e0d-4433-bc32-f60ebd4a69b6` | `2763f3e5-0336-4dc6-8793-ec7ee4da251f` | `e0:19:95:d9:36:97` | `192.168.38.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 13 | `lrp-router-port_4933d693-021b-4cdd-865b-e03ad35e38bc` | `3fc4095e-3805-4162-887c-71b9eaa90883` | `e0:19:95:76:79:1b` | `192.168.82.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 14 | `lrp-router-port_16454167-c055-409b-a40d-5ceb61fae279` | `8610d9f1-2572-4fc0-890b-100afda5600d` | `e0:19:95:be:a2:71` | `192.168.64.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 15 | `lrp-router-port_958e7d1d-cd00-4ddf-adc9-58bf9ec0616d` | `0545a833-0b59-4c18-8919-5640c7912ecc` | `e0:19:95:21:5d:99` | `192.168.49.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 16 | `lrp-router-port_72e62619-8a96-4f15-bf23-e14f602a7423` | `2ee233dd-4d99-4198-8a29-eacb91aa1bbe` | `e0:19:95:8b:bd:df` | `192.168.17.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 17 | `lrp-router-port_398e6097-726d-4417-8d4e-a5b0e15f3387` | `687af993-8f90-4d57-8a33-42188b111a29` | `e0:19:95:af:e4:55` | `192.168.53.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 18 | `lrp-router-port_09083e0f-1d76-4a6f-aef8-282667aa110e` | `f65ff748-0838-4271-8a68-2706bfdc5284` | `e0:19:95:5d:25:5c` | `192.168.100.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 19 | `lrp-router-port_e65429bf-d32a-4274-8b35-39156398a0bb` | `30427c24-dbca-4f41-8a91-96fbe13afc89` | `e0:19:95:39:80:d0` | `192.168.3.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 20 | `lrp-router-port_ee90ab74-e669-4214-a816-de31615f8f40` | `26b2cd4c-8694-43ed-8b01-9485cf61d758` | `e0:19:95:52:02:d1` | `192.168.18.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 21 | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `62ccf088-8c87-48ec-8b68-4c4a6ccff023` | `e0:19:95:59:9f:05` | `192.168.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 22 | `lrp-router-port_91565e00-afaf-4848-b6c8-aadf55a89177` | `df63142c-e14a-491a-8cb3-37ab3cf5a8dd` | `e0:19:95:89:f9:5f` | `192.168.12.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 23 | `lrp-router-port_bcd3c336-727d-4cff-8741-76b3ab62c5f0` | `a464601b-26ab-4e9c-8cd3-059103a020d2` | `e0:19:95:ee:c5:d6` | `192.168.79.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 24 | `lrp-router-port_b6d9bfd6-dcf4-4ad2-bec7-fdac3c8c0901` | `0648ea03-0536-4291-8d5e-35dbf69e81a6` | `e0:19:95:15:6e:33` | `192.168.6.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 25 | `lrp-router-port_b7bbab8b-6c91-4ba1-86a1-7cbc2862b47a` | `7700a0f7-61bf-49b0-8d92-8deb67cb8fd1` | `e0:19:95:56:68:15` | `192.168.60.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 26 | `lrp-router-port_a6a82a86-eb1c-4ed7-81a0-138e06ac03ed` | `a8a3dfa6-43b8-4c63-8def-129e71303a7a` | `e0:19:95:46:b9:db` | `192.168.10.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 27 | `lrp-router-port_f6ad4655-b1dc-4ac8-92be-fb23f95e6e5c` | `c32f35c9-98f0-4811-8e19-644a4dcb44a7` | `e0:19:95:f8:27:ef` | `192.168.73.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 28 | `lrp-router-port_b156442e-c14c-4cee-bcf9-df780d716265` | `cb322ac4-6a7d-4549-8e23-3c06da773e2f` | `e0:19:95:3e:7f:be` | `192.168.50.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 29 | `lrp-router-port_03c2ec09-65c6-439a-8878-b987580c3924` | `1302f241-0856-4c93-8e2b-7066e870f0db` | `e0:19:95:61:0b:fb` | `192.168.41.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 30 | `lrp-router-port_691b4004-10b5-45ee-bbaa-f455fd574caa` | `df61ba73-10f2-40bf-8ffc-a20007295519` | `e0:19:95:61:46:00` | `192.168.61.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 31 | `lrp-router-port_731e491b-f5c9-4a91-a1fa-e5a623312321` | `8be0edca-af0b-4e9b-90cb-d32e1ea52414` | `e0:19:95:2a:a7:ea` | `192.168.5.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 32 | `lrp-router-port_30af069f-3873-406c-b618-1910068e78f6` | `7ba051ea-2148-438f-9272-f56dc6d42318` | `e0:19:95:88:28:38` | `192.168.31.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 33 | `lrp-router-port_ad47fb2b-5cf5-413b-9c84-708688d9bd34` | `b0abc6ad-db4d-4a8d-93bf-12e86370fb04` | `e0:19:95:6f:cb:8d` | `192.168.4.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 34 | `lrp-router-port_f4227f2b-0e70-4a07-a5f7-85f8ee92d9a4` | `70eafc87-f2b3-44b1-943d-9bc53ac20b02` | `e0:19:95:6a:19:8e` | `192.168.21.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 35 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `6ca4b6f3-615e-440b-9509-f0bae9fa92ae` | `e0:19:95:8d:46:1a` | `169.254.2.20/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 36 | `lrp-router-port_f4954815-1f1b-4f5a-9cb1-fe89ccbfed8a` | `7cd4dd6d-8a60-4f81-9624-672d137594e4` | `e0:19:95:74:a7:99` | `192.168.81.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 37 | `lrp-router-port_6ff10629-2c72-4efb-901d-eac2f09ba7ba` | `69c11b2a-570b-4d3f-9675-e1e410812178` | `e0:19:95:26:86:0b` | `192.168.36.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 38 | `lrp-router-port_58903cc2-b80a-47e0-83b0-c10a12478545` | `bb4efea6-7779-4b61-967f-41210ee092e9` | `e0:19:95:1c:64:43` | `192.168.14.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 39 | `lrp-router-port_de78f2f1-94a3-42b5-8736-68541ff9142a` | `3a86aae5-e8f2-475c-977e-d937826ced86` | `e0:19:95:7e:56:be` | `192.168.63.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 40 | `lrp-router-port_4e3981a3-4f75-439c-a5fa-f5ab9e9a2809` | `c1d9c0b3-f723-4b94-978a-7e6756ec51f9` | `e0:19:95:99:7d:6d` | `192.168.59.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 41 | `lrp-router-port_4f4768cb-67cc-482a-bccb-054c3cb73cd3` | `a00283e9-9d49-4983-97c6-28ba0603962b` | `e0:19:95:5f:be:05` | `192.168.88.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 42 | `lrp-router-port_a2ff46ff-216a-484b-ae3c-fa005b99a422` | `607a43e7-69f2-45a4-97dd-11011f90b70f` | `e0:19:95:84:72:2e` | `192.168.70.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 43 | `lrp-router-port_7b7ecd3c-2b5c-49ca-936f-ab79b67aea63` | `7a6a831c-2458-4b8f-98e1-0288698bb258` | `e0:19:95:21:5f:10` | `192.168.52.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 44 | `lrp-router-port_7b5bb2c4-526f-4300-9d11-338fe4083c58` | `21152ff1-720d-4d32-9a07-2324cf086bff` | `e0:19:95:2a:ff:d3` | `192.168.22.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 45 | `lrp-router-port_4732a674-e2c3-4a32-8b98-8d04ad8981e0` | `17988d81-2928-45a9-9a80-2edf76faaf62` | `e0:19:95:05:43:ed` | `192.168.15.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 46 | `lrp-router-port_a6bdf8cc-6ed7-4989-b7f5-33fd250b3be8` | `0fd2e091-9ee3-4e88-9b8a-3641be17b0fc` | `e0:19:95:f3:3e:cf` | `192.168.45.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 47 | `lrp-router-port_bfdb0087-699f-4cda-968a-c83f5c59a0e3` | `8fe2c5e6-db95-400c-9c57-f7f76badcffc` | `e0:19:95:cf:05:22` | `192.168.74.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 48 | `lrp-router-port_ba2f2f7b-819b-48e8-9873-3a8d03a4ccd8` | `17cd03dc-e2c8-45aa-9ce5-b6d5819d3622` | `e0:19:95:36:d7:11` | `192.168.13.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 49 | `lrp-router-port_dd8bd26a-26ac-4dce-ba1a-b013a8a2eaeb` | `2b95718e-60a7-4d54-9cfb-4dae09bac113` | `e0:19:95:d6:bf:b8` | `192.168.40.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 50 | `lrp-router-port_aaacea27-4b19-408b-b2a8-3ea5e8563bd8` | `43bb7dfe-8d72-45ed-9d40-51665fc9de55` | `e0:19:95:e0:5a:3c` | `192.168.29.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 51 | `lrp-router-port_6056da2d-7903-441e-9bad-f694d7c6efd6` | `7ba29460-8bff-4f6c-9d8e-3288cae7024a` | `e0:19:95:d3:17:89` | `192.168.16.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 52 | `lrp-router-port_8e2c5018-5789-4e8d-a0ca-de2aef90b054` | `4715b57f-cb32-4ffa-9dbf-746dbdcfdb29` | `e0:19:95:c8:9c:48` | `192.168.24.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 53 | `lrp-router-port_8aedd6c8-e897-4611-978e-c968c15eda92` | `9d507d16-5bba-48bf-9f49-1a0db886eaa0` | `e0:19:95:e8:38:9b` | `192.168.86.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 54 | `lrp-router-port_31f2dffa-1a77-4667-9df5-96ddbbb25998` | `46dacec5-595a-4981-9fcb-d02764c53c0b` | `e0:19:95:ad:8e:80` | `192.168.7.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 55 | `lrp-router-port_a26841c2-d315-4598-9d4e-b722e6b0740e` | `80787dc8-89cd-4341-a0b5-c748926d4a56` | `e0:19:95:7e:07:2e` | `192.168.75.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 56 | `lrp-router-port_98b8a929-e141-402b-8abd-cbafab4aad11` | `b75c7fd8-b0ae-4a1a-a0e6-21f49ff45749` | `e0:19:95:a5:0a:df` | `192.168.35.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 57 | `lrp-router-port_b5ac7378-d238-4655-bbcf-21965877290b` | `80fce37e-b24f-4a00-a125-cffc58307756` | `e0:19:95:13:20:17` | `192.168.55.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 58 | `lrp-router-port_ee75b808-37c3-48e3-b951-323cd7ce8623` | `47ca54b7-bfb0-40cd-a13e-61677b2e360d` | `e0:19:95:9a:16:b3` | `192.168.57.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 59 | `lrp-router-port_ec0d7873-0cec-4e0f-b521-fb87d4b8a5a2` | `38be4b24-8dd6-4eee-a183-a7ee1042ec0d` | `e0:19:95:03:46:c3` | `192.168.9.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 60 | `lrp-router-port_cd95a7dd-3a73-4f75-bdb7-cca39a8c349f` | `dc5025e8-2706-4b3c-a184-a5ed191976ab` | `e0:19:95:a6:fd:89` | `192.168.2.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 61 | `lrp-router-port_5536566e-9f0e-4b24-a74a-23b37e1a4cc9` | `1d33b72e-0dac-4485-a48f-620f790d050c` | `e0:19:95:e8:28:e5` | `192.168.92.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 62 | `lrp-router-port_7fa8249e-89c7-436c-b73c-fc1c6c35c8a2` | `9066107c-9159-4ff3-a58d-2400ac332891` | `e0:19:95:cf:3a:72` | `192.168.44.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 63 | `lrp-router-port_a6099d81-d558-4801-a626-e4b67e523609` | `46198781-f26b-4330-a598-842ddd4e3f62` | `e0:19:95:bb:e9:84` | `192.168.89.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 64 | `lrp-router-port_75dc71e6-0677-49f6-a6fc-1aba0dbcd96e` | `964fe22e-17d1-4dbb-a59b-4e4f2f8201c9` | `e0:19:95:98:b3:da` | `192.168.95.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 65 | `lrp-router-port_5f201938-3047-4926-83e7-a2ce47cf5323` | `c8f66473-fd25-44a9-a6ce-6b5bb777763e` | `e0:19:95:10:0e:fc` | `192.168.85.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 66 | `lrp-router-port_a8f4c5b9-8ed3-49c0-95a3-9fd9a367f8d5` | `80c816af-7743-4fd3-a869-f3dc00eb38de` | `e0:19:95:96:eb:72` | `192.168.71.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 67 | `lrp-router-port_d2c5df99-e81d-40e4-98da-6faaf1e56f02` | `ae3b445e-192d-4a9b-a897-4dd32f07fdf8` | `e0:19:95:ac:88:24` | `192.168.253.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 68 | `lrp-router-port_c2884fa3-9c1b-4775-b3f5-1c1d4fa0545a` | `0295ad20-3242-4472-a9d4-fd6cf42e33b9` | `e0:19:95:98:26:10` | `192.168.78.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 69 | `lrp-router-port_91a6ac0f-3bd8-4902-b3b2-b24dc0cbe78c` | `12d04eef-e817-4903-a9f8-2bc3e2b3c9e4` | `e0:19:95:81:1f:2d` | `192.168.34.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 70 | `lrp-router-port_8ffb4745-7439-4c63-8557-ac89ee2a67c1` | `aeb92a2c-61c7-4300-aa08-8de26ed2f7e4` | `e0:19:95:7f:f0:1d` | `192.168.19.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 71 | `lrp-router-port_aef08078-d157-4726-81f9-89a0740b2b75` | `2ed0304e-7c2b-4d6a-aa37-cc7621e8af30` | `e0:19:95:2d:62:4c` | `192.168.56.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 72 | `lrp-router-port_d8fbdfbb-d700-4bb6-acfa-cf2a4496eb77` | `4a59ccaf-922b-43cb-aafd-090a05dc4b53` | `e0:19:95:97:04:00` | `192.168.93.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 73 | `lrp-router-port_c3be4831-ac8f-46c1-b915-e7ff36a141c7` | `7bcb9a50-95b3-482e-ab2f-6028f3f421d9` | `e0:19:95:4f:f7:72` | `192.168.72.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 74 | `lrp-router-port_ae3f429f-f5b2-419b-85d5-7604d80d17be` | `3c4c8ed0-7da4-492c-ab91-e0fe153cd534` | `e0:19:95:f0:0c:48` | `192.168.27.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 75 | `lrp-router-port_26655dc6-20c7-46fc-afa1-6854ebb737b9` | `29dc7752-6e9b-4207-ac16-6ca33d4b3f4c` | `e0:19:95:04:e1:cc` | `192.168.96.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 76 | `lrp-router-port_7adec254-a0fd-4908-a1c8-0a5f43bb0639` | `7256f97c-cc27-4463-ad0f-9ee7b92439fb` | `e0:19:95:3d:d5:df` | `192.168.66.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 77 | `lrp-router-port_7fe3e8df-402c-43a6-9b89-9f2518963842` | `8bfa16d5-6c10-4fc5-aede-f4de5d2a6833` | `e0:19:95:a2:52:2a` | `192.168.20.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 78 | `lrp-router-port_27af2774-c142-4a05-8739-d78d1f02d22e` | `e3980676-46ba-42c0-af1c-4df22f5e4bbf` | `e0:19:95:8a:1e:cf` | `192.168.8.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 79 | `lrp-router-port_d5a053c9-426c-486c-bdd0-fab8ea9febb7` | `f4a72d66-f266-4fd8-b0de-d4802a48a103` | `e0:19:95:5e:56:4e` | `192.168.77.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 80 | `lrp-router-port_b5e6667d-3a04-4a97-8772-bbed3136b58a` | `74f62dd6-fa11-42c1-b122-7979e09219d6` | `e0:19:95:6b:59:f0` | `192.168.51.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 81 | `lrp-router-port_d0d67ec6-bc34-4470-9c4d-ae668c5bf7a2` | `ec6831d8-11cf-4366-b15a-6ac089949ef3` | `e0:19:95:6e:fc:63` | `192.168.99.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 82 | `lrp-router-port_951af33a-3f9c-43df-9489-8295a785bfff` | `08ad9c24-9c42-4a45-b16f-bc75a0f935c5` | `e0:19:95:43:99:15` | `192.168.11.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 83 | `lrp-router-port_0d9118a5-635c-4128-a672-8da5544f07da` | `b2b8b548-bb39-44ca-b179-79e27c6e58f7` | `e0:19:95:7c:cd:aa` | `192.168.97.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 84 | `lrp-router-port_8c51f88f-84a9-4bc6-91a3-d86fba6000eb` | `572f0fa5-86fc-464e-b18c-07e8dc89ace2` | `e0:19:95:0a:7a:ff` | `192.168.67.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 85 | `lrp-router-port_20a2dea6-ce0a-4ed1-a7c2-487f61008c87` | `bbeb457a-5d11-47ae-b1f9-a809e99ae285` | `e0:19:95:3f:16:2e` | `192.168.98.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 86 | `lrp-router-port_e71f71b1-e394-4035-b892-5474f450f7d7` | `c02496ca-0774-4d74-b275-398637b1fa61` | `e0:19:95:b8:2c:ac` | `192.168.84.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 87 | `lrp-router-port_724f58ea-11b2-49b7-96c5-cdc7e540cde1` | `07ca5d3e-ebe0-479e-b45e-56ad0c9127e8` | `e0:19:95:3e:01:ff` | `192.168.37.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 88 | `lrp-router-port_9088b9d8-aea5-4f6f-94f3-ddb503d57c45` | `5aed614b-a6a6-4a26-b497-e6a4cb311cbb` | `e0:19:95:55:b0:34` | `192.168.46.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 89 | `lrp-router-port_d3474aa1-21ac-4614-98b3-9578f293491d` | `9c3e3f20-78ab-4953-b651-3c5c635e86aa` | `e0:19:95:a1:ba:e5` | `192.168.30.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 90 | `lrp-router-port_4da00f14-4b97-492c-98f8-7cdee12d3f89` | `d0015b9e-6b63-4e73-b6cd-35c0a9269fb7` | `e0:19:95:95:ec:2a` | `192.168.69.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 91 | `lrp-router-port_e92240e5-8825-4ecf-aced-98081cbc3483` | `981798f5-ba26-4ee7-b8e9-07963d1ec9d4` | `e0:19:95:5e:e3:54` | `192.168.58.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 92 | `lrp-router-port_86dbbc63-cec8-4f84-b7c4-297def9ce02a` | `a79bf5e9-a0c5-42b6-b9fd-393cb1feb815` | `e0:19:95:45:b7:d4` | `192.168.62.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 93 | `lrp-router-port_2c813b95-2ea6-4ae9-8943-4915dcb03bf1` | `f49a6290-92cc-46e0-ba1e-4ac54a78e934` | `e0:19:95:3e:9b:37` | `192.168.65.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 94 | `lrp-router-port_d12a033b-c4fa-40fe-86d5-59e0204b99df` | `8a92498e-892e-4562-bab1-3199afb61bf3` | `e0:19:95:06:bf:e4` | `192.168.33.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 95 | `lrp-router-port_12116e83-b0e3-4db1-9e07-5da35760bd0a` | `8d49e600-290f-498e-bb15-97f882610cc1` | `e0:19:95:f3:7b:9a` | `192.168.83.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 96 | `lrp-router-port_31d327ab-cdfa-4e6a-bb41-de932541ebb4` | `2ad20d26-f301-40ca-bbac-cb80e6aeec89` | `e0:19:95:fa:6e:92` | `192.168.76.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 97 | `lrp-router-port_47c2c0c7-8697-4c67-bb84-d41d887af480` | `3fd55c58-d434-4757-bc24-73621eeaf972` | `e0:19:95:ba:80:ef` | `192.168.39.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 98 | `lrp-router-port_9ccef8d3-00c6-4419-83b1-f1630f89f70e` | `6cc86baa-cb56-426b-bd1a-007e59cd2cf6` | `e0:19:95:7a:78:e3` | `192.168.91.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 99 | `lrp-router-port_6c0558f1-f3b2-48fc-9770-5f2536efabb9` | `5d76b4df-8d6c-41a7-bd30-ea2599ca0701` | `e0:19:95:d0:ee:21` | `192.168.254.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 100 | `lrp-router-port_19e53512-d5ca-4400-a202-b4ecf350398a` | `cab3c6d6-8a91-41f5-bd3d-19c9fe8453ae` | `e0:19:95:6c:80:d7` | `192.168.94.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 101 | `lrp-router-port_f77b955e-d890-4442-aa17-e54663100cfb` | `104d274c-1180-4c54-bd96-25fa3ef2c320` | `e0:19:95:d8:28:84` | `192.168.23.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 102 | `lrp-router-port_50dd6605-d26f-461a-a825-6a585a416d5e` | `28e83fd2-1890-4872-bf1a-72b50f4daaa2` | `e0:19:95:3e:ea:3f` | `192.168.32.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 103 | `lrp-router-port_d0bbe94e-c02c-4978-a52d-6a1c31468ef9` | `03e2e174-7651-4b49-bf92-4ca90ff66829` | `e0:19:95:3e:c1:b0` | `192.168.43.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` uuid `f7e6f4bb-0dfd-40a3-8023-270912e79985`

```json
{
  "ls_uuid": "f7e6f4bb-0dfd-40a3-8023-270912e79985",
  "name": "gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
  "transit": true,
  "localnet": false,
  "datapath_uuid": "142ae345-5743-4655-b32e-857596482fb5",
  "tunnel_key": 45,
  "other_config": {},
  "external_ids": {
    "neutron:network_name": "gw-scale-out-network_nat_818b2c20-4d1b-40b7-a951-5deb85316e68"
  },
  "ports": [
    {
      "lsp_uuid": "69cb04a8-f3af-49c9-91da-856e0e850c52",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "18a748dc-09a5-42c5-9816-c6cb1f2a48a9",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "560df029-b486-43c8-b6bf-8efb33209f1c",
      "name": "gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 3
    }
  ]
}
```

Path LSPs — 3 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `69cb04a8-f3af-49c9-91da-856e0e850c52` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `18a748dc-09a5-42c5-9816-c6cb1f2a48a9` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 3 | router | `gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` | `560df029-b486-43c8-b6bf-8efb33209f1c` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` uuid `6572681a-8ffe-4fba-9263-8501622d7726`

```json
{
  "lr_uuid": "6572681a-8ffe-4fba-9263-8501622d7726",
  "name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0",
  "has_nat": true,
  "datapath_uuid": "5dbeea18-4571-4439-a5a7-f334ae8c699c",
  "tunnel_key": 105,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0"
  },
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `50e071f0-0ec8-4532-9132-241a776b2cde` | `e0:19:95:87:06:3b` | `169.254.2.100/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `9cc5a260-0c66-43b8-95be-0f18815bdda2` | `e0:19:95:14:17:37` | `10.116.246.47/18` | `` | yes | `b74195ce-8332-4bca-8057-10dc9c20cc30` |

##### Router (standby scale-out) `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` uuid `ce75ff4c-456e-4154-bab4-add0f3c5401f`

```json
{
  "lr_uuid": "ce75ff4c-456e-4154-bab4-add0f3c5401f",
  "name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1",
  "datapath_uuid": "343cd570-3b2c-4f79-a87f-81e7d877e697",
  "tunnel_key": 154,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1"
  },
  "ext_mac": "e0:19:95:5b:76:31",
  "ext_cidr": "10.116.246.48/18",
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d` | `7d613d5f-98e1-4cd8-9d33-21bf9b9e30b9` | `e0:19:95:5b:76:31` | `10.116.246.48/18` | `` | yes | `8c9aaafe-1bc2-43d0-af84-ec1e3c4f6d2c` |
| 2 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` | `6d52f0b1-a274-40c1-ba60-9c15ea3eddd0` | `e0:19:95:4b:de:17` | `169.254.2.101/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` uuid `43a3a38a-89e1-4410-8101-b255757c2f28`

```json
{
  "ls_uuid": "43a3a38a-89e1-4410-8101-b255757c2f28",
  "name": "network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a",
  "transit": false,
  "localnet": true,
  "datapath_uuid": "068f23c5-b151-4b7c-b29e-3693db43765a",
  "tunnel_key": 10105,
  "other_config": {
    "fdb_age_threshold": "300",
    "requested-tnl-key": "10105",
    "use-gateway-chassis": "true",
    "use-redirect-chassis": "true"
  },
  "external_ids": {
    "neutron:network_name": "network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"
  },
  "ports": [
    {
      "lsp_uuid": "f4fa863b-5594-45be-a7cc-5bf9f28a9ecd",
      "name": "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a",
      "type": "localnet",
      "mac": "",
      "ip": "",
      "addresses": [
        "unknown"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "b22162c5-e587-4890-8085-b76d293a76c2",
      "name": "ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 28
    },
    {
      "lsp_uuid": "04e3b382-2f5f-4040-8091-1e4312a40a4f",
      "name": "ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 36
    },
    {
      "lsp_uuid": "c2de99be-11a5-457f-8183-98226ad847ac",
      "name": "ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 57
    },
    {
      "lsp_uuid": "4405e7a2-e8a0-465f-8294-297c70606aae",
      "name": "ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 79
    },
    {
      "lsp_uuid": "4d199482-a59a-4e4a-8319-05e195ff321e",
      "name": "ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 72
    },
    {
      "lsp_uuid": "c4a2cf30-8309-4d49-8361-e2e488037ee6",
      "name": "ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 30
    },
    {
      "lsp_uuid": "c085d386-f0c8-4b7b-83c1-8a35a4a546f8",
      "name": "ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 101
    },
    {
      "lsp_uuid": "0e61cbbd-aab6-4884-83cf-2e78724f9b54",
      "name": "ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 40
    },
    {
      "lsp_uuid": "78aea322-f9b1-40af-8408-da0bed1cf133",
      "name": "ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 118
    },
    {
      "lsp_uuid": "82292c3d-d065-4e85-84ad-979b6cacac59",
      "name": "ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 10
    },
    {
      "lsp_uuid": "6cb9a15f-bd36-4b1b-84cb-700c64ab9f56",
      "name": "ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 32
    },
    {
      "lsp_uuid": "ab267d54-5904-4713-8537-ab044945cfc5",
      "name": "ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 113
    },
    {
      "lsp_uuid": "8158cd47-c722-46b3-854f-06c445d7d8f9",
      "name": "ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 83
    },
    {
      "lsp_uuid": "4455ba8e-a13a-4d92-856c-de3eb1e78a7d",
      "name": "ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 37
    },
    {
      "lsp_uuid": "9d5868fc-7ea8-407e-858e-cfed2707ad63",
      "name": "ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 112
    },
    {
      "lsp_uuid": "20f58a10-33ec-4de6-85bb-36165bfc4622",
      "name": "ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 20
    },
    {
      "lsp_uuid": "201b4c49-cd0a-4412-85cc-521bbb2f860d",
      "name": "ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 107
    },
    {
      "lsp_uuid": "99412605-21cd-4892-86a4-5176e78a7d2e",
      "name": "ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 33
    },
    {
      "lsp_uuid": "989e51e7-eaed-4cae-86eb-45d724d3ab4f",
      "name": "ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 49
    },
    {
      "lsp_uuid": "df4fe3e0-e864-4114-87e3-ab12c486461a",
      "name": "ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 120
    },
    {
      "lsp_uuid": "f43ea2e5-5f44-4199-8840-e49673530166",
      "name": "ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 51
    },
    {
      "lsp_uuid": "90088652-0ea3-46a5-8846-ee27f8322692",
      "name": "ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 105
    },
    {
      "lsp_uuid": "989f439e-ec40-4416-88e5-ec3aa44722c6",
      "name": "ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 103
    },
    {
      "lsp_uuid": "d6070400-dd17-4543-8926-fb3b1729f868",
      "name": "ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 50
    },
    {
      "lsp_uuid": "18bb547a-b8b1-4558-89d9-6b6a49014507",
      "name": "ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 106
    },
    {
      "lsp_uuid": "1583fc95-52a4-4160-8a3c-089dcb460db5",
      "name": "ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 54
    },
    {
      "lsp_uuid": "927dcc8b-a1f8-4da3-8bba-ec1b7de03407",
      "name": "ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 115
    },
    {
      "lsp_uuid": "36b08d86-9914-40fd-8bd8-3f2e7d998e25",
      "name": "ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 109
    },
    {
      "lsp_uuid": "1a3dfddd-497b-44d9-8d45-ffa6ffa9988c",
      "name": "ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 38
    },
    {
      "lsp_uuid": "66f4083d-010d-44bf-8d6c-39b30e075809",
      "name": "ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 5
    },
    {
      "lsp_uuid": "5d524534-92c4-475e-8df3-3b7087fe7b49",
      "name": "ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 61
    },
    {
      "lsp_uuid": "0d71ba7f-6a19-4cbe-8e95-2509fbc1e400",
      "name": "ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 74
    },
    {
      "lsp_uuid": "153ebc0e-92cf-4790-8eb9-52a23c0f98a1",
      "name": "ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5",
      "peer": "",
      "chassis_uuid": "2c14a1d7-8966-454c-add0-780ff2eb9e58",
      "hostname": "zadkiel04-2",
      "pb_tunnel_key": 22
    },
    {
      "lsp_uuid": "60b76970-d858-450a-8f25-32380ebc3395",
      "name": "ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 73
    },
    {
      "lsp_uuid": "e1a8e74b-a9db-455b-8f81-3b9717b6bdee",
      "name": "ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 58
    },
    {
      "lsp_uuid": "43331636-bf61-4f97-8fc9-96db066395dd",
      "name": "ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 42
    },
    {
      "lsp_uuid": "fe0ac9dc-0cc9-4604-90f4-20b749b552b1",
      "name": "ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 13
    },
    {
      "lsp_uuid": "e3ac9ca1-79c0-4d62-9202-5939fb359621",
      "name": "ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 29
    },
    {
      "lsp_uuid": "39e2d9a5-5b25-41b3-9241-11d065edaf58",
      "name": "ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 7
    },
    {
      "lsp_uuid": "0c341497-785b-4c04-929b-2a600d0dc4bd",
      "name": "ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 67
    },
    {
      "lsp_uuid": "d4f2a21c-172c-4b18-9308-cb5e1f51f916",
      "name": "ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 114
    },
    {
      "lsp_uuid": "e6460a46-863e-4eb3-9344-42fc2b298990",
      "name": "ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 27
    },
    {
      "lsp_uuid": "e43fcbec-a601-448d-9476-55b4ded3e871",
      "name": "ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 12
    },
    {
      "lsp_uuid": "27bd606d-2364-40ab-9537-7a9f4e60242c",
      "name": "ext_gw_port_304298e6-167f-4851-8079-de67d33a9012",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_304298e6-167f-4851-8079-de67d33a9012",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 102
    },
    {
      "lsp_uuid": "498c196d-ad22-4cb6-958c-3b7c43a2f4b5",
      "name": "ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 100
    },
    {
      "lsp_uuid": "d6c598db-0c85-452e-9670-776d1a6931b2",
      "name": "ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 121
    },
    {
      "lsp_uuid": "42f5ac1f-f9ba-415c-96ec-4caccf13dbde",
      "name": "ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 8
    },
    {
      "lsp_uuid": "b80685f3-c404-47c0-97de-4a5d277cbf5b",
      "name": "ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 70
    },
    {
      "lsp_uuid": "5c5e854a-ed46-49ef-98a0-5af79bdf16a1",
      "name": "ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 80
    },
    {
      "lsp_uuid": "021a0596-7f84-4e10-9988-056938036b3c",
      "name": "ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 16
    },
    {
      "lsp_uuid": "cff8f4b3-e387-476b-99d4-cedc44009909",
      "name": "ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 63
    },
    {
      "lsp_uuid": "20e8c7a4-8ca3-4208-9a51-6b5f87e9153e",
      "name": "ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 108
    },
    {
      "lsp_uuid": "b14ea735-a041-438c-9b8f-adcdb3ec8563",
      "name": "ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 77
    },
    {
      "lsp_uuid": "8b3826d1-e5c5-40fc-9c4e-4c9fa145813b",
      "name": "ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 17
    },
    {
      "lsp_uuid": "c9a732da-9258-4b46-9c80-0668c7f97895",
      "name": "ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 53
    },
    {
      "lsp_uuid": "3e7ff167-8192-4311-9cd4-7934c1ba62bd",
      "name": "ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 110
    },
    {
      "lsp_uuid": "8bf73314-806e-4676-9dab-efb758415c80",
      "name": "ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 11
    },
    {
      "lsp_uuid": "0adcc2d5-2ea3-4c07-9dc5-ef4a409b0109",
      "name": "ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 14
    },
    {
      "lsp_uuid": "d375a1a7-ffd7-44b6-9e71-157eb283d704",
      "name": "ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 65
    },
    {
      "lsp_uuid": "b170f977-8661-4642-9eca-297d78ae50d4",
      "name": "ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 35
    },
    {
      "lsp_uuid": "66d53fc9-2d9d-4de5-a093-00e34a346eed",
      "name": "ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 48
    },
    {
      "lsp_uuid": "32bb1d65-bd20-49e6-a0c1-180a8da45ea8",
      "name": "ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 24
    },
    {
      "lsp_uuid": "5ffd75ad-5796-4720-a0e3-4ac10529e035",
      "name": "ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 25
    },
    {
      "lsp_uuid": "e27a8b4d-d62d-472d-a14f-04a74712f6b2",
      "name": "ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4",
      "peer": "",
      "chassis_uuid": "0ac0e36a-7a86-49fb-92fd-cd7a62f64223",
      "hostname": "flashfire02-3",
      "pb_tunnel_key": 45
    },
    {
      "lsp_uuid": "a3537e9d-8e27-47fd-a1f3-3b708eed6e47",
      "name": "ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8",
      "peer": "",
      "chassis_uuid": "2c14a1d7-8966-454c-add0-780ff2eb9e58",
      "hostname": "zadkiel04-2",
      "pb_tunnel_key": 69
    },
    {
      "lsp_uuid": "241cca2e-41fc-4928-a44c-812ff094ddf8",
      "name": "ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 119
    },
    {
      "lsp_uuid": "88ba4c00-ee9e-4992-a4b8-1e48deed3350",
      "name": "ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 111
    },
    {
      "lsp_uuid": "617457c6-34a6-4687-a57d-d40d806a1c30",
      "name": "ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 62
    },
    {
      "lsp_uuid": "bd433961-36a5-44ba-a85a-a64e304b3069",
      "name": "ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 26
    },
    {
      "lsp_uuid": "d2abd2ee-06bd-4339-a8ca-51a4bbe40ff4",
      "name": "ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 116
    },
    {
      "lsp_uuid": "a6e4d0ac-66f7-4340-a964-884b44a27be0",
      "name": "ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 34
    },
    {
      "lsp_uuid": "2b111075-320b-4b57-a9de-7cf6d50ac0f1",
      "name": "ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 60
    },
    {
      "lsp_uuid": "26ea5e49-c7d5-4372-aa2c-1ee0b94f7f89",
      "name": "ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995",
      "peer": "",
      "chassis_uuid": "479280a7-6534-4919-b7aa-571179d31935",
      "hostname": "spymaster01-4",
      "pb_tunnel_key": 104
    },
    {
      "lsp_uuid": "80161cf8-9a96-4b68-ab0a-4e2d8723e724",
      "name": "ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 46
    },
    {
      "lsp_uuid": "9d3664d7-13f9-481d-ab80-1692fb8d0d34",
      "name": "ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 15
    },
    {
      "lsp_uuid": "cdff6077-d9d8-4e90-ab9d-56227b2013c0",
      "name": "ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 4
    },
    {
      "lsp_uuid": "1ebad8ae-47f5-4386-abf0-c6b2fad83a5e",
      "name": "ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 6
    },
    {
      "lsp_uuid": "597ee0ed-1b85-4929-ac2c-6fd90946af0f",
      "name": "ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 75
    },
    {
      "lsp_uuid": "91e979fd-c82a-410c-aed0-694cf5fe4131",
      "name": "ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 117
    },
    {
      "lsp_uuid": "74ed9666-a7be-4d79-b110-80363b9ee5a8",
      "name": "ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 18
    },
    {
      "lsp_uuid": "fd67c739-b765-41c5-b177-209180c441fa",
      "name": "ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 3
    },
    {
      "lsp_uuid": "9ffbc63e-e6bd-40f0-b231-3eef6a634103",
      "name": "ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 84
    },
    {
      "lsp_uuid": "5eb5fc46-ebeb-4f44-b26f-faace424d0ad",
      "name": "ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 68
    },
    {
      "lsp_uuid": "9ba85068-2be3-4923-b3ce-1472a8a26f2b",
      "name": "ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 9
    },
    {
      "lsp_uuid": "4101c6f5-65a8-497c-b532-a0d6ec411bca",
      "name": "ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 52
    },
    {
      "lsp_uuid": "f2bad144-e0bb-4c43-b583-876d3080e7e6",
      "name": "ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0",
      "peer": "",
      "chassis_uuid": "e6226ec1-fa8f-41e5-8d0c-7a884b7f9634",
      "hostname": "zadkiel04-3",
      "pb_tunnel_key": 47
    },
    {
      "lsp_uuid": "7b5172c3-0539-4d1e-b5dc-614f3822ed02",
      "name": "ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 23
    },
    {
      "lsp_uuid": "b42ba710-d879-4c62-b755-28fab485a81e",
      "name": "ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 56
    },
    {
      "lsp_uuid": "edb66f57-a291-429b-b92d-4d064fbf6dd7",
      "name": "ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f",
      "peer": "",
      "chassis_uuid": "f1765be8-a221-47b1-87ae-542158a5ad77",
      "hostname": "spymaster01-1",
      "pb_tunnel_key": 59
    },
    {
      "lsp_uuid": "e6f40ce8-4bc8-47fb-b968-2d59a7d24b4a",
      "name": "ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 19
    },
    {
      "lsp_uuid": "90b97bb3-81e7-44e9-bb7a-ff26220a911e",
      "name": "ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458",
      "peer": "",
      "chassis_uuid": "74e0be63-f78f-482a-b04e-a09ada933f20",
      "hostname": "flashfire01-2",
      "pb_tunnel_key": 76
    },
    {
      "lsp_uuid": "58597c91-a41b-42e5-bcb4-e95dc760c6cb",
      "name": "ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 44
    },
    {
      "lsp_uuid": "ec6b0017-7cd4-4ad4-bd63-7cc7bb43af37",
      "name": "ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3",
      "peer": "",
      "chassis_uuid": "b594f638-f4a0-439b-91d4-1c513f0c4529",
      "hostname": "zadkiel04-1",
      "pb_tunnel_key": 31
    },
    {
      "lsp_uuid": "c753a8a3-9628-4c23-bd9c-f91732baa7eb",
      "name": "ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79",
      "peer": "",
      "chassis_uuid": "8ea4717f-7bab-451e-95de-4f193fab4b91",
      "hostname": "flashfire02-2",
      "pb_tunnel_key": 43
    },
    {
      "lsp_uuid": "17c4e3d1-2ef2-4d7a-be2e-84d46f895f0b",
      "name": "ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d",
      "peer": "",
      "chassis_uuid": "e537d72a-6c1a-4f4c-98eb-5eb6a0de2ae0",
      "hostname": "flashfire02-1",
      "pb_tunnel_key": 55
    },
    {
      "lsp_uuid": "e4f00edb-4fd5-4afd-be64-a16ab449a4db",
      "name": "ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738",
      "peer": "",
      "chassis_uuid": "314c08ea-754f-4a17-ac82-51146c0b80b0",
      "hostname": "flashfire01-3",
      "pb_tunnel_key": 39
    },
    {
      "lsp_uuid": "1bd77ae1-06de-4cab-be8d-8a5c02067341",
      "name": "ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97",
      "peer": "",
      "chassis_uuid": "c610447f-a2c5-49a7-aeab-654ce28c7668",
      "hostname": "spymaster01-3",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "d1571ad3-856f-406b-bef4-0defdd0874d8",
      "name": "ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c",
      "peer": "",
      "chassis_uuid": "bbd822da-f0b1-4a7d-a894-df4029cfb598",
      "hostname": "spymaster01-2",
      "pb_tunnel_key": 64
    },
    {
      "lsp_uuid": "34d56a59-83c0-4859-bf26-3bc428958697",
      "name": "ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8",
      "peer": "",
      "chassis_uuid": "1751256c-4902-478d-9ba1-d65f7d343129",
      "hostname": "flashfire01-1",
      "pb_tunnel_key": 21
    },
    {
      "lsp_uuid": "1ab98f2a-f5ac-42b8-bfaa-543ce76a1a82",
      "name": "ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f",
      "peer": "",
      "chassis_uuid": "e9033164-8403-4900-a816-ee61b6146fbe",
      "hostname": "flashfire02-4",
      "pb_tunnel_key": 41
    }
  ]
}
```

Path LSPs — 101 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | localnet | `localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` | `f4fa863b-5594-45be-a7cc-5bf9f28a9ecd` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `ext_gw_port_f5222cee-06cb-49e9-ad28-a5d978c59075` | `b22162c5-e587-4890-8085-b76d293a76c2` | `` | `` | `spymaster01-3` |
| 3 | router | `ext_gw_port_c2d78b41-8cd9-4842-8367-4091d6a65141` | `04e3b382-2f5f-4040-8091-1e4312a40a4f` | `` | `` | `flashfire01-3` |
| 4 | router | `ext_gw_port_172fbb16-02d5-41ab-88d6-37d5c4131be8` | `c2de99be-11a5-457f-8183-98226ad847ac` | `` | `` | `spymaster01-1` |
| 5 | router | `ext_gw_port_1f6f6478-5134-4f60-b62d-010b4debb769` | `4405e7a2-e8a0-465f-8294-297c70606aae` | `` | `` | `spymaster01-4` |
| 6 | router | `ext_gw_port_ac7bf0cf-4936-42da-a5d1-b16f54343c11` | `4d199482-a59a-4e4a-8319-05e195ff321e` | `` | `` | `spymaster01-2` |
| 7 | router | `ext_gw_port_54b16241-e05c-4c70-a6d1-d1613f7a0b93` | `c4a2cf30-8309-4d49-8361-e2e488037ee6` | `` | `` | `flashfire01-2` |
| 8 | router | `ext_gw_port_321d6da0-4c97-4ca9-9dc2-c78524033eb9` | `c085d386-f0c8-4b7b-83c1-8a35a4a546f8` | `` | `` | `spymaster01-4` |
| 9 | router | `ext_gw_port_ec3d2ea9-1799-43c2-a520-6a417295facc` | `0e61cbbd-aab6-4884-83cf-2e78724f9b54` | `` | `` | `flashfire01-2` |
| 10 | router | `ext_gw_port_7cc37782-3508-4cd0-8ef5-375e4d2d0bbc` | `78aea322-f9b1-40af-8408-da0bed1cf133` | `` | `` | `flashfire01-3` |
| 11 | router | `ext_gw_port_f243396a-1d5d-433b-aefd-345e5629869a` | `82292c3d-d065-4e85-84ad-979b6cacac59` | `` | `` | `flashfire01-3` |
| 12 | router | `ext_gw_port_9d5d3136-0048-4eff-afef-c0046ff990ac` | `6cb9a15f-bd36-4b1b-84cb-700c64ab9f56` | `` | `` | `flashfire02-1` |
| 13 | router | `ext_gw_port_4ae96839-ebdc-4dcf-8236-634f379ea9c5` | `ab267d54-5904-4713-8537-ab044945cfc5` | `` | `` | `flashfire02-1` |
| 14 | router | `ext_gw_port_86231676-5157-4b9d-90de-e496fc451c6a` | `8158cd47-c722-46b3-854f-06c445d7d8f9` | `` | `` | `flashfire01-2` |
| 15 | router | `ext_gw_port_57901b56-b34e-4a2d-9f2f-7725a3f1b54e` | `4455ba8e-a13a-4d92-856c-de3eb1e78a7d` | `` | `` | `flashfire02-1` |
| 16 | router | `ext_gw_port_ef07a6f2-90b9-4449-8759-6ae55345b7bb` | `9d5868fc-7ea8-407e-858e-cfed2707ad63` | `` | `` | `spymaster01-3` |
| 17 | router | `ext_gw_port_dd302972-c253-4878-ad2a-fe99b24b6fd2` | `20f58a10-33ec-4de6-85bb-36165bfc4622` | `` | `` | `spymaster01-3` |
| 18 | router | `ext_gw_port_9b705763-6ad2-4d1e-acf7-6115bfcc7fc2` | `201b4c49-cd0a-4412-85cc-521bbb2f860d` | `` | `` | `flashfire01-1` |
| 19 | router | `ext_gw_port_68f155d6-f38e-4cf9-a6f6-490866a146bd` | `99412605-21cd-4892-86a4-5176e78a7d2e` | `` | `` | `flashfire02-4` |
| 20 | router | `ext_gw_port_b0b81ee0-9a75-4726-9e25-dbf60e030e52` | `989e51e7-eaed-4cae-86eb-45d724d3ab4f` | `` | `` | `flashfire01-2` |
| 21 | router | `ext_gw_port_301bc557-a6ce-4754-8422-b689a8d9acdd` | `df4fe3e0-e864-4114-87e3-ab12c486461a` | `` | `` | `flashfire02-1` |
| 22 | router | `ext_gw_port_d204386c-baf4-4bed-ba65-e6125081238c` | `f43ea2e5-5f44-4199-8840-e49673530166` | `` | `` | `flashfire01-1` |
| 23 | router | `ext_gw_port_a1dba5af-8ffa-44b9-a290-74ad152fb2c6` | `90088652-0ea3-46a5-8846-ee27f8322692` | `` | `` | `flashfire02-3` |
| 24 | router | `ext_gw_port_947c4646-af77-47bf-bdd9-31aca451efae` | `989f439e-ec40-4416-88e5-ec3aa44722c6` | `` | `` | `flashfire01-2` |
| 25 | router | `ext_gw_port_623ad20b-19b3-4647-a9c6-21361380170c` | `d6070400-dd17-4543-8926-fb3b1729f868` | `` | `` | `flashfire02-1` |
| 26 | router | `ext_gw_port_3c59dd12-a46a-44bc-887a-7a480bd22d43` | `18bb547a-b8b1-4558-89d9-6b6a49014507` | `` | `` | `flashfire01-2` |
| 27 | router | `ext_gw_port_f6d82a0f-5916-49d5-babd-f34edaf33fcc` | `1583fc95-52a4-4160-8a3c-089dcb460db5` | `` | `` | `flashfire02-4` |
| 28 | router | `ext_gw_port_53bcecf8-0e5e-46b1-923b-05add1ff3c15` | `927dcc8b-a1f8-4da3-8bba-ec1b7de03407` | `` | `` | `zadkiel04-3` |
| 29 | router | `ext_gw_port_740dcf5b-7ea4-4a3c-9306-511f5758d571` | `36b08d86-9914-40fd-8bd8-3f2e7d998e25` | `` | `` | `spymaster01-3` |
| 30 | router | `ext_gw_port_39c31b32-31d2-4f9a-adcd-5b845819333d` | `1a3dfddd-497b-44d9-8d45-ffa6ffa9988c` | `` | `` | `flashfire02-4` |
| 31 | router | `ext_gw_port_66ebd093-6129-4bd3-b43c-f9604ea6a955` | `66f4083d-010d-44bf-8d6c-39b30e075809` | `` | `` | `spymaster01-1` |
| 32 | router | `ext_gw_port_c4bdbf8c-3eb3-4f56-96e5-ebc6525c9acd` | `5d524534-92c4-475e-8df3-3b7087fe7b49` | `` | `` | `flashfire01-1` |
| 33 | router | `ext_gw_port_a428d1ff-92be-4967-a954-3ad2a78f5526` | `0d71ba7f-6a19-4cbe-8e95-2509fbc1e400` | `` | `` | `flashfire01-3` |
| 34 | router | `ext_gw_port_c4e233fc-0357-4655-b34c-70affa5b06b5` | `153ebc0e-92cf-4790-8eb9-52a23c0f98a1` | `` | `` | `zadkiel04-2` |
| 35 | router | `ext_gw_port_d17ac9c9-90fd-43d3-b9d6-9899be08762b` | `60b76970-d858-450a-8f25-32380ebc3395` | `` | `` | `flashfire01-1` |
| 36 | router | `ext_gw_port_e1d8ced5-debf-4be4-8634-3a74194e2ab9` | `e1a8e74b-a9db-455b-8f81-3b9717b6bdee` | `` | `` | `flashfire01-2` |
| 37 | router | `ext_gw_port_23f15969-b70c-43d5-947f-53917b81098d` | `43331636-bf61-4f97-8fc9-96db066395dd` | `` | `` | `flashfire01-1` |
| 38 | router | `ext_gw_port_eee40fc0-bc4a-4270-8c8f-f00d64ff0e6b` | `fe0ac9dc-0cc9-4604-90f4-20b749b552b1` | `` | `` | `flashfire01-1` |
| 39 | router | `ext_gw_port_a9856577-cd74-47bb-a1e2-23ab5a2008e7` | `e3ac9ca1-79c0-4d62-9202-5939fb359621` | `` | `` | `flashfire02-4` |
| 40 | router | `ext_gw_port_967b0ae4-5e6d-4487-8da4-b1f251ee3dda` | `39e2d9a5-5b25-41b3-9241-11d065edaf58` | `` | `` | `flashfire01-1` |
| 41 | router | `ext_gw_port_59726804-fb98-41bf-918a-eb83d4d20d8b` | `0c341497-785b-4c04-929b-2a600d0dc4bd` | `` | `` | `flashfire02-4` |
| 42 | router | `ext_gw_port_38eac00c-5f85-4525-be28-a92b5280ab4a` | `d4f2a21c-172c-4b18-9308-cb5e1f51f916` | `` | `` | `spymaster01-4` |
| 43 | router | `ext_gw_port_7e99de2a-fbbf-40f1-8f4b-1361b6b2a977` | `e6460a46-863e-4eb3-9344-42fc2b298990` | `` | `` | `zadkiel04-3` |
| 44 | router | `ext_gw_port_3ca3459d-4a03-4f13-beb0-6c52b1d93bdd` | `e43fcbec-a601-448d-9476-55b4ded3e871` | `` | `` | `flashfire01-1` |
| 45 | router | `ext_gw_port_304298e6-167f-4851-8079-de67d33a9012` | `27bd606d-2364-40ab-9537-7a9f4e60242c` | `` | `` | `flashfire02-1` |
| 46 | router | `ext_gw_port_3c967ee6-1cba-4958-b407-21524aace268` | `498c196d-ad22-4cb6-958c-3b7c43a2f4b5` | `` | `` | `zadkiel04-1` |
| 47 | router | `ext_gw_port_33cbcdd9-14fd-47fb-b866-602194e6bf50` | `d6c598db-0c85-452e-9670-776d1a6931b2` | `` | `` | `flashfire01-2` |
| 48 | router | `ext_gw_port_26923114-d87b-4215-bc80-d9e743c98cd4` | `42f5ac1f-f9ba-415c-96ec-4caccf13dbde` | `` | `` | `spymaster01-3` |
| 49 | router | `ext_gw_port_bb1cf505-df38-41d0-a9a9-efa26697eae5` | `b80685f3-c404-47c0-97de-4a5d277cbf5b` | `` | `` | `spymaster01-2` |
| 50 | router | `ext_gw_port_ff477bd8-f43b-4edf-b384-5c9c81dbb8ee` | `5c5e854a-ed46-49ef-98a0-5af79bdf16a1` | `` | `` | `flashfire02-3` |
| 51 | router | `ext_gw_port_8d3c8220-0f5d-4c88-8e62-ef782568d423` | `021a0596-7f84-4e10-9988-056938036b3c` | `` | `` | `flashfire01-3` |
| 52 | router | `ext_gw_port_2c9a8843-cf74-4169-85c4-1c5469ec1ba3` | `cff8f4b3-e387-476b-99d4-cedc44009909` | `` | `` | `flashfire02-2` |
| 53 | router | `ext_gw_port_6e9015dd-c863-40d0-81d2-ce770fa77ab7` | `20e8c7a4-8ca3-4208-9a51-6b5f87e9153e` | `` | `` | `spymaster01-4` |
| 54 | router | `ext_gw_port_105164f7-3791-4f02-b507-584b47eb8cb0` | `b14ea735-a041-438c-9b8f-adcdb3ec8563` | `` | `` | `flashfire02-1` |
| 55 | router | `ext_gw_port_3469b089-0b30-4fb2-8955-ceaf61fad6ee` | `8b3826d1-e5c5-40fc-9c4e-4c9fa145813b` | `` | `` | `flashfire02-1` |
| 56 | router | `ext_gw_port_1774b892-a0ff-41b4-a7eb-63be0d50d5f4` | `c9a732da-9258-4b46-9c80-0668c7f97895` | `` | `` | `flashfire02-1` |
| 57 | router | `ext_gw_port_46f7d252-c430-4248-83dc-68cea5bd7fd1` | `3e7ff167-8192-4311-9cd4-7934c1ba62bd` | `` | `` | `flashfire02-1` |
| 58 | router | `ext_gw_port_a236b124-7c00-4896-bc8b-97c6e4993e1b` | `8bf73314-806e-4676-9dab-efb758415c80` | `` | `` | `zadkiel04-3` |
| 59 | router | `ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26` | `0adcc2d5-2ea3-4c07-9dc5-ef4a409b0109` | `` | `` | `flashfire01-2` |
| 60 | router | `ext_gw_port_bd4ecdb4-4168-4c1b-8494-b58f7312ca41` | `d375a1a7-ffd7-44b6-9e71-157eb283d704` | `` | `` | `spymaster01-4` |
| 61 | router | `ext_gw_port_a1bbae8a-f65e-4581-84a2-157671b66ac2` | `b170f977-8661-4642-9eca-297d78ae50d4` | `` | `` | `spymaster01-1` |
| 62 | router | `ext_gw_port_06be7788-2481-4085-a33e-fa0b906bbfa5` | `66d53fc9-2d9d-4de5-a093-00e34a346eed` | `` | `` | `spymaster01-2` |
| 63 | router | `ext_gw_port_6e2f8f32-8140-47bf-8468-f76a3c0ab751` | `32bb1d65-bd20-49e6-a0c1-180a8da45ea8` | `` | `` | `spymaster01-4` |
| 64 | router | `ext_gw_port_e8da5408-0502-4821-b58b-bda2159e2f71` | `5ffd75ad-5796-4720-a0e3-4ac10529e035` | `` | `` | `zadkiel04-1` |
| 65 | router | `ext_gw_port_4c299ca8-0567-493b-a6c6-938ee4b750a4` | `e27a8b4d-d62d-472d-a14f-04a74712f6b2` | `` | `` | `flashfire02-3` |
| 66 | router | `ext_gw_port_f99d67c4-afe6-4194-89b2-8b9b3c7085a8` | `a3537e9d-8e27-47fd-a1f3-3b708eed6e47` | `` | `` | `zadkiel04-2` |
| 67 | router | `ext_gw_port_22b11baa-8164-40fd-b285-2b603244086d` | `241cca2e-41fc-4928-a44c-812ff094ddf8` | `` | `` | `flashfire01-2` |
| 68 | router | `ext_gw_port_93ab1154-a632-4777-909d-b6cc0f5b13a3` | `88ba4c00-ee9e-4992-a4b8-1e48deed3350` | `` | `` | `flashfire01-2` |
| 69 | router | `ext_gw_port_e1ddef4a-88ee-47d7-9e7e-94f61ad0c813` | `617457c6-34a6-4687-a57d-d40d806a1c30` | `` | `` | `flashfire02-1` |
| 70 | router | `ext_gw_port_3fdabba1-ec63-40ca-83ba-f4549b8953db` | `bd433961-36a5-44ba-a85a-a64e304b3069` | `` | `` | `flashfire02-1` |
| 71 | router | `ext_gw_port_237ab00c-c500-4e40-a20b-f55f2babbf81` | `d2abd2ee-06bd-4339-a8ca-51a4bbe40ff4` | `` | `` | `flashfire02-4` |
| 72 | router | `ext_gw_port_0092d0e0-8a71-40ac-b406-36a6b1cf2ffd` | `a6e4d0ac-66f7-4340-a964-884b44a27be0` | `` | `` | `flashfire01-2` |
| 73 | router | `ext_gw_port_3fbbf574-b83f-4ea2-a054-f2f3d0564509` | `2b111075-320b-4b57-a9de-7cf6d50ac0f1` | `` | `` | `flashfire01-1` |
| 74 | router | `ext_gw_port_af5903c6-ee1a-4bdf-85bc-d5fa85611995` | `26ea5e49-c7d5-4372-aa2c-1ee0b94f7f89` | `` | `` | `spymaster01-4` |
| 75 | router | `ext_gw_port_64d54626-3459-4b9f-947a-0d95e9fb475d` | `80161cf8-9a96-4b68-ab0a-4e2d8723e724` | `` | `` | `flashfire01-2` |
| 76 | router | `ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `9d3664d7-13f9-481d-ab80-1692fb8d0d34` | `` | `` | `zadkiel04-1` |
| 77 | router | `ext_gw_port_5fde242e-1c70-4718-b324-e7dc5804a475` | `cdff6077-d9d8-4e90-ab9d-56227b2013c0` | `` | `` | `zadkiel04-1` |
| 78 | router | `ext_gw_port_a5c3db29-3661-48c9-a001-dfd3b1d3db10` | `1ebad8ae-47f5-4386-abf0-c6b2fad83a5e` | `` | `` | `flashfire02-1` |
| 79 | router | `ext_gw_port_5b9f3734-155f-401e-ac67-4a4be6efc8d6` | `597ee0ed-1b85-4929-ac2c-6fd90946af0f` | `` | `` | `flashfire02-1` |
| 80 | router | `ext_gw_port_ce7feac4-a0da-4d0e-9326-702e3bd39252` | `91e979fd-c82a-410c-aed0-694cf5fe4131` | `` | `` | `flashfire01-2` |
| 81 | router | `ext_gw_port_ac9dab3a-c23a-495c-820d-d858f186ccad` | `74ed9666-a7be-4d79-b110-80363b9ee5a8` | `` | `` | `flashfire02-2` |
| 82 | router | `ext_gw_port_64b613ed-a152-4af9-8506-886ef6cfc856` | `fd67c739-b765-41c5-b177-209180c441fa` | `` | `` | `spymaster01-1` |
| 83 | router | `ext_gw_port_a8294cc6-db30-4efd-9132-4c48202e916c` | `9ffbc63e-e6bd-40f0-b231-3eef6a634103` | `` | `` | `zadkiel04-1` |
| 84 | router | `ext_gw_port_1531d26e-22aa-4c9c-b14d-5a5e91ea1a93` | `5eb5fc46-ebeb-4f44-b26f-faace424d0ad` | `` | `` | `zadkiel04-1` |
| 85 | router | `ext_gw_port_17fcb5bf-f98a-46b2-8399-992cf8a4fa7e` | `9ba85068-2be3-4923-b3ce-1472a8a26f2b` | `` | `` | `spymaster01-2` |
| 86 | router | `ext_gw_port_afeea6ec-3e63-420d-aacf-ad10560fb2fb` | `4101c6f5-65a8-497c-b532-a0d6ec411bca` | `` | `` | `flashfire01-1` |
| 87 | router | `ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `f2bad144-e0bb-4c43-b583-876d3080e7e6` | `` | `` | `zadkiel04-3` |
| 88 | router | `ext_gw_port_0fab4d31-5d27-450b-a20b-fd853cf40eb7` | `7b5172c3-0539-4d1e-b5dc-614f3822ed02` | `` | `` | `flashfire01-2` |
| 89 | router | `ext_gw_port_7c562bd3-c494-4009-98f3-60a8a313f349` | `b42ba710-d879-4c62-b755-28fab485a81e` | `` | `` | `flashfire01-2` |
| 90 | router | `ext_gw_port_41dbb601-90fb-4f4f-8e35-3473cde5de9f` | `edb66f57-a291-429b-b92d-4d064fbf6dd7` | `` | `` | `spymaster01-1` |
| 91 | router | `ext_gw_port_748384f1-a3ae-486b-aead-d1c3ce2e7a91` | `e6f40ce8-4bc8-47fb-b968-2d59a7d24b4a` | `` | `` | `flashfire02-1` |
| 92 | router | `ext_gw_port_845cd009-c029-4645-ab2f-88f623d7d458` | `90b97bb3-81e7-44e9-bb7a-ff26220a911e` | `` | `` | `flashfire01-2` |
| 93 | router | `ext_gw_port_c782b8e8-7849-48c4-b46e-2bf44ea00dc0` | `58597c91-a41b-42e5-bcb4-e95dc760c6cb` | `` | `` | `flashfire02-1` |
| 94 | router | `ext_gw_port_0c577f5a-1970-4b7a-bae1-6d72d9c278f3` | `ec6b0017-7cd4-4ad4-bd63-7cc7bb43af37` | `` | `` | `zadkiel04-1` |
| 95 | router | `ext_gw_port_e198e5b0-5406-4e77-a0e0-20ce0785ac79` | `c753a8a3-9628-4c23-bd9c-f91732baa7eb` | `` | `` | `flashfire02-2` |
| 96 | router | `ext_gw_port_26179723-6633-4cf1-8d8a-87d68c6d211d` | `17c4e3d1-2ef2-4d7a-be2e-84d46f895f0b` | `` | `` | `flashfire02-1` |
| 97 | router | `ext_gw_port_a569929d-b5fc-4de7-8ded-82479484e738` | `e4f00edb-4fd5-4afd-be64-a16ab449a4db` | `` | `` | `flashfire01-3` |
| 98 | router | `ext_gw_port_c3010982-e897-4faf-9cfe-523fcbfd8e97` | `1bd77ae1-06de-4cab-be8d-8a5c02067341` | `` | `` | `spymaster01-3` |
| 99 | router | `ext_gw_port_98e34538-9bd0-450f-a20e-e6df9855700c` | `d1571ad3-856f-406b-bef4-0defdd0874d8` | `` | `` | `spymaster01-2` |
| 100 | router | `ext_gw_port_b89d5219-4327-4e2a-abfb-23e7ecee11d8` | `34d56a59-83c0-4859-bf26-3bc428958697` | `` | `` | `flashfire01-1` |
| 101 | router | `ext_gw_port_8440af58-3c9f-4815-a243-f62439e5d24f` | `1ab98f2a-f5ac-42b8-bfaa-543ce76a1a82` | `` | `` | `flashfire02-4` |

##### Router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` uuid `edba0385-d5d3-4d07-8ca5-f9253e4af298`

```json
{
  "lr_uuid": "edba0385-d5d3-4d07-8ca5-f9253e4af298",
  "name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
  "has_nat": true,
  "datapath_uuid": "471c4d36-6dbb-49ed-8ff4-c4552d7a57a0",
  "tunnel_key": 33,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1"
  },
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `b3f1099a-b8ad-4bbe-962f-05cc5b4a3511` | `e0:19:95:9b:58:bb` | `10.116.246.55/18` | `` | yes | `4ed92972-5ec0-4c25-893d-6d5ef42551c7` |
| 2 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `5d3e7d2c-6a4f-4f15-ac5d-f698ccb2162d` | `e0:19:95:60:29:5b` | `169.254.2.101/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Router (standby scale-out) `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` uuid `f75fea9a-563e-474b-bdc0-08683ebd3842`

```json
{
  "lr_uuid": "f75fea9a-563e-474b-bdc0-08683ebd3842",
  "name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
  "datapath_uuid": "83526036-f5b1-463f-a72d-2363389bf512",
  "tunnel_key": 63,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400"
  },
  "external_ids": {
    "neutron:router_name": "gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0"
  },
  "ext_mac": "e0:19:95:c0:b3:04",
  "ext_cidr": "10.116.246.54/18",
  "lrp_count": 2
}
```

Every LRP — 2 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` | `02a3eba2-e737-4eb0-85f6-2e7d203b7aaf` | `e0:19:95:8d:49:e8` | `169.254.2.100/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-ext_gw_port_89d45665-a752-4622-899e-ff7f2889fa26` | `f0923e0b-40f2-49f3-bf4e-8dab34f0fb23` | `e0:19:95:c0:b3:04` | `10.116.246.54/18` | `` | yes | `86d08eb2-d621-441e-bf3b-2cfb6e6d7595` |

##### Switch `gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `df8dadd4-7138-4ea7-95da-15fab0b6838c`

```json
{
  "ls_uuid": "df8dadd4-7138-4ea7-95da-15fab0b6838c",
  "name": "gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
  "transit": true,
  "localnet": false,
  "datapath_uuid": "8ba15c30-c06f-4057-9b02-17415e5b45cd",
  "tunnel_key": 13,
  "other_config": {},
  "external_ids": {
    "neutron:network_name": "gw-scale-out-network_nat_fc433064-926d-4fc0-a1a3-7c089ad90343"
  },
  "ports": [
    {
      "lsp_uuid": "2e5f3f25-7a44-4e2d-8837-ec9ee315a26b",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    },
    {
      "lsp_uuid": "4d5e629c-a83e-49b6-a2df-e672399326b1",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 2
    },
    {
      "lsp_uuid": "51e2887a-f678-466c-bee8-7a80e658e3d2",
      "name": "gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 3
    }
  ]
}
```

Path LSPs — 3 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `2e5f3f25-7a44-4e2d-8837-ec9ee315a26b` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 2 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `4d5e629c-a83e-49b6-a2df-e672399326b1` | `` | `` | `00000000-0000-0000-0000-000000000000` |
| 3 | router | `gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` | `51e2887a-f678-466c-bee8-7a80e658e3d2` | `` | `` | `00000000-0000-0000-0000-000000000000` |

##### Router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` uuid `cb58bbb0-4bdc-429e-9378-838e204b99f1`

```json
{
  "lr_uuid": "cb58bbb0-4bdc-429e-9378-838e204b99f1",
  "name": "router_fc433064-926d-4fc0-a1a3-7c089ad90343",
  "has_nat": false,
  "datapath_uuid": "6ebe35ee-be81-4e57-8439-8fa1f83e557f",
  "tunnel_key": 10110,
  "options": {
    "always_learn_from_arp_request": "false",
    "dynamic_neigh_routers": "true",
    "mac_binding_age_threshold": "10.116.192.1/32:0;169.254.2.0/24:0;14400",
    "requested-tnl-key": "10110"
  },
  "external_ids": {
    "neutron:router_name": "router_fc433064-926d-4fc0-a1a3-7c089ad90343"
  },
  "lrp_count": 104
}
```

Every LRP — 104 rows
| # | lrp | uuid | mac | cidr | peer | ext_gw | ha_group |
|---|-----|------|-----|------|------|--------|----------|
| 1 | `lrp-router-port_8ca6f7a0-3f82-4de7-911b-f1e92b5ec140` | `64233e11-9c0b-4555-80ef-22cf6b6f4814` | `e0:19:95:56:6a:af` | `192.168.93.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 2 | `lrp-router-port_e03534c4-e36c-4067-9f9d-459ce653637d` | `a5b8e793-495b-4d7c-8116-6cf2bac22b97` | `e0:19:95:8b:c8:83` | `192.168.34.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 3 | `lrp-router-port_b4685b3f-31a1-4c96-9b30-a68ae1b0a272` | `694c9dc4-ea30-479d-812b-1487bd5ca7c3` | `e0:19:95:3e:c2:5f` | `192.168.61.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 4 | `lrp-router-port_d110f476-68a9-4d94-9911-5fc864464b43` | `fd790747-13c3-42c3-820d-0158b6a313a4` | `e0:19:95:9e:df:8d` | `192.168.72.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 5 | `lrp-router-port_bfbc4008-67c9-476c-966a-cf8465a909e3` | `1e86a625-ecbb-48bb-8219-f43de8bd052d` | `e0:19:95:ff:37:99` | `192.168.45.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 6 | `lrp-router-port_a7799f72-bad9-482e-9466-cbcdd59d7625` | `3672efca-9d87-491b-8466-9aaac1b523fe` | `e0:19:95:25:67:61` | `192.168.98.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 7 | `lrp-router-port_d4df28ac-20e5-40fe-b659-368c0d4f9698` | `437374f4-d008-42c2-847c-eaae13a01c4d` | `e0:19:95:fe:19:81` | `192.168.70.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 8 | `lrp-router-port_0c904e1b-e631-4f18-8acb-e3051368d3f9` | `897fc7b4-f272-4dc0-84e2-029be59f8df5` | `e0:19:95:14:82:0e` | `192.168.81.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 9 | `lrp-router-port_807ed90e-1fda-497f-9098-7958ef0d4990` | `dd0e4979-a149-49c1-8560-8773271ce258` | `e0:19:95:88:7d:95` | `192.168.4.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 10 | `lrp-router-port_c8d975d9-60b0-419c-b56d-f28f9200504f` | `55136155-be12-4a98-8563-21d12185c179` | `e0:19:95:d0:e5:4f` | `192.168.9.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 11 | `lrp-router-port_4bceacc5-ac6e-4008-8e70-97cfd30e5430` | `0cbf3173-108d-492f-85a2-4d0239a2a7d7` | `e0:19:95:ca:65:c1` | `192.168.32.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 12 | `lrp-router-port_8f8336aa-42da-43b7-8757-3997a975a07d` | `9b0ca561-7935-4667-85ed-68bb78a1fa84` | `e0:19:95:77:a4:ba` | `192.168.68.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 13 | `lrp-router-port_8dcafab3-5338-4114-9eef-0e6fa19605df` | `c5d49730-2e9f-41a0-8632-dc03b4108af0` | `e0:19:95:93:ab:9b` | `192.168.99.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 14 | `lrp-router-port_9dd293d7-0450-478d-980b-8b5bd08a89cb` | `cf63cbce-f5d2-413a-8673-13fe67460180` | `e0:19:95:6f:90:f9` | `192.168.87.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 15 | `lrp-router-port_4ea3c785-c4a9-498c-80f3-ed2aa55c29d9` | `03f7e95b-82fa-4672-881e-57b1d0056991` | `e0:19:95:b9:0c:9d` | `192.168.11.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 16 | `lrp-router-port_c307271a-0a3d-4325-8071-71b873bc3768` | `8646d92c-5c81-4cc6-8882-799442c809bd` | `e0:19:95:18:d4:6b` | `192.168.100.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 17 | `lrp-router-port_fa0c4784-a17e-4b1f-b4ff-220bca5b4cce` | `31e722c0-ec9e-4e24-899f-83ef276c6802` | `e0:19:95:e2:19:b8` | `192.168.14.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 18 | `lrp-router-port_e141bb39-f661-4c6f-95cd-63773a7db69d` | `1f01d52b-1db8-406e-8c37-1c57bea23203` | `e0:19:95:68:c7:41` | `192.168.48.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 19 | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `a962db06-7c7f-4a0b-8ca8-fe5ccfedf145` | `e0:19:95:08:22:c9` | `192.168.2.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 20 | `lrp-router-port_032fedb1-1e88-4849-bc5d-ad7f358ea600` | `ad13ede1-97ad-4037-8ce2-1e12ca1382f0` | `e0:19:95:cb:87:d1` | `192.168.73.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 21 | `lrp-router-port_2c1b4c9d-8fd5-4354-8205-62ef2d28cef8` | `f68c0d67-c7c5-46e0-8ce3-57440cb1db36` | `e0:19:95:56:0b:15` | `192.168.60.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 22 | `lrp-router-port_2dc24931-94e9-439b-986f-7a62a7bf92a1` | `539ecc8b-3c07-492c-8d4b-6210dec56a46` | `e0:19:95:28:39:6d` | `192.168.55.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 23 | `lrp-router-port_0743c6fc-5073-425e-9770-ead8c56c42e9` | `5423818c-753e-4123-8de0-67236f85704b` | `e0:19:95:5c:82:51` | `192.168.78.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 24 | `lrp-router-port_830e914f-389c-4171-a7be-8e0d1f94c96b` | `056cfc0f-d9db-494b-8e26-e1ad2a6d1be9` | `e0:19:95:90:d1:bf` | `192.168.33.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 25 | `lrp-router-port_d25f3dea-d19d-4c4c-a487-41613ce2eb61` | `c291e650-cabc-4738-8e9e-6c7457201f65` | `e0:19:95:31:ca:12` | `192.168.67.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 26 | `lrp-router-port_71d41765-890f-4b8d-895b-e82505096413` | `14262dba-7024-407b-8fb6-87aa8397da05` | `e0:19:95:dd:34:b6` | `192.168.46.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 27 | `lrp-router-port_675f2734-4826-467a-b43e-00698627a259` | `943232a2-0da1-4f2e-9089-93b0f878dab7` | `e0:19:95:80:ac:36` | `192.168.40.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 28 | `lrp-router-port_42ecfffe-0e34-4d14-85f7-5301de17cf69` | `ef431a7c-025b-483d-9105-c9ca3663d10e` | `e0:19:95:76:5c:04` | `192.168.90.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 29 | `lrp-router-port_fa896d0f-b0d0-4fa3-b688-331e9edc2a39` | `161655fa-d6ab-43e5-9139-c0999ec180c4` | `e0:19:95:6c:e3:fd` | `192.168.20.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 30 | `lrp-router-port_0ba9c57a-57c7-4ef9-8c24-4786c8f54d47` | `33155985-fe1d-4f89-916f-f816da6612ef` | `e0:19:95:20:df:2e` | `192.168.31.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 31 | `lrp-router-port_174db21e-8ba1-48eb-beb6-aa4ab68a2305` | `9651f6ea-731d-4ab4-9175-053456e3fd2b` | `e0:19:95:9c:97:00` | `192.168.76.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 32 | `lrp-router-port_4bdb92dc-d31e-46fb-89e9-88a99f403c29` | `3a37d6c9-bec2-47d1-91f1-fae7fe2792e2` | `e0:19:95:46:1a:15` | `192.168.57.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 33 | `lrp-router-port_ca086587-3fdb-41e7-8571-d01547cece9f` | `3aa8a711-0114-4ac4-9204-f3d709c8a166` | `e0:19:95:ac:cf:7e` | `192.168.17.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 34 | `lrp-router-port_2dac78de-9721-4a5b-8086-4c965dd6c619` | `f04df7ad-7eef-4e1f-932c-5ee1d2861ba4` | `e0:19:95:2b:aa:74` | `192.168.27.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 35 | `lrp-router-port_dae15e78-0138-406f-9c44-5931c2433eae` | `bb143bbf-1dd5-4758-939e-9693a95474b0` | `e0:19:95:99:e6:0d` | `192.168.253.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 36 | `lrp-router-port_f78566a0-d032-4d39-b160-26a846193005` | `e171de44-3da5-49e6-9510-263948c34e89` | `e0:19:95:c5:63:33` | `192.168.6.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 37 | `lrp-router-port_81097727-e648-454a-81df-ae0520caca2c` | `3bbbc8a4-9afa-478d-9551-07da22c5da2c` | `e0:19:95:6a:b4:16` | `192.168.74.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 38 | `lrp-router-port_1358d80d-13be-42f7-ac61-82d076a18135` | `51a681b0-c999-47a2-9564-dc5827ad9b08` | `e0:19:95:34:81:33` | `192.168.96.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 39 | `lrp-router-port_30c8fe9c-b42a-4e3e-a38a-cc11cb73d1e6` | `5fb293cb-4aaa-4c9d-9570-0f9c7a3820d5` | `e0:19:95:c7:1e:be` | `192.168.16.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 40 | `lrp-router-port_8b6751f8-979a-42f0-b64d-d71fea87beee` | `b7eb6b2c-877c-43f8-95ce-b5c5342bbc97` | `e0:19:95:a0:be:92` | `192.168.19.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 41 | `lrp-router-port_2f065e5c-a736-43f7-a8f9-ad969e733b13` | `d808dcb7-4bfc-43ac-95d7-590b1242bacc` | `e0:19:95:a7:19:d9` | `192.168.8.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 42 | `lrp-router-port_0f1f3f44-0fa0-45c4-918d-ac99e0d75e0d` | `66ed755b-200a-425d-9723-87881189eb5b` | `e0:19:95:c7:e4:05` | `192.168.95.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 43 | `lrp-router-port_e09f8b78-d094-4bdd-9f6d-18b0d14e50bf` | `68158f91-4874-4acd-973e-9f5c334ff84b` | `e0:19:95:e2:cb:26` | `192.168.63.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 44 | `lrp-router-port_80e90459-8298-4d6c-95bf-9deecc8c48fb` | `a2090153-8094-4b16-98a1-283a7a36cac3` | `e0:19:95:e3:3f:66` | `192.168.29.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 45 | `lrp-router-port_073a0cb1-e7cc-4b24-92f2-9c07ff0ab096` | `fdfb64dd-55e6-4c6d-98b3-599a934d791b` | `e0:19:95:a0:0f:1a` | `192.168.41.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 46 | `lrp-router-port_37fb764e-d0fa-457b-a216-43d9b11b3aed` | `f3f7daab-3a78-4bcb-98b9-744fa87dc752` | `e0:19:95:fa:ba:a0` | `192.168.65.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 47 | `lrp-router-port_b69e06e1-b184-4390-8cd6-f22044118b16` | `c22e6517-9139-4df6-990e-feba9f218988` | `e0:19:95:82:51:dc` | `100.64.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 48 | `lrp-router-port_75e16325-7223-4e38-a44c-a04509f4f777` | `27386bc2-49b8-4f66-9960-21aeac1f0407` | `e0:19:95:9d:2e:87` | `192.168.44.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 49 | `lrp-router-port_c0e67438-6eae-42c9-b6f2-6f6e470d4db8` | `e90cc4c6-2008-4f4f-9968-d28d5cae43ba` | `e0:19:95:6d:3a:78` | `192.168.89.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 50 | `lrp-router-port_de80667d-6f56-4481-ba8f-14be08b4a8fc` | `07da41d5-6b8e-4514-9ad1-9a680f47990a` | `e0:19:95:25:71:58` | `192.168.42.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 51 | `lrp-router-port_e8a882dc-a636-4b57-ab53-813694611e92` | `21d3bc09-a435-413b-9ad6-54248ecd643b` | `e0:19:95:2f:45:38` | `192.168.26.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 52 | `lrp-router-port_620e1ab8-b44e-4051-97b4-b3e73728664d` | `2c909093-c8ec-4818-9b5a-1446ce094ccc` | `e0:19:95:27:93:33` | `192.168.30.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 53 | `lrp-router-port_6e1383c1-5e63-46ea-b513-416115448c8e` | `da1703ff-d6bc-42da-9ba6-de6bfd61aacd` | `e0:19:95:02:91:54` | `192.168.80.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 54 | `lrp-router-port_195bf1a1-d7ab-44a9-987b-4e595a4c34e0` | `c3e621ce-c10f-4f2f-9cd7-75edbbda6e74` | `e0:19:95:51:42:af` | `192.168.58.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 55 | `lrp-router-port_e800940d-51e7-42e1-a338-647494e919db` | `f6d53175-5856-45d8-a043-a9aea6645785` | `e0:19:95:35:75:0e` | `192.168.47.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 56 | `lrp-router-port_e0002237-57a9-433f-9e82-938599b90a98` | `dab6f27c-3eb7-4332-a05d-166723f03a8e` | `e0:19:95:b0:f3:f9` | `192.168.83.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 57 | `lrp-router-port_48ef8369-ed7d-400a-b84c-c74e67a54347` | `79fba623-a2c0-4ab8-a19f-af56eb1e6e5a` | `e0:19:95:f1:59:a8` | `192.168.88.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 58 | `lrp-router-port_c275c897-fea0-434c-a9ab-fa02a5af893a` | `4fcb480b-2d45-4691-a1e7-31cb4ef035d7` | `e0:19:95:8c:48:8e` | `192.168.69.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 59 | `lrp-router-port_fe749a87-cf4d-42e1-b165-e5551acdb3c3` | `c2b65616-59ee-4206-a24c-5d689a1058b0` | `e0:19:95:4c:aa:79` | `192.168.21.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 60 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `42734276-bf85-470b-a2bd-ddfeff3c11f4` | `e0:19:95:c9:5b:48` | `169.254.2.20/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 61 | `lrp-router-port_da0d1e4f-cd5e-4d70-b6cb-76c26d3268ef` | `c00fb43f-5ad9-499c-a3c5-8798396a4207` | `e0:19:95:e8:bd:5e` | `192.168.36.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 62 | `lrp-router-port_a42276da-b029-4099-bc9d-c81a6c5c229d` | `a717f6de-4dba-488d-a3ed-35f40a0af6b3` | `e0:19:95:a9:61:71` | `192.168.56.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 63 | `lrp-router-port_baf0d081-ea93-4077-899d-f7e6dc63f539` | `bf84ed6b-a702-4a76-a438-d3b6ee9f3a6d` | `e0:19:95:f7:eb:9c` | `192.168.59.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 64 | `lrp-router-port_ebf08da2-c15c-473b-a1bd-8f5f871ad07a` | `55f2a571-2f98-4f84-a442-223d6e39dfa2` | `e0:19:95:90:3c:3f` | `192.168.71.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 65 | `lrp-router-port_c5422e1c-4aae-4e5f-9520-936bc881921d` | `47b50377-d52f-4a1b-a4c7-65c7c1ea04f1` | `e0:19:95:5e:f5:f1` | `192.168.28.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 66 | `lrp-router-port_b53ef258-faec-4995-b4e7-d2d4a061ddf2` | `a53c75c6-c3b1-4a93-a507-3592b164beed` | `e0:19:95:69:61:ea` | `192.168.18.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 67 | `lrp-router-port_d5d2d617-49ca-49a7-9665-f89f5ff8d0f2` | `fdc608a4-8603-4024-a53a-c90b431a02c1` | `e0:19:95:e3:14:7a` | `192.168.22.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 68 | `lrp-router-port_782ca68a-04b1-4fdc-a822-9d58215f7765` | `0d85ffb0-14c7-42de-a6bf-3660b7c80574` | `e0:19:95:bb:f4:cf` | `192.168.86.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 69 | `lrp-router-port_dbf060f4-6528-4cd8-8a68-f32313bb409a` | `93439c46-da3d-417b-a70d-be08c1001858` | `e0:19:95:b1:79:98` | `192.168.92.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 70 | `lrp-router-port_d1624e61-07ee-47a2-9816-691b67ad9a9b` | `17ae7a43-e7cd-435d-a76e-a418cd3d162b` | `e0:19:95:b0:94:7d` | `192.168.77.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 71 | `lrp-router-port_3ea92dc1-e13d-4e44-adad-e2adb944fd31` | `b6b01066-e41d-4ae9-a791-c74fbf0f00d2` | `e0:19:95:7f:30:ff` | `192.168.24.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 72 | `lrp-router-port_6c8f9dd7-4e03-4c2c-9fe5-da7eac887606` | `afcfcbe5-a1c8-4a46-a7ee-1c9b6e7e982c` | `e0:19:95:7c:02:0c` | `192.168.66.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 73 | `lrp-router-port_4124a4e2-3461-47f4-8612-377639eaaf87` | `3273c602-7eec-4752-aa44-d7569020eeb9` | `e0:19:95:e5:cb:45` | `192.168.64.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 74 | `lrp-router-port_3299d3a7-124a-4c43-9ae9-0f798040eae1` | `767d5a44-7559-4aa7-aa86-27200c5d0335` | `e0:19:95:98:b8:cc` | `192.168.49.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 75 | `lrp-router-port_93837b6a-1c71-47fe-a427-7b818c6874d7` | `4d71d847-edb0-4280-aaac-25d75a5810ce` | `e0:19:95:9a:19:81` | `192.168.43.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 76 | `lrp-router-port_9ec643a3-96ce-4ad1-b80d-708e8149f79d` | `5f9c5aa7-c8b6-43a2-abac-ae4483b20d9d` | `e0:19:95:c6:34:74` | `192.168.15.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 77 | `lrp-router-port_3d07fc33-53d7-4f9a-b853-449ef50a2eea` | `cdd687af-d3f6-42a8-ae63-f15be86f2cbc` | `e0:19:95:27:1e:73` | `192.168.94.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 78 | `lrp-router-port_6fef40cb-9010-4464-af83-fa6e75ec0b6d` | `2a05c567-dfe9-48e3-aeaf-869b44116993` | `e0:19:95:dd:bf:9c` | `192.168.7.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 79 | `lrp-router-port_5fd6becb-db5b-4c6f-bcdd-35e95888cc20` | `783bfc2a-8236-4d1d-b093-532163105e24` | `e0:19:95:66:94:35` | `192.168.254.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 80 | `lrp-router-port_455bebd3-3c1b-4e18-be7b-343d7350e90f` | `efde5afd-2364-42b7-b0c2-230394485c34` | `e0:19:95:52:ac:b4` | `192.168.39.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 81 | `lrp-router-port_a5627ef6-0b96-4e84-867a-3f257ea3dbf3` | `d7cff9d2-08f2-4c79-b0f8-9d3c59d0e80a` | `e0:19:95:a2:b1:49` | `192.168.97.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 82 | `lrp-router-port_88c50715-b1a5-4281-bee9-11dc6671f8ad` | `d739568b-b227-4f23-b2c9-bf8ebd0bfdc9` | `e0:19:95:21:8e:11` | `192.168.84.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 83 | `lrp-router-port_96d3605c-fe95-455b-83a6-dd2d3e52373a` | `92538731-a957-45a1-b2e3-673a1540c556` | `e0:19:95:30:5d:5d` | `192.168.52.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 84 | `lrp-router-port_ca6a8331-7e2a-4573-987c-4ef24353ee07` | `4479b60f-0384-4350-b336-09805472978b` | `e0:19:95:6b:43:45` | `192.168.13.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 85 | `lrp-router-port_865e3efc-d7dc-4861-93d5-68bf71423c8b` | `ad58477d-08a5-40b1-b36a-0417ec785185` | `e0:19:95:98:eb:88` | `192.168.53.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 86 | `lrp-router-port_39569c73-80df-40ac-ad18-7423d9cfb292` | `74fe2778-f060-4418-b371-8a6e6199ae71` | `e0:19:95:0a:05:d1` | `192.168.51.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 87 | `lrp-router-port_80f5715e-6fd6-4de3-9899-17770493824a` | `e25a3ec5-ca19-485d-b470-bb433fd33839` | `e0:19:95:f9:a3:97` | `192.168.91.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 88 | `lrp-router-port_6d7bd89d-5a0f-431e-84a4-309187eb3f7b` | `e78d4932-9bda-4ca8-b4cc-cc18cd794874` | `e0:19:95:1a:ca:99` | `192.168.38.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 89 | `lrp-router-port_dfc48fc2-f9a8-4586-bfec-4cd162977bfd` | `f320ef75-25f1-4be0-b536-8f908aac2ca7` | `e0:19:95:9c:71:23` | `192.168.62.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 90 | `lrp-router-port_52c2face-3b8d-477b-8b84-fa721e061794` | `2f0936bd-85b6-4aaf-b5f5-f83ddb39ed6f` | `e0:19:95:e9:10:ae` | `192.168.37.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 91 | `lrp-router-port_f472f5ad-5429-4b29-8044-19347c60d356` | `62c1baba-d3f6-4530-b641-5eb139002dcb` | `e0:19:95:aa:f8:6e` | `192.168.10.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 92 | `lrp-router-port_262750bb-7def-46a5-acd0-cd35df02f331` | `ea3d5522-6198-46eb-b726-65399892d456` | `e0:19:95:d6:98:39` | `192.168.82.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 93 | `lrp-router-port_cf479cc5-632e-4c40-ae45-4c316472ab1e` | `e546c7b3-705c-41ee-b74b-144bb62fcaa9` | `e0:19:95:19:f3:7f` | `192.168.79.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 94 | `lrp-router-port_fcd16e74-c7c6-4617-91f8-9d0bbc6aec9c` | `5e7e50b5-37df-4fdd-b750-5c3d337ecf41` | `e0:19:95:87:91:8d` | `192.168.85.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 95 | `lrp-router-port_133a16f9-8bc5-4d93-b4c3-b904e5104e8b` | `d41b831a-7dcf-418c-b823-b073717cf637` | `e0:19:95:2b:ee:2c` | `192.168.5.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 96 | `lrp-router-port_e89aafa4-4e4a-4f4e-a6c9-e41f1c13093d` | `5b641834-09cb-4f95-b832-4aac462a0c06` | `e0:19:95:60:b8:6f` | `192.168.50.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 97 | `lrp-router-port_e1e88e81-2f03-4004-b335-7db74953710d` | `b5500489-42ba-486d-b8cf-ef4360c6ad48` | `e0:19:95:46:16:b8` | `192.168.25.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 98 | `lrp-router-port_45329ac7-c80e-4968-9e81-1e8cc9e08d1b` | `6c0e10d5-cb00-4de2-b8e8-5ab4b2e4c4da` | `e0:19:95:06:43:d8` | `192.168.12.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 99 | `lrp-router-port_389a4d77-cf3f-48eb-98e2-ab825f6f637d` | `e85f8874-aef6-43d6-b989-e5fcb2c2dbdd` | `e0:19:95:87:cf:c0` | `192.168.35.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 100 | `lrp-router-port_450b41f1-6e7d-460d-a4fa-08aaa5673156` | `e373c0ab-453a-4c25-ba30-bf13c39471bf` | `e0:19:95:8e:3c:88` | `192.168.54.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 101 | `lrp-router-port_36add0c8-c730-4664-9aad-2da692db4a87` | `58760282-7056-40c7-bbbf-d94c6ced3dab` | `e0:19:95:0c:11:e7` | `192.168.23.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 102 | `lrp-router-port_bd6f114b-6dcd-4aae-8d1f-6c3a3058eeec` | `6a925c33-f0e9-4483-bdee-0a7fc9d3430a` | `e0:19:95:ef:4e:1c` | `192.168.1.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 103 | `lrp-router-port_fcf0b04e-dc57-4d88-accc-baf335985908` | `59e1f0f8-5c0e-4f15-bf9a-536db8005224` | `e0:19:95:b4:28:df` | `192.168.3.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |
| 104 | `lrp-router-port_dc090365-4e0b-40cb-8b74-1f2c7fd6928b` | `744cff50-e538-4410-bfe1-308f13a52642` | `e0:19:95:78:cb:43` | `192.168.75.1/24` | `` |  | `00000000-0000-0000-0000-000000000000` |

##### Switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` uuid `02d0de22-21a5-41f7-befd-75b6cb9c4cc7`

```json
{
  "ls_uuid": "02d0de22-21a5-41f7-befd-75b6cb9c4cc7",
  "name": "network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
  "transit": false,
  "localnet": false,
  "datapath_uuid": "bd8492c8-3307-42fa-8a75-d484a87f4db7",
  "tunnel_key": 10207,
  "other_config": {
    "lb_vip_mac": "e0:19:95:08:22:c9",
    "requested-tnl-key": "10207"
  },
  "external_ids": {
    "neutron:network_name": "network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef"
  },
  "ports": [
    {
      "lsp_uuid": "915f1338-1aba-4c27-a016-cb9876cdc970",
      "name": "port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2",
      "type": "vif",
      "mac": "50:6b:8d:19:78:77",
      "ip": "192.168.2.186",
      "addresses": [
        "50:6b:8d:19:78:77 192.168.2.186"
      ],
      "options_router_port": "",
      "peer": "",
      "chassis_uuid": "a774c18b-7b6e-44f7-8661-6ac53c4607ca",
      "hostname": "zadkiel05-3",
      "pb_tunnel_key": 160
    },
    {
      "lsp_uuid": "aa4764a1-7aca-4ccb-b52b-c97072e274ae",
      "name": "router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
      "type": "router",
      "mac": "",
      "ip": "",
      "addresses": [
        "router"
      ],
      "options_router_port": "lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef",
      "peer": "",
      "chassis_uuid": "00000000-0000-0000-0000-000000000000",
      "hostname": "",
      "pb_tunnel_key": 1
    }
  ]
}
```

Path LSPs — 2 rows
| # | type | lsp | uuid | mac | ip | chassis |
|---|------|-----|------|-----|----|---------|
| 1 | vif | `port_12a2ce8a-afb5-40e5-b5ff-a7b3f895ffc2` | `915f1338-1aba-4c27-a016-cb9876cdc970` | `50:6b:8d:19:78:77` | `192.168.2.186` | `zadkiel05-3` |
| 2 | router | `router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `aa4764a1-7aca-4ccb-b52b-c97072e274ae` | `` | `` | `00000000-0000-0000-0000-000000000000` |


#### Downstream — full from-lport ACL list (leave source NIC) — 23 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.151,192.168.254.221)) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) \|\| (tcp.dst >= 18376 && tcp.dst <= 18385) \|\| (tcp.dst >= 18389 && tcp.dst <= 18398) \|\| (tcp.dst >= 18401 && tcp.dst <= 18410) \|\| (tcp.dst >= 18415 && tcp.dst <= 18424) \|\| (tcp.dst >= 18429 && tcp.dst <= 18438) \|\| (tcp.dst >= 18441 && tcp.dst <= 18450) \|\| (tcp.dst >= 18455 && tcp.dst <= 18464) \|\| (tcp.dst >= 18468 && tcp.dst <= 18477) \|\| (tcp.dst >= 18483 && tcp.dst <= 18492))) \|\| (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) \|\| (udp.dst >= 18376 && udp.dst <= 18385) \|\| (udp.dst >= 18389 && udp.dst <= 18398) \|\| (udp.dst >= 18401 && udp.dst <= 18410) \|\| (udp.dst >= 18415 && udp.dst <= 18424) \|\| (udp.dst >= 18429 && udp.dst <= 18438) \|\| (udp.dst >= 18441 && udp.dst <= 18450) \|\| (udp.dst >= 18455 && udp.dst <= 18464) \|\| (udp.dst >= 18468 && udp.dst <= 18477) \|\| (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.253.70/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) \|\| (tcp.dst >= 18512 && tcp.dst <= 18521) \|\| (tcp.dst >= 18524 && tcp.dst <= 18533) \|\| (tcp.dst >= 18537 && tcp.dst <= 18546) \|\| (tcp.dst >= 18551 && tcp.dst <= 18560) \|\| (tcp.dst >= 18564 && tcp.dst <= 18573) \|\| (tcp.dst >= 18576 && tcp.dst <= 18585) \|\| (tcp.dst >= 18590 && tcp.dst <= 18599) \|\| (tcp.dst >= 18603 && tcp.dst <= 18612) \|\| (tcp.dst >= 18618 && tcp.dst <= 18627))) \|\| (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) \|\| (udp.dst >= 18512 && udp.dst <= 18521) \|\| (udp.dst >= 18524 && udp.dst <= 18533) \|\| (udp.dst >= 18537 && udp.dst <= 18546) \|\| (udp.dst >= 18551 && udp.dst <= 18560) \|\| (udp.dst >= 18564 && udp.dst <= 18573) \|\| (udp.dst >= 18576 && udp.dst <= 18585) \|\| (udp.dst >= 18590 && udp.dst <= 18599) \|\| (udp.dst >= 18603 && udp.dst <= 18612) \|\| (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 7 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 8 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 9 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |
| 10 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 11 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 12 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 13 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $inbound_VPC_California_SJ_Pheonix_Customer_1_App_1_src) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) \|\| (tcp.dst >= 1037 && tcp.dst <= 1046) \|\| (tcp.dst >= 1049 && tcp.dst <= 1058) \|\| (tcp.dst >= 1062 && tcp.dst <= 1071) \|\| (tcp.dst >= 1074 && tcp.dst <= 1083) \|\| (tcp.dst >= 1086 && tcp.dst <= 1095) \|\| (tcp.dst >= 1101 && tcp.dst <= 1110) \|\| (tcp.dst >= 1113 && tcp.dst <= 1122) \|\| (tcp.dst >= 1125 && tcp.dst <= 1134) \|\| (tcp.dst >= 1140 && tcp.dst <= 1149))) \|\| (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) \|\| (udp.dst >= 1037 && udp.dst <= 1046) \|\| (udp.dst >= 1049 && udp.dst <= 1058) \|\| (udp.dst >= 1062 && udp.dst <= 1071) \|\| (udp.dst >= 1074 && udp.dst <= 1083) \|\| (udp.dst >= 1086 && udp.dst <= 1095) \|\| (udp.dst >= 1101 && udp.dst <= 1110) \|\| (udp.dst >= 1113 && udp.dst <= 1122) \|\| (udp.dst >= 1125 && udp.dst <= 1134) \|\| (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 14 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.168/32,192.168.254.89/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 15 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.129/32,192.168.254.132/32,192.168.254.151/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) \|\| (tcp.dst >= 1166 && tcp.dst <= 1175) \|\| (tcp.dst >= 1181 && tcp.dst <= 1190) \|\| (tcp.dst >= 1193 && tcp.dst <= 1202) \|\| (tcp.dst >= 1205 && tcp.dst <= 1214) \|\| (tcp.dst >= 1218 && tcp.dst <= 1227) \|\| (tcp.dst >= 1230 && tcp.dst <= 1239) \|\| (tcp.dst >= 1242 && tcp.dst <= 1251) \|\| (tcp.dst >= 1257 && tcp.dst <= 1266) \|\| (tcp.dst >= 1271 && tcp.dst <= 1280))) \|\| (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) \|\| (udp.dst >= 1166 && udp.dst <= 1175) \|\| (udp.dst >= 1181 && udp.dst <= 1190) \|\| (udp.dst >= 1193 && udp.dst <= 1202) \|\| (udp.dst >= 1205 && udp.dst <= 1214) \|\| (udp.dst >= 1218 && udp.dst <= 1227) \|\| (udp.dst >= 1230 && udp.dst <= 1239) \|\| (udp.dst >= 1242 && udp.dst <= 1251) \|\| (udp.dst >= 1257 && udp.dst <= 1266) \|\| (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 16 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 17 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 18 | 1019 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 19 | 1018 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 20 | 1017 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(0.0.0.0/1,128.0.0.0/2,192.0.0.0/9+14)) && outport == @AppType/EG_Exclude_Policy1` |
| 21 | 1015 | allow-related | to-lport | pg | `ip4 && outport == @AppType/EG_Exclude_Policy1` |
| 22 | 1015 | allow-related | to-lport | pg | `ip6 && outport == @AppType/EG_Exclude_Policy1` |
| 23 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — full to-lport ACL list (enter dest NIC) — 23 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.164,192.168.254.72)) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) \|\| (tcp.dst >= 18646 && tcp.dst <= 18655) \|\| (tcp.dst >= 18661 && tcp.dst <= 18670) \|\| (tcp.dst >= 18673 && tcp.dst <= 18682) \|\| (tcp.dst >= 18685 && tcp.dst <= 18694) \|\| (tcp.dst >= 18699 && tcp.dst <= 18708) \|\| (tcp.dst >= 18712 && tcp.dst <= 18721) \|\| (tcp.dst >= 18725 && tcp.dst <= 18734) \|\| (tcp.dst >= 18737 && tcp.dst <= 18746) \|\| (tcp.dst >= 18751 && tcp.dst <= 18760))) \|\| (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) \|\| (udp.dst >= 18646 && udp.dst <= 18655) \|\| (udp.dst >= 18661 && udp.dst <= 18670) \|\| (udp.dst >= 18673 && udp.dst <= 18682) \|\| (udp.dst >= 18685 && udp.dst <= 18694) \|\| (udp.dst >= 18699 && udp.dst <= 18708) \|\| (udp.dst >= 18712 && udp.dst <= 18721) \|\| (udp.dst >= 18725 && udp.dst <= 18734) \|\| (udp.dst >= 18737 && udp.dst <= 18746) \|\| (udp.dst >= 18751 && udp.dst <= 18760))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) \|\| (tcp.dst >= 18779 && tcp.dst <= 18788) \|\| (tcp.dst >= 18794 && tcp.dst <= 18803) \|\| (tcp.dst >= 18809 && tcp.dst <= 18818) \|\| (tcp.dst >= 18821 && tcp.dst <= 18830) \|\| (tcp.dst >= 18833 && tcp.dst <= 18842) \|\| (tcp.dst >= 18847 && tcp.dst <= 18856) \|\| (tcp.dst >= 18860 && tcp.dst <= 18869) \|\| (tcp.dst >= 18874 && tcp.dst <= 18883) \|\| (tcp.dst >= 18888 && tcp.dst <= 18897))) \|\| (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) \|\| (udp.dst >= 18779 && udp.dst <= 18788) \|\| (udp.dst >= 18794 && udp.dst <= 18803) \|\| (udp.dst >= 18809 && udp.dst <= 18818) \|\| (udp.dst >= 18821 && udp.dst <= 18830) \|\| (udp.dst >= 18833 && udp.dst <= 18842) \|\| (udp.dst >= 18847 && udp.dst <= 18856) \|\| (udp.dst >= 18860 && udp.dst <= 18869) \|\| (udp.dst >= 18874 && udp.dst <= 18883) \|\| (udp.dst >= 18888 && udp.dst <= 18897))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4` |
| 8 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |
| 9 | 1000 | allow | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18` |
| 10 | 100 | **drop** | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"` |
| 11 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 12 | 1060 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 13 | 1052 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 14 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $IPs(192.168.254.11/32,192.168.254.122/32,192.168.254.149/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) \|\| (tcp.dst >= 1429 && tcp.dst <= 1438) \|\| (tcp.dst >= 1441 && tcp.dst <= 1450) \|\| (tcp.dst >= 1455 && tcp.dst <= 1464) \|\| (tcp.dst >= 1469 && tcp.dst <= 1478) \|\| (tcp.dst >= 1483 && tcp.dst <= 1492) \|\| (tcp.dst >= 1498 && tcp.dst <= 1507) \|\| (tcp.dst >= 1511 && tcp.dst <= 1520) \|\| (tcp.dst >= 1524 && tcp.dst <= 1533) \|\| (tcp.dst >= 1539 && tcp.dst <= 1548))) \|\| (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) \|\| (udp.dst >= 1429 && udp.dst <= 1438) \|\| (udp.dst >= 1441 && udp.dst <= 1450) \|\| (udp.dst >= 1455 && udp.dst <= 1464) \|\| (udp.dst >= 1469 && udp.dst <= 1478) \|\| (udp.dst >= 1483 && udp.dst <= 1492) \|\| (udp.dst >= 1498 && udp.dst <= 1507) \|\| (udp.dst >= 1511 && udp.dst <= 1520) \|\| (udp.dst >= 1524 && udp.dst <= 1533) \|\| (udp.dst >= 1539 && udp.dst <= 1548))))` |
| 15 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $outbound_VPC_California_SJ_Pheonix_Customer_1_App_1_dest) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) \|\| (tcp.dst >= 1297 && tcp.dst <= 1306) \|\| (tcp.dst >= 1312 && tcp.dst <= 1321) \|\| (tcp.dst >= 1324 && tcp.dst <= 1333) \|\| (tcp.dst >= 1336 && tcp.dst <= 1345) \|\| (tcp.dst >= 1350 && tcp.dst <= 1359) \|\| (tcp.dst >= 1363 && tcp.dst <= 1372) \|\| (tcp.dst >= 1378 && tcp.dst <= 1387) \|\| (tcp.dst >= 1390 && tcp.dst <= 1399) \|\| (tcp.dst >= 1403 && tcp.dst <= 1412))) \|\| (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) \|\| (udp.dst >= 1297 && udp.dst <= 1306) \|\| (udp.dst >= 1312 && udp.dst <= 1321) \|\| (udp.dst >= 1324 && udp.dst <= 1333) \|\| (udp.dst >= 1336 && udp.dst <= 1345) \|\| (udp.dst >= 1350 && udp.dst <= 1359) \|\| (udp.dst >= 1363 && udp.dst <= 1372) \|\| (udp.dst >= 1378 && udp.dst <= 1387) \|\| (udp.dst >= 1390 && udp.dst <= 1399) \|\| (udp.dst >= 1403 && udp.dst <= 1412))))` |
| 16 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip6` |
| 17 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4` |
| 18 | 1019 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 19 | 1018 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 20 | 1017 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 21 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 22 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip6` |
| 23 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` from-lport (full) — 9 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.151,192.168.254.221)) && ((ip.proto == 6 && ((tcp.dst >= 18363 && tcp.dst <= 18372) \|\| (tcp.dst >= 18376 && tcp.dst <= 18385) \|\| (tcp.dst >= 18389 && tcp.dst <= 18398) \|\| (tcp.dst >= 18401 && tcp.dst <= 18410) \|\| (tcp.dst >= 18415 && tcp.dst <= 18424) \|\| (tcp.dst >= 18429 && tcp.dst <= 18438) \|\| (tcp.dst >= 18441 && tcp.dst <= 18450) \|\| (tcp.dst >= 18455 && tcp.dst <= 18464) \|\| (tcp.dst >= 18468 && tcp.dst <= 18477) \|\| (tcp.dst >= 18483 && tcp.dst <= 18492))) \|\| (ip.proto == 17 && ((udp.dst >= 18363 && udp.dst <= 18372) \|\| (udp.dst >= 18376 && udp.dst <= 18385) \|\| (udp.dst >= 18389 && udp.dst <= 18398) \|\| (udp.dst >= 18401 && udp.dst <= 18410) \|\| (udp.dst >= 18415 && udp.dst <= 18424) \|\| (udp.dst >= 18429 && udp.dst <= 18438) \|\| (udp.dst >= 18441 && udp.dst <= 18450) \|\| (udp.dst >= 18455 && udp.dst <= 18464) \|\| (udp.dst >= 18468 && udp.dst <= 18477) \|\| (udp.dst >= 18483 && udp.dst <= 18492)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.253.70/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18497 && tcp.dst <= 18506) \|\| (tcp.dst >= 18512 && tcp.dst <= 18521) \|\| (tcp.dst >= 18524 && tcp.dst <= 18533) \|\| (tcp.dst >= 18537 && tcp.dst <= 18546) \|\| (tcp.dst >= 18551 && tcp.dst <= 18560) \|\| (tcp.dst >= 18564 && tcp.dst <= 18573) \|\| (tcp.dst >= 18576 && tcp.dst <= 18585) \|\| (tcp.dst >= 18590 && tcp.dst <= 18599) \|\| (tcp.dst >= 18603 && tcp.dst <= 18612) \|\| (tcp.dst >= 18618 && tcp.dst <= 18627))) \|\| (ip.proto == 17 && ((udp.dst >= 18497 && udp.dst <= 18506) \|\| (udp.dst >= 18512 && udp.dst <= 18521) \|\| (udp.dst >= 18524 && udp.dst <= 18533) \|\| (udp.dst >= 18537 && udp.dst <= 18546) \|\| (udp.dst >= 18551 && udp.dst <= 18560) \|\| (udp.dst >= 18564 && udp.dst <= 18573) \|\| (udp.dst >= 18576 && udp.dst <= 18585) \|\| (udp.dst >= 18590 && udp.dst <= 18599) \|\| (udp.dst >= 18603 && udp.dst <= 18612) \|\| (udp.dst >= 18618 && udp.dst <= 18627)))) && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 7 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 8 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33` |
| 9 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — switch `network_17fe24db-e08b-4f81-969a-e06d6f23b35c` to-lport (full) — 8 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $App33_VPC_California_SJ_Pheonix_Customer_19_App_33_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.164,192.168.254.72)) && ((ip.proto == 6 && ((tcp.dst >= 18631 && tcp.dst <= 18640) \|\| (tcp.dst >= 18646 && tcp.dst <= 18655) \|\| (tcp.dst >= 18661 && tcp.dst <= 18670) \|\| (tcp.dst >= 18673 && tcp.dst <= 18682) \|\| (tcp.dst >= 18685 && tcp.dst <= 18694) \|\| (tcp.dst >= 18699 && tcp.dst <= 18708) \|\| (tcp.dst >= 18712 && tcp.dst <= 18721) \|\| (tcp.dst >= 18725 && tcp.dst <= 18734) \|\| (tcp.dst >= 18737 && tcp.dst <= 18746) \|\| (tcp.dst >= 18751 && tcp.dst <= 18760))) \|\| (ip.proto == 17 && ((udp.dst >= 18631 && udp.dst <= 18640) \|\| (udp.dst >= 18646 && udp.dst <= 18655) \|\| (udp.dst >= 18661 && udp.dst <= 18670) \|\| (udp.dst >= 18673 && udp.dst <= 18682) \|\| (udp.dst >= 18685 && udp.dst <= 18694) \|\| (udp.dst >= 18699 && udp.dst <= 18708) \|\| (udp.dst >= 18712 && udp.dst <= 18721) \|\| (udp.dst >= 18725 && udp.dst <= 18734) \|\| (udp.dst >= 18737 && udp.dst <= 18746) \|\| (udp.dst >= 18751 && udp.dst <= 18760))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4 && (ip4.dst == $IPs(192.168.254.117/32,192.168.254.227/32)) && ((ip.proto == 6 && ((tcp.dst >= 18764 && tcp.dst <= 18773) \|\| (tcp.dst >= 18779 && tcp.dst <= 18788) \|\| (tcp.dst >= 18794 && tcp.dst <= 18803) \|\| (tcp.dst >= 18809 && tcp.dst <= 18818) \|\| (tcp.dst >= 18821 && tcp.dst <= 18830) \|\| (tcp.dst >= 18833 && tcp.dst <= 18842) \|\| (tcp.dst >= 18847 && tcp.dst <= 18856) \|\| (tcp.dst >= 18860 && tcp.dst <= 18869) \|\| (tcp.dst >= 18874 && tcp.dst <= 18883) \|\| (tcp.dst >= 18888 && tcp.dst <= 18897))) \|\| (ip.proto == 17 && ((udp.dst >= 18764 && udp.dst <= 18773) \|\| (udp.dst >= 18779 && udp.dst <= 18788) \|\| (udp.dst >= 18794 && udp.dst <= 18803) \|\| (udp.dst >= 18809 && udp.dst <= 18818) \|\| (udp.dst >= 18821 && udp.dst <= 18830) \|\| (udp.dst >= 18833 && udp.dst <= 18842) \|\| (udp.dst >= 18847 && udp.dst <= 18856) \|\| (udp.dst >= 18860 && udp.dst <= 18869) \|\| (udp.dst >= 18874 && udp.dst <= 18883) \|\| (udp.dst >= 18888 && udp.dst <= 18897))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @App33/VPC_California_SJ_Pheonix_Customer_19_App_33 && ip4` |
| 8 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` from-lport (full) — 0 rules
(none)

#### Downstream — switch `network_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a` to-lport (full) — 2 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 1000 | allow | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a" && ip4.dst == 10.116.192.0/18` |
| 2 | 100 | **drop** | from-lport | ls | `ip && inport == "localnet_b65d16d9-ee5c-44c2-aa9c-0ad60cd9c28a"` |

#### Downstream — switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` from-lport (full) — 14 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | to-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 3 | 1052 | **drop** | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 4 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $inbound_VPC_California_SJ_Pheonix_Customer_1_App_1_src) && ((ip.proto == 6 && ((tcp.dst >= 1025 && tcp.dst <= 1034) \|\| (tcp.dst >= 1037 && tcp.dst <= 1046) \|\| (tcp.dst >= 1049 && tcp.dst <= 1058) \|\| (tcp.dst >= 1062 && tcp.dst <= 1071) \|\| (tcp.dst >= 1074 && tcp.dst <= 1083) \|\| (tcp.dst >= 1086 && tcp.dst <= 1095) \|\| (tcp.dst >= 1101 && tcp.dst <= 1110) \|\| (tcp.dst >= 1113 && tcp.dst <= 1122) \|\| (tcp.dst >= 1125 && tcp.dst <= 1134) \|\| (tcp.dst >= 1140 && tcp.dst <= 1149))) \|\| (ip.proto == 17 && ((udp.dst >= 1025 && udp.dst <= 1034) \|\| (udp.dst >= 1037 && udp.dst <= 1046) \|\| (udp.dst >= 1049 && udp.dst <= 1058) \|\| (udp.dst >= 1062 && udp.dst <= 1071) \|\| (udp.dst >= 1074 && udp.dst <= 1083) \|\| (udp.dst >= 1086 && udp.dst <= 1095) \|\| (udp.dst >= 1101 && udp.dst <= 1110) \|\| (udp.dst >= 1113 && udp.dst <= 1122) \|\| (udp.dst >= 1125 && udp.dst <= 1134) \|\| (udp.dst >= 1140 && udp.dst <= 1149)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 5 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.168/32,192.168.254.89/32)) && ((ip.proto == 1 && ((icmp4.type == 8 && icmp4.code == 0))) \|\| (ip.proto == 6 && (tcp.dst == 22 \|\| tcp.dst == 1024 \|\| tcp.dst == 80)) \|\| (ip.proto == 17 && (udp.dst == 22))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 6 | 1050 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(192.168.254.129/32,192.168.254.132/32,192.168.254.151/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1152 && tcp.dst <= 1161) \|\| (tcp.dst >= 1166 && tcp.dst <= 1175) \|\| (tcp.dst >= 1181 && tcp.dst <= 1190) \|\| (tcp.dst >= 1193 && tcp.dst <= 1202) \|\| (tcp.dst >= 1205 && tcp.dst <= 1214) \|\| (tcp.dst >= 1218 && tcp.dst <= 1227) \|\| (tcp.dst >= 1230 && tcp.dst <= 1239) \|\| (tcp.dst >= 1242 && tcp.dst <= 1251) \|\| (tcp.dst >= 1257 && tcp.dst <= 1266) \|\| (tcp.dst >= 1271 && tcp.dst <= 1280))) \|\| (ip.proto == 17 && ((udp.dst >= 1152 && udp.dst <= 1161) \|\| (udp.dst >= 1166 && udp.dst <= 1175) \|\| (udp.dst >= 1181 && udp.dst <= 1190) \|\| (udp.dst >= 1193 && udp.dst <= 1202) \|\| (udp.dst >= 1205 && udp.dst <= 1214) \|\| (udp.dst >= 1218 && udp.dst <= 1227) \|\| (udp.dst >= 1230 && udp.dst <= 1239) \|\| (udp.dst >= 1242 && udp.dst <= 1251) \|\| (udp.dst >= 1257 && udp.dst <= 1266) \|\| (udp.dst >= 1271 && udp.dst <= 1280)))) && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 7 | 1045 | **drop** | to-lport | pg | `ip4 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 8 | 1045 | **drop** | to-lport | pg | `ip6 && outport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1` |
| 9 | 1019 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 10 | 1018 | allow-related | to-lport | pg | `ip4 && (ip4.src == $AppType_EG_Exclude_Policy1_secured) && outport == @AppType/EG_Exclude_Policy1` |
| 11 | 1017 | allow-related | to-lport | pg | `ip4 && (ip4.src == $IPs(0.0.0.0/1,128.0.0.0/2,192.0.0.0/9+14)) && outport == @AppType/EG_Exclude_Policy1` |
| 12 | 1015 | allow-related | to-lport | pg | `ip4 && outport == @AppType/EG_Exclude_Policy1` |
| 13 | 1015 | allow-related | to-lport | pg | `ip6 && outport == @AppType/EG_Exclude_Policy1` |
| 14 | 500 | allow-related | to-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — switch `network_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` to-lport (full) — 13 rules
| # | pri | action | direction | attach | match |
|---|-----|--------|-----------|--------|-------|
| 1 | 31500 | allow-stateless | from-lport | ls | `(udp.src == 67 && udp.dst == 68) \|\| (udp.src == 68 && udp.dst == 67)` |
| 2 | 1060 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 3 | 1052 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 4 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $IPs(192.168.254.11/32,192.168.254.122/32,192.168.254.149/32+7)) && ((ip.proto == 6 && ((tcp.dst >= 1416 && tcp.dst <= 1425) \|\| (tcp.dst >= 1429 && tcp.dst <= 1438) \|\| (tcp.dst >= 1441 && tcp.dst <= 1450) \|\| (tcp.dst >= 1455 && tcp.dst <= 1464) \|\| (tcp.dst >= 1469 && tcp.dst <= 1478) \|\| (tcp.dst >= 1483 && tcp.dst <= 1492) \|\| (tcp.dst >= 1498 && tcp.dst <= 1507) \|\| (tcp.dst >= 1511 && tcp.dst <= 1520) \|\| (tcp.dst >= 1524 && tcp.dst <= 1533) \|\| (tcp.dst >= 1539 && tcp.dst <= 1548))) \|\| (ip.proto == 17 && ((udp.dst >= 1416 && udp.dst <= 1425) \|\| (udp.dst >= 1429 && udp.dst <= 1438) \|\| (udp.dst >= 1441 && udp.dst <= 1450) \|\| (udp.dst >= 1455 && udp.dst <= 1464) \|\| (udp.dst >= 1469 && udp.dst <= 1478) \|\| (udp.dst >= 1483 && udp.dst <= 1492) \|\| (udp.dst >= 1498 && udp.dst <= 1507) \|\| (udp.dst >= 1511 && udp.dst <= 1520) \|\| (udp.dst >= 1524 && udp.dst <= 1533) \|\| (udp.dst >= 1539 && udp.dst <= 1548))))` |
| 5 | 1050 | allow-related | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4 && (ip4.dst == $outbound_VPC_California_SJ_Pheonix_Customer_1_App_1_dest) && ((ip.proto == 6 && ((tcp.dst >= 1285 && tcp.dst <= 1294) \|\| (tcp.dst >= 1297 && tcp.dst <= 1306) \|\| (tcp.dst >= 1312 && tcp.dst <= 1321) \|\| (tcp.dst >= 1324 && tcp.dst <= 1333) \|\| (tcp.dst >= 1336 && tcp.dst <= 1345) \|\| (tcp.dst >= 1350 && tcp.dst <= 1359) \|\| (tcp.dst >= 1363 && tcp.dst <= 1372) \|\| (tcp.dst >= 1378 && tcp.dst <= 1387) \|\| (tcp.dst >= 1390 && tcp.dst <= 1399) \|\| (tcp.dst >= 1403 && tcp.dst <= 1412))) \|\| (ip.proto == 17 && ((udp.dst >= 1285 && udp.dst <= 1294) \|\| (udp.dst >= 1297 && udp.dst <= 1306) \|\| (udp.dst >= 1312 && udp.dst <= 1321) \|\| (udp.dst >= 1324 && udp.dst <= 1333) \|\| (udp.dst >= 1336 && udp.dst <= 1345) \|\| (udp.dst >= 1350 && udp.dst <= 1359) \|\| (udp.dst >= 1363 && udp.dst <= 1372) \|\| (udp.dst >= 1378 && udp.dst <= 1387) \|\| (udp.dst >= 1390 && udp.dst <= 1399) \|\| (udp.dst >= 1403 && udp.dst <= 1412))))` |
| 6 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip6` |
| 7 | 1045 | **drop** | from-lport | pg | `inport == @AppType/VPC_California_SJ_Pheonix_Customer_1_App_1 && ip4` |
| 8 | 1019 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 9 | 1018 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4 && (ip4.dst == $AppType_EG_Exclude_Policy1_secured)` |
| 10 | 1017 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 11 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip4` |
| 12 | 1015 | allow-related | from-lport | pg | `inport == @AppType/EG_Exclude_Policy1 && ip6` |
| 13 | 500 | allow-related | from-lport | ls | `tcp \|\| udp \|\| icmp` |

#### Downstream — router `router_818b2c20-4d1b-40b7-a951-5deb85316e68`

#### Downstream — NAT on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 0 rows
(none)

#### Downstream — PBR on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 3 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 100 | allow | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 2 | 10 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 3 | 1 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |

#### Downstream — connected routes on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 103 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-router-port_b0b648a3-fff9-40e9-b453-da9b575d26b2` | `192.168.90.1/24` |  |
| 2 | `lrp-router-port_1b6eb248-5d85-45d1-80b0-bc85aea0d484` | `192.168.47.1/24` |  |
| 3 | `lrp-router-port_5455f7ec-6475-4a62-ab71-dc28807bfb8d` | `192.168.68.1/24` |  |
| 4 | `lrp-router-port_8cb9eba0-0473-49c4-acc6-d22df0813b16` | `192.168.87.1/24` |  |
| 5 | `lrp-router-port_fdff4156-a468-4b28-b6be-4165566ed91b` | `192.168.42.1/24` |  |
| 6 | `lrp-router-port_eaccfc3a-2676-4295-9403-96dc5f703e60` | `192.168.26.1/24` |  |
| 7 | `lrp-router-port_81e65b0f-4933-4648-8c05-d72c77d6455e` | `192.168.48.1/24` |  |
| 8 | `lrp-router-port_4b52ccc7-a78b-4768-a784-27e105367c96` | `192.168.54.1/24` |  |
| 9 | `lrp-router-port_a824f5f1-d59a-439d-a863-88a82e9f728f` | `192.168.80.1/24` |  |
| 10 | `lrp-router-port_237161d6-1f23-40b9-9126-41e50710a4aa` | `192.168.25.1/24` |  |
| 11 | `lrp-router-port_a096b3ec-b472-4645-bb77-3889e617df1b` | `192.168.28.1/24` |  |
| 12 | `lrp-router-port_130a0318-7e0d-4433-bc32-f60ebd4a69b6` | `192.168.38.1/24` |  |
| 13 | `lrp-router-port_4933d693-021b-4cdd-865b-e03ad35e38bc` | `192.168.82.1/24` |  |
| 14 | `lrp-router-port_16454167-c055-409b-a40d-5ceb61fae279` | `192.168.64.1/24` |  |
| 15 | `lrp-router-port_958e7d1d-cd00-4ddf-adc9-58bf9ec0616d` | `192.168.49.1/24` |  |
| 16 | `lrp-router-port_72e62619-8a96-4f15-bf23-e14f602a7423` | `192.168.17.1/24` |  |
| 17 | `lrp-router-port_398e6097-726d-4417-8d4e-a5b0e15f3387` | `192.168.53.1/24` |  |
| 18 | `lrp-router-port_09083e0f-1d76-4a6f-aef8-282667aa110e` | `192.168.100.1/24` |  |
| 19 | `lrp-router-port_e65429bf-d32a-4274-8b35-39156398a0bb` | `192.168.3.1/24` |  |
| 20 | `lrp-router-port_ee90ab74-e669-4214-a816-de31615f8f40` | `192.168.18.1/24` |  |
| 21 | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `192.168.1.1/24` |  |
| 22 | `lrp-router-port_91565e00-afaf-4848-b6c8-aadf55a89177` | `192.168.12.1/24` |  |
| 23 | `lrp-router-port_bcd3c336-727d-4cff-8741-76b3ab62c5f0` | `192.168.79.1/24` |  |
| 24 | `lrp-router-port_b6d9bfd6-dcf4-4ad2-bec7-fdac3c8c0901` | `192.168.6.1/24` |  |
| 25 | `lrp-router-port_b7bbab8b-6c91-4ba1-86a1-7cbc2862b47a` | `192.168.60.1/24` |  |
| 26 | `lrp-router-port_a6a82a86-eb1c-4ed7-81a0-138e06ac03ed` | `192.168.10.1/24` |  |
| 27 | `lrp-router-port_f6ad4655-b1dc-4ac8-92be-fb23f95e6e5c` | `192.168.73.1/24` |  |
| 28 | `lrp-router-port_b156442e-c14c-4cee-bcf9-df780d716265` | `192.168.50.1/24` |  |
| 29 | `lrp-router-port_03c2ec09-65c6-439a-8878-b987580c3924` | `192.168.41.1/24` |  |
| 30 | `lrp-router-port_691b4004-10b5-45ee-bbaa-f455fd574caa` | `192.168.61.1/24` |  |
| 31 | `lrp-router-port_731e491b-f5c9-4a91-a1fa-e5a623312321` | `192.168.5.1/24` |  |
| 32 | `lrp-router-port_30af069f-3873-406c-b618-1910068e78f6` | `192.168.31.1/24` |  |
| 33 | `lrp-router-port_ad47fb2b-5cf5-413b-9c84-708688d9bd34` | `192.168.4.1/24` |  |
| 34 | `lrp-router-port_f4227f2b-0e70-4a07-a5f7-85f8ee92d9a4` | `192.168.21.1/24` |  |
| 35 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `169.254.2.20/24` |  |
| 36 | `lrp-router-port_f4954815-1f1b-4f5a-9cb1-fe89ccbfed8a` | `192.168.81.1/24` |  |
| 37 | `lrp-router-port_6ff10629-2c72-4efb-901d-eac2f09ba7ba` | `192.168.36.1/24` |  |
| 38 | `lrp-router-port_58903cc2-b80a-47e0-83b0-c10a12478545` | `192.168.14.1/24` |  |
| 39 | `lrp-router-port_de78f2f1-94a3-42b5-8736-68541ff9142a` | `192.168.63.1/24` |  |
| 40 | `lrp-router-port_4e3981a3-4f75-439c-a5fa-f5ab9e9a2809` | `192.168.59.1/24` |  |
| 41 | `lrp-router-port_4f4768cb-67cc-482a-bccb-054c3cb73cd3` | `192.168.88.1/24` |  |
| 42 | `lrp-router-port_a2ff46ff-216a-484b-ae3c-fa005b99a422` | `192.168.70.1/24` |  |
| 43 | `lrp-router-port_7b7ecd3c-2b5c-49ca-936f-ab79b67aea63` | `192.168.52.1/24` |  |
| 44 | `lrp-router-port_7b5bb2c4-526f-4300-9d11-338fe4083c58` | `192.168.22.1/24` |  |
| 45 | `lrp-router-port_4732a674-e2c3-4a32-8b98-8d04ad8981e0` | `192.168.15.1/24` |  |
| 46 | `lrp-router-port_a6bdf8cc-6ed7-4989-b7f5-33fd250b3be8` | `192.168.45.1/24` |  |
| 47 | `lrp-router-port_bfdb0087-699f-4cda-968a-c83f5c59a0e3` | `192.168.74.1/24` |  |
| 48 | `lrp-router-port_ba2f2f7b-819b-48e8-9873-3a8d03a4ccd8` | `192.168.13.1/24` |  |
| 49 | `lrp-router-port_dd8bd26a-26ac-4dce-ba1a-b013a8a2eaeb` | `192.168.40.1/24` |  |
| 50 | `lrp-router-port_aaacea27-4b19-408b-b2a8-3ea5e8563bd8` | `192.168.29.1/24` |  |
| 51 | `lrp-router-port_6056da2d-7903-441e-9bad-f694d7c6efd6` | `192.168.16.1/24` |  |
| 52 | `lrp-router-port_8e2c5018-5789-4e8d-a0ca-de2aef90b054` | `192.168.24.1/24` |  |
| 53 | `lrp-router-port_8aedd6c8-e897-4611-978e-c968c15eda92` | `192.168.86.1/24` |  |
| 54 | `lrp-router-port_31f2dffa-1a77-4667-9df5-96ddbbb25998` | `192.168.7.1/24` |  |
| 55 | `lrp-router-port_a26841c2-d315-4598-9d4e-b722e6b0740e` | `192.168.75.1/24` |  |
| 56 | `lrp-router-port_98b8a929-e141-402b-8abd-cbafab4aad11` | `192.168.35.1/24` |  |
| 57 | `lrp-router-port_b5ac7378-d238-4655-bbcf-21965877290b` | `192.168.55.1/24` |  |
| 58 | `lrp-router-port_ee75b808-37c3-48e3-b951-323cd7ce8623` | `192.168.57.1/24` |  |
| 59 | `lrp-router-port_ec0d7873-0cec-4e0f-b521-fb87d4b8a5a2` | `192.168.9.1/24` |  |
| 60 | `lrp-router-port_cd95a7dd-3a73-4f75-bdb7-cca39a8c349f` | `192.168.2.1/24` |  |
| 61 | `lrp-router-port_5536566e-9f0e-4b24-a74a-23b37e1a4cc9` | `192.168.92.1/24` |  |
| 62 | `lrp-router-port_7fa8249e-89c7-436c-b73c-fc1c6c35c8a2` | `192.168.44.1/24` |  |
| 63 | `lrp-router-port_a6099d81-d558-4801-a626-e4b67e523609` | `192.168.89.1/24` |  |
| 64 | `lrp-router-port_75dc71e6-0677-49f6-a6fc-1aba0dbcd96e` | `192.168.95.1/24` |  |
| 65 | `lrp-router-port_5f201938-3047-4926-83e7-a2ce47cf5323` | `192.168.85.1/24` |  |
| 66 | `lrp-router-port_a8f4c5b9-8ed3-49c0-95a3-9fd9a367f8d5` | `192.168.71.1/24` |  |
| 67 | `lrp-router-port_d2c5df99-e81d-40e4-98da-6faaf1e56f02` | `192.168.253.1/24` |  |
| 68 | `lrp-router-port_c2884fa3-9c1b-4775-b3f5-1c1d4fa0545a` | `192.168.78.1/24` |  |
| 69 | `lrp-router-port_91a6ac0f-3bd8-4902-b3b2-b24dc0cbe78c` | `192.168.34.1/24` |  |
| 70 | `lrp-router-port_8ffb4745-7439-4c63-8557-ac89ee2a67c1` | `192.168.19.1/24` |  |
| 71 | `lrp-router-port_aef08078-d157-4726-81f9-89a0740b2b75` | `192.168.56.1/24` |  |
| 72 | `lrp-router-port_d8fbdfbb-d700-4bb6-acfa-cf2a4496eb77` | `192.168.93.1/24` |  |
| 73 | `lrp-router-port_c3be4831-ac8f-46c1-b915-e7ff36a141c7` | `192.168.72.1/24` |  |
| 74 | `lrp-router-port_ae3f429f-f5b2-419b-85d5-7604d80d17be` | `192.168.27.1/24` |  |
| 75 | `lrp-router-port_26655dc6-20c7-46fc-afa1-6854ebb737b9` | `192.168.96.1/24` |  |
| 76 | `lrp-router-port_7adec254-a0fd-4908-a1c8-0a5f43bb0639` | `192.168.66.1/24` |  |
| 77 | `lrp-router-port_7fe3e8df-402c-43a6-9b89-9f2518963842` | `192.168.20.1/24` |  |
| 78 | `lrp-router-port_27af2774-c142-4a05-8739-d78d1f02d22e` | `192.168.8.1/24` |  |
| 79 | `lrp-router-port_d5a053c9-426c-486c-bdd0-fab8ea9febb7` | `192.168.77.1/24` |  |
| 80 | `lrp-router-port_b5e6667d-3a04-4a97-8772-bbed3136b58a` | `192.168.51.1/24` |  |
| 81 | `lrp-router-port_d0d67ec6-bc34-4470-9c4d-ae668c5bf7a2` | `192.168.99.1/24` |  |
| 82 | `lrp-router-port_951af33a-3f9c-43df-9489-8295a785bfff` | `192.168.11.1/24` |  |
| 83 | `lrp-router-port_0d9118a5-635c-4128-a672-8da5544f07da` | `192.168.97.1/24` |  |
| 84 | `lrp-router-port_8c51f88f-84a9-4bc6-91a3-d86fba6000eb` | `192.168.67.1/24` |  |
| 85 | `lrp-router-port_20a2dea6-ce0a-4ed1-a7c2-487f61008c87` | `192.168.98.1/24` |  |
| 86 | `lrp-router-port_e71f71b1-e394-4035-b892-5474f450f7d7` | `192.168.84.1/24` |  |
| 87 | `lrp-router-port_724f58ea-11b2-49b7-96c5-cdc7e540cde1` | `192.168.37.1/24` |  |
| 88 | `lrp-router-port_9088b9d8-aea5-4f6f-94f3-ddb503d57c45` | `192.168.46.1/24` |  |
| 89 | `lrp-router-port_d3474aa1-21ac-4614-98b3-9578f293491d` | `192.168.30.1/24` |  |
| 90 | `lrp-router-port_4da00f14-4b97-492c-98f8-7cdee12d3f89` | `192.168.69.1/24` |  |
| 91 | `lrp-router-port_e92240e5-8825-4ecf-aced-98081cbc3483` | `192.168.58.1/24` |  |
| 92 | `lrp-router-port_86dbbc63-cec8-4f84-b7c4-297def9ce02a` | `192.168.62.1/24` |  |
| 93 | `lrp-router-port_2c813b95-2ea6-4ae9-8943-4915dcb03bf1` | `192.168.65.1/24` |  |
| 94 | `lrp-router-port_d12a033b-c4fa-40fe-86d5-59e0204b99df` | `192.168.33.1/24` |  |
| 95 | `lrp-router-port_12116e83-b0e3-4db1-9e07-5da35760bd0a` | `192.168.83.1/24` |  |
| 96 | `lrp-router-port_31d327ab-cdfa-4e6a-bb41-de932541ebb4` | `192.168.76.1/24` |  |
| 97 | `lrp-router-port_47c2c0c7-8697-4c67-bb84-d41d887af480` | `192.168.39.1/24` |  |
| 98 | `lrp-router-port_9ccef8d3-00c6-4419-83b1-f1630f89f70e` | `192.168.91.1/24` |  |
| 99 | `lrp-router-port_6c0558f1-f3b2-48fc-9770-5f2536efabb9` | `192.168.254.1/24` |  |
| 100 | `lrp-router-port_19e53512-d5ca-4400-a202-b4ecf350398a` | `192.168.94.1/24` |  |
| 101 | `lrp-router-port_f77b955e-d890-4442-aa17-e54663100cfb` | `192.168.23.1/24` |  |
| 102 | `lrp-router-port_50dd6605-d26f-461a-a825-6a585a416d5e` | `192.168.32.1/24` |  |
| 103 | `lrp-router-port_d0bbe94e-c02c-4978-a52d-6a1c31468ef9` | `192.168.43.1/24` |  |

#### Downstream — static routes on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 2 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `0.0.0.0/0` | `169.254.2.101` | `dst-ip` | `` |
| 2 | `0.0.0.0/0` | `169.254.2.100` | `dst-ip` | `` |

#### Downstream — GW chassis (RC) on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 0 rows
(none)

#### Downstream — path LRPs on router `router_818b2c20-4d1b-40b7-a951-5deb85316e68` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | LR ↔ transit | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68` | `e0:19:95:8d:46:1a` | `169.254.2.20/24` |  |
| 2 | src LS ↔ LR | `lrp-router-port_17fe24db-e08b-4f81-969a-e06d6f23b35c` | `e0:19:95:59:9f:05` | `192.168.1.1/24` |  |

#### Downstream — router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` ext-GW

#### Downstream — NAT on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 103 rows
| # | type | external_ip | logical_ip | logical_port |
|---|------|-------------|------------|--------------|
| 1 | dnat_and_snat | `10.116.246.72` | `192.168.253.70` | `` |
| 2 | snat | `10.116.246.47` | `192.168.1.0/24` | `` |
| 3 | snat | `10.116.246.47` | `192.168.10.0/24` | `` |
| 4 | snat | `10.116.246.47` | `192.168.100.0/24` | `` |
| 5 | snat | `10.116.246.47` | `192.168.11.0/24` | `` |
| 6 | snat | `10.116.246.47` | `192.168.12.0/24` | `` |
| 7 | snat | `10.116.246.47` | `192.168.13.0/24` | `` |
| 8 | snat | `10.116.246.47` | `192.168.14.0/24` | `` |
| 9 | snat | `10.116.246.47` | `192.168.15.0/24` | `` |
| 10 | snat | `10.116.246.47` | `192.168.16.0/24` | `` |
| 11 | snat | `10.116.246.47` | `192.168.17.0/24` | `` |
| 12 | snat | `10.116.246.47` | `192.168.18.0/24` | `` |
| 13 | snat | `10.116.246.47` | `192.168.19.0/24` | `` |
| 14 | snat | `10.116.246.47` | `192.168.2.0/24` | `` |
| 15 | snat | `10.116.246.47` | `192.168.20.0/24` | `` |
| 16 | snat | `10.116.246.47` | `192.168.21.0/24` | `` |
| 17 | snat | `10.116.246.47` | `192.168.22.0/24` | `` |
| 18 | snat | `10.116.246.47` | `192.168.23.0/24` | `` |
| 19 | snat | `10.116.246.47` | `192.168.24.0/24` | `` |
| 20 | snat | `10.116.246.47` | `192.168.25.0/24` | `` |
| 21 | snat | `10.116.246.47` | `192.168.253.0/24` | `` |
| 22 | snat | `10.116.246.47` | `192.168.254.0/24` | `` |
| 23 | snat | `10.116.246.47` | `192.168.26.0/24` | `` |
| 24 | snat | `10.116.246.47` | `192.168.27.0/24` | `` |
| 25 | snat | `10.116.246.47` | `192.168.28.0/24` | `` |
| 26 | snat | `10.116.246.47` | `192.168.29.0/24` | `` |
| 27 | snat | `10.116.246.47` | `192.168.3.0/24` | `` |
| 28 | snat | `10.116.246.47` | `192.168.30.0/24` | `` |
| 29 | snat | `10.116.246.47` | `192.168.31.0/24` | `` |
| 30 | snat | `10.116.246.47` | `192.168.32.0/24` | `` |
| 31 | snat | `10.116.246.47` | `192.168.33.0/24` | `` |
| 32 | snat | `10.116.246.47` | `192.168.34.0/24` | `` |
| 33 | snat | `10.116.246.47` | `192.168.35.0/24` | `` |
| 34 | snat | `10.116.246.47` | `192.168.36.0/24` | `` |
| 35 | snat | `10.116.246.47` | `192.168.37.0/24` | `` |
| 36 | snat | `10.116.246.47` | `192.168.38.0/24` | `` |
| 37 | snat | `10.116.246.47` | `192.168.39.0/24` | `` |
| 38 | snat | `10.116.246.47` | `192.168.4.0/24` | `` |
| 39 | snat | `10.116.246.47` | `192.168.40.0/24` | `` |
| 40 | snat | `10.116.246.47` | `192.168.41.0/24` | `` |
| 41 | snat | `10.116.246.47` | `192.168.42.0/24` | `` |
| 42 | snat | `10.116.246.47` | `192.168.43.0/24` | `` |
| 43 | snat | `10.116.246.47` | `192.168.44.0/24` | `` |
| 44 | snat | `10.116.246.47` | `192.168.45.0/24` | `` |
| 45 | snat | `10.116.246.47` | `192.168.46.0/24` | `` |
| 46 | snat | `10.116.246.47` | `192.168.47.0/24` | `` |
| 47 | snat | `10.116.246.47` | `192.168.48.0/24` | `` |
| 48 | snat | `10.116.246.47` | `192.168.49.0/24` | `` |
| 49 | snat | `10.116.246.47` | `192.168.5.0/24` | `` |
| 50 | snat | `10.116.246.47` | `192.168.50.0/24` | `` |
| 51 | snat | `10.116.246.47` | `192.168.51.0/24` | `` |
| 52 | snat | `10.116.246.47` | `192.168.52.0/24` | `` |
| 53 | snat | `10.116.246.47` | `192.168.53.0/24` | `` |
| 54 | snat | `10.116.246.47` | `192.168.54.0/24` | `` |
| 55 | snat | `10.116.246.47` | `192.168.55.0/24` | `` |
| 56 | snat | `10.116.246.47` | `192.168.56.0/24` | `` |
| 57 | snat | `10.116.246.47` | `192.168.57.0/24` | `` |
| 58 | snat | `10.116.246.47` | `192.168.58.0/24` | `` |
| 59 | snat | `10.116.246.47` | `192.168.59.0/24` | `` |
| 60 | snat | `10.116.246.47` | `192.168.6.0/24` | `` |
| 61 | snat | `10.116.246.47` | `192.168.60.0/24` | `` |
| 62 | snat | `10.116.246.47` | `192.168.61.0/24` | `` |
| 63 | snat | `10.116.246.47` | `192.168.62.0/24` | `` |
| 64 | snat | `10.116.246.47` | `192.168.63.0/24` | `` |
| 65 | snat | `10.116.246.47` | `192.168.64.0/24` | `` |
| 66 | snat | `10.116.246.47` | `192.168.65.0/24` | `` |
| 67 | snat | `10.116.246.47` | `192.168.66.0/24` | `` |
| 68 | snat | `10.116.246.47` | `192.168.67.0/24` | `` |
| 69 | snat | `10.116.246.47` | `192.168.68.0/24` | `` |
| 70 | snat | `10.116.246.47` | `192.168.69.0/24` | `` |
| 71 | snat | `10.116.246.47` | `192.168.7.0/24` | `` |
| 72 | snat | `10.116.246.47` | `192.168.70.0/24` | `` |
| 73 | snat | `10.116.246.47` | `192.168.71.0/24` | `` |
| 74 | snat | `10.116.246.47` | `192.168.72.0/24` | `` |
| 75 | snat | `10.116.246.47` | `192.168.73.0/24` | `` |
| 76 | snat | `10.116.246.47` | `192.168.74.0/24` | `` |
| 77 | snat | `10.116.246.47` | `192.168.75.0/24` | `` |
| 78 | snat | `10.116.246.47` | `192.168.76.0/24` | `` |
| 79 | snat | `10.116.246.47` | `192.168.77.0/24` | `` |
| 80 | snat | `10.116.246.47` | `192.168.78.0/24` | `` |
| 81 | snat | `10.116.246.47` | `192.168.79.0/24` | `` |
| 82 | snat | `10.116.246.47` | `192.168.8.0/24` | `` |
| 83 | snat | `10.116.246.47` | `192.168.80.0/24` | `` |
| 84 | snat | `10.116.246.47` | `192.168.81.0/24` | `` |
| 85 | snat | `10.116.246.47` | `192.168.82.0/24` | `` |
| 86 | snat | `10.116.246.47` | `192.168.83.0/24` | `` |
| 87 | snat | `10.116.246.47` | `192.168.84.0/24` | `` |
| 88 | snat | `10.116.246.47` | `192.168.85.0/24` | `` |
| 89 | snat | `10.116.246.47` | `192.168.86.0/24` | `` |
| 90 | snat | `10.116.246.47` | `192.168.87.0/24` | `` |
| 91 | snat | `10.116.246.47` | `192.168.88.0/24` | `` |
| 92 | snat | `10.116.246.47` | `192.168.89.0/24` | `` |
| 93 | snat | `10.116.246.47` | `192.168.9.0/24` | `` |
| 94 | snat | `10.116.246.47` | `192.168.90.0/24` | `` |
| 95 | snat | `10.116.246.47` | `192.168.91.0/24` | `` |
| 96 | snat | `10.116.246.47` | `192.168.92.0/24` | `` |
| 97 | snat | `10.116.246.47` | `192.168.93.0/24` | `` |
| 98 | snat | `10.116.246.47` | `192.168.94.0/24` | `` |
| 99 | snat | `10.116.246.47` | `192.168.95.0/24` | `` |
| 100 | snat | `10.116.246.47` | `192.168.96.0/24` | `` |
| 101 | snat | `10.116.246.47` | `192.168.97.0/24` | `` |
| 102 | snat | `10.116.246.47` | `192.168.98.0/24` | `` |
| 103 | snat | `10.116.246.47` | `192.168.99.0/24` | `` |

#### Downstream — PBR on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 0 rows
(none)

#### Downstream — connected routes on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 2 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `169.254.2.100/24` |  |
| 2 | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `10.116.246.47/18` | yes |

#### Downstream — static routes on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 103 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `192.168.11.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 2 | `192.168.25.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 3 | `192.168.42.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 4 | `192.168.52.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 5 | `192.168.53.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 6 | `192.168.4.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 7 | `192.168.60.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 8 | `192.168.96.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 9 | `192.168.77.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 10 | `192.168.92.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 11 | `192.168.69.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 12 | `192.168.65.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 13 | `192.168.54.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 14 | `192.168.44.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 15 | `192.168.56.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 16 | `192.168.74.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 17 | `192.168.9.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 18 | `192.168.38.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 19 | `192.168.86.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 20 | `192.168.95.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 21 | `192.168.55.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 22 | `192.168.76.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 23 | `192.168.8.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 24 | `192.168.81.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 25 | `192.168.50.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 26 | `192.168.36.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 27 | `192.168.33.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 28 | `192.168.14.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 29 | `192.168.59.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 30 | `192.168.26.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 31 | `192.168.61.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 32 | `192.168.71.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 33 | `192.168.79.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 34 | `192.168.90.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 35 | `192.168.83.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 36 | `192.168.72.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 37 | `192.168.35.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 38 | `192.168.12.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 39 | `192.168.63.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 40 | `192.168.84.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 41 | `192.168.27.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 42 | `192.168.2.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 43 | `192.168.253.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 44 | `192.168.34.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 45 | `192.168.19.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 46 | `192.168.66.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 47 | `192.168.89.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 48 | `192.168.29.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 49 | `192.168.78.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 50 | `192.168.28.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 51 | `192.168.58.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 52 | `192.168.80.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 53 | `192.168.85.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 54 | `192.168.20.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 55 | `192.168.254.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 56 | `192.168.39.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 57 | `192.168.48.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 58 | `192.168.62.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 59 | `192.168.16.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 60 | `192.168.46.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 61 | `192.168.37.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 62 | `0.0.0.0/0` | `10.116.192.1` | `dst-ip` | `` |
| 63 | `192.168.68.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 64 | `192.168.45.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 65 | `192.168.10.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 66 | `192.168.49.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 67 | `192.168.6.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 68 | `192.168.7.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 69 | `192.168.73.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 70 | `192.168.57.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 71 | `192.168.70.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 72 | `192.168.18.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 73 | `192.168.22.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 74 | `192.168.43.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 75 | `192.168.87.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 76 | `192.168.3.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 77 | `192.168.98.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 78 | `192.168.93.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 79 | `192.168.17.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 80 | `192.168.99.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 81 | `192.168.75.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 82 | `192.168.31.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 83 | `192.168.64.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 84 | `192.168.51.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 85 | `192.168.21.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 86 | `192.168.88.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 87 | `192.168.91.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 88 | `192.168.24.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 89 | `192.168.30.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 90 | `192.168.100.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 91 | `192.168.94.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 92 | `192.168.15.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 93 | `192.168.5.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 94 | `192.168.32.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 95 | `192.168.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 96 | `192.168.67.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 97 | `192.168.23.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 98 | `192.168.41.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 99 | `192.168.82.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 100 | `192.168.47.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 101 | `192.168.40.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 102 | `192.168.13.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 103 | `192.168.97.0/24` | `169.254.2.20` | `dst-ip` | `` |

#### Downstream — GW chassis (RC) on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 1 rows
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | active RC | `zadkiel04-3` | `e6226ec1-fa8f-41e5-8d0c-7a884b7f9634` | `a109bd1b-b3d4-423d-8122-3fc3c80d4292` | 100 |

#### Downstream — path LRPs on router `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | transit ↔ GW | `lrp-gw-scale-out-router-port_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0` | `e0:19:95:87:06:3b` | `169.254.2.100/24` |  |
| 2 | GW ↔ external | `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` | `e0:19:95:14:17:37` | `10.116.246.47/18` | yes |

#### Downstream — External GW MAC/IP on `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_0`

- LRP `lrp-ext_gw_port_682ea258-3d59-4a4e-bc34-34810b9f29b0` MAC `e0:19:95:14:17:37` IP `10.116.246.47/18`

#### Downstream — scale-out peer `gw-scale-out-router_nat_818b2c20-4d1b-40b7-a951-5deb85316e68_1` (standby) host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20`

- External GW MAC `e0:19:95:5b:76:31` IP `10.116.246.48/18`
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | standby scale-out | `flashfire01-2` | `74e0be63-f78f-482a-b04e-a09ada933f20` | `ef355d92-dc3b-4dc4-aaf4-7c559db792d7` | 100 |

#### Downstream — router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` ext-GW

#### Downstream — NAT on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 105 rows
| # | type | external_ip | logical_ip | logical_port |
|---|------|-------------|------------|--------------|
| 1 | dnat_and_snat | `10.116.246.1` | `192.168.254.168` | `` |
| 2 | dnat_and_snat | `10.116.246.43` | `100.64.1.222` | `` |
| 3 | snat | `10.116.246.55` | `100.64.1.0/24` | `` |
| 4 | snat | `10.116.246.55` | `192.168.1.0/24` | `` |
| 5 | snat | `10.116.246.55` | `192.168.10.0/24` | `` |
| 6 | snat | `10.116.246.55` | `192.168.100.0/24` | `` |
| 7 | snat | `10.116.246.55` | `192.168.11.0/24` | `` |
| 8 | snat | `10.116.246.55` | `192.168.12.0/24` | `` |
| 9 | snat | `10.116.246.55` | `192.168.13.0/24` | `` |
| 10 | snat | `10.116.246.55` | `192.168.14.0/24` | `` |
| 11 | snat | `10.116.246.55` | `192.168.15.0/24` | `` |
| 12 | snat | `10.116.246.55` | `192.168.16.0/24` | `` |
| 13 | snat | `10.116.246.55` | `192.168.17.0/24` | `` |
| 14 | snat | `10.116.246.55` | `192.168.18.0/24` | `` |
| 15 | snat | `10.116.246.55` | `192.168.19.0/24` | `` |
| 16 | snat | `10.116.246.55` | `192.168.2.0/24` | `` |
| 17 | snat | `10.116.246.55` | `192.168.20.0/24` | `` |
| 18 | snat | `10.116.246.55` | `192.168.21.0/24` | `` |
| 19 | snat | `10.116.246.55` | `192.168.22.0/24` | `` |
| 20 | snat | `10.116.246.55` | `192.168.23.0/24` | `` |
| 21 | snat | `10.116.246.55` | `192.168.24.0/24` | `` |
| 22 | snat | `10.116.246.55` | `192.168.25.0/24` | `` |
| 23 | snat | `10.116.246.55` | `192.168.253.0/24` | `` |
| 24 | snat | `10.116.246.55` | `192.168.254.0/24` | `` |
| 25 | snat | `10.116.246.55` | `192.168.26.0/24` | `` |
| 26 | snat | `10.116.246.55` | `192.168.27.0/24` | `` |
| 27 | snat | `10.116.246.55` | `192.168.28.0/24` | `` |
| 28 | snat | `10.116.246.55` | `192.168.29.0/24` | `` |
| 29 | snat | `10.116.246.55` | `192.168.3.0/24` | `` |
| 30 | snat | `10.116.246.55` | `192.168.30.0/24` | `` |
| 31 | snat | `10.116.246.55` | `192.168.31.0/24` | `` |
| 32 | snat | `10.116.246.55` | `192.168.32.0/24` | `` |
| 33 | snat | `10.116.246.55` | `192.168.33.0/24` | `` |
| 34 | snat | `10.116.246.55` | `192.168.34.0/24` | `` |
| 35 | snat | `10.116.246.55` | `192.168.35.0/24` | `` |
| 36 | snat | `10.116.246.55` | `192.168.36.0/24` | `` |
| 37 | snat | `10.116.246.55` | `192.168.37.0/24` | `` |
| 38 | snat | `10.116.246.55` | `192.168.38.0/24` | `` |
| 39 | snat | `10.116.246.55` | `192.168.39.0/24` | `` |
| 40 | snat | `10.116.246.55` | `192.168.4.0/24` | `` |
| 41 | snat | `10.116.246.55` | `192.168.40.0/24` | `` |
| 42 | snat | `10.116.246.55` | `192.168.41.0/24` | `` |
| 43 | snat | `10.116.246.55` | `192.168.42.0/24` | `` |
| 44 | snat | `10.116.246.55` | `192.168.43.0/24` | `` |
| 45 | snat | `10.116.246.55` | `192.168.44.0/24` | `` |
| 46 | snat | `10.116.246.55` | `192.168.45.0/24` | `` |
| 47 | snat | `10.116.246.55` | `192.168.46.0/24` | `` |
| 48 | snat | `10.116.246.55` | `192.168.47.0/24` | `` |
| 49 | snat | `10.116.246.55` | `192.168.48.0/24` | `` |
| 50 | snat | `10.116.246.55` | `192.168.49.0/24` | `` |
| 51 | snat | `10.116.246.55` | `192.168.5.0/24` | `` |
| 52 | snat | `10.116.246.55` | `192.168.50.0/24` | `` |
| 53 | snat | `10.116.246.55` | `192.168.51.0/24` | `` |
| 54 | snat | `10.116.246.55` | `192.168.52.0/24` | `` |
| 55 | snat | `10.116.246.55` | `192.168.53.0/24` | `` |
| 56 | snat | `10.116.246.55` | `192.168.54.0/24` | `` |
| 57 | snat | `10.116.246.55` | `192.168.55.0/24` | `` |
| 58 | snat | `10.116.246.55` | `192.168.56.0/24` | `` |
| 59 | snat | `10.116.246.55` | `192.168.57.0/24` | `` |
| 60 | snat | `10.116.246.55` | `192.168.58.0/24` | `` |
| 61 | snat | `10.116.246.55` | `192.168.59.0/24` | `` |
| 62 | snat | `10.116.246.55` | `192.168.6.0/24` | `` |
| 63 | snat | `10.116.246.55` | `192.168.60.0/24` | `` |
| 64 | snat | `10.116.246.55` | `192.168.61.0/24` | `` |
| 65 | snat | `10.116.246.55` | `192.168.62.0/24` | `` |
| 66 | snat | `10.116.246.55` | `192.168.63.0/24` | `` |
| 67 | snat | `10.116.246.55` | `192.168.64.0/24` | `` |
| 68 | snat | `10.116.246.55` | `192.168.65.0/24` | `` |
| 69 | snat | `10.116.246.55` | `192.168.66.0/24` | `` |
| 70 | snat | `10.116.246.55` | `192.168.67.0/24` | `` |
| 71 | snat | `10.116.246.55` | `192.168.68.0/24` | `` |
| 72 | snat | `10.116.246.55` | `192.168.69.0/24` | `` |
| 73 | snat | `10.116.246.55` | `192.168.7.0/24` | `` |
| 74 | snat | `10.116.246.55` | `192.168.70.0/24` | `` |
| 75 | snat | `10.116.246.55` | `192.168.71.0/24` | `` |
| 76 | snat | `10.116.246.55` | `192.168.72.0/24` | `` |
| 77 | snat | `10.116.246.55` | `192.168.73.0/24` | `` |
| 78 | snat | `10.116.246.55` | `192.168.74.0/24` | `` |
| 79 | snat | `10.116.246.55` | `192.168.75.0/24` | `` |
| 80 | snat | `10.116.246.55` | `192.168.76.0/24` | `` |
| 81 | snat | `10.116.246.55` | `192.168.77.0/24` | `` |
| 82 | snat | `10.116.246.55` | `192.168.78.0/24` | `` |
| 83 | snat | `10.116.246.55` | `192.168.79.0/24` | `` |
| 84 | snat | `10.116.246.55` | `192.168.8.0/24` | `` |
| 85 | snat | `10.116.246.55` | `192.168.80.0/24` | `` |
| 86 | snat | `10.116.246.55` | `192.168.81.0/24` | `` |
| 87 | snat | `10.116.246.55` | `192.168.82.0/24` | `` |
| 88 | snat | `10.116.246.55` | `192.168.83.0/24` | `` |
| 89 | snat | `10.116.246.55` | `192.168.84.0/24` | `` |
| 90 | snat | `10.116.246.55` | `192.168.85.0/24` | `` |
| 91 | snat | `10.116.246.55` | `192.168.86.0/24` | `` |
| 92 | snat | `10.116.246.55` | `192.168.87.0/24` | `` |
| 93 | snat | `10.116.246.55` | `192.168.88.0/24` | `` |
| 94 | snat | `10.116.246.55` | `192.168.89.0/24` | `` |
| 95 | snat | `10.116.246.55` | `192.168.9.0/24` | `` |
| 96 | snat | `10.116.246.55` | `192.168.90.0/24` | `` |
| 97 | snat | `10.116.246.55` | `192.168.91.0/24` | `` |
| 98 | snat | `10.116.246.55` | `192.168.92.0/24` | `` |
| 99 | snat | `10.116.246.55` | `192.168.93.0/24` | `` |
| 100 | snat | `10.116.246.55` | `192.168.94.0/24` | `` |
| 101 | snat | `10.116.246.55` | `192.168.95.0/24` | `` |
| 102 | snat | `10.116.246.55` | `192.168.96.0/24` | `` |
| 103 | snat | `10.116.246.55` | `192.168.97.0/24` | `` |
| 104 | snat | `10.116.246.55` | `192.168.98.0/24` | `` |
| 105 | snat | `10.116.246.55` | `192.168.99.0/24` | `` |

#### Downstream — PBR on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 1 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 1000 | reroute | `ip4.src==100.64.1.6/32` | `169.254.2.100` |

#### Downstream — connected routes on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 2 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `10.116.246.55/18` | yes |
| 2 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `169.254.2.101/24` |  |

#### Downstream — static routes on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 104 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `192.168.49.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 2 | `192.168.65.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 3 | `192.168.4.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 4 | `192.168.59.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 5 | `192.168.78.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 6 | `192.168.254.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 7 | `192.168.98.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 8 | `192.168.28.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 9 | `192.168.16.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 10 | `192.168.84.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 11 | `192.168.25.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 12 | `192.168.39.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 13 | `192.168.12.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 14 | `192.168.81.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 15 | `192.168.91.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 16 | `192.168.43.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 17 | `192.168.42.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 18 | `192.168.40.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 19 | `192.168.86.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 20 | `192.168.64.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 21 | `192.168.67.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 22 | `192.168.13.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 23 | `0.0.0.0/0` | `10.116.192.1` | `dst-ip` | `` |
| 24 | `192.168.8.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 25 | `192.168.46.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 26 | `192.168.253.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 27 | `192.168.44.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 28 | `192.168.21.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 29 | `192.168.100.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 30 | `192.168.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 31 | `192.168.18.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 32 | `192.168.20.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 33 | `192.168.47.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 34 | `100.64.1.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 35 | `192.168.19.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 36 | `192.168.6.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 37 | `192.168.95.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 38 | `192.168.85.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 39 | `192.168.60.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 40 | `192.168.7.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 41 | `192.168.30.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 42 | `192.168.80.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 43 | `192.168.57.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 44 | `192.168.75.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 45 | `192.168.68.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 46 | `192.168.10.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 47 | `192.168.27.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 48 | `192.168.61.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 49 | `192.168.22.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 50 | `192.168.70.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 51 | `192.168.94.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 52 | `192.168.66.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 53 | `192.168.17.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 54 | `192.168.38.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 55 | `192.168.2.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 56 | `192.168.96.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 57 | `192.168.82.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 58 | `192.168.3.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 59 | `192.168.36.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 60 | `192.168.31.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 61 | `192.168.92.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 62 | `192.168.90.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 63 | `192.168.33.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 64 | `192.168.50.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 65 | `192.168.48.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 66 | `192.168.62.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 67 | `192.168.14.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 68 | `192.168.37.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 69 | `192.168.29.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 70 | `192.168.41.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 71 | `192.168.63.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 72 | `192.168.88.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 73 | `192.168.51.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 74 | `192.168.34.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 75 | `192.168.23.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 76 | `192.168.56.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 77 | `192.168.99.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 78 | `192.168.71.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 79 | `192.168.72.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 80 | `192.168.93.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 81 | `192.168.15.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 82 | `192.168.89.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 83 | `192.168.5.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 84 | `192.168.69.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 85 | `192.168.76.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 86 | `192.168.73.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 87 | `192.168.45.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 88 | `192.168.11.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 89 | `192.168.54.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 90 | `192.168.97.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 91 | `192.168.26.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 92 | `192.168.83.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 93 | `192.168.32.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 94 | `192.168.55.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 95 | `192.168.9.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 96 | `192.168.53.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 97 | `192.168.52.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 98 | `192.168.77.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 99 | `192.168.87.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 100 | `192.168.79.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 101 | `192.168.24.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 102 | `192.168.74.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 103 | `192.168.35.0/24` | `169.254.2.20` | `dst-ip` | `` |
| 104 | `192.168.58.0/24` | `169.254.2.20` | `dst-ip` | `` |

#### Downstream — GW chassis (RC) on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 1 rows
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | active RC | `zadkiel04-1` | `b594f638-f4a0-439b-91d4-1c513f0c4529` | `bb49616e-e5ad-4dd7-9d98-ad529702d2df` | 100 |

#### Downstream — path LRPs on router `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | GW ↔ external | `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` | `e0:19:95:9b:58:bb` | `10.116.246.55/18` | yes |
| 2 | transit ↔ GW | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1` | `e0:19:95:60:29:5b` | `169.254.2.101/24` |  |

#### Downstream — External GW MAC/IP on `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_1`

- LRP `lrp-ext_gw_port_2d18744a-e421-4971-910d-e3e120f2d212` MAC `e0:19:95:9b:58:bb` IP `10.116.246.55/18`

#### Downstream — scale-out peer `gw-scale-out-router_nat_fc433064-926d-4fc0-a1a3-7c089ad90343_0` (standby) host `flashfire01-2` chassis `74e0be63-f78f-482a-b04e-a09ada933f20`

- External GW MAC `e0:19:95:c0:b3:04` IP `10.116.246.54/18`
| # | role | hostname | chassis_uuid | chassis_name | priority |
|---|------|----------|--------------|--------------|----------|
| 1 | standby scale-out | `flashfire01-2` | `74e0be63-f78f-482a-b04e-a09ada933f20` | `ef355d92-dc3b-4dc4-aaf4-7c559db792d7` | 100 |

#### Downstream — router `router_fc433064-926d-4fc0-a1a3-7c089ad90343`

#### Downstream — NAT on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 0 rows
(none)

#### Downstream — PBR on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 3 rows
| # | pri | action | match | nexthop |
|---|-----|--------|-------|---------|
| 1 | 100 | allow | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 2 | 10 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |
| 3 | 1 | drop | `ip4.dst==0.0.0.0/0 && ip4.src==0.0.0.0/0` | `` |

#### Downstream — connected routes on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 104 rows
| # | lrp | cidr | ext_gw |
|---|-----|------|--------|
| 1 | `lrp-router-port_8ca6f7a0-3f82-4de7-911b-f1e92b5ec140` | `192.168.93.1/24` |  |
| 2 | `lrp-router-port_e03534c4-e36c-4067-9f9d-459ce653637d` | `192.168.34.1/24` |  |
| 3 | `lrp-router-port_b4685b3f-31a1-4c96-9b30-a68ae1b0a272` | `192.168.61.1/24` |  |
| 4 | `lrp-router-port_d110f476-68a9-4d94-9911-5fc864464b43` | `192.168.72.1/24` |  |
| 5 | `lrp-router-port_bfbc4008-67c9-476c-966a-cf8465a909e3` | `192.168.45.1/24` |  |
| 6 | `lrp-router-port_a7799f72-bad9-482e-9466-cbcdd59d7625` | `192.168.98.1/24` |  |
| 7 | `lrp-router-port_d4df28ac-20e5-40fe-b659-368c0d4f9698` | `192.168.70.1/24` |  |
| 8 | `lrp-router-port_0c904e1b-e631-4f18-8acb-e3051368d3f9` | `192.168.81.1/24` |  |
| 9 | `lrp-router-port_807ed90e-1fda-497f-9098-7958ef0d4990` | `192.168.4.1/24` |  |
| 10 | `lrp-router-port_c8d975d9-60b0-419c-b56d-f28f9200504f` | `192.168.9.1/24` |  |
| 11 | `lrp-router-port_4bceacc5-ac6e-4008-8e70-97cfd30e5430` | `192.168.32.1/24` |  |
| 12 | `lrp-router-port_8f8336aa-42da-43b7-8757-3997a975a07d` | `192.168.68.1/24` |  |
| 13 | `lrp-router-port_8dcafab3-5338-4114-9eef-0e6fa19605df` | `192.168.99.1/24` |  |
| 14 | `lrp-router-port_9dd293d7-0450-478d-980b-8b5bd08a89cb` | `192.168.87.1/24` |  |
| 15 | `lrp-router-port_4ea3c785-c4a9-498c-80f3-ed2aa55c29d9` | `192.168.11.1/24` |  |
| 16 | `lrp-router-port_c307271a-0a3d-4325-8071-71b873bc3768` | `192.168.100.1/24` |  |
| 17 | `lrp-router-port_fa0c4784-a17e-4b1f-b4ff-220bca5b4cce` | `192.168.14.1/24` |  |
| 18 | `lrp-router-port_e141bb39-f661-4c6f-95cd-63773a7db69d` | `192.168.48.1/24` |  |
| 19 | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `192.168.2.1/24` |  |
| 20 | `lrp-router-port_032fedb1-1e88-4849-bc5d-ad7f358ea600` | `192.168.73.1/24` |  |
| 21 | `lrp-router-port_2c1b4c9d-8fd5-4354-8205-62ef2d28cef8` | `192.168.60.1/24` |  |
| 22 | `lrp-router-port_2dc24931-94e9-439b-986f-7a62a7bf92a1` | `192.168.55.1/24` |  |
| 23 | `lrp-router-port_0743c6fc-5073-425e-9770-ead8c56c42e9` | `192.168.78.1/24` |  |
| 24 | `lrp-router-port_830e914f-389c-4171-a7be-8e0d1f94c96b` | `192.168.33.1/24` |  |
| 25 | `lrp-router-port_d25f3dea-d19d-4c4c-a487-41613ce2eb61` | `192.168.67.1/24` |  |
| 26 | `lrp-router-port_71d41765-890f-4b8d-895b-e82505096413` | `192.168.46.1/24` |  |
| 27 | `lrp-router-port_675f2734-4826-467a-b43e-00698627a259` | `192.168.40.1/24` |  |
| 28 | `lrp-router-port_42ecfffe-0e34-4d14-85f7-5301de17cf69` | `192.168.90.1/24` |  |
| 29 | `lrp-router-port_fa896d0f-b0d0-4fa3-b688-331e9edc2a39` | `192.168.20.1/24` |  |
| 30 | `lrp-router-port_0ba9c57a-57c7-4ef9-8c24-4786c8f54d47` | `192.168.31.1/24` |  |
| 31 | `lrp-router-port_174db21e-8ba1-48eb-beb6-aa4ab68a2305` | `192.168.76.1/24` |  |
| 32 | `lrp-router-port_4bdb92dc-d31e-46fb-89e9-88a99f403c29` | `192.168.57.1/24` |  |
| 33 | `lrp-router-port_ca086587-3fdb-41e7-8571-d01547cece9f` | `192.168.17.1/24` |  |
| 34 | `lrp-router-port_2dac78de-9721-4a5b-8086-4c965dd6c619` | `192.168.27.1/24` |  |
| 35 | `lrp-router-port_dae15e78-0138-406f-9c44-5931c2433eae` | `192.168.253.1/24` |  |
| 36 | `lrp-router-port_f78566a0-d032-4d39-b160-26a846193005` | `192.168.6.1/24` |  |
| 37 | `lrp-router-port_81097727-e648-454a-81df-ae0520caca2c` | `192.168.74.1/24` |  |
| 38 | `lrp-router-port_1358d80d-13be-42f7-ac61-82d076a18135` | `192.168.96.1/24` |  |
| 39 | `lrp-router-port_30c8fe9c-b42a-4e3e-a38a-cc11cb73d1e6` | `192.168.16.1/24` |  |
| 40 | `lrp-router-port_8b6751f8-979a-42f0-b64d-d71fea87beee` | `192.168.19.1/24` |  |
| 41 | `lrp-router-port_2f065e5c-a736-43f7-a8f9-ad969e733b13` | `192.168.8.1/24` |  |
| 42 | `lrp-router-port_0f1f3f44-0fa0-45c4-918d-ac99e0d75e0d` | `192.168.95.1/24` |  |
| 43 | `lrp-router-port_e09f8b78-d094-4bdd-9f6d-18b0d14e50bf` | `192.168.63.1/24` |  |
| 44 | `lrp-router-port_80e90459-8298-4d6c-95bf-9deecc8c48fb` | `192.168.29.1/24` |  |
| 45 | `lrp-router-port_073a0cb1-e7cc-4b24-92f2-9c07ff0ab096` | `192.168.41.1/24` |  |
| 46 | `lrp-router-port_37fb764e-d0fa-457b-a216-43d9b11b3aed` | `192.168.65.1/24` |  |
| 47 | `lrp-router-port_b69e06e1-b184-4390-8cd6-f22044118b16` | `100.64.1.1/24` |  |
| 48 | `lrp-router-port_75e16325-7223-4e38-a44c-a04509f4f777` | `192.168.44.1/24` |  |
| 49 | `lrp-router-port_c0e67438-6eae-42c9-b6f2-6f6e470d4db8` | `192.168.89.1/24` |  |
| 50 | `lrp-router-port_de80667d-6f56-4481-ba8f-14be08b4a8fc` | `192.168.42.1/24` |  |
| 51 | `lrp-router-port_e8a882dc-a636-4b57-ab53-813694611e92` | `192.168.26.1/24` |  |
| 52 | `lrp-router-port_620e1ab8-b44e-4051-97b4-b3e73728664d` | `192.168.30.1/24` |  |
| 53 | `lrp-router-port_6e1383c1-5e63-46ea-b513-416115448c8e` | `192.168.80.1/24` |  |
| 54 | `lrp-router-port_195bf1a1-d7ab-44a9-987b-4e595a4c34e0` | `192.168.58.1/24` |  |
| 55 | `lrp-router-port_e800940d-51e7-42e1-a338-647494e919db` | `192.168.47.1/24` |  |
| 56 | `lrp-router-port_e0002237-57a9-433f-9e82-938599b90a98` | `192.168.83.1/24` |  |
| 57 | `lrp-router-port_48ef8369-ed7d-400a-b84c-c74e67a54347` | `192.168.88.1/24` |  |
| 58 | `lrp-router-port_c275c897-fea0-434c-a9ab-fa02a5af893a` | `192.168.69.1/24` |  |
| 59 | `lrp-router-port_fe749a87-cf4d-42e1-b165-e5551acdb3c3` | `192.168.21.1/24` |  |
| 60 | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `169.254.2.20/24` |  |
| 61 | `lrp-router-port_da0d1e4f-cd5e-4d70-b6cb-76c26d3268ef` | `192.168.36.1/24` |  |
| 62 | `lrp-router-port_a42276da-b029-4099-bc9d-c81a6c5c229d` | `192.168.56.1/24` |  |
| 63 | `lrp-router-port_baf0d081-ea93-4077-899d-f7e6dc63f539` | `192.168.59.1/24` |  |
| 64 | `lrp-router-port_ebf08da2-c15c-473b-a1bd-8f5f871ad07a` | `192.168.71.1/24` |  |
| 65 | `lrp-router-port_c5422e1c-4aae-4e5f-9520-936bc881921d` | `192.168.28.1/24` |  |
| 66 | `lrp-router-port_b53ef258-faec-4995-b4e7-d2d4a061ddf2` | `192.168.18.1/24` |  |
| 67 | `lrp-router-port_d5d2d617-49ca-49a7-9665-f89f5ff8d0f2` | `192.168.22.1/24` |  |
| 68 | `lrp-router-port_782ca68a-04b1-4fdc-a822-9d58215f7765` | `192.168.86.1/24` |  |
| 69 | `lrp-router-port_dbf060f4-6528-4cd8-8a68-f32313bb409a` | `192.168.92.1/24` |  |
| 70 | `lrp-router-port_d1624e61-07ee-47a2-9816-691b67ad9a9b` | `192.168.77.1/24` |  |
| 71 | `lrp-router-port_3ea92dc1-e13d-4e44-adad-e2adb944fd31` | `192.168.24.1/24` |  |
| 72 | `lrp-router-port_6c8f9dd7-4e03-4c2c-9fe5-da7eac887606` | `192.168.66.1/24` |  |
| 73 | `lrp-router-port_4124a4e2-3461-47f4-8612-377639eaaf87` | `192.168.64.1/24` |  |
| 74 | `lrp-router-port_3299d3a7-124a-4c43-9ae9-0f798040eae1` | `192.168.49.1/24` |  |
| 75 | `lrp-router-port_93837b6a-1c71-47fe-a427-7b818c6874d7` | `192.168.43.1/24` |  |
| 76 | `lrp-router-port_9ec643a3-96ce-4ad1-b80d-708e8149f79d` | `192.168.15.1/24` |  |
| 77 | `lrp-router-port_3d07fc33-53d7-4f9a-b853-449ef50a2eea` | `192.168.94.1/24` |  |
| 78 | `lrp-router-port_6fef40cb-9010-4464-af83-fa6e75ec0b6d` | `192.168.7.1/24` |  |
| 79 | `lrp-router-port_5fd6becb-db5b-4c6f-bcdd-35e95888cc20` | `192.168.254.1/24` |  |
| 80 | `lrp-router-port_455bebd3-3c1b-4e18-be7b-343d7350e90f` | `192.168.39.1/24` |  |
| 81 | `lrp-router-port_a5627ef6-0b96-4e84-867a-3f257ea3dbf3` | `192.168.97.1/24` |  |
| 82 | `lrp-router-port_88c50715-b1a5-4281-bee9-11dc6671f8ad` | `192.168.84.1/24` |  |
| 83 | `lrp-router-port_96d3605c-fe95-455b-83a6-dd2d3e52373a` | `192.168.52.1/24` |  |
| 84 | `lrp-router-port_ca6a8331-7e2a-4573-987c-4ef24353ee07` | `192.168.13.1/24` |  |
| 85 | `lrp-router-port_865e3efc-d7dc-4861-93d5-68bf71423c8b` | `192.168.53.1/24` |  |
| 86 | `lrp-router-port_39569c73-80df-40ac-ad18-7423d9cfb292` | `192.168.51.1/24` |  |
| 87 | `lrp-router-port_80f5715e-6fd6-4de3-9899-17770493824a` | `192.168.91.1/24` |  |
| 88 | `lrp-router-port_6d7bd89d-5a0f-431e-84a4-309187eb3f7b` | `192.168.38.1/24` |  |
| 89 | `lrp-router-port_dfc48fc2-f9a8-4586-bfec-4cd162977bfd` | `192.168.62.1/24` |  |
| 90 | `lrp-router-port_52c2face-3b8d-477b-8b84-fa721e061794` | `192.168.37.1/24` |  |
| 91 | `lrp-router-port_f472f5ad-5429-4b29-8044-19347c60d356` | `192.168.10.1/24` |  |
| 92 | `lrp-router-port_262750bb-7def-46a5-acd0-cd35df02f331` | `192.168.82.1/24` |  |
| 93 | `lrp-router-port_cf479cc5-632e-4c40-ae45-4c316472ab1e` | `192.168.79.1/24` |  |
| 94 | `lrp-router-port_fcd16e74-c7c6-4617-91f8-9d0bbc6aec9c` | `192.168.85.1/24` |  |
| 95 | `lrp-router-port_133a16f9-8bc5-4d93-b4c3-b904e5104e8b` | `192.168.5.1/24` |  |
| 96 | `lrp-router-port_e89aafa4-4e4a-4f4e-a6c9-e41f1c13093d` | `192.168.50.1/24` |  |
| 97 | `lrp-router-port_e1e88e81-2f03-4004-b335-7db74953710d` | `192.168.25.1/24` |  |
| 98 | `lrp-router-port_45329ac7-c80e-4968-9e81-1e8cc9e08d1b` | `192.168.12.1/24` |  |
| 99 | `lrp-router-port_389a4d77-cf3f-48eb-98e2-ab825f6f637d` | `192.168.35.1/24` |  |
| 100 | `lrp-router-port_450b41f1-6e7d-460d-a4fa-08aaa5673156` | `192.168.54.1/24` |  |
| 101 | `lrp-router-port_36add0c8-c730-4664-9aad-2da692db4a87` | `192.168.23.1/24` |  |
| 102 | `lrp-router-port_bd6f114b-6dcd-4aae-8d1f-6c3a3058eeec` | `192.168.1.1/24` |  |
| 103 | `lrp-router-port_fcf0b04e-dc57-4d88-accc-baf335985908` | `192.168.3.1/24` |  |
| 104 | `lrp-router-port_dc090365-4e0b-40cb-8b74-1f2c7fd6928b` | `192.168.75.1/24` |  |

#### Downstream — static routes on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 2 rows
| # | prefix | nexthop | policy | output_port |
|---|--------|---------|--------|-------------|
| 1 | `0.0.0.0/0` | `169.254.2.101` | `dst-ip` | `` |
| 2 | `0.0.0.0/0` | `169.254.2.100` | `dst-ip` | `` |

#### Downstream — GW chassis (RC) on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 0 rows
(none)

#### Downstream — path LRPs on router `router_fc433064-926d-4fc0-a1a3-7c089ad90343` (full) — 2 rows
| # | role | lrp | mac | cidr | ext_gw |
|---|------|-----|-----|------|--------|
| 1 | LR ↔ transit | `lrp-gw-scale-out-router-port_nat_fc433064-926d-4fc0-a1a3-7c089ad90343` | `e0:19:95:c9:5b:48` | `169.254.2.20/24` |  |
| 2 | src LS ↔ LR | `lrp-router-port_9472b0d1-09fb-4e7e-a1cf-9536d262b6ef` | `e0:19:95:08:22:c9` | `192.168.2.1/24` |  |
