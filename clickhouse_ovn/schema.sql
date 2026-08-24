-- flow_ovn: OVN NB/SB path graph. Do not touch flow_policy.
-- Native 127.0.0.1:19000 / HTTP 8123. User default.
-- ReplacingMergeTree(updated_at); no Nullable; no PARTITION BY.
-- ORDER BY: low-cardinality first, then UUID (schema-pk-cardinality-order).

CREATE DATABASE IF NOT EXISTS flow_ovn;

DROP TABLE IF EXISTS flow_ovn.ovn_ls_stretch;
DROP TABLE IF EXISTS flow_ovn.ovn_edge_lr_lr;
DROP TABLE IF EXISTS flow_ovn.ovn_edge_ls_lr;
DROP TABLE IF EXISTS flow_ovn.ovn_ha_chassis;
DROP TABLE IF EXISTS flow_ovn.ovn_mac_binding;
DROP TABLE IF EXISTS flow_ovn.ovn_port_binding;
DROP TABLE IF EXISTS flow_ovn.ovn_datapath;
DROP TABLE IF EXISTS flow_ovn.ovn_encap;
DROP TABLE IF EXISTS flow_ovn.ovn_chassis;
DROP TABLE IF EXISTS flow_ovn.ovn_vm_nic;
DROP TABLE IF EXISTS flow_ovn.ovn_vm;
DROP TABLE IF EXISTS flow_ovn.ovn_nat;
DROP TABLE IF EXISTS flow_ovn.ovn_pbr;
DROP TABLE IF EXISTS flow_ovn.ovn_pg_port;
DROP TABLE IF EXISTS flow_ovn.ovn_acl_on_pg;
DROP TABLE IF EXISTS flow_ovn.ovn_acl_on_ls;
DROP TABLE IF EXISTS flow_ovn.ovn_pg;
DROP TABLE IF EXISTS flow_ovn.ovn_acl;
DROP TABLE IF EXISTS flow_ovn.ovn_lrp;
DROP TABLE IF EXISTS flow_ovn.ovn_lr;
DROP TABLE IF EXISTS flow_ovn.ovn_lsp;
DROP TABLE IF EXISTS flow_ovn.ovn_ls;

CREATE TABLE flow_ovn.ovn_ls
(
    ls_uuid     UUID,
    name        String DEFAULT '',
    other_config Array(Tuple(String, String)) DEFAULT [],
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ls_uuid;

CREATE TABLE flow_ovn.ovn_lsp
(
    lsp_uuid               UUID,
    ls_uuid                UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    name                   String DEFAULT '',
    type                   LowCardinality(String) DEFAULT '',
    mac                    String DEFAULT '',
    ip4                    Array(String) DEFAULT [],
    ip6                    Array(String) DEFAULT [],
    addresses              Array(String) DEFAULT [],
    dynamic_addresses      String DEFAULT '',
    enabled                UInt8 DEFAULT 1,
    up                     UInt8 DEFAULT 0,
    parent_name            String DEFAULT '',
    tag                    UInt16 DEFAULT 0,
    options_router_port    String DEFAULT '',
    options_network_name   String DEFAULT '',
    peer                   String DEFAULT '',
    nic_uuid               UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    updated_at             DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (type, ls_uuid, lsp_uuid);

CREATE TABLE flow_ovn.ovn_lr
(
    lr_uuid     UUID,
    name        String DEFAULT '',
    enabled     UInt8 DEFAULT 1,
    has_nat     UInt8 DEFAULT 0,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY lr_uuid;

CREATE TABLE flow_ovn.ovn_lrp
(
    lrp_uuid            UUID,
    lr_uuid             UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    name                String DEFAULT '',
    mac                 String DEFAULT '',
    networks            Array(String) DEFAULT [],
    peer                String DEFAULT '',
    ha_chassis_group    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    is_ext_gw           UInt8 DEFAULT 0,
    updated_at          DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (lr_uuid, lrp_uuid);

CREATE TABLE flow_ovn.ovn_acl
(
    acl_uuid    UUID,
    name        String DEFAULT '',
    direction   LowCardinality(String) DEFAULT '',
    action      LowCardinality(String) DEFAULT '',
    match       String DEFAULT '',
    priority    Int32 DEFAULT 0,
    log         UInt8 DEFAULT 0,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (direction, action, acl_uuid);

CREATE TABLE flow_ovn.ovn_acl_on_ls
(
    ls_uuid     UUID,
    acl_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (ls_uuid, acl_uuid);

CREATE TABLE flow_ovn.ovn_pg
(
    pg_uuid     UUID,
    name        String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY pg_uuid;

CREATE TABLE flow_ovn.ovn_acl_on_pg
(
    pg_uuid     UUID,
    acl_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (pg_uuid, acl_uuid);

CREATE TABLE flow_ovn.ovn_pg_port
(
    pg_uuid     UUID,
    lsp_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (pg_uuid, lsp_uuid);

CREATE TABLE flow_ovn.ovn_pbr
(
    pbr_uuid    UUID,
    lr_uuid     UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    match       String DEFAULT '',
    action      LowCardinality(String) DEFAULT '',
    nexthop     String DEFAULT '',
    nexthops    Array(String) DEFAULT [],
    priority    Int32 DEFAULT 0,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (lr_uuid, priority, pbr_uuid);

CREATE TABLE flow_ovn.ovn_nat
(
    nat_uuid        UUID,
    lr_uuid         UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    type            LowCardinality(String) DEFAULT '',
    external_ip     String DEFAULT '',
    logical_ip      String DEFAULT '',
    logical_port    String DEFAULT '',
    external_mac    String DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (lr_uuid, nat_uuid);

CREATE TABLE flow_ovn.ovn_vm
(
    vm_uuid     UUID,
    name        String DEFAULT '',
    host_ip     String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY vm_uuid;

CREATE TABLE flow_ovn.ovn_vm_nic
(
    nic_uuid    UUID,
    vm_uuid     UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    vm_name     String DEFAULT '',
    mac         String DEFAULT '',
    ip4         String DEFAULT '',
    host_ip     String DEFAULT '',
    lsp_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    ls_uuid     UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (vm_uuid, nic_uuid);

CREATE TABLE flow_ovn.ovn_chassis
(
    chassis_uuid UUID,
    name         String DEFAULT '',
    hostname     String DEFAULT '',
    updated_at   DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY chassis_uuid;

CREATE TABLE flow_ovn.ovn_encap
(
    encap_uuid      UUID,
    chassis_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    chassis_name    String DEFAULT '',
    ip              String DEFAULT '',
    encap_type      LowCardinality(String) DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (chassis_uuid, encap_uuid);

CREATE TABLE flow_ovn.ovn_datapath
(
    datapath_uuid UUID,
    kind          LowCardinality(String) DEFAULT '',
    nb_uuid       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    name          String DEFAULT '',
    tunnel_key    UInt32 DEFAULT 0,
    updated_at    DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (kind, nb_uuid);

CREATE TABLE flow_ovn.ovn_port_binding
(
    pb_uuid         UUID,
    logical_port    String DEFAULT '',
    type            LowCardinality(String) DEFAULT '',
    datapath_uuid   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    chassis_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    mac             Array(String) DEFAULT [],
    tunnel_key      UInt32 DEFAULT 0,
    up              UInt8 DEFAULT 0,
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (type, datapath_uuid, pb_uuid);

CREATE TABLE flow_ovn.ovn_mac_binding
(
    mb_uuid         UUID,
    datapath_uuid   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    ip              String DEFAULT '',
    logical_port    String DEFAULT '',
    mac             String DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (datapath_uuid, ip);

CREATE TABLE flow_ovn.ovn_ha_chassis
(
    group_uuid      UUID,
    group_name      String DEFAULT '',
    chassis_name    String DEFAULT '',
    priority        UInt16 DEFAULT 0,
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (group_uuid, chassis_name);

CREATE TABLE flow_ovn.ovn_edge_ls_lr
(
    ls_uuid     UUID,
    lr_uuid     UUID,
    lsp_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lsp_name    String DEFAULT '',
    lrp_name    String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (ls_uuid, lr_uuid, lsp_uuid);

CREATE TABLE flow_ovn.ovn_edge_lr_lr
(
    via         LowCardinality(String) DEFAULT '',
    lr_a        UUID,
    lr_b        UUID,
    via_ls_uuid UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_a       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_b       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (via, lr_a, lr_b, via_ls_uuid);

CREATE TABLE flow_ovn.ovn_ls_stretch
(
    ls_uuid         UUID,
    chassis_uuid    UUID,
    hostname        String DEFAULT '',
    encap_type      LowCardinality(String) DEFAULT '',
    encap_ip        String DEFAULT '',
    vif_count       UInt32 DEFAULT 0,
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (ls_uuid, chassis_uuid);
