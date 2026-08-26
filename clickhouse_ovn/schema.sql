-- flow_ovn: OVN NB/SB path graph. Do not touch flow_policy.
-- Native 127.0.0.1:19000 / HTTP 8123. User default.
-- Panacea-style: every fact row has log_bundle_id; PARTITION BY log_bundle_id
-- so re-ingest of the same bundle is ALTER TABLE … DROP PARTITION (instant),
-- not ALTER DELETE. Other bundles stay. ReplacingMergeTree(updated_at).
-- No Nullable. ORDER BY: log_bundle_id first (filter), then low-cardinality,
-- then UUID (schema-pk-cardinality-order, schema-pk-prioritize-filters).
-- Ingest uses CREATE IF NOT EXISTS. --reset-schema drops tables once.

CREATE DATABASE IF NOT EXISTS flow_ovn;

CREATE TABLE IF NOT EXISTS flow_ovn.bundle
(
    log_bundle_id   UInt64,
    dump_dir        String DEFAULT '',
    cluster_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    cluster_name    LowCardinality(String) DEFAULT '',
    pc_ip           String DEFAULT '',
    nos_version     String DEFAULT '',
    collected_at    DateTime64(3) DEFAULT now64(),
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY log_bundle_id;

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_ls
(
    log_bundle_id UInt64,
    ls_uuid     UUID,
    name        String DEFAULT '',
    other_config Array(Tuple(String, String)) DEFAULT [],
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, ls_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_lsp
(
    log_bundle_id          UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, type, ls_uuid, lsp_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_lr
(
    log_bundle_id UInt64,
    lr_uuid     UUID,
    name        String DEFAULT '',
    enabled     UInt8 DEFAULT 1,
    has_nat     UInt8 DEFAULT 0,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, lr_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_lrp
(
    log_bundle_id       UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, lr_uuid, lrp_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_acl
(
    log_bundle_id UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, direction, action, acl_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_acl_on_ls
(
    log_bundle_id UInt64,
    ls_uuid     UUID,
    acl_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, ls_uuid, acl_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_pg
(
    log_bundle_id UInt64,
    pg_uuid     UUID,
    name        String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, pg_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_acl_on_pg
(
    log_bundle_id UInt64,
    pg_uuid     UUID,
    acl_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, pg_uuid, acl_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_pg_port
(
    log_bundle_id UInt64,
    pg_uuid     UUID,
    lsp_uuid    UUID,
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, pg_uuid, lsp_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_pbr
(
    log_bundle_id UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, lr_uuid, priority, pbr_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_nat
(
    log_bundle_id   UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, lr_uuid, nat_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_vm
(
    log_bundle_id UInt64,
    vm_uuid     UUID,
    name        String DEFAULT '',
    host_ip     String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, vm_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_vm_nic
(
    log_bundle_id UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, vm_uuid, nic_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_chassis
(
    log_bundle_id UInt64,
    chassis_uuid UUID,
    name         String DEFAULT '',
    hostname     String DEFAULT '',
    updated_at   DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, chassis_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_encap
(
    log_bundle_id   UInt64,
    encap_uuid      UUID,
    chassis_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    chassis_name    String DEFAULT '',
    ip              String DEFAULT '',
    encap_type      LowCardinality(String) DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, chassis_uuid, encap_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_datapath
(
    log_bundle_id UInt64,
    datapath_uuid UUID,
    kind          LowCardinality(String) DEFAULT '',
    nb_uuid       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    name          String DEFAULT '',
    tunnel_key    UInt32 DEFAULT 0,
    updated_at    DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, kind, nb_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_port_binding
(
    log_bundle_id   UInt64,
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
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, type, datapath_uuid, pb_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_mac_binding
(
    log_bundle_id   UInt64,
    mb_uuid         UUID,
    datapath_uuid   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    ip              String DEFAULT '',
    logical_port    String DEFAULT '',
    mac             String DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, datapath_uuid, ip);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_ha_chassis
(
    log_bundle_id   UInt64,
    group_uuid      UUID,
    group_name      String DEFAULT '',
    chassis_name    String DEFAULT '',
    priority        UInt16 DEFAULT 0,
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, group_uuid, chassis_name);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_edge_ls_lr
(
    log_bundle_id UInt64,
    ls_uuid     UUID,
    lr_uuid     UUID,
    lsp_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_uuid    UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lsp_name    String DEFAULT '',
    lrp_name    String DEFAULT '',
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, ls_uuid, lr_uuid, lsp_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_edge_lr_lr
(
    log_bundle_id UInt64,
    via         LowCardinality(String) DEFAULT '',
    lr_a        UUID,
    lr_b        UUID,
    via_ls_uuid UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_a       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    lrp_b       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    updated_at  DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, via, lr_a, lr_b, via_ls_uuid);

CREATE TABLE IF NOT EXISTS flow_ovn.ovn_ls_stretch
(
    log_bundle_id   UInt64,
    ls_uuid         UUID,
    chassis_uuid    UUID,
    hostname        String DEFAULT '',
    encap_type      LowCardinality(String) DEFAULT '',
    encap_ip        String DEFAULT '',
    vif_count       UInt32 DEFAULT 0,
    updated_at      DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, ls_uuid, chassis_uuid);
