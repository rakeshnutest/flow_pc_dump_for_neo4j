-- One flat port-set table. Presence columns on the same row:
--   computed_port_set_uuid = hash from ingest.py, or zero if Atlas-only
--   atlas_port_set_uuid    = port_set.list/get uuid, or zero if computed-only
-- FLEX dest/src (neo4j Secured/Endpoint) keep selector columns AND
-- applied_to_* from the applied_to EG: two port-set UUIDs
-- (port_set_uuid + applied_to_port_set_uuid). role = 'applied_to' is the
-- second UUID as its own Atlas-matching row.
-- One port-set UUID can sit on many policies/rules. There is no row-level
-- policy_uuid, policy_name, rule_uuid, or component_id. Every policy+rule
-- that uses this hash lives in rule_u_sg as
-- (rule_uuid, sg_id[], sg_ports, policy_name, policy_uuid, policy_type,
-- policy_mode, flex_policy, rule_priority, type).
-- policy_type is app / isolation / quarantine. policy_mode is
-- enforce / monitor / save (dump state APPLY → enforce).
-- type is secured_entity, end_point_src, or end_point_dst.
-- FLEX spec.priority is rule_priority; rule.type FLEX sets flex_policy.
-- flow_policy.u_sg is the unique service lookup (dump SG UUID, list, or
-- inline ports). Lists and inline keep u_sg.sg_id zero.
-- should_allow_any_src/dst matches every NIC in the policy project, or
-- every VM NIC if the policy has no project.
-- Secured-group NICs exclude VLAN Basic (advance_vlan /
-- is_advanced_networking false). Advanced VLAN and overlay stay.
-- Zero UUID means not present.
-- Native 127.0.0.1:19000 / HTTP 8123.
-- Panacea-style: every fact row has log_bundle_id; PARTITION BY log_bundle_id
-- so re-ingest of the same bundle is ALTER TABLE … DROP PARTITION (instant),
-- not ALTER DELETE. Other bundles stay. ReplacingMergeTree(updated_at).
-- No Nullable. ORDER BY: log_bundle_id first (filter), then low-cardinality,
-- then UUID. Ingest uses CREATE IF NOT EXISTS. --reset-schema drops tables once.

CREATE DATABASE IF NOT EXISTS flow_policy;

CREATE TABLE IF NOT EXISTS flow_policy.bundle
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

CREATE TABLE IF NOT EXISTS flow_policy.portset
(
    log_bundle_id              UInt64,
    port_set_uuid              UUID,
    computed_port_set_uuid     UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    atlas_port_set_uuid        UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    applied_to_port_set_uuid   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    role                       LowCardinality(String) DEFAULT '',
    entity_type                LowCardinality(String) DEFAULT '',
    namespace_uuid             UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    virtual_network_uuid       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    entity_group_uuid          UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    reference_uuids            Array(UUID) DEFAULT [],
    vm_category_refs           Array(UUID) DEFAULT [],
    subnet_category_refs       Array(UUID) DEFAULT [],
    vpc_category_refs          Array(UUID) DEFAULT [],
    vm_ext_ids                 Array(UUID) DEFAULT [],
    subnet_ext_ids             Array(UUID) DEFAULT [],
    subnet_list                Array(String) DEFAULT [],
    exception_list             Array(String) DEFAULT [],
    applied_to_entity_group_uuid UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    applied_to_vm_category_refs  Array(UUID) DEFAULT [],
    applied_to_subnet_category_refs Array(UUID) DEFAULT [],
    applied_to_vpc_category_refs Array(UUID) DEFAULT [],
    applied_to_vm_ext_ids        Array(UUID) DEFAULT [],
    applied_to_subnet_ext_ids    Array(UUID) DEFAULT [],
    applied_to_subnet_list       Array(String) DEFAULT [],
    applied_to_exception_list    Array(String) DEFAULT [],
    applied_to_entity_group_name String DEFAULT '',
    applied_to_vm_category_names Array(String) DEFAULT [],
    applied_to_subnet_category_names Array(String) DEFAULT [],
    applied_to_vpc_category_names Array(String) DEFAULT [],
    effective_vpc_refs         Array(UUID) DEFAULT [],
    effective_vpc_names        Array(String) DEFAULT [],
    eg_address_grp             Array(String) DEFAULT [],
    eg_exception_address_grp   Array(String) DEFAULT [],
    rule_u_sg Array(Tuple(
        rule_uuid UUID,
        sg_id Array(UUID),
        sg_ports Tuple(
            tcp Array(String),
            udp Array(String),
            icmp Array(String),
            icmpv6 Array(String)
        ),
        policy_name String,
        policy_uuid UUID,
        policy_type LowCardinality(String),
        policy_mode LowCardinality(String),
        flex_policy UInt8,
        rule_priority Int32,
        type LowCardinality(String)
    )) DEFAULT [],
    computed_nic_uuids         Array(UUID) DEFAULT [],
    atlas_nic_uuids            Array(UUID) DEFAULT [],
    atlas_name                 String DEFAULT '',
    vpc_name                   LowCardinality(String) DEFAULT '',
    entity_group_name          String DEFAULT '',
    vm_category_names          Array(String) DEFAULT [],
    subnet_category_names      Array(String) DEFAULT [],
    vpc_category_names         Array(String) DEFAULT [],
    reference_names            Array(String) DEFAULT [],
    computed_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String,
        host_uuid UUID,
        host String,
        cluster_uuid UUID,
        cluster String
    )) DEFAULT [],
    atlas_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String,
        host_uuid UUID,
        host String,
        cluster_uuid UUID,
        cluster String
    )) DEFAULT [],
    match_status               LowCardinality(String) DEFAULT '',
    mismatch_kind              LowCardinality(String) DEFAULT '',
    only_computed_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String,
        host_uuid UUID,
        host String,
        cluster_uuid UUID,
        cluster String
    )) DEFAULT [],
    only_atlas_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String,
        host_uuid UUID,
        host String,
        cluster_uuid UUID,
        cluster String
    )) DEFAULT [],
    all_ports                  UInt8 DEFAULT 0,
    updated_at                 DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, entity_type, port_set_uuid);

CREATE TABLE IF NOT EXISTS flow_policy.u_sg
(
    log_bundle_id              UInt64,
    u_sg_id                    UUID,
    sg_id                      UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    kind                       LowCardinality(String) DEFAULT '',
    sg_uuids                   Array(UUID) DEFAULT [],
    sg_names                   Array(String) DEFAULT [],
    tcp_ports                  Array(String) DEFAULT [],
    udp_ports                  Array(String) DEFAULT [],
    icmp_types                 Array(String) DEFAULT [],
    icmp_v6_types              Array(String) DEFAULT [],
    is_inline                  UInt8 DEFAULT 0,
    is_all_ports               UInt8 DEFAULT 0,
    secured_group_action       LowCardinality(String) DEFAULT '',
    network_function_uuid      UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    network_function_name      String DEFAULT '',
    network_function_failure_handling LowCardinality(String) DEFAULT '',
    network_function_traffic_forwarding_mode LowCardinality(String) DEFAULT '',
    network_function_high_availability_mode LowCardinality(String) DEFAULT '',
    network_function_nic_pairs Array(Tuple(
        vm_uuid UUID,
        ingress_nic_uuid UUID,
        egress_nic_uuid UUID,
        high_availability_state String,
        data_plane_health_status String
    )) DEFAULT [],
    updated_at                 DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, u_sg_id);

CREATE TABLE IF NOT EXISTS flow_policy.vm_nic
(
    log_bundle_id          UInt64,
    nic_uuid               UUID,
    vm_uuid                UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    vm_name                String DEFAULT '',
    subnet_uuid            UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    subnet                 LowCardinality(String) DEFAULT '',
    vpc_uuid               UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    vpc                    LowCardinality(String) DEFAULT '',
    ip                     String DEFAULT '',
    host_uuid              UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    host                   LowCardinality(String) DEFAULT '',
    cluster_uuid           UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    cluster                LowCardinality(String) DEFAULT '',
    updated_at             DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, nic_uuid);

CREATE TABLE IF NOT EXISTS flow_policy.category
(
    log_bundle_id          UInt64,
    category_uuid          UUID,
    name                   String DEFAULT '',
    updated_at             DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY log_bundle_id
ORDER BY (log_bundle_id, category_uuid);
