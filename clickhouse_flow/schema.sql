-- One flat port-set table. Presence columns on the same row:
--   computed_port_set_uuid = uuid5 hash, or zero if Atlas-only
--   atlas_port_set_uuid    = port_set.list/get uuid, or zero if computed-only
-- Zero UUID means not present (schema-types-avoid-nullable).
-- Native 127.0.0.1:19000 / HTTP 8123.
-- Per schema-types-native-types, schema-pk-cardinality-order,
-- schema-pk-prioritize-filters, schema-partition-start-without,
-- insert-mutation-avoid-update.

CREATE DATABASE IF NOT EXISTS flow_policy;

DROP VIEW IF EXISTS flow_policy.v_port_set_nic_diff;
DROP TABLE IF EXISTS flow_policy.atlas_port_set;
DROP TABLE IF EXISTS flow_policy.computed_port_set;
DROP TABLE IF EXISTS flow_policy.portset;
DROP TABLE IF EXISTS flow_policy.vm_nic;
DROP TABLE IF EXISTS flow_policy.category;

CREATE TABLE flow_policy.portset
(
    port_set_uuid              UUID,
    computed_port_set_uuid     UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    atlas_port_set_uuid        UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    policy_uuid                UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    rule_uuid                  UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    role                       LowCardinality(String) DEFAULT '',
    component_id               String DEFAULT '',
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
    computed_nic_uuids         Array(UUID) DEFAULT [],
    atlas_nic_uuids            Array(UUID) DEFAULT [],
    policy_name                String DEFAULT '',
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
        ip String
    )) DEFAULT [],
    atlas_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String
    )) DEFAULT [],
    match_status               LowCardinality(String) DEFAULT '',
    mismatch_kind              LowCardinality(String) DEFAULT '',
    only_computed_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String
    )) DEFAULT [],
    only_atlas_nics Array(Tuple(
        vm_name String,
        nic_uuid UUID,
        subnet String,
        vpc String,
        ip String
    )) DEFAULT [],
    updated_at                 DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (entity_type, port_set_uuid, policy_uuid, component_id);

CREATE TABLE flow_policy.vm_nic
(
    nic_uuid               UUID,
    vm_uuid                UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    vm_name                String DEFAULT '',
    subnet_uuid            UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    subnet                 LowCardinality(String) DEFAULT '',
    vpc_uuid               UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    vpc                    LowCardinality(String) DEFAULT '',
    ip                     String DEFAULT '',
    updated_at             DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY nic_uuid;

CREATE TABLE flow_policy.category
(
    category_uuid          UUID,
    name                   String DEFAULT '',
    updated_at             DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY category_uuid;
