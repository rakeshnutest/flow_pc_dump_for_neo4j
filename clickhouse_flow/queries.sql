-- Flat table lookups. Native 127.0.0.1:19000 / HTTP 8123.
-- Always filter log_bundle_id (one dump / Panacea bundle).

SELECT 1;

SELECT
    port_set_uuid,
    computed_port_set_uuid,
    atlas_port_set_uuid,
    computed_nics,
    atlas_nics
FROM flow_policy.portset
WHERE log_bundle_id = {log_bundle_id:UInt64}
  AND port_set_uuid = {port_set_uuid:UUID}
LIMIT 1;

SELECT
    port_set_uuid,
    applied_to_port_set_uuid,
    atlas_name,
    role,
    vm_category_refs,
    subnet_category_refs,
    vpc_category_refs,
    vm_ext_ids,
    subnet_ext_ids,
    subnet_list,
    exception_list,
    applied_to_entity_group_uuid,
    applied_to_vm_category_refs,
    applied_to_subnet_category_refs,
    applied_to_vpc_category_refs,
    applied_to_vm_ext_ids,
    applied_to_subnet_ext_ids,
    applied_to_subnet_list,
    applied_to_exception_list
FROM flow_policy.portset
WHERE log_bundle_id = {log_bundle_id:UInt64}
  AND role IN ('src', 'dest', 'secured')
  AND applied_to_port_set_uuid != toUUID('00000000-0000-0000-0000-000000000000')
LIMIT 20;

SELECT
    port_set_uuid,
    applied_to_port_set_uuid,
    atlas_name,
    role,
    entity_group_uuid,
    vm_category_refs,
    subnet_category_refs,
    vpc_category_refs,
    vm_ext_ids,
    subnet_ext_ids,
    subnet_list,
    exception_list
FROM flow_policy.portset
WHERE log_bundle_id = {log_bundle_id:UInt64}
  AND role = 'applied_to'
LIMIT 20;

SELECT
    port_set_uuid,
    rule_u_sg
FROM flow_policy.portset
WHERE log_bundle_id = {log_bundle_id:UInt64}
  AND length(rule_u_sg) > 1
LIMIT 20;

SELECT
    p.port_set_uuid,
    tupleElement(m, 'rule_uuid') AS rule_uuid,
    tupleElement(m, 'sg_id') AS sg_id,
    tupleElement(m, 'sg_ports') AS sg_ports,
    tupleElement(m, 'policy_name') AS policy_name,
    tupleElement(m, 'policy_uuid') AS policy_uuid,
    tupleElement(m, 'policy_type') AS policy_type,
    tupleElement(m, 'policy_mode') AS policy_mode,
    tupleElement(m, 'flex_policy') AS flex_policy,
    tupleElement(m, 'rule_priority') AS rule_priority,
    tupleElement(m, 'type') AS type
FROM flow_policy.portset AS p
ARRAY JOIN p.rule_u_sg AS m
WHERE p.log_bundle_id = {log_bundle_id:UInt64}
  AND p.port_set_uuid = {port_set_uuid:UUID}
LIMIT 50;

SELECT
    u_sg_id,
    sg_id,
    kind,
    sg_uuids,
    sg_names,
    tcp_ports,
    udp_ports,
    icmp_types,
    icmp_v6_types,
    is_inline,
    is_all_ports,
    network_function_uuid,
    network_function_name
FROM flow_policy.u_sg
WHERE log_bundle_id = {log_bundle_id:UInt64}
LIMIT 20;

SELECT
    n.vm_name,
    n.nic_uuid,
    n.subnet,
    n.vpc,
    n.ip,
    n.host_uuid,
    n.host,
    n.cluster_uuid,
    n.cluster
FROM flow_policy.vm_nic AS n
WHERE n.log_bundle_id = {log_bundle_id:UInt64}
  AND n.nic_uuid = {nic_uuid:UUID};
