-- Flat table lookups. Native 127.0.0.1:19000 / HTTP 8123.

SELECT 1;

SELECT
    port_set_uuid,
    computed_port_set_uuid,
    atlas_port_set_uuid,
    computed_nics,
    atlas_nics
FROM flow_policy.portset
WHERE port_set_uuid = {port_set_uuid:UUID}
LIMIT 1;

SELECT
    port_set_uuid,
    applied_to_port_set_uuid,
    policy_name,
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
WHERE role IN ('src', 'dest', 'secured')
  AND applied_to_port_set_uuid != toUUID('00000000-0000-0000-0000-000000000000')
LIMIT 20;

SELECT
    port_set_uuid,
    applied_to_port_set_uuid,
    policy_name,
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
WHERE role = 'applied_to'
LIMIT 20;

SELECT
    port_set_uuid,
    rule_uuid,
    rule_uuids,
    rule_u_sg
FROM flow_policy.portset
WHERE length(rule_uuids) > 1
LIMIT 20;

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
LIMIT 20;

SELECT
    p.port_set_uuid,
    tupleElement(m, 1) AS rule_uuid,
    tupleElement(m, 2) AS u_sg_id,
    tupleElement(m, 3) AS rule_priority,
    u.sg_id,
    u.kind,
    u.sg_uuids,
    u.sg_names,
    u.tcp_ports,
    u.udp_ports,
    u.network_function_uuid,
    u.network_function_name
FROM flow_policy.portset AS p
ARRAY JOIN p.rule_u_sg AS m
INNER JOIN flow_policy.u_sg AS u ON u.u_sg_id = tupleElement(m, 2)
WHERE p.port_set_uuid = {port_set_uuid:UUID}
LIMIT 50;

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
WHERE n.nic_uuid = {nic_uuid:UUID};
