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
    policy_name,
    role,
    entity_group_uuid AS applied_to_entity_group_reference,
    entity_group_name AS applied_to_entity_group_name,
    vm_category_refs AS applied_to_vm_category_refs,
    vm_category_names AS applied_to_vm_category_names,
    subnet_category_refs AS applied_to_subnet_category_refs,
    subnet_category_names AS applied_to_subnet_category_names,
    vpc_category_refs AS applied_to_vpc_category_refs,
    vpc_category_names AS applied_to_vpc_category_names,
    vm_ext_ids AS applied_to_vm_ext_ids,
    subnet_ext_ids AS applied_to_subnet_ext_ids,
    subnet_list AS applied_to_subnet_list,
    exception_list AS applied_to_exception_list,
    effective_vpc_refs AS applied_to_effective_vpc_refs,
    effective_vpc_names AS applied_to_effective_vpc_names,
    eg_address_grp,
    eg_exception_address_grp,
    computed_nic_uuids,
    computed_nics,
    atlas_nic_uuids
FROM flow_policy.portset
WHERE role = 'applied_to'
LIMIT 20;

SELECT
    n.vm_name,
    n.nic_uuid,
    n.subnet,
    n.vpc,
    n.ip
FROM flow_policy.vm_nic AS n
WHERE n.nic_uuid = {nic_uuid:UUID};
