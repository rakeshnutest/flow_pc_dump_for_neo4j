"""Port-set UUID hash copied from neo4j_db_insert.py.

generate_port_set_id and compute_hash_value are the same algorithm as
PolicyGraphInserter in neo4j_db_insert.py. Constants below stand in for
FlowNgConstants (not importable in this tree).
"""

from __future__ import annotations

import hashlib
import re
import uuid as uuid_lib

# FlowNgConstants.CATEGORY_SELECTION_TYPE_MAP / DEFAULT_PROJECT_EXT_ID
CATEGORY_SELECTION_TYPE_MAP = {
    "VM": "kVM",
    "SUBNET": "kSubnet",
    "VPC": "kVPC",
}
DEFAULT_PROJECT_EXT_ID = "00000000-0000-0000-0000-000000000000"
GLOBAL_SCOPE_UNIQUE_ID = "global-scope-unique-id"
VLAN_SCOPE_UNIQUE_ID = "vlan-scope-unique-id"
SALUS_SERVICE_NAME = "salus"


def generate_port_set_id(
        reference_info, unique_uuid, project_uuid=None, is_flex=False):
    """Same body as neo4j_db_insert.PolicyGraphInserter.generate_port_set_id.

    EG uses no type suffix: the docstring example is ("", [eg_uuid]), and the
    FLEX branch never suffixes EG. compute_hash_value passes entity_type "EG";
    MAP has no EG key, so a raw str(MAP.get("EG")) would append ":None" and
    miss Atlas. Empty / EG is treated like VM (no suffix).
    """
    reference_selection_type, reference_uuids = reference_info
    if reference_uuids is None:
        reference_uuids = []
    if not unique_uuid:
        return ""

    if is_flex:
        sorted_refs = sorted(list(reference_uuids))
        reference_uuids = "[" + " ".join(sorted_refs) + "]"
        pattern = r"'[a-z0-9A-Z\-]+'"
        reference_uuids = re.sub(
            pattern, lambda x: "u" + x.group(0), reference_uuids)
        if (reference_selection_type
                and reference_selection_type not in ("VM", "EG")):
            suffix = CATEGORY_SELECTION_TYPE_MAP.get(reference_selection_type)
            if suffix:
                reference_uuids = reference_uuids + ":" + str(suffix)
        if project_uuid and project_uuid != DEFAULT_PROJECT_EXT_ID:
            reference_uuids = reference_uuids + ":project:" + project_uuid
        first_input = SALUS_SERVICE_NAME + unique_uuid
        combined = "".join([first_input, reference_uuids])
        digest = hashlib.md5(combined.encode()).digest()
        return str(uuid_lib.UUID(bytes=digest))

    reference_uuids = str(sorted(list(reference_uuids)))
    pattern = r"'[a-z0-9A-Z\-]+'"
    reference_uuids = re.sub(
        pattern, lambda x: "u" + x.group(0), reference_uuids)
    if (reference_selection_type
            and reference_selection_type not in ("VM", "EG")):
        reference_uuids = (
            reference_uuids + ":"
            + str(CATEGORY_SELECTION_TYPE_MAP.get(reference_selection_type)))
    if project_uuid and project_uuid != DEFAULT_PROJECT_EXT_ID:
        reference_uuids = reference_uuids + ":project:" + project_uuid
    vid = uuid_lib.UUID(str(unique_uuid))
    return str(uuid_lib.uuid5(vid, reference_uuids))


def compute_addressset_hashes(entity_uuid, has_ipv4, has_ipv6):
    """Same as neo4j_db_insert.PolicyGraphInserter.compute_addressset_hashes."""
    vid = uuid_lib.UUID(entity_uuid)
    hashes = []
    if has_ipv4 and has_ipv6:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv4")))
        hashes.append(str(uuid_lib.uuid5(vid, "IPv6")))
    elif has_ipv6:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv6")))
    else:
        hashes.append(str(uuid_lib.uuid5(vid, "IPv4")))
    return hashes


def compute_hash_value(
        vm_category_refs, subnet_category_refs, vpc_category_refs,
        entity_group_ref, addresses=None, subnet_list=None,
        policy_vpc_references=None, scope=None, vm_ext_ids=None,
        subnet_ext_ids=None, project_uuid=None, is_flex=False,
        is_endpoint=False, vlan_unique_uuid=None, global_unique_uuid=None):
    """Same precedence as neo4j_db_insert.PolicyGraphInserter.compute_hash_value.

    Returns a port-set UUID string, a list of address-set UUIDs, or "".
    """
    vm_category_refs = vm_category_refs or []
    subnet_category_refs = subnet_category_refs or []
    vpc_category_refs = vpc_category_refs or []
    vm_ext_ids = vm_ext_ids or []
    subnet_ext_ids = subnet_ext_ids or []
    policy_vpc_references = policy_vpc_references or []
    subnet_list = subnet_list or []
    addresses = addresses or []

    entity_type = None
    refs_uuid = None
    if entity_group_ref and subnet_list and (is_flex or is_endpoint):
        has_ipv4 = any("." in addr for addr in subnet_list)
        has_ipv6 = any(":" in addr for addr in subnet_list)
        return compute_addressset_hashes(entity_group_ref, has_ipv4, has_ipv6)
    if entity_group_ref:
        entity_type = "EG"
        if isinstance(entity_group_ref, (list, tuple)):
            refs_uuid = list(entity_group_ref)
        else:
            refs_uuid = [entity_group_ref]
    elif vm_category_refs:
        entity_type = "VM"
        refs_uuid = vm_category_refs
    elif vm_ext_ids:
        entity_type = "VM"
        refs_uuid = vm_ext_ids
    elif subnet_category_refs:
        entity_type = "SUBNET"
        refs_uuid = subnet_category_refs
    elif subnet_ext_ids:
        entity_type = "SUBNET"
        refs_uuid = subnet_ext_ids
    elif vpc_category_refs:
        entity_type = "VPC"
        refs_uuid = vpc_category_refs
    elif addresses:
        addressset_hash = []
        for address in addresses:
            has_ipv4 = any("." in addr for addr in addresses)
            has_ipv6 = any(":" in addr for addr in addresses)
            addressset_hash.extend(
                compute_addressset_hashes(address, has_ipv4, has_ipv6))
        return addressset_hash

    unique_uuid = None
    if scope == "GLOBAL":
        unique_uuid = (
            GLOBAL_SCOPE_UNIQUE_ID if is_flex else global_unique_uuid)
    elif scope == "ALL_VLAN":
        unique_uuid = (
            VLAN_SCOPE_UNIQUE_ID if is_flex else vlan_unique_uuid)
    elif scope == "VPC_AS_CATEGORY":
        unique_uuid = policy_vpc_references[0] if policy_vpc_references else None
    elif scope == "VPC_LIST":
        unique_uuid = policy_vpc_references[0] if policy_vpc_references else None
    elif scope in ("ALL_VPC", "kGlobal"):
        unique_uuid = global_unique_uuid
    elif scope in ("kAllVlan",):
        unique_uuid = vlan_unique_uuid

    if not entity_type and not refs_uuid and subnet_list:
        return None
    if not refs_uuid or not unique_uuid:
        return ""
    return generate_port_set_id(
        (entity_type, refs_uuid), unique_uuid, project_uuid, is_flex=is_flex)
