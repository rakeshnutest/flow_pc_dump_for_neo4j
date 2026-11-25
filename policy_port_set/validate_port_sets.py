#!/usr/bin/env python3
"""Compare policy port_set hashes with idfcli port_set entities.

Expected UUIDs use the same algorithm as neo4j_db_insert.generate_port_set_id
(uuid5 for application rules, MD5 for FLEX). A FLEX rule also hashes
applied_to (the applied entity group) and an allow-any side (empty Go
list). UI Global applied_to, where that field is absent, is not a port set.
--flow-cli (default) reads policies with flow_cli policy.list and
policy.get. Flow must be up for that path. --idf-cli reads them from
idfcli. The rule body is the zlib protobuf in __zprotobuf__.

  idfcli get entity -e network_security_policy --all -o json
  idfcli get entity -e atlas_port_set --all -o json
  idfcli get entitytype -e port_set -o json

--port-set-entity auto tries atlas_port_set, then port_set.
--port-set-entity atlas_port_set or --port-set-entity port_set picks one.

SMSP reads both from idfcli inside the flow cluster and uses the Atlas
ZK scope UUIDs.

Standalone. One file, stdlib only. Nothing is written to disk.
Stdout is only mismatch rows, tab-separated:

  mismatch  port_set  policy  nic_mismatch

  computed_without_idf   policy hash is not an atlas port set.
                         nic_mismatch is port_set_missing.
  idf_without_computed   atlas port set was not produced by a policy.
                         nic_mismatch is that port set's NIC uuids.

K8s_* port sets and Quarantine port sets with no NICs are left out.
Address groups are not port sets. SAVE-mode policies are skipped.

FLEX also hashes applied_to (the entity group on the rule) and an empty
VM selector when should_allow_any_src/dst is set or the rule has no
selector. A missing applied_to field is UI Global and is not a port set.
SMSP reads port_set with idfcli in the flow cluster and uses the Atlas
ZK scope UUIDs. CMSP uses the local idfcli and zkcat.

  python3 validate_port_sets.py
  python3 validate_port_sets.py --flow_cli
  python3 validate_port_sets.py --idf_cli
  python3 validate_port_sets.py --idf_cli --port-set-entity port_set
  python3 validate_port_sets.py --port-set-entity atlas_port_set
  python3 validate_port_sets.py --self-test
  panacea_cli validate_port_sets.py
  panacea_cli validate_port_sets.py --self-test
"""

try:
    import panacea_cli_usage_tracker  # noqa: F401  (present on a live PC)
except ImportError:
    pass

import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import re
import subprocess
import zlib
import sys
import tempfile
import uuid as uuid_lib

ZERO = "00000000-0000-0000-0000-000000000000"
DEFAULT_PROJECT = ZERO
SALUS_SERVICE_NAME = "Salus"
GLOBAL_SCOPE_UNIQUE_ID = "global-scope-unique-id"
VLAN_SCOPE_UNIQUE_ID = "vlan-scope-unique-id"
_U_QUOTE = re.compile(r"'[a-z0-9A-Z\-]+'")
CAT_SUFFIX = {"VM": "kVM", "SUBNET": "kSubnet", "VPC": "kVPC"}
CAT_TYPE = {
    "kVM": "VM", "VM": "VM",
    "kSubnet": "SUBNET", "SUBNET": "SUBNET", "kSUBNET": "SUBNET",
    "kVPC": "VPC", "VPC": "VPC",
}
GLOBAL_SCOPES = frozenset(("kGlobal", "GLOBAL", "ALL_VPC", "kAllVpc"))
VLAN_SCOPES = frozenset(("kAllVlan", "ALL_VLAN", "kVlan", "", None))
VPC_CAT_SCOPES = frozenset(("kVpcAsCategory", "VPC_AS_CATEGORY"))
VPC_LIST_SCOPES = frozenset(("kVpc", "kVpcList", "VPC_LIST", "VPC"))
COMPONENT_KEYS = (
    "endpoint", "secured_group", "src_endpoint", "dest_endpoint",
    "first_secured_group", "second_secured_group", "isolation_group",
)
RULE_KEYS = (
    "application_rule", "quarantine_rule", "secured_group_rule",
    "flex_policy_rule", "isolation_rule", "multi_env_isolation_rule",
    "shared_service_rule",
)
SKIP_ALLOW = frozenset(("kTypeAll", "kTypeNone", "ALL", "NONE"))
TCP_PROTOS = frozenset(("kTCP", "TCP", "3"))
UDP_PROTOS = frozenset(("kUDP", "UDP", "4"))
ICMP_PROTOS = frozenset(("kICMP", "ICMP", "2"))
ICMP6_PROTOS = frozenset(("kICMPv6", "kICMPV6", "ICMPv6", "ICMPV6", "5"))
ALL_PROTOS = frozenset(("kALL", "kAll", "ALL", "1"))
LOG = logging.getLogger("validate_port_sets")
DEFAULT_OUTPUT_BASE = "/tmp"
IDF_AG_TYPES = ("network_address_group", "address_group")
IDF_FQDN_TYPES = ("fns_fqdn_to_ip_info",)
VLAN_ZK = "/appliance/logical/flow/vlan_unique_uuid"
GLOBAL_ZK = "/appliance/logical/flow/global_unique_uuid"
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ATLAS_ZK_PY = (
    "from zeus.zookeeper_session import ZookeeperSession\n"
    "zk = ZookeeperSession()\n"
    "for key, path in (("
    "'vlan_unique_uuid', '%s'), ('global_unique_uuid', '%s')):\n"
    "  val = zk.get(path)\n"
    "  if isinstance(val, (bytes, bytearray)):\n"
    "    val = val.decode('utf-8', 'replace')\n"
    "  print('%%s=%%s' %% (key, val))\n" % (VLAN_ZK, GLOBAL_ZK))
def first(node, key, default=""):
    if not isinstance(node, dict):
        return default
    vals = node.get(key, default)
    if vals is None or vals == "":
        return default
    if isinstance(vals, list):
        return vals[0] if vals else default
    return vals


def values(node, key):
    if not isinstance(node, dict):
        return []
    vals = node.get(key)
    if vals is None or vals == "":
        return []
    if isinstance(vals, list):
        return [item for item in vals if item not in (None, "")]
    return [vals]

def _md5(data):
    """FLEX port-set id. usedforsecurity=False keeps MD5 available on FIPS PCs."""
    try:
        return hashlib.md5(data, usedforsecurity=False)
    except TypeError:
        return hashlib.md5(data)


def generate_port_set_id(entity_type, refs, unique_uuid, project_uuid=None,
                         is_flex=False):
    """APPLICATION uuid5; FLEX MD5(salus+scope+Go list). Same as ingest.py."""
    refs = list(refs or [])
    if not unique_uuid:
        return "", ""
    if is_flex:
        body = "[" + " ".join(sorted(refs)) + "]"
        body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
        if entity_type and entity_type not in ("VM", "EG"):
            suffix = CAT_SUFFIX.get(entity_type)
            if suffix:
                body = body + ":" + str(suffix)
        if project_uuid and project_uuid != DEFAULT_PROJECT:
            body = body + ":project:" + project_uuid
        digest = _md5(
            (SALUS_SERVICE_NAME + unique_uuid + body).encode()).digest()
        return str(uuid_lib.UUID(bytes=digest)), body
    body = str(sorted(list(refs)))
    body = _U_QUOTE.sub(lambda m: "u" + m.group(0), body)
    if entity_type and entity_type not in ("VM", "EG"):
        body = body + ":" + str(CAT_SUFFIX.get(entity_type))
    if project_uuid and project_uuid != DEFAULT_PROJECT:
        body = body + ":project:" + project_uuid
    return str(uuid_lib.uuid5(uuid_lib.UUID(str(unique_uuid)), body)), body


def scope_unique_uuid(scope, is_flex, vlan_uuid, global_uuid, vpc_uuids,
                      scope_refs=None):
    if scope in GLOBAL_SCOPES:
        return GLOBAL_SCOPE_UNIQUE_ID if is_flex else global_uuid
    if scope in VLAN_SCOPES:
        return VLAN_SCOPE_UNIQUE_ID if is_flex else vlan_uuid
    if scope in VPC_CAT_SCOPES:
        refs = scope_refs or []
        return refs[0] if refs else ""
    if scope in VPC_LIST_SCOPES:
        return vpc_uuids[0] if vpc_uuids else ""
    return vlan_uuid if not is_flex else VLAN_SCOPE_UNIQUE_ID


def _uuid_fields(policy, keys):
    out = []
    for key in keys:
        for item in values(policy, key):
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
    return out


def policy_vpc_uuids(policy):
    return _uuid_fields(policy, (
        "vpc_uuid", "vpc_uuid_list", "vpc_uuids", "target_vpc_uuid",
        "vpc_reference", "scope_vpc_uuid", "vpc_references",
        "scope_references"))


def policy_scope_refs(policy):
    """VPC-as-category scope id. flow_cli stores it in reference_uuid_list."""
    return _uuid_fields(policy, (
        "reference_uuid_list", "scope_reference_uuid_list",
        "scope_references", "policy_category"))


def as_uuid_list(items):
    out = []
    seen = set()
    for item in items or []:
        text = str(item or "").strip().lower()
        if not text or text in seen or text == ZERO:
            continue
        seen.add(text)
        out.append(text)
    return out


def as_str_list(value):
    out = []
    if value is None or value == "":
        return out
    if isinstance(value, list):
        for item in value:
            out.extend(as_str_list(item))
        return out
    if isinstance(value, dict):
        if "value_list" in value:
            return as_str_list(value.get("value_list"))
        for key in ("value", "str_value", "ip", "cidr", "address", "ipv4", "ipv6"):
            if value.get(key) not in (None, ""):
                return as_str_list(value.get(key))
        return out
    text = str(value).strip()
    if text:
        out.append(text)
    return out


def component_refs(comp):
    """Return (entity_type, refs, skip_reason) for EG/category port-sets."""
    allow = str(first(comp, "allow_type") or "")
    if allow in SKIP_ALLOW:
        return None, [], "allow_type=%s" % allow
    egs = as_uuid_list(values(comp, "entity_group_uuid_list"))
    if egs:
        return None, egs, ""
    cats = as_uuid_list(values(comp, "category_uuid_list"))
    if cats:
        if any(item in ("all", "any") for item in cats):
            return None, [], "wildcard category"
        sel = CAT_TYPE.get(
            str(first(comp, "category_selection_type") or "kVM"), "VM")
        return sel, cats, ""
    vms = as_uuid_list(values(comp, "vm_uuid_list"))
    if vms:
        return "VM", vms, ""
    subnets = as_uuid_list(values(comp, "subnet_uuid_list"))
    if subnets:
        return "SUBNET", subnets, ""
    vpcs = as_uuid_list(values(comp, "vpc_uuid_list"))
    if vpcs:
        return "VPC", vpcs, ""
    if values(comp, "address_group_uuid") or values(comp, "ip_subnet"):
        return None, [], ""
    if isinstance(comp, dict):
        for key in ("endpoint_entity", "secured_entity"):
            child = comp.get(key)
            if isinstance(child, dict):
                return component_refs(child)
    return None, [], "no entity refs"
def idf_json_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [idf_json_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "str_list" in value:
        inner = value.get("str_list")
        if isinstance(inner, dict):
            return as_str_list(inner.get("value_list"))
        if isinstance(inner, list):
            return as_str_list(inner)
        return []
    if "int64_list" in value:
        inner = value.get("int64_list") or {}
        items = inner.get("value_list") if isinstance(inner, dict) else inner
        out = []
        for item in items or []:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                out.append(item)
        return out
    if "value_list" in value and set(value.keys()) <= set(
            ("value_list", "timestamp_usecs")):
        return [idf_json_value(item) for item in (value.get("value_list") or [])]
    if "str_value" in value:
        return str(value.get("str_value") or "")
    if "bool_value" in value:
        return bool(value.get("bool_value"))
    for key in ("int64_value", "uint64_value", "int32_value"):
        if key in value:
            try:
                return int(value.get(key))
            except (TypeError, ValueError):
                return value.get(key)
    return value


def flatten_idf_entity(ent):
    if not isinstance(ent, dict):
        return None
    attrs = {}
    guid = ent.get("entity_guid") or {}
    if isinstance(guid, dict):
        uid = str(guid.get("entity_id") or "").strip()
        if uid:
            attrs["ext_id"] = uid
            attrs["uuid"] = uid
    elif ent.get("ext_id") or ent.get("uuid"):
        uid = str(ent.get("ext_id") or ent.get("uuid") or "").strip()
        if uid:
            attrs["ext_id"] = uid
            attrs["uuid"] = uid
    adm = ent.get("attribute_data_map")
    items = []
    if isinstance(adm, list):
        items = adm
    elif isinstance(adm, dict):
        if adm.get("name"):
            items = [adm]
        else:
            items = [{"name": key, "value": val} for key, val in adm.items()]
    if not items and not adm:
        row = dict(ent)
        row.pop("attribute_data_map", None)
        return row
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        if not name:
            continue
        if name == "__zprotobuf__":
            raw = item.get("value") if isinstance(item.get("value"), dict) else {}
            attrs[name] = _zprotobuf_bytes((raw or {}).get("bytes_value"))
            continue
        attrs[name] = idf_json_value(item.get("value"))
    return attrs or None


def parse_idf_entities(payload):
    ents = []
    if isinstance(payload, dict):
        raw = payload.get("entity")
        if raw is None:
            raw = payload.get("entities")
        if isinstance(raw, list):
            ents = raw
        elif isinstance(raw, dict):
            ents = [raw]
        elif payload.get("attribute_data_map") or payload.get("entity_guid"):
            ents = [payload]
    elif isinstance(payload, list):
        ents = payload
    rows = []
    for ent in ents:
        row = flatten_idf_entity(ent)
        if row:
            rows.append(row)
    return rows


def walk_components(node, sink, role=None):
    if not isinstance(node, dict):
        return
    key = role or node.get("_key") or ""
    if key in COMPONENT_KEYS:
        if node.get("_key") != key:
            node = dict(node)
            node["_key"] = key
        sink.append(node)
        return
    for child_key, val in node.items():
        if str(child_key).startswith("_"):
            continue
        if isinstance(val, dict):
            walk_components(val, sink, child_key)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    if child_key == "isolation_group_list":
                        group = dict(item)
                        group["_key"] = "secured_group"
                        sink.append(group)
                        continue
                    walk_components(item, sink, child_key)


def rule_is_flex(rule, policy_type):
    if (rule.get("_key") or "") == "flex_policy_rule":
        return True
    return str(policy_type or "") in ("kFlex", "FLEX")



ENDPOINT_ROLES = frozenset(("endpoint", "src_endpoint", "dest_endpoint"))


def _eg_flag(refs, eg_map, flag):
    if not eg_map or not refs:
        return False
    return all((eg_map.get(uid) or {}).get(flag) for uid in refs)


def _address_egs(refs, eg_map):
    """True when every ref is an address-group entity group."""
    return _eg_flag(refs, eg_map, "address")


def _kube_egs(refs, eg_map):
    """True when every ref is a Kubernetes entity group. Those are not port sets."""
    return _eg_flag(refs, eg_map, "kube")


def annotate_component(comp, unique_uuid, project_uuid, is_flex, include_project,
                       eg_map=None):
    """Port-set hash only. Address groups are not port sets."""
    entity_type, refs, skip = component_refs(comp)
    role = comp.get("_key") or ""
    row = {
        "role": role,
        "kind": "",
        "entity_type": entity_type,
        "refs": refs,
        "port_set": "",
        "port_set_uuid": "",
    }
    if as_uuid_list(values(comp, "address_group_uuid")) or values(comp, "ip_subnet"):
        row["kind"] = "address_set"
        return row
    if role in ENDPOINT_ROLES and _address_egs(refs, eg_map):
        row["kind"] = "address_set"
        return row
    if _kube_egs(refs, eg_map):
        return row
    if skip or not refs or not unique_uuid:
        return row
    project = project_uuid
    hashed, _body = generate_port_set_id(
        entity_type, refs, unique_uuid, project, is_flex=is_flex)
    row["kind"] = "port_set"
    row["port_set"] = hashed
    row["port_set_uuid"] = hashed
    return row


def iter_rules(policy):
    for rules_list in values(policy, "rules_list"):
        if not isinstance(rules_list, dict):
            continue
        for rkey in RULE_KEYS:
            for rule in values(rules_list, rkey):
                if isinstance(rule, dict):
                    if not rule.get("_key"):
                        rule = dict(rule)
                        rule["_key"] = rkey
                    yield rkey, rule


def annotate_policy(policy, vlan_uuid, global_uuid, include_project, eg_map=None):
    name = first(policy, "name")
    policy_uuid = first(policy, "uuid")
    scope = first(policy, "scope") or "kAllVlan"
    mode = first(policy, "mode")
    policy_type = first(policy, "policy_type")
    project = first(policy, "project_uuid") or ZERO
    vpc_uuids = policy_vpc_uuids(policy)
    scope_refs = policy_scope_refs(policy)
    rules_out = []
    save_mode = str(mode) in ("kSave", "SAVE")
    if not save_mode:
        for rkey, rule in iter_rules(policy):
            is_flex = rule_is_flex(rule, policy_type) or rkey == "flex_policy_rule"
            unique = scope_unique_uuid(
                scope, is_flex, vlan_uuid, global_uuid, vpc_uuids, scope_refs)
            info = first(rule, "rule_info") or {}
            if not isinstance(info, dict):
                info = {}
            rule_uuid = first(info, "uuid") or first(rule, "uuid") or ""
            comps = []
            walk_components(rule, comps)
            seen = set()
            component_rows = []
            for comp in comps:
                marker = (comp.get("_start"), comp.get("_end"), id(comp))
                if marker in seen:
                    continue
                seen.add(marker)
                component_rows.append(annotate_component(
                    comp, unique, project, is_flex, include_project, eg_map))
            rules_out.append({
                "rule_kind": rkey or rule.get("_key"),
                "rule_uuid": rule_uuid,
                "is_flex": is_flex,
                "unique_uuid": unique,
                "components": component_rows,
            })
    return {
        "name": name,
        "uuid": policy_uuid,
        "scope": scope,
        "mode": mode,
        "policy_type": policy_type,
        "project_uuid": project,
        "skipped_save": save_mode,
        "rules": rules_out,
    }, []


def _which(*paths):
    for path in paths:
        if path and os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return paths[-1] if paths else ""


def _run(argv, timeout, input_text=None):
    """Run a command and keep stdout in memory."""
    kw = {
        "check": False,
        "timeout": max(5, int(timeout)),
        "text": True,
        "capture_output": True,
    }
    if input_text is None:
        kw["stdin"] = subprocess.DEVNULL
    else:
        kw["input"] = input_text
    try:
        proc = subprocess.run(argv, **kw)
    except subprocess.TimeoutExpired:
        return -1, "", "timed out after %ss" % timeout
    except Exception as err:
        return -1, "", str(err)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _bash(cmd, timeout=30):
    rc, out, err = _run(
        ["bash", "-lc", "source /etc/profile >/dev/null 2>&1; %s" % cmd], timeout)
    return rc, out, err


def _json_loads(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    for a, b in (("{", "}"), ("[", "]")):
        start, end = text.find(a), text.rfind(b)
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except Exception:
                pass
    return None


def detect_platform():
    info = {"platform": "cmsp", "smsp_cluster_uuid": ""}
    _rc, out, err = _bash("mspctl cluster get flow --verbose", 45)
    parsed = _json_loads(out)
    uid = ""
    if isinstance(parsed, dict):
        uid = str(
            parsed.get("ClusterUUID") or parsed.get("cluster_uuid") or
            parsed.get("uuid") or "")
    if not uid:
        match = re.search(
            r"ClusterUUID['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F-]{36})",
            "%s\n%s" % (out, err), re.I)
        uid = match.group(1) if match else ""
    if uid:
        info["platform"] = "smsp"
        info["smsp_cluster_uuid"] = uid
        LOG.info("Detected SMSP uuid=%s", uid)
    else:
        LOG.info("Detected CMSP")
    return info
def _kubectl_bin():
    return _which(
        "/usr/bin/kubectl", "/usr/local/bin/kubectl",
        "/home/nutanix/bin/kubectl", "kubectl")


_KUBECTL_PREFIX = {}


def _kubectl_prefix(kubeconfig=""):
    key = kubeconfig or ""
    cached = _KUBECTL_PREFIX.get(key)
    if cached:
        return list(cached)
    kubectl = _kubectl_bin()
    # Plain kubectl works on CMSP. sudo without -n waits on a password.
    prefix = [kubectl]
    for candidate in ([kubectl], ["sudo", "-n", kubectl]):
        rc, _out, _err = _run(candidate + ["get", "ns"], 20)
        if rc == 0:
            prefix = candidate
            break
    if kubeconfig:
        prefix = list(prefix) + ["--kubeconfig", kubeconfig]
    _KUBECTL_PREFIX[key] = list(prefix)
    return list(prefix)


def _kubectl(extra, timeout, kubeconfig="", input_text=None):
    return _run(
        _kubectl_prefix(kubeconfig) + list(extra), timeout,
        input_text=input_text)


def _flow_kubeconfig(dest_dir):
    _rc, out, err = _bash("mspctl cluster kubeconfig flow", 45)
    text = out or ""
    yaml_text = ""
    for marker in ("apiVersion:", "kind: Config", "clusters:"):
        idx = text.find(marker)
        if idx >= 0:
            yaml_text = text[idx:].strip() + "\n"
            break
    if not yaml_text:
        return "", (err or out or "mspctl cluster kubeconfig flow failed")[:400]
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, ".flow.kubeconfig")
    with open(path, "w") as handle:
        handle.write(yaml_text)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return path, ""


def _find_pod(app, preferred, namespace="", kubeconfig=""):
    ns_flag = ["-n", namespace] if namespace else ["-A"]
    rc, stdout, stderr = _kubectl(
        ["get", "pods"] + ns_flag + [
            "-o",
            "jsonpath={range .items[*]}{.metadata.namespace}{\"\\t\"}"
            "{.metadata.name}{\"\\t\"}{.status.phase}{\"\\t\"}"
            "{.metadata.labels.app}{\"\\n\"}{end}"],
        45, kubeconfig=kubeconfig)
    if rc != 0:
        return "", "", (stderr or stdout or "kubectl get pods failed")[:400]
    matches = []
    for line in (stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or parts[2].strip() != "Running":
            continue
        ns, name = parts[0].strip(), parts[1].strip()
        label = parts[3].strip() if len(parts) > 3 else ""
        if name == preferred or label == app or name.startswith(app + "-"):
            matches.append((ns, name))
    if not matches:
        return "", "", "no Running pod %s" % preferred
    for ns, name in matches:
        if name == preferred:
            return ns, name, ""
    for ns, name in matches:
        if name.endswith("-0"):
            return ns, name, ""
    return matches[0][0], matches[0][1], ""


def _zk_bin(name):
    for path in (
            "/home/nutanix/cluster/bin/%s" % name,
            "/usr/local/nutanix/cluster/bin/%s" % name):
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return ""


def _pc_zk_uuids():
    out = {"vlan_unique_uuid": "", "global_unique_uuid": ""}
    zkcat = _zk_bin("zkcat")
    if not zkcat:
        return out
    for key, path in (
            ("vlan_unique_uuid", VLAN_ZK), ("global_unique_uuid", GLOBAL_ZK)):
        rc, stdout, _err = _run([zkcat, path], 20)
        match = UUID_RE.search((stdout or "").strip())
        if rc == 0 and match:
            out[key] = match.group(0)
    return out


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")


COLUMNS = ("mismatch", "port_set", "policy", "nic_mismatch")
# port_set is an evictable IDF type: Insights rejects --all.
# atlas_port_set is the table idfcli can list. Entity id is the port-set UUID.
IDF_ENTITIES = ("atlas_port_set", "port_set")
IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
    "idfcli",
)
POLICY_IDF_ENTITIES = ("network_security_policy", "security_policy")


def idfcli_bin():
    return _which(*IDF_BINS)


def _nic_list(row):
    for key in (
            "virtual_nic_uuid_list", "vnic_uuid_list", "virtual_nic_uuids"):
        raw = row.get(key) if isinstance(row, dict) else None
        if raw:
            return as_str_list(raw)
    return []


def index_idf_port_sets(rows):
    """uuid -> {uuid, name, nics} from flattened idfcli port_set rows."""
    out = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        uid = str(row.get("uuid") or row.get("ext_id") or "").strip().lower()
        if not UUID_RE.fullmatch(uid):
            continue
        name = str(row.get("name") or "")
        prev = out.get(uid)
        nics = _nic_list(row)
        if prev is None:
            out[uid] = {"uuid": uid, "name": name, "nics": nics}
            continue
        if name and not prev["name"]:
            prev["name"] = name
        for nic in nics:
            if nic not in prev["nics"]:
                prev["nics"].append(nic)
    return out


def port_set_entities(choice):
    """auto reads atlas_port_set, then the evictable port_set table."""
    text = str(choice or "auto").strip()
    if text == "auto":
        return IDF_ENTITIES
    if text not in IDF_ENTITIES:
        raise SystemExit(
            "unknown --port-set-entity %s (auto, atlas_port_set, port_set)" % text)
    return (text,)


def fetch_idf_port_sets(info, timeout=300, entity="auto"):
    """Load port sets from idfcli. Stdout stays in memory.

    SMSP uses the flow-cluster IDF. CMSP uses the local idfcli.
    atlas_port_set accepts get entity --all. port_set is evictable, so
    that call falls through to get entitytype.
    """
    entities = port_set_entities(entity)
    rows = fetch_idf_rows(info, entities, timeout, required=True)
    found = index_idf_port_sets(rows)
    if not found:
        raise SystemExit("idfcli %s returned no port sets" % ",".join(entities))
    LOG.info("idfcli port_set entity=%s count=%s", ",".join(entities), len(found))
    return found


# IDF ints. mode 1=MONITOR 2=ENFORCE. scope 1=ALL_VLAN 3=VPC 4=GLOBAL
# 5=VPC_AS_CATEGORY. SAVE is 0 or 3. FLEX is a rule, not a policy type.
POLICY_TYPE_NAME = {1: "kApplication", 2: "kIsolation", 3: "kQuarantine"}
POLICY_MODE_NAME = {0: "kSave", 1: "kMonitor", 2: "kApply", 3: "kSave"}
POLICY_SCOPE_NAME = {
    1: "kAllVlan", 2: "kVpcList", 3: "kVpcList",
    4: "kGlobal", 5: "kVpcAsCategory",
}
CAT_SEL_NAME = {1: "kVM", 2: "kVPC", 3: "kSubnet"}
ALLOW_NAME = {1: "kTypeAll", 2: "kTypeNone"}
# Application rule field 5. 1 is inbound, 2 is outbound.
RULE_DIRECTION_NAME = {1: "kIn", 2: "kOut"}
# Service message field 1. Only kAll showed up as a bare protocol.
SERVICE_PROTO_NAME = {1: "kAll", 2: "kICMP", 3: "kTCP", 4: "kUDP", 5: "kICMPv6"}
_RULE_FIELDS = (
    (1, "application_rule", "app"),
    (2, "isolation_rule", "two"),
    (3, "quarantine_rule", "app"),
    (4, "secured_group_rule", "sg"),
    (5, "multi_env_isolation_rule", "multi"),
    (6, "shared_service_rule", "app"),
    (7, "flex_policy_rule", "flex"),
)


def _zprotobuf_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str) or not value:
        return b""
    try:
        return base64.b64decode(value)
    except Exception:
        return b""


def _zlib_decompress(data):
    if not data:
        return b""
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            continue
    return data


def _proto_read_varint(buf, idx):
    value = 0
    shift = 0
    n = len(buf or b"")
    while idx < n:
        byte = buf[idx]
        idx += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, idx
        shift += 7
        if shift > 63:
            break
    return None, idx


def _proto_decode(buf):
    """field number -> [(wire, value)]. Stdlib protobuf wire decoder."""
    fields = {}
    idx = 0
    n = len(buf or b"")
    while idx < n:
        key, idx = _proto_read_varint(buf, idx)
        if key is None:
            break
        field_n = key >> 3
        wire = key & 7
        if field_n <= 0:
            break
        if wire == 0:
            val, idx = _proto_read_varint(buf, idx)
            if val is None:
                break
        elif wire == 1:
            if idx + 8 > n:
                break
            val = buf[idx:idx + 8]
            idx += 8
        elif wire == 2:
            length, idx = _proto_read_varint(buf, idx)
            if length is None or length < 0 or idx + length > n:
                break
            val = buf[idx:idx + length]
            idx += length
        elif wire == 5:
            if idx + 4 > n:
                break
            val = buf[idx:idx + 4]
            idx += 4
        else:
            break
        fields.setdefault(field_n, []).append((wire, val))
    return fields


def _proto_varint(fields, number, default=0):
    for wire, val in fields.get(number) or []:
        if wire == 0 and val is not None:
            return int(val)
    return default


def _proto_chunks(fields, number):
    out = []
    for wire, val in fields.get(number) or []:
        if wire == 2 and isinstance(val, (bytes, bytearray)):
            out.append(bytes(val))
    return out


def _proto_text(raw):
    if not raw:
        return ""
    if len(raw) == 16:
        try:
            return str(uuid_lib.UUID(bytes=raw))
        except Exception:
            pass
    try:
        text = raw.decode("utf-8").strip()
    except Exception:
        return ""
    if text and all(32 <= ord(ch) < 127 for ch in text):
        return text
    return ""


def _proto_str(fields, number):
    chunks = _proto_chunks(fields, number)
    return _proto_text(chunks[0]) if chunks else ""


def _proto_str_list(fields, number):
    out = []
    for raw in _proto_chunks(fields, number):
        text = _proto_text(raw)
        if text:
            out.append(text)
    return out


def _secured_group_dict(raw):
    if not raw:
        return {}
    fields = _proto_decode(raw)
    out = {}
    cats = _proto_str_list(fields, 1)
    egs = _proto_str_list(fields, 4)
    if cats:
        out["category_uuid_list"] = cats
        sel = _proto_varint(fields, 5, 1)
        out["category_selection_type"] = CAT_SEL_NAME.get(sel, "kVM")
    if egs:
        out["entity_group_uuid_list"] = egs
    return out


def _endpoint_dict(raw):
    if not raw:
        return {}
    fields = _proto_decode(raw)
    out = {}
    ents = _proto_chunks(fields, 1)
    if ents:
        ent = _proto_decode(ents[0])
        cats = _proto_str_list(ent, 1)
        if cats:
            sel = _proto_varint(ent, 2, 1)
            out["endpoint_entity"] = {
                "category_uuid_list": cats,
                "category_selection_type": CAT_SEL_NAME.get(sel, "kVM"),
            }
    subnet = _proto_str(fields, 2) or _proto_str(fields, 6)
    if subnet:
        out["ip_subnet"] = subnet
    ag = _proto_str(fields, 3)
    if ag:
        out["address_group_uuid"] = ag
    allow = _proto_varint(fields, 4, 0)
    if allow:
        out["allow_type"] = ALLOW_NAME.get(allow, str(allow))
    egs = _proto_str_list(fields, 5)
    if egs:
        out["entity_group_uuid_list"] = egs
    return out


def _rule_info_dict(raw):
    uid = _proto_str(_proto_decode(raw or b""), 1)
    return {"uuid": uid} if uid else {}


def _take_msg(fields, number):
    chunks = _proto_chunks(fields, number)
    return chunks[0] if chunks else b""


def _rule_direction(fields, number=5):
    value = _proto_varint(fields, number, 0)
    return RULE_DIRECTION_NAME.get(value, "")


def _rule_action(fields, number):
    """Bool action. Field absent means the caller should leave it unset."""
    for wire, val in fields.get(number) or []:
        if wire == 0 and val is not None:
            return bool(int(val))
    return None


def _service_dict(raw):
    sub = _proto_decode(raw or b"")
    uid = _proto_str(sub, 4)
    if uid:
        return {"service_group_uuid": uid}
    proto = _proto_varint(sub, 1, 0)
    if proto in SERVICE_PROTO_NAME:
        return {"protocol": SERVICE_PROTO_NAME[proto]}
    if proto:
        return {"protocol": str(proto)}
    return {}


def _rule_services(fields, number=4):
    out = []
    for raw in _proto_chunks(fields, number):
        svc = _service_dict(raw)
        if svc:
            out.append(svc)
    return out


def _attach_rule_meta(body, fields, action_field=None):
    direction = _rule_direction(fields)
    if direction:
        body["direction"] = direction
    if action_field is not None:
        action = _rule_action(fields, action_field)
        if action is not None:
            body["action"] = action
    services = _rule_services(fields)
    if services:
        body["services"] = services
    return body


def _app_rule_dict(raw):
    fields = _proto_decode(raw or b"")
    body = {"rule_info": _rule_info_dict(_take_msg(fields, 1))}
    secured = _secured_group_dict(_take_msg(fields, 2))
    if secured:
        body["secured_group"] = secured
    endpoint = _endpoint_dict(_take_msg(fields, 3))
    if endpoint:
        body["endpoint"] = endpoint
    return _attach_rule_meta(body, fields)


def _two_env_dict(raw):
    fields = _proto_decode(raw or b"")
    body = {"rule_info": _rule_info_dict(_take_msg(fields, 1))}
    first = _secured_group_dict(_take_msg(fields, 2))
    second = _secured_group_dict(_take_msg(fields, 3))
    if first:
        body["first_secured_group"] = first
    if second:
        body["second_secured_group"] = second
    return body


def _sg_rule_dict(raw):
    fields = _proto_decode(raw or b"")
    body = {"rule_info": _rule_info_dict(_take_msg(fields, 1))}
    secured = _secured_group_dict(_take_msg(fields, 2))
    if secured:
        body["secured_group"] = secured
    # Field 3 is the intra-group action. 0 is deny, 1 is allow.
    return _attach_rule_meta(body, fields, action_field=3)


def _multi_dict(raw):
    fields = _proto_decode(raw or b"")
    body = {"rule_info": _rule_info_dict(_take_msg(fields, 1))}
    groups = []
    blob = _take_msg(fields, 3)
    if blob:
        for chunk in _proto_chunks(_proto_decode(blob), 1):
            secured = _secured_group_dict(chunk)
            if secured:
                groups.append(secured)
    if groups:
        body["all_to_all_isolation_group"] = {"isolation_group_list": groups}
    return body


def _flex_side(endpoint, flag):
    """Allow-any is a flag with no endpoint. Other selectors stay on the side."""
    if not endpoint:
        return {}
    refs = (
        endpoint.get("entity_group_uuid_list")
        or endpoint.get("endpoint_entity")
        or endpoint.get("address_group_uuid")
        or endpoint.get("ip_subnet"))
    if endpoint.get("allow_type") in SKIP_ALLOW and not refs:
        return {flag: True}
    return {}


def _flex_rule_dict(raw):
    fields = _proto_decode(raw or b"")
    body = {"rule_info": _rule_info_dict(_take_msg(fields, 1))}
    src = _endpoint_dict(_take_msg(fields, 2))
    dst = _endpoint_dict(_take_msg(fields, 3))
    src_flag = _flex_side(src, "should_allow_any_src")
    dst_flag = _flex_side(dst, "should_allow_any_dst")
    if src_flag:
        body.update(src_flag)
    elif src:
        body["src_endpoint"] = src
    if dst_flag:
        body.update(dst_flag)
    elif dst:
        body["dest_endpoint"] = dst
    if 10 in fields:
        body["applied_to_entity_group_uuid_list"] = _proto_str_list(fields, 10)
    return body


def _rule_body(kind, raw):
    if kind == "app":
        return _app_rule_dict(raw)
    if kind == "two":
        return _two_env_dict(raw)
    if kind == "sg":
        return _sg_rule_dict(raw)
    if kind == "multi":
        return _multi_dict(raw)
    return _flex_rule_dict(raw)


def _rules_from_zprotobuf(raw):
    data = _zprotobuf_bytes(raw)
    if not data:
        return []
    top = _proto_decode(_zlib_decompress(data))
    rules = []
    for _wire, entry in top.get(6) or []:
        if not isinstance(entry, (bytes, bytearray)):
            continue
        vals = _proto_chunks(_proto_decode(entry), 2)
        if not vals:
            continue
        rule = _proto_decode(vals[0])
        for number, name, kind in _RULE_FIELDS:
            chunks = _proto_chunks(rule, number)
            if not chunks:
                continue
            rules.append({name: _rule_body(kind, chunks[0])})
            break
    return rules


def _idf_enum(value, table, default):
    if value in (None, ""):
        return default
    text = str(value).strip()
    if text in table.values() or text.startswith("k"):
        return text
    try:
        return table.get(int(text), default)
    except (TypeError, ValueError):
        return default


def policy_from_idf_row(row):
    """IDF network_security_policy row -> the dict annotate_policy already walks."""
    if not isinstance(row, dict):
        return None
    uid = str(row.get("uuid") or row.get("ext_id") or "").strip()
    rules = _rules_from_zprotobuf(row.get("__zprotobuf__"))
    if not uid and not rules:
        return None
    scope = _idf_enum(row.get("scope"), POLICY_SCOPE_NAME, "kAllVlan")
    policy = {
        "uuid": uid,
        "name": str(row.get("name") or ""),
        "mode": _idf_enum(row.get("mode"), POLICY_MODE_NAME, "kApply"),
        "policy_type": _idf_enum(
            row.get("policy_type"), POLICY_TYPE_NAME, "kApplication"),
        "scope": scope,
        "project_uuid": str(row.get("project_uuid") or ZERO),
        "rules_list": rules,
    }
    vpc = str(row.get("vpc_uuid") or "").strip()
    refs = as_str_list(row.get("reference_uuid_list"))
    # VPC-as-category hashes against reference_uuid_list, not the VPC uuid.
    if refs:
        policy["reference_uuid_list"] = refs
    if vpc and vpc != ZERO:
        policy["vpc_uuid"] = vpc
        policy["vpc_uuid_list"] = [vpc]
    return policy


def _idf_rows_from_stdout(text):
    payload = _json_loads(text)
    if payload is None:
        return []
    return parse_idf_entities(payload)


def _idfcli_commands(entity):
    """get entity --all, then get entitytype. port_set rejects --all."""
    bins = ("idfcli", "/usr/local/nutanix/bin/idfcli", "/home/nutanix/bin/idfcli")
    commands = []
    for binary in bins:
        commands.append(
            "%s get entity -e %s --all -o json" % (binary, entity))
        commands.append(
            "%s get entitytype -e %s -o json" % (binary, entity))
    return " || ".join(commands)


def _idfcli_argvs(binary, entity):
    return (
        [binary, "get", "entity", "-e", entity, "--all", "-o", "json"],
        [binary, "get", "entitytype", "-e", entity, "-o", "json"],
    )


def _fetch_idf_rows_smsp(entities, timeout):
    """Flow IDF on SMSP is inside the flow cluster, not on the PC."""
    tmp = tempfile.mkdtemp(prefix="port_set_kube_")
    kubeconfig = ""
    try:
        kubeconfig, kube_err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            return [], "smsp kubeconfig: %s" % (kube_err or "failed")
        found_pod = ("", "", "no pod")
        for app, preferred in (
                ("atlas", "atlas-0"), ("insights", "insights-0"), ("idf", "idf-0")):
            ns, pod, err = _find_pod(app, preferred, "ntnx-flow", kubeconfig)
            if not pod:
                ns, pod, err = _find_pod(app, preferred, "", kubeconfig)
            if pod:
                found_pod = (ns, pod, err)
                break
        ns, pod, err = found_pod
        if not pod:
            return [], "smsp idf pod: %s" % (err or "missing")
        last = "empty"
        for entity in entities:
            _rc, out, err = _kubectl(
                ["exec", "-n", ns, pod, "--", "bash", "-lc", _idfcli_commands(entity)],
                timeout, kubeconfig=kubeconfig)
            rows = _idf_rows_from_stdout(out)
            if rows:
                LOG.info("idfcli %s via %s/%s count=%s", entity, ns, pod, len(rows))
                return rows, ""
            last = (err or out or "empty").strip().replace("\n", " ")[:300]
        return [], "smsp idfcli %s/%s: %s" % (ns, pod, last)
    finally:
        if kubeconfig:
            try:
                os.remove(kubeconfig)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def fetch_idf_rows(info, entities, timeout, required=True):
    """Flattened idfcli rows. SMSP uses the flow-cluster idfcli."""
    errors = []
    if (info or {}).get("platform") == "smsp":
        rows, detail = _fetch_idf_rows_smsp(entities, timeout)
        if rows:
            return rows
        if detail:
            errors.append(detail)
    binary = idfcli_bin()
    for entity in entities:
        for argv in _idfcli_argvs(binary, entity):
            _rc, out, err = _run(argv, timeout)
            rows = _idf_rows_from_stdout(out)
            if rows:
                LOG.info("idfcli %s count=%s", " ".join(argv), len(rows))
                return rows
            detail = (err or out or "empty").strip().replace("\n", " ")[:300]
            errors.append("%s: %s" % (" ".join(argv), detail))
    if required:
        raise SystemExit(
            "idfcli %s returned no entities\n%s" % (
                ",".join(entities), "\n".join(errors)))
    if errors:
        LOG.warning("idfcli %s: %s", ",".join(entities), errors[0])
    return []


def _flow_cli_bin():
    return _which(
        "/home/nutanix/flow/bin/flow_cli",
        "/usr/local/nutanix/bin/flow_cli",
        "/home/nutanix/bin/flow_cli",
        "flow_cli")


def _cli_join(cli, args):
    return " ".join([cli, "-o", "json"] + [str(a) for a in args])


def _run_bash_cli(inner, timeout, log_cmd=True):
    if log_cmd:
        LOG.info("DUMP flow_cli: bash -lc %s", inner)
    rc, out, err = _run(["bash", "-lc", inner], timeout)
    parsed = _json_loads(out)
    if parsed is None:
        raise RuntimeError("flow_cli rc=%s: %s" % (rc, (err or out)[:400]))
    return parsed, out


def _run_kratos_cli(kubeconfig, ns, pod, inner, timeout, log_cmd=True):
    if log_cmd:
        LOG.info("DUMP kratos: kubectl exec %s/%s -- bash -lc %s", ns, pod, inner)
    rc, out, err = _kubectl(
        ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
        timeout, kubeconfig=kubeconfig)
    parsed = _json_loads(out)
    if parsed is None:
        raise RuntimeError("kratos rc=%s: %s" % (rc, (err or out)[:400]))
    return parsed, out


def _pod_bin(kubeconfig, ns, pod, inner):
    rc, out, _err = _kubectl(
        ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
        30, kubeconfig=kubeconfig)
    for line in (out or "").strip().splitlines():
        cand = line.strip()
        if cand:
            return cand
    return ""


def _list_rows(parsed):
    if isinstance(parsed, list):
        return parsed
    if not isinstance(parsed, dict):
        return []
    data = parsed.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rows = []
        for key, value in data.items():
            row = dict(value) if isinstance(value, dict) else {"value": value}
            row.setdefault("uuid", key)
            rows.append(row)
        return rows
    for key in ("entities", "items", "value", "results"):
        if isinstance(parsed.get(key), list):
            return parsed[key]
    return []


def _item_uuid(item):
    if isinstance(item, str):
        return item if UUID_RE.search(item) else ""
    if not isinstance(item, dict):
        return ""
    for key in ("uuid", "ext_id", "extId", "UUID", "id"):
        val = str(item.get(key) or "")
        if UUID_RE.search(val):
            return UUID_RE.search(val).group(0)
    return ""


def _uuids_from_rows(rows):
    out, seen = [], set()
    for item in rows or []:
        uid = _item_uuid(item)
        if uid and uid not in seen:
            seen.add(uid)
            out.append(uid)
    return out


def unwrap_policy(rec):
    if not isinstance(rec, dict):
        return None
    if rec.get("_key") == "network_security_policy":
        return rec
    if "network_security_policy" in rec and isinstance(
            rec.get("network_security_policy"), dict):
        return rec["network_security_policy"]
    data = rec.get("data")
    if isinstance(data, dict) and isinstance(data.get("network_security_policy"), dict):
        return data["network_security_policy"]
    if rec.get("uuid") and rec.get("rules_list") is not None:
        return rec
    return None


def _policy_runner(info):
    """Return (runner, cleanup) for flow_cli policy.list/get."""
    platform = (info or {}).get("platform") or "cmsp"
    cleanup = []
    if platform != "smsp":
        binary = _flow_cli_bin()

        def runner(args, timeout, log_cmd=True, _binary=binary):
            return _run_bash_cli(
                _cli_join(_binary, args), timeout, log_cmd=log_cmd)

        return runner, cleanup

    tmp = tempfile.mkdtemp(prefix="port_set_kube_")
    kubeconfig, kube_err = _flow_kubeconfig(tmp)

    def _cleanup():
        if kubeconfig:
            try:
                os.remove(kubeconfig)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass

    cleanup.append(_cleanup)
    if kubeconfig:
        ns, pod, err = _find_pod("kratos", "kratos-0", "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, err = _find_pod("kratos", "kratos-0", "", kubeconfig)
        cli = ""
        if pod:
            cli = _pod_bin(
                kubeconfig, ns, pod,
                "command -v kratos_cli || command -v flow_cli || "
                "ls /home/nutanix/flow/bin/kratos_cli "
                "/home/nutanix/flow/bin/flow_cli 2>/dev/null | head -1")
        if pod and cli:
            def runner(args, timeout, log_cmd=True, _cli=cli, _ns=ns, _pod=pod):
                return _run_kratos_cli(
                    kubeconfig, _ns, _pod, _cli_join(_cli, args),
                    timeout, log_cmd=log_cmd)

            return runner, cleanup
        LOG.warning("kratos cli missing (%s)", err or "no cli")
    smsp_uuid = (info or {}).get("smsp_cluster_uuid") or ""
    if not smsp_uuid:
        _cleanup()
        raise SystemExit(
            "SMSP policy fetch failed: %s" % (kube_err or "no ClusterUUID"))
    binary = _flow_cli_bin()
    ws = "ws://smsp-%s.ntnx-ikat.svc:2051/flow_cli" % smsp_uuid

    def runner(args, timeout, log_cmd=True, _binary=binary, _ws=ws):
        return _run_bash_cli(
            "%s -u '%s' -o json %s" % (
                _binary, _ws, " ".join(str(arg) for arg in args)),
            timeout, log_cmd=log_cmd)

    return runner, cleanup


def fetch_policies_flow_cli(info, workers=8, timeout=1800):
    """Policies from flow_cli. Fails when the Flow process is down."""
    runner, cleanup = _policy_runner(info)
    try:
        list_timeout = max(60, min(300, int(timeout)))
        per = max(15, min(45, int(timeout)))
        parsed, _text = runner(["policy.list"], list_timeout)
        if isinstance(parsed, dict) and parsed.get("status") not in (None, 0, "0"):
            raise SystemExit("policy.list status=%s" % parsed.get("status"))
        uuids = _uuids_from_rows(_list_rows(parsed))
        gets = {}
        if not uuids:
            return []
        get_workers = max(1, min(int(workers), len(uuids)))

        def _one(uid):
            one, _text = runner(["policy.get", uid], per, log_cmd=False)
            if isinstance(one, dict) and one.get("status") not in (None, 0, "0"):
                raise RuntimeError("status=%s" % one.get("status"))
            return one

        failed = []
        from concurrent.futures import ThreadPoolExecutor, wait
        with ThreadPoolExecutor(max_workers=get_workers) as pool:
            fmap = {pool.submit(_one, uid): uid for uid in uuids}
            done, pending = wait(fmap.keys(), timeout=timeout)
            for fut in done:
                uid = fmap[fut]
                try:
                    gets[uid] = fut.result(timeout=1)
                except Exception as err:
                    failed.append("%s" % err)
            for fut in pending:
                failed.append(fmap[fut])
                fut.cancel()
        if failed and not gets:
            raise SystemExit("policy.get failed: %s" % failed[0])
        if failed:
            LOG.warning("policy.get failed %s of %s", len(failed), len(uuids))
        policies = []
        for rec in gets.values():
            policy = unwrap_policy(rec)
            if policy:
                policies.append(policy)
        return policies
    finally:
        for fn in cleanup:
            fn()


def policy_backend(flow_cli=False, idf_cli=False):
    """--flow-cli or --idf-cli. Neither flag means flow_cli."""
    if flow_cli and idf_cli:
        raise SystemExit("pass only one of --flow-cli or --idf-cli")
    if idf_cli:
        return "idf_cli"
    return "flow_cli"


def fetch_policies(info, workers=8, timeout=1800, backend="flow_cli"):
    """Policies from idfcli or flow_cli."""
    if backend == "flow_cli":
        return fetch_policies_flow_cli(info, workers, timeout)
    rows = fetch_idf_rows(
        info, POLICY_IDF_ENTITIES, min(int(timeout), 600), required=True)
    policies = []
    decoded = 0
    for row in rows:
        policy = policy_from_idf_row(row)
        if not policy:
            continue
        if policy.get("rules_list"):
            decoded += 1
        policies.append(policy)
    LOG.info("idf policies=%s with_rules=%s", len(policies), decoded)
    if policies and not decoded:
        raise SystemExit(
            "idfcli policies had no decodable rules (__zprotobuf__)")
    return policies

EG_KUBE_SELECT = {4, 5, 6, 7}
EG_ADDRESS_SELECT = {8, 9, 10}


def _eg_flags_from_row(row):
    """Kube select types are 4-7. Address-group select types are 8-10."""
    raw = (row or {}).get("allowed_entity_select_type_enums") or []
    if not isinstance(raw, list):
        raw = [raw]
    address = False
    kube = False
    for item in raw:
        text = str(item or "")
        if text.startswith("kAddressGroup"):
            address = True
            continue
        if text.startswith("kKube"):
            kube = True
            continue
        try:
            num = int(text)
        except (TypeError, ValueError):
            continue
        if num in EG_ADDRESS_SELECT:
            address = True
        elif num in EG_KUBE_SELECT:
            kube = True
    return address, kube


def _eg_spec(payload):
    if not isinstance(payload, dict):
        return None
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    group = data.get("network_entity_group") if isinstance(data, dict) else None
    if isinstance(group, dict):
        spec = group.get("spec")
        return spec if isinstance(spec, dict) else group
    return data if isinstance(data, dict) else None


def _eg_select(spec, prefix):
    if not isinstance(spec, dict):
        return False
    for ent in spec.get("allowed_entities") or []:
        if not isinstance(ent, dict):
            continue
        if str(ent.get("select_type_enum") or "").startswith(prefix):
            return True
    return False


def _eg_is_address(spec):
    return _eg_select(spec, "kAddressGroup")


def _eg_is_kube(spec):
    return _eg_select(spec, "kKube")


def collect_entity_group_uuids(policies):
    found = []
    seen = set()
    keys = (
        "entity_group_uuid_list", "entity_group_uuid",
        "applied_to_entity_group_uuid_list", "applied_to_entity_group_uuid",
    )

    def walk(node):
        if isinstance(node, dict):
            for key in keys:
                if key not in node:
                    continue
                for uid in as_uuid_list(values(node, key)):
                    if uid not in seen:
                        seen.add(uid)
                        found.append(uid)
            for val in node.values():
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(policies)
    return found



def _fetch_entity_groups_flow(info, uuids, workers, timeout):
    """flow_cli entity_group.get. Used when idfcli returns no entity groups."""
    runner, cleanup = _policy_runner(info)
    out = {}
    try:
        per = max(15, min(45, int(timeout)))

        def _one(uid):
            one, _text = runner(["entity_group.get", uid], per, log_cmd=False)
            if isinstance(one, dict) and one.get("status") not in (None, 0, "0"):
                raise RuntimeError("status=%s" % one.get("status"))
            spec = _eg_spec(one)
            return uid, _eg_is_address(spec), _eg_is_kube(spec)

        from concurrent.futures import ThreadPoolExecutor, wait
        get_workers = max(1, min(int(workers), len(uuids)))
        with ThreadPoolExecutor(max_workers=get_workers) as pool:
            fmap = {pool.submit(_one, uid): uid for uid in uuids}
            done, pending = wait(fmap.keys(), timeout=timeout)
            for fut in done:
                uid = fmap[fut]
                try:
                    got, address, kube = fut.result(timeout=1)
                except Exception as err:
                    LOG.warning("entity_group.get %s: %s", uid, err)
                    continue
                if address or kube:
                    out[str(got).lower()] = {
                        "address": bool(address), "kube": bool(kube)}
            for fut in pending:
                LOG.warning("entity_group.get %s timed out", fmap[fut])
                fut.cancel()
        LOG.info(
            "address entity groups=%s kube=%s of %s",
            sum(1 for rec in out.values() if rec.get("address")),
            sum(1 for rec in out.values() if rec.get("kube")),
            len(uuids))
        return out
    except Exception as err:
        LOG.warning("entity_group fetch skipped: %s", err)
        return out
    finally:
        for fn in cleanup:
            fn()


def fetch_entity_groups(info, policies, workers=8, timeout=300):
    """uuid -> {address, kube}. idfcli first so this works while Flow is down."""
    uuids = collect_entity_group_uuids(policies)
    if not uuids:
        return {}
    wanted = set(str(uid).lower() for uid in uuids)
    rows = []
    try:
        rows = fetch_idf_rows(
            info, ("network_entity_group", "entity_group"),
            min(int(timeout), 300), required=False)
    except Exception as err:
        LOG.warning("entity_group idfcli: %s", err)
        rows = []
    if rows:
        out = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            uid = str(row.get("uuid") or row.get("ext_id") or "").strip().lower()
            if uid not in wanted:
                continue
            address, kube = _eg_flags_from_row(row)
            if address or kube:
                out[uid] = {"address": bool(address), "kube": bool(kube)}
        LOG.info(
            "idf entity groups address=%s kube=%s of %s",
            sum(1 for rec in out.values() if rec.get("address")),
            sum(1 for rec in out.values() if rec.get("kube")),
            len(wanted))
        return out
    return _fetch_entity_groups_flow(info, uuids, workers, timeout)


def scope_uuids_for_platform(platform, pc_global, pc_vlan, atlas_global, atlas_vlan):
    """SMSP port-set scope ids come from Atlas ZK, not the PC zkcat copy."""
    if platform == "smsp":
        return atlas_global or pc_global or "", atlas_vlan or pc_vlan or ""
    return pc_global or "", pc_vlan or ""


def fetch_unique_uuids(info):
    rec = _pc_zk_uuids()
    platform = (info or {}).get("platform") or "cmsp"
    if platform != "smsp":
        return scope_uuids_for_platform(
            platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
            "", "")
    atlas = {"global_unique_uuid": "", "vlan_unique_uuid": ""}
    tmp = tempfile.mkdtemp(prefix="port_set_zk_")
    kubeconfig = ""
    try:
        kubeconfig, _err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            return scope_uuids_for_platform(
                platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
                "", "")
        ns, pod, _err = _find_pod("atlas", "atlas-0", "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, _err = _find_pod("atlas", "atlas-0", "", kubeconfig)
        if not pod:
            return scope_uuids_for_platform(
                platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
                "", "")
        py = "/home/nutanix/.venvs/bin/bin/python3"
        _rc, stdout, stderr = _kubectl(
            ["exec", "-n", ns, pod, "--", py, "-c", ATLAS_ZK_PY],
            60, kubeconfig=kubeconfig)
        text = "%s\n%s" % (stdout, stderr)
        for key in ("vlan_unique_uuid", "global_unique_uuid"):
            for line in text.splitlines():
                if key in line:
                    match = UUID_RE.search(line)
                    if match:
                        atlas[key] = match.group(0)
    finally:
        if kubeconfig:
            try:
                os.remove(kubeconfig)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
    return scope_uuids_for_platform(
        platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
        atlas.get("global_unique_uuid"), atlas.get("vlan_unique_uuid"))


def _flag_on(rule, key):
    return first(rule, key) in (True, "true", "True", "kTrue", 1)


def _field_present(node, key):
    return isinstance(node, dict) and key in node


def flex_extra_selectors(rule):
    """FLEX fields that are not src/dest/secured components.

    applied_to is one port set of every entity group on the rule.
    should_allow_any_* hashes as the empty FLEX VM list (Salus "[]").
    A missing applied_to field is that same empty list: the global
    port set.
    """
    applied = []
    has_applied_key = False
    for key in (
            "applied_to_entity_group_uuid_list",
            "applied_to_entity_group_uuid"):
        if _field_present(rule, key):
            has_applied_key = True
            applied.extend(as_uuid_list(values(rule, key)))
    if applied:
        yield ("applied_to", "EG", applied)
    elif not has_applied_key:
        yield ("applied_to", "VM", [])
    for flag, endpoint_key, role in (
            ("should_allow_any_src", "src_endpoint", "src_allow_any"),
            ("should_allow_any_dst", "dest_endpoint", "dest_allow_any")):
        if _flag_on(rule, flag) and not values(rule, endpoint_key):
            yield (role, "VM", [])
    has_side = any(
        values(rule, key) for key in (
            "src_endpoint", "dest_endpoint", "secured_group", "endpoint"))
    if not has_side and not applied and not has_applied_key and not any(
            _flag_on(rule, flag) for flag in (
                "should_allow_any_src", "should_allow_any_dst")):
        yield ("dest_allow_any", "VM", [])


def _remember(computed, idf_map, uid, **fields):
    uid = str(uid or "").strip().lower()
    if not UUID_RE.fullmatch(uid):
        return
    slot = computed.get(uid)
    if slot is None:
        fields["mismatch"] = "computed_without_idf"
        fields["port_set"] = uid
        fields["idf_name"] = (idf_map.get(uid) or {}).get("name") or ""
        fields["components"] = 1
        fields["present"] = uid in idf_map
        computed[uid] = fields
        return
    slot["components"] += 1


def _skip_idf_only(rec, policy_names=None):
    name = str((rec or {}).get("name") or "")
    nics = (rec or {}).get("nics") or []
    if name.startswith("K8s_"):
        return True
    if name.startswith("Quarantine") and not nics:
        return True
    # Atlas keeps a nic-less port set after the policy is deleted.
    if policy_names is not None and name and name not in policy_names and not nics:
        return True
    return False


def mismatch_rows(policies, vlan_uuid, global_uuid, idf_map, include_project=False,
                  eg_map=None):
    """One row per port_set UUID that is missing on either side."""
    idf_map = idf_map or {}
    eg_map = eg_map or {}
    computed = {}
    policy_names = set()
    for policy in policies or []:
        policy_names.add(str(first(policy, "name") or ""))
        annotated, _extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project, eg_map)
        if annotated.get("skipped_save"):
            continue
        for rule in annotated.get("rules") or []:
            for comp in rule.get("components") or []:
                if comp.get("kind") != "port_set":
                    continue
                entity_type = comp.get("entity_type") or "EG"
                refs = comp.get("refs") or []
                _remember(
                    computed, idf_map, comp.get("port_set"),
                    policy=annotated.get("name") or "",
                    policy_uuid=annotated.get("uuid") or "",
                    rule_uuid=rule.get("rule_uuid") or "",
                    role=comp.get("role") or "",
                    entity_type=entity_type,
                    scope=annotated.get("scope") or "",
                    refs=",".join(str(item) for item in refs))
        project = first(policy, "project_uuid") or ZERO
        vpc_uuids = policy_vpc_uuids(policy)
        scope_refs = policy_scope_refs(policy)
        for rkey, rule in iter_rules(policy):
            is_flex = (
                rule_is_flex(rule, annotated.get("policy_type"))
                or rkey == "flex_policy_rule")
            if not is_flex:
                continue
            info = first(rule, "rule_info") or {}
            if not isinstance(info, dict):
                info = {}
            rule_uuid = (
                first(info, "uuid") or first(rule, "uuid") or "")
            unique = scope_unique_uuid(
                annotated.get("scope") or "kAllVlan", True,
                vlan_uuid, global_uuid, vpc_uuids, scope_refs)
            for role, entity_type, refs in flex_extra_selectors(rule):
                if entity_type == "EG" and (
                        _address_egs(refs, eg_map) or _kube_egs(refs, eg_map)):
                    continue
                hashed, _body = generate_port_set_id(
                    entity_type, refs, unique, project, is_flex=True)
                _remember(
                    computed, idf_map, hashed,
                    policy=annotated.get("name") or "",
                    policy_uuid=annotated.get("uuid") or "",
                    rule_uuid=rule_uuid,
                    role=role,
                    entity_type=entity_type,
                    scope=annotated.get("scope") or "",
                    refs=",".join(str(item) for item in refs))
    rows = []
    matched = []
    for uid in sorted(computed):
        slot = computed[uid]
        if slot.pop("present"):
            matched.append({
                "port_set": uid,
                "policy": slot.get("policy") or "",
            })
            continue
        slot["nic_mismatch"] = "port_set_missing"
        rows.append(slot)
    for uid in sorted(idf_map):
        if uid in computed:
            continue
        rec = idf_map[uid]
        if _skip_idf_only(rec, policy_names):
            continue
        nics = [str(nic) for nic in (rec.get("nics") or []) if nic]
        rows.append({
            "mismatch": "idf_without_computed",
            "port_set": uid,
            "idf_name": rec.get("name") or "",
            "policy": "",
            "nic_mismatch": ",".join(nics),
        })
    return rows, matched


def usable_address(rec):
    """Generated address set. IPv4 when Atlas has one, otherwise IPv6.

    The all-zero UUID is not an address set. An IPv6-only port set is present.
    """
    for key in ("ipv4", "ipv6"):
        uid = str((rec or {}).get(key) or "").strip().lower()
        if UUID_RE.fullmatch(uid) and uid != ZERO:
            return uid
    return ""


def missing_address_sets(matched, address_map):
    """Port sets Atlas has, with no generated IPv4 or IPv6 address set."""
    rows = []
    for rec in matched or []:
        uid = str(rec.get("port_set") or "").lower()
        if usable_address((address_map or {}).get(uid)):
            continue
        rows.append({
            "mismatch": "address_set_missing",
            "port_set": uid,
            "policy": rec.get("policy") or "",
            "nic_mismatch": "address_set_missing",
        })
    return rows


def write_rows(rows, handle):
    writer = csv.DictWriter(
        handle, fieldnames=COLUMNS, delimiter="\t", lineterminator="\n",
        extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


def self_test():
    strict, _body = generate_port_set_id(
        "EG", ["15ae6907-1069-49b7-bbf0-0ae0f8d3d956"],
        GLOBAL_SCOPE_UNIQUE_ID, is_flex=True)
    if strict != "aaa68b7f-8f06-ad22-ea45-6fb0667e9c17":
        raise SystemExit("Salus strict hash %s" % strict)
    empty, _body = generate_port_set_id(
        "VM", [], GLOBAL_SCOPE_UNIQUE_ID, is_flex=True)
    if empty != "1a6c2142-bf53-3439-69ba-8500d05b2ab6":
        raise SystemExit("Salus global empty hash %s" % empty)
    global_uuid = "702970d3-d72d-41b9-9655-50c40ffd96f4"
    vlan_uuid = "29332a4d-9133-4c73-a219-ce82ea53d532"
    eg = "407982f9-5504-4504-a42d-78143d09f3fe"
    hashed, _body = generate_port_set_id(None, [eg], global_uuid)
    expect = "917386ac-6978-5da1-91a6-3782ffebd275"
    if hashed != expect:
        raise SystemExit("hash mismatch: %s != %s" % (hashed, expect))
    other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_hash, _body = generate_port_set_id(None, [other], global_uuid)
    policy = {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "name": "T",
        "mode": "kApply",
        "policy_type": "kApplication",
        "scope": "kGlobal",
        "project_uuid": ZERO,
        "rules_list": [
            {
                "application_rule": {
                    "direction": "kIn",
                    "rule_info": {
                        "uuid": "22222222-2222-2222-2222-222222222222",
                    },
                    "secured_group": {"entity_group_uuid_list": [eg]},
                }
            },
            {
                "application_rule": {
                    "direction": "kIn",
                    "rule_info": {
                        "uuid": "33333333-3333-3333-3333-333333333333",
                    },
                    "secured_group": {"entity_group_uuid_list": [other]},
                }
            },
        ],
    }
    lone = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    idf_map = index_idf_port_sets([
        {"uuid": other_hash, "name": "kept", "virtual_nic_uuid_list": ["n1"]},
        {"uuid": lone, "name": "Orphan", "virtual_nic_uuid_list": ["n2"]},
        {"uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "name": "K8s_skip"},
        {
            "uuid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "name": "QuarantineStrict",
            "virtual_nic_uuid_list": [],
        },
    ])
    rows, matched = mismatch_rows([policy], vlan_uuid, global_uuid, idf_map)
    kinds = {(row["mismatch"], row["port_set"]) for row in rows}
    if ("computed_without_idf", expect) not in kinds:
        raise SystemExit("missing computed mismatch: %s" % rows)
    if ("idf_without_computed", lone) not in kinds:
        raise SystemExit("missing idf mismatch: %s" % rows)
    expect_row = [row for row in rows if row["port_set"] == expect][0]
    if expect_row["policy"] != "T" or expect_row["nic_mismatch"] != "port_set_missing":
        raise SystemExit("computed row missing policy or nic: %s" % expect_row)
    lone_row = [row for row in rows if row["port_set"] == lone][0]
    if lone_row["nic_mismatch"] != "n2":
        raise SystemExit("idf nic mismatch missing: %s" % lone_row)
    if any(row["port_set"] == other_hash for row in rows):
        raise SystemExit("matched port_set was printed: %s" % rows)
    if any(row["idf_name"].startswith("K8s_") or
           row["idf_name"].startswith("Quarantine") for row in rows):
        raise SystemExit("skipped idf port_set was printed: %s" % rows)
    present = [rec for rec in matched if rec["port_set"] == other_hash]
    if not present:
        raise SystemExit("matched port set was not kept for the address set")
    gaps = missing_address_sets(present, {})
    if len(gaps) != 1 or gaps[0]["mismatch"] != "address_set_missing":
        raise SystemExit("address set gap: %s" % gaps)
    if gaps[0]["policy"] != "T":
        raise SystemExit("address set policy: %s" % gaps[0])
    if missing_address_sets(present, {other_hash: {"ipv4": "49d3b015-7bac-5a2a-8d9a-5c033243ba71"}}):
        raise SystemExit("present address set was reported")
    if missing_address_sets(present, {other_hash: {"ipv4": "", "ipv6": "49d3b015-7bac-5a2a-8d9a-5c033243ba71"}}):
        raise SystemExit("ipv6-only address set was reported missing")
    if not missing_address_sets(present, {other_hash: {"ipv4": ZERO, "ipv6": ""}}):
        raise SystemExit("zero address set was accepted")
    flex_unique = VLAN_SCOPE_UNIQUE_ID
    src_eg = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    applied_eg = eg
    src_hash, _body = generate_port_set_id(
        "EG", [src_eg], flex_unique, is_flex=True)
    applied_hash, _body = generate_port_set_id(
        "EG", [applied_eg], flex_unique, is_flex=True)
    any_hash, _body = generate_port_set_id(
        "VM", [], flex_unique, is_flex=True)
    global_src = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    global_hash, _body = generate_port_set_id(
        "EG", [global_src], flex_unique, is_flex=True)
    flex = {
        "uuid": "44444444-4444-4444-4444-444444444444",
        "name": "FlexT",
        "mode": "kApply",
        "policy_type": "kFlex",
        "scope": "kAllVlan",
        "project_uuid": ZERO,
        "rules_list": [{
            "flex_policy_rule": {
                "rule_info": {"uuid": "55555555-5555-5555-5555-555555555555"},
                "src_endpoint": {"entity_group_uuid_list": [src_eg]},
                "applied_to_entity_group_uuid_list": [applied_eg],
                "should_allow_any_dst": True,
            }
        }],
    }
    flex_global = {
        "uuid": "66666666-6666-6666-6666-666666666666",
        "name": "FlexGlobal",
        "mode": "kApply",
        "policy_type": "kFlex",
        "scope": "kAllVlan",
        "project_uuid": ZERO,
        "rules_list": [{
            "flex_policy_rule": {
                "rule_info": {"uuid": "77777777-7777-7777-7777-777777777777"},
                "src_endpoint": {"entity_group_uuid_list": [global_src]},
            }
        }],
    }
    flex_idf = dict(idf_map)
    flex_idf[src_hash] = {"uuid": src_hash, "name": "flex-src", "nics": ["n"]}
    flex_idf[global_hash] = {
        "uuid": global_hash, "name": "flex-global", "nics": ["n"]}
    flex_rows = mismatch_rows(
        [policy, flex, flex_global], vlan_uuid, global_uuid, flex_idf)[0]
    flex_kinds = {
        (row["mismatch"], row["port_set"], row.get("role") or "")
        for row in flex_rows}
    if ("computed_without_idf", applied_hash, "applied_to") not in flex_kinds:
        raise SystemExit("FLEX applied_to missing: %s" % flex_rows)
    if ("computed_without_idf", any_hash, "dest_allow_any") not in flex_kinds:
        raise SystemExit("FLEX allow-any missing: %s" % flex_rows)
    if any(row["port_set"] in (src_hash, global_hash) for row in flex_rows):
        raise SystemExit("matched FLEX port_set printed: %s" % flex_rows)
    if any(row["policy"] == "FlexGlobal" for row in flex_rows):
        raise SystemExit("FLEX Global applied_to was hashed: %s" % flex_rows)
    smsp_g, smsp_v = scope_uuids_for_platform(
        "smsp", "pc-g", "pc-v", "atlas-g", "atlas-v")
    if (smsp_g, smsp_v) != ("atlas-g", "atlas-v"):
        raise SystemExit("SMSP scope uuid %s %s" % (smsp_g, smsp_v))
    cmsp_g, cmsp_v = scope_uuids_for_platform(
        "cmsp", "pc-g", "pc-v", "atlas-g", "atlas-v")
    if (cmsp_g, cmsp_v) != ("pc-g", "pc-v"):
        raise SystemExit("CMSP scope uuid %s %s" % (cmsp_g, cmsp_v))
    if port_set_entities("auto") != ("atlas_port_set", "port_set"):
        raise SystemExit("auto port set entities")
    if port_set_entities("port_set") != ("port_set",):
        raise SystemExit("port_set option")
    if port_set_entities("atlas_port_set") != ("atlas_port_set",):
        raise SystemExit("atlas_port_set option")
    if policy_backend() != "flow_cli" or policy_backend(True, False) != "flow_cli":
        raise SystemExit("default backend")
    if policy_backend(False, True) != "idf_cli":
        raise SystemExit("idf_cli backend")
    try:
        port_set_entities("other")
    except SystemExit:
        pass
    else:
        raise SystemExit("bad port set entity was accepted")

    def _vi(num):
        out = bytearray()
        while True:
            byte = num & 0x7F
            num >>= 7
            if num:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    def _pb(field, wire, payload):
        return _vi((field << 3) | wire) + payload

    def _pb_str(field, text):
        raw = text.encode()
        return _pb(field, 2, _vi(len(raw)) + raw)

    def _pb_msg(field, body):
        return _pb(field, 2, _vi(len(body)) + body)

    def _pb_var(field, num):
        return _pb(field, 0, _vi(num))

    rule_uuid = "22222222-2222-2222-2222-222222222222"
    secured = _pb_str(4, eg)
    app = _pb_msg(1, _pb_str(1, rule_uuid)) + _pb_msg(2, secured)
    entry = _pb_str(1, rule_uuid) + _pb_msg(2, _pb_msg(1, app))
    blob = zlib.compress(
        _pb_str(1, "11111111-1111-1111-1111-111111111111")
        + _pb_str(2, "FromZ")
        + _pb_var(4, 2)
        + _pb_var(5, 1)
        + _pb_msg(6, entry)
        + _pb_var(14, 4))
    decoded = policy_from_idf_row({
        "uuid": "11111111-1111-1111-1111-111111111111",
        "name": "FromZ",
        "mode": 2,
        "policy_type": 1,
        "scope": 4,
        "project_uuid": ZERO,
        "__zprotobuf__": base64.b64encode(blob).decode("ascii"),
    })
    if decoded["scope"] != "kGlobal" or decoded["mode"] != "kApply":
        raise SystemExit("idf enum map %s" % decoded)
    zrows = mismatch_rows([decoded], vlan_uuid, global_uuid, {})[0]
    if not any(row["port_set"] == expect and row["policy"] == "FromZ" for row in zrows):
        raise SystemExit("zprotobuf policy hash: %s" % zrows)
    iso_cat = "03cf8007-4f92-36fb-ad6b-9f255b74b5b2"
    iso_hash, _body = generate_port_set_id("VM", [iso_cat], global_uuid)
    iso_rule = "99999999-9999-4999-8999-999999999999"
    group = _pb_str(1, iso_cat) + _pb_var(5, 1)
    multi = (
        _pb_msg(1, _pb_str(1, iso_rule))
        + _pb_msg(3, _pb_msg(1, group)))
    iso_entry = _pb_str(1, iso_rule) + _pb_msg(2, _pb_msg(5, multi))
    iso_blob = zlib.compress(_pb_msg(6, iso_entry) + _pb_var(14, 4))
    iso_pol = policy_from_idf_row({
        "uuid": "88888888-8888-4888-8888-888888888888",
        "name": "IsoZ",
        "mode": "2",
        "policy_type": 2,
        "scope": 4,
        "project_uuid": ZERO,
        "__zprotobuf__": iso_blob,
    })
    iso_rows = mismatch_rows([iso_pol], vlan_uuid, global_uuid, {})[0]
    if not any(row["port_set"] == iso_hash and row["policy"] == "IsoZ" for row in iso_rows):
        raise SystemExit("zprotobuf isolation hash: %s" % iso_rows)
    src_ep = _pb_str(5, src_eg)
    allow_ep = _pb_var(4, 1)
    flex_body = (
        _pb_msg(1, _pb_str(1, "55555555-5555-5555-5555-555555555555"))
        + _pb_msg(2, src_ep)
        + _pb_msg(3, allow_ep)
        + _pb_str(10, applied_eg))
    flex_entry = _pb_msg(2, _pb_msg(7, flex_body))
    flex_blob = zlib.compress(_pb_msg(6, flex_entry) + _pb_var(14, 1))
    flex_pol = policy_from_idf_row({
        "uuid": "44444444-4444-4444-4444-444444444444",
        "name": "FlexZ",
        "mode": 2,
        "policy_type": 1,
        "scope": 1,
        "project_uuid": ZERO,
        "__zprotobuf__": flex_blob,
    })
    flex_z = mismatch_rows([flex_pol], vlan_uuid, global_uuid, {})[0]
    flex_z_kinds = {(row["port_set"], row.get("role")) for row in flex_z}
    if (applied_hash, "applied_to") not in flex_z_kinds:
        raise SystemExit("zprotobuf applied_to: %s" % flex_z)
    if (any_hash, "dest_allow_any") not in flex_z_kinds:
        raise SystemExit("zprotobuf allow-any: %s" % flex_z)
    if flex_pol.get("rules_list", [{}])[0].get("flex_policy_rule", {}).get(
            "applied_to_entity_group_uuid_list") != [applied_eg]:
        raise SystemExit("applied_to field: %s" % flex_pol)
    save_pol = policy_from_idf_row({
        "uuid": "12121212-1212-4121-8121-121212121212",
        "name": "Saved",
        "mode": 0,
        "policy_type": 1,
        "scope": 1,
        "project_uuid": ZERO,
        "__zprotobuf__": flex_blob,
    })
    if save_pol["mode"] != "kSave":
        raise SystemExit("save mode %s" % save_pol["mode"])
    if mismatch_rows([save_pol], vlan_uuid, global_uuid, {})[0]:
        raise SystemExit("SAVE policy was hashed")
    iso_cat = "03cf8007-4f92-36fb-ad6b-9f255b74b5b2"
    iso_hash, _body = generate_port_set_id("VM", [iso_cat], global_uuid)
    vpc = "a3295f80-035b-4d55-b2f6-fd2b4eaaf7e8"
    scope_cat = "95c73585-bfc1-5a89-9d0d-8ede2ddf420c"
    se_eg = "3abb1c1c-c74a-45bb-9145-a41716278751"
    cat_hash, _body = generate_port_set_id(None, [se_eg], scope_cat)
    proj = "ff550402-f70a-44c3-bd2a-e29d3fe864a0"
    qcat = "4c313d99-ad50-5480-ae34-6c29ee35ed92"
    q_hash, _body = generate_port_set_id("VM", [qcat], global_uuid, proj)
    kube_eg = "57a0e031-bb94-450a-9094-f8c1d21c2256"
    extra_idf = dict(idf_map)
    extra_idf[iso_hash] = {"uuid": iso_hash, "name": "iso", "nics": ["n"]}
    extra_idf[cat_hash] = {"uuid": cat_hash, "name": "vpc-cat", "nics": ["n"]}
    extra_idf[q_hash] = {"uuid": q_hash, "name": "q", "nics": ["n"]}
    scope_policies = [
        {
            "uuid": "88888888-8888-4888-8888-888888888888",
            "name": "Iso",
            "mode": "kApply",
            "policy_type": "kIsolation",
            "scope": "kGlobal",
            "project_uuid": ZERO,
            "rules_list": [{
                "multi_env_isolation_rule": {
                    "rule_info": {"uuid": "99999999-9999-4999-8999-999999999999"},
                    "all_to_all_isolation_group": {"isolation_group_list": [{
                        "category_uuid_list": [iso_cat],
                        "category_selection_type": "kVM",
                    }]},
                }
            }],
        },
        {
            "name": "VpcCat",
            "uuid": "12121212-1212-4121-8121-121212121212",
            "mode": "kApply",
            "policy_type": "kApplication",
            "scope": "kVpcAsCategory",
            "project_uuid": ZERO,
            "reference_uuid_list": [scope_cat],
            "rules_list": [{
                "application_rule": {
                    "rule_info": {"uuid": "13131313-1313-4131-8131-131313131313"},
                    "secured_group": {"entity_group_uuid_list": [se_eg]},
                }
            }],
        },
        {
            "name": "Kube",
            "uuid": "14141414-1414-4141-8141-141414141414",
            "mode": "kApply",
            "policy_type": "kApplication",
            "scope": "kVpcList",
            "project_uuid": ZERO,
            "vpc_uuid": vpc,
            "rules_list": [{
                "application_rule": {
                    "rule_info": {"uuid": "15151515-1515-4151-8151-151515151515"},
                    "secured_group": {"entity_group_uuid_list": [kube_eg]},
                }
            }],
        },
        {
            "name": "Quarantine Strict Policy",
            "uuid": "16161616-1616-4161-8161-161616161616",
            "mode": "kApply",
            "policy_type": "kQuarantine",
            "scope": "kGlobal",
            "project_uuid": proj,
            "rules_list": [{
                "quarantine_rule": {
                    "rule_info": {"uuid": "17171717-1717-4171-8171-171717171717"},
                    "secured_group": {
                        "category_uuid_list": [qcat],
                        "category_selection_type": "kVM",
                    },
                }
            }],
        },
    ]
    extra_rows, extra_matched = mismatch_rows(
        scope_policies, vlan_uuid, global_uuid, extra_idf,
        eg_map={kube_eg: {"kube": True}})
    missed = {row["port_set"] for row in extra_rows}
    if iso_hash in missed or cat_hash in missed or q_hash in missed:
        raise SystemExit("scope hash missed atlas: %s" % extra_rows)
    if any(row.get("policy") == "Kube" for row in extra_rows):
        raise SystemExit("kube entity group was hashed: %s" % extra_rows)
    matched_ids = {rec["port_set"] for rec in extra_matched}
    if not {iso_hash, cat_hash, q_hash} <= matched_ids:
        raise SystemExit("scope hashes not matched: %s" % extra_matched)
    nested = annotate_component({
        "_key": "endpoint",
        "endpoint_entity": {
            "category_uuid_list": ["86b8e382-5b20-4b95-79a7-0cb3072712f2"],
            "category_selection_type": "kVM",
        },
    }, "7cbdab1d-88d6-490f-b1c0-503d975b507b", ZERO, False, False)
    if nested["port_set"] != "0bca504c-9c74-5d73-b0da-442e4f207e29":
        raise SystemExit("nested endpoint %s" % nested)
    gone = "abababab-abab-4aba-8aba-abababababab"
    still = "acacacac-acac-4aca-8aca-acacacacacac"
    orphan_idf = dict(idf_map)
    orphan_idf[gone] = {"uuid": gone, "name": "DeletedPolicy", "nics": []}
    orphan_idf[still] = {"uuid": still, "name": "T", "nics": []}
    orphan_rows, _orphan_matched = mismatch_rows(
        [policy], vlan_uuid, global_uuid, orphan_idf)
    orphan_ids = {row["port_set"] for row in orphan_rows}
    if gone in orphan_ids:
        raise SystemExit("deleted empty port set was reported")
    if still not in orphan_ids:
        raise SystemExit("live empty port set was skipped")
    addr, kube = _eg_flags_from_row(
        {"allowed_entity_select_type_enums": [3, 4, 6]})
    if kube is not True or addr:
        raise SystemExit("kube entity group enums %s %s" % (addr, kube))
    addr, kube = _eg_flags_from_row(
        {"allowed_entity_select_type_enums": [8]})
    if addr is not True or kube:
        raise SystemExit("address entity group enum %s %s" % (addr, kube))
    scope_id = "95c73585-bfc1-5a89-9d0d-8ede2ddf420c"
    vpc_id = "a3295f80-035b-4d55-b2f6-fd2b4eaaf7e8"
    vpc_cat = policy_from_idf_row({
        "uuid": "23232323-2323-4232-8232-232323232323",
        "name": "VpcCatZ",
        "mode": 2,
        "policy_type": 1,
        "scope": 5,
        "project_uuid": ZERO,
        "reference_uuid_list": [scope_id],
        "vpc_uuid": vpc_id,
    })
    if policy_scope_refs(vpc_cat) != [scope_id]:
        raise SystemExit("vpc-as-category scope ref %s" % vpc_cat)
    if scope_id in policy_vpc_uuids(vpc_cat):
        raise SystemExit("scope ref stored as vpc %s" % policy_vpc_uuids(vpc_cat))
    if vpc_id not in policy_vpc_uuids(vpc_cat):
        raise SystemExit("vpc uuid dropped %s" % vpc_cat)
    text = "".join(_render(rows))
    if "policy.json" in text or text.count("\n") != 1 + len(rows):
        raise SystemExit("unexpected output: %s" % text)
    print("self-test ok mismatches=%s" % len(rows))


def _render(rows):
    import io
    buf = io.StringIO()
    write_rows(rows, buf)
    return buf.getvalue().splitlines(True)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Validate policy port_set hashes against idfcli port_set. "
            "Prints mismatch rows only. Writes no JSON."))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument(
        "--include-project", action="store_true",
        help="Accepted for older command lines. A non-default project is always part of the hash.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--cli",
        default="flow_cli",
        choices=("flow_cli", "idf_cli"),
        help="Policy source (default: %(default)s). idf_cli does not need Flow.")
    parser.add_argument(
        "--flow-cli", "--flow_cli",
        action="store_const", const="flow_cli", dest="cli",
        help="Same as --cli flow_cli. This is the default.")
    parser.add_argument(
        "--idf-cli", "--idf_cli",
        action="store_const", const="idf_cli", dest="cli",
        help="Same as --cli idf_cli. Use this when Flow is down.")
    parser.add_argument(
        "--port-set-entity",
        default="auto",
        choices=("auto", "atlas_port_set", "port_set"),
        help=(
            "IDF table for actual port sets. auto tries atlas_port_set "
            "(idfcli get entity --all), then port_set (idfcli get entitytype)."))
    return parser.parse_args()


AS_MAP_PY = r"""
import json, sys, uuid
try:
  import gflags
  gflags.FLAGS(sys.argv[:1], known_only=True)
except Exception:
  pass
from util.sl_bufs.net.rpc_pb2 import RpcRequestContext
from atlas.atlas_interface_pb2 import PortSetAddressSetMapGetArg
from atlas.client.client import AtlasClient
from util.misc.protobuf import pb2json, reformat_proto
uuids = json.loads('''__UUIDS__''')
ctx = RpcRequestContext()
ctx.should_authorize = False
client = AtlasClient()
out = {}
step = 400
for start in range(0, len(uuids), step):
  arg = PortSetAddressSetMapGetArg()
  for uid in uuids[start:start + step]:
    arg.port_set_uuid_list.append(uuid.UUID(str(uid)).bytes)
  ret = client.PortSetAddressSetMapGet(arg, request_context=ctx)
  payload = pb2json(reformat_proto(ret), b64_bytes=False, convert_enum_to_str=True)
  for row in payload.get("port_set_address_set_map_list") or []:
    out[str(row.get("uuid") or "").lower()] = {
      "ipv4": str(row.get("generated_ipv4_address_set_uuid") or "").lower(),
      "ipv6": str(row.get("generated_ipv6_address_set_uuid") or "").lower(),
    }
sys.stdout.write(json.dumps(out, separators=(",", ":")))
"""


def _atlas_python():
    return _which(
        "/home/nutanix/.venvs/bin/bin/python3",
        "/home/nutanix/.venvs/flow/bin/python3",
        "")


def _run_atlas_pod(info, script, timeout):
    """Run AtlasClient inside the flow-cluster atlas pod. SMSP Atlas is not on the PC."""
    tmp = tempfile.mkdtemp(prefix="port_set_as_")
    kubeconfig = ""
    try:
        kubeconfig, err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            raise SystemExit(err or "mspctl kubeconfig failed")
        ns, pod, err = _find_pod("atlas", "atlas-0", "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, err = _find_pod("atlas", "atlas-0", "", kubeconfig)
        if not pod:
            raise SystemExit(err or "atlas pod not found")
        py = _pod_bin(
            kubeconfig, ns, pod,
            "ls /home/nutanix/.venvs/bin/bin/python3 "
            "/home/nutanix/.venvs/flow/bin/python3 2>/dev/null | head -1")
        if not py:
            raise SystemExit("no python3 in atlas pod")
        return _kubectl(
            ["exec", "-i", "-n", ns, pod, "--", py, "-"],
            timeout, kubeconfig=kubeconfig, input_text=script)
    finally:
        if kubeconfig:
            try:
                os.remove(kubeconfig)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def fetch_port_set_address_sets(info, uuids, timeout):
    """Generated IPv4/IPv6 address set for each port set.

    CMSP calls AtlasClient on the PC. SMSP runs the same call in the flow
    cluster atlas pod.
    """
    uuids = [str(uid).lower() for uid in (uuids or []) if uid]
    if not uuids:
        return {}
    timeout = max(60, min(300, int(timeout or 180)))
    script = AS_MAP_PY.replace("__UUIDS__", json.dumps(uuids))
    if (info or {}).get("platform") == "smsp":
        rc, out, err = _run_atlas_pod(info, script, timeout)
    else:
        py = _atlas_python()
        if not py:
            raise SystemExit("python3 for Atlas is missing")
        rc, out, err = _run([py, "-"], timeout, input_text=script)
    if rc != 0:
        raise SystemExit((err or out or "PortSetAddressSetMapGet failed")[:400])
    payload = _json_loads(out)
    if not isinstance(payload, dict):
        raise SystemExit("PortSetAddressSetMapGet returned no JSON object")
    return payload


def main():
    args = parse_args()
    setup_logging()
    if args.self_test:
        self_test()
        return 0
    info = detect_platform()
    global_uuid, vlan_uuid = fetch_unique_uuids(info)
    if not global_uuid or not vlan_uuid:
        raise SystemExit(
            "missing vlan/global unique uuid (zkcat / atlas ZK)")
    backend = args.cli or "flow_cli"
    LOG.info("policy source=%s", backend)
    policies = fetch_policies(
        info, workers=args.workers, timeout=args.timeout, backend=backend)
    if not policies:
        raise SystemExit("no policies from %s" % backend)
    idf_map = fetch_idf_port_sets(
        info, timeout=min(int(args.timeout), 600), entity=args.port_set_entity)
    eg_map = fetch_entity_groups(
        info, policies, workers=args.workers,
        timeout=min(int(args.timeout), 300))
    rows, matched = mismatch_rows(
        policies, vlan_uuid, global_uuid, idf_map,
        include_project=args.include_project, eg_map=eg_map)
    address_map = fetch_port_set_address_sets(
        info, [rec["port_set"] for rec in matched],
        min(int(args.timeout), 300))
    rows.extend(missing_address_sets(matched, address_map))
    LOG.info(
        "policies=%s idf_port_sets=%s mismatches=%s address_sets=%s",
        len(policies), len(idf_map), len(rows), len(address_map))
    if not rows:
        return 0
    write_rows(rows, sys.stdout)
    return 1


if __name__ == "__main__":
    sys.exit(main())
