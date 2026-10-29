#!/usr/bin/env python3
"""Policy port sets, their incoming and outgoing peers, then OVN-NB validation.

Reads Flow policies and hashes every port set in this file.
Records who may send in and who may be sent to.
Standalone. Stdlib only. No other policy script is imported.
Each row carries the ACL priority. The last lines are the OVN-NB check:
the port group, the peer port group, and the ACL must exist in Northbound.

Runs on any Prism Central VM. A follower copies this script to the leader
over the cluster SSH key and prints the leader's output. No password is
stored.

  python3 verify_policy_ovn.py
  python3 verify_policy_ovn.py --self-test
  panacea_cli verify_policy_ovn.py

Stdout is one JSON object per port set that fails. Each object is:

  {"policy","port_set","ovn","incoming":[...],"outgoing":[...]}

incoming and outgoing each name the peer port set once. service_group is the
list of service groups on that peer. service is the matching list of port
lists, one list per service group. ovn=present means that peer, priority,
and every service are in OVN-NB. A port set or peer that Atlas does not
report is ignored. Kubernetes names are ignored.

  ovn=missing          this port group is not in OVN-NB
  ovn=peer_missing     the peer port group is not in OVN-NB
  ovn=sg_missing       Flow did not return this service group
  ovn=acl_missing      no ACL for that peer and direction
  ovn=service_missing  the ACL does not cover the service ports

direction is incoming or outgoing. A service list is tcp/80, udp/53, icmp/8,
or ALL when the rule has no service. priority is the OVN ACL priority when
every service on that peer is covered, otherwise the policy rule priority.
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import uuid as uuid_lib

try:
    import panacea_cli_usage_tracker  # noqa: F401
except ImportError:
    pass

ZERO = "00000000-0000-0000-0000-000000000000"

DEFAULT_PROJECT = ZERO

SALUS_SERVICE_NAME = "salus"

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

LOG = logging.getLogger("verify_policy_ovn")

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

def scope_unique_uuid(scope, is_flex, vlan_uuid, global_uuid, vpc_uuids):
    if scope in GLOBAL_SCOPES:
        return GLOBAL_SCOPE_UNIQUE_ID if is_flex else global_uuid
    if scope in VLAN_SCOPES:
        return VLAN_SCOPE_UNIQUE_ID if is_flex else vlan_uuid
    if scope in VPC_CAT_SCOPES or scope in VPC_LIST_SCOPES:
        return vpc_uuids[0] if vpc_uuids else ""
    return vlan_uuid if not is_flex else VLAN_SCOPE_UNIQUE_ID

def policy_vpc_uuids(policy):
    out = []
    for key in ("vpc_uuid_list", "vpc_uuids", "target_vpc_uuid",
                "vpc_reference", "scope_vpc_uuid", "vpc_references",
                "scope_references"):
        for item in values(policy, key):
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
    return out

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
        row.pop("__zprotobuf__", None)
        return row
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        if not name or name == "__zprotobuf__":
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
                    walk_components(item, sink, child_key)

def rule_is_flex(rule, policy_type):
    if (rule.get("_key") or "") == "flex_policy_rule":
        return True
    return str(policy_type or "") in ("kFlex", "FLEX")

def annotate_component(comp, unique_uuid, project_uuid, is_flex, include_project):
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
    if skip or not refs or not unique_uuid:
        return row
    project = project_uuid if include_project else None
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

def annotate_policy(policy, vlan_uuid, global_uuid, include_project):
    name = first(policy, "name")
    policy_uuid = first(policy, "uuid")
    scope = first(policy, "scope") or "kAllVlan"
    mode = first(policy, "mode")
    policy_type = first(policy, "policy_type")
    project = first(policy, "project_uuid") or ZERO
    vpc_uuids = policy_vpc_uuids(policy)
    rules_out = []
    save_mode = str(mode) in ("kSave", "SAVE")
    if not save_mode:
        for rkey, rule in iter_rules(policy):
            is_flex = rule_is_flex(rule, policy_type) or rkey == "flex_policy_rule"
            unique = scope_unique_uuid(
                scope, is_flex, vlan_uuid, global_uuid, vpc_uuids)
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
                    comp, unique, project, is_flex, include_project))
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

def _kubectl_prefix(kubeconfig=""):
    kubectl = _kubectl_bin()
    for prefix in (["sudo", "-n", kubectl], ["sudo", kubectl], [kubectl]):
        rc, _out, _err = _run(prefix + ["get", "ns"], 20)
        if rc == 0:
            break
    else:
        prefix = ["sudo", "-n", kubectl]
    if kubeconfig:
        prefix = list(prefix) + ["--kubeconfig", kubeconfig]
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

IDF_ENTITIES = ("atlas_port_set", "port_set")

IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
    "idfcli",
)

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

def parse_idf_stdout(text):
    payload = _json_loads(text)
    if payload is None:
        return []
    return index_idf_port_sets(parse_idf_entities(payload))

def _run_idf_argv(argv, timeout):
    _rc, out, err = _run(argv, timeout)
    found = parse_idf_stdout(out)
    if found:
        return found, ""
    detail = (err or out or "empty").strip().replace("\n", " ")[:300]
    return {}, detail

def fetch_idf_port_sets(info, timeout=300):
    """Load port_set from idfcli. Stdout stays in memory.

    SMSP Atlas port sets are in the flow-cluster IDF, so that idfcli
    runs first. CMSP uses the local idfcli.
    """
    errors = []
    if (info or {}).get("platform") == "smsp":
        found, detail = _fetch_idf_port_sets_smsp(info, timeout)
        if found:
            return found
        if detail:
            errors.append(detail)
    binary = idfcli_bin()
    for entity in IDF_ENTITIES:
        argv = [binary, "get", "entity", "-e", entity, "--all", "-o", "json"]
        found, detail = _run_idf_argv(argv, timeout)
        if found:
            LOG.info("idfcli %s count=%s", entity, len(found))
            return found
        errors.append("%s: %s" % (" ".join(argv), detail))
    raise SystemExit(
        "idfcli port_set returned no entities\n" + "\n".join(errors))

def _fetch_idf_port_sets_smsp(info, timeout):
    """SMSP Atlas port sets live in the flow cluster IDF."""
    tmp = tempfile.mkdtemp(prefix="port_set_kube_")
    kubeconfig = ""
    try:
        kubeconfig, kube_err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            return {}, "smsp kubeconfig: %s" % (kube_err or "failed")
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
            return {}, "smsp idf pod: %s" % (err or "missing")
        last = "empty"
        for entity in IDF_ENTITIES:
            inner = (
                "idfcli get entity -e %s --all -o json "
                "|| /usr/local/nutanix/bin/idfcli get entity -e %s --all -o json "
                "|| /home/nutanix/bin/idfcli get entity -e %s --all -o json"
                % (entity, entity, entity))
            _rc, out, err = _kubectl(
                ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
                timeout, kubeconfig=kubeconfig)
            found = parse_idf_stdout(out)
            if found:
                LOG.info(
                    "idfcli %s via %s/%s count=%s", entity, ns, pod, len(found))
                return found, ""
            last = (err or out or "empty").strip().replace("\n", " ")[:300]
        return {}, "smsp idfcli %s/%s: %s" % (ns, pod, last)
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

def _policy_runner(info):
    """Return (runner, cleanup) for flow_cli policy.list/get. No JSON files."""
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

def fetch_policies(info, workers=8, timeout=1800):
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

    applied_to is its own port set. should_allow_any_* and a rule with no
    selector hash as the empty FLEX VM list (Salus "[]"). A missing
    applied_to field is UI Global and is not hashed.
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
        yield ("applied_to", "EG", [applied[0]])
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


PORT_COLUMNS = ("policy", "port_set", "direction", "peer_port_set", "ovn")
SG_COLUMNS = (
    "policy", "port_set", "direction", "peer_port_set",
    "service_group", "service", "priority", "ovn")
SG_PY = r"""
import json, sys
try:
  import gflags
  gflags.FLAGS(sys.argv[:1], known_only=True)
except Exception:
  pass
from util.sl_bufs.net.rpc_pb2 import RpcRequestContext
from flow.flow_interface_pb2 import ServiceGroupGetArg
from flow.client.client import FlowClient
from util.misc.protobuf import pb2json, reformat_proto
ctx = RpcRequestContext()
ctx.should_authorize = False
ret = FlowClient().ServiceGroupGet(ServiceGroupGetArg(), request_context=ctx)
payload = pb2json(reformat_proto(ret), b64_bytes=False, convert_enum_to_str=True)
if not isinstance(payload, dict) or not isinstance(payload.get("service_group_list"), list):
  sys.stderr.write("ServiceGroupGet missing service_group_list\n")
  sys.exit(2)
sys.stdout.write(json.dumps(payload, separators=(",", ":")))
"""
SELF_ROLES = frozenset(("secured_group", "applied_to"))
IN_ROLES = frozenset(("src_endpoint", "src_allow_any"))
OUT_ROLES = frozenset(("dest_endpoint", "dest_allow_any"))
ISO_ROLES = frozenset((
    "first_secured_group", "second_secured_group", "isolation_group"))
IN_DIRECTIONS = frozenset((
    "kIn", "kInbound", "IN", "INBOUND", "kIngress"))
OUT_DIRECTIONS = frozenset((
    "kOut", "kOutbound", "OUT", "OUTBOUND", "kEgress"))
K8S_NOISE_RE = re.compile(r"(k8s|kubernetes|cilium_vlan_scope)", re.I)
OWNER_IN = re.compile(r"outport == @port_group_([A-Za-z0-9_]+)")
OWNER_OUT = re.compile(r"inport == @port_group_([A-Za-z0-9_]+)")
PEER_SRC = re.compile(
    r"ip[46]\.src == (?:@port_group_|@address_set_|\$address_set_)"
    r"([A-Za-z0-9_]+)")
PEER_DST = re.compile(
    r"ip[46]\.dst == (?:@port_group_|@address_set_|\$address_set_)"
    r"([A-Za-z0-9_]+)")
IPV4_RE = re.compile(r"(?:[0-9]+\.){3}[0-9]+")
LEADER_YES_RE = re.compile(r"Currently leader(?:\s*\(Y/N\))?:\s*Yes")
PRISM_LEADER_PATHS = (
    "/appliance/logical/leaders/prism_monitor",
    "/appliance/logical/pyleaders/prism_monitor",
)


def pg_uuid(token):
    text = str(token or "").strip().strip('"').strip("@")
    for prefix in ("port_group_", "address_set_"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.replace("_", "-").lower()


def policy_priority(rule):
    info = rule.get("rule_info") if isinstance(rule, dict) else None
    if not isinstance(info, dict):
        info = {}
    for node in (info, rule if isinstance(rule, dict) else {}):
        for key in ("priority", "rule_priority"):
            if key not in node or node.get(key) in (None, ""):
                continue
            value = node.get(key)
            if isinstance(value, list):
                value = value[0] if value else ""
            return str(value).strip()
    return ""


def _split_components(comps, direction):
    selves, incoming, outgoing, isolated = [], [], [], []
    for comp in comps:
        if comp.get("kind") != "port_set" or not comp.get("port_set"):
            continue
        role = comp.get("role") or ""
        uid = str(comp.get("port_set")).lower()
        if role in ISO_ROLES:
            isolated.append(uid)
        elif role in SELF_ROLES:
            selves.append(uid)
        elif role in IN_ROLES or (role == "endpoint" and direction in IN_DIRECTIONS):
            incoming.append(uid)
        elif role in OUT_ROLES or (role == "endpoint" and direction in OUT_DIRECTIONS):
            outgoing.append(uid)
        elif role == "endpoint":
            incoming.append(uid)
    return selves, incoming, outgoing, isolated


def _add_edge(found, policy, port_set, direction, peer, priority, spec):
    key = (
        policy, port_set, direction, peer,
        spec.get("service_group") or "", spec.get("service") or "ALL")
    slot = {
        "policy_priority": priority,
        "ports": spec.get("ports") or [],
        "missing_sg": bool(spec.get("missing_sg")),
    }
    prev = found.get(key)
    if prev is None or _prio_num(priority) > _prio_num(prev["policy_priority"]):
        found[key] = slot


def _port_ranges(svc, *keys):
    out = []
    for key in keys:
        for item in svc.get(key) or []:
            if not isinstance(item, dict):
                continue
            start = int(item.get("start_port") or item.get("startPort") or 0)
            end = int(item.get("end_port") or item.get("endPort") or start)
            out.append((start, end))
    return out


def ports_from_service(svc):
    """(proto, start, end) tuples. Empty means every protocol and port."""
    proto = str(svc.get("protocol") or first(svc, "protocol") or "")
    if proto in ("kALL", "kAll", "ALL", "1"):
        return []
    ports = []
    tcp = _port_ranges(svc, "tcp_port_range_list", "tcpPortRangeList")
    udp = _port_ranges(svc, "udp_port_range_list", "udpPortRangeList")
    any_ranges = _port_ranges(svc, "port_range_list", "portRangeList")
    if proto in ("kTCP", "TCP", "3") or (not proto and tcp):
        for start, end in tcp or any_ranges:
            ports.append(("tcp", start, end))
    if proto in ("kUDP", "UDP", "4") or (not proto and udp):
        for start, end in udp or any_ranges:
            ports.append(("udp", start, end))
    if proto in ("kICMP", "ICMP", "2"):
        items = svc.get("icmp_type_code_list") or svc.get("icmpTypeCodeList") or []
        if not items:
            ports.append(("icmp", None, None))
        for item in items:
            if isinstance(item, dict):
                icmp_type = int(item.get("icmp_type") or item.get("type") or 0)
                ports.append(("icmp", icmp_type, icmp_type))
    if proto in ("kICMPv6", "kICMPV6", "ICMPv6", "ICMPV6", "5"):
        items = svc.get("icmp_v6_type_code_list") or []
        if not items:
            ports.append(("icmp6", None, None))
        for item in items:
            if isinstance(item, dict):
                icmp_type = int(item.get("icmp_type") or item.get("type") or 0)
                ports.append(("icmp6", icmp_type, icmp_type))
    if not proto and not ports:
        for start, end in any_ranges:
            ports.append(("tcp", start, end))
    return ports


def service_text(ports):
    if not ports:
        return "ALL"
    parts = []
    for proto, start, end in ports:
        if start is None:
            parts.append(proto)
        elif start == end:
            parts.append("%s/%s" % (proto, start))
        else:
            parts.append("%s/%s-%s" % (proto, start, end))
    return ",".join(parts)


def map_service_group(row):
    uid = str(row.get("uuid") or row.get("ext_id") or row.get("extId") or "").strip().lower()
    if not uid:
        return None
    ports = []
    for svc in row.get("service_list") or []:
        if isinstance(svc, dict):
            ports.extend(ports_from_service(svc))
    if not ports:
        for svc in row.get("tcp_services") or row.get("tcpServices") or []:
            if isinstance(svc, dict):
                ports.append(("tcp", int(svc.get("start_port") or 0), int(svc.get("end_port") or svc.get("start_port") or 0)))
        for svc in row.get("udp_services") or row.get("udpServices") or []:
            if isinstance(svc, dict):
                ports.append(("udp", int(svc.get("start_port") or 0), int(svc.get("end_port") or svc.get("start_port") or 0)))
    return {
        "uuid": uid,
        "name": row.get("name") or "",
        "ports": ports,
        "service": service_text(ports),
    }


def rule_services(rule, sg_map):
    """Service groups and inline services on one rule. ALL when none are set."""
    out = []
    seen = set()
    blobs = [item for item in values(rule, "services") if isinstance(item, dict)]
    for key in ("service_group_uuid_list", "service_group_uuid"):
        for uid in as_uuid_list(values(rule, key)):
            blobs.append({"service_group_uuid": uid})
    for svc in blobs:
        uid = str(first(svc, "service_group_uuid") or "").strip().lower()
        if uid:
            if uid in seen:
                continue
            seen.add(uid)
            rec = sg_map.get(uid)
            if rec is None:
                out.append({
                    "service_group": uid, "service": "", "ports": [],
                    "missing_sg": True})
            else:
                out.append({
                    "service_group": rec["name"] or uid,
                    "service": rec["service"],
                    "ports": rec["ports"],
                    "missing_sg": False,
                })
            continue
        ports = ports_from_service(svc)
        out.append({
            "service_group": "",
            "service": service_text(ports),
            "ports": ports,
            "missing_sg": False,
        })
    if not out:
        out.append({
            "service_group": "", "service": "ALL", "ports": [],
            "missing_sg": False})
    return out


def _prio_num(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return -1


def policy_edges(policies, vlan_uuid, global_uuid, include_project=False, sg_map=None):
    """One edge per policy port set and each incoming or outgoing peer."""
    found = {}
    for policy in policies or []:
        annotated, _extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project)
        if annotated.get("skipped_save"):
            continue
        name = annotated.get("name") or ""
        raw_rules = list(iter_rules(policy))
        project = first(policy, "project_uuid") or ZERO
        project_arg = project if include_project else None
        vpc_uuids = policy_vpc_uuids(policy)
        for (rkey, raw), arule in zip(raw_rules, annotated.get("rules") or []):
            comps = list(arule.get("components") or [])
            if arule.get("is_flex"):
                unique = scope_unique_uuid(
                    annotated.get("scope") or "kAllVlan", True,
                    vlan_uuid, global_uuid, vpc_uuids)
                for role, entity_type, refs in flex_extra_selectors(raw):
                    hashed, _body = generate_port_set_id(
                        entity_type, refs, unique, project_arg, is_flex=True)
                    comps.append({
                        "role": role, "kind": "port_set", "port_set": hashed})
            direction = str(first(raw, "direction") or "")
            priority = policy_priority(raw)
            services = rule_services(raw, sg_map or {})
            selves, incoming, outgoing, isolated = _split_components(
                comps, direction)

            def emit(owner, way, peer):
                for spec in services:
                    _add_edge(found, name, owner, way, peer, priority, spec)

            if isolated:
                for owner in isolated:
                    peers = [item for item in isolated if item != owner]
                    if not peers:
                        emit(owner, "", "")
                        continue
                    for peer in peers:
                        emit(owner, "incoming", peer)
                        emit(owner, "outgoing", peer)
                continue
            owners = selves or []
            if not owners and (incoming or outgoing):
                owners = [""]
            for owner in owners:
                if not owner:
                    continue
                if not incoming and not outgoing:
                    emit(owner, "", "")
                for peer in incoming:
                    if peer != owner:
                        emit(owner, "incoming", peer)
                for peer in outgoing:
                    if peer != owner:
                        emit(owner, "outgoing", peer)
    rows = []
    for key, slot in sorted(found.items()):
        policy, port_set, direction, peer, service_group, service = key
        rows.append({
            "policy": policy,
            "port_set": port_set,
            "direction": direction,
            "peer_port_set": peer,
            "service_group": service_group,
            "service": service,
            "policy_priority": slot["policy_priority"],
            "ports": slot["ports"],
            "missing_sg": slot["missing_sg"],
        })
    return rows


def parse_port_groups(text):
    groups = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        uid = pg_uuid(line.split(",")[0])
        if UUID_RE.fullmatch(uid):
            groups.add(uid)
    return groups


def parse_acl_index(text):
    """Map (port_set, direction, peer) to (priority, match) ACL rows."""
    index = {}
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 3:
            continue
        priority, match = row[0].strip(), ",".join(row[2:]).strip()
        if not match or match == "match":
            continue
        specs = (
            ("incoming", OWNER_IN, PEER_SRC),
            ("outgoing", OWNER_OUT, PEER_DST),
        )
        for direction, owner_re, peer_re in specs:
            owner_m = owner_re.search(match)
            if not owner_m:
                continue
            owner = pg_uuid(owner_m.group(1))
            peers = [pg_uuid(item) for item in peer_re.findall(match)]
            peers = [item for item in peers if UUID_RE.fullmatch(item)]
            if not peers:
                peers = [""]
            for peer in peers:
                index.setdefault((owner, direction, peer), []).append(
                    (str(priority).strip(), match))
    return index


def _numbers(text):
    return [int(item) for item in re.findall(r"\d+", text or "")]


_RANGE_CACHE = {}


def _parsed_ranges(match, proto):
    """Parse one ACL match once. Later service checks reuse the intervals."""
    key = (match or "", proto)
    cached = _RANGE_CACHE.get(key)
    if cached is not None:
        return cached
    low = key[0].lower()
    if proto in ("icmp", "icmp6"):
        if "icmp" not in low:
            cached = ("absent", ())
        else:
            types = tuple(
                int(item) for item in re.findall(r"icmp6?\.type == (\d+)", low))
            cached = ("icmp", types)
    elif proto not in low:
        cached = ("absent", ())
    elif "%s.dst" % proto not in low:
        cached = ("any", ())
    else:
        ranges = []
        for item in re.findall(r"%s\.dst == (\d+)" % proto, low):
            ranges.append((int(item), int(item)))
        for brace in re.findall(r"%s\.dst == \{([0-9, ]+)\}" % proto, low):
            for item in _numbers(brace):
                ranges.append((item, item))
        for lo, hi in re.findall(
                r"%s\.dst >= (\d+).*?%s\.dst <= (\d+)" % (proto, proto), low):
            ranges.append((int(lo), int(hi)))
        cached = ("ranges", tuple(ranges))
    _RANGE_CACHE[key] = cached
    return cached


def range_covered(match, proto, start, end):
    """True when this OVN match allows every port in the service range."""
    kind, ranges = _parsed_ranges(match, proto)
    if kind == "absent":
        return False
    if kind == "any":
        return True
    if kind == "icmp":
        if not ranges or start is None:
            return True
        stop = start if end is None else end
        return any(start <= item <= stop for item in ranges)
    if not ranges or start is None:
        return False
    stop = start if end is None else end
    if stop < start:
        return False
    cursor = start
    for lo, hi in sorted(ranges):
        if hi < cursor:
            continue
        if lo > cursor:
            return False
        if hi >= stop:
            return True
        cursor = hi + 1
    return False


def cover_priority(acls, ports):
    """Highest ACL priority that covers every service port. None if a port is open."""
    if not acls:
        return None
    if not ports:
        return max(acls, key=lambda item: _prio_num(item[0]))[0]
    used = []
    for spec in ports:
        hits = [item for item in acls if range_covered(item[1], *spec)]
        if not hits:
            return None
        used.append(max(hits, key=lambda item: _prio_num(item[0])))
    return max(used, key=lambda item: _prio_num(item[0]))[0]


def is_k8s_name(name):
    return bool(K8S_NOISE_RE.search(str(name or "")))


def atlas_port_name(atlas_ids, uid):
    if not uid or not isinstance(atlas_ids, dict):
        return ""
    rec = atlas_ids.get(uid) or {}
    if isinstance(rec, dict):
        return rec.get("name") or ""
    return ""


def skip_kubernetes(edge, atlas_ids):
    """Same Kubernetes ignore class as the port-set leftover check."""
    if is_k8s_name(edge.get("policy")):
        return True
    if is_k8s_name(atlas_port_name(atlas_ids, edge.get("port_set"))):
        return True
    return is_k8s_name(atlas_port_name(atlas_ids, edge.get("peer_port_set")))


def reported_by_atlas(edge, atlas_ids):
    """False when Atlas did not report this port set or its peer.

    atlas_ids None skips the filter. An empty peer is not a port set.
    """
    if atlas_ids is None:
        return True
    if edge["port_set"] not in atlas_ids:
        return False
    peer = edge.get("peer_port_set") or ""
    return not peer or peer in atlas_ids


def port_set_status(edge, groups):
    """Port-group presence only. Service groups are a later check."""
    if edge["port_set"] not in groups:
        return "missing"
    if edge.get("peer_port_set") and edge["peer_port_set"] not in groups:
        return "peer_missing"
    return "present"


def port_set_rows(edges, groups, atlas_ids=None):
    found = {}
    for edge in edges:
        if skip_kubernetes(edge, atlas_ids) or not reported_by_atlas(edge, atlas_ids):
            continue
        key = (
            edge["policy"], edge["port_set"], edge.get("direction") or "",
            edge.get("peer_port_set") or "")
        if key in found:
            continue
        found[key] = {
            "policy": edge["policy"],
            "port_set": edge["port_set"],
            "direction": edge.get("direction") or "",
            "peer_port_set": edge.get("peer_port_set") or "",
            "ovn": port_set_status(edge, groups),
        }
    return [found[key] for key in sorted(found)]


def acls_for(edge, by_owner):
    port_set = edge["port_set"]
    peer = edge.get("peer_port_set") or ""
    direction = edge.get("direction") or ""
    directions = (direction,) if direction else ("incoming", "outgoing")
    owner = by_owner.get(port_set) or {}
    found = []
    for way in directions:
        peers = owner.get(way) or {}
        if peer:
            found.extend(peers.get(peer) or [])
        else:
            for acls in peers.values():
                found.extend(acls)
    return found


def index_acls_by_owner(acl_index):
    by_owner = {}
    for (owner, direction, peer), acls in acl_index.items():
        by_owner.setdefault(owner, {}).setdefault(direction, {})[peer] = acls
    return by_owner


def service_rows(edges, groups, acl_index, atlas_ids=None):
    """Service groups only after Atlas and OVN-NB both have the port sets."""
    by_owner = index_acls_by_owner(acl_index)
    rows = []
    for edge in edges:
        if skip_kubernetes(edge, atlas_ids) or not reported_by_atlas(edge, atlas_ids):
            continue
        if port_set_status(edge, groups) != "present":
            continue
        service_group = edge.get("service_group") or ""
        service = edge.get("service") or "ALL"
        if not service_group and service == "ALL" and not edge.get("missing_sg"):
            continue
        priority = edge.get("policy_priority") or ""
        acls = acls_for(edge, by_owner)
        ports = edge.get("ports") or []
        if edge.get("missing_sg"):
            ovn = "sg_missing"
        elif not acls:
            ovn = "acl_missing"
        else:
            found = cover_priority(acls, ports)
            if found is None:
                ovn = "service_missing"
            else:
                ovn = "present"
                priority = found
        rows.append({
            "policy": edge["policy"],
            "port_set": edge["port_set"],
            "direction": edge.get("direction") or "",
            "peer_port_set": edge.get("peer_port_set") or "",
            "service_group": service_group,
            "service": service,
            "priority": priority,
            "ovn": ovn,
        })
    return rows


def _side_check(edge, groups, by_owner):
    """Peer port set, priority, and service group against one OVN-NB direction."""
    priority = edge.get("policy_priority") or ""
    status = port_set_status(edge, groups)
    service_group = edge.get("service_group") or ""
    service = edge.get("service") or "ALL"
    if status != "present":
        ovn = status
    elif edge.get("missing_sg"):
        ovn = "sg_missing"
    else:
        acls = acls_for(edge, by_owner)
        if not acls:
            ovn = "acl_missing"
        else:
            found = cover_priority(acls, edge.get("ports") or [])
            if found is None:
                ovn = "service_missing"
            else:
                ovn = "present"
                priority = found
    return {
        "port_set": edge.get("peer_port_set") or "",
        "priority": priority,
        "service_group": service_group,
        "service": service,
        "ovn": ovn,
    }


def _service_parts(text):
    return [part for part in str(text or "").split(",") if part]


def _collapse_direction(items):
    """One peer entry. service_group and service are lists for that peer."""
    worst = {
        "present": 0, "service_missing": 1, "acl_missing": 2,
        "sg_missing": 3, "peer_missing": 4, "missing": 5,
    }
    grouped = {}
    order = []
    for item in items:
        peer = item["port_set"]
        if peer not in grouped:
            grouped[peer] = []
            order.append(peer)
        grouped[peer].append(item)
    out = []
    for peer in order:
        parts = grouped[peer]
        ovn = max((part["ovn"] for part in parts), key=lambda item: worst.get(item, 9))
        if ovn == "present":
            priority = max((part["priority"] for part in parts), key=_prio_num)
        else:
            priority = parts[0]["priority"]
        groups = []
        services = []
        for part in parts:
            ports = _service_parts(part["service"]) or ["ALL"]
            name = part["service_group"]
            if name:
                groups.append(name)
                services.append(ports)
            elif not groups and ports == ["ALL"] and not services:
                services.append(ports)
            elif ports != ["ALL"]:
                services.append(ports)
        out.append({
            "port_set": peer,
            "priority": priority,
            "service_group": groups,
            "service": services,
            "ovn": ovn,
        })
    out.sort(key=lambda item: item["port_set"])
    return out


def port_set_nb(edges, groups, acl_index, atlas_ids=None):
    """One dict per port set: incoming peers and outgoing peers, checked in NB."""
    by_owner = index_acls_by_owner(acl_index)
    found = {}
    for edge in edges:
        if skip_kubernetes(edge, atlas_ids) or not reported_by_atlas(edge, atlas_ids):
            continue
        key = (edge["policy"], edge["port_set"])
        slot = found.get(key)
        if slot is None:
            slot = {
                "policy": edge["policy"],
                "port_set": edge["port_set"],
                "ovn": "missing" if edge["port_set"] not in groups else "present",
                "incoming": [],
                "outgoing": [],
            }
            found[key] = slot
        direction = edge.get("direction") or ""
        if direction not in ("incoming", "outgoing"):
            continue
        slot[direction].append(_side_check(edge, groups, by_owner))
    records = []
    for key in sorted(found):
        rec = found[key]
        for direction in ("incoming", "outgoing"):
            rec[direction] = _collapse_direction(rec[direction])
        records.append(rec)
    return records


def record_failed(rec):
    if rec.get("ovn") != "present":
        return True
    return any(
        item.get("ovn") != "present"
        for item in rec.get("incoming", []) + rec.get("outgoing", []))


def write_nb(records, handle):
    """Print failing port-set dicts. Return how many port sets failed."""
    failed = [rec for rec in records if record_failed(rec)]
    handle.write("OVN NB\n")
    for rec in failed:
        handle.write(json.dumps(rec, separators=(",", ":")) + "\n")
    handle.write(
        "OVN NB: port_sets=%s present=%s missing=%s\n" % (
            len(records), len(records) - len(failed), len(failed)))
    return len(failed)


def write_table(rows, handle, columns):
    writer = csv.DictWriter(
        handle, fieldnames=columns, delimiter="\t", lineterminator="\n",
        extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


def write_section(title, rows, columns, handle):
    missing = [row for row in rows if row.get("ovn") != "present"]
    present = len(rows) - len(missing)
    handle.write("%s\n" % title)
    if missing:
        write_table(missing, handle, columns)
    handle.write(
        "%s: checked=%s present=%s missing=%s\n" % (
            title, len(rows), present, len(missing)))
    return len(missing)


def _ovn_nb(info, args, timeout):
    base = ["--db=unix:/var/run/ovn/ovnnb_db.sock",
            "--format=csv", "--data=bare", "--no-heading"]
    if os.path.exists("/var/run/ovn/ovnnb_db.sock"):
        return _run(["ovn-nbctl"] + base + list(args), timeout)
    kubeconfig = ""
    if info.get("platform") == "smsp":
        dest = "/tmp/policy_ovn_kube"
        kubeconfig, err = _flow_kubeconfig(dest)
        if not kubeconfig:
            raise SystemExit(err or "mspctl kubeconfig failed")
    ns, pod, err = _find_pod("anc-ovn", "anc-ovn-0", kubeconfig=kubeconfig)
    if not pod:
        raise SystemExit(err or "anc-ovn pod not found")
    cmd = ["exec", "-n", ns, pod, "-c", "anc-ovn", "--", "ovn-nbctl"] + base + list(args)
    rc, out, err = _kubectl(cmd, timeout, kubeconfig=kubeconfig)
    if rc != 0:
        cmd = ["exec", "-n", ns, pod, "--", "ovn-nbctl"] + base + list(args)
        rc, out, err = _kubectl(cmd, timeout, kubeconfig=kubeconfig)
    if rc != 0:
        raise SystemExit((err or out or "ovn-nbctl failed")[:400])
    return rc, out, err


def _flow_python():
    return _which(
        "/home/nutanix/.venvs/flow/bin/python3",
        "/home/nutanix/.venvs/bin/bin/python3",
        "")


def fetch_service_groups(info, timeout):
    """ServiceGroupGet in memory. Nothing is written to disk."""
    timeout = max(60, min(300, int(timeout or 180)))
    if info.get("platform") == "smsp":
        kubeconfig, err = _flow_kubeconfig("/tmp/policy_ovn_kube")
        if not kubeconfig:
            raise SystemExit(err or "mspctl kubeconfig failed")
        ns, pod, err = _find_pod(
            "kratos", "kratos-0", namespace="ntnx-flow", kubeconfig=kubeconfig)
        if not pod:
            raise SystemExit(err or "kratos pod not found")
        py = _pod_bin(
            kubeconfig, ns, pod,
            "ls /home/nutanix/.venvs/flow/bin/python3 2>/dev/null || "
            "command -v python3")
        if not py:
            raise SystemExit("no python3 in kratos pod")
        rc, out, err = _kubectl(
            ["exec", "-i", "-n", ns, pod, "--", py, "-"],
            timeout, kubeconfig=kubeconfig, input_text=SG_PY)
    else:
        py = _flow_python()
        if not py:
            raise SystemExit("Flow venv python3 missing for ServiceGroupGet")
        rc, out, err = _run([py, "-"], timeout, input_text=SG_PY)
    if rc != 0:
        raise SystemExit((err or out or "ServiceGroupGet failed")[:400])
    payload = _json_loads(out)
    rows = payload.get("service_group_list") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise SystemExit("ServiceGroupGet missing service_group_list")
    mapped = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        rec = map_service_group(row)
        if rec:
            mapped[rec["uuid"]] = rec
    return mapped


def load_ovn(info, timeout):
    _rc, groups_text, _err = _ovn_nb(
        info, ["--columns=name", "list", "Port_Group"], timeout)
    _rc, acl_text, _err = _ovn_nb(
        info, ["--columns=priority,action,match", "list", "ACL"], timeout)
    return parse_port_groups(groups_text), parse_acl_index(acl_text)


def _local_ips():
    _rc, out, _err = _bash(
        "hostname -I 2>/dev/null; hostname -i 2>/dev/null; "
        "ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1")
    return [token for token in re.split(r"[\s,/]+", out or "") if IPV4_RE.fullmatch(token)]


def _leader_ip():
    zkcat = _zk_bin("zkcat")
    if not zkcat:
        return ""
    zkls = _zk_bin("zkls")
    for path in PRISM_LEADER_PATHS:
        children = []
        if zkls:
            _rc, stdout, _err = _run([zkls, path], 20)
            children = [line.strip() for line in (stdout or "").splitlines() if line.strip()]
        targets = ["%s/%s" % (path, child) for child in children] + [path]
        for target in targets:
            _rc, stdout, _err = _run([zkcat, target], 20)
            text = (stdout or "").replace("\x00", "")
            for line in text.splitlines():
                if LEADER_YES_RE.search(line):
                    match = IPV4_RE.search(line)
                    if match:
                        return match.group(0)
    return ""


def maybe_forward(argv):
    """On a follower PCVM, run this file on the Prism Central leader."""
    if os.environ.get("PC_LEADER_LOCAL") == "1":
        return
    leader = _leader_ip()
    if not leader or leader in _local_ips():
        return
    remote = "/tmp/policy_ovn_e2e"
    ssh_base = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
        "-o", "StrictHostKeyChecking=no", "nutanix@%s" % leader]
    LOG.info("PC follower: running on Prism Central leader %s", leader)
    rc, _out, err = _run(ssh_base + ["mkdir -p %s" % remote], 30)
    if rc != 0:
        raise SystemExit((err or "ssh to leader failed")[:400])
    for name in (os.path.abspath(__file__),):
        with open(name, "rb") as handle:
            body = handle.read()
        dest = "%s/%s" % (remote, os.path.basename(name))
        rc, _out, err = _run(
            ssh_base + ["cat > %s && chmod 755 %s" % (dest, dest)],
            30, input_text=body.decode("utf-8"))
        if rc != 0:
            raise SystemExit((err or "copy to leader failed")[:400])
    quoted = " ".join("'%s'" % arg.replace("'", "'\\''") for arg in argv)
    proc = subprocess.Popen(
        ssh_base + [
            "cd %s && env PC_LEADER_LOCAL=1 PYTHONUNBUFFERED=1 "
            "python3 -u verify_policy_ovn.py %s" % (remote, quoted)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
    finally:
        rc = proc.wait(timeout=1800)
    raise SystemExit(rc if rc >= 0 else 1)


def self_test():
    groups = {
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    acl_text = "\n".join([
        '100,allow-related,"outport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && ip4.src == @port_group_bbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb"',
        '50,drop,"inport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && ip4.dst == @port_group_bbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb"',
    ])
    index = parse_acl_index(acl_text)
    incoming = index.get((
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "incoming",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
    outgoing = index.get((
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "outgoing",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
    if not incoming or incoming[0][0] != "100":
        raise SystemExit("incoming priority missing: %s" % index)
    if not outgoing or outgoing[0][0] != "50":
        raise SystemExit("outgoing priority missing: %s" % index)
    tcp_acl = (
        '100,allow-related,"outport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa '
        '&& ip4.src == @port_group_bbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb && tcp.dst == 80"')
    tcp_index = parse_acl_index(tcp_acl)
    edges = [
        {"policy": "App", "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "direction": "incoming", "peer_port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
         "service_group": "", "service": "ALL", "ports": [],
         "policy_priority": "1"},
        {"policy": "App", "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "direction": "outgoing", "peer_port_set": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
         "service_group": "Web", "service": "tcp/80", "ports": [("tcp", 80, 80)],
         "policy_priority": "2"},
        {"policy": "Gone", "port_set": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
         "direction": "", "peer_port_set": "", "service_group": "",
         "service": "ALL", "ports": [], "policy_priority": "3"},
        {"policy": "App", "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "direction": "incoming", "peer_port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
         "service_group": "Web", "service": "tcp/80", "ports": [("tcp", 80, 80)],
         "policy_priority": "4"},
        {"policy": "App", "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "direction": "incoming", "peer_port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
         "service_group": "SSH", "service": "tcp/22", "ports": [("tcp", 22, 22)],
         "policy_priority": "5"},
        {"policy": "App", "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "direction": "incoming", "peer_port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
         "service_group": "99999999-9999-4999-8999-999999999999",
         "service": "", "ports": [], "missing_sg": True, "policy_priority": "6"},
    ]
    combined = list(edges[:3])
    for edge in edges[3:]:
        combined.append(edge)
    # The tcp ACL applies only to the last three edges. Check those against
    # tcp_index and the first three against the allow-all index by splitting.
    port_rows = port_set_rows(combined, groups)
    port_by = {}
    for row in port_rows:
        port_by.setdefault(row["ovn"], []).append(row)
    if set(port_by) != set(("present", "peer_missing", "missing")):
        raise SystemExit("port-set status: %s" % port_rows)
    svc_rows = service_rows(edges[:1], groups, index)
    svc_rows.extend(service_rows(edges[3:], groups, tcp_index))
    by_ovn = {}
    for row in svc_rows:
        by_ovn.setdefault(row["ovn"], []).append(row)
    web = [row for row in by_ovn.get("present", []) if row["service"] == "tcp/80"]
    if not web or web[0]["priority"] != "100" or web[0]["service_group"] != "Web":
        raise SystemExit("service present: %s" % svc_rows)
    if "service_missing" not in by_ovn or "sg_missing" not in by_ovn:
        raise SystemExit("service status: %s" % list(by_ovn))
    if any(row["peer_port_set"].startswith("cccccccc") for row in svc_rows):
        raise SystemExit("service check ran before the port set existed: %s" % svc_rows)
    atlas = set(groups) | {
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    }
    not_atlas = {
        "policy": "Quarantine Forensic Policy",
        "port_set": "f0157191-9663-5b78-8c48-386c3b0f1cb2",
        "direction": "", "peer_port_set": "", "service_group": "",
        "service": "ALL", "ports": [], "policy_priority": "",
    }
    peer_not_atlas = {
        "policy": "EG_Exclude_Policy1",
        "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "direction": "incoming",
        "peer_port_set": "bc53edec-4a09-5bda-adcc-b9cfc919bc93",
        "service_group": "", "service": "ALL", "ports": [],
        "policy_priority": "",
    }
    filtered = port_set_rows(combined + [not_atlas, peer_not_atlas], groups, atlas)
    if filtered != port_rows:
        raise SystemExit("atlas filter changed reported rows: %s" % filtered)
    if any(row["policy"].startswith("Quarantine") for row in filtered):
        raise SystemExit("quarantine port set was reported: %s" % filtered)
    k8s_edge = {
        "policy": "K8s_App_1_Cilium_VLAN_Scope",
        "port_set": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "direction": "outgoing",
        "peer_port_set": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "service_group": "nginx", "service": "tcp/80",
        "ports": [("tcp", 80, 80)], "policy_priority": "1",
    }
    k8s_rows = port_set_rows(combined + [k8s_edge], groups, atlas)
    if k8s_rows != port_rows or any(is_k8s_name(row["policy"]) for row in k8s_rows):
        raise SystemExit("kubernetes port set was reported: %s" % k8s_rows)
    k8s_svc = service_rows([k8s_edge], groups, tcp_index, atlas)
    if k8s_svc:
        raise SystemExit("kubernetes service group was reported: %s" % k8s_svc)
    nb = port_set_nb(edges[:3], groups, index)
    by_policy = {rec["policy"]: rec for rec in nb}
    app = by_policy["App"]
    if app["ovn"] != "present" or len(app["incoming"]) != 1 or len(app["outgoing"]) != 1:
        raise SystemExit("app dict: %s" % app)
    inc = app["incoming"][0]
    if inc["port_set"] != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" or inc["priority"] != "100" or inc["ovn"] != "present":
        raise SystemExit("incoming dict: %s" % inc)
    if inc["service_group"] != [] or inc["service"] != [["ALL"]]:
        raise SystemExit("incoming services: %s" % inc)
    out = app["outgoing"][0]
    if out["service_group"] != ["Web"] or out["service"] != [["tcp/80"]] or out["ovn"] != "peer_missing":
        raise SystemExit("outgoing dict: %s" % out)
    both = port_set_nb(edges[3:5], groups, tcp_index)
    both_in = both[0]["incoming"][0]
    if both_in["service_group"] != ["Web", "SSH"] or both_in["service"] != [["tcp/80"], ["tcp/22"]]:
        raise SystemExit("service lists: %s" % both_in)
    if by_policy["Gone"]["ovn"] != "missing":
        raise SystemExit("missing port set dict: %s" % by_policy["Gone"])
    hidden = port_set_nb(combined + [not_atlas, peer_not_atlas, k8s_edge], groups, index, atlas)
    if any(rec["policy"].startswith("Quarantine") or is_k8s_name(rec["policy"]) for rec in hidden):
        raise SystemExit("ignored port set was reported: %s" % hidden)
    if any(item["port_set"].startswith("bc53edec") for rec in hidden for item in rec["incoming"] + rec["outgoing"]):
        raise SystemExit("peer missing from atlas was reported: %s" % hidden)
    buf = io.StringIO()
    missing = write_nb(nb, buf)
    text = buf.getvalue()
    if not text.startswith("OVN NB\n{") or missing != 2:
        raise SystemExit("nb output missing=%s\n%s" % (missing, text))
    if not text.endswith("OVN NB: port_sets=2 present=0 missing=2\n"):
        raise SystemExit("nb summary: %s" % text)
    policy = {
        "uuid": "11111111-1111-4111-8111-111111111111",
        "name": "Iso",
        "mode": "kApply",
        "policy_type": "kIsolation",
        "scope": "kGlobal",
        "rules_list": [{
            "isolation_rule": {
                "priority": 25,
                "rule_info": {"uuid": "22222222-2222-4222-8222-222222222222"},
                "first_secured_group": {
                    "entity_group_uuid_list": ["407982f9-5504-4504-a42d-78143d09f3fe"]},
                "second_secured_group": {
                    "entity_group_uuid_list": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]},
                "services": [{
                    "service_group_uuid": "407982f9-5504-4504-a42d-78143d09f3fe"}],
            }
        }],
    }
    built = policy_edges(
        [policy], "29332a4d-9133-4c73-a219-ce82ea53d532",
        "702970d3-d72d-41b9-9655-50c40ffd96f4",
        sg_map={
            "407982f9-5504-4504-a42d-78143d09f3fe": {
                "uuid": "407982f9-5504-4504-a42d-78143d09f3fe",
                "name": "Web",
                "ports": [("tcp", 80, 80)],
                "service": "tcp/80",
            }})
    dirs = {(row["direction"], row["policy_priority"], row["service"]) for row in built}
    if ("incoming", "25", "tcp/80") not in dirs or ("outgoing", "25", "tcp/80") not in dirs:
        raise SystemExit("isolation edges: %s" % built)
    if any(row["service_group"] != "Web" for row in built):
        raise SystemExit("service group name: %s" % built)
    print("self-test ok edges=%s" % len(built))


def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description=(
            "List policy port-set incoming and outgoing peers, service groups, "
            "and priority, then validate them in OVN-NB."))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--include-project", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    setup_logging()
    if args.self_test:
        self_test()
        return 0
    maybe_forward(argv)
    info = detect_platform()
    global_uuid, vlan_uuid = fetch_unique_uuids(info)
    if not global_uuid or not vlan_uuid:
        raise SystemExit("missing vlan/global unique uuid (zkcat / atlas ZK)")
    policies = fetch_policies(info, workers=args.workers, timeout=args.timeout)
    if not policies:
        raise SystemExit("no policies from flow_cli")
    sg_map = fetch_service_groups(info, min(int(args.timeout), 300))
    edges = policy_edges(
        policies, vlan_uuid, global_uuid, include_project=args.include_project,
        sg_map=sg_map)
    atlas_map = fetch_idf_port_sets(info, min(int(args.timeout), 300))
    kept = [
        edge for edge in edges
        if reported_by_atlas(edge, atlas_map) and not skip_kubernetes(edge, atlas_map)]
    groups, acl_index = load_ovn(info, min(int(args.timeout), 600))
    LOG.info(
        "policies=%s service_groups=%s edges=%s atlas_port_sets=%s "
        "kept_edges=%s ovn_port_groups=%s ovn_acls=%s",
        len(policies), len(sg_map), len(edges), len(atlas_map), len(kept),
        len(groups), len(acl_index))
    records = port_set_nb(kept, groups, acl_index, atlas_map)
    missing = write_nb(records, sys.stdout)
    sys.stdout.flush()
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
