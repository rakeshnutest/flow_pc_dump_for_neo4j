#!/usr/bin/env python3
"""Policy port sets, their incoming and outgoing peers, then OVN-NB validation.

Reads Flow policies and hashes every port set in this file.
Records who may send in and who may be sent to.
Standalone. Stdlib only. No other policy script is imported.
Each row carries the OVN-NB ACL priority for that rule class.
An address-group peer is uuid5(address_group, "IPv4"|"IPv6").
A port-set peer is that port set's generated address set.
The last lines are the OVN-NB check, then the derived OVN-SB check.
Each Northbound ACL that northd should emit must have a Logical_Flow at
the ACL priority plus 1000, in ls_in_acl_eval or ls_out_acl_eval.

Runs on any Prism Central VM. A follower copies this script to the leader
over the cluster SSH key and prints the leader's output. No password is
stored.

  python3 verify_policy_ovn.py
  python3 verify_policy_ovn.py --skip-sb
  python3 verify_policy_ovn.py --src NIC --dst NIC --port 80 --proto tcp
  python3 verify_policy_ovn.py --self-test
  panacea_cli verify_policy_ovn.py

With no arguments the full port-set and ACL check runs, including
southbound. --skip-sb stops after the Northbound check. --src, --dst,
--port, and --proto select one flow and print its Northbound ACL, its
Southbound flow, the OpenFlow cookie, the host to check in OVS, and
allow or deny.

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
or ALL when the rule has no service. priority is the priority on the OVN-NB
ACL row. The ACL table is the check: every ACL is classified and verified.
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

def annotate_component(comp, unique_uuid, project_uuid, is_flex, include_project,
                        has_ipv6=False):
    """Port-set hash, or the address-set uuid5 when the peer is an address group."""
    entity_type, refs, skip = component_refs(comp)
    role = comp.get("_key") or ""
    row = {
        "role": role,
        "kind": "",
        "entity_type": entity_type,
        "refs": refs,
        "port_set": "",
        "port_set_uuid": "",
        "address_sets": [],
    }
    groups = as_uuid_list(values(comp, "address_group_uuid"))
    if groups or values(comp, "ip_subnet"):
        row["kind"] = "address_set"
        for uid in groups:
            row["address_sets"].extend(address_set_ids(uid, has_ipv6))
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
            has_ipv6 = _policy_has_ipv6(policy)
            for comp in comps:
                marker = (comp.get("_start"), comp.get("_end"), id(comp))
                if marker in seen:
                    continue
                seen.add(marker)
                component_rows.append(annotate_component(
                    comp, unique, project, is_flex, include_project, has_ipv6))
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

# Hermes adds this to the Flow priority when it programs the ACL.
# Flex security groups do not use it. hermes.consts.ACL_PRIORITY_OFFSET.
ACL_PRIORITY_OFFSET = 1000

# ovn-northd adds this to the NB ACL priority when it writes Logical_Flow.
# northd.c OVN_ACL_PRI_OFFSET. The stage is ls_in_acl_eval or ls_out_acl_eval.
SB_ACL_PRI_OFFSET = 1000
SB_STAGE = {
    "from-lport": "ls_in_acl_eval",
    "to-lport": "ls_out_acl_eval",
}
SB_VERDICT = {
    "allow": "reg8[16]",
    "allow-related": "reg8[16]",
    "allow-stateless": "reg8[16]",
    "drop": "reg8[17]",
    "reject": "reg8[18]",
}
# Flow BaseNetworkSecurityPolicyTranslator label. Bits 14-0 unique_id,
# bit 15 is 0 for outbound and 1 for inbound, bits 17-16 are the mode.
LABEL_LSB_MASK = 32767
LABEL_MODE = {"allow": 1, "monitor": 2, "deny": 3}


def flow_label(unique_id, direction, mode):
    """32-bit conntrack label Flow stores on the OVN-NB ACL."""
    uid = int(unique_id)
    value = uid & LABEL_LSB_MASK
    if str(direction) not in ("kOutbound", "outbound", "from-lport"):
        value |= 1 << 15
    value |= LABEL_MODE[mode] << 16
    if uid > LABEL_LSB_MASK:
        value |= (uid >> 15) << 28
    return value

# Flow policy_translator.consts after rearrange_priorities_for_enforce_monitor_policies.
# kApply uses APPLY. kMonitor uses MONITOR. OVN stores value + ACL_PRIORITY_OFFSET.
# Isolation L2 rows (eth.src / eth.dst) are the IP priority minus 1.
APPLY_PRIORITY = {
    "qs_intra_deny": 97,
    "qs_default_deny": 95,
    "qf_intra_deny": 92,
    "qf_allow": 90,
    "qf_default_deny": 80,
    "ss_intra_deny": 77,
    "ss_intra_allow": 75,
    "ss_intra_default_deny": 74,
    "ss_allow": 73,
    "ss_default_allow": 72,
    "ss_default_deny": 71,
    "isolation_drop": 65,
    "app_intra_deny": 60,
    "app_intra_allow": 55,
    "app_intra_default_deny": 52,
    "app_allow": 50,
    "app_default_allow": 47,
    "app_default_deny": 45,
    "isolation_allow_rest": 5,
}
MONITOR_PRIORITY = {
    "qf_intra_allow": 40,
    "qf_allow": 38,
    "qf_default_allow": 35,
    "ss_intra_deny": 33,
    "ss_intra_allow": 31,
    "ss_intra_default_deny": 30,
    "ss_allow": 29,
    "ss_default_allow": 27,
    "isolation_allow": 23,
    "app_intra_deny": 21,
    "app_intra_allow": 19,
    "app_intra_default_deny": 18,
    "app_allow": 17,
    "app_default_allow": 15,
}
# Hermes system ACLs. These are not Flow priority + offset.
SYSTEM_PRIORITY = {
    "dhcp": 31500,
    "ipfix_allow": 500,
    "nat_external_allow": 1000,
    "nat_external_drop": 100,
}
MONITOR_MODES = frozenset(("kMonitor", "MONITOR"))
SHARED_TYPES = frozenset(("kSharedServices", "kSharedService"))
QUARANTINE_TYPES = frozenset(("kQuarantine",))
ISOLATION_TYPES = frozenset(("kIsolation", "kMultiEnvIsolation"))
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


def address_set_ids(entity_uuid, has_ipv6=False):
    """uuid5(address_group, "IPv4"|"IPv6"). The OVN name is $address_set_<uuid>."""
    vid = uuid_lib.UUID(str(entity_uuid))
    rows = [str(uuid_lib.uuid5(vid, "IPv4"))]
    if has_ipv6:
        rows.append(str(uuid_lib.uuid5(vid, "IPv6")))
    return rows


def ovn_priority(role, mode="kApply"):
    """OVN-NB priority for one Flow rule class. -1 when that class has none."""
    table = MONITOR_PRIORITY if str(mode or "") in MONITOR_MODES else APPLY_PRIORITY
    value = table.get(role)
    if value is None:
        return -1
    return value + ACL_PRIORITY_OFFSET


def _role_by_priority():
    found = {}
    for role, value in APPLY_PRIORITY.items():
        found[value + ACL_PRIORITY_OFFSET] = role
    for role, value in MONITOR_PRIORITY.items():
        found.setdefault(value + ACL_PRIORITY_OFFSET, "monitor_%s" % role)
    found[APPLY_PRIORITY["isolation_drop"] + ACL_PRIORITY_OFFSET - 1] = "isolation_drop_l2"
    found[APPLY_PRIORITY["isolation_allow_rest"] + ACL_PRIORITY_OFFSET - 1] = (
        "isolation_allow_rest_l2")
    for role, value in SYSTEM_PRIORITY.items():
        found[value] = role
    return found


ROLE_BY_PRIORITY = _role_by_priority()


def _policy_has_ipv6(policy):
    opts = first(policy, "options") or {}
    if not isinstance(opts, dict):
        return False
    return bool(opts.get("ipv6_address_scope") or opts.get("allow_ipv6_traffic"))


def _rule_role(policy_type, rule_kind, action, categories, quar):
    """Flow class for this rule. The OVN number comes from ovn_priority."""
    ptype = str(policy_type or "")
    kind = str(rule_kind or "")
    cats = set(str(item).lower() for item in (categories or []))
    strict = str((quar or {}).get("strict") or "").lower()
    forensic = str((quar or {}).get("forensic") or "").lower()
    denied = action in (False, 0, "false", "False", "0")
    quarantine = ptype in QUARANTINE_TYPES or kind == "quarantine_rule"
    if quarantine and strict and strict in cats:
        if kind == "secured_group_rule":
            return "qs_intra_deny"
        return "qs_default_deny"
    if quarantine and forensic and forensic in cats:
        if kind == "secured_group_rule":
            return "qf_intra_deny"
        return "qf_allow"
    if quarantine:
        return ""
    if kind in ("isolation_rule", "multi_env_isolation_rule") or ptype in ISOLATION_TYPES:
        return "isolation_drop"
    if ptype in SHARED_TYPES or kind == "shared_service_rule":
        if kind == "secured_group_rule":
            return "ss_intra_deny" if denied else "ss_intra_allow"
        return "ss_allow"
    if kind == "secured_group_rule":
        return "app_intra_deny" if denied else "app_intra_allow"
    if kind in ("application_rule", "quarantine_rule", "flex_policy_rule"):
        return "app_allow"
    return ""


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


def _add_edge(found, policy, port_set, direction, peer, priority, spec, extra=None):
    extra = extra or {}
    key = (
        policy, port_set, direction, peer,
        spec.get("service_group") or "", spec.get("service") or "ALL",
        extra.get("peer_kind") or "", extra.get("role") or "")
    slot = {
        "policy_priority": priority,
        "ports": spec.get("ports") or [],
        "missing_sg": bool(spec.get("missing_sg")),
        "policy_name": extra.get("policy_name") or "",
        "peer_kind": extra.get("peer_kind") or "",
        "address_set": extra.get("address_set") or "",
        "role": extra.get("role") or "",
        "expected_priority": extra.get("expected_priority") or "",
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


def _address_peers(comps, direction):
    incoming, outgoing = [], []
    for comp in comps:
        if comp.get("kind") != "address_set":
            continue
        ids = [item for item in (comp.get("address_sets") or []) if item]
        if not ids:
            continue
        role = comp.get("role") or ""
        if role in IN_ROLES or (role == "endpoint" and direction in IN_DIRECTIONS):
            incoming.extend(ids)
        elif role in OUT_ROLES or (role == "endpoint" and direction in OUT_DIRECTIONS):
            outgoing.extend(ids)
        elif role == "endpoint":
            incoming.extend(ids)
    return incoming, outgoing


def _owner_categories(comps, owners):
    cats = []
    wanted = set(owners or [])
    for comp in comps:
        if comp.get("kind") != "port_set":
            continue
        if wanted and str(comp.get("port_set") or "").lower() not in wanted:
            continue
        cats.extend(str(item).lower() for item in (comp.get("refs") or []))
    return cats


def policy_edges(policies, vlan_uuid, global_uuid, include_project=False, sg_map=None,
                 quar=None):
    """One edge per policy port set and each incoming or outgoing peer.

    The policy field is the policy UUID. An address-group peer is the
    address-set UUID, not a port set. expected_priority is the OVN number
    for that rule class.
    """
    found = {}
    quar = quar or {}
    for policy in policies or []:
        annotated, _extra = annotate_policy(
            policy, vlan_uuid, global_uuid, include_project)
        if annotated.get("skipped_save"):
            continue
        policy_uuid = str(annotated.get("uuid") or "").lower()
        policy_name = annotated.get("name") or ""
        mode = annotated.get("mode") or ""
        policy_type = annotated.get("policy_type") or ""
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
                        "role": role, "kind": "port_set", "port_set": hashed,
                        "refs": refs})
            direction = str(first(raw, "direction") or "")
            priority = policy_priority(raw)
            services = rule_services(raw, sg_map or {})
            selves, incoming, outgoing, isolated = _split_components(
                comps, direction)
            addr_in, addr_out = _address_peers(comps, direction)
            owners_for_role = selves or isolated
            role = _rule_role(
                policy_type, arule.get("rule_kind") or rkey,
                first(raw, "action"),
                _owner_categories(comps, owners_for_role), quar)
            if arule.get("is_flex"):
                expected = priority if _prio_num(priority) >= 0 else ""
                role = role or "flex"
            else:
                expected = ovn_priority(role, mode)
                expected = "" if expected < 0 else str(expected)

            def emit(owner, way, peer, peer_kind, address_set, use_role):
                use_expected = expected if use_role == role else ""
                if use_role and use_role != role:
                    alt = ovn_priority(use_role, mode)
                    use_expected = "" if alt < 0 else str(alt)
                extra = {
                    "policy_name": policy_name,
                    "peer_kind": peer_kind,
                    "address_set": address_set,
                    "role": use_role,
                    "expected_priority": use_expected,
                }
                specs = services if peer_kind == "port_set" or peer_kind == "address_set" else [{
                    "service_group": "", "service": "ALL", "ports": [],
                    "missing_sg": False,
                }]
                for spec in specs:
                    _add_edge(
                        found, policy_uuid, owner, way, peer, priority, spec, extra)

            if isolated:
                for owner in isolated:
                    peers = [item for item in isolated if item != owner]
                    if not peers:
                        emit(owner, "", "", "port_set", "", role)
                        continue
                    for peer in peers:
                        emit(owner, "incoming", peer, "port_set", "", role)
                        emit(owner, "outgoing", peer, "port_set", "", role)
                    allow = "isolation_allow" if str(mode) in MONITOR_MODES else "isolation_allow_rest"
                    emit(owner, "incoming", "", "default_deny", "", allow)
                    emit(owner, "outgoing", "", "default_deny", "", allow)
                continue
            owners = selves or []
            for owner in owners:
                if not owner:
                    continue
                for peer in incoming:
                    if peer != owner:
                        emit(owner, "incoming", peer, "port_set", "", role)
                for peer in outgoing:
                    if peer != owner:
                        emit(owner, "outgoing", peer, "port_set", "", role)
                for peer in addr_in:
                    emit(owner, "incoming", peer, "address_set", peer, role)
                for peer in addr_out:
                    emit(owner, "outgoing", peer, "address_set", peer, role)
                if role.endswith("_intra_deny") or role.endswith("_intra_allow"):
                    emit(owner, "incoming", "", "intra", "", role)
                    emit(owner, "outgoing", "", "intra", "", role)
                    intra_default = role.replace("_intra_deny", "_intra_default_deny").replace(
                        "_intra_allow", "_intra_default_deny")
                    if intra_default != role and ovn_priority(intra_default, mode) >= 0:
                        emit(owner, "incoming", "", "intra", "", intra_default)
                        emit(owner, "outgoing", "", "intra", "", intra_default)
                    if role.startswith("app_intra"):
                        deny_role = (
                            "app_default_allow" if str(mode) in MONITOR_MODES
                            else "app_default_deny")
                        emit(owner, "incoming", "", "default_deny", "", deny_role)
                        emit(owner, "outgoing", "", "default_deny", "", deny_role)
                if role in ("app_allow", "ss_allow", "qf_allow", "qs_default_deny"):
                    deny_role = {
                        "app_allow": "app_default_allow" if str(mode) in MONITOR_MODES else "app_default_deny",
                        "ss_allow": "ss_default_allow" if str(mode) in MONITOR_MODES else "ss_default_deny",
                        "qf_allow": "qf_default_allow" if str(mode) in MONITOR_MODES else "qf_default_deny",
                        "qs_default_deny": "qs_default_deny",
                    }[role]
                    emit(owner, "incoming", "", "default_deny", "", deny_role)
                    emit(owner, "outgoing", "", "default_deny", "", deny_role)
                    if role == "qf_allow":
                        emit(owner, "incoming", "", "default_deny", "", "qf_allow")
                        emit(owner, "outgoing", "", "default_deny", "", "qf_allow")
    rows = []
    for key, slot in sorted(found.items()):
        policy, port_set, direction, peer, service_group, service, peer_kind, role = key
        rows.append({
            "policy": policy,
            "policy_name": slot["policy_name"],
            "port_set": port_set,
            "direction": direction,
            "peer_port_set": "" if peer_kind in ("address_set", "intra", "default_deny") else peer,
            "address_set": slot["address_set"] or (peer if peer_kind == "address_set" else ""),
            "peer_kind": peer_kind,
            "role": role,
            "expected_priority": slot["expected_priority"],
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


def parse_acl_rows(text):
    """Every OVN-NB ACL row. Priority is the number stored on that row."""
    rows = []
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 3:
            continue
        priority, action = row[0].strip(), row[1].strip()
        match = ",".join(row[2:]).strip()
        if not match or match == "match" or priority == "priority":
            continue
        ins = [pg_uuid(item) for item in re.findall(
            r"inport == @(port_group_[A-Za-z0-9_]+)", match)]
        outs = [pg_uuid(item) for item in re.findall(
            r"outport == @(port_group_[A-Za-z0-9_]+)", match)]
        srcs = [pg_uuid(item) for item in PEER_SRC.findall(match)]
        dsts = [pg_uuid(item) for item in PEER_DST.findall(match)]
        ins = [item for item in ins if UUID_RE.fullmatch(item)]
        outs = [item for item in outs if UUID_RE.fullmatch(item)]
        srcs = [item for item in srcs if UUID_RE.fullmatch(item)]
        dsts = [item for item in dsts if UUID_RE.fullmatch(item)]
        if ins and outs and set(ins) == set(outs):
            kind, direction, owners, peers = "intra", "intra", ins, ins
        elif outs and srcs:
            kind, direction, owners, peers = "incoming", "incoming", outs, srcs
        elif ins and dsts:
            kind, direction, owners, peers = "outgoing", "outgoing", ins, dsts
        elif outs:
            kind, direction, owners, peers = "outport_only", "incoming", outs, []
        elif ins:
            kind, direction, owners, peers = "inport_only", "outgoing", ins, []
        else:
            kind, direction, owners, peers = "global", "", [], []
        rows.append({
            "priority": priority,
            "action": action,
            "kind": kind,
            "direction": direction,
            "owners": owners,
            "peers": peers,
        })
    return rows


def verify_acl_rows(acl_rows, groups):
    """Every ACL. The priority check uses the number on that OVN-NB row."""
    failed = []
    counts = {}
    priorities = {}
    priority_checked = 0
    for rec in acl_rows:
        counts[rec["kind"]] = counts.get(rec["kind"], 0) + 1
        priority = rec["priority"]
        if _prio_num(priority) < 0:
            failed.append({
                "priority": priority,
                "action": rec["action"],
                "kind": rec["kind"],
                "port_set": (rec["owners"] or [""])[0],
                "ovn": "priority_missing",
            })
            continue
        priority_checked += 1
        priorities[priority] = priorities.get(priority, 0) + 1
        if rec["kind"] == "global":
            continue
        owners = list(rec["owners"])
        missing = [uid for uid in owners if uid not in groups]
        if not owners:
            failed.append({
                "priority": priority,
                "action": rec["action"],
                "kind": rec["kind"],
                "port_set": "",
                "ovn": "unparsed",
            })
        elif missing:
            failed.append({
                "priority": priority,
                "action": rec["action"],
                "kind": rec["kind"],
                "port_set": missing[0],
                "ovn": "owner_missing",
            })
    return failed, counts, priorities, priority_checked


def write_acls(acl_rows, groups, handle):
    """Print the ACL verification. Return how many ACL rows failed."""
    failed, counts, priorities, priority_checked = verify_acl_rows(acl_rows, groups)
    priority_failed = len(acl_rows) - priority_checked
    handle.write(
        "OVN NB acl: checked=%s verified=%s failed=%s "
        "priority_checked=%s priority_failed=%s\n" % (
            len(acl_rows), len(acl_rows) - len(failed), len(failed),
            priority_checked, priority_failed))
    handle.write(
        "OVN NB acl kind: %s\n" % " ".join(
            "%s=%s" % (kind, counts[kind]) for kind in sorted(counts)))
    handle.write(
        "OVN NB acl priority: %s\n" % " ".join(
            "%s=%s" % (pri, priorities[pri])
            for pri in sorted(priorities, key=_prio_num, reverse=True)))
    roles = {}
    for pri, count in priorities.items():
        role = ROLE_BY_PRIORITY.get(_prio_num(pri), "unknown")
        roles[role] = roles.get(role, 0) + count
    handle.write(
        "OVN NB acl role: %s\n" % " ".join(
            "%s=%s" % (role, roles[role]) for role in sorted(roles)))
    for rec in failed:
        handle.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return len(failed)


PG_TOKEN_RE = re.compile(
    r"port_group_([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})")


def acl_hint(acl_uuid):
    """northd stage-hint: first 32 bits of the ACL uuid, 8 hex digits."""
    text = str(acl_uuid or "").strip().lower()
    group = text.split("-", 1)[0]
    if len(group) != 8 or not UUID_RE.fullmatch(text):
        return ""
    return group


def flow_cookie(flow_uuid):
    """OpenFlow cookie ovn-controller installs: Logical_Flow uuid.parts[0]."""
    text = str(flow_uuid or "").strip().lower()
    group = text.split("-", 1)[0]
    if len(group) != 8 or not UUID_RE.fullmatch(text):
        return 0
    return int(group, 16)


def cookie_hex(cookies):
    """Same cookies as 8 hex digits, the form ovs-ofctl prints."""
    return ["0x%08x" % int(value) for value in cookies or []]


def _verdict_set(actions, bit):
    return bool(re.search(r"%s\s*=\s*1" % re.escape(bit), actions or ""))


def _label_set(actions, label):
    return bool(re.search(r"(?:^|[^0-9])%d(?:[^0-9]|$)" % int(label), actions or ""))


def parse_nb_acl_detail(text):
    """NB ACL rows with the uuid, direction, and label northd copies."""
    rows = []
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 6:
            continue
        acl_uuid, priority, direction, action, label = (item.strip() for item in row[:5])
        match = ",".join(row[5:]).strip()
        if not match or acl_uuid in ("_uuid", "uuid") or priority == "priority":
            continue
        if not UUID_RE.fullmatch(acl_uuid):
            continue
        owners = []
        for token in PG_TOKEN_RE.findall(match):
            uid = token.replace("_", "-")
            if uid not in owners:
                owners.append(uid)
        rows.append({
            "acl": acl_uuid.lower(),
            "priority": priority,
            "direction": direction,
            "action": action,
            "label": _prio_num(label),
            "match": match,
            "owners": owners,
        })
    return rows


def parse_sb_flows(text):
    """Index Logical_Flow rows by stage-hint."""
    found = {}
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 4:
            continue
        flow_uuid, priority, actions, external = (item.strip() for item in row[:4])
        match = ",".join(row[4:]).strip() if len(row) > 4 else ""
        if priority == "priority" or flow_uuid in ("_uuid", "uuid"):
            continue
        if "stage-hint=" not in external:
            continue
        hint = external.split("stage-hint=", 1)[1].split()[0].strip(",\"")
        stage = ""
        if "stage-name=" in external:
            stage = external.split("stage-name=", 1)[1].split()[0].strip(",\"")
        if not hint or "acl_eval" not in stage:
            continue
        found.setdefault(hint, []).append({
            "priority": _prio_num(priority),
            "stage": stage,
            "actions": actions,
            "match": match,
            "cookie": flow_cookie(flow_uuid),
        })
    return found


def parse_sb_port_groups(text):
    """Port-group UUIDs that have at least one logical switch port in SB."""
    live = set()
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 2:
            continue
        name, ports = row[0].strip(), ",".join(row[1:]).strip()
        if name in ("name", ""):
            continue
        if "port_" not in ports:
            continue
        for token in PG_TOKEN_RE.findall(name):
            live.add(token.replace("_", "-"))
    return live


def verify_sb(nb_rows, flows, live_groups):
    """Each policy ACL that northd should emit has a Logical_Flow at priority+1000.

    A policy ACL names a port group. DHCP, IPFIX, and the other system ACLs
    do not, and they are skipped. A port-group ACL is emitted only when that
    port group has a member port on a logical switch. An empty port group is
    not_emitted. The cookie is the OpenFlow cookie of each matching flow.
    """
    failed = []
    matched = []
    emitted = 0
    not_emitted = 0
    skipped = 0
    for rec in nb_rows:
        owners = rec["owners"]
        if not owners:
            skipped += 1
            continue
        if not any(uid in live_groups for uid in owners):
            not_emitted += 1
            continue
        emitted += 1
        hint = acl_hint(rec["acl"])
        stage = SB_STAGE.get(rec["direction"], "")
        expect = _prio_num(rec["priority"])
        expect = expect + SB_ACL_PRI_OFFSET if expect >= 0 else -1
        hits = [
            flow for flow in flows.get(hint, [])
            if flow["stage"] == stage and flow["priority"] == expect
        ]
        reason = ""
        if not hint or not stage or expect < 0:
            reason = "sb_unparsed"
        elif not hits:
            reason = "sb_missing"
        else:
            bit = SB_VERDICT.get(rec["action"], "")
            if bit and not any(_verdict_set(flow["actions"], bit) for flow in hits):
                reason = "sb_verdict"
            elif rec["label"] > 0 and not any(
                    _label_set(flow["actions"], rec["label"]) for flow in hits):
                reason = "sb_label"
            else:
                tokens = PG_TOKEN_RE.findall(rec["match"])
                tokens += re.findall(r"address_set_[0-9a-f_]+", rec["match"])
                blob = " ".join(flow["match"] for flow in hits)
                if any(token not in blob for token in tokens):
                    reason = "sb_match"
        cookies = sorted({
            flow["cookie"] for flow in hits if flow.get("cookie")})
        row = {
            "acl": rec["acl"],
            "priority": rec["priority"],
            "direction": rec["direction"],
            "port_set": owners[0],
            "cookie": cookies,
            "cookie_hex": cookie_hex(cookies),
        }
        if reason:
            row.update({
                "action": rec["action"],
                "label": rec["label"] if rec["label"] > 0 else 0,
                "stage": stage,
                "sb_priority": expect if expect >= 0 else "",
                "ovn": reason,
            })
            failed.append(row)
        else:
            matched.append(row)
    return failed, emitted, len(matched), not_emitted, skipped, matched


def write_sb(nb_rows, flows, live_groups, handle):
    """Print the policy southbound check. Return how many policy ACLs failed."""
    failed, emitted, verified, not_emitted, skipped, matched = verify_sb(
        nb_rows, flows, live_groups)
    handle.write(
        "OVN SB acl: policy=%s skipped=%s emitted=%s verified=%s "
        "not_emitted=%s failed=%s\n" % (
            emitted + not_emitted, skipped, emitted, verified,
            not_emitted, len(failed)))
    for rec in matched:
        handle.write(json.dumps(rec, separators=(",", ":")) + "\n")
    for rec in failed:
        handle.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return len(failed)


def _cfg_ints(text):
    nums = [int(item) for item in re.findall(r"\d+", text or "")]
    return nums


def write_cfg(cfg, handle):
    """Pass only when one sample read the same nb_cfg from both databases."""
    nb_cfg = cfg.get("nb_cfg", -1)
    sb_cfg = cfg.get("sb_nb_cfg", -1)
    hv_cfg = cfg.get("hv_cfg", -1)
    handle.write(
        "OVN cfg: nb_cfg=%s sb_nb_cfg=%s hv_cfg=%s\n" % (nb_cfg, sb_cfg, hv_cfg))
    return nb_cfg < 0 or sb_cfg < 0 or nb_cfg != sb_cfg


def pick_cfg(samples):
    """First sample where both counters are the same number, else the last."""
    last = {"nb_cfg": -1, "sb_nb_cfg": -1, "hv_cfg": -1}
    for cfg in samples or []:
        last = cfg
        nb_cfg = cfg.get("nb_cfg", -1)
        if nb_cfg >= 0 and nb_cfg == cfg.get("sb_nb_cfg"):
            return cfg
    return last


def _cfg_from_text(nb_text, sb_text):
    nb_nums = _cfg_ints(nb_text)
    sb_nums = _cfg_ints(sb_text)
    return {
        "nb_cfg": nb_nums[0] if nb_nums else -1,
        "hv_cfg": nb_nums[1] if len(nb_nums) > 1 else -1,
        "sb_nb_cfg": sb_nums[0] if sb_nums else -1,
    }


def read_cfg(info, timeout, attempts=5):
    """Read NB and SB nb_cfg until one pair is equal.

    The extra count appears when a transaction commits between the two reads.
    Repeating the pair until both sides show the same number removes that gap.
    """
    samples = []
    for _ in range(max(1, int(attempts))):
        _rc, nb_text, _err = _ovn_nb(
            info, ["--columns=nb_cfg,hv_cfg", "list", "NB_Global"], timeout)
        _rc, sb_text, _err = _ovn_sb(
            info, ["--columns=nb_cfg", "list", "SB_Global"], timeout)
        cfg = _cfg_from_text(nb_text, sb_text)
        samples.append(cfg)
        if cfg["nb_cfg"] >= 0 and cfg["nb_cfg"] == cfg["sb_nb_cfg"]:
            break
    return pick_cfg(samples)


def load_sb(info, timeout):
    """NB ACL identity plus the SB logical flows and live port groups."""
    _rc, acl_text, _err = _ovn_nb(
        info,
        ["--columns=_uuid,priority,direction,action,label,match", "list", "ACL"],
        timeout)
    _rc, flow_text, _err = _ovn_sb(
        info,
        ["--columns=_uuid,priority,actions,external_ids,match", "list", "Logical_Flow"],
        timeout)
    _rc, pg_text, _err = _ovn_sb(
        info, ["--columns=name,ports", "list", "Port_Group"], timeout)
    cfg = read_cfg(info, timeout)
    return (
        parse_nb_acl_detail(acl_text),
        parse_sb_flows(flow_text),
        parse_sb_port_groups(pg_text),
        cfg)


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
    if is_k8s_name(edge.get("policy")) or is_k8s_name(edge.get("policy_name")):
        return True
    if is_k8s_name(atlas_port_name(atlas_ids, edge.get("port_set"))):
        return True
    return is_k8s_name(atlas_port_name(atlas_ids, edge.get("peer_port_set")))


def reported_by_atlas(edge, atlas_ids):
    """False when Atlas did not report this port set or its port-set peer.

    An address set is not an atlas_port_set row. atlas_ids None skips the filter.
    """
    if atlas_ids is None:
        return True
    if edge["port_set"] not in atlas_ids:
        return False
    if edge.get("peer_kind") in ("address_set", "intra", "default_deny"):
        return True
    peer = edge.get("peer_port_set") or ""
    return not peer or peer in atlas_ids


def port_set_status(edge, groups):
    """Port-group presence only. An address set is not a port group."""
    if edge["port_set"] not in groups:
        return "missing"
    if edge.get("peer_kind") in ("address_set", "intra", "default_deny"):
        return "present"
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
    """ACLs for this owner and peer.

    The peer is the address-set UUID when the rule names an address group
    or a port set's generated address set. A port-group token still matches
    when the ACL was programmed that way.
    """
    port_set = edge["port_set"]
    direction = edge.get("direction") or ""
    directions = (direction,) if direction in ("incoming", "outgoing") else (
        "incoming", "outgoing")
    owner = by_owner.get(port_set) or {}
    want = []
    if edge.get("address_set"):
        want.append(edge["address_set"])
    peer = edge.get("peer_port_set") or ""
    if peer and edge.get("peer_kind") != "address_set":
        want.append(peer)
    if edge.get("peer_kind") in ("intra", "default_deny") and not want:
        want = [""]
    elif not want:
        want = [""]
    found = []
    for way in directions:
        peers = owner.get(way) or {}
        if want == [""] and edge.get("peer_kind") not in ("intra", "default_deny", "address_set"):
            for acls in peers.values():
                found.extend(acls)
            continue
        for key in want:
            found.extend(peers.get(key) or [])
    expected = edge.get("expected_priority")
    if expected not in (None, ""):
        hit = [item for item in found if str(item[0]) == str(expected)]
        if hit:
            return hit
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
            expected = edge.get("expected_priority")
            if found is None:
                ovn = "service_missing"
            elif expected not in (None, "") and str(found) != str(expected):
                ovn = "priority_mismatch"
                priority = found
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
    """Peer port set, OVN-NB ACL priority, and service group for one direction."""
    priority = ""
    status = port_set_status(edge, groups)
    service_group = edge.get("service_group") or ""
    service = edge.get("service") or "ALL"
    if status != "present":
        ovn = status
    elif edge.get("missing_sg"):
        ovn = "sg_missing"
    else:
        acls = acls_for(edge, by_owner)
        expected = edge.get("expected_priority")
        if not acls:
            ovn = "acl_missing"
        else:
            found = cover_priority(acls, edge.get("ports") or [])
            if found is None:
                ovn = "service_missing"
            elif _prio_num(found) < 0:
                ovn = "priority_missing"
            elif expected not in (None, "") and str(found) != str(expected):
                ovn = "priority_mismatch"
                priority = found
            else:
                ovn = "present"
                priority = found
    peer_kind = edge.get("peer_kind") or ""
    return {
        "port_set": "" if peer_kind == "address_set" else (edge.get("peer_port_set") or ""),
        "address_set": edge.get("address_set") or "",
        "role": edge.get("role") or "",
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
        "present": 0, "service_missing": 1, "priority_mismatch": 2,
        "acl_missing": 3, "sg_missing": 4, "peer_missing": 5, "missing": 6,
    }
    grouped = {}
    order = []
    for item in items:
        peer = (
            item.get("port_set") or "",
            item.get("address_set") or "",
            item.get("role") or "",
        )
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
            "port_set": parts[0].get("port_set") or "",
            "address_set": parts[0].get("address_set") or "",
            "role": parts[0].get("role") or "",
            "priority": priority,
            "service_group": groups,
            "service": services,
            "ovn": ovn,
        })
    out.sort(key=lambda item: (item["port_set"], item["address_set"], item["role"]))
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


def not_checked_rows(records, groups, atlas_map):
    """OVN port groups whose UUID no current policy hash produced.

    A shared name string does not attach a port set to a policy. The only
    link is the port-set UUID the policy rules hash to.
    """
    checked = {rec["port_set"] for rec in records}
    rows = []
    for uid in sorted(groups or ()):
        if uid in checked:
            continue
        name = atlas_port_name(atlas_map, uid)
        if is_k8s_name(name):
            reason = "kubernetes"
            detail = "Port set %s is skipped." % uid
        elif isinstance(atlas_map, dict) and uid not in atlas_map:
            reason = "not_in_atlas"
            detail = "OVN-NB has port set %s. Atlas has no entity with this UUID." % uid
        else:
            reason = "no_policy_uuid"
            detail = "No current policy UUID hashes to port set %s." % uid
        rows.append({"port_set": uid, "reason": reason, "detail": detail})
    return rows


def write_nb(records, handle, port_groups=0, acls=0, groups=None, atlas_map=None):
    """Print the OVN-NB fetch, the missing report, and port groups not checked."""
    failed = [rec for rec in records if record_failed(rec)]
    skipped = not_checked_rows(records, groups, atlas_map) if groups is not None else []
    handle.write(
        "OVN NB fetched: port_groups=%s acls=%s\n" % (port_groups, acls))
    handle.write(
        "OVN NB report: port_sets=%s present=%s missing=%s not_checked=%s\n" % (
            len(records), len(records) - len(failed), len(failed), len(skipped)))
    handle.write("OVN NB missing: %s\n" % len(failed))
    for rec in failed:
        handle.write(json.dumps(rec, separators=(",", ":")) + "\n")
    if groups is not None:
        handle.write("OVN NB not_checked: %s\n" % len(skipped))
        for row in skipped:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
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


def _ovn_ctl(info, which, args, timeout):
    """ovn-nbctl or ovn-sbctl. which is nb or sb."""
    tool = "ovn-%sctl" % which
    db = "ovnnb" if which == "nb" else "ovnsb"
    base = ["--db=unix:/var/run/ovn/%s_db.sock" % db,
            "--format=csv", "--data=bare", "--no-heading"]
    if os.path.exists("/var/run/ovn/%s_db.sock" % db):
        return _run([tool] + base + list(args), timeout)
    kubeconfig = ""
    if info.get("platform") == "smsp":
        dest = "/tmp/policy_ovn_kube"
        kubeconfig, err = _flow_kubeconfig(dest)
        if not kubeconfig:
            raise SystemExit(err or "mspctl kubeconfig failed")
    ns, pod, err = _find_pod("anc-ovn", "anc-ovn-0", kubeconfig=kubeconfig)
    if not pod:
        raise SystemExit(err or "anc-ovn pod not found")
    cmd = ["exec", "-n", ns, pod, "-c", "anc-ovn", "--", tool] + base + list(args)
    rc, out, err = _kubectl(cmd, timeout, kubeconfig=kubeconfig)
    if rc != 0:
        cmd = ["exec", "-n", ns, pod, "--", tool] + base + list(args)
        rc, out, err = _kubectl(cmd, timeout, kubeconfig=kubeconfig)
    if rc != 0:
        raise SystemExit((err or out or "%s failed" % tool)[:400])
    return rc, out, err


def _ovn_nb(info, args, timeout):
    return _ovn_ctl(info, "nb", args, timeout)


def _ovn_sb(info, args, timeout):
    return _ovn_ctl(info, "sb", args, timeout)


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
    return (
        parse_port_groups(groups_text),
        parse_acl_index(acl_text),
        parse_acl_rows(acl_text))


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
    missing = write_nb(
        nb, buf, port_groups=len(groups), acls=len(index), groups=groups)
    text = buf.getvalue()
    if not text.startswith("OVN NB fetched: port_groups=2 acls=2\n") or missing != 2:
        raise SystemExit("nb output missing=%s\n%s" % (missing, text))
    if "OVN NB report: port_sets=2 present=0 missing=2 not_checked=1\n" not in text:
        raise SystemExit("nb summary: %s" % text)
    if "OVN NB missing: 2\n{" not in text:
        raise SystemExit("missing report: %s" % text)
    if '"reason":"no_policy_uuid"' not in text or "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" not in text:
        raise SystemExit("not checked report: %s" % text)
    if '"name":' in text.split("OVN NB not_checked:", 1)[-1]:
        raise SystemExit("not checked row used a name: %s" % text)
    acl_sample = "\n".join([
        '100,allow-related,"outport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && ip4.src == @port_group_bbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb"',
        '1045,drop,"outport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && ip4"',
        '1017,allow-related,"inport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && outport == @port_group_aaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa && ip4"',
        '31500,allow-stateless,"udp.src == 67 && udp.dst == 68"',
        '50,drop,"outport == @port_group_ffffffff_ffff_4fff_8fff_ffffffffffff && ip4"',
    ])
    acl_rows = parse_acl_rows(acl_sample)
    kinds = {}
    for rec in acl_rows:
        kinds[rec["kind"]] = kinds.get(rec["kind"], 0) + 1
    if kinds.get("incoming") != 1 or kinds.get("outport_only") != 2 or kinds.get("intra") != 1 or kinds.get("global") != 1:
        raise SystemExit("acl kinds: %s" % kinds)
    if acl_rows[0]["priority"] != "100":
        raise SystemExit("acl priority: %s" % acl_rows[0])
    acl_rows.append({
        "priority": "",
        "action": "allow-related",
        "kind": "incoming",
        "direction": "incoming",
        "owners": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        "peers": ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
    })
    acl_buf = io.StringIO()
    acl_failed = write_acls(acl_rows, groups, acl_buf)
    acl_text_out = acl_buf.getvalue()
    if acl_failed != 2 or "priority_checked=5 priority_failed=1" not in acl_text_out:
        raise SystemExit("acl report: %s" % acl_text_out)
    if '"ovn":"owner_missing"' not in acl_text_out or '"ovn":"priority_missing"' not in acl_text_out:
        raise SystemExit("acl failure row: %s" % acl_text_out)
    if "31500=1" not in acl_text_out or "100=1" not in acl_text_out:
        raise SystemExit("acl priorities: %s" % acl_text_out)
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
    peer_rows = [row for row in built if row.get("peer_port_set")]
    if any(row["service_group"] != "Web" for row in peer_rows):
        raise SystemExit("service group name: %s" % built)
    if any(row["policy"] == "Iso" for row in built):
        raise SystemExit("policy edge used a name: %s" % built)
    if ovn_priority("app_allow", "kApply") != 1050:
        raise SystemExit("app allow priority")
    if ovn_priority("app_default_deny", "kApply") != 1045:
        raise SystemExit("app default deny priority")
    if ovn_priority("app_intra_deny", "kApply") != 1060:
        raise SystemExit("app intra deny priority")
    if ovn_priority("qs_intra_deny", "kApply") != 1097:
        raise SystemExit("qs intra deny priority")
    if ovn_priority("qf_default_deny", "kApply") != 1080:
        raise SystemExit("qf default deny priority")
    if ovn_priority("isolation_drop", "kApply") != 1065:
        raise SystemExit("isolation drop priority")
    if ovn_priority("app_allow", "kMonitor") != 1017:
        raise SystemExit("monitor app allow priority")
    if SYSTEM_PRIORITY["dhcp"] != 31500 or SYSTEM_PRIORITY["ipfix_allow"] != 500:
        raise SystemExit("system priority")
    if ROLE_BY_PRIORITY.get(31500) != "dhcp" or ROLE_BY_PRIORITY.get(500) != "ipfix_allow":
        raise SystemExit("system role: %s" % ROLE_BY_PRIORITY.get(31500))
    if ROLE_BY_PRIORITY.get(1050) != "app_allow" or ROLE_BY_PRIORITY.get(1045) != "app_default_deny":
        raise SystemExit("apply role")
    if ROLE_BY_PRIORITY.get(1097) != "qs_intra_deny" or ROLE_BY_PRIORITY.get(1065) != "isolation_drop":
        raise SystemExit("quarantine or isolation role")
    if address_set_ids("da2f45c1-e4a5-40a9-9aec-ac32fad3b6f8", False) != [
            "49d3b015-7bac-5a2a-8d9a-5c033243ba71"]:
        raise SystemExit("address set hash")
    app_policy = {
        "uuid": "af1c7c7a-b22e-4136-90eb-44eb2a006a17",
        "name": "ignored",
        "mode": "kApply",
        "policy_type": "kApplication",
        "scope": "kAllVlan",
        "rules_list": [{
            "application_rule": {
                "rule_info": {"uuid": "9b1ebc64-6756-4d09-97d9-875539a8d831"},
                "direction": "kIn",
                "secured_group": {"category_uuid_list": [
                    "e9a488b7-adab-346c-92d4-00180d6e6748"]},
                "endpoint": {"address_group_uuid": "da2f45c1-e4a5-40a9-9aec-ac32fad3b6f8"},
                "services": [{"service_group_uuid": "407982f9-5504-4504-a42d-78143d09f3fe"}],
            }
        }],
    }
    app_edges = policy_edges(
        [app_policy], "29332a4d-9133-4c73-a219-ce82ea53d532",
        "702970d3-d72d-41b9-9655-50c40ffd96f4",
        sg_map={
            "407982f9-5504-4504-a42d-78143d09f3fe": {
                "uuid": "407982f9-5504-4504-a42d-78143d09f3fe",
                "name": "Web", "ports": [("tcp", 80, 80)], "service": "tcp/80",
            }})
    addr = [
        row for row in app_edges
        if row.get("address_set") == "49d3b015-7bac-5a2a-8d9a-5c033243ba71"]
    if not addr or addr[0]["expected_priority"] != "1050" or addr[0]["peer_kind"] != "address_set":
        raise SystemExit("address set edge: %s" % app_edges)
    if addr[0]["policy"] != "af1c7c7a-b22e-4136-90eb-44eb2a006a17":
        raise SystemExit("policy uuid: %s" % addr[0])
    if flow_label(27044, "kOutbound", "allow") != 92580:
        raise SystemExit("label allow")
    if flow_label(27048, "kOutbound", "deny") != 223656:
        raise SystemExit("label deny")
    if flow_label(27052, "kIn", "allow") != 125356:
        raise SystemExit("label inbound")
    if acl_hint("d4ee03c2-fff9-414d-a8c6-41be729442c3") != "d4ee03c2":
        raise SystemExit("hint")
    nb_text = "\n".join([
        "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa,1050,from-lport,allow-related,92580,"
        "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4",
        "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb,1045,to-lport,drop,217679,"
        "ip4 && outport == @port_group_bbbbbbbb_2222_4222_8222_bbbbbbbbbbbb",
        "cccccccc-3333-4333-8333-cccccccccccc,1045,to-lport,drop,1,"
        "ip4 && outport == @port_group_cccccccc_3333_4333_8333_cccccccccccc",
    ])
    nb_text += (
        "\ndddddddd-4444-4444-8444-dddddddddddd,500,from-lport,allow-related,0,"
        "tcp || udp || icmp"
    )
    flow_buf = io.StringIO()
    csv.writer(flow_buf).writerow([
        "11223344-5555-4666-8777-888888888888",
        "2050",
        "reg8[16] = 1; reg3 = 92580; next;",
        "stage-hint=aaaaaaaa stage-name=ls_in_acl_eval",
        "reg0[7] == 1 && (inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4)",
    ])
    pg_text = "\n".join([
        "10040_port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa,port_abc",
        "10041_port_group_bbbbbbbb_2222_4222_8222_bbbbbbbbbbbb,port_def",
        "10042_port_group_cccccccc_3333_4333_8333_cccccccccccc,[]",
    ])
    failed, emitted, verified, not_emitted, skipped, matched = verify_sb(
        parse_nb_acl_detail(nb_text),
        parse_sb_flows(flow_buf.getvalue()),
        parse_sb_port_groups(pg_text))
    if (len(failed), emitted, verified, not_emitted, skipped) != (1, 2, 1, 1, 1):
        raise SystemExit(
            "sb check %s %s %s %s %s" % (
                failed, emitted, verified, not_emitted, skipped))
    if failed[0]["ovn"] != "sb_missing" or failed[0]["sb_priority"] != 2045:
        raise SystemExit("sb missing: %s" % failed[0])
    if failed[0]["acl"].startswith("dddddddd"):
        raise SystemExit("system acl was checked: %s" % failed[0])
    if matched[0]["cookie"] != [0x11223344]:
        raise SystemExit("cookie: %s" % matched[0])
    if matched[0]["cookie_hex"] != ["0x11223344"]:
        raise SystemExit("cookie hex: %s" % matched[0])
    bare = parse_args([])
    if bare.src or bare.dst or bare.port is not None or bare.proto or bare.skip_sb:
        raise SystemExit("default args: %s" % bare)
    if not parse_args(["--skip-sb"]).skip_sb:
        raise SystemExit("skip-sb flag")
    src_nic = "11111111-1111-4111-8111-111111111111"
    dst_nic = "22222222-2222-4222-8222-222222222222"
    src_set = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
    dst_set = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
    src_as = "cccccccc-3333-4333-8333-cccccccccccc"
    dst_as = "dddddddd-4444-4444-8444-dddddddddddd"
    allow_nb = {
        "acl": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
        "priority": "1050",
        "direction": "from-lport",
        "action": "allow-related",
        "label": 92580,
        "match": (
            "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && "
            "ip4.dst == $address_set_%s && tcp && tcp.dst == 80" % dst_as.replace("-", "_")),
        "owners": [src_set],
    }
    deny_nb = {
        "acl": "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
        "priority": "1045",
        "direction": "from-lport",
        "action": "drop",
        "label": 217679,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4",
        "owners": [src_set],
    }
    in_allow = {
        "acl": "eeeeeeee-5555-4555-8555-eeeeeeeeeeee",
        "priority": "1050",
        "direction": "to-lport",
        "action": "allow-related",
        "label": 125356,
        "match": (
            "outport == @port_group_bbbbbbbb_2222_4222_8222_bbbbbbbbbbbb && "
            "ip4.src == $address_set_%s && tcp && tcp.dst == 80" % src_as.replace("-", "_")),
        "owners": [dst_set],
    }
    in_deny = {
        "acl": "ffffffff-6666-4666-8666-ffffffffffff",
        "priority": "1045",
        "direction": "to-lport",
        "action": "drop",
        "label": 1,
        "match": "outport == @port_group_bbbbbbbb_2222_4222_8222_bbbbbbbbbbbb && ip4",
        "owners": [dst_set],
    }
    flow_rows = {}
    for hint, pri, stage in (
            ("aaaaaaaa", 2050, "ls_in_acl_eval"),
            ("eeeeeeee", 2050, "ls_out_acl_eval")):
        flow_rows.setdefault(hint, []).append({
            "priority": pri, "stage": stage, "actions": "reg8[16] = 1; next;",
            "match": "", "cookie": 0x11223344,
        })
    _out, _inc, verdict, src_remote, dst_remote = traffic_verdict(
        [allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [src_set], [dst_set], [src_as], [dst_as], "tcp", 80)
    if verdict != "allow" or _out["acl"] != allow_nb["acl"] or _inc["acl"] != in_allow["acl"]:
        raise SystemExit("traffic allow: %s %s %s" % (verdict, _out, _inc))
    if src_remote or dst_remote:
        raise SystemExit("both nics are local")
    _stage, sb_pri, cookies, _actions = _sb_hits(_out, flow_rows)
    if _stage != "ls_in_acl_eval" or sb_pri != 2050 or cookies != [0x11223344]:
        raise SystemExit("traffic cookie: %s %s %s" % (_stage, sb_pri, cookies))
    _out, _inc, verdict, _sr, _dr = traffic_verdict(
        [deny_nb, in_deny], flow_rows, [src_set], [dst_set], [src_as], [dst_as],
        "tcp", 80)
    if verdict != "deny" or _out is None or _inc is None:
        raise SystemExit("traffic deny: %s" % verdict)
    _out, _inc, verdict, _sr, _dr = traffic_verdict(
        [allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [src_set], [dst_set], [src_as], [dst_as], "udp", 80)
    if verdict != "deny":
        raise SystemExit("traffic proto: %s" % verdict)
    _out, _inc, verdict, src_remote, dst_remote = traffic_verdict(
        [allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [src_set], [], [src_as], [], "tcp", 80)
    if not dst_remote or src_remote or verdict != "deny" or _inc is not None:
        raise SystemExit("dest remote: %s %s %s" % (verdict, dst_remote, _out))
    if _out["acl"] != deny_nb["acl"]:
        raise SystemExit("dest remote used a specific peer: %s" % _out)
    _out, _inc, verdict, src_remote, dst_remote = traffic_verdict(
        [allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [], [dst_set], [], [dst_as], "tcp", 80)
    if not src_remote or dst_remote or verdict != "deny" or _out is not None:
        raise SystemExit("src remote: %s %s %s" % (verdict, src_remote, _inc))
    if _inc["acl"] != in_deny["acl"]:
        raise SystemExit("src remote used a specific peer: %s" % _inc)
    mon = {
        "acl": "abababab-7777-4777-8777-abababababab",
        "priority": "1021",
        "direction": "from-lport",
        "action": "drop",
        "label": 0,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4",
        "owners": [src_set],
    }
    _out, _inc, verdict, _sr, _dr = traffic_verdict(
        [mon, in_allow], flow_rows, [src_set], [dst_set], [src_as], [dst_as],
        "tcp", 80)
    if verdict != "allow" or not _is_monitor(mon):
        raise SystemExit("traffic monitor: %s" % verdict)
    ip6_deny = {
        "acl": "241d9ec4-b1af-4507-9755-c3ea9ca046c5",
        "priority": "1090",
        "direction": "from-lport",
        "action": "drop",
        "label": 196625,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip6",
        "owners": [src_set],
    }
    _out, _inc, verdict, _sr, _dr = traffic_verdict(
        [ip6_deny, allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [src_set], [dst_set], [src_as], [dst_as], "tcp", 80)
    if _out["acl"] == ip6_deny["acl"] or verdict != "allow":
        raise SystemExit("ip6 deny covered ipv4: %s %s" % (verdict, _out))
    _out6, _inc6, verdict6, _sr, _dr = traffic_verdict(
        [ip6_deny, allow_nb, deny_nb, in_allow, in_deny], flow_rows,
        [src_set], [dst_set], [src_as], [dst_as], "tcp", 80, family="ip6")
    if not _out6 or _out6["acl"] != ip6_deny["acl"] or verdict6 != "deny":
        raise SystemExit("ip6 deny missing: %s %s" % (verdict6, _out6))
    if not acl_covers("ip6", "tcp", 22, "ip6"):
        raise SystemExit("ip6 generic did not cover ipv6")
    if acl_covers("ip4 && tcp", "tcp", 22, "ip6"):
        raise SystemExit("ip4 match covered ipv6")
    if usable_address({"ipv4": "", "ipv6": "49d3b015-7bac-5a2a-8d9a-5c033243ba71"}) != (
            "49d3b015-7bac-5a2a-8d9a-5c033243ba71"):
        raise SystemExit("ipv6 address set fallback")
    if usable_address({"ipv4": ZERO, "ipv6": ""}):
        raise SystemExit("zero address set accepted")
    hosts = index_ovs_hosts(
        "port_%s,chassis-1\n"
        "port_c2fb9fbf-80cf-4242-8f1a-2b6ac872d341,"
        "50:6b:8d:4d:49:af unknown,chassis-1\n" % src_nic,
        "chassis-1,host-a,10.1.1.1\n")
    if host_for(hosts, src_nic) != "10.1.1.1":
        raise SystemExit("ovs host: %s" % hosts)
    if host_for(hosts, "99999999-9999-4999-8999-999999999999",
                "50:6b:8d:4d:49:af") != "10.1.1.1":
        raise SystemExit("ovs host mac: %s" % hosts)
    printed = io.StringIO()
    write_traffic(
        src_nic, dst_nic, "tcp", 80, allow_nb, in_allow, "allow",
        flow_rows, hosts, printed, macs={src_nic: "50:6b:8d:4d:49:af"})
    printed_text = printed.getvalue()
    if "OVS host" in printed_text or '"ovs_host":"10.1.1.1"' not in printed_text:
        raise SystemExit("host json: %s" % printed_text)
    if '"family":"ip4"' not in printed_text:
        raise SystemExit("family missing: %s" % printed_text)
    if '"label":92580' not in printed_text or "reg8[16]" not in printed_text:
        raise SystemExit("label or reg missing: %s" % printed_text)
    both = {
        src_nic: {"mac": "50:6b:8d:4d:49:af", "ipv4": ["10.1.1.2"], "ipv6": ["fe80::1"]},
        dst_nic: {"mac": "", "ipv4": ["10.1.1.3"], "ipv6": ["fe80::2"]},
    }
    if families_for(both, src_nic, dst_nic) != ["ip4", "ip6"]:
        raise SystemExit("nic families: %s" % families_for(both, src_nic, dst_nic))
    ip6_text = io.StringIO()
    write_traffic(
        src_nic, dst_nic, "tcp", 80, ip6_deny, None, "deny",
        flow_rows, hosts, ip6_text, macs=both, family="ip6")
    if ip6_deny["acl"] not in ip6_text.getvalue():
        raise SystemExit("ip6 deny not printed: %s" % ip6_text.getvalue())
    if port_sets_for_nic({src_set: {"nics": [src_nic]}}, src_nic) != [src_set]:
        raise SystemExit("nic port set")
    sink = io.StringIO()
    if write_cfg({"nb_cfg": 10, "sb_nb_cfg": 10, "hv_cfg": 10}, sink):
        raise SystemExit("cfg equal")
    if not write_cfg({"nb_cfg": 10, "sb_nb_cfg": 11, "hv_cfg": 10}, sink):
        raise SystemExit("cfg unequal")
    picked = pick_cfg([
        {"nb_cfg": 740533, "sb_nb_cfg": 740534, "hv_cfg": 740533},
        {"nb_cfg": 740534, "sb_nb_cfg": 740534, "hv_cfg": 740534},
    ])
    if picked["nb_cfg"] != 740534 or picked["sb_nb_cfg"] != 740534:
        raise SystemExit("cfg resample: %s" % picked)
    if write_cfg(picked, sink):
        raise SystemExit("cfg resample failed")
    print("self-test ok edges=%s" % len(built))


def port_sets_for_nic(atlas_map, nic):
    """Port-set UUIDs whose NIC list contains this NIC."""
    want = str(nic or "").strip().lower()
    found = []
    if not want:
        return found
    for uid, rec in (atlas_map or {}).items():
        nics = [str(item).strip().lower() for item in (rec.get("nics") or [])]
        if want in nics and uid not in found:
            found.append(uid)
    return found


def acl_owner(rec):
    """Port group this ACL is attached to, from its direction."""
    if rec.get("direction") == "from-lport":
        found = OWNER_OUT.search(rec.get("match") or "")
    elif rec.get("direction") == "to-lport":
        found = OWNER_IN.search(rec.get("match") or "")
    else:
        return ""
    return pg_uuid(found.group(1)) if found else ""


def _match_family(match):
    """ip4, ip6, or empty when the match names neither or both."""
    low = (match or "").lower()
    has4 = re.search(r"\bip4\b", low) is not None
    has6 = re.search(r"\bip6\b", low) is not None
    if has4 and not has6:
        return "ip4"
    if has6 and not has4:
        return "ip6"
    return ""


def acl_covers(match, proto, port, family="ip4"):
    """True when this ACL match applies to proto, the destination port, and family.

    A generic IPv6 deny does not cover an IPv4 packet. A match with no ip4
    or ip6 token covers both.
    """
    got = _match_family(match)
    if family and got and got != family:
        return False
    proto = str(proto or "").lower()
    kind, spec = _parsed_ranges(match, proto)
    if kind == "absent":
        low = (match or "").lower()
        return not any(token in low for token in ("tcp", "udp", "icmp"))
    if kind == "any":
        return True
    if kind == "icmp":
        return not spec or int(port) in spec
    if kind == "ranges":
        value = int(port)
        return any(lo <= value <= hi for lo, hi in spec)
    return False


def _peer_ids(match, direction):
    rule = PEER_DST if direction == "from-lport" else PEER_SRC
    return [pg_uuid(item) for item in rule.findall(match or "")]


def _is_monitor(rec):
    role = ROLE_BY_PRIORITY.get(_prio_num(rec.get("priority")), "")
    return role.startswith("monitor_")


def _stage_effect(rec):
    """Enforce drop denies. A monitor drop does not."""
    if rec is None:
        return "allow"
    if rec.get("action") == "drop" and not _is_monitor(rec):
        return "deny"
    return "allow"


def _pick_winner(rows):
    if not rows:
        return None
    best = max(_prio_num(rec["priority"]) for rec in rows)
    top = [rec for rec in rows if _prio_num(rec["priority"]) == best]
    drops = [rec for rec in top if rec.get("action") == "drop"]
    return drops[0] if drops else top[0]


def _sb_hits(rec, flows):
    hint = acl_hint(rec["acl"])
    stage = SB_STAGE.get(rec.get("direction"), "")
    expect = _prio_num(rec.get("priority"))
    expect = expect + SB_ACL_PRI_OFFSET if expect >= 0 else -1
    hits = [
        flow for flow in (flows or {}).get(hint, [])
        if flow["stage"] == stage and flow["priority"] == expect]
    cookies = sorted({flow["cookie"] for flow in hits if flow.get("cookie")})
    actions = [flow.get("actions") or "" for flow in hits]
    return stage, expect, cookies, actions


def matching_acls(nb_rows, owners, direction, peer_sets, proto, port,
                  remote_peer=False, family="ip4"):
    """Policy ACLs on these port sets that fit the other side, protocol, and port.

    remote_peer means the other NIC is not on this cluster. Only an ACL with
    no named peer applies to that remote side.
    """
    owners = set(owners or [])
    peers = set(peer_sets or [])
    found = []
    for rec in nb_rows or []:
        if rec.get("direction") != direction:
            continue
        owner = acl_owner(rec)
        if owner not in owners:
            continue
        if not acl_covers(rec.get("match"), proto, port, family):
            continue
        named = _peer_ids(rec.get("match"), direction)
        if remote_peer:
            if named:
                continue
        elif named and not any(item in peers for item in named):
            continue
        found.append(rec)
    return found


def traffic_verdict(nb_rows, flows, src_sets, dst_sets, src_addr, dst_addr,
                    proto, port, family="ip4"):
    """Winning outgoing and incoming policy ACL, and allow or deny.

    Both sides are checked when both NICs belong to a port set. A NIC with
    no port set is remote: that direction is not a local policy, and the
    side that does exist is still checked. family is ip4 or ip6. An ip6
    match is not applied to an ip4 packet.
    """
    src_remote = not src_sets
    dst_remote = not dst_sets
    outgoing = None
    incoming = None
    if not src_remote:
        outgoing = _pick_winner(matching_acls(
            nb_rows, src_sets, "from-lport", set(dst_sets) | set(dst_addr),
            proto, port, remote_peer=dst_remote, family=family))
    if not dst_remote:
        incoming = _pick_winner(matching_acls(
            nb_rows, dst_sets, "to-lport", set(src_sets) | set(src_addr),
            proto, port, remote_peer=src_remote, family=family))
    effects = []
    if not src_remote:
        effects.append(_stage_effect(outgoing))
    if not dst_remote:
        effects.append(_stage_effect(incoming))
    verdict = "deny" if "deny" in effects else "allow"
    return outgoing, incoming, verdict, src_remote, dst_remote


def _stage_report(rec, flows):
    if not rec:
        return None
    stage, sb_pri, cookies, actions = _sb_hits(rec, flows)
    return {
        "acl": rec["acl"],
        "priority": rec["priority"],
        "direction": rec["direction"],
        "action": rec["action"],
        "label": rec.get("label") or 0,
        "match": rec.get("match") or "",
        "port_set": acl_owner(rec),
        "stage": stage,
        "sb_priority": sb_pri if sb_pri >= 0 else "",
        "cookie": cookies,
        "actions": actions,
        "effect": _stage_effect(rec),
    }


def index_ovs_hosts(binding_text, chassis_text):
    """logical port, NIC uuid, or MAC -> chassis hostname, where OVS has the cookie.

    Port_Binding.logical_port is port_<atlas-port-uuid>. The NIC uuid passed
    on the command line is the virtual_nic id, so the MAC is the join.
    """
    names = {}
    reader = csv.reader(io.StringIO(chassis_text or ""))
    for row in reader:
        if len(row) < 3:
            continue
        uid, name, hostname = (item.strip() for item in row[:3])
        if uid in ("_uuid", "uuid"):
            continue
        label = hostname or name
        if uid:
            names[uid.lower()] = label
        if name:
            names[name.lower()] = label
    hosts = {}
    reader = csv.reader(io.StringIO(binding_text or ""))
    for row in reader:
        if len(row) < 2:
            continue
        if len(row) >= 3:
            logical, mac, chassis = (item.strip() for item in row[:3])
        else:
            logical, mac, chassis = row[0].strip(), "", row[1].strip()
        if logical in ("logical_port", ""):
            continue
        host = names.get(chassis.lower(), chassis)
        hosts[logical.lower()] = host
        for token in mac.replace('"', " ").split():
            if ":" in token:
                hosts[token.lower()] = host
    return hosts


def host_for(hosts, nic, mac=""):
    """Chassis hostname for this NIC. Empty when Port_Binding has no row."""
    want = str(nic or "").strip().lower()
    mac_key = str(mac or "").strip().lower()
    if mac_key and mac_key in (hosts or {}):
        return hosts[mac_key]
    if not want:
        return ""
    keys = (want, "port_%s" % want, want.replace("-", "_"))
    for key in keys:
        if key in (hosts or {}):
            return hosts[key]
    folded = want.replace("-", "_")
    for key, host in (hosts or {}).items():
        if folded and folded in key.replace("-", "_"):
            return host
    return ""


def _mac_of(facts, nic):
    rec = (facts or {}).get(str(nic or "").lower())
    if isinstance(rec, str):
        return rec
    if isinstance(rec, dict):
        return rec.get("mac") or ""
    return ""


def nic_families(facts, nic):
    """ip4 and ip6 present on this NIC. Unknown addresses stay on ip4."""
    rec = (facts or {}).get(str(nic or "").lower())
    if not isinstance(rec, dict):
        return ["ip4"]
    found = []
    if rec.get("ipv4"):
        found.append("ip4")
    if rec.get("ipv6"):
        found.append("ip6")
    return found or ["ip4"]


def families_for(facts, src, dst):
    """One result per address family that either NIC actually has."""
    order = []
    present = set(nic_families(facts, src)) | set(nic_families(facts, dst))
    for family in ("ip4", "ip6"):
        if family in present:
            order.append(family)
    return order or ["ip4"]


def write_traffic(src, dst, proto, port, outgoing, incoming, verdict,
                  flows, hosts, handle, src_remote=False, dst_remote=False,
                  macs=None, family="ip4"):
    """Print the one-flow check. The last line is allow or deny.

    The chassis hostname and the address family are fields of the first JSON
    for that direction. family is ip4 or ip6.
    """
    macs = macs or {}
    handle.write(
        "traffic src=%s dst=%s proto=%s port=%s family=%s\n" % (
            src, dst, proto, port, family))
    for label, rec, nic, remote in (
            ("outgoing", outgoing, src, src_remote),
            ("incoming", incoming, dst, dst_remote)):
        if remote:
            handle.write("OVN NB %s: %s\n" % (
                label, json.dumps(
                    {"family": family, "ovs_host": "remote"},
                    separators=(",", ":"))))
            handle.write("OVN SB %s: remote\n" % label)
            continue
        host = host_for(hosts, nic, _mac_of(macs, nic))
        has_family = family in nic_families(macs, nic)
        report = _stage_report(rec, flows) if has_family else None
        if not has_family:
            handle.write("OVN NB %s: %s\n" % (
                label, json.dumps(
                    {"family": family, "ovs_host": host},
                    separators=(",", ":"))))
            handle.write("OVN SB %s: none\n" % label)
        elif not report:
            handle.write("OVN NB %s: %s\n" % (
                label, json.dumps(
                    {"family": family, "ovs_host": host},
                    separators=(",", ":"))))
            handle.write("OVN SB %s: none\n" % label)
        else:
            handle.write("OVN NB %s: %s\n" % (
                label, json.dumps({
                    "acl": report["acl"],
                    "priority": report["priority"],
                    "direction": report["direction"],
                    "action": report["action"],
                    "label": report["label"],
                    "match": report["match"],
                    "port_set": report["port_set"],
                    "effect": report["effect"],
                    "family": family,
                    "ovs_host": host,
                }, separators=(",", ":"))))
            handle.write("OVN SB %s: %s\n" % (
                label, json.dumps({
                    "stage": report["stage"],
                    "sb_priority": report["sb_priority"],
                    "cookie": report["cookie"],
                    "cookie_hex": cookie_hex(report["cookie"]),
                    "actions": report["actions"],
                }, separators=(",", ":"))))
    handle.write("verdict: %s\n" % verdict)


def _attr_values(entity, name):
    for item in (entity or {}).get("attribute_data_map") or []:
        if item.get("name") != name:
            continue
        value = item.get("value") or {}
        if value.get("str_value"):
            return [str(value.get("str_value")).strip()]
        listed = (value.get("str_list") or {}).get("value_list") or []
        return [str(item).strip() for item in listed if str(item).strip()]
    return []


def fetch_nic_macs(nics, timeout):
    """virtual_nic uuid -> mac, ipv4, and ipv6.

    The OVN port name is a different uuid. The MAC joins the port binding.
    IPv6 addresses, including link-local, mean the ip6 deny is printed.
    """
    binary = idfcli_bin()
    if not binary:
        return {}
    found = {}
    for nic in nics or []:
        nic = str(nic or "").strip()
        if not nic:
            continue
        _rc, text, _err = _run(
            [binary, "get", "entity", "-e", "virtual_nic", "-k", nic, "-o", "json"],
            timeout)
        payload = _json_loads(text)
        entities = []
        if isinstance(payload, dict):
            entities = payload.get("entity") or []
        for entity in entities:
            mac = ""
            for item in _attr_values(entity, "mac_address"):
                mac = item.lower()
                break
            found[nic.lower()] = {
                "mac": mac,
                "ipv4": _attr_values(entity, "ipv4_addresses"),
                "ipv6": _attr_values(entity, "ipv6_addresses"),
            }
    return found


def _family_addrs(address_map, uids, family):
    key = "ipv6" if family == "ip6" else "ipv4"
    found = []
    for uid in uids or []:
        got = str((address_map or {}).get(uid, {}).get(key) or "").strip().lower()
        if UUID_RE.fullmatch(got) and got != ZERO and got not in found:
            found.append(got)
    return found


def load_hosts(info, timeout):
    _rc, binding_text, _err = _ovn_sb(
        info, ["--columns=logical_port,mac,chassis", "list", "Port_Binding"], timeout)
    _rc, chassis_text, _err = _ovn_sb(
        info, ["--columns=_uuid,name,hostname", "list", "Chassis"], timeout)
    return index_ovs_hosts(binding_text, chassis_text)


def traffic_main(info, args):
    """One source NIC, one dest NIC, one protocol, one destination port."""
    proto = str(args.proto or "").strip().lower()
    if proto not in ("tcp", "udp", "icmp"):
        raise SystemExit("traffic check needs --proto tcp, udp, or icmp")
    if not args.src or not args.dst or args.port is None:
        raise SystemExit("traffic check needs --src, --dst, --port, and --proto")
    atlas_map = fetch_idf_port_sets(info, min(int(args.timeout), 300))
    src_sets = port_sets_for_nic(atlas_map, args.src)
    dst_sets = port_sets_for_nic(atlas_map, args.dst)
    wanted = []
    for uid in src_sets + dst_sets:
        if uid not in wanted:
            wanted.append(uid)
    address_map = fetch_port_set_address_sets(
        info, wanted, min(int(args.timeout), 300))
    nb_rows, flows, _live, _cfg = load_sb(info, min(int(args.timeout), 600))
    hosts = load_hosts(info, min(int(args.timeout), 300))
    macs = fetch_nic_macs([args.src, args.dst], min(int(args.timeout), 120))
    for family in families_for(macs, args.src, args.dst):
        src_addr = _family_addrs(address_map, src_sets, family)
        dst_addr = _family_addrs(address_map, dst_sets, family)
        outgoing, incoming, verdict, src_remote, dst_remote = traffic_verdict(
            nb_rows, flows, src_sets, dst_sets, src_addr, dst_addr,
            proto, args.port, family=family)
        write_traffic(
            args.src, args.dst, proto, args.port, outgoing, incoming, verdict,
            flows, hosts, sys.stdout, src_remote=src_remote,
            dst_remote=dst_remote, macs=macs, family=family)
    sys.stdout.flush()
    return 0


def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description=(
            "List policy port-set incoming and outgoing peers, service groups, "
            "and priority, then validate them in OVN-NB. "
            "With --src, --dst, --port, and --proto, print the ACL, the "
            "southbound flow, the cookie, the OVS host, and allow or deny."))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--include-project", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--skip-sb", action="store_true",
        help="stop after the Northbound check and do not read Logical_Flow")
    parser.add_argument("--src", default="", help="source NIC uuid")
    parser.add_argument("--dst", default="", help="destination NIC uuid")
    parser.add_argument("--port", type=int, default=None, help="destination port or icmp type")
    parser.add_argument("--proto", default="", help="tcp, udp, or icmp")
    return parser.parse_args(argv)


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

CAT_PY = r"""
import json, sys
try:
  import gflags
  gflags.FLAGS(sys.argv[:1], known_only=True)
except Exception:
  pass
from aplos.categories.category import Category
sys.stdout.write(json.dumps({
  "strict": str(Category("Quarantine", "Default").uuid),
  "forensic": str(Category("Quarantine", "Forensics").uuid),
}, separators=(",", ":")))
"""


def _atlas_python():
    return _which(
        "/home/nutanix/.venvs/bin/bin/python3",
        "/home/nutanix/.venvs/flow/bin/python3",
        "")


def _run_pc_python(py, script, timeout):
    if not py:
        raise SystemExit("python3 for Atlas/Flow is missing")
    rc, out, err = _run([py, "-"], timeout, input_text=script)
    if rc != 0:
        raise SystemExit((err or out or "python failed")[:400])
    payload = _json_loads(out)
    if not isinstance(payload, dict):
        raise SystemExit("python returned no JSON object")
    return payload


def _run_atlas_pod(info, script, timeout):
    """Run AtlasClient inside the flow-cluster atlas pod. SMSP Atlas is not on the PC."""
    tmp = tempfile.mkdtemp(prefix="policy_ovn_as_")
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
    """Atlas generated IPv4/IPv6 address set for each port set.

    CMSP calls AtlasClient on the PC. SMSP runs the same call in the flow
    cluster atlas pod, because that Atlas is not the PC process.
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


def fetch_quarantine_categories(info, timeout):
    """System category UUIDs Flow uses to choose strict versus forensic.

    The lookup is the same Category(key, value) Flow's quarantine translator
    uses. The rest of this script compares those UUIDs and does not keep the
    category value.
    """
    timeout = max(30, min(120, int(timeout or 60)))
    py = _flow_python()
    try:
        return _run_pc_python(py, CAT_PY, timeout)
    except SystemExit as err:
        LOG.info("quarantine categories unavailable: %s", err)
        return {}


def usable_address(rec):
    """Generated address set. IPv4 when Atlas has one, otherwise IPv6.

    The all-zero UUID is not an address set.
    """
    for key in ("ipv4", "ipv6"):
        uid = str((rec or {}).get(key) or "").strip().lower()
        if UUID_RE.fullmatch(uid) and uid != ZERO:
            return uid
    return ""


def bind_address_sets(edges, address_map):
    """Fill the port set's generated address set. Address groups are already hashed."""
    address_map = address_map or {}
    for edge in edges:
        kind = edge.get("peer_kind") or ""
        if kind == "address_set":
            continue
        if kind == "intra":
            edge["address_set"] = usable_address(
                address_map.get(edge.get("port_set") or ""))
            continue
        if kind == "default_deny":
            continue
        peer = edge.get("peer_port_set") or ""
        got = usable_address(address_map.get(peer))
        if got:
            edge["address_set"] = got


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    setup_logging()
    if args.self_test:
        self_test()
        return 0
    maybe_forward(argv)
    info = detect_platform()
    if args.src or args.dst or args.port is not None or args.proto:
        return traffic_main(info, args)
    global_uuid, vlan_uuid = fetch_unique_uuids(info)
    if not global_uuid or not vlan_uuid:
        raise SystemExit("missing vlan/global unique uuid (zkcat / atlas ZK)")
    policies = fetch_policies(info, workers=args.workers, timeout=args.timeout)
    if not policies:
        raise SystemExit("no policies from flow_cli")
    sg_map = fetch_service_groups(info, min(int(args.timeout), 300))
    quar = fetch_quarantine_categories(info, min(int(args.timeout), 120))
    edges = policy_edges(
        policies, vlan_uuid, global_uuid, include_project=args.include_project,
        sg_map=sg_map, quar=quar)
    atlas_map = fetch_idf_port_sets(info, min(int(args.timeout), 300))
    address_map = fetch_port_set_address_sets(
        info, list(atlas_map), min(int(args.timeout), 300))
    bind_address_sets(edges, address_map)
    kept = [
        edge for edge in edges
        if reported_by_atlas(edge, atlas_map) and not skip_kubernetes(edge, atlas_map)]
    groups, acl_index, acl_rows = load_ovn(info, min(int(args.timeout), 600))
    LOG.info(
        "policies=%s service_groups=%s edges=%s atlas_port_sets=%s "
        "kept_edges=%s ovn_port_groups=%s ovn_acls=%s",
        len(policies), len(sg_map), len(edges), len(atlas_map), len(kept),
        len(groups), len(acl_rows))
    acl_failed = write_acls(acl_rows, groups, sys.stdout)
    records = port_set_nb(kept, groups, acl_index, atlas_map)
    missing = write_nb(
        records, sys.stdout, port_groups=len(groups), acls=len(acl_rows),
        groups=groups, atlas_map=atlas_map)
    if args.skip_sb:
        sys.stdout.flush()
        return 1 if missing or acl_failed else 0
    nb_detail, flows, live_groups, cfg = load_sb(info, min(int(args.timeout), 600))
    cfg_failed = write_cfg(cfg, sys.stdout)
    sb_failed = write_sb(nb_detail, flows, live_groups, sys.stdout)
    LOG.info(
        "sb_acls=%s sb_hints=%s sb_live_port_groups=%s sb_failed=%s",
        len(nb_detail), len(flows), len(live_groups), sb_failed)
    sys.stdout.flush()
    return 1 if missing or acl_failed or cfg_failed or sb_failed else 0


if __name__ == "__main__":
    sys.exit(main())
