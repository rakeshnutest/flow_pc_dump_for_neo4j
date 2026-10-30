#!/usr/bin/env python3
"""Allow or deny for one source NIC, one dest NIC, one protocol, one port.

Looks up the port groups those NICs belong to, lists only the ACLs on those
groups, and reads the logical flows for the winning ACL on each side.
Does not list the Logical_Flow table.

Standalone. Stdlib only. Does not import verify_policy_ovn.py.
Copy it to any Prism Central VM and run it there. A follower copies this
file to the leader over the cluster SSH key and prints the leader output.

  python3 verify_nic_ovn.py --src <nic-uuid> --dst <nic-uuid> --port 22 --proto tcp
  python3 verify_nic_ovn.py --self-test

--proto is tcp, udp, or icmp. --port is the destination port, or the ICMP
type. Both NICs are virtual_nic UUIDs.

Stdout is one block per address family the NICs actually have, IPv4 then
IPv6. Each block starts with a traffic line, then the winning outgoing ACL
and the winning incoming ACL. The last line of the block is verdict: allow
or verdict: deny. An enforce drop denies. A monitor drop does not.

The Northbound JSON carries acl, priority, direction, action, label, match,
port_set, effect, family, and ovs_host. ovs_host is the chassis hostname
for that NIC. The Southbound JSON carries stage, sb_priority, cookie,
cookie_hex, and actions. cookie is the OpenFlow cookie in decimal.
cookie_hex is the same value as ovs-ofctl prints it. A stateful ACL has
two cookies. actions is the logical-flow text: reg8[16] = 1 is allow,
reg8[17] = 1 is drop, reg8[18] = 1 is reject.

One ovn-nbctl process reads the port groups and their ACLs. One ovn-sbctl
process reads the winning flows and the port bindings used for ovs_host.

On CMSP, AtlasClient on the PC supplies each port set's generated IPv4 and
IPv6 address set. On SMSP that same call runs inside the flow-cluster atlas
pod, port sets and NIC addresses are read from the flow-cluster IDF, and
OVN is reached with the flow kubeconfig. An all-zero generated UUID is not
an address set. IPv4 uses the IPv4 UUID; IPv6 uses the IPv6 UUID.
"""

import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading

ZERO = "00000000-0000-0000-0000-000000000000"
ACL_PRIORITY_OFFSET = 1000
SB_ACL_PRI_OFFSET = 1000
SB_STAGE = {
    "from-lport": "ls_in_acl_eval",
    "to-lport": "ls_out_acl_eval",
}
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
SYSTEM_PRIORITY = {
    "dhcp": 31500,
    "ipfix_allow": 500,
    "nat_external_allow": 1000,
    "nat_external_drop": 100,
}
LOG = logging.getLogger("verify_nic_ovn")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
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
IDF_ENTITIES = ("atlas_port_set", "port_set")
IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
    "idfcli",
)

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


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")


def _which(*paths):
    for path in paths:
        if path and os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return paths[-1] if paths else ""


def _run(argv, timeout, input_text=None):
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
    return _run(
        ["bash", "-lc", "source /etc/profile >/dev/null 2>&1; %s" % cmd], timeout)


def _json_loads(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            return None
    return None


def _prio_num(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return -1


def _zk_bin(name):
    for path in (
            "/home/nutanix/cluster/bin/%s" % name,
            "/usr/local/nutanix/cluster/bin/%s" % name):
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return ""


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
    with open(os.path.abspath(__file__), "rb") as handle:
        body = handle.read()
    dest_name = os.path.basename(__file__)
    dest = "%s/%s" % (remote, dest_name)
    rc, _out, err = _run(
        ssh_base + ["cat > %s && chmod 755 %s" % (dest, dest)],
        30, input_text=body.decode("utf-8"))
    if rc != 0:
        raise SystemExit((err or "copy to leader failed")[:400])
    quoted = " ".join("'%s'" % arg.replace("'", "'\\''") for arg in argv)
    proc = subprocess.Popen(
        ssh_base + [
            "cd %s && env PC_LEADER_LOCAL=1 PYTHONUNBUFFERED=1 "
            "python3 -u %s %s" % (remote, dest_name, quoted)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
    finally:
        rc = proc.wait(timeout=1800)
    raise SystemExit(rc if rc >= 0 else 1)


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
    """kubectl for this process. A flow kubeconfig is used as given.

    The local probe is only for the PC's own cluster. SMSP passes the flow
    kubeconfig, so that path does not try sudo against the PC.
    """
    kubectl = _kubectl_bin()
    if kubeconfig:
        return [kubectl, "--kubeconfig", kubeconfig]
    prefix = [kubectl]
    rc, _out, _err = _run(prefix + ["get", "ns"], 15)
    if rc != 0:
        prefix = ["sudo", "-n", kubectl]
    return list(prefix)


def _kubectl(extra, timeout, kubeconfig="", input_text=None):
    return _run(
        _kubectl_prefix(kubeconfig) + list(extra), timeout, input_text=input_text)


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


def _pod_bin(kubeconfig, ns, pod, inner):
    rc, out, _err = _kubectl(
        ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
        30, kubeconfig=kubeconfig)
    for line in (out or "").strip().splitlines():
        cand = line.strip()
        if cand:
            return cand
    return ""


def _ovn_ctl(info, which, args, timeout):
    tool = "ovn-%sctl" % which
    db = "ovnnb" if which == "nb" else "ovnsb"
    base = ["--db=unix:/var/run/ovn/%s_db.sock" % db,
            "--format=csv", "--data=bare", "--no-heading"]
    if os.path.exists("/var/run/ovn/%s_db.sock" % db):
        rc, out, err = _run([tool] + base + list(args), timeout)
    else:
        kubeconfig = ""
        if info.get("platform") == "smsp":
            kubeconfig, err = _flow_kubeconfig("/tmp/policy_ovn_kube")
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


def ovn_commands(info, which, commands, timeout):
    """Several ovn-*ctl commands in one process, separated by --."""
    args = []
    for index, command in enumerate(commands):
        if index:
            args.append("--")
        args.extend(command)
    return _ovn_ctl(info, which, args, timeout)


def port_group_token(uid):
    return "port_group_%s" % str(uid or "").strip().lower().replace("-", "_")


def pg_uuid(token):
    text = str(token or "").strip().strip('"').strip("@")
    for prefix in ("port_group_", "address_set_"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.replace("_", "-").lower()


def acl_hint(acl_uuid):
    text = str(acl_uuid or "").strip().lower()
    group = text.split("-", 1)[0]
    if len(group) != 8 or not UUID_RE.fullmatch(text):
        return ""
    return group


def flow_cookie(flow_uuid):
    text = str(flow_uuid or "").strip().lower()
    group = text.split("-", 1)[0]
    if len(group) != 8 or not UUID_RE.fullmatch(text):
        return 0
    return int(group, 16)


def cookie_hex(cookies):
    return ["0x%08x" % int(value) for value in cookies or []]


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
        for key in ("value", "str_value"):
            if value.get(key) not in (None, ""):
                return as_str_list(value.get(key))
        return out
    text = str(value).strip()
    if text:
        out.append(text)
    return out


def idf_json_value(value):
    if value is None or not isinstance(value, dict):
        return value
    if "str_list" in value:
        inner = value.get("str_list") or {}
        if isinstance(inner, dict):
            return as_str_list(inner.get("value_list"))
        return as_str_list(inner)
    if "str_value" in value:
        return str(value.get("str_value") or "")
    return value


def flatten_idf_entity(ent):
    if not isinstance(ent, dict):
        return None
    attrs = {}
    guid = ent.get("entity_guid") or {}
    if isinstance(guid, dict):
        uid = str(guid.get("entity_id") or "").strip()
        if uid:
            attrs["uuid"] = uid
    adm = ent.get("attribute_data_map")
    items = adm if isinstance(adm, list) else []
    if isinstance(adm, dict):
        items = [{"name": key, "value": val} for key, val in adm.items()]
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        if not name or name == "__zprotobuf__":
            continue
        attrs[name] = idf_json_value(item.get("value"))
    return attrs or None


def _nic_list(row):
    for key in ("virtual_nic_uuid_list", "vnic_uuid_list", "virtual_nic_uuids"):
        raw = row.get(key) if isinstance(row, dict) else None
        if raw:
            return [str(item).strip().lower() for item in as_str_list(raw)]
    return []


def index_idf_port_sets(rows):
    out = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        uid = str(row.get("uuid") or "").strip().lower()
        if not UUID_RE.fullmatch(uid):
            continue
        nics = _nic_list(row)
        prev = out.get(uid)
        if prev is None:
            out[uid] = {"uuid": uid, "name": str(row.get("name") or ""), "nics": nics}
            continue
        for nic in nics:
            if nic not in prev["nics"]:
                prev["nics"].append(nic)
    return out


def parse_idf_stdout(text):
    payload = _json_loads(text)
    ents = []
    if isinstance(payload, dict):
        raw = payload.get("entity") or payload.get("entities") or []
        ents = raw if isinstance(raw, list) else [raw]
    elif isinstance(payload, list):
        ents = payload
    return index_idf_port_sets([flatten_idf_entity(ent) for ent in ents])


def idfcli_bin():
    return _which(*IDF_BINS)


def fetch_idf_port_sets(info, timeout):
    errors = []
    if (info or {}).get("platform") == "smsp":
        found, detail = _fetch_idf_smsp(info, timeout)
        if found:
            return found
        if detail:
            errors.append(detail)
    binary = idfcli_bin()
    for entity in IDF_ENTITIES:
        argv = [binary, "get", "entity", "-e", entity, "--all", "-o", "json"]
        _rc, out, err = _run(argv, timeout)
        found = parse_idf_stdout(out)
        if found:
            LOG.info("idfcli %s count=%s", entity, len(found))
            return found
        errors.append((err or out or "empty")[:200])
    raise SystemExit("idfcli port_set returned no entities\n" + "\n".join(errors))


def _idf_inner(entity, key=""):
    """idfcli argv inside a flow pod. key limits the get to one entity."""
    select = "-e %s --all" % entity
    if key:
        select = "-e %s -k %s" % (entity, key)
    bins = (
        "idfcli",
        "/usr/local/nutanix/bin/idfcli",
        "/home/nutanix/bin/idfcli",
    )
    return " || ".join("%s get entity %s -o json" % (binary, select) for binary in bins)


def _smsp_idf_pod(kubeconfig):
    """Atlas port sets live in the flow-cluster IDF, often beside atlas."""
    found_pod = ("", "", "no pod")
    for app, preferred in (
            ("atlas", "atlas-0"), ("insights", "insights-0"), ("idf", "idf-0")):
        ns, pod, err = _find_pod(app, preferred, "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, err = _find_pod(app, preferred, "", kubeconfig)
        if pod:
            return ns, pod, ""
        found_pod = (ns, pod, err)
    return found_pod


def _fetch_idf_smsp(info, timeout):
    tmp = tempfile.mkdtemp(prefix="nic_ovn_kube_")
    kubeconfig = ""
    try:
        kubeconfig, kube_err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            return {}, kube_err or "smsp kubeconfig failed"
        ns, pod, err = _smsp_idf_pod(kubeconfig)
        if not pod:
            return {}, err or "smsp idf pod missing"
        last = "empty"
        for entity in IDF_ENTITIES:
            _rc, out, err = _kubectl(
                ["exec", "-n", ns, pod, "--", "bash", "-lc", _idf_inner(entity)],
                timeout, kubeconfig=kubeconfig)
            found = parse_idf_stdout(out)
            if found:
                LOG.info("idfcli %s via %s/%s count=%s", entity, ns, pod, len(found))
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


def port_sets_for_nic(atlas_map, nic):
    want = str(nic or "").strip().lower()
    found = []
    if not want:
        return found
    for uid, rec in (atlas_map or {}).items():
        if want in (rec.get("nics") or []) and uid not in found:
            found.append(uid)
    return found


def _atlas_python():
    return _which(
        "/home/nutanix/.venvs/bin/bin/python3",
        "/home/nutanix/.venvs/flow/bin/python3",
        "")


def _run_atlas_pod(info, script, timeout):
    tmp = tempfile.mkdtemp(prefix="nic_ovn_as_")
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
    uuids = [str(uid).lower() for uid in (uuids or []) if uid]
    if not uuids:
        return {}
    LOG.info("address sets n=%s", len(uuids))
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
    LOG.info("address sets ready=%s", len(payload))
    return payload


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


def _nic_from_idf_text(text, nic):
    payload = _json_loads(text)
    entities = []
    if isinstance(payload, dict):
        raw = payload.get("entity") or []
        entities = raw if isinstance(raw, list) else [raw]
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        mac = ""
        for item in _attr_values(entity, "mac_address"):
            mac = item.lower()
            break
        if not mac and not _attr_values(entity, "ipv4_addresses"):
            continue
        return {
            "mac": mac,
            "ipv4": _attr_values(entity, "ipv4_addresses"),
            "ipv6": _attr_values(entity, "ipv6_addresses"),
        }
    return {}


def _fetch_nic_mac_smsp(nic, timeout):
    """virtual_nic from the flow-cluster IDF. PC IDF is the fallback."""
    tmp = tempfile.mkdtemp(prefix="nic_ovn_vnic_")
    kubeconfig = ""
    try:
        kubeconfig, _err = _flow_kubeconfig(tmp)
        if not kubeconfig:
            return {}
        ns, pod, _err = _smsp_idf_pod(kubeconfig)
        if not pod:
            return {}
        _rc, out, _err = _kubectl(
            ["exec", "-n", ns, pod, "--", "bash", "-lc",
             _idf_inner("virtual_nic", nic)],
            timeout, kubeconfig=kubeconfig)
        return _nic_from_idf_text(out, nic)
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


def fetch_nic_macs(info, nics, timeout):
    """MAC and addresses for these virtual_nic UUIDs.

    SMSP reads the flow-cluster IDF first. A miss falls back to idfcli on
    the PC, which is where the NIC entity lives on CMSP.
    """
    binary = idfcli_bin()
    found = {}
    smsp = (info or {}).get("platform") == "smsp"
    for nic in nics or []:
        nic = str(nic or "").strip()
        if not nic:
            continue
        rec = _fetch_nic_mac_smsp(nic, timeout) if smsp else {}
        if not rec and binary:
            _rc, text, _err = _run(
                [binary, "get", "entity", "-e", "virtual_nic", "-k", nic, "-o", "json"],
                timeout)
            rec = _nic_from_idf_text(text, nic)
        if rec:
            found[nic.lower()] = rec
    return found


def parse_nb_acls(text):
    rows = []
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 6:
            continue
        acl_uuid, priority, direction, action, label = (item.strip() for item in row[:5])
        match = ",".join(row[5:]).strip()
        if not match or not UUID_RE.fullmatch(acl_uuid):
            continue
        rows.append({
            "acl": acl_uuid.lower(),
            "priority": priority,
            "direction": direction,
            "action": action,
            "label": _prio_num(label),
            "match": match,
        })
    return rows


def parse_sb_flows(text):
    found = {}
    reader = csv.reader(io.StringIO(text or ""))
    for row in reader:
        if len(row) < 4:
            continue
        flow_uuid, priority, actions, external = (item.strip() for item in row[:4])
        match = ",".join(row[4:]).strip() if len(row) > 4 else ""
        if "stage-hint=" not in external or not UUID_RE.fullmatch(flow_uuid):
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


def load_acls_for_port_sets(info, port_sets, timeout):
    """One ovn-nbctl: port groups by exact name, then those ACL uuids."""
    tokens = []
    for uid in port_sets or []:
        token = port_group_token(uid)
        if token != "port_group_" and token not in tokens:
            tokens.append(token)
    if not tokens:
        return []
    commands = [
        ["--columns=acls", "find", "Port_Group", "name=%s" % token]
        for token in tokens]
    _rc, text, _err = ovn_commands(info, "nb", commands, timeout)
    acl_uuids = []
    for item in UUID_RE.findall(text or ""):
        item = item.lower()
        if item not in acl_uuids:
            acl_uuids.append(item)
    LOG.info("port group acls=%s", len(acl_uuids))
    if not acl_uuids:
        return []
    rows = []
    step = 80
    for start in range(0, len(acl_uuids), step):
        chunk = acl_uuids[start:start + step]
        _rc, acl_text, _err = ovn_commands(
            info, "nb",
            [["--columns=_uuid,priority,direction,action,label,match", "list", "ACL"] + chunk],
            timeout)
        rows.extend(parse_nb_acls(acl_text))
    seen = set()
    unique = []
    for rec in rows:
        if rec["acl"] in seen:
            continue
        seen.add(rec["acl"])
        unique.append(rec)
    LOG.info("nic acls=%s", len(unique))
    return unique


def load_flows_and_hosts(info, hints, macs, timeout):
    """Winning logical flows, port bindings, and chassis in one ovn-sbctl."""
    wanted = []
    for hint in hints or []:
        hint = str(hint or "").strip().lower()
        if len(hint) == 8 and hint not in wanted:
            wanted.append(hint)
    commands = [[
        "--columns=_uuid,priority,actions,external_ids,match",
        "find", "Logical_Flow", "external_ids:stage-hint=%s" % hint,
    ] for hint in wanted]
    commands.append(["--columns=logical_port,mac,chassis", "list", "Port_Binding"])
    commands.append(["--columns=_uuid,name,hostname", "list", "Chassis"])
    _rc, text, _err = ovn_commands(info, "sb", commands, timeout)
    flow_lines = []
    binding_lines = []
    chassis_lines = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if "stage-hint=" in line:
            flow_lines.append(line)
            continue
        first = line.split(",", 1)[0]
        if ":" in line and ":" not in first:
            binding_lines.append(line)
        else:
            chassis_lines.append(line)
    hosts = index_ovs_hosts("\n".join(binding_lines), "\n".join(chassis_lines))
    named = [host_for(hosts, "", mac) for mac in macs or [] if mac]
    LOG.info("ovs hosts=%s named=%s", len(hosts), ",".join(item for item in named if item))
    return parse_sb_flows("\n".join(flow_lines)), hosts


def index_ovs_hosts(binding_text, chassis_text):
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


def acl_owner(rec):
    if rec.get("direction") == "from-lport":
        found = OWNER_OUT.search(rec.get("match") or "")
    elif rec.get("direction") == "to-lport":
        found = OWNER_IN.search(rec.get("match") or "")
    else:
        return ""
    return pg_uuid(found.group(1)) if found else ""


def _match_family(match):
    low = (match or "").lower()
    has4 = re.search(r"\bip4\b", low) is not None
    has6 = re.search(r"\bip6\b", low) is not None
    if has4 and not has6:
        return "ip4"
    if has6 and not has4:
        return "ip6"
    return ""


def _numbers(text):
    return [int(item) for item in re.findall(r"\d+", text or "")]


def _parsed_ranges(match, proto):
    low = (match or "").lower()
    if proto in ("icmp", "icmp6"):
        if "icmp" not in low:
            return "absent", ()
        types = tuple(int(item) for item in re.findall(r"icmp6?\.type == (\d+)", low))
        return "icmp", types
    if proto not in low:
        return "absent", ()
    if "%s.dst" % proto not in low:
        return "any", ()
    ranges = []
    for item in re.findall(r"%s\.dst == (\d+)" % proto, low):
        ranges.append((int(item), int(item)))
    for brace in re.findall(r"%s\.dst == \{([0-9, ]+)\}" % proto, low):
        for item in _numbers(brace):
            ranges.append((item, item))
    for lo, hi in re.findall(
            r"%s\.dst >= (\d+).*?%s\.dst <= (\d+)" % (proto, proto), low):
        ranges.append((int(lo), int(hi)))
    return "ranges", tuple(ranges)


def acl_covers(match, proto, port, family="ip4"):
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


def traffic_verdict(nb_rows, src_sets, dst_sets, src_addr, dst_addr,
                    proto, port, family="ip4"):
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


def host_for(hosts, nic, mac=""):
    want = str(nic or "").strip().lower()
    mac_key = str(mac or "").strip().lower()
    if mac_key and mac_key in (hosts or {}):
        return hosts[mac_key]
    if not want:
        return ""
    for key in (want, "port_%s" % want, want.replace("-", "_")):
        if key in (hosts or {}):
            return hosts[key]
    folded = want.replace("-", "_")
    for key, host in (hosts or {}).items():
        if folded and folded in key.replace("-", "_"):
            return host
    return ""


def _mac_of(facts, nic):
    rec = (facts or {}).get(str(nic or "").lower())
    if isinstance(rec, dict):
        return rec.get("mac") or ""
    if isinstance(rec, str):
        return rec
    return ""


def nic_families(facts, nic):
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
    present = set(nic_families(facts, src)) | set(nic_families(facts, dst))
    order = [family for family in ("ip4", "ip6") if family in present]
    return order or ["ip4"]


def _family_addrs(address_map, uids, family):
    key = "ipv6" if family == "ip6" else "ipv4"
    found = []
    for uid in uids or []:
        got = str((address_map or {}).get(uid, {}).get(key) or "").strip().lower()
        if UUID_RE.fullmatch(got) and got != ZERO and got not in found:
            found.append(got)
    return found


def write_traffic(src, dst, proto, port, outgoing, incoming, verdict,
                  flows, hosts, handle, src_remote=False, dst_remote=False,
                  macs=None, family="ip4"):
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
        if not report:
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


def _spawn(fn, args):
    box = {}

    def run():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    return thread, box


def _join(thread, box):
    thread.join()
    if box.get("error") is not None:
        raise box["error"]
    return box.get("value")


def traffic_main(info, args):
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
    LOG.info("nic port sets src=%s dst=%s", len(src_sets), len(dst_sets))
    addr_thread, addr_box = _spawn(
        fetch_port_set_address_sets, (info, wanted, min(int(args.timeout), 300)))
    mac_thread, mac_box = _spawn(
        fetch_nic_macs, (info, [args.src, args.dst], min(int(args.timeout), 120)))
    nb_rows = load_acls_for_port_sets(info, wanted, min(int(args.timeout), 180))
    address_map = _join(addr_thread, addr_box)
    macs = _join(mac_thread, mac_box)
    planned = []
    hints = []
    for family in families_for(macs, args.src, args.dst):
        outgoing, incoming, verdict, src_remote, dst_remote = traffic_verdict(
            nb_rows, src_sets, dst_sets,
            _family_addrs(address_map, src_sets, family),
            _family_addrs(address_map, dst_sets, family),
            proto, args.port, family=family)
        planned.append((family, outgoing, incoming, verdict, src_remote, dst_remote))
        for rec in (outgoing, incoming):
            hint = acl_hint((rec or {}).get("acl"))
            if hint and hint not in hints:
                hints.append(hint)
    flows, hosts = load_flows_and_hosts(
        info, hints, [_mac_of(macs, args.src), _mac_of(macs, args.dst)],
        min(int(args.timeout), 180))
    for family, outgoing, incoming, verdict, src_remote, dst_remote in planned:
        write_traffic(
            args.src, args.dst, proto, args.port, outgoing, incoming, verdict,
            flows, hosts, sys.stdout, src_remote=src_remote,
            dst_remote=dst_remote, macs=macs, family=family)
    sys.stdout.flush()
    return 0


def self_test():
    src_set = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
    dst_set = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
    if port_group_token(src_set) != "port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa":
        raise SystemExit("port group token")
    allow = {
        "acl": "11111111-1111-4111-8111-111111111111",
        "priority": "1050", "direction": "from-lport", "action": "allow-related",
        "label": 92580,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4 && tcp && tcp.dst == 80",
    }
    ip6 = {
        "acl": "241d9ec4-b1af-4507-9755-c3ea9ca046c5",
        "priority": "1090", "direction": "from-lport", "action": "drop",
        "label": 196625,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip6",
    }
    outgoing, _incoming, verdict, _sr, _dr = traffic_verdict(
        [allow, ip6], [src_set], [dst_set], [], [], "tcp", 80, family="ip4")
    if verdict != "allow" or outgoing["acl"] != allow["acl"]:
        raise SystemExit("ip6 deny won an ip4 packet: %s" % outgoing)
    outgoing, _incoming, verdict, _sr, _dr = traffic_verdict(
        [allow, ip6], [src_set], [dst_set], [], [], "tcp", 80, family="ip6")
    if verdict != "deny" or not outgoing["acl"].startswith("241d9ec4"):
        raise SystemExit("ip6 packet missed the ip6 deny")
    peer_as = "cccccccc-3333-4333-8333-cccccccccccc"
    peer_token = peer_as.replace("-", "_")
    specific = {
        "acl": "33333333-3333-4333-8333-333333333333",
        "priority": "1100", "direction": "from-lport", "action": "allow-related",
        "label": 1,
        "match": (
            "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && "
            "ip4.dst == $address_set_%s && tcp && tcp.dst == 22" % peer_token),
    }
    generic = {
        "acl": "44444444-4444-4444-8444-444444444444",
        "priority": "1045", "direction": "from-lport", "action": "drop",
        "label": 2,
        "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4",
    }
    outgoing, _incoming, verdict, _sr, _dr = traffic_verdict(
        [generic, specific], [src_set], [dst_set], [], [peer_as],
        "tcp", 22, family="ip4")
    if verdict != "allow" or not outgoing["acl"].startswith("33333333"):
        raise SystemExit("address set peer was not selected: %s" % outgoing)
    outgoing, _incoming, verdict, _sr, _dr = traffic_verdict(
        [generic, specific], [src_set], [dst_set], [], [ZERO],
        "tcp", 22, family="ip4")
    if verdict != "deny" or not outgoing["acl"].startswith("44444444"):
        raise SystemExit("zero address set counted as a peer: %s" % outgoing)
    ip6_as = "dddddddd-4444-4444-8444-dddddddddddd"
    ip6_specific = {
        "acl": "55555555-5555-4555-8555-555555555555",
        "priority": "1100", "direction": "to-lport", "action": "allow-related",
        "label": 3,
        "match": (
            "ip6.src == $address_set_%s && tcp && tcp.dst == 22 && "
            "outport == @port_group_bbbbbbbb_2222_4222_8222_bbbbbbbbbbbb"
            % ip6_as.replace("-", "_")),
    }
    _outgoing, incoming, verdict, _sr, _dr = traffic_verdict(
        [ip6_specific, generic], [src_set], [dst_set], [ip6_as], [],
        "tcp", 22, family="ip6")
    if verdict != "allow" or not incoming["acl"].startswith("55555555"):
        raise SystemExit("ipv6 address set peer was not selected: %s" % incoming)
    if _family_addrs({dst_set: {"ipv4": ZERO, "ipv6": ip6_as}}, [dst_set], "ip4"):
        raise SystemExit("zero ipv4 address set was used")
    if _family_addrs({dst_set: {"ipv4": ZERO, "ipv6": ip6_as}}, [dst_set], "ip6") != [ip6_as]:
        raise SystemExit("ipv6 address set fallback failed")
    if "virtual_nic" not in _idf_inner("virtual_nic", src_set):
        raise SystemExit("smsp idf command")
    monitor = {
        "acl": "22222222-2222-4222-8222-222222222222",
        "priority": "1017", "direction": "from-lport", "action": "drop",
        "label": 0, "match": "inport == @port_group_aaaaaaaa_1111_4111_8111_aaaaaaaaaaaa && ip4",
    }
    if _stage_effect(monitor) != "allow":
        raise SystemExit("monitor drop denied")
    flows = parse_sb_flows(
        "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa,2050,reg8[16] = 1,"
        "stage-hint=11111111 stage-name=ls_in_acl_eval,inport")
    _stage, pri, cookies, actions = _sb_hits(allow, flows)
    if pri != 2050 or cookies != [0xaaaaaaaa] or "reg8[16]" not in actions[0]:
        raise SystemExit("sb hits %s %s %s" % (pri, cookies, actions))
    print("self-test ok")


def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description="Allow or deny between two NICs from the port groups they belong to.")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--src", default="")
    parser.add_argument("--dst", default="")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--proto", default="")
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
    return traffic_main(info, args)


if __name__ == "__main__":
    sys.exit(main())
