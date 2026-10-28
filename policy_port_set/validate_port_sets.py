#!/usr/bin/env python3
"""Compare policy port_set hashes with idfcli port_set entities.

Expected UUIDs use the same algorithm as neo4j_db_insert.generate_port_set_id
(uuid5 for application rules, MD5 for FLEX). A FLEX rule also hashes
applied_to (the applied entity group) and an allow-any side (empty Go
list). UI Global applied_to, where that field is absent, is not a port set.
SMSP reads port_set with idfcli inside the flow cluster and uses the Atlas
ZK scope UUIDs. Actual port sets come from

  idfcli get entity -e atlas_port_set --all -o json

Nothing is written to disk. Stdout is only mismatch rows, tab-separated:

  mismatch  port_set  idf_name  policy  policy_uuid  rule_uuid  role
  entity_type  scope  refs  components

  computed_without_idf   hash from a policy component, absent in idfcli
  idf_without_computed   idfcli port_set, not produced by any component

K8s_* port sets and Quarantine port sets with no NICs are left out.
Address groups are not port sets. SAVE-mode policies are skipped.

FLEX also hashes applied_to (the entity group on the rule) and an empty
VM selector when should_allow_any_src/dst is set or the rule has no
selector. A missing applied_to field is UI Global and is not a port set.
SMSP reads port_set with idfcli in the flow cluster and uses the Atlas
ZK scope UUIDs. CMSP uses the local idfcli and zkcat.

  python3 validate_port_sets.py
  python3 validate_port_sets.py --self-test
"""

import argparse
import csv
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import update_policy_port_sets as ups  # noqa: E402

COLUMNS = (
    "mismatch", "port_set", "idf_name", "policy", "policy_uuid",
    "rule_uuid", "role", "entity_type", "scope", "refs", "components",
)
# port_set is an evictable IDF type: Insights rejects --all.
# atlas_port_set is the table idfcli can list. Entity id is the port-set UUID.
IDF_ENTITIES = ("atlas_port_set", "port_set")
IDF_BINS = (
    "/home/docker/msp_controller/bootstrap/msp_tools/cmsp-scripts/idfcli",
    "/home/nutanix/bin/idfcli",
    "/usr/local/nutanix/bin/idfcli",
    "idfcli",
)


def idfcli_bin():
    return ups._which(*IDF_BINS)


def _nic_list(row):
    for key in (
            "virtual_nic_uuid_list", "vnic_uuid_list", "virtual_nic_uuids"):
        raw = row.get(key) if isinstance(row, dict) else None
        if raw:
            return ups.as_str_list(raw)
    return []


def index_idf_port_sets(rows):
    """uuid -> {uuid, name, nics} from flattened idfcli port_set rows."""
    out = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        uid = str(row.get("uuid") or row.get("ext_id") or "").strip().lower()
        if not ups.UUID_RE.fullmatch(uid):
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
    payload = ups._json_loads(text)
    if payload is None:
        return []
    return index_idf_port_sets(ups.parse_idf_entities(payload))


def _run_idf_argv(argv, timeout):
    _rc, out, err = ups._run(argv, timeout)
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
            ups.LOG.info("idfcli %s count=%s", entity, len(found))
            return found
        errors.append("%s: %s" % (" ".join(argv), detail))
    raise SystemExit(
        "idfcli port_set returned no entities\n" + "\n".join(errors))


def _fetch_idf_port_sets_smsp(info, timeout):
    """SMSP Atlas port sets live in the flow cluster IDF."""
    tmp = tempfile.mkdtemp(prefix="port_set_kube_")
    kubeconfig = ""
    try:
        kubeconfig, kube_err = ups._flow_kubeconfig(tmp)
        if not kubeconfig:
            return {}, "smsp kubeconfig: %s" % (kube_err or "failed")
        found_pod = ("", "", "no pod")
        for app, preferred in (
                ("atlas", "atlas-0"), ("insights", "insights-0"), ("idf", "idf-0")):
            ns, pod, err = ups._find_pod(app, preferred, "ntnx-flow", kubeconfig)
            if not pod:
                ns, pod, err = ups._find_pod(app, preferred, "", kubeconfig)
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
            _rc, out, err = ups._kubectl(
                ["exec", "-n", ns, pod, "--", "bash", "-lc", inner],
                timeout, kubeconfig=kubeconfig)
            found = parse_idf_stdout(out)
            if found:
                ups.LOG.info(
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
        binary = ups._flow_cli_bin()

        def runner(args, timeout, log_cmd=True, _binary=binary):
            return ups._run_bash_cli(
                ups._cli_join(_binary, args), timeout, log_cmd=log_cmd)

        return runner, cleanup

    tmp = tempfile.mkdtemp(prefix="port_set_kube_")
    kubeconfig, kube_err = ups._flow_kubeconfig(tmp)

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
        ns, pod, err = ups._find_pod("kratos", "kratos-0", "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, err = ups._find_pod("kratos", "kratos-0", "", kubeconfig)
        cli = ""
        if pod:
            cli = ups._pod_bin(
                kubeconfig, ns, pod,
                "command -v kratos_cli || command -v flow_cli || "
                "ls /home/nutanix/flow/bin/kratos_cli "
                "/home/nutanix/flow/bin/flow_cli 2>/dev/null | head -1")
        if pod and cli:
            def runner(args, timeout, log_cmd=True, _cli=cli, _ns=ns, _pod=pod):
                return ups._run_kratos_cli(
                    kubeconfig, _ns, _pod, ups._cli_join(_cli, args),
                    timeout, log_cmd=log_cmd)

            return runner, cleanup
        ups.LOG.warning("kratos cli missing (%s)", err or "no cli")
    smsp_uuid = (info or {}).get("smsp_cluster_uuid") or ""
    if not smsp_uuid:
        _cleanup()
        raise SystemExit(
            "SMSP policy fetch failed: %s" % (kube_err or "no ClusterUUID"))
    binary = ups._flow_cli_bin()
    ws = "ws://smsp-%s.ntnx-ikat.svc:2051/flow_cli" % smsp_uuid

    def runner(args, timeout, log_cmd=True, _binary=binary, _ws=ws):
        return ups._run_bash_cli(
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
        uuids = ups._uuids_from_rows(ups._list_rows(parsed))
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
            ups.LOG.warning("policy.get failed %s of %s", len(failed), len(uuids))
        policies = []
        for rec in gets.values():
            policy = ups.unwrap_policy(rec)
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
    rec = ups._pc_zk_uuids()
    platform = (info or {}).get("platform") or "cmsp"
    if platform != "smsp":
        return scope_uuids_for_platform(
            platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
            "", "")
    atlas = {"global_unique_uuid": "", "vlan_unique_uuid": ""}
    tmp = tempfile.mkdtemp(prefix="port_set_zk_")
    kubeconfig = ""
    try:
        kubeconfig, _err = ups._flow_kubeconfig(tmp)
        if not kubeconfig:
            return scope_uuids_for_platform(
                platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
                "", "")
        ns, pod, _err = ups._find_pod("atlas", "atlas-0", "ntnx-flow", kubeconfig)
        if not pod:
            ns, pod, _err = ups._find_pod("atlas", "atlas-0", "", kubeconfig)
        if not pod:
            return scope_uuids_for_platform(
                platform, rec.get("global_unique_uuid"), rec.get("vlan_unique_uuid"),
                "", "")
        py = "/home/nutanix/.venvs/bin/bin/python3"
        _rc, stdout, stderr = ups._kubectl(
            ["exec", "-n", ns, pod, "--", py, "-c", ups.ATLAS_ZK_PY],
            60, kubeconfig=kubeconfig)
        text = "%s\n%s" % (stdout, stderr)
        for key in ("vlan_unique_uuid", "global_unique_uuid"):
            for line in text.splitlines():
                if key in line:
                    match = ups.UUID_RE.search(line)
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
    return ups.first(rule, key) in (True, "true", "True", "kTrue", 1)


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
            applied.extend(ups.as_uuid_list(ups.values(rule, key)))
    if applied:
        yield ("applied_to", "EG", [applied[0]])
    for flag, endpoint_key, role in (
            ("should_allow_any_src", "src_endpoint", "src_allow_any"),
            ("should_allow_any_dst", "dest_endpoint", "dest_allow_any")):
        if _flag_on(rule, flag) and not ups.values(rule, endpoint_key):
            yield (role, "VM", [])
    has_side = any(
        ups.values(rule, key) for key in (
            "src_endpoint", "dest_endpoint", "secured_group", "endpoint"))
    if not has_side and not applied and not has_applied_key and not any(
            _flag_on(rule, flag) for flag in (
                "should_allow_any_src", "should_allow_any_dst")):
        yield ("dest_allow_any", "VM", [])


def _remember(computed, idf_map, uid, **fields):
    uid = str(uid or "").strip().lower()
    if not ups.UUID_RE.fullmatch(uid):
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


def _skip_idf_only(rec):
    name = str((rec or {}).get("name") or "")
    if name.startswith("K8s_"):
        return True
    if name.startswith("Quarantine") and not (rec or {}).get("nics"):
        return True
    return False


def mismatch_rows(policies, vlan_uuid, global_uuid, idf_map, include_project=False):
    """One row per port_set UUID that is missing on either side."""
    idf_map = idf_map or {}
    computed = {}
    for policy in policies or []:
        annotated, _extra = ups.annotate_policy(
            policy, vlan_uuid, global_uuid, include_project)
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
        project = ups.first(policy, "project_uuid") or ups.ZERO
        project_arg = project if include_project else None
        vpc_uuids = ups.policy_vpc_uuids(policy)
        for rkey, rule in ups.iter_rules(policy):
            is_flex = (
                ups.rule_is_flex(rule, annotated.get("policy_type"))
                or rkey == "flex_policy_rule")
            if not is_flex:
                continue
            info = ups.first(rule, "rule_info") or {}
            if not isinstance(info, dict):
                info = {}
            rule_uuid = (
                ups.first(info, "uuid") or ups.first(rule, "uuid") or "")
            unique = ups.scope_unique_uuid(
                annotated.get("scope") or "kAllVlan", True,
                vlan_uuid, global_uuid, vpc_uuids)
            for role, entity_type, refs in flex_extra_selectors(rule):
                hashed, _body = ups.generate_port_set_id(
                    entity_type, refs, unique, project_arg, is_flex=True)
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
    for uid in sorted(computed):
        slot = computed[uid]
        if slot.pop("present"):
            continue
        rows.append(slot)
    for uid in sorted(idf_map):
        if uid in computed:
            continue
        rec = idf_map[uid]
        if _skip_idf_only(rec):
            continue
        rows.append({
            "mismatch": "idf_without_computed",
            "port_set": uid,
            "idf_name": rec.get("name") or "",
            "policy": "",
            "policy_uuid": "",
            "rule_uuid": "",
            "role": "",
            "entity_type": "",
            "scope": "",
            "refs": "",
            "components": 0,
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
    global_uuid = "702970d3-d72d-41b9-9655-50c40ffd96f4"
    vlan_uuid = "29332a4d-9133-4c73-a219-ce82ea53d532"
    eg = "407982f9-5504-4504-a42d-78143d09f3fe"
    hashed, _body = ups.generate_port_set_id(None, [eg], global_uuid)
    expect = "917386ac-6978-5da1-91a6-3782ffebd275"
    if hashed != expect:
        raise SystemExit("hash mismatch: %s != %s" % (hashed, expect))
    other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_hash, _body = ups.generate_port_set_id(None, [other], global_uuid)
    policy = {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "name": "T",
        "mode": "kApply",
        "policy_type": "kApplication",
        "scope": "kGlobal",
        "project_uuid": ups.ZERO,
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
    rows = mismatch_rows([policy], vlan_uuid, global_uuid, idf_map)
    kinds = {(row["mismatch"], row["port_set"]) for row in rows}
    if ("computed_without_idf", expect) not in kinds:
        raise SystemExit("missing computed mismatch: %s" % rows)
    if ("idf_without_computed", lone) not in kinds:
        raise SystemExit("missing idf mismatch: %s" % rows)
    if any(row["port_set"] == other_hash for row in rows):
        raise SystemExit("matched port_set was printed: %s" % rows)
    if any(row["idf_name"].startswith("K8s_") or
           row["idf_name"].startswith("Quarantine") for row in rows):
        raise SystemExit("skipped idf port_set was printed: %s" % rows)
    flex_unique = ups.VLAN_SCOPE_UNIQUE_ID
    src_eg = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    applied_eg = eg
    src_hash, _body = ups.generate_port_set_id(
        "EG", [src_eg], flex_unique, is_flex=True)
    applied_hash, _body = ups.generate_port_set_id(
        "EG", [applied_eg], flex_unique, is_flex=True)
    any_hash, _body = ups.generate_port_set_id(
        "VM", [], flex_unique, is_flex=True)
    global_src = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    global_hash, _body = ups.generate_port_set_id(
        "EG", [global_src], flex_unique, is_flex=True)
    flex = {
        "uuid": "44444444-4444-4444-4444-444444444444",
        "name": "FlexT",
        "mode": "kApply",
        "policy_type": "kFlex",
        "scope": "kAllVlan",
        "project_uuid": ups.ZERO,
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
        "project_uuid": ups.ZERO,
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
        [policy, flex, flex_global], vlan_uuid, global_uuid, flex_idf)
    flex_kinds = {(row["mismatch"], row["port_set"], row["role"]) for row in flex_rows}
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
        help="Append :project:<uuid> when hashing (validator default is off)")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    ups.setup_logging()
    if args.self_test:
        self_test()
        return 0
    info = ups.detect_platform()
    global_uuid, vlan_uuid = fetch_unique_uuids(info)
    if not global_uuid or not vlan_uuid:
        raise SystemExit(
            "missing vlan/global unique uuid (zkcat / atlas ZK)")
    policies = fetch_policies(info, workers=args.workers, timeout=args.timeout)
    if not policies:
        raise SystemExit("no policies from flow_cli")
    idf_map = fetch_idf_port_sets(info, timeout=min(int(args.timeout), 600))
    rows = mismatch_rows(
        policies, vlan_uuid, global_uuid, idf_map,
        include_project=args.include_project)
    ups.LOG.info(
        "policies=%s idf_port_sets=%s mismatches=%s",
        len(policies), len(idf_map), len(rows))
    if not rows:
        return 0
    write_rows(rows, sys.stdout)
    return 1


if __name__ == "__main__":
    sys.exit(main())
