#!/usr/bin/env python3
"""After ingest, stamp match/mismatch and print PASS/FAIL.

Uses ReplacingMergeTree inserts (not ALTER UPDATE). Match is computed in
Python from UUID arrays only. Stamp INSERT SELECT copies rows by port-set
UUID chunks and never groupArray's rule_u_sg or 9-field nic tuples.
only_computed_nics / only_atlas_nics are left empty (scorecard uses
mismatch_kind and UUID presence).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
ZERO = "00000000-0000-0000-0000-000000000000"
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I)
# FINAL rows per INSERT. One UUID larger than this is still its own chunk.
STAMP_ROWS = 50
EMPTY_NICS = (
    "CAST([], 'Array(Tuple(String, UUID, String, String, String, "
    "UUID, String, UUID, String))')"
)
STAMP_SETTINGS = (
    "SETTINGS max_insert_block_size = 32, "
    "max_block_size = 32, "
    "max_threads = 1, "
    "max_memory_usage = 8000000000"
)

LIGHT_SQL = """
SELECT
    toString(port_set_uuid),
    toString(anyIf(computed_port_set_uuid,
                   computed_port_set_uuid != toUUID('%(z)s'))),
    toString(anyIf(atlas_port_set_uuid,
                   atlas_port_set_uuid != toUUID('%(z)s'))),
    arraySort(arrayDistinct(arrayFlatten(groupArray(computed_nic_uuids))))
        = arraySort(arrayDistinct(arrayFlatten(groupArray(atlas_nic_uuids)))),
    count()
FROM flow_policy.portset
FINAL
WHERE log_bundle_id = %(bid)d
GROUP BY port_set_uuid
ORDER BY count(), port_set_uuid
FORMAT TabSeparated
"""

STAMP_SQL = """
INSERT INTO flow_policy.portset
SELECT
    p.* EXCEPT (match_status, mismatch_kind, only_computed_nics, only_atlas_nics, all_ports, updated_at),
    a.match_status,
    a.mismatch_kind,
    %(empty)s AS only_computed_nics,
    %(empty)s AS only_atlas_nics,
    p.all_ports,
    now64()
FROM flow_policy.portset AS p FINAL
INNER JOIN
(
    %(match_rows)s
) AS a USING (log_bundle_id, port_set_uuid)
WHERE p.log_bundle_id = %(bid)d
  AND p.port_set_uuid IN (%(uuids)s)
%(settings)s
"""

SCORE_SQL = """
SELECT
  uniqExact(port_set_uuid) AS total,
  uniqExactIf(port_set_uuid, match_status = 'match') AS pass_both,
  uniqExactIf(port_set_uuid, mismatch_kind = 'computed_without_atlas') AS fail_computed_only,
  uniqExactIf(port_set_uuid, mismatch_kind = 'atlas_without_computed'
              AND NOT startsWith(atlas_name, 'K8s_')
              AND NOT (startsWith(atlas_name, 'Quarantine')
                       AND empty(atlas_nic_uuids))) AS fail_atlas_only,
  uniqExactIf(port_set_uuid, mismatch_kind = 'atlas_without_computed'
              AND startsWith(atlas_name, 'K8s_')) AS kube_atlas,
  uniqExactIf(port_set_uuid, mismatch_kind = 'atlas_without_computed'
              AND startsWith(atlas_name, 'Quarantine')
              AND empty(atlas_nic_uuids)) AS quarantine_empty,
  uniqExactIf(port_set_uuid, mismatch_kind = 'nic_set') AS fail_nic_set,
  uniqExactIf(port_set_uuid, mismatch_kind = 'nic_set'
              AND empty(computed_nic_uuids) AND notEmpty(atlas_nic_uuids)) AS fail_nic_computed_empty,
  countIf(startsWith(role, 'isolation')) AS isolation_rows,
  countIf(startsWith(role, 'isolation')
          AND computed_port_set_uuid = atlas_port_set_uuid
          AND atlas_port_set_uuid != toUUID('%(z)s')) AS isolation_hash_ok,
  countIf(startsWith(role, 'isolation') AND match_status = 'match') AS isolation_nic_ok
FROM flow_policy.portset
FINAL
WHERE log_bundle_id = %(bid)d
FORMAT TabSeparated
"""

SAMPLE_SQL = """
SELECT
    toString(port_set_uuid),
    any(mismatch_kind),
    any(length(only_computed_nics)),
    any(length(only_atlas_nics))
FROM flow_policy.portset
FINAL
WHERE log_bundle_id = %(bid)d
  AND match_status = 'mismatch'
GROUP BY port_set_uuid
ORDER BY (any(length(only_computed_nics)) + any(length(only_atlas_nics))) DESC
LIMIT {limit}
FORMAT TabSeparated
"""


def ch_query(sql):
    cmd = [
        "clickhouse-client",
        "--host", CH_HOST,
        "--port", CH_NATIVE,
        "--user", "default",
        "--send_timeout", "600",
        "--receive_timeout", "600",
        "--query", sql,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "ch failed")
    return proc.stdout


def fmt_uuids(uuids):
    out = []
    for value in uuids:
        text = str(value).strip().lower()
        if not UUID_RE.match(text):
            raise RuntimeError("bad port_set_uuid %r" % value)
        out.append("toUUID('%s')" % text)
    return ", ".join(out)


def match_fields(computed_uuid, atlas_uuid, nics_eq):
    computed_ok = computed_uuid != ZERO
    atlas_ok = atlas_uuid != ZERO
    if computed_ok and atlas_ok and nics_eq:
        return "match", ""
    if computed_ok and not atlas_ok:
        return "mismatch", "computed_without_atlas"
    if atlas_ok and not computed_ok:
        return "mismatch", "atlas_without_computed"
    return "mismatch", "nic_set"


def uuid_chunks(rows):
    chunk = []
    nsum = 0
    for item, n_rows in rows:
        n_rows = max(int(n_rows), 1)
        if chunk and (nsum + n_rows > STAMP_ROWS):
            yield chunk
            chunk = []
            nsum = 0
        chunk.append(item)
        nsum += n_rows
        if nsum >= STAMP_ROWS:
            yield chunk
            chunk = []
            nsum = 0
    if chunk:
        yield chunk


def latest_log_bundle_id():
    out = ch_query(
        "SELECT log_bundle_id FROM flow_policy.bundle "
        "ORDER BY updated_at DESC LIMIT 1")
    text = (out or "").strip()
    if not text:
        raise SystemExit("no flow_policy.bundle rows; ingest with --log_bundle_id first")
    return int(text.splitlines()[0])


def env_or_latest_bundle(explicit=0):
    if explicit and int(explicit) > 0:
        return int(explicit)
    env = os.environ.get("PANACEA_LOG_BUNDLE_ID") or os.environ.get("LOG_BUNDLE_ID")
    if env:
        return int(env)
    return latest_log_bundle_id()


def stamp_match(bid):
    rows = []
    for line in ch_query(LIGHT_SQL % {"z": ZERO, "bid": bid}).splitlines():
        if not line.strip():
            continue
        uuid_text, computed_uuid, atlas_uuid, nics_eq, n_rows = line.split("\t")
        uuid_text = uuid_text.strip().lower()
        computed_uuid = computed_uuid.strip().lower()
        atlas_uuid = atlas_uuid.strip().lower()
        status, kind = match_fields(computed_uuid, atlas_uuid, nics_eq == "1")
        rows.append(((uuid_text, status, kind), n_rows))
    if not rows:
        raise RuntimeError("no port_set_uuid rows to stamp")
    done = 0
    total = len(rows)
    for chunk in uuid_chunks(rows):
        match_parts = []
        uuids = []
        for uuid_text, status, kind in chunk:
            if not UUID_RE.match(uuid_text):
                raise RuntimeError("bad port_set_uuid %r" % uuid_text)
            match_parts.append(
                "SELECT %d AS log_bundle_id, toUUID('%s') AS port_set_uuid, "
                "'%s' AS match_status, '%s' AS mismatch_kind"
                % (bid, uuid_text, status, kind))
            uuids.append(uuid_text)
        ch_query(STAMP_SQL % {
            "empty": EMPTY_NICS,
            "match_rows": " UNION ALL ".join(match_parts),
            "uuids": fmt_uuids(uuids),
            "settings": STAMP_SETTINGS,
            "bid": bid,
        })
        done += len(chunk)
        sys.stderr.write("stamped %s / %s port-set uuids\n" % (done, total))
        sys.stderr.flush()


def line(verdict, name, got, need):
    print("%-4s  %-42s  %s / %s" % (verdict, name, got, need))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mismatch_limit", type=int, default=15)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--log_bundle_id",
        type=int,
        default=0,
        help="Panacea log_bundle_id (default: latest flow_policy.bundle)")
    args = parser.parse_args()
    bid = env_or_latest_bundle(args.log_bundle_id)
    sys.stderr.write("log_bundle_id=%s\n" % bid)
    sys.stderr.flush()

    stamp_match(bid)
    parts = ch_query(SCORE_SQL % {"z": ZERO, "bid": bid}).strip().split("\t")
    (total, pass_both, fail_computed, fail_atlas, kube_atlas,
     quarantine_empty, fail_nic, fail_nic_empty, iso_rows, iso_hash,
     iso_nic) = [int(x) for x in parts]

    comparable = total - kube_atlas - quarantine_empty
    expected_match = comparable - fail_atlas
    iso_hash_pass = iso_rows > 0 and iso_hash == iso_rows
    iso_nic_pass = iso_rows > 0 and iso_nic == iso_rows
    uuid_pass = fail_computed == 0
    nic_pass = fail_nic == 0
    both_pass = pass_both == expected_match and expected_match > 0
    overall = (
        both_pass and iso_hash_pass and iso_nic_pass and uuid_pass
        and nic_pass and fail_atlas == 0)

    print("RESULT  %s" % ("PASS" if overall else "FAIL"))
    print("")
    line("PASS" if both_pass else "FAIL",
         "Port-set UUID and NIC set match Atlas", pass_both, expected_match)
    line("PASS" if iso_hash_pass else "FAIL",
         "Isolation hash UUID in Atlas", iso_hash, iso_rows)
    line("PASS" if iso_nic_pass else "FAIL",
         "Isolation NIC UUID set matches Atlas", iso_nic, iso_rows)
    line("PASS" if fail_computed == 0 else "FAIL",
         "Computed UUID missing from Atlas (need 0)", fail_computed, 0)
    line("PASS" if fail_atlas == 0 else "FAIL",
         "Atlas UUID missing from computed (need 0)", fail_atlas, 0)
    line("PASS" if nic_pass else "FAIL",
         "NIC UUID sets differ (need 0)", fail_nic, 0)
    if fail_nic_empty:
        print("      computed NIC list empty, Atlas has NICs: %s" % fail_nic_empty)

    if args.verbose and (fail_computed or fail_atlas or fail_nic):
        sample_sql = SAMPLE_SQL.replace(
            "{limit}", str(max(1, int(args.mismatch_limit)))) % {"bid": bid}
        print("")
        print("mismatch samples")
        print(ch_query(sample_sql).rstrip())

    if not overall:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
