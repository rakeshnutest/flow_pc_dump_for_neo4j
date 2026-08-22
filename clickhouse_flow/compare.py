#!/usr/bin/env python3
"""After ingest, stamp match/mismatch and print PASS/FAIL.

Uses ReplacingMergeTree inserts (not ALTER UPDATE). No JSON.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

CH_HOST = "127.0.0.1"
CH_NATIVE = "19000"
ZERO = "00000000-0000-0000-0000-000000000000"

STAMP_SQL = """
INSERT INTO flow_policy.portset
SELECT
    p.* EXCEPT (match_status, mismatch_kind, only_computed_nics, only_atlas_nics, all_ports, updated_at),
    a.match_status,
    a.mismatch_kind,
    a.only_computed_nics,
    a.only_atlas_nics,
    p.all_ports,
    now64()
FROM flow_policy.portset AS p
INNER JOIN
(
    SELECT
        port_set_uuid,
        if(computed_uuid != toUUID('%(z)s')
           AND atlas_uuid != toUUID('%(z)s')
           AND computed_uuids = atlas_uuids,
           'match', 'mismatch') AS match_status,
        if(computed_uuid != toUUID('%(z)s')
           AND atlas_uuid != toUUID('%(z)s')
           AND computed_uuids = atlas_uuids,
           '',
           if(computed_uuid != toUUID('%(z)s') AND atlas_uuid = toUUID('%(z)s'),
              'computed_without_atlas',
              if(computed_uuid = toUUID('%(z)s') AND atlas_uuid != toUUID('%(z)s'),
                 'atlas_without_computed',
                 'nic_set'))) AS mismatch_kind,
        arrayFilter(
            x -> NOT has(atlas_uuids, tupleElement(x, 2)),
            computed_tuples) AS only_computed_nics,
        arrayFilter(
            x -> NOT has(computed_uuids, tupleElement(x, 2)),
            atlas_tuples) AS only_atlas_nics
    FROM
    (
        SELECT
            port_set_uuid,
            anyIf(computed_port_set_uuid, computed_port_set_uuid != toUUID('%(z)s')) AS computed_uuid,
            anyIf(atlas_port_set_uuid, atlas_port_set_uuid != toUUID('%(z)s')) AS atlas_uuid,
            arraySort(arrayDistinct(arrayFlatten(groupArray(computed_nic_uuids)))) AS computed_uuids,
            arraySort(arrayDistinct(arrayFlatten(groupArray(atlas_nic_uuids)))) AS atlas_uuids,
            arrayDistinct(arrayFlatten(groupArray(computed_nics))) AS computed_tuples,
            arrayDistinct(arrayFlatten(groupArray(atlas_nics))) AS atlas_tuples
        FROM flow_policy.portset
        GROUP BY port_set_uuid
    )
) AS a USING (port_set_uuid)
""" % {"z": ZERO}

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
FORMAT TabSeparated
""" % {"z": ZERO}

SAMPLE_SQL = """
SELECT
    toString(port_set_uuid),
    any(mismatch_kind),
    any(length(only_computed_nics)),
    any(length(only_atlas_nics))
FROM flow_policy.portset
FINAL
WHERE match_status = 'mismatch'
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
        "--query", sql,
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "ch failed")
    return proc.stdout


def line(verdict, name, got, need):
    print("%-4s  %-42s  %s / %s" % (verdict, name, got, need))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mismatch_limit", type=int, default=15)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    ch_query(STAMP_SQL)
    parts = ch_query(SCORE_SQL).strip().split("\t")
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
            "{limit}", str(max(1, int(args.mismatch_limit))))
        print("")
        print("mismatch samples")
        print(ch_query(sample_sql).rstrip())

    if not overall:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
