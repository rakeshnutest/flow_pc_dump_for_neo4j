#!/usr/bin/env python3
"""After ingest, stamp match/mismatch and NIC diffs onto each portset row.

Uses ReplacingMergeTree inserts (not ALTER UPDATE). No JSON.

Mismatch when exactly one of computed_port_set_uuid / atlas_port_set_uuid
is present, or both present but NIC UUID sets differ. Leftover Atlas-only
rows stay mismatches. Kube leftovers are ingested; leftover analysis that
ignores kube is observe_leftovers.py, not this script.
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
    p.* EXCEPT (match_status, mismatch_kind, only_computed_nics, only_atlas_nics, updated_at),
    a.match_status,
    a.mismatch_kind,
    a.only_computed_nics,
    a.only_atlas_nics,
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

COUNTS_SQL = """
SELECT
    match_status,
    mismatch_kind,
    uniqExact(port_set_uuid) AS port_sets,
    count() AS rows
FROM flow_policy.portset
FINAL
GROUP BY match_status, mismatch_kind
ORDER BY match_status, mismatch_kind
FORMAT TabSeparatedWithNames
"""

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

ROW_SQL = """
SELECT
    toString(port_set_uuid),
    match_status,
    mismatch_kind,
    toString(arraySlice(only_computed_nics, 1, {nic_limit})),
    toString(arraySlice(only_atlas_nics, 1, {nic_limit}))
FROM flow_policy.portset
FINAL
WHERE port_set_uuid = toUUID('{ps}')
LIMIT 1
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mismatch_limit", type=int, default=15)
    parser.add_argument("--nic_limit", type=int, default=20)
    args = parser.parse_args()
    nic_limit = max(1, int(args.nic_limit))

    print("stamping match_status onto flow_policy.portset")
    ch_query(STAMP_SQL)

    print("counts")
    print(ch_query(COUNTS_SQL).rstrip())

    sample_sql = SAMPLE_SQL.replace("{limit}", str(max(1, int(args.mismatch_limit))))
    samples = []
    for line in ch_query(sample_sql).splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        samples.append(parts)

    print("mismatch_port_sets_shown", len(samples))
    mismatch_n = 0
    match_line = ch_query(
        "SELECT uniqExactIf(port_set_uuid, match_status = 'match') "
        "FROM flow_policy.portset FINAL").strip()
    mismatch_n = int(ch_query(
        "SELECT uniqExactIf(port_set_uuid, match_status = 'mismatch') "
        "FROM flow_policy.portset FINAL").strip() or "0")
    print("match_port_sets", match_line)
    print("mismatch_port_sets", mismatch_n)

    for parts in samples:
        ps, kind, only_c, only_a = parts[0], parts[1], parts[2], parts[3]
        row_sql = ROW_SQL.format(nic_limit=nic_limit, ps=ps)
        row = ch_query(row_sql).rstrip().split("\t")
        print(
            "MISMATCH", kind,
            "port_set_uuid", ps,
            "only_computed_nics", only_c,
            "only_atlas_nics", only_a)
        if len(row) >= 5:
            print("  computed_nics - atlas_nics", row[3])
            print("  atlas_nics - computed_nics", row[4])

    leftover = mismatch_n - len(samples)
    if leftover > 0:
        print("... %s more mismatches" % leftover)

    if mismatch_n:
        sys.exit(1)
    if int(match_line or "0") <= 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
