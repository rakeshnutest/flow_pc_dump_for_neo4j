---
name: ovn-path-test
description: >-
  Test all 5 OVN scenarios into .md files, then composite-eval upstream and
  downstream (ACL, L2, L3, GW, External). Use with ovn-path-trace,
  ovn-path-upstream, ovn-path-downstream.
---

# Test 5 scenarios (composites)

Identity is UUID. DB `flow_ovn` `127.0.0.1:19000`.

**Read:** `ovn-path-trace`, `ovn-path-upstream`, `ovn-path-downstream`.

| # | id | Upstream/downstream must |
|---|---|---|
| 1 | `same_l2` | ACL+L2 PASS; L3/GW/External N/A |
| 2 | `l2_l3_l2` | ACL+L2+L3 PASS |
| 3 | `two_router` | ACL+L2+L3 PASS (two Routers or transit) |
| 4 | `northbound` | all five; GW+External PASS |
| 5 | `acl_drop` | ACL has drop; other layers as on path |

```bash
PY=/home/rakeshkumar.r/panacea/clickhouse_ovn/trace.py
CK=/home/rakeshkumar.r/panacea/.cursor/skills/ovn-path-eval/scripts/check_trace.py
python3 "$PY" --run-scenarios
# writes clickhouse_ovn/out/scenarios.md and out/<id>.md
python3 "$CK" --scenario northbound /home/rakeshkumar.r/panacea/clickhouse_ovn/out/northbound.md
```

Each file must contain both composite mermaids. Report 5 rows: id, COMPOSITE PASS/FAIL.

Never `.txt`. Checker only accepts `.md`.
