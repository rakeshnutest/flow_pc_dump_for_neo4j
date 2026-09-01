---
name: network-storage-io
description: >-
  Atomic network RCA skill for Panacea 1.0 port that runs one deterministic
  diagnostic intent and returns evidence plus gaps.
skill_type: atomic
component: networking
sub_component: network_storage_io
keywords:
  - network-rca-1.0
  - deterministic
  - clickhouse-evidence
symptoms:
  - "network-storage-io evidence needed for network RCA"
severity: P0-P2
roles_allowed: [engineer, sre]
mcp_capabilities_required:
  - logs.search
last_verified: 2026-07-14
---

## Purpose
Run one independent check using existing Panacea evidence and return
status, observations, evidence, suggested checks, and evidence gaps.

## Decision Tree
- If required source coverage is missing -> `EVIDENCE_INSUFFICIENT`.
- If scoped issue evidence exists -> positive `*_FOUND` or `*_OVERLAP`.
- If coverage exists without issue signal -> `NO_*` result.

## Procedure 1
Collect scoped evidence from existing Panacea data surfaces by bundle,
time window, and entity/pair context.

## Procedure 2
Apply deterministic classification logic and produce stable JSON output.

## See also
- [network-rca-orchestrator](../network-rca-orchestrator/SKILL.md)
