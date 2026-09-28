from __future__ import annotations

from typing import Any


def _query_rows(db_client: Any, table: str, context: dict[str, Any], extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
  params = {
    'bundle_id': context.get('bundle_id'),
    'start_time': context.get('start_time'),
    'end_time': context.get('end_time'),
  }
  if context.get('degraded_svm_ip'):
    params['degraded_svm_ip'] = context['degraded_svm_ip']
  if context.get('cvm_ip'):
    params['cvm_ip'] = context['cvm_ip']
  if context.get('host_ip'):
    params['host_ip'] = context['host_ip']
  if context.get('peer_ip'):
    params['peer_ip'] = context['peer_ip']
  if extra:
    params.update(extra)
  try:
    rows = db_client.query(table, **params)
    return rows if isinstance(rows, list) else []
  except Exception:
    return []


def _search_rows(db_client: Any, context: dict[str, Any], patterns: list[str]) -> list[dict[str, Any]]:
  try:
    rows = db_client.search_logs(
      table='nu_logs_local',
      bundle_id=context.get('bundle_id'),
      start_time=context.get('start_time'),
      end_time=context.get('end_time'),
      svm_ip=context.get('degraded_svm_ip') or context.get('cvm_ip'),
      patterns=patterns,
    )
    return rows if isinstance(rows, list) else []
  except Exception:
    return []


def _result(skill: str, status: str, context: dict[str, Any], observations: list[dict[str, Any]], evidence: list[dict[str, Any]], gaps: list[str], suggested: list[dict[str, str]] | None = None) -> dict[str, Any]:
  return {
    'skill': skill,
    'status': status,
    'entity_context': context,
    'observations': observations,
    'suggested_checks': suggested or [],
    'evidence': evidence,
    'evidence_gaps': gaps,
  }


def _is_overlap(row: dict[str, Any]) -> bool:
  message = str(row.get('message', '')).lower()
  return any([
    row.get('await_ms', 0) > row.get('await_threshold_ms', 0),
    row.get('latency_ms', 0) > row.get('latency_threshold_ms', 0),
    row.get('queue_depth', 0) > row.get('queue_threshold', 0),
    'hba lockup' in message,
    'io error' in message,
    'stuck operation' in message,
  ])


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  rows = []
  for table in [
      'nu_metrics_sysstats',
      'nu_metrics_sysstats_anomaly',
      'nu_storage_container_usage',
      'nu_storage_container_savings',
      'nu_storage_container_garbage',
      'nu_events',
  ]:
    rows.extend(_query_rows(db_client, table, context))
  rows.extend(_search_rows(db_client, context, ['hba', 'disk error', 'io error', 'stuck operation', 'await']))

  if not rows:
    return _result('network-storage-io', 'NO_STORAGE_IO_EVIDENCE', context, [], [], ['No storage/IO evidence'])

  overlap = [row for row in rows if _is_overlap(row)]
  if overlap:
    return _result('network-storage-io', 'STORAGE_IO_OVERLAP', context, [{'type': 'STORAGE_IO_OVERLAP', 'count': len(overlap)}], overlap, [])
  return _result('network-storage-io', 'NO_STORAGE_IO_OVERLAP', context, [], rows, [])
