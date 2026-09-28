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


def _relevant(row: dict[str, Any], context: dict[str, Any]) -> bool:
  values = {
    row.get('source_ip'),
    row.get('destination_ip'),
    row.get('local_ip'),
    row.get('remote_ip'),
  }
  scoped = {
    context.get('cvm_ip'),
    context.get('degraded_svm_ip'),
    context.get('peer_ip'),
  }
  return bool(values.intersection(scoped))


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  rows = _search_rows(db_client, context, ['DROP', 'REJECT', 'packet dropped', 'iptables', 'firewall'])
  event_rows = _query_rows(db_client, 'nu_events', context)
  rows.extend(event_rows)
  if not rows:
    return _result('network-firewall-iptables', 'NO_DROP_EVIDENCE', context, [], [], ['No firewall/iptables evidence'])

  relevant = [row for row in rows if _relevant(row, context)]
  if relevant:
    return _result('network-firewall-iptables', 'FIREWALL_DROP_FOUND', context, [{'type': 'DROP', 'count': len(relevant)}], relevant, [])
  return _result('network-firewall-iptables', 'DROP_NOT_RELEVANT', context, [], rows, [])
