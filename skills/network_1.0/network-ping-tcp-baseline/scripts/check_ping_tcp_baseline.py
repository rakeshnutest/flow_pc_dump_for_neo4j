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

PING_TCP_SUGGESTIONS = [
  'network-firewall-iptables',
  'network-nic-mtu-ncc',
  'network-cassandra-metadata',
  'network-ovs-host-evidence',
]


def _is_issue(row: dict[str, Any]) -> bool:
  message = str(row.get('message', '')).lower()
  return any([
    row.get('packet_loss', 0) > 0,
    row.get('retransmits', 0) > 0,
    row.get('latency_ms', 0) > row.get('latency_threshold_ms', 0),
    row.get('cqi_score', 100) < row.get('cqi_threshold', 70),
    'timeout' in message,
    'unreachable' in message,
    'connection refused' in message,
  ])


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  metric_rows = _query_rows(db_client, 'nu_metrics_sysstats', context)
  anomaly_rows = _query_rows(db_client, 'nu_metrics_sysstats_anomaly', context)
  log_rows = _search_rows(db_client, context, ['timeout', 'unreachable', 'retransmit', 'connection refused'])
  all_rows = metric_rows + anomaly_rows + log_rows
  if not all_rows:
    return _result('network-ping-tcp-baseline', 'EVIDENCE_INSUFFICIENT', context, [], [], ['No ping/TCP evidence rows'])

  issues = [row for row in all_rows if _is_issue(row)]
  if not issues:
    return _result('network-ping-tcp-baseline', 'NO_PING_TCP_ISSUE', context, [], all_rows, [])

  observations = [{'type': 'PING_TCP_ISSUE', 'count': len(issues)}]
  suggested = [{'skill': item, 'reason': 'Ping/TCP issue signal exists'} for item in PING_TCP_SUGGESTIONS]
  return _result('network-ping-tcp-baseline', 'PING_TCP_ISSUE_FOUND', context, observations, issues, [], suggested)
