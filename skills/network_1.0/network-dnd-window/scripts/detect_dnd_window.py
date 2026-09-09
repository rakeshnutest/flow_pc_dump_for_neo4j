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

DND_SUGGESTIONS = [
  'network-cassandra-metadata',
  'network-firewall-iptables',
  'network-nic-mtu-ncc',
  'network-host-pressure',
  'network-storage-io',
  'network-upgrade-config-change',
  'network-ovs-host-evidence',
]


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  windows = _query_rows(db_client, 'nu_rca_dnd_windows', context)
  if windows:
    obs = [{'type': 'DND_WINDOW', 'count': len(windows)}]
    sug = [{'skill': item, 'reason': 'DND-local signal exists'} for item in DND_SUGGESTIONS]
    return _result('network-dnd-window', 'DND_SIGNAL_FOUND', context, obs, windows, [], sug)

  log_rows = _search_rows(db_client, context, ['degraded node', 'DND', 'zookeeper_monitor'])
  if log_rows:
    obs = [{'type': 'DND_LOG_SIGNAL', 'count': len(log_rows)}]
    sug = [{'skill': item, 'reason': 'DND log signal exists'} for item in DND_SUGGESTIONS]
    return _result('network-dnd-window', 'DND_SIGNAL_FOUND', context, obs, log_rows, [], sug)

  coverage = _query_rows(db_client, 'nu_data_availability', context, {'source_hint': 'zookeeper'})
  if coverage:
    return _result('network-dnd-window', 'NO_DND_EVIDENCE', context, [], coverage, [])

  return _result('network-dnd-window', 'EVIDENCE_INSUFFICIENT', context, [], [], ['Missing DND logs/coverage'])
