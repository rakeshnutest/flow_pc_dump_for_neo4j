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


def _is_change(row: dict[str, Any]) -> bool:
  text = f"{row.get('message', '')} {row.get('changed_field', '')}".lower()
  return any(token in text for token in ['upgrade', 'lcm', 'firmware', 'driver', 'mtu', 'bond', 'nic', 'interface'])


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  rows = []
  rows.extend(_search_rows(db_client, context, ['upgrade', 'lcm', 'firmware', 'driver', 'mtu', 'bond', 'nic']))
  rows.extend(_query_rows(db_client, 'nu_events', context))
  for table in [
      'nu_config_network_nics',
      'nu_config_network_bonds',
      'nu_config_network_nic_settings',
      'nu_config_network_nic_features',
  ]:
    rows.extend(_query_rows(db_client, table, context))

  if not rows:
    return _result('network-upgrade-config-change', 'NO_CHANGE_EVIDENCE', context, [], [], ['No upgrade/config-change evidence'])

  changes = [row for row in rows if _is_change(row)]
  if changes:
    return _result('network-upgrade-config-change', 'RELEVANT_CHANGE_FOUND', context, [{'type': 'RELEVANT_CHANGE', 'count': len(changes)}], changes, [])
  return _result('network-upgrade-config-change', 'NO_RELEVANT_CHANGE_FOUND', context, [], rows, [])
