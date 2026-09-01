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

NIC_SUGGESTIONS = [
  'network-host-pressure',
  'network-upgrade-config-change',
  'network-ovs-host-evidence',
]


def _is_issue(row: dict[str, Any]) -> bool:
  message = str(row.get('message', '')).lower()
  status = str(row.get('status', '')).upper()
  return any([
    status in {'FAIL', 'FAILED', 'ERROR', 'WARN'},
    row.get('mtu_mismatch') is True,
    row.get('link_state') == 'down',
    'link down' in message,
    'bond failure' in message,
    'mtu mismatch' in message,
    'ncc' in message and 'fail' in message,
  ])


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
  rows = []
  for table in [
      'nu_config_ncc_checks',
      'nu_config_network_nics',
      'nu_config_network_bonds',
      'nu_config_network_nic_settings',
      'nu_config_network_nic_features',
  ]:
    rows.extend(_query_rows(db_client, table, context))
  rows.extend(_search_rows(db_client, context, ['nic', 'link down', 'bond', 'mtu', 'ncc']))

  if not rows:
    return _result('network-nic-mtu-ncc', 'EVIDENCE_INSUFFICIENT', context, [], [], ['No NIC/MTU/NCC evidence rows'])

  issues = [row for row in rows if _is_issue(row)]
  if not issues:
    return _result('network-nic-mtu-ncc', 'NO_NIC_MTU_NCC_ISSUE', context, [], rows, [])

  observations = [{'type': 'NIC_MTU_NCC_ISSUE', 'count': len(issues)}]
  suggested = [{'skill': item, 'reason': 'NIC/MTU/NCC issue may have host/change overlap'} for item in NIC_SUGGESTIONS]
  return _result('network-nic-mtu-ncc', 'NIC_MTU_NCC_ISSUE_FOUND', context, observations, issues, [], suggested)
