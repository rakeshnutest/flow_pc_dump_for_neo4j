"""Product entrypoint: network-sar-debugging from ClickHouse (nu_metrics_sysstats).

Ingestion (panacea-ingestion-pipeline → ntnx_metric_parser) lands SAR / ping /
host_nic / ethtool / bond metrics into ``panacea.nu_metrics_sysstats``. This
script is what Panacea product skills call via ``run(db_client, context)``.

Offline diamond/logbay file analysis remains in ``analyze_sar_network.py``.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

# Metrics written by panacea-ingestion-pipeline (PR #408 / feat/sar-error-and-iface-metrics)
SAR_RX = "sar_rx_packets_per_sec"
SAR_TX = "sar_tx_packets_per_sec"
SAR_RX_DROP = "sar_rx_drops_per_sec"
SAR_RX_ERR = "sar_rx_errors_per_sec"
PING_LOST = "ping_all_lost_pkt"
PING_UNREACH = "ping_all_unreachable"
PING_LAT = "ping_all_latency"
HOST_NIC_DROP = "host_nic_rx_dropped"
HOST_NIC_CRC = "host_nic_rx_crc_errors"
ETHTOOL_DROP = "ethtool_rx_dropped"
ETHTOOL_CRC = "ethtool_rx_crc_errors"
BOND_ACTIVE = "bond_member_active"
BOND_ENABLED = "bond_member_enabled"

RX_FLOOD_THRESH = 100_000.0
RX_FLOOD_STRONG = 500_000.0
CORR_WINDOW_SEC = 120.0

NETWORK_METRICS = {
    SAR_RX,
    SAR_TX,
    SAR_RX_DROP,
    SAR_RX_ERR,
    PING_LOST,
    PING_UNREACH,
    PING_LAT,
    HOST_NIC_DROP,
    HOST_NIC_CRC,
    ETHTOOL_DROP,
    ETHTOOL_CRC,
    BOND_ACTIVE,
    BOND_ENABLED,
}


def _query_rows(
    db_client: Any,
    table: str,
    context: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "bundle_id": context.get("bundle_id"),
        "start_time": context.get("start_time"),
        "end_time": context.get("end_time"),
    }
    for key in ("degraded_svm_ip", "cvm_ip", "host_ip", "peer_ip"):
        if context.get(key):
            params[key] = context[key]
    if extra:
        params.update(extra)
    try:
        rows = db_client.query(table, **params)
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def _result(
    status: str,
    context: dict[str, Any],
    observations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    gaps: list[str],
    suggested: list[dict[str, str]] | None = None,
    root_class: str | None = None,
) -> dict[str, Any]:
    return {
        "skill": "network-sar-debugging",
        "status": status,
        "root_class": root_class,
        "entity_context": context,
        "observations": observations,
        "suggested_checks": suggested or [],
        "evidence": evidence,
        "evidence_gaps": gaps,
        "evidence_source": "clickhouse:nu_metrics_sysstats",
    }


def _metric_name(row: dict[str, Any]) -> str:
    return str(row.get("metric_name") or row.get("name") or "")


def _value(row: dict[str, Any]) -> float:
    try:
        return float(row.get("value") or row.get("metric_value") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _iface(row: dict[str, Any]) -> str:
    inst = str(row.get("component_instance") or "")
    if inst:
        return inst
    tags = row.get("tags") or {}
    if isinstance(tags, str):
        # tags often JSON: {"interface":"eth1"}
        if '"interface":"' in tags:
            try:
                start = tags.index('"interface":"') + len('"interface":"')
                end = tags.index('"', start)
                return tags[start:end]
            except ValueError:
                return ""
        return ""
    if isinstance(tags, dict):
        return str(tags.get("interface") or "")
    return ""


def _ts(row: dict[str, Any]) -> float | None:
    for key in ("event_timestamp", "timestamp", "ts"):
        val = row.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            # ClickHouse DateTime may already be epoch seconds
            return float(val) if val > 1_000_000_000 else float(val)
        if isinstance(val, datetime):
            return val.timestamp()
        if isinstance(val, str):
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %I:%M:%S %p",
            ):
                try:
                    return datetime.strptime(val.strip()[:19], fmt[: len(val.strip())]).timestamp()
                except ValueError:
                    continue
            try:
                return float(val)
            except ValueError:
                continue
    return None


def _filter_network_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        name = _metric_name(row)
        if name in NETWORK_METRICS:
            out.append(row)
            continue
        # anomaly table may embed metric in message
        msg = str(row.get("message") or "").lower()
        if any(m.lower() in msg for m in NETWORK_METRICS):
            out.append(row)
    return out


def _detect_flood(
    rows: list[dict[str, Any]],
    bond_roles: dict[str, str],
) -> dict[str, Any]:
    """Group SAR rx/tx by timestamp bucket + iface; find flood windows."""
    by_ts: dict[int, dict[str, dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    for row in rows:
        name = _metric_name(row)
        if name not in (SAR_RX, SAR_TX):
            continue
        ts = _ts(row)
        if ts is None:
            continue
        bucket = int(ts // 10) * 10  # 10s bucket
        iface = _iface(row) or "unknown"
        if name == SAR_RX:
            by_ts[bucket][iface]["rx"] = _value(row)
        else:
            by_ts[bucket][iface]["tx"] = _value(row)

    windows: list[dict[str, Any]] = []
    standby_flood = False
    multi_iface = False
    for bucket, ifaces in by_ts.items():
        hot = []
        for iface, vals in ifaces.items():
            rx = vals.get("rx", 0.0)
            tx = vals.get("tx", 0.0)
            if rx < RX_FLOOD_THRESH:
                continue
            role = bond_roles.get(iface, "unknown")
            item = {"iface": iface, "rxpck": rx, "txpck": tx, "role": role, "ts": float(bucket)}
            hot.append(item)
            if role == "standby" or (tx < 1.0 and rx >= RX_FLOOD_THRESH):
                standby_flood = True
        if not hot:
            continue
        if len(hot) >= 2:
            multi_iface = True
        windows.append(
            {
                "ts": float(bucket),
                "max_rxpck": max(h["rxpck"] for h in hot),
                "hot": hot,
                "standby_rx_flood": [
                    h
                    for h in hot
                    if h["role"] == "standby" or (h["txpck"] < 1.0 and h["rxpck"] >= RX_FLOOD_THRESH)
                ],
            }
        )

    windows.sort(key=lambda w: w["max_rxpck"], reverse=True)
    confirmed = bool(windows) and (
        standby_flood
        or multi_iface
        or (windows and windows[0]["max_rxpck"] >= RX_FLOOD_STRONG)
    )
    return {
        "confirmed": confirmed,
        "standby_rx_flood": standby_flood,
        "multi_iface_flood": multi_iface,
        "n_flood_windows": len(windows),
        "top_windows": windows[:15],
        "verdict": "EXTERNAL_RX_FLOOD" if confirmed else ("RX_ELEVATED" if windows else "NO_RX_FLOOD"),
    }


def _bond_roles(rows: list[dict[str, Any]]) -> dict[str, str]:
    roles: dict[str, str] = {}
    enabled: dict[str, float] = {}
    active: dict[str, float] = {}
    for row in rows:
        name = _metric_name(row)
        iface = _iface(row)
        if not iface:
            continue
        if name == BOND_ENABLED:
            enabled[iface] = _value(row)
        elif name == BOND_ACTIVE:
            active[iface] = _value(row)
    for iface in set(enabled) | set(active):
        if active.get(iface, 0) >= 1:
            roles[iface] = "active"
        elif enabled.get(iface, 0) >= 1:
            roles[iface] = "standby"
        else:
            roles[iface] = "disabled"
    return roles


def _ping_fail_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        name = _metric_name(row)
        if name not in (PING_LOST, PING_UNREACH):
            continue
        if _value(row) < 1.0:
            continue
        ts = _ts(row)
        if ts is None:
            continue
        events.append(
            {
                "ts": ts,
                "kind": "LOST_PKT" if name == PING_LOST else "UNREACHABLE",
                "target": _iface(row) or str(row.get("component_instance") or ""),
                "row": row,
            }
        )
    return events


def _correlate(
    fail_events: list[dict[str, Any]], flood: dict[str, Any]
) -> dict[str, Any]:
    tops = flood.get("top_windows") or []
    if not fail_events or not flood.get("confirmed") or not tops:
        return {"correlated": False, "n_matches": 0, "matches": [], "verdict": "PING_LOSS_NO_FLOOD_OVERLAP"}
    matches = []
    for ev in fail_events:
        for w in tops:
            if abs(ev["ts"] - w["ts"]) <= CORR_WINDOW_SEC:
                matches.append(
                    {
                        "ping_ts": ev["ts"],
                        "flood_ts": w["ts"],
                        "delta_sec": abs(ev["ts"] - w["ts"]),
                        "max_rxpck": w["max_rxpck"],
                        "kind": ev["kind"],
                        "target": ev["target"],
                    }
                )
                break
    return {
        "correlated": bool(matches),
        "n_matches": len(matches),
        "matches": matches[:20],
        "verdict": (
            "PING_LOSS_CORRELATES_WITH_RX_FLOOD"
            if matches
            else "PING_LOSS_NO_FLOOD_OVERLAP"
        ),
    }


def _l1_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    crc = 0.0
    drops = 0.0
    for row in rows:
        name = _metric_name(row)
        if name in (HOST_NIC_CRC, ETHTOOL_CRC):
            crc = max(crc, _value(row))
        if name in (HOST_NIC_DROP, ETHTOOL_DROP, SAR_RX_DROP):
            drops = max(drops, _value(row))
    return {
        "crc_nonzero": crc > 0,
        "max_crc": crc,
        "soft_rx_drops_signal": drops > 0,
        "max_drop_signal": drops,
        "note": "CRC=0 is a finding; soft drops ≠ CRC",
    }


def run(db_client: Any, context: dict[str, Any]) -> dict[str, Any]:
    """Panacea product skill entry — ClickHouse first."""
    raw = []
    raw.extend(_query_rows(db_client, "nu_metrics_sysstats", context))
    raw.extend(_query_rows(db_client, "nu_metrics_sysstats_anomaly", context))
    rows = _filter_network_rows(raw)

    if not rows:
        return _result(
            "EVIDENCE_INSUFFICIENT",
            context,
            [],
            [],
            [
                "No network SAR/ping/host_nic/ethtool/bond rows in nu_metrics_sysstats "
                "for this bundle (needs ingestion PR #408 parsers + metrics-enabled ingest)"
            ],
        )

    bond_roles = _bond_roles(rows)
    flood = _detect_flood(rows, bond_roles)
    ping_fails = _ping_fail_events(rows)
    corr = _correlate(ping_fails, flood)
    l1 = _l1_summary(rows)

    observations: list[dict[str, Any]] = [
        {"type": "BOND_ROLES", "roles": bond_roles},
        {"type": "EXTERNAL_RX_FLOOD", **{k: flood[k] for k in ("confirmed", "verdict", "standby_rx_flood", "multi_iface_flood", "n_flood_windows")}},
        {"type": "PING_FLOOD_CORRELATION", **{k: corr[k] for k in ("correlated", "verdict", "n_matches")}},
        {"type": "L1_CRC_DROPS", **l1},
        {"type": "PATH_PING_FAILS", "n_fails": len(ping_fails)},
    ]

    evidence: list[dict[str, Any]] = []
    for w in (flood.get("top_windows") or [])[:5]:
        evidence.append(
            {
                "kind": "flood_window",
                "ts": w["ts"],
                "max_rxpck": w["max_rxpck"],
                "ifaces": [
                    f"{h['iface']}:{int(h['rxpck'])}rx/{int(h['txpck'])}tx/{h['role']}"
                    for h in w["hot"]
                ],
            }
        )
    for m in (corr.get("matches") or [])[:5]:
        evidence.append({"kind": "ping_flood_match", **m})

    gaps: list[str] = []
    if not bond_roles:
        gaps.append("bond_member_* metrics missing — roles unknown (standby flood heuristic uses TX≈0)")
    if not any(_metric_name(r) == SAR_RX for r in rows):
        gaps.append("sar_rx_packets_per_sec missing")
    if not ping_fails and not any(_metric_name(r) in (PING_LOST, PING_UNREACH) for r in rows):
        gaps.append("ping_all_lost_pkt / ping_all_unreachable missing or zero")

    if corr.get("correlated"):
        return _result(
            "EXTERNAL_RX_FLOOD_CORRELATED",
            context,
            observations,
            evidence,
            gaps,
            suggested=[
                {"skill": "network-cassandra-metadata", "reason": "Peer timeouts may follow path loss"},
                {"skill": "network-host-pressure", "reason": "Check co-existing storage pressure"},
            ],
            root_class="EXTERNAL_RX_FLOOD",
        )
    if flood.get("confirmed"):
        return _result(
            "EXTERNAL_RX_FLOOD_FOUND",
            context,
            observations,
            evidence,
            gaps,
            suggested=[{"skill": "network-ping-tcp-baseline", "reason": "Confirm path loss window"}],
            root_class="EXTERNAL_RX_FLOOD",
        )
    if ping_fails:
        return _result(
            "PATH_LOSS_WITHOUT_FLOOD",
            context,
            observations,
            evidence + [{"kind": "ping_fail", **e} for e in ping_fails[:10]],
            gaps,
            root_class="PATH_EDGE",
        )
    if l1.get("crc_nonzero"):
        return _result(
            "L1_CRC_FOUND",
            context,
            observations,
            evidence,
            gaps,
            root_class="L1_CRC_OR_LINK",
        )

    return _result(
        "NO_SAR_FLOOD_ISSUE",
        context,
        observations,
        evidence,
        gaps,
        root_class="INCONCLUSIVE",
    )
