#!/usr/bin/env python3
"""Ignore-class leftover noise for OVN report and leftover observer.

Identity of remaining leftovers is still port-set UUID only. Display names
are used only to classify *noise* to drop (K8s; empty Quarantine).
Do not group leftovers by name.
"""

from __future__ import annotations

import re

ZERO = "00000000-0000-0000-0000-000000000000"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Ignore-class only. Cilium_VLAN_Scope is the Atlas K8s leftover name style.
K8S_NOISE_RE = re.compile(r"(k8s|kubernetes|cilium_vlan_scope)", re.I)
NIC_KEYS = (
    "atlas_nic_uuids",
    "computed_nic_uuids",
    "only_atlas_nics",
    "only_computed_nics",
    "atlas_nics",
    "computed_nics",
)


def _one_uuid(item):
    if isinstance(item, str):
        text = item.strip().lower()
        if UUID_RE.match(text) and text != ZERO:
            return text
        return ""
    if isinstance(item, dict):
        return _one_uuid(
            item.get("nic_uuid") or item.get("uuid") or item.get("ext_id") or "")
    if isinstance(item, (list, tuple)) and item:
        for part in item:
            uid = _one_uuid(part)
            if uid:
                return uid
    return ""


def leftover_nic_uuids(rec):
    """Union of jsonl NIC UUID fields used for 'without NIC'.

    Fields: atlas_nic_uuids, computed_nic_uuids, only_atlas_nics,
    only_computed_nics, atlas_nics, computed_nics.
    """
    bags = [rec]
    bags.extend(rec.get("rows") or [])
    nics = set()
    for bag in bags:
        if not isinstance(bag, dict):
            continue
        for key in NIC_KEYS:
            values = bag.get(key)
            if isinstance(values, (set, list, tuple)):
                for item in values:
                    uid = _one_uuid(item)
                    if uid:
                        nics.add(uid)
    return nics


def leftover_display_names(rec):
    names = []
    seen = set()

    def add(value):
        text = str(value or "").strip()
        if not text or text in seen:
            return
        seen.add(text)
        names.append(text)

    add(rec.get("atlas_name"))
    add(rec.get("entity_group_name"))
    add(rec.get("policy_name"))
    for key in ("atlas_names", "policy_names"):
        for item in rec.get(key) or []:
            add(item)
    for bag in [rec] + list(rec.get("rows") or []):
        if not isinstance(bag, dict):
            continue
        add(bag.get("atlas_name"))
        add(bag.get("entity_group_name"))
        for entry in bag.get("rule_u_sg") or []:
            if isinstance(entry, dict):
                add(entry.get("policy_name"))
    return names


def is_k8s_leftover_noise(rec):
    return any(K8S_NOISE_RE.search(name) for name in leftover_display_names(rec))


def is_empty_quarantine_leftover(rec):
    if not any("quarantine" in name.lower() for name in leftover_display_names(rec)):
        return False
    return not leftover_nic_uuids(rec)


def leftover_ignore_reason(rec):
    """Return 'k8s', 'empty_quarantine', or '' (keep)."""
    if is_k8s_leftover_noise(rec):
        return "k8s"
    if is_empty_quarantine_leftover(rec):
        return "empty_quarantine"
    return ""
