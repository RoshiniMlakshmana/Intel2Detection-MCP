"""Intelligence-first routing: known IOC matches or source-backed research backlog.

This matches only exact, non-expired stored IOC values from collected feeds.
No inference from CVE severity or similarity, no automatic draft approval.
"""
from __future__ import annotations
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from . import store

FIELDS = {
    "ip": ("DestinationIp", "SourceIp", "RemoteIP"),
    "domain": ("DestinationHostname", "RemoteUrl", "DnsQuery"),
    "url": ("Url", "RequestURL"),
    "sha256": ("SHA256", "FileHash"),
}
SUPPORTED = frozenset(FIELDS)


def _canonical(kind, value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind == "sha256":
        import re
        return value.lower() if re.fullmatch(r"[a-fA-F0-9]{64}", value) else None
    if kind == "domain":
        return value.rstrip(".").casefold()
    if kind == "url":
        return value  # Exact match only: no guessing on redirects, query strings, or case
    return None


def _indicator_from_row(row):
    raw = row["indicator"]
    kind = (row["indicator_type"] or "").lower().replace("-", "")
    if not isinstance(raw, str):
        return None
    if kind in ("ip:port", "ipport"):
        # Matching IP-only when intelligence specifies a port would be wrong.
        return ("ip_port", raw)
    aliases = {"ipaddress": "ip", "ipv4": "ip", "ipv6": "ip",
               "hostname": "domain", "fqdn": "domain", "sha256hash": "sha256"}
    kind = aliases.get(kind, kind)
    if kind not in SUPPORTED:
        return None
    return kind, raw


def classify_event(event, path: Path | None = None):
    """Return observed exact IOC matches plus research fallback; never claim compromise."""
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    store.initialize(path)
    with store.connection(path) as db:
        records = db.execute(
            "SELECT id,title,indicator,indicator_type,confidence,expires_at,sources,kind "
            "FROM threats WHERE indicator IS NOT NULL AND kind='ioc'"
        ).fetchall()
    matches, unsupported = [], 0
    now = datetime.now(timezone.utc)
    for row in records:
        if row["expires_at"]:
            try:
                expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expiry.tzinfo is None or expiry <= now:
                    continue
            except ValueError:
                continue
        parsed = _indicator_from_row(row)
        if parsed is None:
            unsupported += 1
            continue
        kind, raw = parsed
        if kind == "ip_port":
            try:
                ip, port = raw.rsplit(":", 1)
                target = _canonical("ip", ip.strip("[]"))
                port = int(port)
            except (ValueError, AttributeError):
                continue
            observed = _canonical("ip", event.get("DestinationIp") or event.get("RemoteIP"))
            try:
                observed_port = int(event.get("DestinationPort", event.get("RemotePort")))
            except (ValueError, TypeError):
                continue
            if observed != target or observed_port != port:
                continue
            matched_field = "DestinationIp+DestinationPort"
        else:
            wanted = _canonical(kind, raw)
            if wanted is None:
                continue
            matched_field = next((name for name in FIELDS[kind]
                                  if _canonical(kind, event.get(name)) == wanted), None)
            if not matched_field:
                continue
        sources = json.loads(row["sources"] or "[]")
        matches.append({
            "threat_id": row["id"], "title": row["title"],
            "indicator_type": kind, "matched_field": matched_field,
            "indicator": raw, "confidence": row["confidence"],
            "sources": sources, "classification": "known_threat_indicator_match",
            "compromise_confirmed": False,
        })
    matches.sort(key=lambda x: (x["threat_id"], x["matched_field"]))
    return {
        "status": "known_intelligence_match" if matches else "no_known_indicator_match",
        "matches": matches, "unsupported_ioc_records": unsupported,
        "next_step": ("triage_and_environment_relevance" if matches
                      else "research_source_backed_behaviors_and_propose_unverified_rules"),
        "rules_auto_approved": False,
        "compromise_confirmed": False,
    }


def route(threat_id, path: Path | None = None):
    """Distinguish trusted IOC leads from source-inspection work to do."""
    store.initialize(path)
    with store.connection(path) as db:
        row = db.execute("SELECT id,kind,indicator,sources FROM threats WHERE id=?",
                         (threat_id.upper(),)).fetchone()
        if not row:
            raise ValueError("unknown threat")
    indicator = _indicator_from_row(row)
    if row["kind"] == "ioc" and indicator:
        return {"threat_id": row["id"], "path": "known_indicator",
                "next_step": "match_exact_indicator_against_declared_telemetry"}
    return {"threat_id": row["id"], "path": "behavior_research",
            "next_step": "research_lead_then_evidence_linked_draft_proposal",
            "sources": json.loads(row["sources"] or "[]"),
            "automatic_approval": False}
