"""Read-side aggregation for the analyst dashboard.

Nothing here collects data on its own; it only queries what the poller,
adapters and analyst actions already recorded, and assembles it into the
shapes the dashboard pages render. Keeping this separate from core.py keeps
the MCP tool surface and the dashboard's view-model concerns apart.
"""

from pathlib import Path

from . import environment, frameworks, lead_queue, poller, repo_updates, research_feeds, rules, store
from .core import backfill_source_names, get_threat, now, research_view


def source_catalog():
    """Every source name collect_daily/poller can produce, in the same
    spelling used by source_counts/source_errors, independent of whether it
    has ever run. This is what lets a never-collected source still show a
    card instead of silently disappearing."""
    names = [("CISA KEV", "government feed"), ("NVD", "government feed"),
             ("GitHub advisories", "registry feed"), ("RansomLook leak claims", "leak-site tracker"),
             ("ThreatFox C2", "community IOC feed (optional, needs THREATFOX_AUTH_KEY)")]
    names += [("GitHub: " + name, "curated GitHub repository") for name, _, _, _ in repo_updates.REPOSITORIES]
    names += [("RSS: " + name, f"{kind} RSS/Atom feed") for name, _, kind in research_feeds.FEEDS]
    return names


def sources_overview(path: Path | None = None):
    """One card per configured source: last successful refresh, latest
    publication date among its collected records, a persistent record
    count, and its most recent collection error (if any)."""
    store.initialize(path)
    backfill_source_names(path)
    state = poller.poll_status(path)
    last_result = state["last_result"] or {}
    source_errors = last_result.get("source_errors", {})
    with store.connection(path) as db:
        rows = {r["name"]: dict(r) for r in db.execute("SELECT * FROM source_state")}
        counts = {r["source_name"]: r["n"] for r in db.execute(
            "SELECT source_name, COUNT(DISTINCT threat_id) AS n FROM evidence "
            "WHERE kind='source_fact' AND source_name IS NOT NULL GROUP BY source_name")}
        latest_pub = {r["source_name"]: r["latest"] for r in db.execute(
            "SELECT e.source_name, MAX(t.published) AS latest FROM evidence e "
            "JOIN threats t ON t.id=e.threat_id WHERE e.kind='source_fact' AND e.source_name IS NOT NULL "
            "GROUP BY e.source_name")}
    from .workflow import source_attempts
    attempts = source_attempts(path)
    cards = []
    for name, category in source_catalog():
        row = rows.get(name)
        attempt = attempts.get(name)
        if attempt:
            error = attempt["detail"] if attempt["status"] in ("error", "partial") else None
            status = {"error": "error", "partial": "partial"}.get(attempt["status"], "ok")
        else:
            error = source_errors.get(name) or (row["last_error"] if row else None)
            status = "error" if error else "ok" if row else "never_collected"
        cards.append({
            "name": name, "category": category,
            "last_success": row["last_success"] if row else None,
            "record_count": counts.get(name, 0),
            "latest_publication": latest_pub.get(name),
            "latest_fetch": attempt["attempted_at"] if attempt else None,
            "error": error, "error_at": attempt["attempted_at"] if attempt and error else
            (row["last_error_at"] if row and row["last_error"] else None),
            "status": status,
        })
    framework_state = frameworks.status(path)
    framework_errors = (last_result.get("framework_update") or {}).get("errors", {})
    for fw_name, label in frameworks.LABELS.items():
        info = framework_state[fw_name]
        attempt = attempts.get(label)
        error = (attempt["detail"] if attempt["status"] == "error" else None) if attempt else framework_errors.get(fw_name)
        cards.append({
            "name": label, "category": "framework release", "last_success": info.get("fetched_at"),
            "record_count": None, "latest_publication": info.get("version"),
            "latest_fetch": attempt["attempted_at"] if attempt else None,
            "error": error, "error_at": attempt["attempted_at"] if attempt and error else None,
            "status": "error" if error else "stale" if info.get("status") == "stale" else
                      "ok" if info.get("status") == "current" else "never_collected",
        })
    queue = lead_queue.queue_status(path)
    pending = queue["article_queue"].get("pending", 0)
    cards.append({
        "name": "Article review queue", "category": "internal backlog", "last_success": None,
        "record_count": queue["review_required_behavior_leads"], "latest_publication": None, "latest_fetch": None,
        "error": f"{pending} articles pending review" if pending >= 25 else None, "error_at": None,
        "status": "backlogged" if pending >= 25 else "ok",
    })
    return {"as_of": now(), "poll_interval_minutes": state["interval_minutes"],
            "poll_running": state["running"], "last_poll_completed": state["last_completed"],
            "email_configured": state["email_configured"],
            "last_result_stale": state["last_result_stale"],
            "last_result_age_minutes": state["last_result_age_minutes"],
            "sources": sorted(cards, key=lambda c: (c["status"] not in ("error", "partial", "backlogged"), c["name"]))}


def threats_for_source(name, path: Path | None = None, limit=50):
    store.initialize(path)
    backfill_source_names(path)
    with store.connection(path) as db:
        rows = db.execute(
            "SELECT DISTINCT t.id,t.title,t.kind,t.published,t.last_seen,t.kev FROM threats t "
            "JOIN evidence e ON e.threat_id=t.id WHERE e.source_name=? AND e.kind='source_fact' "
            "ORDER BY COALESCE(t.published,t.last_seen) DESC LIMIT ?",
            (name, max(1, min(int(limit), 200)))).fetchall()
    return [dict(r) for r in rows]


def recent_threats(path: Path | None = None, limit=50, kind=None):
    store.initialize(path)
    with store.connection(path) as db:
        if kind:
            rows = db.execute("SELECT id,title,kind,published,last_seen,kev FROM threats WHERE kind=? "
                              "ORDER BY COALESCE(published,last_seen) DESC LIMIT ?",
                              (kind, max(1, min(int(limit), 200)))).fetchall()
        else:
            rows = db.execute("SELECT id,title,kind,published,last_seen,kev FROM threats "
                              "ORDER BY COALESCE(published,last_seen) DESC LIMIT ?",
                              (max(1, min(int(limit), 200)),)).fetchall()
    return [dict(r) for r in rows]


def workspace_notes(threat_id, path: Path | None = None):
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM analyst_workspace_notes WHERE threat_id=? ORDER BY created_at DESC",
                          (threat_id.upper(),)).fetchall()
    return [dict(r) for r in rows]


def add_workspace_note(threat_id, note_type, content, path: Path | None = None):
    if note_type not in ("telemetry_fields", "benign_example", "feedback"):
        raise ValueError("note_type must be telemetry_fields, benign_example, or feedback")
    if not isinstance(content, str) or not 3 <= len(content.strip()) <= 2000:
        raise ValueError("note content must be 3-2000 characters")
    if get_threat(threat_id, path) is None:
        raise ValueError("unknown threat")
    with store.connection(path) as db:
        db.execute("INSERT INTO analyst_workspace_notes (threat_id,note_type,content,created_at) VALUES (?,?,?,?)",
                   (threat_id.upper(), note_type, content.strip(), now()))
        row_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return row_id


def threat_detail_view(threat_id, path: Path | None = None):
    """Everything the threat detail page's five sections need, assembled
    from existing research/risk/rule/framework functions without duplicating
    their logic or inventing anything they did not already return."""
    threat = get_threat(threat_id, path)
    if not threat:
        return None
    research = research_view(threat_id, path)
    inventory = rules.inventory_status(threat_id, path)
    env_state = environment.status(path)
    if threat["kind"] == "advisory":
        risk = (environment.risk_from_assets(threat_id, path) if env_state.get("configured")
                else {"score": None, "priority": "verify_client_assets",
                      "reason": "No verified client asset inventory is configured; run onboard first."})
    else:
        from .core import assess_risk
        risk = assess_risk(threat_id, {}, path)
    behaviors = sorted({e["behavior"] for e in threat["evidence"]
                        if e["kind"] == "analyst_observation" and e["behavior"] in rules.TEMPLATES})
    framework_context = {behavior: frameworks.retrieve(behavior, path, update=False) for behavior in behaviors}
    rule_details = [rules.get_rule(r["id"], path) for r in threat["rules"]]
    return {
        "threat": threat, "research": research, "inventory_status": inventory,
        "environment_risk": risk, "environment_configured": env_state.get("configured", False),
        "framework_context": framework_context, "rules": rule_details,
        "workspace_notes": workspace_notes(threat_id, path),
        "verification_needed": [
            "Which cited technical report or tested local observation confirms the behavior?",
            "What specific fields and literal values identify it in your process, network or MCP audit logs?",
            "Which assets are confirmed affected, and what benign activity might match?",
        ],
    }
