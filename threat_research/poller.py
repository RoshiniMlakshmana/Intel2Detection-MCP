"""Continuous bounded collection with durable alert queue and source health."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import digest, lead_queue, store
from .core import collect_daily, now


def interval_minutes():
    value = int(os.environ.get("POLL_INTERVAL_MINUTES", "15"))
    if not 5 <= value <= 1440:
        raise ValueError("POLL_INTERVAL_MINUTES must be 5-1440")
    return value


def poll_status(path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        state = db.execute("SELECT * FROM poll_state WHERE id=1").fetchone()
        pending = db.execute("SELECT COUNT(*) FROM alert_queue WHERE sent_at IS NULL").fetchone()[0]
        sources = db.execute("SELECT COUNT(*) FROM source_state").fetchone()[0]
    return {"interval_minutes": interval_minutes(), "running": bool(state and state["lease_until"] and state["lease_until"] > now()),
            "last_started": state["last_started"] if state else None,
            "last_completed": state["last_completed"] if state else None,
            "last_result": json.loads(state["last_result"]) if state and state["last_result"] else None,
            "pending_alerts": pending, "sources_with_successful_checkpoint": sources,
            "email_configured": bool(os.environ.get("SMTP_HOST") and
              (os.environ.get("ALERT_TO") or os.environ.get("DIGEST_TO"))),
            "article_review": lead_queue.queue_status(path)}


def _source_windows(path, at):
    """Overlap one hour; retry failed sources from their last success, up to seven days."""
    with store.connection(path) as db:
        rows = db.execute("SELECT name,last_success FROM source_state").fetchall()
    floor = at - timedelta(days=7)
    return {r["name"]: max(floor, datetime.fromisoformat(r["last_success"].replace("Z", "+00:00")) - timedelta(hours=1))
            for r in rows}


def _queue_new(new_ids, path):
    if not new_ids:
        return 0
    research = os.environ.get("ALERT_RESEARCH", "false").lower() == "true"
    eligible = []
    with store.connection(path) as db:
        for start in range(0, len(new_ids), 400):
            batch = new_ids[start:start + 400]
            rows = db.execute("SELECT id,kind,kev,confidence FROM threats WHERE id IN (" +
                              ",".join("?" for _ in batch) + ")", batch).fetchall()
            eligible.extend(r["id"] for r in rows if r["kev"] or
                            (r["kind"] == "ioc" and (r["confidence"] or 0) >= 75) or
                            (research and r["kind"] in ("campaign", "research_update", "community_rule")))
        db.executemany("INSERT OR IGNORE INTO alert_queue(threat_id,queued_at) VALUES (?,?)",
                       [(ident, now()) for ident in eligible])
    return len(eligible)


def _deliver_pending(path, send=None):
    address = os.environ.get("ALERT_TO") or os.environ.get("DIGEST_TO", "")
    if not address or not os.environ.get("SMTP_HOST"):
        return {"status": "pending_email_configuration"}
    with store.connection(path) as db:
        rows = db.execute("SELECT t.id,t.title,t.kind,t.kev,t.sources FROM alert_queue q "
                          "JOIN threats t ON t.id=q.threat_id WHERE q.sent_at IS NULL "
                          "ORDER BY t.kev DESC,q.queued_at ASC LIMIT 10").fetchall()
    if not rows:
        return {"status": "no_pending_alerts", "sent": 0}
    lines = ["New threat leads for analyst review:", ""]
    for row in rows:
        refs = json.loads(row["sources"])
        lines.extend([f"- {row['id']} | {'CISA KEV' if row['kev'] else row['kind']} | {row['title'][:120]}",
                      f"  {refs[0] if refs else 'source unavailable'}"])
    lines.extend(["", "A source lead is not verified exploit behavior or confirmed local exposure. Check asset inventory and evidence before drafting a rule."])
    sender = send or digest.send_email
    sender("\n".join(lines) + "\n", f"Threat research: {len(rows)} new lead(s)", address)
    with store.connection(path) as db:
        db.executemany("UPDATE alert_queue SET sent_at=? WHERE threat_id=? AND sent_at IS NULL",
                       [(now(), row["id"]) for row in rows])
    return {"status": "delivered", "sent": len(rows)}


def run_poll(path: Path | None = None, adapters=None, send=None):
    """Run one collection. A SQLite lease prevents overlapping workers on one DB."""
    store.initialize(path)
    started = now()
    lease = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(timespec="seconds").replace("+00:00", "Z")
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO poll_state(id) VALUES (1)")
        acquired = db.execute("UPDATE poll_state SET lease_until=?,last_started=? WHERE id=1 "
                              "AND (lease_until IS NULL OR lease_until<=?)", (lease, started, started)).rowcount
    if not acquired:
        return {"status": "already_running", "started": started}
    result = None
    try:
        until = datetime.now(timezone.utc)
        source_since = _source_windows(path, until) if adapters is None else None
        result = collect_daily(path, adapters=adapters, include_ids=True, until=until, source_since=source_since)
        with store.connection(path) as db:
            stamp = until.isoformat().replace("+00:00", "Z")
            db.executemany("INSERT INTO source_state(name,last_success,total_records,last_error) VALUES (?,?,?,NULL) "
                           "ON CONFLICT(name) DO UPDATE SET last_success=excluded.last_success,"
                           "total_records=source_state.total_records+excluded.total_records,last_error=NULL",
                           [(name, stamp, result["sources"][name]) for name in result["sources"]
                            if name != "FIRST EPSS"])
            # Only a source with a prior successful checkpoint gets its row
            # touched here; a source that has never once succeeded must not
            # gain a source_state row from a bare failure (that would corrupt
            # sources_with_successful_checkpoint's meaning). Its error is
            # still visible via this run's own source_errors in poll_state.
            db.executemany("UPDATE source_state SET last_error=?,last_error_at=? WHERE name=?",
                           [(message, stamp, name) for name, message in result["errors"].items()])
        article_review = {"queued": 0, "attempted": 0, "inspected": 0, "leads": 0, "errors": {}}
        if adapters is None:
            article_review["queued"] = lead_queue.queue_new_report_articles(result["new_ids"], path)
            article_review.update(lead_queue.inspect_due(path))
        framework_update = None
        if adapters is None:
            from . import frameworks
            framework_update = frameworks.refresh(path)
        result.pop("new_ids")
        alert_ids = result.pop("alert_ids")
        queued = _queue_new(alert_ids, path)
        notification = _deliver_pending(path, send=send)
        summary = {"status": "degraded" if result["errors"] or article_review["errors"] or (framework_update and framework_update["errors"]) else "collected", "started": started, "completed": now(),
                   "new_records": result["new_records"], "alert_leads_queued": queued,
                   "article_review": article_review,
                   "framework_update": framework_update,
                   "notification": notification, "source_counts": result["sources"],
                   "source_errors": result["errors"]}
        return summary
    except Exception as exc:
        summary = {"status": "failed", "started": started, "completed": now(),
                   "error": str(exc)[:300], "collection": result}
        raise
    finally:
        with store.connection(path) as db:
            db.execute("UPDATE poll_state SET lease_until=NULL,last_completed=?,last_result=? WHERE id=1",
                       (now(), json.dumps(summary if result is not None else {"status": "failed", "started": started}),))


def serve(path: Path | None = None):
    """One long-running worker per database; poll immediately, then every interval."""
    next_run = 0.0
    last_digest_attempt = 0.0
    while True:
        if time.monotonic() >= next_run:
            try:
                print(json.dumps(run_poll(path)), flush=True)
            except Exception as exc:
                print(json.dumps({"status": "poll_failed", "error": str(exc)[:300]}), flush=True)
            next_run = time.monotonic() + interval_minutes() * 60
        if digest.due_now() and time.monotonic() - last_digest_attempt >= 900:
            last_digest_attempt = time.monotonic()
            try:
                daily = digest.run_daily(path, collect=True)
                if daily["status"] not in ("already_delivered", "already_saved"):
                    print(json.dumps({"daily_digest": daily}), flush=True)
            except Exception as exc:
                print(json.dumps({"status": "digest_failed", "error": str(exc)[:300]}), flush=True)
        time.sleep(min(30, max(1, next_run - time.monotonic())))
