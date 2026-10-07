"""Continuous bounded collection with durable alert queue and source health."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, digest, lead_queue, proposal_pass, research_feeds, research_pass, store
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
        attempts = [dict(r) for r in db.execute("SELECT * FROM source_attempts ORDER BY status!='error',name")]
    last_result = json.loads(state["last_result"]) if state and state["last_result"] else None
    configured_interval = (last_result or {}).get("interval_minutes", interval_minutes())
    if not isinstance(configured_interval, int) or not 5 <= configured_interval <= 1440:
        configured_interval = interval_minutes()
    age_minutes = None
    if state and state["last_completed"]:
        completed = datetime.fromisoformat(state["last_completed"].replace("Z", "+00:00"))
        age_minutes = round((datetime.now(timezone.utc) - completed).total_seconds() / 60)
    produced_by = (last_result or {}).get("collector_version")
    return {"database": str((path or store.db_path()).resolve()), "interval_minutes": configured_interval, "running": bool(state and state["lease_until"] and state["lease_until"] > now()),
            "installed_collector_version": __version__,
            "last_result_age_minutes": age_minutes,
            # A result older than two intervals, or produced by different
            # collector code, may describe failures this installation has
            # already fixed; re-run poll_now before acting on its errors.
            "last_result_stale": bool(age_minutes is None or age_minutes > 2 * configured_interval
                                      or produced_by != __version__),
            "last_result_collector_version": produced_by or "unknown (older than 0.11.0)",
            "source_attempts": attempts,
            "last_started": state["last_started"] if state else None,
            "last_completed": state["last_completed"] if state else None,
            "last_result": last_result,
            "pending_alerts": pending, "sources_with_successful_checkpoint": sources,
            "email_configured": bool(os.environ.get("SMTP_HOST") and
              (os.environ.get("ALERT_TO") or os.environ.get("DIGEST_TO"))),
            "article_review": lead_queue.queue_status(path)}


def _source_windows(path, at):
    """Overlap one hour; retry failed sources from their last success, up to seven days."""
    with store.connection(path) as db:
        rows = db.execute("SELECT name,last_success,total_records FROM source_state").fetchall()
    floor = at - timedelta(days=7)
    return {r["name"]: (at - timedelta(days=research_feeds.INITIAL_LOOKBACK_DAYS) if r["name"].startswith("RSS: ") and not r["total_records"] else
            max(floor, datetime.fromisoformat(r["last_success"].replace("Z", "+00:00")) - timedelta(hours=1)))
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


def run_poll(path: Path | None = None, adapters=None, send=None, notify=True):
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
            partial = result.get("partial", {})
            complete = [name for name in result["sources"] if name != "FIRST EPSS" and name not in partial]
            db.executemany("INSERT INTO source_state(name,last_success,total_records,last_error) VALUES (?,?,?,NULL) "
                           "ON CONFLICT(name) DO UPDATE SET last_success=excluded.last_success,"
                           "total_records=source_state.total_records+excluded.total_records,last_error=NULL",
                           [(name, stamp, result["sources"][name]) for name in complete])
            # A partial fetch checkpoints only through the part it fully
            # covered, and never moves an existing checkpoint backwards; its
            # error stays set so it is never shown as a complete refresh.
            for name, through in partial.items():
                db.execute("INSERT INTO source_state(name,last_success,total_records,last_error,last_error_at) "
                           "VALUES (?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                           "last_success=MAX(source_state.last_success,excluded.last_success),"
                           "total_records=source_state.total_records+excluded.total_records,"
                           "last_error=excluded.last_error,last_error_at=excluded.last_error_at",
                           (name, through, result["sources"].get(name, 0), result["errors"][name], stamp))
            # Only a source with a prior successful checkpoint gets its row
            # touched here; a source that has never once succeeded must not
            # gain a source_state row from a bare failure (that would corrupt
            # sources_with_successful_checkpoint's meaning). Every attempt,
            # including a never-successful source's, is in source_attempts.
            db.executemany("UPDATE source_state SET last_error=?,last_error_at=? WHERE name=?",
                           [(message, stamp, name) for name, message in result["errors"].items()
                            if name not in partial])
            empty = {r["name"] for r in db.execute("SELECT s.name FROM source_state s WHERE s.total_records=0 AND NOT EXISTS(SELECT 1 FROM evidence e WHERE e.source_name=s.name)")
                     if r["name"].startswith(("RSS: ", "GitHub: "))}
            attempts = [(name, stamp, "partial" if name in partial else "empty_feed" if name in empty else "ok", count,
                         result["errors"].get(name) or ("No usable records have ever been collected; inspect URL, parser and lookback."
                         if name in empty else None)) for name, count in result["sources"].items()]
            attempts += [(name, stamp, "empty_feed" if "no RSS/Atom entries" in message else "error", 0, message) for name, message in result["errors"].items()
                         if name not in result["sources"]]
            db.executemany("INSERT INTO source_attempts(name,attempted_at,status,records,detail) VALUES (?,?,?,?,?) "
                           "ON CONFLICT(name) DO UPDATE SET attempted_at=excluded.attempted_at,status=excluded.status,"
                           "records=excluded.records,detail=excluded.detail", attempts)
        article_review = {"queued": 0, "attempted": 0, "inspected": 0, "leads": 0, "errors": {}}
        if adapters is None:
            article_review["queued"] = lead_queue.queue_new_report_articles(result["new_ids"], path)
            article_review.update(lead_queue.inspect_due(path))
        research = None
        if adapters is None:
            try:
                research = research_pass.run_pass(path)
                research = {"leads_researched": research["leads_researched"], "pages_fetched": research["pages_fetched"],
                            "outcomes": {r["threat_id"]: r["status"] for r in research["results"]},
                            "publisher_blocked_pages": research["publisher_blocked_pages"],
                            "backlog_remaining": research["backlog_remaining"]}
            except (OSError, ValueError) as exc:
                research = {"error": str(exc)[:200]}
            # Raw triage runs only after the KEV-first pass, on its own small
            # budget, so it widens coverage without taking priority capacity.
            try:
                triage = research_pass.triage_raw(path)
                research["raw_triage"] = {"researched": triage["researched"],
                                          "skipped_without_fetch": triage["skipped_without_fetch"],
                                          "pages_fetched": triage["pages_fetched"],
                                          "untriaged_remaining": triage["untriaged_remaining"]}
            except (OSError, ValueError) as exc:
                research["raw_triage"] = {"error": str(exc)[:200]}
            # Work through older research already in SQLite without another
            # publisher fetch. The durable cursor resumes on the next poll;
            # each draft remains unverified and later batches deduplicate.
            try:
                research["stored_draft_backfill"] = proposal_pass.advance_stored_backfill(path, limit=20)
            except (OSError, ValueError) as exc:
                research["stored_draft_backfill"] = {"error": str(exc)[:200]}
        framework_update = None
        if adapters is None:
            from . import frameworks
            framework_update = frameworks.refresh(path)
        result.pop("new_ids")
        alert_ids = result.pop("alert_ids")
        queued = _queue_new(alert_ids, path)
        notification = _deliver_pending(path, send=send) if notify else {"status": "disabled_for_collection_job"}
        summary = {"status": "degraded" if empty or result["errors"] or article_review["errors"] or (framework_update and framework_update["errors"]) else "collected", "started": started, "completed": now(),
                   "new_records": result["new_records"], "alert_leads_queued": queued,
                   "article_review": article_review,
                   "research_pass": research,
                   "framework_update": framework_update,
                   "notification": notification, "source_counts": result["sources"],
                   "source_errors": result["errors"], "empty_sources": sorted(empty), "partial_sources": result.get("partial", {}),
                   "collector_version": __version__, "interval_minutes": interval_minutes()}
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
