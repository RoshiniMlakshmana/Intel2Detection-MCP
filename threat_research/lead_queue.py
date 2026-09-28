"""Durable, bounded review queue for newly collected publisher articles."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import report_inspection, store
from .core import now


def batch_size():
    value = int(os.environ.get("ARTICLE_REVIEW_BATCH_SIZE", "18"))
    if not 1 <= value <= 40:
        raise ValueError("ARTICLE_REVIEW_BATCH_SIZE must be 1-40")
    return value


def _eligible(url):
    parsed = urlsplit(url)
    try:
        return (parsed.scheme == "https" and parsed.hostname in report_inspection.ALLOWED_HOSTS
                and parsed.port in (None, 443) and not parsed.username and not parsed.password
                and len(url) <= 500)
    except ValueError:
        return False


def queue_new_report_articles(new_ids, path: Path | None = None):
    """Only newly inserted campaign reports from configured publisher hosts."""
    if not new_ids:
        return 0
    queued = 0
    with store.connection(path) as db:
        for start in range(0, len(new_ids), 400):
            group = new_ids[start:start + 400]
            rows = db.execute("SELECT id,sources FROM threats WHERE kind='campaign' AND id IN (" +
                              ",".join("?" for _ in group) + ")", group).fetchall()
            for row in rows:
                for url in json.loads(row["sources"]):
                    if _eligible(url):
                        queued += db.execute("INSERT OR IGNORE INTO article_inspection_queue "
                                             "(threat_id,source_url,next_try) VALUES (?,?,?)",
                                             (row["id"], url, now())).rowcount
                        break
    return queued


def inspect_due(path: Path | None = None, fetch=None, limit=None):
    """Inspect a bounded batch of queued reports; only store research leads, never evidence.

    Default batch size is configurable (ARTICLE_REVIEW_BATCH_SIZE, default 18,
    up from a fixed 6) so a backlog from a burst of new reports clears within
    a few poll cycles instead of growing faster than it drains.
    """
    limit = batch_size() if limit is None else limit
    with store.connection(path) as db:
        rows = db.execute("SELECT threat_id,source_url,attempts FROM article_inspection_queue "
                          "WHERE status='pending' AND next_try<=? ORDER BY next_try,threat_id LIMIT ?",
                          (now(), max(1, min(int(limit), 40)))).fetchall()
    result = {"attempted": 0, "inspected": 0, "leads": 0, "errors": {}}
    for row in rows:
        result["attempted"] += 1
        try:
            kwargs = {"fetch": fetch} if fetch else {}
            page = report_inspection.inspect_report(row["threat_id"], row["source_url"], path, **kwargs)
            with store.connection(path) as db:
                for lead in page["behavior_leads"]:
                    result["leads"] += db.execute(
                        "INSERT OR IGNORE INTO article_behavior_leads "
                        "(threat_id,source_url,sha256,behavior,paragraph,excerpt,first_seen) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (row["threat_id"], row["source_url"], page["sha256"], lead["behavior"],
                         lead["paragraph"], lead["excerpt"], now())).rowcount
                db.execute("UPDATE article_inspection_queue SET status='inspected',attempts=attempts+1,"
                           "inspected_at=?,last_error=NULL WHERE threat_id=? AND source_url=?",
                           (now(), row["threat_id"], row["source_url"]))
            result["inspected"] += 1
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            attempts = row["attempts"] + 1
            delay = timedelta(minutes=min(15 * 2 ** (attempts - 1), 720))
            next_try = (datetime.now(timezone.utc) + delay).isoformat(timespec="seconds").replace("+00:00", "Z")
            with store.connection(path) as db:
                db.execute("UPDATE article_inspection_queue SET attempts=?,status=?,next_try=?,last_error=? "
                           "WHERE threat_id=? AND source_url=?",
                           (attempts, "failed" if attempts >= 5 else "pending", next_try, str(exc)[:200],
                            row["threat_id"], row["source_url"]))
            result["errors"][row["threat_id"]] = str(exc)[:200]
    return result


def list_leads(path: Path | None = None, limit=20, days=None):
    store.initialize(path)
    cutoff = ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z")
              if days is not None else None)
    with store.connection(path) as db:
        rows = db.execute("SELECT l.*,t.title FROM article_behavior_leads l "
                          "JOIN threats t ON t.id=l.threat_id WHERE (? IS NULL OR l.first_seen>=?) "
                          "ORDER BY l.first_seen DESC,l.id DESC LIMIT ?",
                          (cutoff, cutoff, max(1, min(int(limit), 100)))).fetchall()
    return [{**dict(row), "note": "Untrusted article text; read the full source, verify the behavior and telemetry, then record an analyst observation."}
            for row in rows]


def queue_status(path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        counts = db.execute("SELECT status,COUNT(*) AS n FROM article_inspection_queue GROUP BY status").fetchall()
        leads = db.execute("SELECT COUNT(*) FROM article_behavior_leads").fetchone()[0]
    return {"article_queue": {row["status"]: row["n"] for row in counts},
            "review_required_behavior_leads": leads}
