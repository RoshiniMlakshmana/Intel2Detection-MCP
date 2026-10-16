"""Durable, bounded review queue for newly collected publisher articles."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import corroboration, report_inspection, store
from .core import now


SPECIFIC_ARTIFACTS = "specific_artifacts"


def batch_size():
    value = int(os.environ.get("ARTICLE_REVIEW_BATCH_SIZE", "18"))
    if not 1 <= value <= 40:
        raise ValueError("ARTICLE_REVIEW_BATCH_SIZE must be 1-40")
    return value


def _eligible(url):
    return report_inspection.allowed_url(url)


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
    result = {"attempted": 0, "inspected": 0, "leads": 0, "corroboration_reviews_queued": 0, "errors": {}}
    for row in rows:
        from .research_feeds import DISABLED_HOSTS
        if urlsplit(row["source_url"]).hostname in DISABLED_HOSTS:
            with store.connection(path) as db:
                db.execute("UPDATE article_inspection_queue SET status='failed',last_error='Source disabled: publisher blocks' WHERE threat_id=? AND source_url=?", (row["threat_id"], row["source_url"]))
            continue
        result["attempted"] += 1
        try:
            kwargs = {"fetch": fetch} if fetch else {}
            page = report_inspection.inspect_report(row["threat_id"], row["source_url"], path, **kwargs)
            with store.connection(path) as db:
                db.execute("UPDATE article_inspection_queue SET status='inspected',attempts=attempts+1,"
                           "inspected_at=?,last_error=NULL WHERE threat_id=? AND source_url=?",
                           (now(), row["threat_id"], row["source_url"]))
            stored = store_page_leads(row["threat_id"], row["source_url"], page, path)
            result["leads"] += stored["leads"]
            result["corroboration_reviews_queued"] += stored["corroboration_reviews_queued"]
            result["inspected"] += 1
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            attempts = row["attempts"] + 1
            # A publisher block is reported honestly and stops retrying after
            # a confirming second attempt; it is not a transient failure.
            blocked = "publisher blocked" in str(exc)
            delay = timedelta(minutes=min(15 * 2 ** (attempts - 1), 720))
            next_try = (datetime.now(timezone.utc) + delay).isoformat(timespec="seconds").replace("+00:00", "Z")
            with store.connection(path) as db:
                db.execute("UPDATE article_inspection_queue SET attempts=?,status=?,next_try=?,last_error=? "
                           "WHERE threat_id=? AND source_url=?",
                           (attempts, "publisher_blocked" if blocked and attempts >= 2 else
                            "failed" if attempts >= 5 else "pending", next_try, str(exc)[:200],
                            row["threat_id"], row["source_url"]))
            result["errors"][row["threat_id"]] = str(exc)[:200]
    return result


def store_page_leads(threat_id, source_url, page, path: Path | None = None):
    """Persist an inspected page's lexical behavior leads (untrusted, review-only)."""
    new_leads, count = [], 0
    with store.connection(path) as db:
        for lead in page["behavior_leads"]:
            inserted = db.execute(
                "INSERT OR IGNORE INTO article_behavior_leads "
                "(threat_id,source_url,sha256,behavior,paragraph,excerpt,first_seen) "
                "VALUES (?,?,?,?,?,?,?)",
                (threat_id, source_url, page["sha256"], lead["behavior"],
                 lead["paragraph"], lead["excerpt"], now())).rowcount
            count += inserted
            if inserted:
                # Only a genuinely new lead (this exact source/paragraph/
                # behavior was never seen before) is eligible to queue a
                # corroboration review, so a re-poll, retry, or re-fetch
                # of the same article can never queue -- let alone
                # approve -- a duplicate.
                new_leads.append(lead)
    details = page.get("specific_details") or []
    with store.connection(path) as db:
        # Derived from the latest read only: a re-read that no longer finds
        # artifacts (e.g. after a detector fix) must not leave a stale lead
        # holding the report in the backlog. Template leads are untouched.
        db.execute("DELETE FROM article_behavior_leads WHERE threat_id=? AND source_url=? AND behavior=?",
                   (threat_id, source_url, SPECIFIC_ARTIFACTS))
    if details and not page["behavior_leads"]:
        # A technical report with concrete artifacts (hashes, file names,
        # paths) needs an analyst read even when no fixed template matched;
        # without this row it stayed a raw lead after inspection. It is an
        # untrusted lead only: never evidence, never corroboration (not a
        # template behavior), never a rule.
        with store.connection(path) as db:
            count += db.execute(
                "INSERT OR IGNORE INTO article_behavior_leads "
                "(threat_id,source_url,sha256,behavior,paragraph,excerpt,first_seen) VALUES (?,?,?,?,?,?,?)",
                (threat_id, source_url, page["sha256"], SPECIFIC_ARTIFACTS, details[0]["paragraph"],
                 details[0]["excerpt"][:420], now())).rowcount
    queued = sum(1 for lead in new_leads if corroboration.queue_from_lead(
        threat_id, source_url, lead["paragraph"], lead["behavior"], lead["excerpt"], path))
    queued += len(corroboration.queue_custom_matches(threat_id, source_url, page, path))
    return {"leads": count, "corroboration_reviews_queued": queued}


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
        pending_reviews = db.execute("SELECT COUNT(*) FROM corroboration_reviews WHERE status='pending'").fetchone()[0]
    return {"article_queue": {row["status"]: row["n"] for row in counts},
            "review_required_behavior_leads": leads,
            "pending_corroboration_reviews": pending_reviews}
