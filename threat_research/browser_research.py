"""Browser-to-MCP handoff for cited pages the HTTP collector cannot read.

Claude's browser connector is separate from this stdio server. It may supply
page text, but doing so never creates analyst evidence or verifies the page.
"""

import json
from pathlib import Path
from urllib.parse import urlsplit

from . import report_inspection, store
from .core import get_threat, now


def review_queue(path: Path | None = None, page=1, limit=20, category="all"):
    """Blocked pages first, then unreadable and outside-host pages; filterable."""
    store.initialize(path)
    page, limit = max(1, int(page)), max(1, min(int(limit), 20))
    if category not in ("all", "publisher_blocked", "unreadable", "outside_allowlist"):
        raise ValueError("category must be all, publisher_blocked, unreadable or outside_allowlist")
    base = """WITH review AS (
        SELECT t.id threat_id,tr.result,tr.reason,t.title,t.sources,t.first_seen,tr.triaged_at,
               (SELECT COUNT(*) FROM browser_source_captures c WHERE c.threat_id=t.id) capture_count,
               CASE
                 WHEN tr.result='publisher_blocked' OR EXISTS
                   (SELECT 1 FROM research_page_inspections p WHERE p.threat_id=t.id
                    AND p.status='publisher_blocked') OR EXISTS
                   (SELECT 1 FROM article_inspection_queue a WHERE a.threat_id=t.id
                    AND a.status='publisher_blocked') THEN 'publisher_blocked'
                 WHEN tr.result='unreadable_source' OR EXISTS
                   (SELECT 1 FROM research_page_inspections p WHERE p.threat_id=t.id
                    AND p.status IN ('unreadable','failed')) THEN 'unreadable'
                 WHEN tr.result='no_allowlisted_source' OR EXISTS
                   (SELECT 1 FROM research_page_inspections p WHERE p.threat_id=t.id
                    AND p.status='not_allowlisted') THEN 'outside_allowlist'
                 ELSE '' END category
        FROM threats t LEFT JOIN triage_results tr ON tr.threat_id=t.id)
    """
    selected = "WHERE category!=''" + (" AND category=?" if category != "all" else "")
    args = (category,) if category != "all" else ()
    with store.connection(path) as db:
        total = db.execute(base + "SELECT COUNT(*) FROM review " + selected, args).fetchone()[0]
        rows = db.execute(base + "SELECT * FROM review " + selected +
                          " ORDER BY CASE category WHEN 'publisher_blocked' THEN 0 "
                          "WHEN 'unreadable' THEN 1 ELSE 2 END, capture_count>0, "
                          "COALESCE(triaged_at,first_seen) DESC,threat_id LIMIT ? OFFSET ?",
                          args + (limit, (page - 1) * limit)).fetchall()
        items = []
        for row in rows:
            blocked = db.execute("SELECT url,status FROM research_page_inspections WHERE threat_id=? "
                                 "AND status IN ('publisher_blocked','unreadable','failed','not_allowlisted') "
                                 "ORDER BY inspected_at DESC",
                                 (row["threat_id"],)).fetchall()
            article_blocks = db.execute("SELECT source_url FROM article_inspection_queue WHERE threat_id=? "
                                        "AND status='publisher_blocked' ORDER BY source_url",
                                        (row["threat_id"],)).fetchall()
            refs = list(dict.fromkeys([r["url"] for r in blocked if r["status"] == "publisher_blocked"] +
                                      [r["source_url"] for r in article_blocks] +
                                      [r["url"] for r in blocked if r["status"] != "publisher_blocked"])) or [u for u in json.loads(row["sources"])
                  if urlsplit(u).hostname not in ("nvd.nist.gov", "www.cve.org", "cveawg.mitre.org")]
            items.append({"threat_id": row["threat_id"], "title": row["title"], "category": row["category"],
                          "reason": row["result"] or (blocked[0]["status"] if blocked else "browser_review_needed"),
                          "detail": row["reason"], "cited_urls": refs[:5],
                          "browser_captures": row["capture_count"]})
    return {"total": total, "page": page, "page_size": limit, "category": category, "items": items,
            "handoff": "Open a cited URL with a browser tool, then pass extracted article text to "
                       "capture_browser_source. A browser capture remains unverified publisher text."}


def capture(threat_id, url, page_text, path: Path | None = None):
    """Store a browser-supplied cited page, never an analyst verification."""
    from . import drafting
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    parsed = urlsplit(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("browser source must be an HTTPS URL")
    if url not in drafting._lead_urls(threat, path):
        raise ValueError("URL must be cited by this lead or already tried by its research")
    extracted = report_inspection.extract_report_text(threat["id"], url, page_text)
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO browser_source_captures "
                   "(threat_id,url,page_text,text_sha256,captured_at) VALUES (?,?,?,?,?)",
                   (threat["id"], url, page_text, extracted["sha256"], now()))
        row = db.execute("SELECT id,captured_at FROM browser_source_captures WHERE threat_id=? AND url=? "
                         "AND text_sha256=?", (threat["id"], url, extracted["sha256"])).fetchone()
    return {"browser_capture_id": row["id"], "threat_id": threat["id"], "url": url,
            "captured_at": row["captured_at"], "sha256": extracted["sha256"],
            "paragraphs_scanned": extracted["paragraphs_scanned"],
            "specific_details_to_verify": extracted["specific_details"],
            "behavior_leads_to_verify": extracted["behavior_leads"],
            "publisher_hunting_queries": extracted["publisher_hunts"],
            "status": "assistant_browser_capture_unverified", "analyst_verified": False,
            "note": "Browser text may be incomplete or altered by a page. Check the cited page yourself; "
                    "this capture creates no analyst evidence, rule, score or approval."}


def get_capture(capture_id, path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM browser_source_captures WHERE id=?", (int(capture_id),)).fetchone()
    return dict(row) if row else None


def list_captures(threat_id, path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        rows = db.execute("SELECT id,url,text_sha256,captured_at,provenance FROM browser_source_captures "
                          "WHERE threat_id=? ORDER BY id DESC LIMIT 20", (threat_id.upper(),)).fetchall()
    return [dict(row) for row in rows]


def capture_summaries(threat_id, path: Path | None = None):
    """Show only bounded source findings, so reopening a lead never returns full page text."""
    summaries = []
    for item in list_captures(threat_id, path)[:5]:
        capture = get_capture(item["id"], path)
        result = report_inspection.extract_report_text(threat_id, item["url"], capture["page_text"])
        summaries.append({**item, "paragraphs_scanned": result["paragraphs_scanned"],
                          "specific_details_to_verify": result["specific_details"][:8],
                          "behavior_leads_to_verify": result["behavior_leads"][:8],
                          "publisher_hunting_queries": result["publisher_hunts"][:8],
                          "analyst_verified": False})
    return summaries
