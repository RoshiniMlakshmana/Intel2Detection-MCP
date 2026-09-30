"""Bounded, prioritized, read-only research pass over high-priority leads.

Reading a public page that a collected record already cites is read-only
research, so it runs automatically (from polling, from the MCP tools and from
research_detection_plan) without asking the analyst first. For each lead it
opens, within fixed budgets:

1. primary references from the CVE/CNA record on primary vendor hosts, and
   the lead's CISA KEV entry;
2. CISA and vendor guidance linked from those pages, and reports that cite
   the CVE (or, for a report lead, its own article).

Every page tried is recorded with its outcome and time. Publisher blocks,
unreadable (script-rendered) pages and hosts outside the allowlist are kept
apart from pages that were actually read. The conclusion is one of:

- completed_insufficient_detail: the sources were read and none names a
  specific observable a rule could be built on. Research is done; the lead
  leaves the backlog and an exposure/patch review is offered instead.
- observables_need_analyst_verification: a page contains a lexical behavior
  lead. It is stored as an untrusted article lead for the analyst to verify.
- no_readable_source: nothing primary could be read automatically; the lead
  stays in the backlog with the exact URLs to open in a browser.

Nothing here records an analyst observation, drafts or approves a rule, or
computes a numeric environment risk score.
"""

import html
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import drafting, environment, lead_queue, report_inspection, research_feeds, sources, store
from .core import get_threat, now

MAX_LEADS = 4
MAX_PAGES_PER_LEAD = 14
MAX_FETCHES_PER_PASS = 40
MAX_LINKED_GUIDANCE = 3
MAX_EVIDENCE = 15
NO_SOURCE_RETRY = timedelta(hours=12)
KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
# The collected record itself; its facts are already stored as source facts.
RECORD_HOSTS = {"nvd.nist.gov", "www.cve.org", "cveawg.mitre.org"}
PRIMARY_ROLES = ("primary_advisory", "kev_entry", "cisa_guidance", "linked_guidance")
ROLE_ORDER = {"primary_advisory": 0, "kev_entry": 1, "cisa_guidance": 2, "linked_guidance": 3, "cited_report": 4}
HREF = re.compile(rb"""href\s*=\s*["'](https://[^"'<>\s]{1,500})["']""", re.I)

# High-priority leads that need a report read before anything else can
# happen: CISA KEV advisories, reports that cite a KEV CVE, and reports whose
# text already produced a behavior lead. Everything else is a raw lead.
BACKLOG_SQL = ("((t.kind='advisory' AND t.kev=1) "
               "OR (t.kind='campaign' AND EXISTS(SELECT 1 FROM report_cves rc JOIN threats c ON c.id=rc.cve_id "
               "WHERE rc.report_id=t.id AND c.kev=1)) "
               "OR EXISTS(SELECT 1 FROM article_behavior_leads l WHERE l.threat_id=t.id) "
               # A lead the pass itself sent to verification stays actionable
               # even if it started as a raw lead. An unreadable raw lead does
               # not: triage records why it stays open instead of flooding the
               # backlog with every non-KEV CVE whose sources are blocked.
               "OR EXISTS(SELECT 1 FROM research_outcomes rv WHERE rv.threat_id=t.id "
               "AND rv.status='observables_need_analyst_verification'))")
NO_OBSERVATION_SQL = ("NOT EXISTS(SELECT 1 FROM evidence o WHERE o.threat_id=t.id "
                      "AND o.kind='analyst_observation')")


def max_leads():
    value = int(os.environ.get("RESEARCH_PASS_MAX_LEADS", str(MAX_LEADS)))
    if not 1 <= value <= 20:
        raise ValueError("RESEARCH_PASS_MAX_LEADS must be 1-20")
    return value


def _clean_url(url):
    """Drop fragments, tracking parameters and a trailing slash so one page is fetched once.

    Publishers link the same page with and without the slash (observed: the
    Citrix bulletin from two CISA pages); fetch_article retries the slash
    form itself when a publisher insists on it.
    """
    parts = urlsplit(url)
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                       if not k.lower().startswith("utm_")])
    path = parts.path.rstrip("/") if len(parts.path) > 1 else parts.path
    return urlunsplit(parts._replace(path=path, query=query, fragment=""))


def _host(url):
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _reference_role(url):
    host = _host(url)
    if host in RECORD_HOSTS or url == KEV_CATALOG:
        return None
    if url.startswith(KEV_CATALOG + "?"):
        return "kev_entry"
    if host == "www.cisa.gov":
        return "cisa_guidance"
    if host in report_inspection.PRIMARY_HOSTS:
        return "primary_advisory"
    return "cited_report"


def _candidates(threat, path):
    """(url, role, via, owner) in priority order; owner is the lead the page belongs to."""
    seen, out = set(), []

    def add(url, role, via, owner):
        if role and url not in seen and isinstance(url, str) and url.startswith("https://"):
            seen.add(url)
            out.append({"url": url, "role": role, "via": via, "owner": owner})

    for url in threat["sources"]:
        add(url, _reference_role(url), None, threat["id"])
    for item in threat["evidence"]:
        if item["kind"] in ("source_fact", "reference_pointer"):
            add(item["source_url"], _reference_role(item["source_url"]), None, threat["id"])
    for report in threat.get("related_reports", []):
        for url in report["sources"]:
            role = "cisa_guidance" if _host(url) == "www.cisa.gov" else "cited_report"
            add(url, role, report["id"], report["id"])
    return sorted(out, key=lambda c: ROLE_ORDER[c["role"]])


def _linked_guidance(raw, from_url):
    """Vendor guidance linked from a primary page (never CISA site navigation)."""
    found = []
    for match in HREF.findall(raw[:report_inspection.MAX_BYTES]):
        url = _clean_url(html.unescape(match.decode("utf-8", errors="replace")))
        host = _host(url)
        if (host in report_inspection.PRIMARY_HOSTS and host != "www.cisa.gov" and url != from_url
                and report_inspection.allowed_url(url) and url not in found):
            found.append(url)
    return found


def _fetch(url, fetch, cache, budget):
    """One network fetch per URL per pass; returns None when the pass budget is spent."""
    if url in cache:
        return cache[url]
    if not report_inspection.allowed_url(url):
        cache[url] = {"status": "not_allowlisted", "inspected_at": now(), "raw": None,
                      "detail": "Host is not a configured publisher or primary vendor host; not fetched automatically."}
        return cache[url]
    if budget["remaining"] <= 0:
        return None
    budget["remaining"] -= 1
    budget["fetched"] += 1
    try:
        cache[url] = {"status": "fetched", "raw": fetch(url), "inspected_at": now(), "detail": None}
    except ValueError as exc:
        blocked = "publisher blocked" in str(exc)
        cache[url] = {"status": "publisher_blocked" if blocked else "failed", "raw": None,
                      "inspected_at": now(), "detail": str(exc)[:200]}
    except (OSError, UnicodeError) as exc:
        cache[url] = {"status": "failed", "raw": None, "inspected_at": now(), "detail": str(exc)[:200]}
    return cache[url]


def _read(threat_id, candidate, fetched):
    """Turn a fetch into a page record plus (for readable pages) its extraction."""
    record = {"url": candidate["url"], "role": candidate["role"], "via": candidate["via"],
              "status": fetched["status"], "detail": fetched["detail"], "sha256": None,
              "paragraphs_scanned": None, "inspected_at": fetched["inspected_at"]}
    if fetched["status"] != "fetched":
        return record, None
    try:
        page = report_inspection.extract_report_html(threat_id, candidate["url"], fetched["raw"])
    except ValueError as exc:
        record.update(status="unreadable", detail=str(exc)[:200])
        return record, None
    record.update(sha256=page["sha256"], paragraphs_scanned=page["paragraphs_scanned"])
    if not page["paragraphs_scanned"]:
        record.update(status="unreadable",
                      detail="No readable article text (the page is likely rendered by script); open it in a browser.")
        return record, None
    record["status"] = "inspected"
    return record, page


def _save_page(db, threat_id, record):
    db.execute("INSERT INTO research_page_inspections (threat_id,url,role,via,status,detail,sha256,"
               "paragraphs_scanned,inspected_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(threat_id,url) DO UPDATE SET "
               "role=excluded.role,via=excluded.via,status=excluded.status,detail=excluded.detail,"
               "sha256=excluded.sha256,paragraphs_scanned=excluded.paragraphs_scanned,"
               "inspected_at=excluded.inspected_at",
               (threat_id, record["url"], record["role"], record["via"], record["status"], record["detail"],
                record["sha256"], record["paragraphs_scanned"], record["inspected_at"]))


def _keywords(threat):
    words = {threat["id"].upper(), *(c.upper() for c in threat.get("mentioned_cves", []))}
    words.update(w.upper() for item in threat.get("affected", []) for w in item.split() if len(w) > 3)
    return words


def _excerpts(threat, record, page, limit=3):
    """Excerpts that name the lead (its CVE, product or cited CVEs); site boilerplate is dropped."""
    words = _keywords(threat)
    relevant = [e for e in page["excerpts"] if any(w in e["excerpt"].upper() for w in words)]
    if not relevant and not sources.CVE.fullmatch(threat["id"]):
        relevant = page["excerpts"][:2]  # a report lead's own page is relevant by citation
    ranked = sorted(relevant, key=lambda e: threat["id"].upper() not in e["excerpt"].upper())
    return [{"url": record["url"], "role": record["role"], "paragraph": e["paragraph"], "excerpt": e["excerpt"]}
            for e in ranked[:limit]]


SHARE_HOSTS = {"twitter.com", "x.com", "facebook.com", "linkedin.com", "reddit.com", "t.me", "google.com",
               "feedburner.com", "youtube.com", "bsky.app", "mastodon.social", "whatsapp.com"}


# Only news coverage quotes someone else's research; a vendor, government or
# research page is itself the original (observed: Microsoft's own report
# otherwise "matched" the legitimate software sites its malware abuses).
NEWS_HOSTS = {urlsplit(url).hostname for _, url, category in research_feeds.FEEDS if category == "news"} | {
    "thehackernews.com"}
STATIC_ASSET = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|json|xml)$", re.I)


def _original_candidates(raw, page, from_url):
    """Links on a quoting page to the publisher it names (e.g. a research firm's own post).

    Only hosts whose name appears in the page's relevant text qualify. They
    are listed, never fetched: these hosts are outside the fetch allowlist.
    """
    text = " ".join([e["excerpt"] for e in page["excerpts"]] +
                    [d["excerpt"] for d in page.get("specific_details", [])]).lower()
    # The publisher's own domain is never "another" original: on a vendor's
    # own report (observed: Microsoft) its site navigation matched by name.
    own, found = ".".join(_host(from_url).split(".")[-2:]), []
    for match in HREF.findall(raw[:report_inspection.MAX_BYTES]):
        url = _clean_url(html.unescape(match.decode("utf-8", errors="replace")))
        host = _host(url)
        labels = host.split(".")
        name = labels[-2] if len(labels) >= 2 else ""
        if (host and ".".join(labels[-2:]) != own and host not in report_inspection.ALLOWED_HOSTS
                and len(name) >= 5 and not STATIC_ASSET.search(urlsplit(url).path)
                and ".".join(labels[-2:]) not in SHARE_HOSTS and name in text and url not in found):
            found.append(url)
    return found[:5]


def _details(record, page, raw=b""):
    details = page.get("specific_details", [])
    originals = (_original_candidates(raw, page, record["url"])
                 if details and raw and _host(record["url"]) in NEWS_HOSTS else [])
    return [{"url": record["url"], "role": record["role"], **d,
             "original_publication_candidates": originals} for d in details]


def _cves_for(threat):
    if sources.CVE.fullmatch(threat["id"]):
        return [threat["id"]]
    return threat.get("mentioned_cves", [])


def _exposure_offer(threat, path, pending_verification=False):
    cves = _cves_for(threat)
    if not cves:
        return None
    env = environment.status(path)
    has_assets = bool(env.get("configured") and env.get("assets"))
    return {
        "offered": True,
        "question": ("While the leads above are verified, run an exposure/patch review?" if pending_verification else
                     "No detection can be justified from these sources. Run an exposure/patch review instead?"),
        "cves": cves,
        "checks": ["Which assets run the affected products named in the vendor advisory",
                   "Their installed versions against the fixed versions the vendor lists",
                   "Whether those assets are internet-exposed",
                   "Whether the fix or vendor mitigation has been applied, and when"],
        "affected_products": threat.get("affected", []),
        "vendor_statement": ({"text": threat["summary"][:600], "source": threat["sources"][0] if threat["sources"] else None}
                             if sources.CVE.fullmatch(threat["id"]) else None),
        "how": (f"risk_from_asset_inventory('{cves[0]}') uses the {env['assets']} confirmed asset(s) on file."
                if has_assets else
                "No confirmed asset inventory is configured (environment_setup_status); list the affected "
                "assets, versions and exposure, or import an asset snapshot, before any risk is scored."),
        "numeric_risk_score": None,
        "note": "No numeric environment risk score is given without confirmed asset data.",
    }


def _conclude(threat, pages, evidence, observables, details, path, hunts=()):
    is_cve = bool(sources.CVE.fullmatch(threat["id"]))
    # For a CVE, only primary vendor/CISA pages decide; leads and claims found
    # in other reports stay on those report leads (which go to analyst
    # verification) and are listed here for context. For a report lead, its
    # own cited page is the source.
    decisive = [d for d in details if d["role"] in PRIMARY_ROLES or not is_cve]
    quoted = [d for d in details if d not in decisive]
    decisive_leads = [o for o in observables if o["role"] in PRIMARY_ROLES or not is_cve]
    decisive_hunts = [h for h in hunts if h["role"] in PRIMARY_ROLES or not is_cve]
    inspected = [p for p in pages if p["status"] == "inspected"]
    read_primary = [p for p in inspected if p["role"] in PRIMARY_ROLES]
    blocked = [p for p in pages if p["status"] == "publisher_blocked"]
    unreadable = [p for p in pages if p["status"] in ("unreadable", "failed")]
    outside = [p for p in pages if p["status"] == "not_allowlisted"]
    if decisive_leads or decisive or decisive_hunts:
        status = "observables_need_analyst_verification"
        summary = (f"{len(decisive_leads)} behavior lead(s) and {len(decisive)} paragraph(s) with specific artifacts "
                   f"and {len(decisive_hunts)} publisher query/queries found in {len(inspected)} inspected page(s). "
                   "They are untrusted source text until an analyst "
                   "verifies them in the full report and its original publication.")
    elif read_primary if is_cve else inspected:
        status = "completed_insufficient_detail"
        summary = (f"Research completed: {len(inspected)} page(s) inspected ({len(read_primary)} primary vendor/CISA). "
                   "Insufficient detection detail: " +
                   ("no primary vendor or CISA source names a specific observable a rule could use." if is_cve else
                    "the report names no specific observable a rule could use."))
        if quoted:
            summary += (f" {len(quoted)} paragraph(s) in secondary reports quote third-party findings with specific "
                        "artifacts; they are listed for verification against the original publication and were not "
                        "turned into indicators or rules.")
        if observables:
            summary += (f" {len(observables)} lexical behavior lead(s) in secondary reports were queued on those "
                        "reports for analyst verification.")
    else:
        status = "no_readable_source"
        summary = ("No primary vendor/CISA page could be read automatically." if is_cve else
                   "The cited report could not be read automatically.") + " Open the listed URLs in a browser."
    manual = [p["url"] for p in blocked + unreadable if p["role"] in PRIMARY_ROLES or not is_cve]
    missing = []
    if status == "completed_insufficient_detail":
        missing.append("A specific, cited observable attributed to the exploitation or intrusion (for example a "
                       "process or command line, a file path or name, an HTTP request pattern, or a network "
                       "indicator) from a primary vendor, CISA or original-research source. None of the inspected "
                       "primary pages provides one.")
    if quoted or decisive:
        originals = list(dict.fromkeys(u for d in details for u in d.get("original_publication_candidates", [])))
        missing.append("Verify the quoted claims under specific_details_to_verify in the original researcher's "
                       "publication" + (f" (linked from the quoting report: {', '.join(originals)})" if originals else "")
                       + "; only then record them (record_observed_behavior or draft_custom_detection) citing that "
                       "publication. Until then they are not detection evidence.")
    if manual:
        missing.append("Automation could not read: " + ", ".join(manual) +
                       ". Open these in a browser; if one lists concrete indicators, record them with "
                       "record_observed_behavior or draft_custom_detection.")
    env = environment.status(path)
    telemetry = ["Cannot be determined yet: required telemetry follows from a cited observable, and none was found."
                 if not decisive_leads else
                 "Follows from the behavior once an analyst verifies it; see the lead's behavior template.",
                 (f"Configured telemetry families: {', '.join(env['telemetry_families'])}; none can be matched until "
                  "an observable is cited.") if env.get("configured") else
                 "No telemetry profile is configured for this installation, so the collected log sources are also unknown."]
    return {
        "status": status, "summary": summary,
        "pages_inspected": len(inspected),
        "evidence": evidence[:MAX_EVIDENCE],
        "observables_found": observables,
        "specific_details_to_verify": details[:10],
        "publisher_hunting_queries": list(hunts)[:8],
        "publisher_blocked": [{"url": p["url"], "role": p["role"], "detail": p["detail"]} for p in blocked],
        "unreadable": [{"url": p["url"], "role": p["role"], "detail": p["detail"]} for p in unreadable],
        "not_fetched_host_not_allowlisted": [p["url"] for p in outside],
        "missing_for_detection": missing,
        "missing_telemetry": telemetry,
        "exposure_patch_review": _exposure_offer(threat, path, status == "observables_need_analyst_verification"),
        "rule_drafting": ("Not drafted. Drafting needs a cited, analyst-verified observation "
                          "(record_observed_behavior, then draft_detection or draft_custom_detection), and approval "
                          "needs the analyst's explicit 'implement this rule'. Nothing was drafted or approved."),
    }


def _store_outcome(db, threat_id, conclusion):
    db.execute("INSERT INTO research_outcomes (threat_id,status,completed_at,detail) VALUES (?,?,?,?) "
               "ON CONFLICT(threat_id) DO UPDATE SET status=excluded.status,completed_at=excluded.completed_at,"
               "detail=excluded.detail", (threat_id, conclusion["status"], now(), json.dumps(conclusion)))


def _research(threat_id, path, fetch, cache, budget, max_pages=MAX_PAGES_PER_LEAD):
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    ident = threat["id"]
    queue = _candidates(threat, path)
    pages, evidence, observables, details, hunts, owned = [], [], [], [], [], {}
    linked_added = 0
    index = 0
    while index < len(queue) and len(pages) < max_pages:
        candidate = queue[index]
        index += 1
        fetched = _fetch(candidate["url"], fetch, cache, budget)
        if fetched is None:
            break
        record, page = _read(ident, candidate, fetched)
        pages.append(record)
        if candidate["owner"] != ident:
            owned.setdefault(candidate["owner"], []).append((record, page))
        if not page:
            continue
        evidence.extend(_excerpts(threat, record, page))
        details.extend(_details(record, page, fetched["raw"]))
        hunts.extend({**h, "role": record["role"]} for h in page.get("publisher_hunts", []))
        for lead in page["behavior_leads"]:
            observables.append({"url": record["url"], "role": record["role"], **lead})
        drafting.record_paragraphs(candidate["url"], page, path)
        lead_queue.store_page_leads(candidate["owner"], candidate["url"], page, path)
        if candidate["role"] in ("primary_advisory", "kev_entry", "cisa_guidance"):
            known = {_clean_url(c["url"]) for c in queue}
            for url in _linked_guidance(fetched["raw"], candidate["url"]):
                if linked_added >= MAX_LINKED_GUIDANCE:
                    break
                if url not in known:
                    queue.append({"url": url, "role": "linked_guidance", "via": candidate["url"], "owner": ident})
                    linked_added += 1
            queue[index:] = sorted(queue[index:], key=lambda c: ROLE_ORDER[c["role"]])
    conclusion = _conclude(threat, pages, evidence, observables, details, path, hunts)
    with store.connection(path) as db:
        # A re-read replaces this lead's page set, so it never shows stale pages.
        db.execute("DELETE FROM research_page_inspections WHERE threat_id=?", (ident,))
        for record in pages:
            _save_page(db, ident, record)
        _store_outcome(db, ident, conclusion)
        # A report read while researching its CVE is itself researched: it
        # has exactly that one cited page, so conclude it from that page.
        for owner, results in owned.items():
            for record, _ in results:
                _save_page(db, owner, {**record, "role": "cited_report", "via": None})
    for owner, results in owned.items():
        report = get_threat(owner, path)
        if report and not any(e["kind"] == "analyst_observation" for e in report["evidence"]):
            report_pages = [{**r, "role": "cited_report"} for r, _ in results]
            report_evidence = [x for r, p in results if p for x in _excerpts(report, r, p)]
            report_obs = [{"url": r["url"], "role": "cited_report", **lead}
                          for r, p in results if p for lead in p["behavior_leads"]]
            report_details = [{**d, "role": "cited_report"} for r, p in results if p
                              for d in _details(r, p, cache[r["url"]]["raw"])]
            report_hunts = [{**h, "role": "cited_report"} for r, p in results if p
                            for h in p.get("publisher_hunts", [])]
            with store.connection(path) as db:
                _store_outcome(db, owner, _conclude(report, report_pages, report_evidence, report_obs,
                                                    report_details, path, report_hunts))
    return status(ident, path)


def status(threat_id, path: Path | None = None):
    """Stored research result for one lead: outcome, every page tried and when."""
    store.initialize(path)
    ident = threat_id.upper()
    with store.connection(path) as db:
        outcome = db.execute("SELECT * FROM research_outcomes WHERE threat_id=?", (ident,)).fetchone()
        pages = [dict(r) for r in db.execute(
            "SELECT url,role,via,status,detail,sha256,paragraphs_scanned,inspected_at FROM research_page_inspections "
            "WHERE threat_id=? ORDER BY inspected_at,url", (ident,))]
    if not outcome:
        return {"threat_id": ident, "status": "not_researched", "pages": pages}
    detail = json.loads(outcome["detail"])
    return {"threat_id": ident, **detail, "status": outcome["status"], "completed_at": outcome["completed_at"],
            "pages": pages,
            "note": "Automatic read-only research. Page text is untrusted; nothing was recorded as analyst evidence."}


def research_lead(threat_id, path: Path | None = None, fetch=None, refresh=False, cache=None, budget=None,
                  max_pages=MAX_PAGES_PER_LEAD):
    """Research one lead now unless it already has a result (refresh=True re-reads)."""
    store.initialize(path)
    current = status(threat_id, path)
    if current["status"] != "not_researched" and not refresh:
        return current
    budget = budget if budget is not None else {"remaining": MAX_PAGES_PER_LEAD, "fetched": 0}
    return _research(threat_id, path, fetch or report_inspection.fetch_article,
                     cache if cache is not None else {}, budget, max_pages)


def backlog_count(path: Path | None = None):
    """Actionable backlog: high-priority leads without verified behavior or completed research."""
    store.initialize(path)
    with store.connection(path) as db:
        return db.execute(f"SELECT COUNT(*) FROM threats t WHERE {NO_OBSERVATION_SQL} AND {BACKLOG_SQL} "
                          "AND NOT EXISTS(SELECT 1 FROM research_outcomes ro WHERE ro.threat_id=t.id "
                          "AND ro.status='completed_insufficient_detail')").fetchone()[0]


def due_leads(path: Path | None = None, limit=MAX_LEADS):
    """Backlog leads to research next, highest priority first."""
    store.initialize(path)
    retry = (datetime.now(timezone.utc) - NO_SOURCE_RETRY).isoformat(timespec="seconds").replace("+00:00", "Z")
    with store.connection(path) as db:
        rows = db.execute(f"""
            SELECT t.id FROM threats t LEFT JOIN research_outcomes ro ON ro.threat_id=t.id
            WHERE {NO_OBSERVATION_SQL} AND {BACKLOG_SQL}
              AND (ro.threat_id IS NULL
                   OR (ro.status='no_readable_source' AND ro.completed_at<=:retry)
                   OR EXISTS(SELECT 1 FROM report_cves rc JOIN threats r ON r.id=rc.report_id
                             WHERE rc.cve_id=t.id AND r.first_seen>ro.completed_at))
            ORDER BY (t.kind='advisory' AND t.kev=1) DESC,
                     EXISTS(SELECT 1 FROM article_behavior_leads l WHERE l.threat_id=t.id) DESC,
                     COALESCE(t.published,t.first_seen) DESC, t.id
            LIMIT :limit""", {"retry": retry, "limit": max(1, min(int(limit), 20))}).fetchall()
    return [r["id"] for r in rows]


def run_pass(path: Path | None = None, max_leads_=None, fetch=None, threat_ids=None, max_fetches=None):
    """One resumable pass; the explicit deep batch may raise the fetch budget, bounded at 120."""
    store.initialize(path)
    started = now()
    ids = [i.upper() for i in threat_ids] if threat_ids else due_leads(path, max_leads_ or max_leads())
    fetch_limit = MAX_FETCHES_PER_PASS if max_fetches is None else max(1, min(int(max_fetches), 120))
    cache, budget = {}, {"remaining": fetch_limit, "fetched": 0}
    results = []
    for ident in ids:
        if budget["remaining"] <= 0:
            break
        try:
            result = research_lead(ident, path, fetch=fetch, refresh=True, cache=cache, budget=budget)
        except ValueError as exc:
            results.append({"threat_id": ident, "status": "error", "summary": str(exc)[:200]})
            continue
        results.append({key: result.get(key) for key in (
            "threat_id", "status", "summary", "completed_at", "pages_inspected", "publisher_blocked", "unreadable",
            "evidence", "observables_found", "specific_details_to_verify", "publisher_hunting_queries",
            "missing_for_detection", "missing_telemetry", "exposure_patch_review",
            "rule_drafting")} | {"pages": result["pages"]})
    blocked = sorted({p["url"] for r in results for p in r.get("publisher_blocked") or []})
    return {"started": started, "completed": now(), "leads_researched": len(results),
            "pages_fetched": budget["fetched"], "results": results,
            "publisher_blocked_pages": blocked,
            "backlog_remaining": backlog_count(path),
            "note": ("Read-only research ran automatically; no analyst permission is needed to read cited public "
                     "pages. Nothing was recorded as evidence, drafted, approved or risk-scored.")}


# ---------------------------------------------------------------------------
# Raw-lead triage: bounded, resumable, round-robin across sources.
#
# The priority pass above works KEV CVEs and reports citing them first, with
# its own larger budget; triage runs after it with a separate small budget,
# so raw coverage grows every poll without ever taking KEV capacity. Each
# processed lead gets one triage_results row saying why it is closed or why
# it stays open; the next run resumes with leads that have no row.
# ---------------------------------------------------------------------------

TRIAGE_MAX_LEADS = 8
TRIAGE_MAX_FETCHES = 16
TRIAGE_PAGES_PER_LEAD = 4
TRIAGE_MAX_SKIPS = 200
TRIAGE_SKIP = {
    "leak_claim": ("Leak-site claim: names a claimed victim and carries no technical behavior to research; "
                   "check relevance with leak_claim_relevance."),
    "research_update": "Repository commit: review the linked diff; there is no report page to research.",
    "community_rule": "Community rule commit: compare it with your inventory; there is no report page to research.",
    "ioc": "IOC feed entry: use draft_c2_ioc_hunt for a recent high-confidence indicator; no report page to research.",
}


def raw_triage_candidates(path: Path | None = None):
    """Untriaged raw leads, newest first within each source, interleaved across sources."""
    store.initialize(path)
    with store.connection(path) as db:
        rows = db.execute(f"""
            SELECT t.id,t.kind,COALESCE((SELECT e.source_name FROM evidence e WHERE e.threat_id=t.id
                   AND e.kind='source_fact' AND e.source_name IS NOT NULL ORDER BY e.id LIMIT 1),'unlabeled')
                   AS source_name, COALESCE(t.published,t.first_seen) AS day
            FROM threats t
            WHERE {NO_OBSERVATION_SQL} AND NOT {BACKLOG_SQL}
              AND NOT EXISTS(SELECT 1 FROM research_outcomes ro WHERE ro.threat_id=t.id)
              AND NOT EXISTS(SELECT 1 FROM triage_results tr WHERE tr.threat_id=t.id)
            ORDER BY day DESC, t.id""").fetchall()
    groups = {}
    for row in rows:
        groups.setdefault(row["source_name"], []).append(dict(row))
    ordered, names = [], sorted(groups)
    while any(groups[name] for name in names):
        for name in names:
            if groups[name]:
                ordered.append(groups[name].pop(0))
    return ordered


def _record_triage(threat_id, source_name, result, reason, path):
    with store.connection(path) as db:
        db.execute("INSERT INTO triage_results (threat_id,source_name,result,reason,triaged_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT(threat_id) DO UPDATE SET source_name=excluded.source_name,result=excluded.result,"
                   "reason=excluded.reason,triaged_at=excluded.triaged_at",
                   (threat_id, source_name, result, reason[:600], now()))


def _open_reason(result):
    blocked = result.get("publisher_blocked") or []
    unreadable = result.get("unreadable") or []
    outside = result.get("not_fetched_host_not_allowlisted") or []
    parts = []
    if blocked:
        parts.append("publisher blocked: " + ", ".join(p["url"] for p in blocked[:3]))
    if unreadable:
        parts.append("unreadable or failed: " + ", ".join(p["url"] for p in unreadable[:3]))
    if outside:
        parts.append("not on an allowlisted host: " + ", ".join(outside[:3]))
    return "; ".join(parts) or result.get("summary") or "no readable primary source"


def triage_raw(path: Path | None = None, max_leads=TRIAGE_MAX_LEADS, fetch=None, max_fetches=TRIAGE_MAX_FETCHES):
    """Triage the next raw leads; returns before/after counts and why each lead is closed or still open."""
    from . import workflow
    store.initialize(path)
    before = workflow.workflow_counts(path)
    candidates = raw_triage_candidates(path)
    cache, budget = {}, {"remaining": max(1, min(int(max_fetches), 60)), "fetched": 0}
    researched, skips, processed = 0, 0, []
    limit = max(1, min(int(max_leads), 40))
    for lead in candidates:
        if skips >= TRIAGE_MAX_SKIPS:
            break
        ident, source_name = lead["id"], lead["source_name"]
        if lead["kind"] in TRIAGE_SKIP:
            skips += 1
            _record_triage(ident, source_name, "skipped_not_researchable", TRIAGE_SKIP[lead["kind"]], path)
            processed.append({"threat_id": ident, "source": source_name, "kind": lead["kind"],
                              "result": "skipped_not_researchable", "reason": TRIAGE_SKIP[lead["kind"]], "open": True})
            continue
        threat = get_threat(ident, path)
        readable = [c for c in _candidates(threat, path) if report_inspection.allowed_url(c["url"])]
        if not readable:
            cited = sorted({_host(u) for u in threat["sources"] + [e["source_url"] for e in threat["evidence"]]
                            if _host(u) and _host(u) not in RECORD_HOSTS})
            reason = ("No cited page is on a configured publisher or vendor host" +
                      (f" (cited hosts: {', '.join(cited[:5])})" if cited else " (only the collected record itself)") +
                      "; open the references manually or add a vetted host.")
            skips += 1
            _record_triage(ident, source_name, "no_allowlisted_source", reason, path)
            processed.append({"threat_id": ident, "source": source_name, "kind": lead["kind"],
                              "result": "no_allowlisted_source", "reason": reason, "open": True})
            continue
        if researched >= limit or budget["remaining"] <= 0:
            # Resumable: this lead keeps no triage row and is picked up next
            # run; cheaper no-fetch leads after it are still closed now.
            continue
        result = research_lead(ident, path, fetch=fetch, refresh=True, cache=cache, budget=budget,
                               max_pages=TRIAGE_PAGES_PER_LEAD)
        researched += 1
        status = result["status"]
        if status == "completed_insufficient_detail":
            outcome, reason, still_open = "researched_insufficient_detail", result["summary"], False
        elif status == "observables_need_analyst_verification":
            outcome, reason, still_open = "moved_to_research_backlog", result["summary"], False
        else:
            outcome = "publisher_blocked" if result.get("publisher_blocked") else "unreadable_source"
            reason, still_open = _open_reason(result), True
        _record_triage(ident, source_name, outcome, reason, path)
        processed.append({"threat_id": ident, "source": source_name, "kind": lead["kind"], "result": outcome,
                          "reason": reason, "open": still_open,
                          "publisher_blocked": [p["url"] for p in result.get("publisher_blocked") or []]})
    after = workflow.workflow_counts(path)
    keys = ("actionable_research_backlog", "raw_unreviewed_leads", "triaged_open",
            "research_completed_insufficient_detail", "evidence_recorded", "leads_total")
    return {"before": {k: before.get(k) for k in keys}, "after": {k: after.get(k) for k in keys},
            "processed": processed, "researched": researched, "skipped_without_fetch": skips,
            "pages_fetched": budget["fetched"],
            "publisher_blocks": sorted({u for p in processed for u in p.get("publisher_blocked", [])}),
            "untriaged_remaining": len(raw_triage_candidates(path)),
            "note": ("Raw triage is read-only and resumable. The KEV-first priority pass runs before it with its own "
                     "budget, so triage never takes KEV capacity. Nothing was recorded as evidence, drafted, approved "
                     "or risk-scored.")}


def triage_summary(path: Path | None = None, limit=50):
    """Why triaged leads remain open, grouped by what they need, from each lead's current queue.

    Only leads still in the triaged_open queue count as open (a lead triage later moved to the backlog or
    research_completed is not). "Read, no detection detail" counts only leads whose sources were actually
    read, automatically or by the analyst; unread sources are never counted as researched.
    """
    import collections
    from . import workflow
    store.initialize(path)
    with store.connection(path) as db:
        rows = [dict(r) for r in db.execute(
            f"SELECT tr.threat_id,tr.source_name,tr.result,tr.reason,tr.triaged_at,t.title,t.kind,"
            f"{workflow._QUEUE_SQL} AS queue FROM triage_results tr JOIN threats t ON t.id=tr.threat_id "
            "ORDER BY tr.triaged_at DESC,tr.threat_id")]
        pages = collections.defaultdict(list)
        for r in db.execute("SELECT threat_id,status,detail FROM research_page_inspections "
                            "WHERE status IN ('publisher_blocked','unreadable','failed')"):
            pages[r["threat_id"]].append(dict(r))
        read = {r["prov"]: r["n"] for r in db.execute(
            "SELECT CASE WHEN detail LIKE '%analyst_manual_review%' THEN 'analyst_manual_review' ELSE "
            "'automated_read' END AS prov, COUNT(*) AS n FROM research_outcomes ro "
            "WHERE status='completed_insufficient_detail' AND NOT EXISTS(SELECT 1 FROM evidence o WHERE "
            "o.threat_id=ro.threat_id AND o.kind='analyst_observation') GROUP BY prov")}
    open_rows = [r for r in rows if r["queue"] == "triaged_open"]

    def browser_kind(row):
        statuses = {p["status"] for p in pages.get(row["threat_id"], [])}
        details = " ".join(p["detail"] or "" for p in pages.get(row["threat_id"], []))
        if "publisher_blocked" in statuses or row["result"] == "publisher_blocked":
            return "publisher_blocked"
        if "rendered by script" in details:
            return "script_rendered"
        if "not recognizable HTML" in details or "did not return HTML" in details:
            return "not_an_html_article"  # fetched, but the response is an app shell or non-HTML document
        return "fetch_failed"

    groups = {
        "no_detection_detail_by_kind": {
            "meaning": ("Leak-site claims and repository commits: no technical report to read. Closed by kind, "
                        "not by reading."),
            "next_action": "None for detection; check leak claims with leak_claim_relevance if an alias matters.",
            "rows": [r for r in open_rows if r["result"] == "skipped_not_researchable"]},
        "needs_browser_review": {
            "meaning": "A cited page exists but automation could not read it. Not researched.",
            "next_action": ("Open the URL in a browser; record what you read with record_manual_source_review "
                            "(text, how retrieved, your decision)."),
            "rows": [r for r in open_rows if r["result"] in ("publisher_blocked", "unreadable_source")]},
        "needs_analyst_source_decision": {
            "meaning": ("Cited only on hosts outside the fetch allowlist, so never read. Not researched; no claim is "
                        "made about detection detail."),
            "next_action": ("Decide per host: open the references manually (record_manual_source_review) or vet the "
                            "host for automated reading."),
            "rows": [r for r in open_rows if r["result"] == "no_allowlisted_source"]},
    }
    other = [r for r in open_rows if not any(r in g["rows"] for g in groups.values())]
    out = {}
    for name, group in groups.items():
        entry = {"count": len(group["rows"]), "meaning": group["meaning"], "next_action": group["next_action"],
                 "examples": [{k: r[k] for k in ("threat_id", "source_name", "kind", "reason")}
                              for r in group["rows"][:max(1, min(int(limit), 200))]]}
        if name == "no_detection_detail_by_kind":
            entry["by_kind"] = dict(collections.Counter(r["kind"] for r in group["rows"]))
        if name == "needs_browser_review":
            entry["by_cause"] = dict(collections.Counter(browser_kind(r) for r in group["rows"]))
        if name == "needs_analyst_source_decision":
            hosts = collections.Counter()
            for r in group["rows"]:
                if "cited hosts: " in r["reason"]:
                    hosts.update(h.strip() for h in r["reason"].split("cited hosts: ", 1)[1].split(")")[0].split(","))
            entry["top_cited_hosts"] = dict(hosts.most_common(15))
            entry["only_the_collected_record"] = sum("only the collected record" in r["reason"] for r in group["rows"])
        out[name] = entry
    return {"open_total": len(open_rows), "groups": out,
            "other_open": [{k: r[k] for k in ("threat_id", "result", "reason")} for r in other[:20]],
            "read_no_detection_detail": read,
            "untriaged_remaining": len(raw_triage_candidates(path)),
            "results_recorded": dict(collections.Counter(r["result"] for r in rows)),
            "note": ("Counts come from each lead's current queue. Unread sources (blocked, script-rendered, outside "
                     "the allowlist) are never counted as researched.")}
