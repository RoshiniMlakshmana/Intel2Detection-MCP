"""Read-side workflow queries shared by the dashboard and the MCP tools.

Everything here is a bounded query over what collection and analyst actions
already recorded. The page size is a display limit for this local database;
it is unrelated to any upstream API's pagination (NVD, GitHub, feeds), which
the source adapters handle and checkpoint separately.
"""

import json
import re
from pathlib import Path

from . import corroboration, environment, frameworks, research_pass, rule_repository, rules, soc_replay, store
from .core import backfill_source_names, get_threat

PAGE_SIZE = 50
STATUSES = ("research_needed", "article_leads", "research_completed", "evidence_recorded")
# Mutually exclusive work queues. research_backlog: high-priority leads (CISA
# KEV, reports citing a KEV CVE, reports with behavior leads) still needing a
# report read; raw_unreviewed: everything else nobody has looked at yet;
# research_completed: sources read, insufficient detail for a detection.
QUEUES = ("research_backlog", "raw_unreviewed", "triaged_open", "research_completed", "evidence_recorded")
RULE_STATES = ("none", "draft", "approved", "rejected")
KINDS = ("advisory", "campaign", "ioc", "leak_claim", "research_update", "community_rule")
DATE_FIELDS = ("published", "collected")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# MCP tool behind each dashboard tab, so the two surfaces stay discoverable
# from each other (the dashboard prints these; README lists the same names).
TAB_TOOLS = {
    "research_backlog": "list_leads(queue='research_backlog') / run_research_pass()",
    "raw_unreviewed": "list_leads(queue='raw_unreviewed') / triage_raw_leads()",
    "triaged_open": "list_leads(queue='triaged_open') / triage_status()",
    "draft_rules": "list_rules(state='draft')",
    "pending_reviews": "pending_corroboration_reviews()",
    "approved_rules": "list_rules(state='approved')",
    "source_errors": "source_errors()",
}

_STATUS_SQL = ("CASE WHEN EXISTS(SELECT 1 FROM evidence o WHERE o.threat_id=t.id AND o.kind='analyst_observation') "
               "THEN 'evidence_recorded' "
               "WHEN EXISTS(SELECT 1 FROM article_behavior_leads l WHERE l.threat_id=t.id) THEN 'article_leads' "
               # Without this, a lead whose sources were read showed "research_needed"
               # beside queue "research_completed".
               "WHEN EXISTS(SELECT 1 FROM research_outcomes ro WHERE ro.threat_id=t.id "
               "AND ro.status='completed_insufficient_detail') THEN 'research_completed' "
               "ELSE 'research_needed' END")
_QUEUE_SQL = ("CASE WHEN EXISTS(SELECT 1 FROM evidence o WHERE o.threat_id=t.id AND o.kind='analyst_observation') "
              "THEN 'evidence_recorded' "
              "WHEN EXISTS(SELECT 1 FROM research_outcomes ro WHERE ro.threat_id=t.id "
              "AND ro.status='completed_insufficient_detail') THEN 'research_completed' "
              f"WHEN {research_pass.BACKLOG_SQL} THEN 'research_backlog' "
              "WHEN EXISTS(SELECT 1 FROM triage_results tr WHERE tr.threat_id=t.id) THEN 'triaged_open' "
              "ELSE 'raw_unreviewed' END")
_RULE_STATE_SQL = ("CASE WHEN EXISTS(SELECT 1 FROM rules r WHERE r.threat_id=t.id AND r.status='approved') THEN 'approved' "
                   "WHEN EXISTS(SELECT 1 FROM rules r WHERE r.threat_id=t.id AND r.status='draft') THEN 'draft' "
                   "WHEN EXISTS(SELECT 1 FROM rules r WHERE r.threat_id=t.id AND r.status='rejected') THEN 'rejected' "
                   "ELSE 'none' END")


def _choice(value, allowed, label):
    if value in (None, ""):
        return None
    if value not in allowed:
        raise ValueError(f"{label} must be one of: {', '.join(allowed)}")
    return value


def _day(value, label):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not DAY.fullmatch(value):
        raise ValueError(f"{label} must be YYYY-MM-DD")
    return value


def _page(page, per_page):
    try:
        page, per_page = int(page), int(per_page)
    except (TypeError, ValueError) as exc:
        raise ValueError("page and per_page must be integers") from exc
    return max(1, page), max(1, min(per_page, PAGE_SIZE))


def source_attempts(path: Path | None = None):
    """Latest fetch outcome per source; falls back to pre-0.11 source_state errors."""
    store.initialize(path)
    with store.connection(path) as db:
        attempts = {r["name"]: dict(r) for r in db.execute("SELECT * FROM source_attempts")}
        for row in db.execute("SELECT name,last_success,last_error,last_error_at FROM source_state"):
            if row["name"] not in attempts:
                attempts[row["name"]] = {
                    "name": row["name"], "attempted_at": row["last_error_at"] or row["last_success"],
                    "status": "error" if row["last_error"] else "ok", "records": None, "detail": row["last_error"]}
    return attempts


def list_leads(path: Path | None = None, source=None, date_from=None, date_to=None, date_field="published",
               status=None, rule_state=None, kind=None, page=1, per_page=PAGE_SIZE, queue=None):
    """One bounded page of leads with a total count; filters combine with AND."""
    store.initialize(path)
    backfill_source_names(path)
    status = _choice(status, STATUSES, "status")
    queue = _choice(queue, QUEUES, "queue")
    rule_state = _choice(rule_state, RULE_STATES, "rule_state")
    kind = _choice(kind, KINDS, "kind")
    date_field = _choice(date_field or "published", DATE_FIELDS, "date_field")
    date_from, date_to = _day(date_from, "date_from"), _day(date_to, "date_to")
    page, per_page = _page(page, per_page)
    source = source or None
    if source is not None and (not isinstance(source, str) or len(source) > 120):
        raise ValueError("source must be a source name from list_sources")
    date_sql = "substr(t.published,1,10)" if date_field == "published" else "substr(t.first_seen,1,10)"
    source_pick = ("SELECT {col} FROM evidence e WHERE e.threat_id=t.id AND e.kind='source_fact' "
                   "AND e.source_name IS NOT NULL AND (:source IS NULL OR e.source_name=:source) ORDER BY e.id LIMIT 1")
    query = f"""
        WITH base AS (
          SELECT t.id,t.title,t.kind,t.kev,t.published,t.first_seen AS collected,t.sources,
                 ({source_pick.format(col='e.source_name')}) AS source_name,
                 ({source_pick.format(col='e.source_url')}) AS source_url,
                 {_STATUS_SQL} AS status, {_QUEUE_SQL} AS queue, {_RULE_STATE_SQL} AS rule_state, {date_sql} AS filter_day
          FROM threats t
          WHERE (:source IS NULL OR EXISTS(SELECT 1 FROM evidence e WHERE e.threat_id=t.id
                 AND e.kind='source_fact' AND e.source_name=:source))
            AND (:kind IS NULL OR t.kind=:kind))
        SELECT * FROM base WHERE (:status IS NULL OR status=:status)
          AND (:queue IS NULL OR queue=:queue)
          AND (:rule_state IS NULL OR rule_state=:rule_state)
          AND (:date_from IS NULL OR filter_day>=:date_from)
          AND (:date_to IS NULL OR filter_day<=:date_to)"""
    params = {"source": source, "kind": kind, "status": status, "queue": queue, "rule_state": rule_state,
              "date_from": date_from, "date_to": date_to}
    with store.connection(path) as db:
        total = db.execute(f"SELECT COUNT(*) FROM ({query})", params).fetchone()[0]
        rows = db.execute(query + " ORDER BY COALESCE(published,collected) DESC, id LIMIT :limit OFFSET :offset",
                          {**params, "limit": per_page, "offset": (page - 1) * per_page}).fetchall()
    attempts = source_attempts(path)
    items = []
    for row in rows:
        item = dict(row)
        item.pop("filter_day")
        refs = json.loads(item.pop("sources"))
        item["source_url"] = item["source_url"] or (refs[0] if refs else None)
        attempt = attempts.get(item["source_name"]) if item["source_name"] else None
        item["latest_fetch"] = ({"status": attempt["status"], "at": attempt["attempted_at"], "detail": attempt["detail"]}
                                if attempt else {"status": "unknown", "at": None, "detail": None})
        item["kev"] = bool(item["kev"])
        items.append(item)
    pages = max(1, -(-total // per_page))
    return {"total": total, "page": page, "per_page": per_page, "pages": pages,
            "has_previous": page > 1, "has_next": page < pages,
            "filters": {"source": source, "date_from": date_from, "date_to": date_to, "date_field": date_field,
                        "status": status, "queue": queue, "rule_state": rule_state, "kind": kind},
            "items": items,
            "note": "Display page of this local database (max 50 per page); unrelated to upstream API pagination."}


def list_rules(path: Path | None = None, state="draft", page=1, per_page=PAGE_SIZE):
    store.initialize(path)
    state = _choice(state, ("draft", "approved", "rejected"), "state") or "draft"
    page, per_page = _page(page, per_page)
    with store.connection(path) as db:
        total = db.execute("SELECT COUNT(*) FROM rules WHERE status=?", (state,)).fetchone()[0]
        rows = db.execute("SELECT r.id,r.title,r.behavior,r.status,r.pattern_score,r.created_at,r.threat_id,"
                          "t.title AS threat_title FROM rules r JOIN threats t ON t.id=r.threat_id WHERE r.status=? "
                          "ORDER BY r.created_at DESC,r.id LIMIT ? OFFSET ?",
                          (state, per_page, (page - 1) * per_page)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["labeled_checks"] = latest_check(row["id"], path)
        items.append(item)
    pages = max(1, -(-total // per_page))
    return {"state": state, "total": total, "page": page, "per_page": per_page, "pages": pages,
            "has_previous": page > 1, "has_next": page < pages, "items": items,
            "note": "Approved means approved in this local rule repository; nothing is deployed to a SIEM."}


def source_errors(path: Path | None = None):
    """Sources whose latest fetch failed or was partial, plus blocked article fetches."""
    items = [a for a in source_attempts(path).values() if a["status"] in ("error", "partial")]
    with store.connection(path) as db:
        articles = [dict(r) for r in db.execute(
            "SELECT threat_id,source_url,status,attempts,last_error FROM article_inspection_queue "
            "WHERE status IN ('publisher_blocked','failed') ORDER BY threat_id LIMIT 100")]
        research = [dict(r) for r in db.execute(
            "SELECT url,status,MAX(detail) AS detail,MAX(inspected_at) AS inspected_at,"
            "GROUP_CONCAT(threat_id) AS leads FROM research_page_inspections "
            "WHERE status IN ('publisher_blocked','unreadable','failed') "
            "GROUP BY url,status ORDER BY status,url LIMIT 100")]
    return {"sources": sorted(items, key=lambda a: a["name"]), "article_fetches": articles,
            "research_publisher_blocks": [r for r in research if r["status"] == "publisher_blocked"],
            "research_unreadable_pages": [r for r in research if r["status"] != "publisher_blocked"],
            "note": "A publisher block is reported as-is; read that article in a browser and record behavior manually."}


def workflow_counts(path: Path | None = None):
    """Tab counts. The four lead queues are disjoint and add up to leads_total."""
    store.initialize(path)
    with store.connection(path) as db:
        queues = {row[0]: row[1] for row in db.execute(
            f"SELECT {_QUEUE_SQL} AS queue, COUNT(*) FROM threats t GROUP BY queue")}
        drafts = db.execute("SELECT COUNT(*) FROM rules WHERE status='draft'").fetchone()[0]
        approved = db.execute("SELECT COUNT(*) FROM rules WHERE status='approved'").fetchone()[0]
        outcomes = {row[0]: row[1] for row in db.execute(
            "SELECT status,COUNT(*) FROM research_outcomes ro WHERE NOT EXISTS(SELECT 1 FROM evidence o "
            "WHERE o.threat_id=ro.threat_id AND o.kind='analyst_observation') GROUP BY status")}
    errors = source_errors(path)
    return {"actionable_research_backlog": queues.get("research_backlog", 0),
            "raw_unreviewed_leads": queues.get("raw_unreviewed", 0),
            "triaged_open": queues.get("triaged_open", 0),
            "research_completed_insufficient_detail": queues.get("research_completed", 0),
            "evidence_recorded": queues.get("evidence_recorded", 0),
            "leads_total": sum(queues.values()),
            "backlog_detail": {
                "awaiting_analyst_verification": outcomes.get("observables_need_analyst_verification", 0),
                "no_readable_source": outcomes.get("no_readable_source", 0)},
            "research_publisher_blocked_pages": len(errors["research_publisher_blocks"]),
            "draft_rules": drafts,
            "pending_reviews": corroboration.pending_count(path), "approved_rules": approved,
            "source_errors": len(errors["sources"]) + len(errors["article_fetches"])
            + len(errors["research_publisher_blocks"]),
            "definitions": {
                "actionable_research_backlog": ("CISA KEV CVEs, reports citing a KEV CVE, and reports with behavior "
                                                "leads that still need research; run_research_pass works this queue."),
                "raw_unreviewed_leads": ("Collected leads nobody has triaged yet (non-KEV CVEs, leak claims, "
                                         "general news); triage_raw_leads works through them."),
                "triaged_open": ("Raw leads triage looked at but could not close: skipped as not researchable, "
                                 "no allowlisted source, publisher blocked or unreadable; triage_status() gives "
                                 "each reason."),
                "research_completed_insufficient_detail": ("Sources were read automatically and no specific cited "
                                                           "observable supports a rule; an exposure/patch review "
                                                           "is offered instead.")},
            "mcp_tools": TAB_TOOLS}


def latest_check(rule_id, path):
    rule = rules.get_rule(rule_id, path)
    with store.connection(path) as db:
        row = db.execute("SELECT rule_hash,tested_at,sample_size,counts,sample_source,sample_provenance "
                         "FROM rule_tests WHERE rule_id=? ORDER BY id DESC LIMIT 1", (rule_id,)).fetchone()
    if not row:
        return None
    return {"tested_at": row["tested_at"], "sample_size": row["sample_size"], "counts": json.loads(row["counts"]),
            "sample_source": row["sample_source"],
            "sample_provenance": row["sample_provenance"] or "unrecorded (before provenance tracking)",
            "tests_current_version": bool(rule and row["rule_hash"] == soc_replay.rule_content_hash(rule))}


def _linked_evidence(rule_id, path):
    with store.connection(path) as db:
        local = {r[0] for r in db.execute("SELECT evidence_id FROM rule_evidence WHERE rule_id=?", (rule_id,))}
        external = db.execute("SELECT evidence_ids FROM external_inventory WHERE id=?", (rule_id,)).fetchone()
    return local | set(json.loads(external["evidence_ids"]) if external else [])


def _repository_entry(rule_id, status, path):
    root = rule_repository.repo_dir(path)
    folder = "approved" if status == "approved" else "draft"
    target = root / folder / f"{rule_id}.json"
    return {"path": str(target), "exists": target.is_file(), "folder": folder,
            "git_tracked": (root / ".git").exists(), "repository": str(root)}


def _framework_step(step, template_obs, custom_obs, path):
    """Framework mapping follows from a verified behavior, never from a CVE or headline."""
    if template_obs:
        mappings, unverified = {}, []
        for behavior in sorted({e["behavior"] for e in template_obs}):
            context = frameworks.retrieve(behavior, path, update=False)
            for name, items in context["mappings"].items():
                for item in items:
                    label = f"{item['id']} {item.get('name', '')}".strip()
                    mappings.setdefault(name, []).append(label)
                    if item.get("status") == "unverified_in_current_release":
                        unverified.append(item["id"])
        state = frameworks.status(path)
        step("framework", "Framework mapping (ATT&CK / ATLAS / OWASP)", "attention" if unverified else "done",
             "; ".join(f"{name}: {', '.join(labels)}" for name, labels in mappings.items()),
             mappings=mappings, snapshots={k: {"version": v.get("version"), "status": v["status"]}
                                           for k, v in state.items()},
             missing=(f"Not found in the stored framework releases: {', '.join(unverified)}; run refresh_frameworks."
                      if unverified else None))
    elif custom_obs:
        step("framework", "Framework mapping (ATT&CK / ATLAS / OWASP)", "attention",
             "Custom behavior: no fixed crosswalk.",
             missing="search_framework_techniques(<verified claim>) returns keyword candidates; an analyst assigns "
                     "the label after comparing full definitions.")
    else:
        step("framework", "Framework mapping (ATT&CK / ATLAS / OWASP)", "blocked",
             "Not applicable yet: no verified behavior to map.",
             missing="Framework labels follow from a verified behavior; keyword search on a headline is not a mapping.")


def _environment_step(step, threat, path):
    """Environment risk score only from confirmed assets; otherwise withheld with the reason."""
    cves = ([threat["id"]] if sources_cve(threat["id"]) else threat.get("mentioned_cves") or [])
    env = environment.status(path)
    if not cves:
        step("environment_risk", "Environment risk score", "done",
             "Not applicable: no CVE to match against assets. environment_risk() takes analyst-supplied context "
             "for campaigns; leak claims use leak_claim_relevance().", score=None)
    elif not env.get("configured") or not env.get("assets"):
        step("environment_risk", "Environment risk score", "attention",
             f"Withheld for {', '.join(cves[:3])}: no confirmed asset inventory is onboarded, so no score is assigned.",
             score=None, missing="Onboard a profile and confirmed asset CSV (environment_setup_status), then "
                                 "risk_from_asset_inventory().")
    else:
        result = environment.risk_from_assets(cves[0], path)
        top = max((m["assessment"]["score"] for m in result.get("confirmed_affected", [])), default=None)
        step("environment_risk", "Environment risk score", "done",
             (f"{result['confirmed_affected_count']} of {result['inventory_assets']} asset(s) confirmed affected by "
              f"{cves[0]}; highest score {top}." if top is not None else
              f"No asset is confirmed affected by {cves[0]}; unconfirmed assets stay unknown, not low risk."),
             score=top, assessment=result)


def sources_cve(ident):
    from .sources import CVE
    return bool(CVE.fullmatch(ident.upper()))


def _next_action(ident, current, research, draftable, rule_views, checks, steps, unverified_links=()):
    """One concrete next action, naming the tool; nothing here performs it."""
    key = current["key"] if current else "complete"
    status = research.get("status")
    if key == "research":
        if unverified_links:
            link = unverified_links[0]
            return (f"Analyst: read paragraph {link['paragraph']} at {link['source_url']}; if the draft "
                    f"matches it, verify_draft_source('{link['rule_id']}', 'I verified this source paragraph'), "
                    "otherwise reject_draft_rule(rule_id, reason). The draft remains unverified.")
        if status == "not_researched":
            return f"research_lead('{ident}'): read-only, runs without asking the analyst."
        if status == "observables_need_analyst_verification":
            originals = sorted({u for d in research.get("specific_details_to_verify") or []
                                for u in d.get("original_publication_candidates", [])})
            return ("Analyst: verify the listed leads/quoted artifacts in the full report"
                    + (f" and its original publication(s) {', '.join(originals)}" if originals else "")
                    + "; then record_observed_behavior or draft_custom_detection citing that source.")
        if status == "no_readable_source":
            urls = [p["url"] for p in (research.get("publisher_blocked") or []) + (research.get("unreadable") or [])]
            return "Analyst: open in a browser " + ", ".join(urls[:4]) + " and record any verified behavior."
        return current.get("missing") or "Read a cited technical report."
    if key == "evidence":
        if status == "completed_insufficient_detail":
            offer = research.get("exposure_patch_review")
            extra = ""
            if research.get("specific_details_to_verify"):
                extra = " Optionally verify the quoted secondary claims in their original publications."
            return ("No detection is supportable from the sources read. Offer the exposure/patch review"
                    + (f" ({offer['how']})" if offer else "") + "; do not draft a rule." + extra)
        return current.get("missing")
    if key == "candidate" and draftable:
        return f"draft_detection('{ident}', evidence_id={draftable[0]['id']})"
    if key == "checks":
        untested = [rid for rid, c in checks.items() if not (c and c["tests_current_version"])]
        return (f"test_rule_against_samples('{untested[0]}', <labeled JSONL>) with analyst-labeled positive and "
                "benign events." if untested else current.get("missing"))
    if key == "decision":
        pending = [r["id"] for r in rule_views if r["status"] == "draft"]
        return (f"Analyst decision on {', '.join(pending)}: implement_rule(..., 'implement this rule') only on the "
                "analyst's explicit request, or reject_draft_rule(rule_id, reason). Nothing is approved automatically.")
    if key == "complete":
        return "None: every step is complete. Approved means the local repository only; nothing is deployed."
    return current.get("missing")


def lead_progression(threat_id, path: Path | None = None):
    """Research needed -> evidence -> telemetry -> inventory -> candidate rule
    -> labeled checks -> analyst decision -> versioned repository.

    Each step says what is known and, when blocked, exactly which input is
    missing. Nothing here drafts, approves or corroborates anything.
    """
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    ident = threat["id"]
    observations = [e for e in threat["evidence"] if e["kind"] == "analyst_observation"]
    template_obs = [e for e in observations if e["behavior"] in rules.TEMPLATES]
    custom_obs = [e for e in observations if e["behavior"] == "custom"]
    with store.connection(path) as db:
        article_leads = [dict(r) for r in db.execute(
            "SELECT source_url,behavior,paragraph,excerpt,status FROM article_behavior_leads WHERE threat_id=? "
            "ORDER BY id LIMIT 10", (ident,))]
        reviews = [dict(r) for r in db.execute(
            "SELECT id,rule_kind,rule_id,source_url,paragraph,behavior,status FROM corroboration_reviews "
            "WHERE threat_id=? ORDER BY id DESC", (ident,))]
        source_links = [dict(r) for r in db.execute(
            "SELECT rule_id,source_url,paragraph,status FROM rule_source_links WHERE threat_id=?",
            (ident,))]
    unverified_links = [link for link in source_links if link["status"] == "unverified"]
    steps = []

    def step(key, title, state, summary, missing=None, **extra):
        steps.append({"key": key, "title": title, "state": state, "summary": summary, "missing": missing, **extra})

    source_label = {"advisory": "vulnerability record", "campaign": "article/feed entry", "ioc": "IOC feed entry",
                    "leak_claim": "leak-site claim", "research_update": "repository update",
                    "community_rule": "community rule update"}.get(threat["kind"], threat["kind"])
    research = research_pass.status(ident, path)
    research_view = ({key: research.get(key) for key in (
        "status", "completed_at", "summary", "pages", "evidence", "observables_found",
        "specific_details_to_verify", "publisher_blocked",
        "unreadable", "missing_for_detection", "missing_telemetry", "exposure_patch_review")}
        if research["status"] != "not_researched" else None)
    if observations:
        step("research", "Research needed", "done",
             f"Research recorded: {len(observations)} analyst-verified observation(s).")
    elif research["status"] == "completed_insufficient_detail":
        step("research", "Research needed", "done",
             f"{research['summary']} Completed {research['completed_at']}.", research=research_view,
             untrusted_article_leads=article_leads)
    elif research["status"] in ("observables_need_analyst_verification", "no_readable_source"):
        step("research", "Research needed", "current", f"{research['summary']} ({research['completed_at']})",
             missing=(f"An unverified source-linked draft exists. Check paragraph {unverified_links[0]['paragraph']} "
                      f"at {unverified_links[0]['source_url']} and use verify_draft_source or reject_draft_rule."
                      if unverified_links else " ".join(research["missing_for_detection"]) or
                      "Verify the behavior leads in the full report, then record a cited analyst observation."),
             research=research_view, untrusted_article_leads=article_leads)
    else:
        step("research", "Research needed", "current",
             f"Only a {source_label} is collected ({len(threat['sources'])} cited source(s)); no behavior has been verified.",
             missing=("Read a cited technical report and verify a concrete behavior (run_research_pass and "
                      "research_detection_plan read cited pages automatically). A CVE ID, headline or NVD "
                      "description is not behavior evidence and cannot produce a rule."),
             untrusted_article_leads=article_leads)

    if template_obs or custom_obs:
        step("evidence", "Cited behavior / evidence", "done",
             "; ".join(f"#{e['id']} {e['behavior']} from {e['source_url']}" for e in observations),
             evidence=[{"evidence_id": e["id"], "behavior": e["behavior"], "source_url": e["source_url"],
                        "claim": e["claim"]} for e in observations])
    else:
        step("evidence", "Cited behavior / evidence", "blocked", "No cited, analyst-verified behavior.",
             missing=((f"Draft {unverified_links[0]['rule_id']} is cited but unverified; use verify_draft_source "
                       "after checking its paragraph, or reject_draft_rule. " if unverified_links else
                       "Record the behavior with its HTTPS source (record_observed_behavior, or the dashboard form). ") +
                      f"Supported template behaviors: {', '.join(rules.TEMPLATES)}; anything else needs "
                      "draft_custom_detection with 2-8 bounded field predicates."
                      + (f" {len(article_leads)} unverified article excerpt(s) are available to check."
                         if article_leads else "")))

    telemetry = sorted({rules.TEMPLATES[e["behavior"]]["telemetry"] for e in template_obs})
    if custom_obs:
        telemetry.append("Custom spec: event family and fields declared in its draft_custom_detection spec")
    fits = []
    for rule in threat["rules"]:
        try:
            fit = environment.check_rule_fit(rule["id"], path)
            fits.append({"rule_id": rule["id"], "ready": bool(fit.get("ready")),
                         "detail": fit.get("reason") or fit.get("validation") or fit.get("missing")})
        except (ValueError, KeyError):
            continue
    if not telemetry and source_links:
        candidate_requirements = [rules.get_rule(r["id"], path)["telemetry"] for r in threat["rules"] if r["id"] in
                                  {link["rule_id"] for link in source_links}]
        step("telemetry", "Required telemetry", "attention",
             "Unverified draft requires " + ", ".join(candidate_requirements) + "; availability is unknown.",
             required=candidate_requirements, fit=fits,
             missing="Confirm the draft's log source and fields in your environment before relying on it.")
    elif not telemetry:
        step("telemetry", "Required telemetry", "blocked", "Unknown until a behavior is verified.",
             missing="Verify a behavior first; required logs follow from the behavior, not from the CVE.")
    elif fits and all(f["ready"] for f in fits):
        step("telemetry", "Required telemetry", "done", "; ".join(telemetry), required=telemetry, fit=fits)
    else:
        env_configured = environment.status(path).get("configured", False)
        step("telemetry", "Required telemetry", "attention", "; ".join(telemetry), required=telemetry, fit=fits,
             missing=("Confirm these logs and fields are collected in your SIEM (check_detection_fit)."
                      if env_configured else
                      "No telemetry profile is configured, so availability is unknown; run onboarding or "
                      "confirm the fields manually."))

    inventory = rules.inventory_status(ident, path)
    covered = [b for b in inventory["behaviors"] if b["status"] == "yes"]
    pending_reviews = [r for r in reviews if r["status"] == "pending"]
    answer = inventory["status"].capitalize()
    scope = inventory.get("inventory_scope") or {}
    scope_text = (f" Inventory scope: {scope.get('scope')} (complete={scope.get('complete')}, "
                  f"declared {scope.get('declared_at')})." if scope.get("declared") else
                  " Inventory scope: not declared, so the answer cannot be No.")
    if not inventory["behaviors"]:
        step("inventory", "Inventory Yes/No/Unknown", "blocked", "Unknown: nothing verified to compare yet." + scope_text,
             answer="Unknown", scope=scope,
             missing="Verify a behavior first; inventory is compared by behavior fingerprint.")
    elif covered:
        proposals = []
        for b in covered:
            linked = _linked_evidence(b["rule_id"], path)
            for e in b.get("evidence", []):
                if e["evidence_id"] in linked:
                    continue
                proposals.append({"rule_id": b["rule_id"], "evidence_id": e["evidence_id"],
                                  "action": (f"implement_rule(rule_id='{b['rule_id']}', approval_phrase='implement this rule', "
                                             f"new_evidence_id={e['evidence_id']})"),
                                  "effect": "Links this cited observation to the existing rule and adds +1 pattern_score once."})
        step("inventory", "Inventory Yes/No/Unknown", "done",
             "Yes: existing coverage " + ", ".join(f"{b.get('title') or b['rule_id']} ({b['rule_id']})" for b in covered),
             answer="Yes", scope=scope, existing_rules=covered, pending_corroboration_reviews=pending_reviews,
             proposed_corroboration=proposals)
    else:
        step("inventory", "Inventory Yes/No/Unknown", "done" if inventory["status"] == "no" else "attention",
             f"{answer}: " + "; ".join(b.get("note", "") for b in inventory["behaviors"]) + scope_text,
             answer=answer, scope=scope,
             missing=None if inventory["status"] == "no" else
             "Declare the complete, current rule inventory (declare_inventory_scope) before this can answer No.")

    _framework_step(step, template_obs, custom_obs, path)
    _environment_step(step, threat, path)

    covered_fps = {rules.fingerprint_for(b["behavior"]) for b in covered if b["behavior"] in rules.TEMPLATES}
    drafted = {r["behavior"] for r in threat["rules"]}
    draftable = [e for e in template_obs if e["behavior"] not in drafted
                 and rules.fingerprint_for(e["behavior"]) not in covered_fps]
    rule_views = [rules.get_rule(r["id"], path) for r in threat["rules"]]
    if rule_views:
        step("candidate", "Candidate Sigma / KQL / SPL", "done",
             "; ".join(f"{r['title']} ({r['id']}, {r['status']}" +
                       (", source unverified" if any(link["rule_id"] == r["id"] for link in unverified_links)
                        else "") + ")" for r in rule_views),
             rules=[{"rule_id": r["id"], "title": r["title"], "status": r["status"], "behavior": r["behavior"]}
                    for r in rule_views],
             draftable_evidence=[e["id"] for e in draftable])
    elif draftable:
        step("candidate", "Candidate Sigma / KQL / SPL", "current",
             "Evidence is sufficient to draft a review-only candidate.",
             draftable_evidence=[e["id"] for e in draftable])
    elif covered:
        step("candidate", "Candidate Sigma / KQL / SPL", "done",
             "Not drafted: an existing rule already covers this behavior; review corroboration instead of duplicating it.")
    else:
        step("candidate", "Candidate Sigma / KQL / SPL", "blocked", "No candidate.",
             missing=("Custom behaviors are drafted with draft_custom_detection (verified claim + bounded spec)."
                      if custom_obs else "Needs a cited, analyst-verified behavior; never generated from a CVE title."))

    checks = {r["id"]: latest_check(r["id"], path) for r in rule_views}
    if not rule_views:
        step("checks", "Labeled checks", "blocked", "Nothing to test yet.", missing="Draft a candidate rule first.")
    elif all(c and c["tests_current_version"] for c in checks.values()):
        step("checks", "Labeled checks", "done",
             "; ".join(f"{rid}: TP {c['counts']['tp']} / FP {c['counts']['fp']} / FN {c['counts']['fn']} / "
                       f"TN {c['counts']['tn']} on {c['sample_size']} labeled events" for rid, c in checks.items()),
             checks=checks)
    else:
        step("checks", "Labeled checks", "current", "At least one rule version has no labeled check.", checks=checks,
             missing=("Replay labeled positive and benign events (JSONL with event_id, event_type, scenario, "
                      "expected_malicious) via test_rule_against_samples or the dashboard form."))

    decided = [r for r in rule_views if r["status"] in ("approved", "rejected")]
    if not rule_views:
        step("decision", "Analyst decision", "blocked", "No candidate to decide on.", missing="Draft a candidate rule first.")
    elif len(decided) == len(rule_views):
        step("decision", "Analyst decision", "done", "; ".join(f"{r['id']}: {r['status']}" for r in rule_views))
    else:
        step("decision", "Analyst decision", "current",
             "Awaiting an explicit analyst approve/reject; nothing is approved automatically.",
             missing="Approve only after reviewing evidence, telemetry fit and labeled-check results.")

    entries = {r["id"]: _repository_entry(r["id"], r["status"], path) for r in rule_views}
    if not rule_views:
        step("repository", "Versioned rule repository", "blocked", "No rule snapshot yet.",
             missing="Drafted rules are written to draft/ automatically; approved ones move to approved/.")
    else:
        present = all(e["exists"] for e in entries.values())
        step("repository", "Versioned rule repository", "done" if present else "attention",
             "; ".join(f"{rid} -> {e['folder']}/{rid}.json" for rid, e in entries.items()), files=entries,
             missing=None if present else "A rule snapshot is missing; regenerate the local repository export.")

    # "attention" is a warning (e.g. telemetry not yet confirmed), not the next action.
    current = next((s for s in steps if s["state"] in ("current", "blocked")), None)
    next_action = _next_action(ident, current, research, draftable, rule_views, checks, steps, unverified_links)
    return {"threat_id": ident, "title": threat["title"], "kind": threat["kind"],
            "published": threat.get("published"), "collected": threat.get("first_seen"),
            "research_status": research["status"],
            "sources": threat["sources"], "steps": steps,
            "next_step": current["key"] if current else "complete",
            "next_action": next_action,
            "attention": [s["key"] for s in steps if s["state"] == "attention"],
            "can_draft": bool(draftable), "draftable_evidence": [e["id"] for e in draftable],
            "draft_blocked_reason": None if draftable else
            ("An existing rule already covers this behavior; review the proposed corroboration instead." if covered else
             "An unverified source-linked draft already exists; verify or reject it before redrafting."
             if unverified_links else
             "Every verified behavior already has a candidate rule." if rule_views else
             next((s["missing"] for s in steps if s.get("missing")), "Research needed.")),
            "note": "Progress view only; drafting, approval and corroboration each require an explicit analyst action."}
