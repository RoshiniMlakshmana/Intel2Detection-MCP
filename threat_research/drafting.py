"""Claude-assisted detection drafts from one exact, inspected, cited paragraph.

Claude may propose a bounded predicate spec, but only from a paragraph the
research pass actually fetched and stored (page hash and text). Every
predicate value must appear verbatim in that paragraph, so nothing is
inferred from a CVE title, a headline or a bare file name. The resulting
draft is stored as *unverified*: it cites its source, but no analyst
observation exists until the analyst explicitly verifies the paragraph
(verify_draft_source), and approval is refused until then.
"""

import json
import re
import uuid
from pathlib import Path

from . import behavior_leads, custom_rules, rule_repository, store
from .core import get_threat, now

VERIFY_PHRASE = "i verified this source paragraph"
BARE_FILENAME = re.compile(r"^[\w.-]+\.[A-Za-z0-9]{1,5}$")
TELEMETRY = {
    "file_event": ("Windows file events carrying every predicate field. SHA256 needs a source that records file "
                   "hashes, e.g. Microsoft Defender DeviceFileEvents.SHA256; Sysmon Event ID 11 (FileCreate) "
                   "records no hash."),
    "process_creation": "Windows process-creation events (Sysmon Event ID 1 / Defender DeviceProcessEvents).",
    "network_connection": "Network-connection events (Sysmon Event ID 3 / Defender DeviceNetworkEvents).",
    "mcp_audit": "MCP audit events with the predicate fields.",
}
UNVERIFIED_DESCRIPTION = ("Unverified: proposed from a cited source paragraph; analyst source verification and "
                          "labeled tests pending.")


def record_paragraphs(url, page, path: Path | None = None):
    """Store the exact text of the paragraphs an inspected page result cites."""
    with store.connection(path) as db:
        db.executemany("INSERT OR IGNORE INTO inspected_paragraphs (url,paragraph,page_sha256,text,inspected_at) "
                       "VALUES (?,?,?,?,?)",
                       [(url, int(n), page["sha256"], text[:5000], now())
                        for n, text in page.get("paragraph_text", {}).items()])


def inspected_paragraph(threat_id, source_url, paragraph, path: Path | None = None):
    """The exact paragraph text from the page as inspected for this lead, or a precise refusal."""
    store.initialize(path)
    with store.connection(path) as db:
        page = db.execute("SELECT status,sha256,inspected_at FROM research_page_inspections "
                          "WHERE threat_id=? AND url=?", (threat_id.upper(), source_url)).fetchone()
        if not page or page["status"] != "inspected" or not page["sha256"]:
            raise ValueError("this source page was not inspected for this lead; run research_lead first")
        row = db.execute("SELECT text FROM inspected_paragraphs WHERE url=? AND paragraph=? AND page_sha256=?",
                         (source_url, int(paragraph), page["sha256"])).fetchone()
    if not row:
        raise ValueError(f"paragraph {paragraph} was not stored as cited text for the inspected page; "
                         "propose from a paragraph listed in lead_workup's pattern analysis")
    return {"text": row["text"], "page_sha256": page["sha256"], "inspected_at": page["inspected_at"]}


MANUAL_VIA = ("browser", "pdf", "vendor_portal", "advisory_copy", "other")
MANUAL_DECISIONS = ("undecided", "no_detection_detail", "contains_detection_detail")


def _lead_urls(threat, path):
    """URLs this lead cites or the research pass tried (including blocked, unreadable and
    original-publication candidates): the only URLs a manual review may be recorded for."""
    from . import research_pass
    urls = set(threat["sources"]) | {e["source_url"] for e in threat["evidence"]}
    research = research_pass.status(threat["id"], path)
    urls |= {p["url"] for p in research.get("pages", [])}
    urls |= {u for d in research.get("specific_details_to_verify") or []
             for u in d.get("original_publication_candidates", [])}
    return urls


def record_manual_review(threat_id, url, quoted_text, retrieved_via, decision, note, path: Path | None = None):
    """Analyst-entered text from a page automation could not read. Stored with its provenance;
    never treated as automatically verified. The decision is the analyst's, recorded as given."""
    import hashlib
    from . import research_pass
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    if retrieved_via not in MANUAL_VIA:
        raise ValueError(f"retrieved_via must be one of {', '.join(MANUAL_VIA)}")
    if decision not in MANUAL_DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(MANUAL_DECISIONS)}")
    if not isinstance(quoted_text, str) or not 20 <= len(quoted_text.strip()) <= 5000:
        raise ValueError("quoted_text must be the exact text read at the URL (20-5000 characters)")
    if not isinstance(note, str) or not 10 <= len(note.strip()) <= 500:
        raise ValueError("note must say what was read and why the decision was made (10-500 characters)")
    if url not in _lead_urls(threat, path):
        raise ValueError("the URL is not cited by this lead or tried by its research; record the review for one of "
                         "the lead's own sources")
    text = quoted_text.strip()
    digest = hashlib.sha256(text.encode()).hexdigest()
    with store.connection(path) as db:
        db.execute("INSERT INTO manual_source_reviews (threat_id,url,quoted_text,text_sha256,retrieved_via,decision,"
                   "analyst_note,entered_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(threat_id,url,text_sha256) DO UPDATE "
                   "SET decision=excluded.decision,analyst_note=excluded.analyst_note,retrieved_via=excluded.retrieved_via",
                   (threat["id"], url, text, digest, retrieved_via, decision, note.strip(), now()))
        review_id = db.execute("SELECT id FROM manual_source_reviews WHERE threat_id=? AND url=? AND text_sha256=?",
                               (threat["id"], url, digest)).fetchone()[0]
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "manual_source_review_recorded", threat["id"],
                    json.dumps({"review_id": review_id, "url": url, "decision": decision})))
    if decision == "no_detection_detail":
        conclusion = {"status": "completed_insufficient_detail", "provenance": "analyst_manual_review",
                      "summary": (f"Analyst manual review of {url} ({retrieved_via}): no detection detail. This is the "
                                  "analyst's recorded decision on manually entered text, not an automated read."),
                      "pages_inspected": 0,
                      "evidence": [{"url": url, "role": "analyst_manual_entry", "paragraph": None, "excerpt": text[:420]}],
                      "observables_found": [], "specific_details_to_verify": [], "publisher_blocked": [],
                      "unreadable": [], "not_fetched_host_not_allowlisted": [], "missing_for_detection": [],
                      "missing_telemetry": [], "exposure_patch_review": None,
                      "rule_drafting": "Not drafted: the analyst recorded that this source has no detection detail."}
        with store.connection(path) as db:
            research_pass._store_outcome(db, threat["id"], conclusion)
            db.execute("UPDATE triage_results SET result='manual_review_no_detection_detail',reason=? WHERE threat_id=?",
                       (conclusion["summary"][:600], threat["id"]))
    return {"manual_review_id": review_id, "threat_id": threat["id"], "url": url, "decision": decision,
            "provenance": "analyst_manual_entry", "verified": False,
            "next_step": ("If the text supports a detection, propose_detection_from_paragraph(..., manual_review_id="
                          f"{review_id}); the draft still needs verify_draft_source." if decision ==
                          "contains_detection_detail" else
                          "Lead closed on your recorded decision." if decision == "no_detection_detail" else
                          "Decision pending; record it again with a decision when read."),
            "note": "Manually entered text is kept with its provenance and is never treated as automatically verified."}


def manual_reviews(threat_id, path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        return [dict(r) for r in db.execute(
            "SELECT id,url,quoted_text,retrieved_via,decision,analyst_note,provenance,entered_at "
            "FROM manual_source_reviews WHERE threat_id=? ORDER BY id", (threat_id.upper(),))]


def _overlaps(normalized, fp, db):
    """Other local custom rules sharing a literal predicate (same field and value): related, not identical."""
    wanted = {(p["field"], p["value"].casefold()) for p in normalized["predicates"]}
    out = []
    for row in db.execute("SELECT c.rule_id,c.spec,r.title,r.status,r.fingerprint FROM custom_rule_specs c "
                          "JOIN rules r ON r.id=c.rule_id"):
        if row["fingerprint"] == fp:
            continue
        shared = [p for p in json.loads(row["spec"])["predicates"] if (p["field"], p["value"].casefold()) in wanted]
        if shared:
            out.append({"rule_id": row["rule_id"], "title": row["title"], "status": row["status"],
                        "shared_predicates": shared})
    return out


def _manual_source(threat_id, source_url, manual_review_id, path):
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM manual_source_reviews WHERE id=?", (int(manual_review_id),)).fetchone()
    if not row or row["threat_id"] != threat_id.upper() or row["url"] != source_url:
        raise ValueError("manual review not found for this lead and URL")
    if row["decision"] != "contains_detection_detail":
        raise ValueError("the analyst's manual review does not record this source as containing detection detail")
    return {"text": row["quoted_text"], "page_sha256": "manual:" + row["text_sha256"],
            "inspected_at": row["entered_at"], "provenance": "analyst_manual_entry"}


def propose(threat_id, source_url, paragraph, spec, title, rationale, false_positives, path: Path | None = None,
            manual_review_id=None):
    """Create an unverified, source-linked draft after an inventory comparison; never approves.

    The source is either a stored paragraph of an automatically inspected page, or (manual_review_id)
    text the analyst entered for a page automation could not read. Either way the draft is unverified.
    """
    normalized = custom_rules.validate_spec(spec)
    for label, text, low, high in (("title", title, 8, 150), ("rationale", rationale, 30, 1000),
                                   ("false_positives", false_positives, 15, 500)):
        if not isinstance(text, str) or not low <= len(text.strip()) <= high:
            raise ValueError(f"{label} needs a substantive bounded explanation")
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    source = (_manual_source(threat_id, source_url, manual_review_id, path) if manual_review_id else
              {**inspected_paragraph(threat_id, source_url, paragraph, path), "provenance": "automated_inspection"})
    quoted = source["text"]
    folded = quoted.casefold()
    absent = [p["value"] for p in normalized["predicates"] if p["value"].casefold() not in folded]
    if absent:
        raise ValueError(f"predicate value(s) not found in the cited paragraph: {absent}; every value must be "
                         "quoted from the source, never inferred")
    if all(BARE_FILENAME.fullmatch(p["value"]) for p in normalized["predicates"]):
        raise ValueError("a file name alone is not an attack pattern; add a value the paragraph ties to the "
                         "activity (a hash, command line, path or address)")
    if not (behavior_leads.ACTOR.search(quoted) or behavior_leads.HASH.search(quoted)):
        raise ValueError("the cited paragraph does not describe malicious activity or a malicious artifact")
    fp = custom_rules.fingerprint(normalized)
    title, rationale, false_positives = title.strip(), rationale.strip(), false_positives.strip()
    with store.connection(path) as db:
        local = db.execute("SELECT id,title,status,pattern_score FROM rules WHERE fingerprint=?", (fp,)).fetchone()
        external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?",
                              (fp,)).fetchone()
        overlaps = _overlaps(normalized, fp, db)
    check = {"exact_local": dict(local) if local else None, "exact_imported": dict(external) if external else None,
             "overlapping_local_rules": overlaps,
             "scope": "Exact predicate-set fingerprint against local and analyst-imported rules; overlaps share a "
                      "literal predicate but are different logic."}
    if local or external:
        return {"status": "existing_coverage" if local else "existing_external_coverage",
                "rule_id": (local or external)["id"], "inventory_check": check,
                "note": "No duplicate was created. Compare the existing rule's logic before relying on it."}
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "threat-research:" + fp))
    sigma = custom_rules._sigma(title, normalized, false_positives, UNVERIFIED_DESCRIPTION, (source_url,))
    templates = custom_rules.generic_queries(normalized)
    claim = f"Unverified cited paragraph {paragraph} (proposal {fp[:12]}): {quoted[:800]}"
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO evidence (threat_id,source_url,claim,kind,behavior,observed_at) "
                   "VALUES (?,?,?,?,?,?)", (threat["id"], source_url, claim, "cited_paragraph", "custom", now()))
        evidence_id = db.execute("SELECT id FROM evidence WHERE threat_id=? AND source_url=? AND claim=? "
                                 "AND kind='cited_paragraph'", (threat["id"], source_url, claim)).fetchone()[0]
        db.execute("INSERT INTO rules (id,threat_id,behavior,fingerprint,title,sigma,kql,spl,telemetry,rationale,"
                   "status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (rule_id, threat["id"], "custom", fp, title, sigma, templates["kql"], templates["spl"],
                    normalized["event_family"] + " / " + normalized["platform"], rationale, "draft", now()))
        db.execute("INSERT INTO custom_rule_specs VALUES (?,?)", (rule_id, json.dumps(normalized, sort_keys=True)))
        db.execute("INSERT INTO rule_evidence VALUES (?,?)", (rule_id, evidence_id))
        db.execute("INSERT INTO rule_source_links (rule_id,threat_id,source_url,paragraph,page_sha256,quoted_text,"
                   "proposed_by,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                   (rule_id, threat["id"], source_url, int(paragraph), source["page_sha256"], quoted,
                    "claude_proposal_from_" + source["provenance"], "unverified", now()))
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "draft_proposed_from_paragraph", rule_id,
                    json.dumps({"source": source_url, "paragraph": int(paragraph)})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "draft_unverified", "rule_id": rule_id, "sigma": sigma,
            "required_fields": sorted({p["field"] for p in normalized["predicates"]}),
            "telemetry_requirements": TELEMETRY[normalized["event_family"]],
            "source": {"url": source_url, "paragraph": int(paragraph), "provenance": source["provenance"],
                       "page_sha256": source["page_sha256"],
                       "inspected_at": source["inspected_at"], "quoted_text": quoted},
            "inventory_check": check,
            "queries": query_status(rule_id, path),
            "next_step": (f"Analyst: read paragraph {paragraph} at the source and, if it says what the draft "
                          f"encodes, run verify_draft_source('{rule_id}', 'I verified this source paragraph'). "
                          "Approval is refused until then.")}


def verify(rule_id, confirmation, note="", path: Path | None = None):
    """The analyst's explicit source verification: records the analyst observation; never approves."""
    if not isinstance(confirmation, str) or confirmation.strip().lower() != VERIFY_PHRASE:
        raise ValueError("explicit confirmation 'I verified this source paragraph' is required")
    with store.connection(path) as db:
        link = db.execute("SELECT * FROM rule_source_links WHERE rule_id=?", (rule_id,)).fetchone()
        if not link:
            raise ValueError("this rule has no source-linked proposal to verify")
        if link["status"] == "verified":
            return {"status": "already_verified", "rule_id": rule_id, "verified_at": link["verified_at"]}
        fp = db.execute("SELECT fingerprint FROM rules WHERE id=?", (rule_id,)).fetchone()[0]
        claim = (f"Analyst verified paragraph {link['paragraph']} of the cited source for rule {rule_id[:8]}: "
                 f"{link['quoted_text'][:700]}")
        db.execute("INSERT OR IGNORE INTO evidence (threat_id,source_url,claim,kind,behavior,observed_at) "
                   "VALUES (?,?,?,?,?,?)", (link["threat_id"], link["source_url"], claim, "analyst_observation",
                                            "custom", now()))
        evidence_id = db.execute("SELECT id FROM evidence WHERE threat_id=? AND source_url=? AND claim=? "
                                 "AND kind='analyst_observation'", (link["threat_id"], link["source_url"],
                                                                     claim)).fetchone()[0]
        db.execute("INSERT OR IGNORE INTO custom_rule_observations VALUES (?,?)", (evidence_id, fp))
        db.execute("INSERT OR IGNORE INTO rule_evidence VALUES (?,?)", (rule_id, evidence_id))
        db.execute("UPDATE rule_source_links SET status='verified',verified_at=?,verified_note=? WHERE rule_id=?",
                   (now(), (note or "")[:500], rule_id))
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "draft_source_verified", rule_id, json.dumps({"evidence_id": evidence_id})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "source_verified", "rule_id": rule_id, "evidence_id": evidence_id,
            "rule_status": "draft", "pattern_score_changed": False,
            "note": "Source verified by the analyst. The rule is still a draft; approval remains a separate decision."}


def source_link(rule_id, path: Path | None = None):
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM rule_source_links WHERE rule_id=?", (rule_id,)).fetchone()
    return dict(row) if row else None


def query_status(rule_id, path: Path | None = None):
    """Show generic KQL/SPL now and the mapped native query when configured."""
    from . import environment
    spec = custom_rules.get_spec(rule_id, path)
    templates = custom_rules.generic_queries(spec) if spec else None
    fit = environment.check_rule_fit(rule_id, path)
    if fit.get("ready") and fit.get("mapped_query"):
        return {"siem": fit.get("siem"), "query": fit["mapped_query"], "status": "generated_from_mapping",
                "mapped_query": fit["mapped_query"], "templates": templates,
                "native_test": native_test_status(rule_id, path),
                "validation": fit.get("validation")}
    reason = fit.get("reason") or (f"unmapped fields: {fit.get('missing_fields') or fit.get('missing_canonical_fields')}"
                                   if fit.get("missing_fields") or fit.get("missing_canonical_fields") else
                                   fit.get("validation") or "no native query available")
    return {"siem": fit.get("siem"), "query": None, "mapped_query": None,
            "status": "generic_templates" if templates else "not_generated", "reason": reason,
            "templates": templates, "native_test": native_test_status(rule_id, path)}


def native_test_status(rule_id, path: Path | None = None):
    from . import rules, soc_replay
    rule = rules.get_rule(rule_id, path)
    with store.connection(path) as db:
        row = db.execute("SELECT ran_at,siem,status,result,rule_hash FROM native_siem_tests WHERE rule_id=? "
                         "ORDER BY id DESC LIMIT 1", (rule_id,)).fetchone()
    if not row:
        return {"status": "pending", "detail": "No native SIEM test has been run (test_draft_in_siem)."}
    return {"status": row["status"], "ran_at": row["ran_at"], "siem": row["siem"],
            "result": json.loads(row["result"]),
            "tests_current_version": bool(rule and row["rule_hash"] == soc_replay.rule_content_hash(rule))}


def record_native_test(rule_id, result, path: Path | None = None):
    """Persist a test_draft_in_siem outcome (counts only, never events) so the workup can show it."""
    from . import rules, soc_replay
    rule = rules.get_rule(rule_id, path)
    if not rule:
        return
    with store.connection(path) as db:
        db.execute("INSERT INTO native_siem_tests (rule_id,rule_hash,ran_at,siem,status,result) VALUES (?,?,?,?,?,?)",
                   (rule_id, soc_replay.rule_content_hash(rule), now(), result.get("siem"),
                    result.get("status", "unknown"), json.dumps(result, default=str)[:4000]))
