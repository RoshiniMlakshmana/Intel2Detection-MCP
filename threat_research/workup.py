"""One analyst workup per lead: pattern, why the source calls it malicious,
inventory, draft or drafting blocker, risk (three separate measures), tests
and the next analyst decision. The MCP tool and the dashboard both render
this, so they cannot disagree.

Every pattern comes from a paragraph the research pass actually inspected.
A publisher's statement is reported as that publisher's claim; it is never
presented as activity in the analyst's environment.
"""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from . import (behavior_leads, corroboration, custom_rules, drafting, environment, research_feeds, research_pass,
               rules, sources, store, workflow)
from .core import get_threat, now

HASH_KIND = {64: "sha256", 40: "sha1", 32: "md5"}
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"“(])")
FEED_CATEGORY = {"RSS: " + name: category for name, _, category in research_feeds.FEEDS}
SUFFICIENCY = {
    "sha256": "Specific file identity: the publisher's hash for this file.",
    "sha1": "Specific file identity: the publisher's hash for this file.",
    "md5": "File identity (MD5 is collision-prone; prefer SHA-256 where available).",
    "filename": "Name only: legitimate files can share this name, so it is not sufficient on its own.",
    "path": "Location only: meaningful with a process or file event and the publisher's context.",
    "ipv4": "Network indicator: infrastructure can be shared or reassigned; time-bound.",
    "quoted_file": "Name only (quoted by the source); not sufficient on its own.",
}


def _artifact(value):
    bare = value.strip("\"'“”‘’")
    if behavior_leads.HASH.fullmatch(bare):
        kind = HASH_KIND[len(bare)]
    elif IPV4.fullmatch(bare):
        kind = "ipv4"
    elif value[:1] in "\"'“‘":
        kind = "quoted_file"
    elif "/" in bare or "\\" in bare:
        kind = "path"
    else:
        kind = "filename"
    return {"value": bare, "kind": kind, "sufficiency": SUFFICIENCY[kind]}


def _suggested_spec(text, artifacts):
    """A file name paired with the hash the source prints right after it; a suggestion, never created."""
    hashes = [a for a in artifacts if a["kind"] == "sha256"]
    names = [a for a in artifacts if a["kind"] == "filename"]
    for name in names:
        start = text.find(name["value"])
        after = [(text.find(h["value"], start), h) for h in hashes if text.find(h["value"], start) > start]
        after = [(pos, h) for pos, h in after if pos - start <= 160]
        if after:
            digest = min(after, key=lambda item: item[0])[1]["value"]
            return {"event_family": "file_event", "platform": "windows",
                    "predicates": [{"field": "SHA256", "operator": "equals", "value": digest},
                                   {"field": "TargetFilename", "operator": "endswith", "value": name["value"]}]}
    return None


def _why_malicious(text, title, host):
    sentences = [s.strip() for s in SENTENCE.split(text) if behavior_leads.ACTOR.search(s)]
    cues = sorted({m.group(0).lower() for m in behavior_leads.ACTOR.finditer(text)})
    if sentences:
        explanation = (f"{host} presents this in a report titled “{title}”, and the quoted text ties it to "
                       f"{', '.join(repr(c) for c in cues[:5])}. That is the publisher's assessment of its own "
                       "analysis, not an observation in your environment.")
    else:
        explanation = (f"The paragraph lists the artifact without saying why; its only malicious context is the "
                       f"report title “{title}” from {host}. Treat it as weak until the full report is read.")
    return {"publisher_statements": sentences[:3], "cue_words": cues[:8], "explanation": explanation}


def _page_dates(url, threat, path):
    """Publication/collection dates of the lead that cites this URL (a related report when it is one)."""
    if url in threat["sources"]:
        return threat.get("published"), threat.get("first_seen"), threat["title"]
    with store.connection(path) as db:
        row = db.execute("SELECT published,first_seen,title FROM threats WHERE sources LIKE ? LIMIT 1",
                         (f'%"{url}"%',)).fetchone()
    return (row["published"], row["first_seen"], row["title"]) if row else (None, None, threat["title"])


def local_context(threat_id, path: Path | None = None):
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM local_event_context WHERE threat_id=?", (threat_id.upper(),)).fetchone()
    return dict(row) if row else None


def pattern_analysis(threat_id, path: Path | None = None):
    """Patterns only from inspected paragraphs: URL, dates, quote, artifacts and the publisher's reasoning."""
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    research = research_pass.status(threat["id"], path)
    if research["status"] == "not_researched":
        return {"threat_id": threat["id"], "patterns": [], "status": "not_researched",
                "reason": "No cited page has been inspected for this lead yet; run research_lead first. A CVE title "
                          "or headline is never used as a pattern."}
    pages = {p["url"]: p for p in research.get("pages", [])}
    context = local_context(threat["id"], path)
    items = list(research.get("specific_details_to_verify") or []) + [
        {**o, "artifacts_as_written": [], "lexical_behavior": o.get("behavior")}
        for o in research.get("observables_found") or []]
    patterns = []
    for item in items:
        url, number = item["url"], item["paragraph"]
        page = pages.get(url, {})
        with store.connection(path) as db:
            row = db.execute("SELECT text FROM inspected_paragraphs WHERE url=? AND paragraph=? AND page_sha256=?",
                             (url, number, page.get("sha256") or "")).fetchone()
        text = row["text"] if row else item["excerpt"]
        published, collected, title = _page_dates(url, threat, path)
        artifacts = [_artifact(a) for a in item.get("artifacts_as_written", [])]
        suggestion = _suggested_spec(text, artifacts)
        host = urlsplit(url).hostname or url
        is_cve = bool(sources.CVE.fullmatch(threat["id"]))
        patterns.append({
            "source_url": url, "paragraph": number, "page_role": item.get("role"),
            "published": published, "collected": collected, "inspected_at": page.get("inspected_at"),
            "page_sha256": page.get("sha256"), "quoted_paragraph": text, "quote_is_full_text": bool(row),
            "observable": ({"lexical_behavior": item["lexical_behavior"]} if item.get("lexical_behavior") else
                           {"artifacts": artifacts}),
            "why_malicious_per_source": _why_malicious(text, title, host),
            "claim_scope": ("Secondary report quoting third-party research; verify in the original publication. "
                            if is_cve and item.get("role") == "cited_report" else "") +
                           (f"Publisher's claim ({host}). Not evidence of activity in your environment: "
                            + ("no local event context is recorded for this lead."
                               if not context else f"your recorded local context says observed="
                               f"{'yes' if context['observed'] else 'no'} ({context['detail'][:120]}).")),
            "status": "unverified_quoted_claim",
            "draftable": ({"suggested_spec": suggestion,
                           "note": "Suggestion only; Claude or the analyst must confirm it against the paragraph. "
                                   "Nothing is created until propose_detection_from_paragraph is called."}
                          if suggestion else
                          {"suggested_spec": None,
                           "reason": ("Only file names or paths here: a name alone is not an attack pattern."
                                      if artifacts and all(a["kind"] in ("filename", "quoted_file", "path")
                                                           for a in artifacts) else
                                      "No file name paired with a hash in this paragraph; a spec needs a "
                                      "specific value the paragraph ties to the activity.")}),
        })
    return {"threat_id": threat["id"], "status": research["status"], "patterns": patterns,
            "never_inferred_from": "CVE titles, headlines or file names alone; only inspected paragraph text."}


def record_local_event_context(threat_id, observed, detail, asset_id=None, path: Path | None = None):
    """Analyst-supplied: whether this lead's artifact/behavior was seen in local logs, and how that was checked."""
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    value = {"yes": 1, "no": 0}.get(str(observed).lower())
    if value is None:
        raise ValueError("observed must be yes or no; leave it unrecorded when unknown")
    if not isinstance(detail, str) or not 20 <= len(detail.strip()) <= 500:
        raise ValueError("detail must say which log source, query and time range were checked (20-500 characters)")
    if asset_id:
        with store.connection(path) as db:
            if not db.execute("SELECT 1 FROM environment_assets WHERE asset_id=?", (asset_id,)).fetchone():
                raise ValueError("asset_id must be an onboarded asset")
    with store.connection(path) as db:
        db.execute("INSERT INTO local_event_context (threat_id,asset_id,observed,detail,recorded_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT(threat_id) DO UPDATE SET asset_id=excluded.asset_id,observed=excluded.observed,"
                   "detail=excluded.detail,recorded_at=excluded.recorded_at",
                   (threat["id"], asset_id, value, detail.strip(), now()))
    return {"threat_id": threat["id"], "observed": bool(value), "asset_id": asset_id,
            "note": "Local context recorded; it is analyst input, not collected telemetry, and changes no evidence."}


def _threat_priority(threat):
    if sources.CVE.fullmatch(threat["id"]):
        factors = [f"CISA KEV: {'yes' if threat['kev'] else 'no'}",
                   f"EPSS: {threat['epss']}" if threat["epss"] is not None else "EPSS: unavailable",
                   f"CVSS: {threat['cvss']}" if threat["cvss"] is not None else "CVSS: unavailable"]
        label = ("high" if threat["kev"] else "elevated" if (threat["epss"] or 0) >= 0.1 or (threat["cvss"] or 0) >= 9
                 else "standard" if threat["cvss"] is not None else "unrated")
    else:
        source = next((e["source_name"] for e in threat["evidence"] if e["kind"] == "source_fact"
                       and e.get("source_name")), None)
        category = FEED_CATEGORY.get(source or "", "unknown")
        mentions = threat.get("mentioned_cves") or []
        factors = [f"Reported by: {source or 'unlabeled'} ({category} source)",
                   f"Cites CVEs: {', '.join(mentions[:5])}" if mentions else "Cites no CVE",
                   f"Kind: {threat['kind']}"]
        label = "unverified_claim" if threat["kind"] == "leak_claim" else (
            "elevated" if category in ("research", "government") else "standard")
    return {"label": label, "factors": factors, "numeric": None,
            "meaning": "How notable the threat is in general. It is not your environment's risk."}


def risk_view(threat_id, path: Path | None = None):
    """Environment risk, threat priority and pattern_score, kept separate."""
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    env = environment.status(path)
    cves = [threat["id"]] if sources.CVE.fullmatch(threat["id"]) else list(threat.get("mentioned_cves") or [])
    context = local_context(threat["id"], path)
    with store.connection(path) as db:
        assets = [dict(r) for r in db.execute("SELECT * FROM environment_assets")]
    # Every component must describe ONE asset: the asset the local event
    # context names. An event on asset A is never combined with asset B's CVE
    # confirmation, exposure or criticality.
    cve_confirmed = [a for a in assets if set(json.loads(a["confirmed_cves"])) & set(cves)]
    asset = next((a for a in assets if context and context["asset_id"] and a["asset_id"] == context["asset_id"]),
                 None)
    missing = []
    if not env.get("configured") or not assets:
        missing.append("An onboarded asset inventory: environment_setup_status reports none.")
    if cves and not cve_confirmed:
        missing.append(f"An asset confirmed to run an affected version of {', '.join(cves[:3])}.")
    if not context:
        missing.append(f"Local event context: record_local_event_context('{threat['id']}', observed='yes' or 'no', "
                       "detail='<log source, query and time range checked>', asset_id='<the onboarded asset checked>')"
                       ".")
    elif not context["asset_id"]:
        missing.append("The recorded local event context names no asset; record it again with the asset_id that was "
                       "checked, so exposure and criticality come from that same asset.")
    elif not asset:
        missing.append(f"The local event context names asset {context['asset_id']}, which is not an onboarded asset.")
    elif cves and asset not in cve_confirmed:
        missing.append(f"The local event was recorded for asset {asset['asset_id']}, which is not confirmed to run an "
                       f"affected version of {', '.join(cves[:3])}. An event on one asset is never combined with "
                       "another asset's confirmation; record context for a confirmed asset ("
                       + (", ".join(a["asset_id"] for a in cve_confirmed[:5]) or "none onboarded")
                       + ") or confirm this asset.")
    if missing:
        env_risk = {"score": None, "status": "score unavailable", "missing_inputs": missing, "components": None}
    else:
        if cves:
            components = {"affected_version_confirmed": 30,
                          "internet_exposed": 20 if asset["internet_exposed"] else 0,
                          "asset_criticality": {"low": 0, "medium": 10, "high": 20}[asset["criticality"]],
                          "local_event_observed": 30 if context["observed"] else 0}
        else:
            components = {"local_event_observed": 50 if context["observed"] else 0,
                          "internet_exposed": 20 if asset["internet_exposed"] else 0,
                          "asset_criticality": {"low": 0, "medium": 15, "high": 30}[asset["criticality"]]}
        env_risk = {"score": sum(components.values()), "asset_id": asset["asset_id"], "components": components,
                    "status": "scored", "max": 100, "local_event_context": context,
                    "formula": "Sum of the listed components; each is shown with its value."}
    rule_rows = []
    with store.connection(path) as db:
        for row in db.execute("SELECT id,title,status,pattern_score FROM rules WHERE threat_id=?", (threat["id"],)):
            rule_rows.append({**dict(row), "meaning": "Approved independent source corroborations of this rule's "
                                                      "logic. Not a risk or likelihood score."})
    return {"environment_risk": env_risk, "threat_priority": _threat_priority(threat), "pattern_score": rule_rows,
            "note": ("Three different measures. environment_risk() is a what-if calculator on inputs you type; its "
                     "number is not this lead's environment risk. No score is shown without confirmed asset and "
                     "local event context.")}


def _review_path(draft, inventory, reviews, path):
    """The analyst gates for one draft, in order, each with its state and the exact input it needs.

    Only the analyst can complete source verification, provide labeled samples,
    declare inventory scope and approve. Sample checks do not prove SIEM accuracy.
    """
    rid, link = draft["rule_id"], draft["source"]
    steps = []

    def step(key, title, state, detail, needs=None, gate=True):
        steps.append({"key": key, "title": title, "state": state, "detail": detail, "needs_from_analyst": needs,
                      "blocks_approval": gate})

    verified = draft["source_verification"] in ("verified", "analyst_supplied_claim")
    if draft["source_verification"] == "analyst_supplied_claim":
        step("source_verification", "1. Source verification", "done", "Drafted from an analyst-supplied claim.")
    elif verified:
        step("source_verification", "1. Source verification", "done", "You verified the cited paragraph.")
    else:
        step("source_verification", "1. Source verification", "current",
             f"Paragraph {link['paragraph']} of {link['url']} (proposed by {draft.get('proposed_by')}) "
             "is cited but not verified.",
             needs=(f"Read that paragraph yourself. If it says what the draft encodes: verify_draft_source('{rid}', "
                    f"'I verified this source paragraph'). If not: reject_draft_rule('{rid}', '<reason>')."))
    check = draft["labeled_checks"]
    tested = bool(check.get("tests_current_version"))
    fields = ", ".join(draft["required_fields"] or [])
    if tested:
        provenance = check.get("sample_provenance")
        scope = ("Synthetic fixtures: checks only the listed examples; no production accuracy claim."
                 if provenance == "bundled_synthetic_fixture" else
                 "File origin is unverified: checks only the listed examples; no production accuracy claim.")
        step("labeled_events", "2. Labeled-event check", "done",
             f"{check['sample_size']} labeled events: {check['counts']} at {check['tested_at']}. {scope}")
    else:
        prior = "A check exists for an older rule version. " if check.get("tests_current_version") is False else ""
        step("labeled_events", "2. Labeled-event check", "current" if verified else "waiting",
             prior + "No labeled check covers this exact rule version.",
             needs=("A JSONL file of labeled events, one per line: event_id, timestamp, "
                    f"event_type, {fields}, expected_malicious (true/false), scenario; include benign look-alikes. "
                    f"Then test_rule_against_samples('{rid}', '<path to that file>'). Synthetic examples "
                    "must remain labeled as synthetic."))
    answer = inventory["answer"]
    scope = inventory.get("scope") or {}
    step("inventory", "3. Inventory comparison", "done" if answer in ("Yes", "No") else "attention",
         f"{answer}. " + ("Existing coverage matches; approval would link to it instead of duplicating."
                          if answer == "Yes" else scope.get("reason") or "Compared by exact fingerprint."),
         needs=(None if answer in ("Yes", "No") else
                "Only you can say your rule inventory is complete: declare_inventory_scope('<what you checked>', "
                "complete=True), or import your existing rules. Until then the answer stays Unknown."),
         gate=False)
    if draft["status"] == "approved":
        step("approval", "4. Approval", "done", "Approved in the local repository; nothing deployed.")
    elif draft["status"] == "rejected":
        step("approval", "4. Approval", "rejected", "You rejected this draft; reopen_rejected_rule to revisit.")
    else:
        ready = verified and tested
        step("approval", "4. Approval", "current" if ready else "waiting",
             "Steps 1 and 2 are complete." if ready else "Needs steps 1 and 2 first; approval is refused until then.",
             needs=(f"Your explicit request: implement_rule('{rid}', 'implement this rule'). Local repository only; "
                    "nothing is deployed or declared production validated."))
    repo = draft["repository"]
    step("repository", "5. Repository snapshot", "done" if repo["exists"] else "attention",
         f"{repo['folder']}/{rid}.json" + ("" if repo["exists"] else " (not written yet)")
         + ("" if repo["git_tracked"] else "; the folder is not under git"), gate=False)
    pending = [r for r in reviews if r["rule_id"] == rid]
    step("corroboration", "6. Corroboration", "current" if pending else "waiting",
         (f"{len(pending)} pending review(s); pattern_score {draft['pattern_score']} changes only when you approve one."
          if pending else f"pattern_score {draft['pattern_score']}. A new source whose inspected paragraph contains "
                          "every value of this rule is queued as a pending review automatically."),
         needs=(f"approve_corroboration_review({pending[0]['id']}, 'implement this rule') adds exactly +1, or "
                f"reject_corroboration_review({pending[0]['id']}, '<reason>')." if pending else None), gate=False)
    native = draft["queries"]["native_test"]
    step("native_siem_test", "7. Native SIEM test", "done" if native["status"] == "query_executed" else "pending",
         native.get("detail") or native["status"],
         needs=("A configured SIEM field mapping and read-only credentials, then test_draft_in_siem('" + rid + "'). "
                "Not required for local approval; never claimed until run."), gate=False)
    return steps


def _draft_view(rule_id, path):
    rule = rules.get_rule(rule_id, path)
    spec = custom_rules.get_spec(rule_id, path)
    link = drafting.source_link(rule_id, path)
    return {"rule_id": rule_id, "title": rule["title"], "status": rule["status"],
            "pattern_score": rule["pattern_score"],
            "source_verification": (link["status"] if link else "analyst_supplied_claim"),
            "source": ({"url": link["source_url"], "paragraph": link["paragraph"],
                        "quoted_text": link["quoted_text"], "page_sha256": link["page_sha256"]} if link else None),
            "sigma": rule["sigma"],
            "required_fields": sorted({p["field"] for p in spec["predicates"]}) if spec else None,
            "telemetry_requirements": drafting.TELEMETRY.get(spec["event_family"]) if spec else rule.get("telemetry"),
            "queries": drafting.query_status(rule_id, path),
            "labeled_checks": workflow.latest_check(rule_id, path) or {"status": "not run",
                                                                       "detail": "No labeled sample test yet."},
            "repository": workflow._repository_entry(rule_id, rule["status"], path),
            "proposed_by": link["proposed_by"] if link else None,
            "drafting_guard": ("Every predicate value must appear verbatim in the cited paragraph, and a file name "
                               "alone is refused; this draft pairs its values as the source prints them.")}


def lead_workup(threat_id, path: Path | None = None):
    """Everything an analyst needs for one decision on one lead, from stored records only."""
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    ident = threat["id"]
    progression = workflow.lead_progression(ident, path)
    research = research_pass.status(ident, path)
    patterns = pattern_analysis(ident, path)
    inventory = rules.inventory_status(ident, path)
    drafts = [_draft_view(r["id"], path) for r in threat["rules"]]
    rule_ids = {r["id"] for r in threat["rules"]}
    reviews = [r for r in corroboration.list_pending(path, 100) if r["rule_id"] in rule_ids or r["threat_id"] == ident]
    source = next((e for e in threat["evidence"] if e["kind"] == "source_fact"), None)
    suggestions = [p for p in patterns["patterns"] if (p.get("draftable") or {}).get("suggested_spec")]
    if drafts:
        blocker = None
    elif research["status"] == "not_researched":
        blocker = f"Not researched yet: research_lead('{ident}') reads the cited pages (read-only)."
    elif suggestions:
        first = suggestions[0]
        blocker = (f"No draft yet. Paragraph {first['paragraph']} of {first['source_url']} pairs a file name with "
                   "its hash; Claude may propose it with propose_detection_from_paragraph (stored unverified).")
    elif patterns["patterns"]:
        blocker = ("Not draftable from the inspected text: " +
                   "; ".join(sorted({p["draftable"].get("reason", "") for p in patterns["patterns"]
                                     if p.get("draftable")})))
    else:
        blocker = progression.get("draft_blocked_reason") or "No specific observable in the inspected sources."
    inventory_view = {"answer": inventory["status"].capitalize(), "scope": inventory.get("inventory_scope"),
                      "reason": inventory.get("reason") or inventory.get("scope"),
                      "behaviors": inventory.get("behaviors", [])}
    for draft in drafts:
        draft["review_path"] = _review_path(draft, inventory_view, reviews, path)
    open_steps = [(d["rule_id"], s) for d in drafts for s in d["review_path"] if s["state"] == "current"]
    manual = drafting.manual_reviews(ident, path)
    if open_steps:
        rule_id, first = open_steps[0]
        decision = f"{first['title']} for {rule_id}: {first['needs_from_analyst']}"
    elif any(s["state"] == "attention" and s["needs_from_analyst"] for d in drafts for s in d["review_path"]):
        first = next(s for d in drafts for s in d["review_path"] if s["state"] == "attention" and s["needs_from_analyst"])
        decision = f"{first['title']}: {first['needs_from_analyst']}"
    elif blocker and suggestions:
        decision = blocker
    else:
        decision = progression.get("next_action")
    return {"threat_id": ident, "title": threat["title"], "kind": threat["kind"],
            "source": {"name": source.get("source_name") if source else None,
                       "url": source["source_url"] if source else None},
            "published": threat.get("published"), "collected": threat.get("first_seen"),
            "research": {"status": research["status"], "completed_at": research.get("completed_at"),
                         "summary": research.get("summary"), "pages": research.get("pages", []),
                         "publisher_blocked": research.get("publisher_blocked") or []},
            "pattern_analysis": patterns,
            "inventory": inventory_view,
            "manual_source_reviews": manual,
            "drafts": drafts, "drafting_blocker": blocker,
            "corroboration_reviews": reviews,
            "risk": risk_view(ident, path),
            "tests": [{"rule_id": d["rule_id"], "labeled_checks": d["labeled_checks"],
                       "native_siem_test": d["queries"]["native_test"]} for d in drafts],
            "next_analyst_decision": decision,
            "guarantees": ("Built from stored records only. Nothing was approved, deployed, verified or scored by "
                           "this call.")}
