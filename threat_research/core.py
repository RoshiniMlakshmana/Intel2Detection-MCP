"""Research state, explainable risk, and controlled detection inventory."""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import leak_claims, repo_updates, research_feeds, sources, store


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ingest(records, path: Path | None = None, return_new_ids=False):
    """Merge source facts by advisory identifier; a repeat is never new evidence."""
    store.initialize(path)
    inserted = 0
    new_ids = []
    promoted_ids = []
    with store.connection(path) as db:
        for record in records:
            ident = record["id"].upper()
            old = db.execute("SELECT * FROM threats WHERE id=?", (ident,)).fetchone()
            at = now()
            if old is None:
                inserted += 1
                new_ids.append(ident)
            elif (record.get("kev") and not old["kev"]) or (record.get("kind") == "ioc" and
                     (old["confidence"] or 0) < 75 <= (record.get("confidence") or 0)):
                promoted_ids.append(ident)
            refs = set(json.loads(old["sources"]) if old else [])
            refs.add(record["source"])
            affected = set(json.loads(old["affected"]) if old else [])
            affected.update(x for x in record.get("affected", []) if x)
            summary = (record.get("summary") or (old["summary"] if old else ""))[:8000]
            db.execute("""
                INSERT INTO threats (id,title,summary,published,updated,first_seen,last_seen,kev,epss,cvss,affected,sources,kind,indicator,indicator_type,confidence,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    title=CASE WHEN length(excluded.title)>length(threats.title) THEN excluded.title ELSE threats.title END,
                    summary=CASE WHEN length(excluded.summary)>length(threats.summary) THEN excluded.summary ELSE threats.summary END,
                    updated=excluded.updated,last_seen=excluded.last_seen,
                    kev=MAX(threats.kev,excluded.kev),
                    cvss=COALESCE(excluded.cvss,threats.cvss),
                    affected=excluded.affected,sources=excluded.sources,
                    kind=excluded.kind,indicator=COALESCE(excluded.indicator,threats.indicator),
                    indicator_type=COALESCE(excluded.indicator_type,threats.indicator_type),
                    confidence=COALESCE(excluded.confidence,threats.confidence),
                    expires_at=COALESCE(excluded.expires_at,threats.expires_at)
            """, (ident, (record.get("title") or ident)[:300], summary,
                  record.get("published"), record.get("updated"), at, at,
                  int(record.get("kev", False)), None, record.get("cvss"),
                  json.dumps(sorted(affected)), json.dumps(sorted(refs)), record.get("kind", "advisory"),
                  record.get("indicator"), record.get("indicator_type"), record.get("confidence"),
                  record.get("expires_at")))
            db.execute("""INSERT OR IGNORE INTO evidence
                (threat_id,source_url,claim,kind,behavior,observed_at,source_name) VALUES (?,?,?,?,?,?,?)""",
                (ident, record["source"], record.get("claim", "Source published a record."),
                 "source_fact", None, at, record.get("reported_by")))
            for ref in record.get("references", []):
                if isinstance(ref, str) and ref.startswith("https://") and len(ref) <= 500:
                    db.execute("""INSERT OR IGNORE INTO evidence
                        (threat_id,source_url,claim,kind,behavior,observed_at) VALUES (?,?,?,?,?,?)""",
                        (ident, ref, "NVD lists this reference; its contents have not been verified by this tool.",
                         "reference_pointer", None, at))
            if record.get("kind") in ("campaign", "research_update", "community_rule"):
                for cve in record.get("mentioned_cves", []):
                    if sources.CVE.fullmatch(cve):
                        db.execute("INSERT OR IGNORE INTO report_cves (report_id,cve_id) VALUES (?,?)", (ident, cve))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "ingest", "feeds", json.dumps({"new_records": inserted})))
    return (inserted, new_ids, promoted_ids) if return_new_ids else inserted


def collect_daily(path: Path | None = None, since=None, until=None, adapters=None, include_ids=False, source_since=None):
    """Collect independently: a failed source cannot be mistaken for no threats."""
    store.initialize(path)
    until = until or datetime.now(timezone.utc)
    since = since or until - timedelta(days=2)
    include_research = adapters is None
    source_since = source_since or {}
    if include_research:
        adapters = {
            "CISA KEV": lambda: sources.collect_kev(source_since.get("CISA KEV", since)),
            "NVD": lambda: sources.collect_nvd(source_since.get("NVD", since), until),
            "GitHub advisories": lambda: sources.collect_ghsa(source_since.get("GitHub advisories", since)),
        }
        if os.environ.get("THREATFOX_AUTH_KEY"):
            adapters["ThreatFox C2"] = lambda: sources.collect_threatfox(source_since.get("ThreatFox C2", since))
        adapters["RansomLook leak claims"] = lambda: leak_claims.collect_ransomlook(source_since.get("RansomLook leak claims", since), until)
        for name, repo, repo_path, kind in repo_updates.REPOSITORIES:
            adapters["GitHub: " + name] = (lambda r=repo, p=repo_path, k=kind, n=name:
                                                   repo_updates.collect_catalog(r, p, k, source_since.get("GitHub: " + n, since), until,
                                                       database=path, source_name="GitHub: " + n))
    result = {"new_records": 0, "sources": {}, "errors": {}, "partial": {}}
    newly_inserted = []
    promoted = []
    ids = set()
    for name, collect in adapters.items():
        try:
            try:
                records = list(collect())
            except sources.PartialCollection as partial:
                # Keep what arrived, but report the source as incomplete; the
                # poller checkpoints only through partial.complete_through.
                records = partial.records
                result["errors"][name] = str(partial)[:300]
                result["partial"][name] = partial.complete_through.isoformat().replace("+00:00", "Z")
            for record in records:
                record.setdefault("reported_by", name)
            inserted, fresh, changed = ingest(records, path, return_new_ids=True)
            if records and records[0].get("bootstrap_repo"):
                with store.connection(path) as db:
                    db.execute("INSERT OR REPLACE INTO repo_bootstraps(repo,snapshot_sha,completed_at) VALUES (?,?,?)",
                               (records[0]["bootstrap_repo"], records[0]["bootstrap_sha"], now()))
            result["sources"][name] = len(records)
            result["new_records"] += inserted
            newly_inserted.extend(fresh)
            promoted.extend(changed)
            ids.update(r["id"] for r in records)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            result["errors"][name] = str(exc)[:300]
    if include_research:
        try:
            with store.connection(path) as db:
                populated = {r["name"] for r in db.execute("SELECT name FROM source_state WHERE total_records>0")}
                populated |= {r["source_name"] for r in db.execute("SELECT DISTINCT source_name FROM evidence WHERE source_name IS NOT NULL")}
            feed_since = dict(source_since)
            for name, _, _ in research_feeds.FEEDS:
                if "RSS: " + name not in populated:
                    feed_since["RSS: " + name] = until - timedelta(days=research_feeds.INITIAL_LOOKBACK_DAYS)
            if feed_since:
                report_records, counts, errors = research_feeds.collect_research(since, until, since_by_name=feed_since, retries=1)
            else:
                report_records, counts, errors = research_feeds.collect_research(since, until, retries=1)
            result["errors"].update({"RSS: " + name: error for name, error in errors.items()})
            # Keep individual feed failures visible, even when another publisher works.
            inserted, fresh, changed = ingest(report_records, path, return_new_ids=True)
            result["sources"].update({"RSS: " + name: count for name, count in counts.items()})
            result["new_records"] += inserted
            newly_inserted.extend(fresh)
            promoted.extend(changed)
        except (OSError, ValueError, RuntimeError) as exc:
            result["errors"]["RSS research feeds"] = str(exc)[:300]
    if ids:
        try:
            scores = sources.enrich_epss(sorted(ids))
            with store.connection(path) as db:
                for ident, score in scores.items():
                    db.execute("UPDATE threats SET epss=? WHERE id=?", (score, ident))
            result["sources"]["FIRST EPSS"] = len(scores)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            result["errors"]["FIRST EPSS"] = str(exc)[:300]
    if include_ids:
        result["new_ids"] = newly_inserted
        result["alert_ids"] = list(dict.fromkeys(newly_inserted + promoted))
    return result


def backfill_source_names(path: Path | None = None):
    """Label older evidence rows collected before source_name existed.

    Best-effort hostname/prefix matching against the same adapter catalog
    collect_daily already uses; it never guesses a source that isn't in
    that catalog, and never touches a row that already has a source_name.
    """
    from . import repo_updates, research_feeds

    store.initialize(path)
    with store.connection(path) as db:
        pending = db.execute("SELECT COUNT(*) FROM evidence WHERE kind='source_fact' AND source_name IS NULL").fetchone()[0]
        if not pending:
            return 0
        rows = db.execute("SELECT id,source_url FROM evidence WHERE kind='source_fact' AND source_name IS NULL").fetchall()
        rss_hosts = {urlsplit(url).hostname: "RSS: " + name for name, url, _ in research_feeds.FEEDS}
        # Feeds served through a redirector host publish articles elsewhere.
        rss_hosts["thehackernews.com"] = "RSS: The Hacker News"
        repo_prefixes = {f"https://github.com/{repo}/commit/": "GitHub: " + name for name, repo, _, _ in repo_updates.REPOSITORIES}
        updated = 0
        for row in rows:
            url = row["source_url"]
            host = urlsplit(url).hostname
            name = None
            if url == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog":
                name = "CISA KEV"
            elif url.startswith("https://nvd.nist.gov/vuln/detail/") or url.startswith("https://www.cve.org/CVERecord"):
                name = "NVD"
            elif host == "github.com" and "/advisories/" in url:
                name = "GitHub advisories"
            elif url == "https://www.ransomlook.io/recent":
                name = "RansomLook leak claims"
            elif url.startswith("https://threatfox.abuse.ch/"):
                name = "ThreatFox C2"
            else:
                for prefix, repo_name in repo_prefixes.items():
                    if url.startswith(prefix):
                        name = repo_name
                        break
                if name is None:
                    name = rss_hosts.get(host)
            if name:
                db.execute("UPDATE evidence SET source_name=? WHERE id=?", (name, row["id"]))
                updated += 1
    return updated


def enrich_from_cna(ident, path: Path | None = None):
    if get_threat(ident, path) is None:
        raise ValueError("collect the CVE first")
    record = sources.collect_cve_record(ident)
    ingest([record], path)
    return research_view(ident, path)


def intake_cve(ident, path: Path | None = None, fetch=sources.collect_cve_record):
    """Research a published CVE by ID even when it missed the rolling feed."""
    ident = ident.upper()
    if not sources.CVE.fullmatch(ident):
        raise ValueError("a valid CVE ID is required")
    if get_threat(ident, path) is None:
        ingest([fetch(ident)], path)
    return get_threat(ident, path)


def list_threats(path: Path | None = None, limit=20, days=7):
    store.initialize(path)
    limit = max(1, min(int(limit), 100))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, min(int(days), 90)))).isoformat().replace("+00:00", "Z")
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM threats WHERE last_seen>=? ORDER BY kev DESC, epss DESC, last_seen DESC LIMIT ?", (cutoff, limit)).fetchall()
    return [store.row_dict(row) for row in rows]


def list_emerging(path: Path | None = None, limit=20):
    store.initialize(path)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM threats WHERE kind IN ('ioc','campaign','leak_claim','research_update','community_rule') AND last_seen>=? "
                          "AND (expires_at IS NULL OR expires_at>?) ORDER BY COALESCE(published,last_seen) DESC LIMIT ?",
                          (cutoff, now(), max(1, min(int(limit), 100)))).fetchall()
    return [store.row_dict(row) for row in rows]


def list_community_updates(path: Path | None = None, limit=20):
    store.initialize(path)
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM threats WHERE kind IN ('community_rule','research_update') "
                          "ORDER BY COALESCE(published,last_seen) DESC LIMIT ?", (max(1, min(int(limit), 100)),)).fetchall()
    return [store.row_dict(row) for row in rows]


def get_threat(ident, path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        threat = store.row_dict(db.execute("SELECT * FROM threats WHERE id=?", (ident.upper(),)).fetchone())
        if threat:
            threat["evidence"] = [dict(x) for x in db.execute("SELECT * FROM evidence WHERE threat_id=? ORDER BY id", (ident.upper(),))]
            threat["rules"] = [dict(x) for x in db.execute("SELECT id,title,status,pattern_score,behavior FROM rules WHERE threat_id=?", (ident.upper(),))]
            if threat["kind"] in ("campaign", "research_update", "community_rule"):
                threat["mentioned_cves"] = [r["cve_id"] for r in db.execute("SELECT cve_id FROM report_cves WHERE report_id=?", (ident.upper(),))]
            elif sources.CVE.fullmatch(ident.upper()):
                threat["related_reports"] = [dict(r) for r in db.execute(
                    "SELECT t.id,t.title,t.published,t.sources FROM report_cves rc JOIN threats t ON t.id=rc.report_id "
                    "WHERE rc.cve_id=? ORDER BY t.published DESC LIMIT 30", (ident.upper(),))]
                for item in threat["related_reports"]:
                    item["sources"] = json.loads(item["sources"])
    return threat


def add_behavior_evidence(ident, source_url, claim, behavior, path: Path | None = None):
    """Analyst supplied observed behavior, tied to a specific public source."""
    if behavior not in ("web_server_shell", "encoded_powershell", "mcp_unauthorized_execution"):
        raise ValueError("unsupported behavior; use web_server_shell, encoded_powershell, or mcp_unauthorized_execution")
    if not source_url.startswith("https://") or len(source_url) > 500 or not 12 <= len(claim) <= 1000:
        raise ValueError("a specific HTTPS source and substantive claim are required")
    with store.connection(path) as db:
        target = db.execute("SELECT kind FROM threats WHERE id=?", (ident.upper(),)).fetchone()
        if not target:
            raise ValueError("unknown threat")
        if target["kind"] == "leak_claim" and urlsplit(source_url).hostname in ("ransomlook.io", "www.ransomlook.io"):
            raise ValueError("a leak-site claim listing does not document observed behavior; cite independent technical research")
        db.execute("INSERT OR IGNORE INTO evidence (threat_id,source_url,claim,kind,behavior,observed_at) VALUES (?,?,?,?,?,?)",
                   (ident.upper(), source_url, claim, "analyst_observation", behavior, now()))
        row = db.execute("SELECT id FROM evidence WHERE threat_id=? AND source_url=? AND claim=? AND kind='analyst_observation'", (ident.upper(), source_url, claim)).fetchone()
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "evidence_added", ident.upper(), json.dumps({"evidence_id": row["id"], "behavior": behavior})))
    return row["id"]


def record_campaign_report(title, summary, source_url, path: Path | None = None):
    """Analyst-curated report intake independent of a CVE identifier."""
    url = urlsplit(source_url)
    if url.scheme != "https" or not url.hostname or not 10 <= len(title) <= 200 or not 40 <= len(summary) <= 3000:
        raise ValueError("report needs a HTTPS source, title (10-200), and summary (40-3000)")
    ident = "REPORT-" + hashlib.sha256(source_url.encode()).hexdigest()[:16].upper()
    ingest([{"id": ident, "title": title, "summary": summary, "kind": "campaign",
             "source": source_url, "claim": "Analyst registered this report for research; details require source review."}], path)
    return {"id": ident, "status": "research_needed", "source": source_url}


def assess_risk(ident, environment, path: Path | None = None):
    threat = get_threat(ident, path)
    if threat is None:
        raise ValueError("unknown threat")
    if threat["kind"] in ("research_update", "community_rule"):
        return {"threat_id": ident, "environment": environment, "score": None,
                "priority": "review_external_research" if threat["kind"] == "research_update" else "review_external_rule",
                "components": {}, "uncertainties": ["A commit subject does not establish an active threat, rule behavior, or coverage in your SIEM."],
                "rule_advice": "Inspect the linked diff, original report, telemetry requirements and license; compare against deployed inventory before drafting."}
    if threat["kind"] == "leak_claim":
        return {"threat_id": ident, "environment": environment, "score": None,
                "priority": "verify_claim_and_entity", "components": {},
                "uncertainties": ["The post is a claim; the victim identity, intrusion, and method are unverified."],
                "rule_advice": "Confirm the named organization and independently source technical behavior before considering a detection."}
    if threat["kind"] == "ioc":
        seen = environment.get("seen_in_logs", "unknown")
        if seen not in (True, False, "unknown"):
            raise ValueError("seen_in_logs must be true, false, or unknown")
        expired = bool(threat["expires_at"] and threat["expires_at"] < now())
        components = {"feed_confidence": min(30, round((threat["confidence"] or 0) * .3)),
                      "observed_local_match": 35 if seen is True else 0,
                      "asset_criticality": 15 if environment.get("criticality") == "high" else 5 if environment.get("criticality", "medium") == "medium" else 0}
        score = sum(components.values())
        return {"threat_id": ident, "environment": environment, "score": score,
                "components": components,
                "priority": "stale_revalidate" if expired else "investigate_observed_connection" if seen is True else "verify_network_telemetry" if seen == "unknown" else "hunt_if_relevant",
                "uncertainties": ["No local network event was provided."] if seen == "unknown" else [],
                "rule_advice": "Use an expiring IOC hunt only when the feed item is recent and high confidence; review matching network events and asset context.",
                "expires_at": threat["expires_at"]}
    if threat["kind"] == "campaign":
        seen = environment.get("seen_in_logs", "unknown")
        if seen not in (True, False, "unknown"):
            raise ValueError("seen_in_logs must be true, false, or unknown")
        components = {"local_matching_behavior": 35 if seen is True else 0,
                      "relevant_exposed_asset": 25 if environment.get("internet_exposed") and environment.get("affected") is True else 0,
                      "asset_criticality": 15 if environment.get("criticality") == "high" else 5 if environment.get("criticality", "medium") == "medium" else 0}
        return {"threat_id": ident, "environment": environment, "score": sum(components.values()),
                "components": components,
                "priority": "investigate_matching_behavior" if seen is True else "verify_environment_relevance" if seen == "unknown" else "monitor",
                "uncertainties": ["Report relevance and behavior need confirmation in your logs."] if seen == "unknown" else [],
                "rule_advice": "Translate sourced behavior into a rule only after verifying the report and telemetry; do not treat the report title as a signature."}
    affected = environment.get("affected", "unknown")
    if affected not in (True, False, "unknown"):
        raise ValueError("affected must be true, false, or unknown")
    criticality = environment.get("criticality", "medium")
    if criticality not in ("low", "medium", "high"):
        raise ValueError("criticality must be low, medium, or high")
    asset_role = environment.get("asset_role", "general")
    if asset_role not in ("general", "model_serving", "mcp_server", "agent_runtime"):
        raise ValueError("asset_role must be general, model_serving, mcp_server, or agent_runtime")
    components = {
        "known_exploitation": 25 if threat["kev"] else 0,
        "epss": round(min(20, max(0, (threat["epss"] or 0) * 20))),
        "cvss": round(min(15, max(0, (threat["cvss"] or 0) * 1.5))),
        "affected_asset": 20 if affected is True else 0,
        "internet_exposed": 10 if environment.get("internet_exposed") is True else 0,
        "asset_criticality": {"low": 0, "medium": 5, "high": 10}[criticality],
    }
    score = sum(components.values())
    if affected is False:
        priority = "not_applicable_to_this_asset"
    elif affected == "unknown":
        priority = "verify_affected_version"
    else:
        priority = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {
        "threat_id": ident.upper(), "environment": environment, "score": score,
        "priority": priority, "components": components,
        "uncertainties": (["Affected version has not been confirmed."] if affected == "unknown" else [])
            + (["Missing EPSS; treated as unavailable, not zero likelihood."] if threat["epss"] is None else []),
        "rule_advice": "Hunt or draft only where a cited behavior and required telemetry exist; patching remains primary for applicable CVEs.",
        "ai_security_focus": {
            "general": "Confirm software exposure and affected versions.",
            "model_serving": "Check inference endpoint exposure, model artifact provenance, and request/access logs.",
            "mcp_server": "Check tool authorization decisions, execution outcome, principal and request binding in MCP audit logs.",
            "agent_runtime": "Check agent tool permissions, identity boundaries, and downstream execution telemetry.",
        }[asset_role],
    }


def compare_environments(ident, path: Path | None = None):
    """Illustrative profiles; the user's real assets must be assessed separately."""
    profiles = {
        "affected_internet_facing_critical": {"affected": True, "internet_exposed": True, "criticality": "high"},
        "affected_internal_low_criticality": {"affected": True, "internet_exposed": False, "criticality": "low"},
        "version_not_verified": {"affected": "unknown", "internet_exposed": True, "criticality": "high"},
        "product_not_present": {"affected": False, "internet_exposed": False, "criticality": "low"},
    }
    return {name: assess_risk(ident, environment, path) for name, environment in profiles.items()}


def research_view(ident, path: Path | None = None):
    threat = get_threat(ident, path)
    if threat is None:
        raise ValueError("unknown threat")
    behavior = [x for x in threat["evidence"] if x["kind"] == "analyst_observation"]
    advancements = {
        "web_server_shell": [
            "Inference: an attacker might use a different child interpreter or launch a helper binary instead of cmd.exe; compare with web-worker parent lineage before broadening this rule.",
            "Inference: an attacker might move from a web process to a service or scheduled task; hunt for that sequence only if telemetry and a source report support it.",
        ],
        "encoded_powershell": [
            "Inference: an attacker might use alternate PowerShell switches or another interpreter; inspect process command lines before expanding the match.",
            "Inference: an attacker might avoid command-line encoding entirely; consider script-block telemetry where collected, then test false positives.",
        ],
        "mcp_unauthorized_execution": [
            "Inference: an attacker might shift to a different tool or resource scope; compare principal, request, and binding identifiers before writing a correlation rule.",
            "Inference: an attacker might exploit stale authorization state; examine the decision timestamp and tool execution timestamp with a stable request ID.",
        ],
    }
    future = list(dict.fromkeys(item for e in behavior for item in advancements.get(e["behavior"], [])))
    if not future:
        future = (["Inference: C2 infrastructure may rotate; refresh the IOC and preserve DNS/proxy context before relying on a static IP hunt."]
                  if threat["kind"] == "ioc" else
                  ["Inference: a different literal or field may evade this analyst-provided pattern; inspect related events and benign baselines before widening it."]
                  if any(e["behavior"] == "custom" for e in behavior) else
                  ["Inference: the leak-site claim could be inaccurate or name-colliding; verify the organization before triage. No attack behavior is established."]
                  if threat["kind"] == "leak_claim" else
                  ["Inference: a repository update may reflect an emerging technique, routine maintenance, or a revision; inspect the diff and its cited report before forming a hunt hypothesis."]
                  if threat["kind"] in ("community_rule", "research_update") else
                  ["Inference: attacker adaptation is unknown until a behavior and current reporting are reviewed; no CVE-specific detection can be justified yet."])
    return {
        "observed": [{"claim": x["claim"], "source": x["source_url"], "behavior": x["behavior"]} for x in behavior],
        "source_facts": [{"claim": x["claim"], "source": x["source_url"]} for x in threat["evidence"] if x["kind"] == "source_fact"],
        "research_references": [x["source_url"] for x in threat["evidence"] if x["kind"] == "reference_pointer"],
        "why_hunt": ("A name match warrants entity verification; the claim alone does not justify a behavior hunt."
                     if threat["kind"] == "leak_claim" else
                     "A community update is a lead for source and coverage review, not proof that the threat is active or the rule is deployed."
                     if threat["kind"] in ("community_rule", "research_update") else
                     "Prioritize when the affected asset is present, exposed, and logged. Use the environment assessment for a score."),
        "possible_next_steps": future,
        "probability": "Not calibrated; no numeric probability is asserted. Use EPSS only for its defined CVE exploitation forecast, not a specific attacker behavior.",
        "detection_readiness": ("behavior_evidenced" if behavior else
                                "claim_only_no_behavior_rule" if threat["kind"] == "leak_claim" else
                                "external_update_needs_review" if threat["kind"] in ("community_rule", "research_update") else
                                "research_needed_no_behavior_rule"),
    }
