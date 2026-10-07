"""Fictional report text -> automatic drafts -> predicate regression checks.

No client-supplied predicates or analyst behavior annotations are used. This
checks reference semantics, not execution of Sigma, KQL or SPL in a SIEM.
"""
import html
import json
from pathlib import Path

import yaml

from . import core, drafting, proposal_pass, research_pass, rule_repository, rules, soc_replay, store


def _require(condition, message):
    if not condition:
        raise ValueError("Automatic drafting lab failed: " + message)


def run(directory, fixtures):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((fixtures / "automatic_reports.json").read_text(encoding="utf-8"))
    _require(manifest.get("synthetic") is True, "fixtures must declare synthetic provenance")
    db = directory / "lab.sqlite3"
    store.initialize(db)
    pages, ids = {}, []
    for report in manifest["reports"]:
        ident = "REPORT-SYNTHETIC-" + report["name"].upper()
        # Fictional paths on an allowlisted host; fetch is strictly local below.
        url = "https://www.microsoft.com/en-us/security/blog/2099/01/01/synthetic-" + report["name"]
        pages[url] = ("<html><article>" + "".join(
            "<" + section["tag"] + ">" + html.escape(section["text"]) + "</" + section["tag"] + ">"
            for section in report["sections"]) + "</article></html>").encode()
        core.ingest([{"id": ident, "kind": "campaign", "title": "Synthetic automatic drafting " + report["name"],
                      "source": url, "summary": "Fictional offline regression report, not a publisher claim.",
                      "claim": "Synthetic report fixture."}], db)
        ids.append(ident)
    with rule_repository.isolated_repository(directory / "rule-repository"):
        outcome = research_pass.run_pass(db, threat_ids=ids, fetch=lambda url: pages[url], max_fetches=20)
    checked, sigma_ids, all_rule_ids, query_count = [], [], [], 0
    replay_rules = {r['id']: r for r in soc_replay.local_rules(db, include_drafts=True)}
    for fixture, result in zip(manifest["reports"], outcome["results"]):
        proposed = result.get("rule_proposals", {}).get("proposals", [])
        _require(len(proposed) == fixture["expected_drafts"], f"{fixture['name']} draft count: {result}")
        candidates = [rules.get_rule(p["rule_id"], db) for p in proposed]
        for candidate in candidates:
            link = drafting.source_link(candidate["id"], db)
            _require(candidate["status"] == "draft" and link["status"] == "unverified", "unexpected approval")
            _require(link["proposed_by"].startswith("bounded_research_pass"), "client-authored proposal")
            _require(link["cited_values_still_present"], "missing source predicate")
            docs = list(yaml.safe_load_all(candidate["sigma"]))
            sigma_ids.extend(d["id"] for d in docs)
            all_rule_ids.append(candidate["id"])
            for ext in ("sigma", "kql", "spl"):
                (directory / (candidate["id"] + "." + ext)).write_text(candidate[ext], encoding="utf-8")
        for check in fixture["checks"]:
            # A query's unique literal selects its own draft, never another rule.
            selected = [r for r in candidates if not check.get("query_literal") or
                        check["query_literal"] in drafting.source_link(r["id"], db)["quoted_text"]]
            _require(len(selected) == 1, "ambiguous check target: " + check["name"])
            matched = bool(soc_replay.detect({"event_id": check["name"], "timestamp": "2099-01-01T00:00:00Z",
                                             **check["event"]}, [replay_rules[selected[0]["id"]]]))
            _require(matched == check["expected_match"], check["name"])
            checked.append({"name": check["name"], "rule_id": selected[0]["id"],
                            "expected_match": check["expected_match"], "actual_match": matched})
        query_count += sum(s["tag"] == "pre" and "summarize" not in s["text"] for s in fixture["sections"])
        with rule_repository.isolated_repository(directory / "rule-repository"):
            repeated = proposal_pass.propose_from_stored(result["threat_id"], db)
        _require(all(p["status"] == "existing_draft" for p in repeated["proposals"]), "duplicate pass created drafts")
        if fixture.get("unsupported_query"):
            _require(any("unsupported expression" in g["reason"] for g in repeated["gaps"]), "complex query silently widened")
        if fixture["name"] == "sideload":
            _require("and not 1 of filter_*" in candidates[0]["sigma"], "Sigma exclusion is only a note")
            _require("NOT" in candidates[0]["spl"].upper() and "not(" in candidates[0]["kql"].lower().replace(" ", ""), "query exclusion missing")
    _require(len(checked) == manifest["expected_checks"], "missing reports or event checks")
    _require(len(all_rule_ids) == len(set(all_rule_ids)) == manifest["expected_drafts"], "rule ID collision")
    _require(len(sigma_ids) == len(set(sigma_ids)), "Sigma ID collision")
    with store.connection(db) as connection:
        _require(connection.execute("SELECT count(*) FROM rules WHERE status!='draft'").fetchone()[0] == 0, "approved rules")
    summary = {"status": "passed", "scope": "Synthetic report extraction and local reference matching; native SIEM not run.",
               "reports_tested": len(ids), "automatic_drafts": len(all_rule_ids),
               "publisher_queries_translated": query_count, "checks_passed": len(checked),
               "sigma_ids_unique": True, "dedup_passed": True, "checks": checked}
    (directory / "report.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
