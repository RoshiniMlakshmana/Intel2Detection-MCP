"""Repeatable offline source-to-draft-to-SOC-replay demonstration."""

import json
import shutil
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from . import automatic_lab, core, environment, report_inspection, research_feeds, rule_repository, rules, soc_replay, store

FIXTURES = Path(__file__).resolve().parent / "lab_fixtures"


def _feed(entries, published):
    root = ET.Element("rss")
    channel = ET.SubElement(root, "channel")
    for article in entries:
        item = ET.SubElement(channel, "item")
        for tag, value in (("title", article["title"]), ("link", article["source"]),
                           ("description", article["summary"]), ("pubDate", format_datetime(published))):
            ET.SubElement(item, tag).text = value
    return ET.tostring(root, encoding="utf-8")


def run(output_directory, fixtures=FIXTURES):
    with rule_repository.isolated_repository(Path(output_directory) / "rule-repository"):
        return _run(output_directory, fixtures)


def _run(output_directory, fixtures):
    """Use a new isolated lab database and explicit fixture analyst annotations."""
    directory = Path(output_directory).expanduser().resolve()
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("demo output directory must be new or empty; existing files will not be overwritten")
    directory.mkdir(parents=True, exist_ok=True)
    db = directory / "lab.sqlite3"
    store.initialize(db)
    sources = json.loads((fixtures / "sources.json").read_text(encoding="utf-8"))
    if sources.get("synthetic") is not True or not all(a["source"].startswith("https://example.test/") for a in sources["articles"]):
        raise ValueError("lab source manifest must be explicitly synthetic")
    cve = sources["cve"]
    core.ingest([cve], db)
    clock = datetime.now(timezone.utc)
    articles = sources["articles"]
    feed_records = research_feeds.parse_feed(_feed(articles, clock), "Synthetic SOC lab feed",
                                             "research", clock - timedelta(days=1), clock + timedelta(minutes=1))
    if len(feed_records) != len(articles):
        raise ValueError("synthetic feed entries were rejected")
    core.ingest(feed_records, db)
    assets = environment.parse_assets((fixtures / "assets.csv").read_text(encoding="utf-8"))
    profile = json.loads((fixtures / "profile.json").read_text(encoding="utf-8"))
    environment.onboard(profile, assets, db)
    evidence_path = []
    for article, feed_record in zip(articles, feed_records):
        target = article.get("draft_under", feed_record["id"])
        html = (fixtures / article["html"]).read_bytes()
        inspected = report_inspection.extract_report_html(target, article["source"], html)
        lead = next((x for x in inspected["behavior_leads"] if x["behavior"] == article["reviewed_behavior"]), None)
        if not lead:
            raise ValueError(f"fixture reviewed behavior absent from {article['html']}")
        source_fact = next(e for e in core.get_threat(feed_record["id"], db)["evidence"] if e["kind"] == "source_fact")
        try:
            rules.propose_rule(feed_record["id"], source_fact["id"], db)
        except ValueError as exc:
            blocked = str(exc)
        else:
            raise AssertionError("feed metadata unexpectedly drafted a detection")
        claim = f"Synthetic lab analyst annotation: {lead['excerpt']}"
        evidence_id = core.add_behavior_evidence(target, article["source"], claim,
                                                 article["reviewed_behavior"], db)
        proposal = rules.propose_rule(target, evidence_id, db)
        if proposal["status"] != "draft":
            raise ValueError("lab expected an independent new draft")
        rule = rules.get_rule(proposal["rule_id"], db)
        evidence_path.append({"feed_report_id": feed_record["id"], "linked_cve": feed_record["mentioned_cves"],
                              "draft_under": target, "source": article["source"],
                              "article_sha256": inspected["sha256"], "leads": inspected["behavior_leads"],
                              "fixture_analyst_annotation": article["reviewed_behavior"],
                              "metadata_draft_blocked": blocked, "draft_rule_id": rule["id"]})
        rules_dir = directory / "draft_rules"
        rules_dir.mkdir(exist_ok=True)
        for ext in ("sigma", "kql", "spl"):
            (rules_dir / f"{rule['behavior']}.{ext}").write_text(rule[ext], encoding="utf-8")
    duplicate = rules.propose_rule(cve["id"],
                                  next(e["id"] for e in core.get_threat(cve["id"], db)["evidence"]
                                       if e["kind"] == "analyst_observation"), db)
    active = soc_replay.local_rules(db, include_drafts=True)
    events = list(soc_replay.read_jsonl(fixtures / "events.jsonl"))
    measurement = soc_replay.replay(events, active)
    adaptations = {
        "web_server_shell": "The attacker could start a different child such as rundll32.exe; separately assess web-worker lineage and DLL loads before widening the rule.",
        "encoded_powershell": "The attacker could change the argument syntax or use another script host; validate observed command-line variants and decoded content before expanding detection.",
        "mcp_unauthorized_execution": "An attacker could evade a single audit source or race authorization state; correlate the enforcement decision and execution receipt using the same request ID.",
    }
    rule_reviews = []
    for row in active:
        rule = rules.get_rule(row["id"], db)
        rule_reviews.append({"rule_id": row["id"], "behavior": row["behavior"],
                             "why_use": rule["rationale"], "telemetry_needed": rule["telemetry"],
                             "declared_telemetry_fit": environment.check_rule_fit(row["id"], db),
                             "source_evidence": rule["supporting_evidence"],
                             "further_attacker_adaptation_hypothesis": adaptations[row["behavior"]],
                             "adaptation_probability": "not calibrated; investigate, do not present an invented number"})
    shutil.copyfile(fixtures / "events.jsonl", directory / "events.jsonl")
    (directory / "live_events.jsonl").touch()
    report = {"lab_notice": "Entire source set, CVE, analyst annotations, inventory, and events are synthetic. No real publisher, live SIEM, or production tenant was contacted.",
              "source_records": 1 + len(feed_records), "source_paths": evidence_path,
              "cve_asset_risk": environment.risk_from_assets(cve["id"], db),
              "illustrative_environment_comparison": core.compare_environments(cve["id"], db),
              "inventory_duplicate_check": duplicate, "drafts_tested": len(active),
              "rule_reviews": rule_reviews,
              "approval": "drafts remain unapproved in the isolated lab inventory",
              "measurement": measurement,
              "automatic_drafting": automatic_lab.run(directory / "automatic", fixtures),
              "tuning_notes": [
                  "E02 and E04 need change-window, signer, ancestry, and decoded-command review; suppressing all such traffic could conceal malicious use.",
                  "E08 and E09 are deliberate misses. Investigate these telemetry variants as separately evidenced hypotheses; do not infer coverage from a title or one lab sample.",
                  "MCP E05 is a policy mismatch; verify request binding and independent enforcement records before calling it an intrusion."
              ],
              "watch_command": f"python -m threat_research.cli watch-events --database {db} --file {directory / 'live_events.jsonl'} --include-drafts"}
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {"output": str(directory), "report": str(directory / "report.json"),
            "drafts": len(active), "sample_size": measurement["sample_size"],
            "counts": measurement["counts"], "precision": measurement["precision"],
            "recall": measurement["recall"], "false_positive_rate": measurement["false_positive_rate"],
            "scope": measurement["scope"],
            "automatic_drafting": {k: v for k, v in report["automatic_drafting"].items() if k != "checks"}}
