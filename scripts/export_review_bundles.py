#!/usr/bin/env python3
"""Export review-only Sigma/KQL/SPL draft packs from source-linked research.

Requires no enterprise SOC, SIEM or API access; takes already evaluated
research databases and optional synthetic challenge JSON. NEVER approves,
publishes, or deploys any rule. Uses the stored rule text, not a reconstructed
or newly invented detection. Browser source content is not republished.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from threat_research import custom_rules, drafting, rules, soc_replay

UUIDISH = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")


def _dir_not_nested(source, out):
    source, out = source.resolve(), out.resolve()
    if source == out or source in out.parents or out in source.parents:
        raise ValueError("output must be separate from its source data")


def load_challenges(path):
    if path is None:
        return {}
    data = json.loads((Path(path) / "results.json").read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or
            data.get("provenance") != "analyst_authored_synthetic_scenarios_not_real_incident_logs"):
        raise ValueError("test results must be explicitly fictional challenge replay output")
    pairs = {}
    for case in data.get("cases", []):
        if not isinstance(case, dict) or case.get("status") not in ("scored_fictional_events", "unscored"):
            raise ValueError("unexpected challenge result type")
        key = (case.get("report_id"), case.get("reference_name"))
        if key in pairs:
            raise ValueError("duplicate synthetic challenge result")
        pairs[key] = case
    return pairs


def export(source_directory, output_directory, challenge_directory=None):
    source = Path(source_directory).expanduser().resolve()
    out = Path(output_directory).expanduser().resolve()
    _dir_not_nested(source, out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("export destination must be a new or empty directory")
    research = json.loads((source / "results.json").read_text(encoding="utf-8"))
    if not isinstance(research, dict) or not isinstance(research.get("cases"), list):
        raise ValueError("source results are not a full report benchmark")
    linked = load_challenges(challenge_directory)
    # Resolve all dangerous paths, identifiers and DB preconditions BEFORE
    # creating an output tree, so malicious metadata cannot become filenames.
    exportable = []
    seen = set()
    for report in research["cases"]:
        name = report.get("id")
        if not isinstance(name, str) or not SLUG.fullmatch(name):
            raise ValueError("unsafe report ID")
        if not report.get("scored"):
            continue
        db = source / name / "research.sqlite3"
        if not db.is_file():
            raise ValueError(f"no local research SQLite for {name}")
        for candidate in report.get("generated_drafts", []):
            identifier = candidate.get("rule_id")
            if not isinstance(identifier, str) or not UUIDISH.fullmatch(identifier):
                raise ValueError("unsafe or invalid rule UUID")
            if (name, identifier) in seen:
                raise ValueError("repeated rule in source benchmark")
            seen.add((name, identifier))
            if candidate.get("status") != "draft_unverified":
                raise ValueError("only explicitly unverified drafts may be bundled")
            # Verify current content and linked source; do not trust an
            # external JSON report as authority for the actual detection text.
            rule = rules.get_rule(identifier, db)
            if rule is None or rule["status"] != "draft":
                raise ValueError(f"missing review-only draft {identifier}")
            if candidate.get("spec") != rule.get("custom_spec"):
                raise ValueError("source result spec differs from the stored rule version")
            link = drafting.source_link(identifier, db)
            if link is None or link.get("status") != "unverified":
                raise ValueError("expected an unverified source-linked draft")
            if (link.get("source_url") != candidate.get("source_url")
                    or link.get("paragraph") != candidate.get("paragraph")):
                raise ValueError("stored source link differs from benchmark evidence")
            exportable.append((report, candidate, rule, link))
    out.mkdir(parents=True, exist_ok=True)
    summary = []
    for report, candidate, rule, link in exportable:
        name, identifier = report["id"], rule["id"]
        folder = out / name / identifier
        folder.mkdir(parents=True)
        for ext, column in (("yml", "sigma"), ("kql", "kql"), ("spl", "spl")):
            text = rule.get(column)
            if isinstance(text, str) and text.strip():
                (folder / ("detection." + ext)).write_text(text.rstrip() + "\n", encoding="utf-8")
        tests = []
        for reference in report.get("reference_behaviors", []):
            result = linked.get((name, reference.get("name")))
            if result and result.get("status") == "scored_fictional_events" and identifier in result.get("rule_ids", []):
                tests.append({"reference_name": reference["name"], "counts": result.get("counts"),
                              "sample_size": result.get("sample_count"), "provenance": "fictional_only",
                              "rule_hash_from_replay": result.get("rule_content_hashes", {}).get(identifier)})
        spec = rule["custom_spec"]
        hash_now = soc_replay.rule_content_hash(rule)
        for result in tests:
            if result["rule_hash_from_replay"] != hash_now:
                raise ValueError("synthetic replay tested an obsolete rule version")
        metadata = {
            "rule_id": identifier, "title": rule["title"], "status": "draft_unverified",
            "report_id": name, "publisher_source_url": candidate["source_url"],
            "source_paragraph": candidate["paragraph"],
            "publisher_page_sha256": report.get("page_sha256"),
            "input_provenance": report.get("input_provenance"),
            "source_link_status": "unverified",
            "required_canonical_fields": custom_rules.required_fields(spec),
            "structured_selector": spec,
            "rationale": rule["rationale"], "telemetry_notes": rule["telemetry"],
            "rule_content_hash": hash_now,
            "synthetic_tests": tests,
            "native_siem_executed": False,
            "customer_telemetry_observed": False, "verified_assets": False,
            "inventory_coverage": "unknown_unless_complete_inventory_supplied",
            "automatic_approval": False, "deployed": False,
            "readiness": "EXPERIMENTAL: analyst source review, independent event tests and target-SIEM validation required"
        }
        (folder / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        false_positive_note = "Potential legitimate software administration, installation and DLL loading; environment-specific false positives have NOT been measured."
        counts = tests[0]["counts"] if tests else None
        example = (f"Synthetic local fixture results: TP={counts['tp']}, FP={counts['fp']}, FN={counts['fn']}, TN={counts['tn']}."
                   if counts else "No per-rule synthetic event replay is attached. This is not a validation result.")
        readme = [
            "# " + rule["title"], "",
            "**Review-only detection draft. No rule approval or SIEM deployment occurred.**",
            "", "## Source provenance", "",
            "- Source URL: " + candidate["source_url"],
            "- Cited paragraph number: " + str(candidate["paragraph"]),
            "- Publisher page SHA-256 (retrieved bytes): " + str(report.get("page_sha256") or "unknown"),
            "- Source link status: UNVERIFIED. The publisher assertion has NOT been corroborated as activity in your environment.",
            "", "## Detection requirements", "",
            "- Event family: " + spec["event_family"],
            "- Required canonical fields: " + ", ".join(custom_rules.required_fields(spec)),
            "- Telemetry: " + rule["telemetry"],
            "- Context: " + rule["rationale"],
            "- False positive considerations: " + false_positive_note,
            "", "## Reproducibility and testing", "",
            "- Exact exported rule hash: " + hash_now,
            "- " + example,
            "- Local Python reference matching is **not** native Sigma, KQL or SPL execution.",
            "- No complete existing rule inventory, production telemetry mapping, native query result or actual incident labels were available.",
            "", "## Files", "",
            "- detection.yml — Sigma",
            "- detection.kql — KQL (verify table and field mappings)",
            "- detection.spl — Splunk SPL (verify index and sourcetype)",
            "- metadata.json — structured provenance, field and validation status.",
            "", "Next steps: check source and benign context, import your environment's existing rules, map real event fields, test both attack and benign samples, and only then consider human-approved deployment.",
            ""
        ]
        (folder / "REVIEW.md").write_text("\n".join(readme), encoding="utf-8")
        summary.append({"report_id": name, "rule_id": identifier,
                        "review": str((Path(name) / identifier / "REVIEW.md")),
                        "synthetic_replay_attached": bool(tests)})
    result = {"source_benchmark_id": research.get("benchmark_id"), "rules_exported": len(summary),
              "review_only": True, "native_siem_executed": False,
              "production_validated": False, "packaged": summary}
    (out / "INDEX.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (out / "README.md").write_text(
        "# Detection review bundles — no SIEM required\n\n"
        "These are source-linked **unverified** drafts, not approved alerts or deployable production rules. "
        "Each per-rule folder contains the generated Sigma/KQL/SPL text and human review checklist. "
        "Any attached TP/FP/FN/TN counts are from deliberately fictional challenge events, "
        "not measured SOC precision or false-positive rates. Query execution and telemetry "
        "mapping in actual SIEMs remain untested.\n\n" +
        "\n".join("- [" + p["report_id"] + " / " + p["rule_id"] + "](" + p["review"].replace("\\", "/") + ")"
                  for p in summary) + "\n", encoding="utf-8")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export unverified draft detection packages for human review")
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--challenge-directory", type=Path)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    result = export(args.source_directory, args.output_directory, args.challenge_directory)
    print(json.dumps({k: result[k] for k in ("rules_exported", "review_only", "native_siem_executed")}, indent=2))
    print("All rules remain unverified, unapproved and undeployed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
