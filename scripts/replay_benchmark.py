#!/usr/bin/env python3
"""Challenge source-linked unverified rules using clearly fictional event scenarios.

This checks local reference-matcher semantics, not the native Sigma/KQL/SPL
queries. Event labels are analyst-authored assumptions on fabricated event
examples; they are NOT independently measured SOC ground truth. A report whose
expected rule was missed/unreadable is UNSCORED, not automatically a true negative.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from threat_research import soc_replay

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "benchmarks" / "synthetic_challenges_v1.json"
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")
ALLOWED_EVENT_TYPES = {"process_creation", "image_load", "network_connection", "file_event"}


def validate_challenges(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("challenge schema_version=1 required")
    if data.get("provenance") != "analyst_authored_synthetic_scenarios_not_real_incident_logs":
        raise ValueError("challenge cases must explicitly identify fictional provenance")
    cases = data.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 20:
        raise ValueError("challenge manifest requires 1-20 report references")
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("report_id"), str) or not SLUG.fullmatch(case["report_id"]):
            raise ValueError("invalid report ID")
        key = (case["report_id"], case.get("reference_name"))
        if key in seen or not isinstance(key[1], str) or not key[1]:
            raise ValueError("duplicate or missing reference in challenge manifest")
        seen.add(key)
        events = case.get("scenarios")
        if not isinstance(events, list) or not 2 <= len(events) <= 40:
            raise ValueError("each reference requires 2-40 fictional event scenarios")
        ids = set()
        labels = set()
        for sample in events:
            if not isinstance(sample, dict) or set(sample) != {"id", "scenario", "expected_malicious", "event"}:
                raise ValueError("event sample must include id, scenario, expected_malicious and event only")
            ident = sample["id"]
            if not isinstance(ident, str) or not SLUG.fullmatch(ident) or ident in ids:
                raise ValueError("invalid or repeated scenario ID")
            ids.add(ident)
            if not isinstance(sample["scenario"], str) or not sample["scenario"].strip():
                raise ValueError("scenario name is required")
            if type(sample["expected_malicious"]) is not bool:
                raise ValueError("synthetic scenario labels must be boolean")
            labels.add(sample["expected_malicious"])
            event = sample["event"]
            if not isinstance(event, dict) or event.get("event_type") not in ALLOWED_EVENT_TYPES:
                raise ValueError("unsupported fictional event family")
            if set(event) & {"event_id", "scenario", "expected_malicious", "timestamp"}:
                raise ValueError("event identity, truth label and timestamp are supplied only by benchmark")
            if len(event) > 12 or any(
                not isinstance(k, str) or not isinstance(v, str) or len(v) > 512
                for k, v in event.items()
            ):
                raise ValueError("event fields require short string telemetry values")
        if labels != {True, False}:
            raise ValueError("each reference must include both benign and malicious fictional labels")
    return cases


def _safe_results(report, manifest):
    if not isinstance(report, dict) or not isinstance(report.get("cases"), list):
        raise ValueError("full-report benchmark results missing cases")
    by_id = {x["id"]: x for x in report["cases"]}
    if len(by_id) != len(report["cases"]):
        raise ValueError("duplicate report result identifiers")
    seen = set()
    for case in manifest["cases"]:
        report_id, name = case["report_id"], case["reference_name"]
        row = by_id.get(report_id)
        if not row:
            raise ValueError(f"no full-report result for challenge {report_id}")
        if not SLUG.fullmatch(report_id):
            raise ValueError("invalid result report ID")
        matches = [b for b in row.get("reference_behaviors", []) if b.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"missing or duplicate annotated reference {name} in {report_id}")
        seen.add((report_id, name))
    return by_id


def evaluate(source_directory, challenge_manifest, output_directory):
    challenges = validate_challenges(challenge_manifest)
    source = Path(source_directory).expanduser().resolve()
    report = json.loads((source / "results.json").read_text(encoding="utf-8"))
    by_id = _safe_results(report, challenge_manifest)
    output = Path(output_directory).expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("challenge output must be a new or empty directory")
    # Never overwrite the full-report source benchmark.
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("challenge output must be separate from full-report source")
    output.mkdir(parents=True, exist_ok=True)
    scored = []
    for item in challenges:
        report_id = item["report_id"]
        result = by_id[report_id]
        reference = next(r for r in result["reference_behaviors"] if r["name"] == item["reference_name"])
        ids = reference.get("matching_rule_ids", [])
        allowed = {d["rule_id"] for d in result.get("generated_drafts", [])
                   if d.get("status") == "draft_unverified"}
        if not isinstance(ids, list) or any(not isinstance(x, str) or x not in allowed for x in ids):
            raise ValueError(f"{report_id}: matching rules must be authored drafts in full-report results")
        reason = None
        if not result.get("scored"):
            reason = "source_report_not_readable"
        elif reference.get("extracted") is not True or not ids:
            reason = "no_rule_with_complete_reference_behavior"
        if reason is not None:
            scored.append({
                "report_id": report_id, "reference_name": item["reference_name"],
                "status": "unscored", "reason": reason, "sample_count": len(item["scenarios"]),
                "counts": None, "cases": [], "rule_ids": []
            })
            continue
        db = source / report_id / "research.sqlite3"
        if not db.is_file():
            raise ValueError(f"{report_id}: source-linked rule database is missing")
        generated_rules = {r["id"]: r for r in soc_replay.local_rules(db, include_drafts=True)}
        rules = []
        for rule_id in ids:
            if rule_id not in generated_rules or generated_rules[rule_id]["status"] != "draft":
                raise ValueError(f"{report_id}: missing source-linked unverified draft {rule_id}")
            rules.append(generated_rules[rule_id])
        events = [{
            "event_id": report_id + "-" + scenario["id"],
            "scenario": scenario["scenario"],
            "expected_malicious": scenario["expected_malicious"],
            "timestamp": "2099-01-01T00:00:00Z",
            **scenario["event"],
        } for scenario in item["scenarios"]]
        replay = soc_replay.replay(events, rules)
        scored.append({
            "report_id": report_id, "reference_name": item["reference_name"],
            "status": "scored_fictional_events", "reason": None,
            "sample_count": replay["sample_size"], "counts": replay["counts"],
            "cases": replay["cases"], "rule_ids": ids,
            "rule_content_hashes": {r["id"]: soc_replay.rule_content_hash(r) for r in rules}
        })
    selected = [r for r in scored if r["status"] == "scored_fictional_events"]
    totals = {k: sum(r["counts"][k] for r in selected) for k in ("tp", "fp", "fn", "tn")}
    payload = {
        "provenance": "analyst_authored_synthetic_scenarios_not_real_incident_logs",
        "scope": "Locally replayed reference matcher against fictional labeled event assumptions; no native query execution or measured enterprise false-positive rate.",
        "full_report_benchmark_id": report.get("benchmark_id"),
        "counts": {"references_scored": len(selected),
                   "references_unscored": len(scored) - len(selected),
                   "fictional_events_scored": sum(r["sample_count"] for r in selected),
                   "fictional_events_unscored": sum(r["sample_count"] for r in scored if r["status"] != "scored_fictional_events"),
                   **totals},
        "native_siem_executed": False, "production_accuracy_inferred": False, "cases": scored
    }
    (output / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (output / "SUMMARY.md").write_text(summary(payload), encoding="utf-8")
    return payload


def summary(report):
    c = report["counts"]
    rows = [
        "# Source-linked detection draft — fictional event challenges",
        "", "**NOT a real SOC evaluation.** Every event is fabricated and the malicious/benign label is a scenario assumption. The same draft is tested against expected positives, intentional benign collisions, attacker variations and missing fields.",
        "",
        f"- References evaluated: {c['references_scored']}; unscored: {c['references_unscored']}.",
        f"- Synthetic events evaluated: {c['fictional_events_scored']}; unscored: {c['fictional_events_unscored']}.",
        f"- Synthetic TP={c['tp']}, FP={c['fp']}, FN={c['fn']}, TN={c['tn']}.",
        "", "| Source and behavior | Status | TP | FP | FN | TN |",
        "| --- | --- | ---: | ---: | ---: | ---: |"]
    for case in report["cases"]:
        counts = case["counts"]
        nums = (" | ".join(str(counts[k]) for k in ("tp", "fp", "fn", "tn")) if counts else "— | — | — | —")
        rows.append(f"| {case['report_id']} / {case['reference_name']} | {case['status']} | {nums} |")
    rows.extend([
        "", "## Interpretation",
        "", "- A benign software installation can match a real attacker technique. A draft alert is not proof of compromise.",
        "- Renamed modules, alternative commands, missing fields and vendor-specific schema differences may cause misses.",
        "- Only exact matched source-linked drafts are tested; a report with no qualifying rule is UNSCORED, not credited with true negatives.",
        "- Tested local Python reference predicates are not the same as native KQL/SPL/Sigma execution; time-window constraints may not be evaluated.",
        "- These TP/FP/FN/TN counts are **not representative production precision, recall or false-positive rates**.",
        "- Nothing was approved or deployed.",
        ""
    ])
    return "\n".join(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay explicit fictional malicious/benign challenges against source-linked draft rules")
    parser.add_argument("--source-directory", type=Path, required=True,
                        help="Output directory produced by scripts/benchmark_reports.py")
    parser.add_argument("--challenge-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = json.loads(args.challenge_manifest.read_text(encoding="utf-8"))
    result = evaluate(args.source_directory, manifest, args.output_directory)
    print(json.dumps(result["counts"], indent=2))
    print("Fictional event labels only. Native SIEM tests: NONE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
