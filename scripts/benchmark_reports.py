#!/usr/bin/env python3
"""Evaluate manually annotated behaviors in complete fetched publisher HTML.

No production SIEM or SOC needed. Results are strictly about incomplete,
manually annotated behavior references, not precision or production accuracy.
URLs are checked against the existing research publisher allowlist. Publisher
pages are not stored or republished. HTTP fetches require explicit --live.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from threat_research import core, proposal_pass, report_inspection, research_pass, rule_repository, store

MANIFEST = Path(__file__).resolve().parent.parent / "benchmarks" / "full_reports_v1.json"
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,49}\Z")
MAX_CASES = 20
MIN_PARAGRAPHS = 4


def validate_manifest(raw):
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("expected benchmark schema_version=1")
    cases = raw.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("benchmark requires 1-20 reports")
    ids = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not SLUG.fullmatch(case["id"]):
            raise ValueError("invalid report ID (lowercase slug only)")
        if case["id"] in ids:
            raise ValueError("duplicate report ID")
        ids.add(case["id"])
        url = case.get("source_url")
        parts = urlsplit(url) if isinstance(url, str) else None
        if not parts or parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError("report must cite a credential-free HTTPS publisher URL")
        if not report_inspection.allowed_url(url):
            raise ValueError("report URL outside approved publisher allowlist")
        if not isinstance(case.get("title"), str) or not case["title"].strip():
            raise ValueError("missing report title")
        references = case.get("reference_behaviors")
        if not isinstance(references, list) or not references:
            raise ValueError("reference_behaviors must have at least one annotated behavior")
        for expected in references:
            if not isinstance(expected, dict) or not isinstance(expected.get("name"), str):
                raise ValueError("invalid annotated behavior name")
            if expected.get("event_family") not in ("process_creation", "network_connection", "image_load", "file_event"):
                raise ValueError("invalid event family")
            predicates = expected.get("required_predicates")
            if not isinstance(predicates, list) or not predicates:
                raise ValueError("invalid reference predicates")
            for predicate in predicates:
                if (not isinstance(predicate, dict) or set(predicate) != {"field", "value"}
                        or not all(isinstance(predicate[k], str) and predicate[k].strip() for k in ("field", "value"))):
                    raise ValueError("reference predicate must have field and value")
    return cases


def matches_reference(spec, reference):
    if spec.get("event_family") != reference["event_family"]:
        return False
    actual = {(p.get("field"), str(p.get("value", "")).casefold()) for p in spec.get("predicates", [])}
    required = {(p["field"], p["value"].casefold()) for p in reference["required_predicates"]}
    return required.issubset(actual)


def evaluate(manifest, output, fetch, origin="user_supplied_unverified_snapshot"):
    cases = validate_manifest(manifest)
    if not callable(fetch):
        raise ValueError("an explicit injected fetch function is required")
    output = Path(output).expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases:
        ident = "REPORT-BENCH-" + case["id"].upper()
        folder = output / case["id"]
        folder.mkdir()
        db = folder / "research.sqlite3"
        with rule_repository.isolated_repository(folder / "rules"):
            store.initialize(db)
            core.ingest([{"id": ident, "kind": "campaign", "title": case["title"],
                          "source": case["source_url"], "summary": "Unverified public research benchmark source",
                          "claim": "Publisher URL supplied by benchmark manifest; no local incident claimed."}], db)
            researched = research_pass.research_lead(ident, db, refresh=True, fetch=fetch,
                        max_pages=1, cache={}, budget={"remaining": 1, "fetched": 0})
            page = next((r for r in researched.get("pages", [])
                         if r["url"] == case["source_url"]), {})
            scored = (page.get("status") == "inspected"
                      and (page.get("paragraphs_scanned") or 0) >= MIN_PARAGRAPHS)
            drafts, gaps = [], []
            if scored:
                proposals = proposal_pass.propose_from_stored(ident, db)
                gaps = [g.get("reason", "")[:180] for g in proposals.get("gaps", [])][:25]
                for item in proposals["proposals"]:
                    spec = item.get("candidate_spec")
                    if isinstance(spec, dict):
                        drafts.append({"rule_id": item["rule_id"],
                                       "source_url": item.get("source_url"),
                                       "paragraph": item.get("paragraph"),
                                       "spec": spec, "status": item["status"],
                                       "required_telemetry": sorted({
                                           p["field"] for p in spec.get("predicates", [])})})
            reference_results = []
            for ref in case["reference_behaviors"]:
                matches = [d["rule_id"] for d in drafts if matches_reference(d["spec"], ref)] if scored else []
                reference_results.append({
                    "name": ref["name"], "event_family": ref["event_family"],
                    "required_predicates": ref["required_predicates"],
                    "extracted": bool(matches) if scored else None, "matching_rule_ids": matches})
            rows.append({
                "id": case["id"], "title": case["title"], "source_url": case["source_url"],
                "input_provenance": origin, "page_status": page.get("status", "not_fetched"),
                "page_detail": page.get("detail"), "page_sha256": page.get("sha256"),
                "paragraphs_scanned": page.get("paragraphs_scanned"), "scored": scored,
                "unscored_reason": None if scored else "unreadable_or_insufficient_paragraphs",
                "reference_behaviors": reference_results, "draft_count": len(drafts),
                "generated_drafts": drafts, "reported_gaps": gaps,
                "rules_approved": False, "native_siem_executed": False})
    selected = [r for r in rows if r["scored"]]
    total = sum(len(r["reference_behaviors"]) for r in selected)
    hits = sum(int(b["extracted"]) for r in selected for b in r["reference_behaviors"])
    report = {
        "benchmark_id": manifest.get("benchmark_id", "full-reports-v1"),
        "run_utc": datetime.now(timezone.utc).isoformat(), "origin": origin,
        "scope": "Full publisher HTML (or unverified snapshots), partially annotated behaviors; no production telemetry or native SIEM queries",
        "counts": {
            "reports_attempted": len(rows), "reports_scored": len(selected),
            "reports_unscored": len(rows) - len(selected),
            "annotated_behaviors_scored": total, "reference_behaviors_extracted": hits,
            "reference_behaviors_missed": total - hits,
            "drafts_on_scored_reports": sum(r["draft_count"] for r in selected)},
        "annotated_behavior_recall": round(hits / total, 3) if total else None,
        "warning": "Partial manually annotated reference only; not production accuracy, complete report recall, precision, or false-positive rate.",
        "native_siem_executed": False, "rules_approved": False, "cases": rows}
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "SUMMARY.md").write_text(markdown_summary(report), encoding="utf-8")
    return report


def markdown_summary(report):
    counts = report["counts"]
    lines = ["# Complete publisher-page behavior benchmark (no SIEM)", "",
             "Input origin: " + report["origin"],
             "A page hash records which bytes were parsed, but does not prove the reported behavior occurred in your environment.", "",
             f"- Reports attempted/scored/unscored: {counts['reports_attempted']}/{counts['reports_scored']}/{counts['reports_unscored']}",
             f"- Partially annotated behaviors found/missed: {counts['reference_behaviors_extracted']}/{counts['reference_behaviors_missed']}",
             f"- Unverified draft candidates: {counts['drafts_on_scored_reports']}",
             "", "| Source | Read status | Paragraphs | Drafts | Expected behaviors found |",
             "| --- | --- | ---: | ---: | --- |"]
    for r in report["cases"]:
        matched = ("unscored" if not r["scored"]
                   else str(sum(bool(x["extracted"]) for x in r["reference_behaviors"])) + "/" + str(len(r["reference_behaviors"])))
        lines.append(f"| [{r['id']}]({r['source_url']}) | {r['page_status']} | {r['paragraphs_scanned'] or 0} | {r['draft_count']} | {matched} |")
    return "\n".join(lines + ["", "**No precision or real-world accuracy is calculated.** Reference behaviors are partial. "
                "Other generated rules are not automatically false positives. No SIEM was queried, no rule was approved, and no detection was deployed.", ""])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded full-publication research benchmark; no SIEM required")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--output-directory", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Opt into direct reads of listed, allowlisted publisher URLs")
    mode.add_argument("--snapshots-dir", type=Path, help="Local HTML copies named by report ID; origins unverified")
    args = parser.parse_args(argv)
    payload = json.loads(args.manifest.read_text(encoding="utf-8"))
    cases = validate_manifest(payload)
    if args.live:
        fetch, origin = report_inspection.fetch_article, "live_allowlisted_publisher_https"
    else:
        root = args.snapshots_dir.expanduser().resolve()
        if not root.is_dir():
            parser.error("snapshot directory not found")
        for case in cases:
            if not (root / (case["id"] + ".html")).is_file():
                parser.error("missing snapshot: " + case["id"])

        def fetch(url):
            case = next(x for x in cases if x["source_url"] == url)
            data = (root / (case["id"] + ".html")).read_bytes()
            if len(data) > report_inspection.MAX_BYTES:
                raise ValueError("HTML snapshot exceeds maximum permitted size")
            return data
        origin = "user_supplied_html_unverified_source"
    report = evaluate(payload, args.output_directory, fetch, origin=origin)
    print(json.dumps(report["counts"], indent=2))
    print("Native SIEM: NOT RUN. All rules remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
