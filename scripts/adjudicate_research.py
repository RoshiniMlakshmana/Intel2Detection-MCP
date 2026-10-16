#!/usr/bin/env python3
"""Create an UNREVIEWED human annotation worksheet from existing benchmark data.

This command does not re-run any live publisher report, change fixed labels,
fetch articles, or assert that any reference is correct. Overlap is purely
literal, not semantic equivalence or a detection effectiveness measurement.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from scripts import benchmark_reports

HUMAN_FIELDS = ("independent_reviewer", "supporting_publisher_paragraph",
                "publisher_quote_location", "observed_event_or_hunt",
                "source_supports_label", "telemetry_feasible",
                "analyst_notes", "manual_review_status")
COLUMNS = ("report_id", "source_url", "reference_name", "source_status",
           "source_sha256", "expected_event_family", "expected_predicates_json",
           "exact_machine_match", "draft_count", "same_family_drafts",
           "best_literal_overlap", "structural_gap") + HUMAN_FIELDS


def _predicates(items):
    return {(p.get("field"), str(p.get("value", "")).casefold())
            for p in items if isinstance(p, dict)}


def prepare(manifest, results):
    original = benchmark_reports.validate_manifest(manifest)
    cases = results.get("cases", [])
    if not isinstance(cases, list) or len(cases) != len(original):
        raise ValueError("benchmark result count differs from frozen manifest")
    by_id = {r["id"]: r for r in cases}
    if len(by_id) != len(original):
        raise ValueError("duplicate or missing result IDs")
    rows = []
    for entry in original:
        measured = by_id.get(entry["id"])
        if not measured or measured.get("source_url") != entry["source_url"]:
            raise ValueError("source URL or ID differs from original manifest")
        references = measured.get("reference_behaviors", [])
        if [r.get("name") for r in references] != [r["name"] for r in entry["reference_behaviors"]]:
            raise ValueError("benchmark reference order or name differs from frozen manifest")
        for expected, observed in zip(entry["reference_behaviors"], references):
            if (observed.get("event_family") != expected["event_family"] or
                    observed.get("required_predicates") != expected["required_predicates"]):
                raise ValueError("reference predicates were changed since original scoring")
            drafts = measured.get("generated_drafts", [])
            same = [d for d in drafts if isinstance(d.get("spec"), dict)
                    and d["spec"].get("event_family") == expected["event_family"]]
            req = _predicates(expected["required_predicates"])
            overlap = max((len(req & _predicates(d["spec"].get("predicates", [])))
                           for d in same), default=0)
            if not measured.get("scored"):
                gap = "UNSCORABLE_SOURCE"
            elif observed.get("extracted") is True:
                gap = "MATCHED_PRESELECTED_REFERENCE"
            elif not drafts:
                gap = "NO_DRAFTS"
            elif not same:
                gap = "NO_CANDIDATE_IN_EXPECTED_EVENT_FAMILY"
            else:
                gap = "OTHER_OR_PARTIAL_PREDICATES"
            row = {
                "report_id": entry["id"],
                "source_url": entry["source_url"],
                "reference_name": expected["name"],
                "source_status": measured.get("page_status", "unknown"),
                "source_sha256": measured.get("page_sha256") or "",
                "expected_event_family": expected["event_family"],
                "expected_predicates_json": json.dumps(expected["required_predicates"]),
                "exact_machine_match": observed.get("extracted"),
                "draft_count": len(drafts),
                "same_family_drafts": len(same),
                "best_literal_overlap": f"{overlap}/{len(req)}",
                "structural_gap": gap,
                **{field: "" for field in HUMAN_FIELDS[:-1]},
                "manual_review_status": "PENDING_INDEPENDENT_REVIEW",
            }
            rows.append(row)
    return {"source_benchmark_id": results.get("benchmark_id"),
            "reference_count": len(rows), "human_review_complete": False,
            "source_refetched": False, "native_siem_tested": False,
            "rows": rows}


def export(manifest_path, source_dir, output_dir):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    source = Path(source_dir).expanduser().resolve()
    measured = json.loads((source / "results.json").read_text(encoding="utf-8"))
    output = Path(output_dir).expanduser().resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("output must be outside source benchmark data")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be new or empty")
    output_data = prepare(manifest, measured)
    output.mkdir(parents=True, exist_ok=True)
    (output / "audit_metadata.json").write_text(
        json.dumps(output_data, indent=2) + "\n", encoding="utf-8")
    with (output / "INDEPENDENT_REVIEW.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(output_data["rows"])
    (output / "README.md").write_text(
        "# Independent annotation review — NOT YET COMPLETED\n\n"
        "The CSV is a blank reviewer worksheet generated from EXISTING benchmark output. "
        "It does not assert label correctness and does not fetch or evaluate any new report.\n\n"
        "A second analyst must open each source URL and verify the exact paragraph, "
        "whether the claimed activity was observed or merely a publisher hunt, "
        "whether all required predicates occur in the same event, and benign context. "
        "The analyst can reject initial labels. Do not rewrite the previously frozen "
        "references or describe retrospective changes as improved unseen performance.\n\n"
        "Literal overlap is only a diagnostic clue. These drafts remain unverified; "
        "native SIEM validity, asset coverage and production false-positive rates are unknown.\n",
        encoding="utf-8")
    return output_data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate an unreviewed annotation worksheet with no live access")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    result = export(args.manifest, args.source_directory, args.output_directory)
    print(f"Prepared {result['reference_count']} references for independent analyst review.")
    print("Review status: PENDING, not adjudicated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
