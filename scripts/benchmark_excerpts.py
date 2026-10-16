#!/usr/bin/env python3
"""Offline, source-attributed *excerpt* smoke benchmark for bounded drafting.

This is deliberately much narrower than accuracy against full real threat reports:
the user supplies short publisher excerpts with human-reviewed, bounded expected
predicates. This program does not fetch articles, invent ground truth, execute
KQL/SPL in a SIEM, or treat publisher claims as observed tenant activity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from threat_research import behavior_leads, proposal_pass

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "benchmarks" / "public_excerpts_v1.json"


def _check_manifest(payload: dict) -> list[dict]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("benchmark must be a versioned manifest (schema_version=1)")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark must contain at least one source-attributed case")
    ids = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("each case requires an id")
        if case["id"] in ids:
            raise ValueError(f"duplicate case id: {case['id']}")
        ids.add(case["id"])
        url = case.get("source_url", "")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f"{case['id']}: source_url must be a public HTTPS publisher URL")
        excerpt = case.get("excerpt", "")
        if not isinstance(excerpt, str) or not excerpt.strip():
            raise ValueError(f"{case['id']}: missing report excerpt")
        # A conservative editorial cap: don't redistribute substantial article excerpts.
        if len(excerpt.split()) > 25:
            raise ValueError(f"{case['id']}: excerpt exceeds 25 words; use a shorter attributed quote")
        if type(case.get("expected_draftable")) is not bool:
            raise ValueError(f"{case['id']}: expected_draftable must be a boolean")
        preds = case.get("required_predicates")
        if not isinstance(preds, list):
            raise ValueError(f"{case['id']}: missing expected predicate list")
        if case["expected_draftable"] != bool(preds):
            raise ValueError(f"{case['id']}: positive cases need predicates, negative cases need none")
        if case["expected_draftable"] and not case.get("expected_event_family"):
            raise ValueError(f"{case['id']}: missing expected event family")
        for pred in preds:
            if (not isinstance(pred, dict) or set(pred) != {"field", "value"}
                    or not all(isinstance(pred[k], str) and pred[k] for k in ("field", "value"))):
                raise ValueError(f"{case['id']}: malformed expected predicate")
    return cases


def _candidate_specs(excerpt: str) -> tuple[list[dict], str]:
    if behavior_leads.NEGATION.search(excerpt):
        return [], "negated excerpt: do not draft"
    if not behavior_leads.has_behavior_context(excerpt):
        return [], "insufficient malicious-action or execution-chain context"
    kinds = {p["behavior"] for p in behavior_leads.behavior_patterns([excerpt])}
    # This is the extractor's already-existing local behavior-spec interface,
    # not an invented LLM response or a hand-crafted detection for this case.
    pattern = {"quoted_paragraph": excerpt,
               "observable": {"lexical_behavior": "dll_sideloading" if "dll_sideloading" in kinds
                              else "encoded_powershell" if "encoded_powershell" in kinds else None}}
    return proposal_pass.behavior_specs(pattern), "review-only, bounded local behavior extraction"


def _matches_expected(spec: dict, case: dict) -> bool:
    if spec.get("event_family") != case.get("expected_event_family"):
        return False
    actual = {(p.get("field"), str(p.get("value", "")).casefold()) for p in spec.get("predicates", [])}
    expected = {(p["field"], p["value"].casefold()) for p in case["required_predicates"]}
    # Required predicates must co-occur in one proposal; separate weak rules
    # cannot be counted as complete extraction of a process relationship.
    return expected.issubset(actual)


def evaluate(payload: dict) -> dict:
    cases = _check_manifest(payload)
    scored = []
    supported, unsupported, hits, rejected = 0, 0, 0, 0
    for case in cases:
        specs, reason = _candidate_specs(case["excerpt"])
        required_match = any(_matches_expected(spec, case) for spec in specs)
        if case["expected_draftable"]:
            supported += 1
            hits += int(required_match)
            outcome = "expected_behavior_extracted" if required_match else "missed_expected_predicates"
        else:
            unsupported += 1
            rejected += int(not specs)
            outcome = "correctly_withheld" if not specs else "unexpected_draft_candidate"
        scored.append({
            "id": case["id"], "source_url": case["source_url"], "excerpt_sha256": hashlib.sha256(
                case["excerpt"].encode("utf-8")).hexdigest(),
            "expected_draftable": case["expected_draftable"],
            "candidate_count": len(specs), "candidate_specs": specs,
            "outcome": outcome, "reason": reason,
            "expected_event_family": case.get("expected_event_family"),
            "expected_predicates": case["required_predicates"],
            "review_note": case.get("review_note", "")
        })
    return {
        "benchmark_id": payload.get("benchmark_id", "unnamed"),
        "scope": "Source-attributed, manually curated excerpts only; NOT full reports, actual malicious events, or native SIEM tests.",
        "counts": {"cases": len(cases), "expected_supported": supported, "expected_unsupported": unsupported,
                   "supported_with_all_expected_predicates": hits, "unsupported_correctly_withheld": rejected,
                   "missed_expected": supported - hits, "unexpected_candidates": unsupported - rejected},
        "positive_extraction_fraction": (round(hits / supported, 3) if supported else None),
        "negative_withholding_fraction": (round(rejected / unsupported, 3) if unsupported else None),
        "source_verification": "URLs/quotes manually curated; this offline program does NOT verify article content or date.",
        "native_siem_executed": False,
        "rules_approved": False,
        "case_results": scored,
    }


def markdown_summary(report: dict) -> str:
    c = report["counts"]
    rows = [
        "# Public research excerpt benchmark (offline)",
        "", "**Scope:** Curated excerpts from publisher research; NOT full reports, real telemetry, native SIEM execution, or production detection accuracy.",
        "", f"- Cases: {c['cases']} ({c['expected_supported']} annotated extractable, {c['expected_unsupported']} annotated not bounded)",
        f"- Extracted all annotated predicates: {c['supported_with_all_expected_predicates']} of {c['expected_supported']}",
        f"- Correctly withheld candidates: {c['unsupported_correctly_withheld']} of {c['expected_unsupported']}",
        f"- Misses: {c['missed_expected']} | Unexpected draft candidates: {c['unexpected_candidates']}",
        "", "| Case | Outcome | Candidates | Source |", "| --- | --- | ---: | --- |"
    ]
    for case in report["case_results"]:
        rows.append(f"| {case['id']} | {case['outcome']} | {case['candidate_count']} | [Publisher]({case['source_url']}) |")
    rows.extend(["", "These are **excerpt-level extractor checks**. No source was fetched or verified at runtime, no analyst-approved rules were created, and synthetic event precision/recall must be reported separately.",
                 "For each missed case, inspect the input quote, explicit behavior semantics, necessary telemetry and any over-specific matching before changing extraction logic.", ""])
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate bounded rule extraction on short, attributed public research excerpts.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-directory", type=Path, help="New/empty directory for JSON and Markdown reports")
    args = parser.parse_args(argv)
    payload = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = evaluate(payload)
    if args.output_directory is not None:
        output = args.output_directory.expanduser().resolve()
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            parser.error("output directory must be new or empty; existing results will not be overwritten")
        output.mkdir(parents=True, exist_ok=True)
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "SUMMARY.md").write_text(markdown_summary(report), encoding="utf-8")
        print(f"Wrote benchmark summary to {output / 'SUMMARY.md'}")
    print(json.dumps(report["counts"], indent=2))
    print("NOTE: publisher excerpts, no full-report evaluation or native SIEM executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
