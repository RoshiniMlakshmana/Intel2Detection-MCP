#!/usr/bin/env python3
"""A one-command, offline-only introduction to Intel2Detection-MCP.

Uses the existing deterministic, fictional SOC lab. No threat feeds, customer
systems, SIEM APIs, production credentials, or paid model APIs are contacted.
This is a reference-selector exercise, NOT native KQL/SPL/Sigma execution.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _run_lab(output: Path) -> None:
    from threat_research import soc_lab
    soc_lab.run(output)


def validate_report(report: dict) -> None:
    """Fail rather than accidentally present incomplete data as a success."""
    if not isinstance(report, dict) or "synthetic" not in str(report.get("lab_notice", "")).lower():
        raise ValueError("Offline demo report is missing its synthetic-data disclosure")
    if report.get("drafts_tested", 0) < 1:
        raise ValueError("Offline demo did not produce any analyst-annotated lab drafts")
    result = report.get("measurement")
    if not isinstance(result, dict):
        raise ValueError("Offline demo has no event-level measurement")
    counts = result.get("counts", {})
    names = ("tp", "fp", "fn", "tn")
    if any(type(counts.get(name)) is not int or counts[name] < 0 for name in names):
        raise ValueError("Offline demo counts are missing or invalid")
    if result.get("sample_size", 0) < 1 or sum(counts[name] for name in names) != result["sample_size"]:
        raise ValueError("Offline demo counts do not match the number of events")
    automatic = report.get("automatic_drafting")
    if not isinstance(automatic, dict) or automatic.get("status") != "passed":
        raise ValueError("Offline automatic drafting checks did not pass")
    if automatic.get("automatic_drafts", 0) < 1:
        raise ValueError("Offline automatic lab produced no new draft rules")


def summary_markdown(report: dict) -> str:
    validate_report(report)
    measurement = report["measurement"]
    counts = measurement["counts"]
    generated = report["automatic_drafting"]

    def fmt(number):
        return "not defined" if number is None else f"{number:.3f}"

    return "\n".join([
        "# Intel2Detection-MCP: Offline Demonstration",
        "",
        "> **Scope:** All sources, analyst annotations, assets and events in this demonstration are fictional. No real SOC, SIEM, production tenant or external threat feed was queried.",
        "",
        "## What ran",
        "",
        "1. Fictional intelligence, source excerpts and explicit lab analyst annotations were ingested.",
        "2. Three template-based review drafts were produced; source metadata alone was not enough to draft.",
        "3. Independently, a bounded research pass created draft detections from fictional technical reports.",
        "4. Local reference matching evaluated synthetic malicious and benign events (not native SIEM queries).",
        "",
        "## Results (synthetic fixtures only)",
        "",
        f"- Template/annotated lab drafts: {report['drafts_tested']}",
        f"- Automatically generated draft rules: {generated['automatic_drafts']}",
        f"- Fictional technical reports processed by automatic lab: {generated.get('reports_tested', 'unknown')}",
        f"- Automatic lab predicate checks: {generated.get('checks_passed', 'unknown')}",
        f"- Labeled event count: {measurement['sample_size']}",
        f"- True positives: {counts['tp']}; false positives: {counts['fp']}; false negatives: {counts['fn']}; true negatives: {counts['tn']}",
        f"- Fixture precision: {fmt(measurement.get('precision'))}; fixture recall: {fmt(measurement.get('recall'))}; fixture false-positive rate: {fmt(measurement.get('false_positive_rate'))}",
        "",
        "**These fixture rates are not estimates of real-world or production detection accuracy.**",
        "",
        "## Reviewable artifacts",
        "",
        "- [Detailed lab report](report.json) — source evidence, explicit annotation boundaries, rule reviews and event-level outcomes.",
        "- [Synthetic labeled event samples](events.jsonl) — the exact local replay input.",
        "- [Template/annotated Sigma, KQL and SPL drafts](draft_rules/) — examples to review, not deployed detections.",
        "- [Automatically generated draft files and test summary](automatic/) — includes the automatic lab report.",
        "",
        "## What remains unproven",
        "",
        "- Actual native Sigma, KQL and SPL execution, and telemetry field mapping in a target SIEM.",
        "- Real-world alert accuracy, benign event prevalence, or false-positive rates.",
        "- Coverage of a live organization, asset relevance and completeness of its existing detection inventory.",
        "- Analyst approval or successful deployment: all produced rules remain unverified lab drafts.",
        "",
        "Next: evaluate independently retrieved *real* research reports against a versioned behavior reference set and separately identified labeled test events.",
        "",
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate an offline, fictional SOC demo and readable evidence summary.")
    parser.add_argument("--output-directory", type=Path,
                        help="A new or empty output folder. Defaults to a uniquely named local folder.")
    args = parser.parse_args(argv)
    output = args.output_directory or Path("offline-demo-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output = output.expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error("output folder exists and is not an empty directory; no files were overwritten")

    _run_lab(output)
    report_file = output / "report.json"
    report = json.loads(report_file.read_text(encoding="utf-8"))
    summary = summary_markdown(report)
    summary_file = output / "DEMO_SUMMARY.md"
    summary_file.write_text(summary, encoding="utf-8")
    print("Offline demo completed: fictional evidence and synthetic event replay only.")
    print(f"Readable summary: {summary_file}")
    print(f"Full source-to-rule report: {report_file}")
    print("Native SIEM tested: NO | Rule deployment: NO | Real-world accuracy measured: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
