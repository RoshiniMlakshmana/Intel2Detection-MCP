# Intel2Detection-MCP — v0.12.3 public release candidate

**Status:** Source code integrated into `main`; no production SOC/SIEM validation. The source package version is `0.12.3`. This document is release documentation, **not** a GitHub Releases publication or proof of production readiness.

## What is included

- Evidence-gated public threat-intelligence research and source-linked Sigma, KQL, and SPL **drafts**.
- MCP server, CLI, optional local dashboard, collector health and resilient source ingestion.
- Offline `scripts/offline_demo.py` synthetic SOC demonstration, with intentionally fictional event data and known limitations.
- Four public-source evaluation workflows: short excerpt audit, development-corpus full-HTML reports, frozen first-pass Microsoft reports, and first-pass Google/Mandiant, Palo Alto Unit 42, and Cisco Talos reports.
- `scripts/replay_benchmark.py`: synthetic malicious/benign reference matcher with explicit false positives and misses (not native SIEM execution).
- `scripts/export_review_bundles.py`: human-review detection packages with provenance, required fields, Sigma/KQL/SPL drafts, rule content hashes and any applicable synthetic tests.
- `scripts/adjudicate_research.py`: unreviewed second-analyst worksheet preserving original frozen behavior hypotheses.
- Conservative additional Windows executable process relationships, passive DLL loaded-by descriptions, and explicitly bounded command patterns.
- Offline tests on Ubuntu and Windows, Python 3.11 and 3.12.
- Apache License 2.0, with SPDX project metadata.

## Actual research evaluation and gaps

Twenty distinct public publisher articles were evaluated in separate batches: **3 previously tuned development reports** (3 nominated relationships extracted after correction), **7 first-pass Microsoft reports** (0/7 nominated exact relationships extracted), and **10 first-pass multi-vendor reports** (0/10 nominated exact relationships extracted). All source pages were readable on those particular runs. The nominated references are partial, hand-annotated and not independently second-reviewed. These figures cannot be combined into an accuracy metric. Some other unverified drafts were created but have not been confirmed as true detections. Details: `benchmarks/RESULTS_OCT16.md`, `benchmarks/RESULTS_HOLDOUT_OCT16.md`, `benchmarks/RESULTS_MULTIVENDOR_OCT16.md`.

Synthetic challenge replay of 17 **fabricated, pre-labeled** events recorded TP=3, FP=3, FN=6, TN=5 for the three nominated draft rules. These demonstrate exact-selector brittleness and potential benign overlaps, *not* a production false-positive rate, native KQL/SPL/Sigma testing, or measured SOC detection accuracy.

**Safety and scope:** No enterprise infrastructure, tenant assets, customer telemetry, complete existing rule inventory, native SIEM execution, or actual deployed detections were examined. Unverified detection drafts are NOT approvals, alerts or evidence of compromise. Every implementation needs analyst review, telemetry/field mapping, native query validation and benign/attack tests before considering deployment.

## Quick start

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe scripts/offline_demo.py
```

For Mac/Linux use `python3` and `./.venv/bin/python`. See `README.md` and `QUICKSTART.md` for additional workflows.

## Future validation (not release blockers for a research tool)

- Independent analyst review of the 17 first-pass reference hypotheses.
- Representative event-level data from permitted labs, including meaningful negative samples.
- Native rule syntax and execution in a local or customer-provided SIEM/test engine.
- Complete inventory/asset telemetry coverage checks and multi-engine query translation.
- Usability feedback from 1–3 outside detection engineers.

The release is a **research/developer preview**, not a production-ready SOC detection service.
