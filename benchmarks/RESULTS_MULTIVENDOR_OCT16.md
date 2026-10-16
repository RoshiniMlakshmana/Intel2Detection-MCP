# Multi-vendor technical research audit — first pass (October 16, 2026)

**This is an actual measured extractor evaluation on 10 public HTML reports, not a measured SOC detection accuracy claim.**

The candidate branch `feat/bounded-command-patterns` ran the preselected corpus `multivendor_holdout_v1.json` for the first time in [successful GitHub Actions run #38957335204](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38957335204) at SHA `ac71b6792ec3f8cc133137cfeaffd5e824b3e9c7`. The Actions artifact `multi-vendor-ten-report-first-pass` contains the exact machine-readable `results.json`, source page SHA-256s, retrieved page statuses, and `SUMMARY.md`. Reports were fetched only from explicitly allowlisted publisher HTTPS URLs; there was no customer SOC, enterprise SIEM, alert deployment or native query execution.

## First-pass outcomes (no retuning)

- **10 / 10** publisher HTML pages were read and scored.
- **1,098** HTML text blocks were parsed across those reports.
- **12** source-linked *unverified* draft candidates of any type were generated (mostly file-hash and other process hypotheses).
- **0 / 10** preselected *partial* manual behavior-reference predicates were completely matched by a single proposed candidate.
- **No** precision, operational recall, or genuine false-positive-rate inference is justified. No second annotator has verified this small, nonrandom, manually selected reference set.

| New source | Parsed HTML blocks | Other unverified drafts | Initial target behavior match |
| --- | ---: | ---: | --- |
| Google Mandiant — CORNFLAKE.V3 | 120 | 4 | 0/1 |
| Google Mandiant — UNC4990 USB malware | 194 | 4 | 0/1 |
| Google Mandiant — UNC2165 / AV exclusion | 85 | 0 | 0/1 |
| Google Mandiant — NETWIRE | 61 | 0 | 0/1 |
| Palo Alto Unit 42 — Ivanti | 84 | 0 | 0/1 |
| Palo Alto Unit 42 — Blinder Tunnel | 209 | 0 | 0/1 |
| Palo Alto Unit 42 — Emissary Panda | 130 | 2 | 0/1 |
| Palo Alto Unit 42 — Stately Taurus | 51 | 0 | 0/1 |
| Cisco Talos — ClearFake | 99 | 2 | 0/1 |
| Cisco Talos — UAT-9244 | 65 | 0 | 0/1 |
| **Totals** | **1,098** | **12** | **0/10** |

## Interpreting the misses

- **What is proven:** The bounded extractor generated some unverified draft ideas but did **not** faithfully recreate any of these ten preselected, manually annotated relationships under the current exact normalized predicate matching rules.
- **What is NOT proven:** 0% actual SOC detection accuracy. The reference set is partial, nonrandom and not independently adjudicated. Some expected process names are not expressed as exact `.exe` path fields in the source; other patterns appear in publisher hunt guidance rather than confirmed attack events. A mismatch may represent a conservatively withheld unsupported inference rather than a coding bug.
- **Concrete risk:** In the CORNFLAKE report, an unverified candidate `ParentImage=PowerShell` and `Image=node.exe` was generated, but that does not equal a source-proven `ParentImage=powershell.exe` match and should not be scored as an exact reference hit. Some reports also produced file hash drafts but not the named behavioral correlation. No validity checks against actual benign event frequency were performed.
- **Why this matters:** The earlier 3 known development cases were tuned after a specific failure and cannot be presented as representative. The first unseen Microsoft-only sample found **0/7** exact expected behavior matches. This second 10-source, 3-publisher sample found **0/10**. Neither is a production recall estimate.
- **New command-pattern implementation:** This first-pass run includes narrowly bounded fictional-devel-inspired PowerShell AV-exclusion and complete HTTPS HTA command patterns, but the collector still did not satisfy the pinned published behavior labels in this diverse report sample. It would be misleading to claim otherwise.
- **Do not overfit:** These 10 results are now seen. Future tuning may use their problems as development examples but not represent repeated improvements on these same 10 as fresh out-of-sample wins.

## Next validation requirements

1. **Source-to-label adjudication:** A second analyst should verify each selected behavior is explicitly asserted (not merely proposed as a hunt) and that required predicates belong to the *same telemetry event*. Classify label as supported, incomplete, or unsupported.
2. **Field and text normalization:** Check quoted/dotted filenames, DEFANGED tokens (`[.]`), path/filename matching, passive parent-child wording and nonliteral publisher query semantics. Never silently add source-absent values to a draft rule.
3. **Decouple measurements:** Report source readability, reference extraction, rule syntax, native engine testing and runtime behavior separately; the 12 extra draft candidates are not validated detections.
4. **Use new independently selected technical reports** from distinct publishers for future first-pass evaluation, after changes are frozen. Keep original raw artifacts and metrics.
5. Keep all rules in `draft_unverified` with explicit telemetry, precision and deployment limitations.

With the previously evaluated 3 development + 7 Microsoft + these **10 multi-vendor** reports, the project has now run evaluations on **20 distinct public research reports**. The outcome is a **critical evidence-backed gap in behavior extraction**, not a success claim about generated rules.
