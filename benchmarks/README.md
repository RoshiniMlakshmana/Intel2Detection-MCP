# Intel2Detection-MCP benchmark protocol (October 16, 2026)

## Distinguish research extraction from detection effectiveness

1. **Source access/readability:** Were entire publisher HTML pages fetched? If no, mark **unscored**, never a missed or successful detection. Preserve fetched page SHA-256 and paragraph count, but a hash proves the processed bytes, not authenticity of every assertion.
2. **Behavior extraction:** For each manually nominated reference, did one automatic draft contain all annotated predicates in the same candidate? The reference set is **partial**, not exhaustive. Missing extraction is visible, but unrelated drafts are **not** automatically false positives.
3. **Simulated rule event matching:** Locally replay explicitly **fabricated malicious and benign** events against only source-linked drafts; record TP/FP/FN/TN as synthetic illustration. Do not call this production precision, recall, or operational false-positive rate.
4. **Query language validation:** Generated Sigma/KQL/SPL drafts have **not** been executed in the target query engines (and generic field names need mapping). Never equate Python reference matching with SIEM query tests.
5. **Production relevance and approval:** Environment assets, telemetry presence and the complete inventory are **unknown** unless explicitly supplied. Drafts are unverified, unapproved and undeployed.

## Two source partitions

| Partition | Manifest | Reports | Intended use |
| --- | --- | ---: | --- |
| Development / bug-analysis | [full_reports_v1.json](full_reports_v1.json) | 3 | Inspect extraction failures, repair rules, test synthetic regression fixtures. Do **not** call it held-out. |
| Locked held-out / preselected | [full_reports_holdout_v1.json](full_reports_holdout_v1.json) | 7 | Same-code, first-pass test of seven distinct previously unmeasured public publisher reports. **Do not change extraction code in response to this sample and continue calling it held-out.** |

The sample is not randomized; all 7 held-out reports currently come from Microsoft's security research blog. One nominated candidate behavior per report was manually selected from cited technical descriptions or publisher hunt guidance. **These were not second-reviewed**, some nominated behaviors may be too loosely worded to generate a bounded event selector, and the presence of a published *hunt suggestion* does not imply an observed customer incident. Each label may be correct as a behavior description while the detector properly withholds a rule due to missing telemetry or specificity. Treat results as an initial *audit*, not a performance estimate.

The first three known reports previously exposed a concrete passive DLL-load parsing failure, repaired and retested as described in [RESULTS_OCT16.md](RESULTS_OCT16.md). That iterative set is explicitly excluded from hold-out statistics.

## Reproduce separately

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe scripts/benchmark_reports.py --manifest benchmarks/full_reports_v1.json --live --output-directory known-development-results
& .\.venv\Scripts\python.exe scripts/benchmark_reports.py --manifest benchmarks/full_reports_holdout_v1.json --live --output-directory heldout-results
```

Both commands access only explicitly listed, allowlisted HTTPS publishers, with no production SOC connection. Live pages may change or block automated fetching. Review the generated `SUMMARY.md` and `results.json` files for **attempted/scored/unscored**, source-hash and per-behavior found/missed information. Do not count blocked pages as misses. Source HTML snapshots can be supplied with `--snapshots-dir` and are marked origin-unverified.

Use `scripts/replay_benchmark.py` only with its **matching development-corpus event challenge manifest**; it is not an honest held-out event benchmark if its examples were authored knowing the rules. The current 17 synthetic fixture outcomes are intentionally adversarial illustrative tests, not measured tenant signals.

## Roadmap toward 20 reports

Grow the next **independent** frozen corpus with 10 additional diverse publisher articles from more vendors and both Windows and Linux families; nominate and review behaviors *before* scoring. Keep the seven-report frozen manifest immutable, and version the new cases rather than updating labels based on scores. Report publisher-blocked or unsupported research explicitly, then seek a second analyst to review the expected predicates. Favor independent public benign/event data and native local test engines in a later phase.

**An objective success criterion is transparent evidence of successes, failures and limitations, not maximizing a headline score.**
