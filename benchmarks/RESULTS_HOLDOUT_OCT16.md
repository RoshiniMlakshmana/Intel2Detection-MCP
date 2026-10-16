# First-pass, seven-report locked holdout: results (October 16, 2026)

> **Initial benchmark outcome, recorded without tuning or editing the frozen holdout labels:** all seven publisher HTML pages readable; **0 of 7 preselected, manually annotated behavior hypotheses extracted completely**; **three other unverified drafts**. This is **not** a claim of 0% detection accuracy or of zero useful behavior extraction; it is an intentionally narrow predicate-match audit with incomplete reference labeling. No second-analyst validation or production SOC data was used.

**Immutable evidence:** [GitHub Actions — first successful heldout run #38955359035](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38955359035), at repository commit `ae0050f049a0cc13535004193d6813d3289aa054`. Download the `seven-heldout-public-report-results` artifact for `results.json`, `SUMMARY.md`, per-page SHA hashes and all generated candidate specifications. Workflow successfully executed without any real SOC, SIEM account or production telemetry.

| Previously unseen technical report | HTML paragraphs read | Unverified candidate drafts (of any type) | Pre-annotated target fully extracted |
| --- | ---: | ---: | --- |
| Photo ZIP campaign / compiler stage | 225 | 1 (file hash + name, **not** expected process chain) | ❌ csc.exe → cvtres.exe |
| Counterfeit installers | 127 | 0 | ❌ msiexec.exe with -Embedding |
| Helpdesk impersonation / malicious DLL | 139 | 0 | ❌ rundll32.exe invoking DLL export |
| Search poisoning / cryptojacking | 152 | 1 (SimpleRunPE → PowerShell, **not** expected AV-exclusion command) | ❌ PowerShell Add-MpPreference -ExclusionPath |
| Workplace app impersonation / ScreenConnect | 83 | 0 | ❌ msiexec.exe installing ScreenConnect |
| ACR Stealer / ClickFix | 99 | 1 (PowerShell → Rundll32.exe, **not** MSHTA web command) | ❌ mshta.exe remote web execution |
| AutoJack / AI agent RCE research | 114 | 0 | ❌ published AutoGen Studio parent/child hunt |
| **Total** | **939** | **3** | **0 of 7** |

The initial locked holdout intentionally includes **different behaviors and statement forms** from the three previously tuned development reports. These misses are credible research findings, not a reason to rewrite this manifest or cherry-pick more forgiving labels. Some reference hypotheses may be too specific, may require a complex publisher query, may describe a suggested hunt rather than a measured attacker event, or may not satisfy the current source-inspection evidence gates. Each case needs review by another analyst before it can be treated as reliable ground truth.

## Engineering triage for a separate development dataset

- **Missing process relationships / new command patterns:** csc.exe → cvtres.exe, msiexec.exe -Embedding, and script-host/network command patterns not covered by the small bounded extractors.
- **Overly narrow command parsing:** the Add-MpPreference/-ExclusionPath combination and the rundll32 export-argument behavior were reported but not assembled into the targeted predicate sets.
- **Publisher query semantics:** AutoGen Studio hunting query requires multi-field conditions and regex; the current extractor properly may withhold lossy query translations rather than silently drop constraints.
- **Potential platform inference defect** worth synthetic regression testing: a produced candidate for the ACR Stealer report was `ParentImage=PowerShell` and `Image=Rundll32.exe` but had `platform=linux`, despite an explicit Windows executable child. This is **not** the desired target and must not be counted as successful extraction.
- **No opinion about detection quality of unmatched drafts:** three generated candidates were not manually evaluated as true/false rules in this benchmark. Each remains review-only.

**Methodological commitment:** The old three-report development scores (3/3 after a wording fix) are **not independent** and must not be combined with these 0/7 counts to claim 30% production recall. These seven results have now been observed. Any repairs informed by them are **development**, not an improvement on a still-unseen holdout. Preserve this result, use synthetic development regressions for repairs, and pre-register a **new** independently reviewed holdout from other vendors before claiming out-of-sample progress.

## Next experiments

1. Independently re-check that each nominated predicate set is supported by its source and by feasible event telemetry, tagging publisher hunt suggestions separately from recorded incident observations.
2. Address platform typing and supported bounded behaviors in a *separate development branch* with fictional regression inputs; reject assertions unsupported by specific source text.
3. Collect 10 additional reports from other public publishers to reach 20 distinct report evaluations; **freeze labels before scoring**, avoid training on these seven observed results, and report all unreadable sources.
4. Replay only source-linked rules against properly provenance-labeled benign/malicious event sets and later native local query engines. Simulated matching never equals native Sigma/KQL/SPL execution.
