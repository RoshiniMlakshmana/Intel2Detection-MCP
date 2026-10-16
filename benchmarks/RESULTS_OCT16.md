# Public publisher-page benchmark — October 16, 2026

This is an **observed execution result**, not an accuracy claim about a SOC.

## Configuration

- Branch: `feat/no-siem-demo-sprint`; source snapshot: `41d9844c6cd51d695afa12dc79b86d8672e1ed0c`.
- Command: `python scripts/benchmark_reports.py --live --output-directory public-report-results`, run on GitHub-hosted Ubuntu/Python 3.12.
- Source set: [`full_reports_v1.json`](full_reports_v1.json) — three independent public vendor research articles with **one manually annotated behavior reference per report**.
- The existing research pipeline read the publisher HTML on each report's allowed hostname; each case used an isolated local SQLite database and detection repository.
- No enterprise SOC/Defender/Sentinel/Splunk credentials, native query execution, live customer telemetry, or publishing of detections.
- Primary evidence: [GitHub Actions public report evaluation run #38952812384](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38952812384), with uploaded `public-report-evaluation` JSON + Markdown artifact and event logs.

## Verified output

| Source | HTML text blocks scanned | Unverified drafts | Partial human-annotated behavior found |
| --- | ---: | ---: | --- |
| [Microsoft Security — MSP360 RMM abuse](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/) | 111 | 4 | RMM.Agent.exe → PowerShell → Invoke-WebRequest ✅ |
| [Cisco Talos — Antino DLL sideloading](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/) | 288 | 1 | GatherOsState.exe loads slc.dll ✅ |
| [Cisco Talos — Gamaredon / Remcos](https://blog.talosintelligence.com/gamaredon-campaign-distribute-remcos/) | 63 | 1 | TiVoDiag.exe loads mindclient.dll ✅ |
| **Totals** | **462** | **6** | **3 of 3 nominated behaviors** |

All three public publisher pages were readable in that specific test execution. Every generated rule remained **draft_unverified**. Extra Microsoft drafts included process chains, a publisher-derived hash hunt, and a bounded publisher-derived process query. Their quality and false positives are **not** independently assessed by this benchmark.

## Failure observed and repaired

The initial live test [run #38952468153](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38952468153) extracted 2 of 3 annotated behaviors and produced five drafts. It **missed the Gamaredon DLL-load relationship** because the publisher described a malicious DLL being *loaded by* a clean executable, without the word "sideloaded" in the same relevant sentence, and the detector expected executable-first wording.

The extractor now detects a **same-clause, explicitly malicious DLL loaded by named EXE** phrasing, including quotation marks. It does not create a complete incident chain or infer a malicious local event. Negations, unrelated sentences, and benign DLL descriptions are covered by regression tests. The follow-up run obtained the sixth draft and recognized the nominated Talos behavior.

## Interpretation and limitations

**3/3 means only that all three preselected, manually annotated relationships were recovered by this code version.** It does *not* mean 100% real-world behavior extraction recall, precision, detection accuracy, or deployment readiness. The reference set is **partial**; reports contain additional behaviors that were not labeled or evaluated. A source page hash and repeatable retrieval establish exactly what text was processed, not the truth of every statement. Native Sigma/KQL/SPL execution, realistic telemetry availability, and false-positive rates are still untested.

These results justify expanding to a held-out report sample, independent annotation, and benign/attack event replay, not claiming production performance.
