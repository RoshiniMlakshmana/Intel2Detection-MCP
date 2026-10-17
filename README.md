# Intel2Detection-MCP

**Collect threat intelligence → research behaviors → create Sigma, KQL and SPL drafts.**

- **Version:** 0.12.3.
- **Use through:** Claude MCP, Python CLI or the local dashboard.
- **SIEM optional:** research and local testing work without one.
- **Current status:** supported patterns work; broad real-world accuracy is still unproven.

## Independently labeled event validation (strict, no invented results)

The optional `scripts/evaluate_external_labels.py` scores **existing source-linked local draft rules** only when an external event file and a separate independently evidenced label manifest are supplied. It rejects missing labels, mismatched source hashes, duplicates, and self-asserted synthetic provenance. If no stored rules are available, it returns **UNSCORED**, not a fabricated true negative.

```powershell
& .\.venv\Scripts\python.exe scripts/evaluate_external_labels.py --events external-events.jsonl --labels independent-labels.json --rule-database path-to-research.sqlite3 --output external-evaluation.json
```

The labels JSON must contain `schema_version: 1`, `provenance: "externally_verified_event_labels"`, `external_dataset_url`, `independent_label_evidence_url`, `events_sha256` and an entry for **each** event with `event_id`, `expected_malicious` (boolean) and `evidence` (individual label explanation). Event records must already have `event_id`, `timestamp` and `event_type`, and must not embed assumed attack/benign labels. No synthetic examples are silently used as external ground truth.

External resources such as [Splunk Attack Data](https://github.com/splunk/attack_data) offer documented attack-exercise collections, but a *dataset or folder classified as attack* is **not enough to label every record malicious**: realistic traces contain normal process events too. This project **does not currently ship an independently labeled attack-and-benign event-level benchmark or a scored rule-performance figure**. The new strict evaluator is ready for one, but its results cannot be invented. It runs the Python reference matcher, not native Splunk SPL, KQL, or Sigma execution. Organization-specific human signoff and deployment validation remain the installing organization's responsibility.

## External telemetry smoke check (third-party Sysmon sample)

For a small **independently authored event sample** separate from our own synthetic tests, run:

```powershell
& .\.venv\Scripts\python.exe scripts/check_external_sysmon.py --output external-sysmon-check.json
```

The archived sample originates from [Neo23x0/evt2sigma](https://github.com/Neo23x0/evt2sigma/blob/master/tests/sysmon-event.xml), not from our detector or a fabricated project fixture. The runner records the source, original XML hash, normalized Sysmon Event 1 fields and event values. Without `--rule-database PATH_TO_EXISTING_SQLITE_DB`, it performs **parser/field inspection only** and loads no detection rules. With that option, it performs *local reference-matcher* checks against stored rules only; it does **not** run native KQL/SPL/Sigma or supply missing attack/benign labels.

**This single event is NOT labeled attack or benign. Zero matches do not imply a correct true negative.** Treat this as a first independent-telemetry compatibility check only. For actual detection performance, users must supply trustworthy attack/benign labeled datasets, native query engines, and environment-specific analyst approval. The built-in research benchmark labels are still unadjudicated. Human verification remains the responsibility of an adopting analyst/organization; do not automatically approve draft rules.

## Try it without a SIEM (offline demo)

Requires Python 3.11+; **no SOC, paid API, cloud account or production telemetry needed**. After cloning the repository, install and run:

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe scripts/offline_demo.py
```

On macOS/Linux, replace the first command with `python3 -m venv .venv` and the Python executable with `./.venv/bin/python`. The command creates an isolated `offline-demo-<timestamp>/` directory and prints the path to its **DEMO_SUMMARY.md**. That summary links to the synthetic event samples, detailed report, generated draft rules and automatic lab output. Each run uses a fresh folder and will not overwrite existing output.

This is an intentionally **fictional, reproducible lab**, not an assertion of production accuracy or native SIEM query execution. Its expected outcomes include false positives and missed malicious events. Rules are neither approved nor deployed. For advanced use and real-source evaluation steps, see [QUICKSTART.md](QUICKSTART.md).

## Source-attributed research excerpt benchmark (offline)

Run a small, repeatable check of **real publisher wording** with no SIEM, live access or model key:

```powershell
& .\.venv\Scripts\python.exe scripts/benchmark_excerpts.py --output-directory public-excerpt-results
```

Its inputs are short, manually curated quotations and reference predicates in [benchmarks/public_excerpts_v1.json](benchmarks/public_excerpts_v1.json). It reports which **bounded behavior predicates** the existing extractor recognized and which unsupported descriptions were correctly withheld. Results go to `results.json` and `SUMMARY.md`. Using original publisher excerpts is a stronger smoke test than wholly fictional prose, but **it is not an evaluation of full articles, detection accuracy on real events, or native KQL/SPL execution**. The offline runner does not re-fetch or authenticate the excerpts. We will add wider, independent full-report evaluation separately.

## Full technical-report benchmark (optional live fetch, no SIEM)

A separate, more realistic evaluator processes **entire publisher HTML pages**, not merely excerpts. The initial manually annotated, partial reference set covers three Microsoft/Cisco Talos reports in [benchmarks/full_reports_v1.json](benchmarks/full_reports_v1.json). The run is **not** part of normal startup or CI because live publisher requests may be blocked or change content. To explicitly evaluate the published HTML:

```powershell
& .\.venv\Scripts\python.exe scripts/benchmark_reports.py --live --output-directory full-report-eval
```

Alternatively, use `--snapshots-dir MY_HTML` in place of `--live`, with files named `<case-id>.html` under that directory. Snapshots are **origin-unverified** and must not be claimed to be publisher-retrieved. Each report uses its own isolated SQLite database and reuses the existing evidence-gated research + draft proposal pipeline. Results are written to `results.json` and `SUMMARY.md` with retrieved page hashes, source readability, draft predicates, and missed annotated behaviors. A blocked or unreadable publisher page is **unscored**, not silently treated as a false negative. Only manually nominated patterns are measured: this is not comprehensive report recall, a measured false-positive rate, or evidence of production effectiveness. The rule engine does not execute native Sigma/KQL/SPL or deploy any alerts.

**Actual research benchmark (2026-10-16):** Three live publisher reports were read and six unverified rules drafted; all three *manually nominated* relationships were found after fixing the passive DLL-load extraction gap. See [evidence, before/after logs and limitations](benchmarks/RESULTS_OCT16.md). These three labels do not establish real-world detection accuracy.

## Challenge generated rules with fictional attack **and benign** events

The real-report benchmark now has a second, **independently labeled fictional** stage. Once full-report evaluation succeeds, test its exact source-linked drafts against sample malicious-command variants, authorized administration with overlapping behavior, renamed modules and missing telemetry. There is still **no requirement for a SOC or a SIEM**:

```powershell
& .\.venv\Scripts\python.exe scripts/benchmark_reports.py --live --output-directory full-report-eval
& .\.venv\Scripts\python.exe scripts/replay_benchmark.py --source-directory full-report-eval --output-directory fictional-event-eval
```

The versioned [synthetic challenge scenarios](benchmarks/synthetic_challenges_v1.json) define fictional malicious and benign event assumptions separately from the generated rules; the CLI loads the real-report run's local draft repository and calls the existing reference matcher on **only the qualifying source-linked draft**. It reports synthetic TP, FP, FN and TN, identifies each source-linked rule version by hash, and marks unavailable/missed source rules **unscored**. A benign match shows potential alert noise; attacker variations and missing fields expose evasion and visibility limitations. **These counts are not real SOC precision/recall, operational false-positive rates, or native KQL/SPL/Sigma query execution.** No generated rules are automatically approved or deployed. The same stages also run as a GitHub Actions demonstration and publish JSON/Markdown artifacts.

## Export SOC-review packages without a SIEM

After running the full-report evaluation and fictional-event challenges, you can bundle **the exact generated rules** as Sigma, KQL and SPL files, each accompanied by a source paragraph reference, page hash, required fields, evidence limitations and synthetic event outcomes:

```powershell
& .\.venv\Scripts\python.exe scripts/export_review_bundles.py --source-directory full-report-eval --challenge-directory fictional-event-eval --output-directory detection-review-packages
```

Read `detection-review-packages/README.md`, then open each rule's `REVIEW.md` and `metadata.json`. Rule text is copied from the source-linked draft repository, not regenerated, and checked against the recorded predicate fingerprint. Rules are never approved, published or deployed by this command. Generic example KQL and SPL **are not guaranteed to execute** against your SIEM tables or index configuration. No production environment is required to generate this review package.

The [2026-10-16 evaluation](benchmarks/RESULTS_OCT16.md) records the actual three-publication retrieval, missed DLL relationship and successful extraction retest. Its associated fictional replay is a separate demonstration of intended matches, false alarms and missed variants—not a real-world performance measurement.

## Independent held-out research corpus (no tuning on the results)

The **seven-report locked hold-out** in [benchmarks/full_reports_holdout_v1.json](benchmarks/full_reports_holdout_v1.json) is separate from the three known development reports used above. Its seven publisher pages and partial human behavior references were selected and frozen **before the first scored run**. The separate [held-out GitHub Actions workflow](.github/workflows/heldout-report-evaluation.yml) evaluates the same code on these previously untested publications; keep misses, unsupported behavior types and publisher-blocked articles visible instead of rewriting the labels or changing detection logic to make the score look better. The selection is a convenience sample, not random or independently second-reviewed. In particular, 7/7 would not mean 100% extraction accuracy or production detection effectiveness.

Run locally if desired:

```powershell
& .\.venv\Scripts\python.exe scripts/benchmark_reports.py --manifest benchmarks/full_reports_holdout_v1.json --live --output-directory heldout-report-results
```

The **development benchmark** evaluates 3 known reports. The **held-out benchmark** adds 7 distinct reports, bringing the attempted evaluation set to **10 reports** when both are executed. Do not mix their scores into one impressive-looking metric or claim comprehensive ground truth. See [benchmarks/README.md](benchmarks/README.md) for scope and provenance limits.

## Full 20-report evaluation: actual findings and limitations

We evaluated **20 distinct public technical research articles** in three separate batches: 3 *iteratively tuned* development reports, 7 previously unmeasured Microsoft reports, and 10 new reports from Google/Mandiant, Palo Alto Unit 42 and Cisco Talos. All publisher pages were readable during their respective GitHub Actions runs. **Source-backed rule creation remains inconsistent:** the developer-tuned three references were found, while neither first-pass batch reproduced its human-selected exact behavior predicates (7/7 and 10/10 misses). The system produced other unverified rule drafts, but those are **not automatically correct detection rules**. These partial references lack independent adjudication, and the scores cannot be combined or interpreted as real-world SOC detection effectiveness.

- [Auditable multi-vendor first-pass results, 10 reports](benchmarks/RESULTS_MULTIVENDOR_OCT16.md) — [successful GitHub Actions run](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38957335204).
- [Initial seven-report extraction failure analysis](benchmarks/RESULTS_HOLDOUT_OCT16.md).
- [Known three-report development results and simulated rule test limitations](benchmarks/RESULTS_OCT16.md).
- [Evaluation protocol and no-SIEM claims policy](benchmarks/README.md).

**New narrowly supported drafting:** Synthetic tests now exercise explicit attacker-executed `powershell.exe` commands containing both `Add-MpPreference` and an exclusion switch, and exact `mshta.exe` HTTPS HTA URLs. Generic source descriptions, benign documentation, unrelated clauses and negated events remain unverified and must not generate these command drafts. These are **narrow selectors**, not general malware recognition, and have not been shown to improve the 10-report first-pass result. They cannot automatically be approved or deployed.

## General Windows executable lineage + independent source review

The development branch now recognizes **source-attributed, attacker-linked named .exe → .exe process relationships**, even if neither process is PowerShell or msiexec. For example, a fictional case in which a malicious loader launches a named resource converter can lead to a two-field ParentImage/Image draft. Generic documentation, separate benign activity and unsupported source claims must not automatically become detections. Source evidence, human approval, and local SIEM validation remain mandatory.

The first-pass multi-vendor benchmark also exposed an important measurement limitation: the **manually selected behavior labels themselves have not been independently verified**. Rather than rewriting previously measured targets or pretending the result improved, produce a **blank independent review worksheet** from existing benchmark output:

```powershell
& .\.venv\Scripts\python.exe scripts/adjudicate_research.py --manifest benchmarks/multivendor_holdout_v1.json --source-directory multivendor-results --output-directory review-worksheet
```

Open the generated `INDEPENDENT_REVIEW.csv` and `README.md`. A second analyst must review original publisher wording, decide whether a behavior was observed or merely suggested as a hunt, and verify the proposed telemetry fields. The script makes **no network requests**, leaves frozen report labels and prior results unchanged, and labels **every entry as PENDING_INDEPENDENT_REVIEW**. It does not improve scores or certify rules. This review step works entirely without a SOC or SIEM.

## What it does

- Collects CVEs, advisories, research feeds and GitHub leads.
- Shows failed sources, empty feeds and stale collection.
- Runs collection independently of Claude through a Windows scheduled task.
- Reads cited reports and saves paragraphs, URLs and page hashes.
- Creates drafts from supported process chains, commands, DLL loads, destinations and file/hash selectors.
- Supports Windows and a limited set of Linux behaviors.
- Translates supported publisher KQL filters into drafts.
- Enforces exclusions and creates unique Sigma IDs.
- Deduplicates exact rules and warns about possible overlap.
- Shows mapped examples for Defender and Sysmon/Splunk.
- Flags changed source content for review.
- Stores separate draft and approved rule versions.

## Research and review

- **Priority:** research high-priority leads, starting with CISA KEV.
- **Sources:** vendor advisories, CISA guidance and linked technical reports.
- **Normal budget:** up to 4 leads, 14 pages per lead and 40 fetches per pass.
- **Deeper research:** `deep_research_batch` supports up to 20 leads and 120 fetches.
- **Backfill:** each poll reviews 20 older researched leads; stored-only review does not fetch missing pages.
- **Triage:** groups leads needing source review, browser review or more detection detail.
- **Triage budget:** up to 8 researched leads, 16 fetches and 200 quick closures per run.
- **Enough detail:** propose an unverified draft for analyst review.
- **Insufficient detail:** show the gap; CVE-only leads go to exposure/patch review.
- **Unreadable page:** keep it pending; never count it as researched.
- **Blocked page:** offer browser/manual review; do not bypass access controls.
- **Captured text:** browser captures and manual quotes remain unverified.
- **Workup:** show source, behavior, draft/gap, required fields, inventory status and test results.
- **Existing rules:** compare available inventory before proposing; undeclared coverage stays Unknown.
- **Authorship:** distinguish server-written automatic drafts from Claude/analyst proposals.
- **Corroboration:** queue matching new research for review; approval adds +1 to the pattern score.

## Approval and risk

- Verify the original source paragraph.
- Test the current rule against labeled malicious and benign events.
- Review existing rules and possible overlaps.
- Explicitly approve before saving an approved local snapshot.
- Test the mapped query in its target engine before deployment.
- Synthetic tests do not satisfy source-linked approval requirements.
- Imported samples remain origin-unverified; XML alone does not prove authenticity.
- Approval saves locally; it does not deploy or push a rule.
- Environment risk needs confirmed assets and local event context.
- Risk uses the asset named in that event; it does not combine unrelated assets.
- Threat priority, corroboration score and environment risk are separate.

## Example rules created

From the [fictional RMM report](threat_research/lab_fixtures/automatic_reports.json), the server creates two independent drafts:

- **PowerShell download:** `RMM.Agent.exe` parent + image containing `PowerShell` + `Invoke-WebRequest` command.
- **Silent MSI installation:** `msiexec.exe` image + `/qn` + `ClientSetup.msi`.
- **Telemetry:** process creation, image and command line; the first rule also needs parent image.
- **False positives:** authorized RMM maintenance and software deployment.
- **Limits:** renamed packages or missing fields can evade matching.
- **Scope:** separate hunts; no invented event correlation or MSI parent.

<details>
<summary>Show Sigma, KQL and SPL examples</summary>

**Sigma:** generated MSI selector, with metadata shortened. Fictional, experimental and unverified.

```yaml
title: Reported msiexec.exe /qn execution
id: 980d5e7c-4d76-5d37-8a8c-293c7ed2fa0c
status: experimental
description: Fictional lab draft; real labeled tests pending.
logsource:
  category: process_creation
  product: windows
detection:
  selection_1:
    CommandLine|contains: '/qn'
  selection_2:
    CommandLine|contains: 'ClientSetup.msi'
  selection_3:
    Image|endswith: 'msiexec.exe'
  condition: selection_1 and selection_2 and selection_3
falsepositives:
  - Authorized deployment of the same package
level: medium
```

**Kusto KQL:** Defender schema example; not executed in a customer tenant.

```kusto
DeviceProcessEvents
| where tolower(tostring(ProcessCommandLine)) contains '/qn'
    and tolower(tostring(ProcessCommandLine)) contains 'clientsetup.msi'
    and tolower(tostring(FileName)) endswith 'msiexec.exe'
```

**SPL:** assumes extracted Sysmon fields, index `sysmon_lab` and sourcetype `sysmon`. Adjust to actual ingestion.

```spl
index=sysmon_lab sourcetype=sysmon EventCode=1
| where like(lower(CommandLine), "%/qn%")
    AND like(lower(CommandLine), "%clientsetup.msi%")
    AND like(lower(Image), "%msiexec.exe")
```

</details>

## Where and how to implement

- **First:** ingest relevant logs and confirm every required field.
- **Map:** configure actual tables/indexes, sourcetypes and field names.
- **Test:** check known positive and benign events; tune exclusions.
- **Splunk:** run mapped SPL → **Save As → Alert** → set schedule, time range, trigger and notifications. [Guide](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.2/create-alerts/create-scheduled-alerts).
- **Sentinel:** adapt KQL to workspace tables, return `TimeGenerated`, test in Logs → **Analytics → Create → Scheduled query rule** → set entities, schedule and incidents. [Guide](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules).
- **Defender:** test KQL in Advanced hunting → check identifiers such as `Timestamp`, `DeviceId` and `ReportId` → create and configure a custom detection. [Guide](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules).
- **Elastic:** convert Sigma with an appropriate backend and ECS mappings → test → create a custom detection rule. No native Elastic executor is included. [Guide](https://www.elastic.co/docs/solutions/security/detect-and-alert/custom-query).
- **Other platforms:** convert Sigma with the target backend and field pipeline. [Sigma guide](https://sigmahq.io/docs/guide/getting-started.html).
- **No SIEM:** replay labeled JSONL locally; this checks selectors, not native queries.
- **Native checks:** `test_draft_in_siem` supports bounded Splunk/Defender queries; it does not publish alerts.
- **Important:** Microsoft Kusto KQL and Elastic Kibana KQL are different languages.
- **Profiles:** [offline example](examples/sysmon_splunk_lab_profile.json) · [connected Splunk lab](examples/splunk-sysmon-lab.profile.json). Use only mappings that match actual ingestion.

## Start and test

- Requires Python **3.11+**.
- Run these commands from the cloned project folder in PowerShell:

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m threat_research.cli doctor
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check_offline.ps1
```

- Connect Claude to the absolute venv `python.exe` path with arguments `-m`, `threat_research.server`.
- Fully quit and reopen Claude after updating.
- Ask Claude to run `research_and_propose_detection("REPORT-ID")`, then `lead_workup("REPORT-ID")`.
- Request cited predicates, mapped queries, overlaps, missing telemetry and test results.
- Check `polling_status` and `list_sources` for collection health.
- If a poll call times out, check whether collection is still running before retrying.
- Page `propose_stored_drafts` until its cursor is null for a complete stored backfill.
- **0.12.3 checks:** 298 passing tests; MCP smoke check with 66 tools.
- **Automatic lab:** 5 fictional reports, 12 server-written drafts, 7 query translations and 26 predicate checks.
- **Template challenge:** includes intentional false positives and misses.
- **NeedyMantis fixture:** 2 matches, 2 malicious misses and 2 benign nonmatches; synthetic only.
- **Real logs without SIEM:** export existing Sysmon Event 1, normalize, label and replay. [Instructions](COLLECTOR_SETUP.md#real-local-logs-without-a-siem).

## Limitations

- Supported sentence patterns can miss differently worded behaviors.
- Linux coverage is limited.
- Complex KQL joins, aggregates, OR branches and dynamic expressions need manual review.
- Local replay does not evaluate relative publisher lookback scope.
- Generic queries keep placeholders until telemetry is mapped.
- Concrete examples are schema assumptions, not discovered infrastructure.
- Authorized activity can match; overlap warnings are heuristic.
- Community indexes are pointers, not imported rules or local coverage.
- Feeds can fail, be blocked or require credentials; ThreatFox needs its optional key.
- Collection is polling, not streaming; the Windows task needs the host on and user logged in.
- Email requires configuration; otherwise the digest is saved locally.
- Synthetic results do not establish production accuracy.
- Broad real-report coverage, real-log accuracy and customer native SIEM results remain unproven.
- A rule match does not prove compromise; approval does not deploy alerts.

## Next priorities

- Measure extraction across representative real reports.
- Fix missed behaviors and query-conversion gaps.
- Test drafts against labeled real logs and target query engines.

[Quickstart](QUICKSTART.md) · [Collector setup](COLLECTOR_SETUP.md) · [Detection guide](DETECTION_PLAYBOOK.md) · [Dashboard](DASHBOARD.md) · [Release notes](RELEASE_NOTES_v0.12.3.md)
