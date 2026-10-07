# Collection and telemetry setup

The collector runs independently of Claude. Rules remain drafts until source
verification, labeled checks and explicit approval. Collection does not require a SIEM.

## Windows collector

From the checked-out repository in PowerShell:

```powershell
git pull --ff-only origin fix/detection-gaps-oct06
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m threat_research.cli poll-status
```

Use the **same database** as the MCP server, not a new empty database. If
Claude's server entry sets `THREAT_RESEARCH_DB`, copy that absolute path. Otherwise
the `database` value from `poll-status` is the CLI default; compare it with the
server's `polling_status` before installing the task.

```powershell
$db = (& .\.venv\Scripts\python.exe -m threat_research.cli poll-status | ConvertFrom-Json).database
& .\.venv\Scripts\python.exe -m threat_research.cli poll-once --database $db --no-notifications
& .\scripts\install_collector_task.ps1 -Database $db -IntervalMinutes 30
Get-ScheduledTaskInfo -TaskName 'Intel2Detection Collector'
```

The task uses this checkout's actual `.venv\Scripts\python.exe`. It runs while
your Windows account is logged in, even when Claude is closed; `StartWhenAvailable`
catches missed starts and `WakeToRun` requests wake from sleep. Windows power
policy can prevent waking. It does not collect while the computer is off or the
account is logged out. An always-on host/service is needed for that. The installer
does not replace an existing task. Inspect/delete your own previous task before
reinstalling. Task execution and PowerShell syntax must be checked on Windows;
they cannot be exercised by the Linux test suite.

Each run appends status/counts/errors to `collector-runs.jsonl` beside the database.
A degraded/failed run exits with code 2; overlapping runs use the existing SQLite
lease. Scheduled collection does not deliver queued notifications.

## Credentials and source health

To resume a stopped collector using the existing database from Claude's config:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\resume_collection.ps1
```

This installs (or enables a matching) task, starts it immediately, and logs each
run. It refuses an ambiguous configuration or an existing task pointed elsewhere;
pass `-Database` explicitly if your MCP setup uses another config location. The
machine must be on and the user logged in. Check `polling_status` after completion:
look for a fresh `last_completed` and inspect every `source_attempts` entry. A
scheduled task waiting between runs need not hold an active polling lease.
The runner inherits Windows user environment credentials; if keys exist only in
Claude's MCP config, configure them in the user environment for scheduled intake.

Set `GITHUB_TOKEN` and `THREATFOX_AUTH_KEY` in the Windows user environment, then
restart processes so they inherit them. Do not put credentials in Git or screenshots.
GitHub credentials improve API rate limits; ThreatFox is optional until its abuse.ch
key is configured. Existing GitHub-token support is reused for initial sync.

Community repositories bootstrap all YAML file pointers in SigmaHQ `rules/`,
Sentinel `Detections/`, and Sentinel `Solutions/*/Analytic Rules/`, pinned to a
commit. The checkpoint is written only after ingestion; a truncated response fails
visibly and does not masquerade as a completed initial sync. Incremental Sentinel
polling also follows `Solutions/`. These are **external rule pointers**, not imported
rule bodies or proof of deployed local coverage; inspect the linked rule to compare
behavior and license.

The Sentinel recursive tree can exceed the default 8 MB JSON response limit.
Version 0.12.1 allows up to 32 MB only for curated repository tree fetches, still
refuses a truncated tree, and checkpoints only after ingesting the complete index.
A live check returned 42,285 tree entries and 2,766 in-scope rule pointers.

GitHub advisories use the endpoint's `Link` cursors, rather than unsupported page
numbers. The five-page per-run budget retains fetched records and saves the next
cursor only after successful ingestion. Interrupted fetches retain that page for
retry; completed snapshots clear the cursor before advancing toward the current
poll window. `GITHUB_TOKEN` is honored for advisory requests as well as repositories.
An incomplete catch-up remains `partial`/`degraded`; it is never reported as complete.

Version 0.12.2 repairs missing source labels on historical community `blob`/`commit`
pointers and known repository-name aliases. Publisher host matching accepts the
same host with or without `www`. Existing explicit source attribution is preserved.
Health and `list_sources.record_count` now use the same durable source-fact count.
A positive cumulative fetch counter with zero attributed stored facts reports
`empty_feed`; `records_fetched_total` exposes that counter separately, including
repeat fetches. A populated source returning zero new items remains healthy.
Empty RSS sources retain the initial lookback regardless of old fetch counters.
A community bootstrap checkpoint with no remaining stored rule pointers triggers
a fresh initial index instead of silently switching to commit-only polling.

Process drafting also binds a command from an immediately following sentence
when that sentence explicitly names the same child process as its subject and
states that it executed the command. Another process, negation, or an intervening
process reference cannot supply that command predicate.

New/unpopulated RSS sources start with a 365-day window. A source that has never
produced a usable record reports `empty_feed`; an already populated source may
legitimately return zero during a quiet poll. Empty feeds make the poll degraded.
Dark Reading is disabled, including pending article retries. CVE-only leads are
routed to exposure/patch review; draft from the original technical report instead.

Live feed checks on 2026-10-07 returned eligible records for DFIR Report, SentinelOne,
Securelist, ESET, Datadog, Objective-See, ZDI and Project Zero with a wider window.
Aqua's old `blog.aquasec.com/rss.xml` stopped at May 2025; it was replaced by
`https://www.aquasec.com/feed/`, which returned October 2026 records. Publisher
availability can change; these checks do not establish the laptop's current status.

Rechecked on 2026-10-07 UTC with a 365-day window: DFIR 6, SentinelOne 10,
ESET 100, Securelist 10, Datadog 30, Aqua 10, Objective-See 8, ZDI 20 and
Project Zero 10 eligible feed entries, with no fetch/parser errors. These are
counts from each published feed's available archive, not complete historical totals.

## Splunk Sysmon lab

### No SIEM: one-command offline check

First update/install the checkout as above, then run in PowerShell:

```powershell
& .\scripts\check_offline.ps1
```

This runs the unit suite (including the new Windows/Linux extraction, KQL,
exclusion, ID and source-refresh regressions), an actual MCP stdio smoke check,
and the synthetic labs. It creates a separate timestamped
`offline-lab-*` directory with a lab database, fictitious asset/telemetry profile,
draft Sigma/KQL/SPL, labeled events and `report.json`. It temporarily isolates DB
and rule-repository environment settings and restores them afterwards. A failed
stage stops the script; an existing nonempty output directory is never overwritten.
The lab has 3 draft rules and 12 events. Its expected TP=3, FP=2, FN=2, TN=5 include
intentional benign matches and evasion cases. Matching that baseline validates the
demonstration's behavior; it does not mean all rules have perfect detection accuracy.
The lab itself performs no live SIEM or publisher calls; the full unit suite may
also exercise existing public-framework retrieval paths.

The separate `automatic/` lab supplies five fictional report pages directly to
the normal research pass, without client-provided predicates or behavior
annotations. It requires 11 unverified server-written drafts: RMM/PowerShell,
mshta/GatherOsState, Linux nginx/bash/curl, DLL sideloading, and seven KQL selectors.
Its 23 positive/negative predicate checks cover case sensitivity, whole-term `has`,
`has_any`, `has_all`, suffixes, and the enforced System32 path exclusion. It also
requires unique Sigma IDs, repeat-pass deduplication and a visible gap for a complex
query rather than silently dropping `summarize`. Single-line KQL code blocks are
now retained along with multi-line blocks; extractor version 8 queues stale
research for re-reading. All snapshots stay inside the lab even when a real rule
repository is configured. This verifies bounded automation on synthetic text;
it does not establish results on the user's five real reports or native SIEMs.

For real stored research, `propose-stored --database PATH` processes one bounded
batch. Resume with `--after-id NEXT_CURSOR` until `next_cursor` is null, or ask
Claude to page `propose_stored_drafts`. Refresh outdated/unreadable research first.
Existing analyst drafts report `existing_draft`; they are not new automatic rules
or evidence of deployed coverage.

Draft backfill excludes CVE-only exposure/patch reviews from its bounded batch,
so those records cannot consume all slots before report behavior is considered.
The zero-draft catch-up batch on the user's host consisted of CVE-only records;
it did not test the five reports. Process the report batches and inspect cited
predicates before interpreting their results as automatic drafting coverage.

After this check, fully **quit Claude from the tray**, reopen it, start a new chat,
and confirm `propose_stored_draft_gaps` and `screen_benign_baseline` are available.
Ask it to run `evaluate_synthetic_soc_lab` for a quick isolated in-app check.
Restarting only reloads the server; it does not run these checks or verify actual
stored reports. Keep the lab database separate from the real collection database.
The PowerShell wrapper must be checked on Windows; its underlying Python stages
were exercised on Linux. No live SIEM or API credentials are needed for this lab.

Install Splunk locally, create index `sysmon`, and forward real Sysmon XML events
with sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. Enable process
creation (1), network connection (3), image loads (7), and file creation (11) in
Sysmon. Install/configure the corresponding field extractions. The supplied profile
declares actual Sysmon fields, host/time mappings and event numbers; it does not
assert that ingestion exists. SHA256 drafts need a separate extracted SHA256 field
from Sysmon's `Hashes`; the profile intentionally does not declare that field absent
an extraction. Linux rules require the equivalent actual Linux telemetry mapping.

```powershell
& .\.venv\Scripts\python.exe -m threat_research.cli configure-telemetry --profile .\examples\splunk-sysmon-lab.profile.json --database $db
& .\.venv\Scripts\python.exe -m threat_research.cli probe-splunk --family process_creation --database $db
```

Adjust the profile's index/sourcetype/HTTPS management URL if your lab differs.
Provide `SPLUNK_TOKEN` locally and `SPLUNK_CA_BUNDLE` for your lab certificate if it
is not already trusted. Field configuration preserves asset inventory and its
snapshot age. It creates neither assets nor detection coverage.

Restart Claude, start a new chat, and run `lead_workup`, then `test_draft_in_siem`
on a selected draft with an actual queryable lab. Native validation stays pending
until that real API check succeeds. The included replay tests are matcher tests,
not native Splunk/Defender execution.

## Draft correctness checks

The automatic pass recognizes parent/child launch claims and command terms,
including the RMM→PowerShell/Invoke-WebRequest case and explicit Linux shell
chains. It produces a bounded event selector, not a claim that the entire subsequent
installation sequence is correlated. Simple publisher KQL supports chained `where`,
literal AND, `==`, `=~`, `contains`, `endswith`, `has`, `has_all`, and one `has_any`
group. `has` preserves whole-term matching rather than becoming substring matching.
Joins, computed fields, nested/independent OR groups and other unsupported syntax
remain verbatim for analyst adaptation.

Sideloading drafts enforce a `C:\Windows\System32\` path-prefix exclusion and
identify it as default analyst tuning, not a publisher claim. Full loaded-path
telemetry is required (`ImageLoaded` in Sysmon; `FolderPath` in Defender).
Correlation-step Sigma IDs include the parent spec's identity and step position.
Repeated source-linked proposals report `existing_draft`, and duplicate extraction
paths do not inflate draft counts. Source refreshes retain the original page hash,
show `source_changed_since_draft`, re-check co-occurring cited values, and require
verification of the current page before approval.
