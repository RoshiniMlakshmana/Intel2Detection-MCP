# Synthetic SOC replay

This is a reproducible **offline** evaluation. Its CVE, publisher URLs under
`example.test`, article HTML, analyst annotations, asset inventory, and event
labels are fictional. The fixtures ship inside `threat_research/lab_fixtures/`.
It does not claim to connect to a production Splunk or Defender tenant.

## Run

From the project root after installation:

```bash
python -m threat_research.cli demo-soc --output-directory ./soc-lab-output
```

Open `soc-lab-output/report.json` for every source lead, evidence step,
environment risk component and illustrative high/low/unknown comparison, rule rationale, telemetry check, case outcome, and
tuning note. The `draft_rules/` directory contains Sigma, KQL, and SPL drafts.
The run creates an isolated SQLite inventory containing **drafts only**. Run
with a new or empty output directory for each experiment.

The flow exercises a synthetic CVE record, three RSS article metadata entries,
one article linked to that CVE, two reports without CVEs, local HTML extraction,
explicit fixture analyst annotations, inventory deduplication, and labeled
event replay. Feed metadata alone is rejected as rule evidence. The real
`inspect_cited_report` MCP tool applies additional citation and publisher
host checks before downloading a real article; the lab supplies HTML bytes
locally and never visits the fictional URLs.

## Replay an appended event stream

In one terminal:

```bash
python -m threat_research.cli watch-events --database ./soc-lab-output/lab.sqlite3 --file ./soc-lab-output/live_events.jsonl --include-drafts
```

In another terminal, append an event:

```bash
head -n 1 ./soc-lab-output/events.jsonl >> ./soc-lab-output/live_events.jsonl
```

The watcher emits a matching rule ID, behavior, threat ID, event ID, and
timestamp. It does not print a command line. `--include-drafts` is expressly
for this isolated lab; without it, the watcher reads approved local rules
only. `--from-end` skips events already in the file. Stop with Ctrl-C.
The watcher reads one canonical JSON object per line using `event_id`,
`timestamp`, `event_type`, and the fields listed in the generated selections.
It has an in-memory duplicate set, handles incomplete lines and file rotation,
and does **not** supply durable delivery or a native SIEM ingestion connector.

## Measured baseline

| Event-level outcome | Count | Example |
| --- | ---: | --- |
| True positive | 3 | Web worker to `cmd.exe`, encoded PowerShell, denied MCP tool execution |
| False positive | 2 | Approved web maintenance and approved deployment |
| False negative | 2 | Web worker to `rundll32.exe`, alternate encoded-command syntax |
| True negative | 5 | Correctly blocked tool action and ordinary activity |

On these 12 synthetic events, precision and recall are both **0.60**. The
false-positive rate is **2/7 = 0.286** among the benign fixtures. There is no
statistical basis to extrapolate those values to an enterprise. This reference
matcher evaluates the supported structured Sigma selections, not the exported
KQL/SPL queries. Target SIEM field mapping, native syntax, alert volume, and
representative benign baselines still require testing in the target tenant.

The false alerts need context such as change windows, process ancestry,
signer, and decoded command. The two misses justify separate hypotheses and
telemetry review; simply broadening a detection from one fabricated example
would conceal precision costs. A matched MCP audit event is a policy mismatch
until the request and enforcement records are independently checked.

For a real environment, onboard its asset snapshot and field maps, review an
actual cited article in Claude, record observed behavior, and draft a rule.
Use `check-rule`, `test-siem`, and `compare-splunk-rules` with permitted
read-only credentials. Label representative true and benign events before
deciding whether to approve a rule in the **local** inventory. Approval here
does not deploy a SIEM saved search.
