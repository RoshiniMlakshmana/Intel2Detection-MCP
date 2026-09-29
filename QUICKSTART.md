# Start ThreatResearch MCP without a SIEM

You can use the public intelligence collector, Claude tools, daily digest,
and synthetic SOC lab before connecting any enterprise telemetry. Environment
risk stays uncertain until you provide verified asset and log context.

## 1. Clone and install

```bash
git clone https://github.com/RoshiniMlakshmana/Intel2Detection-MCP.git
cd Intel2Detection-MCP
```

Use Python 3.11 or newer. On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m threat_research.cli doctor
```

On macOS/Linux:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m threat_research.cli doctor
```

The `doctor` result should say `ready_for_research`. It checks the Python/MCP
installation, local SQLite database, time zone, and polling settings offline;
it does not claim that any external feed is reachable.

## 2. Verify the complete workflow locally

Run `python -m threat_research.cli demo-soc --output-directory soc-lab-output`
with the virtual environment's Python executable above. Read
`soc-lab-output/report.json` for source evidence, three Sigma/KQL/SPL drafts,
environment risk comparisons, and 12 labeled event outcomes. Each run needs
a new or empty output directory. The lab uses only fictional data.

## 3. Collect and connect Claude

Run one collection with `python -m threat_research.cli poll-once`, then check
`poll-status` and `review-leads`. Both commands use the same virtual environment
Python. Feed failures are reported separately; a successful command does not
mean every configured source worked.

Run `python -m threat_research.cli refresh-frameworks` to retrieve the latest
official MITRE ATT&CK Enterprise, MITRE ATLAS, and OWASP LLM releases.
`framework-status` shows each release version, fetch time, content hash, and
whether the snapshot is stale. This needs access to official MITRE and OWASP
sites plus GitHub raw files. The live worker checks once per day as well.

For Claude Code, add the MCP server using **absolute paths**. For example on
macOS/Linux (replace the path):

```bash
claude mcp add --scope user threat-research -- /absolute/path/ThreatResearch-MCP/.venv/bin/python -m threat_research.server
```

On Windows PowerShell:

```powershell
claude mcp add --scope user threat-research -- "C:\absolute\path\ThreatResearch-MCP\.venv\Scripts\python.exe" -m threat_research.server
```

Open Claude Code and check `/mcp`. Ask it to run
`evaluate_synthetic_soc_lab` or `latest_threats`. The MCP process and worker
both use the default database in your home directory unless you explicitly
set `THREAT_RESEARCH_DB` for **both** processes. See the [full README](README.md)
for Claude Desktop configuration.

To research a CVE without a SIEM, ask Claude: “Call `research_detection_plan`
for CVE-...; tell me which behavior is actually supported, which sources are
only pointers, and what you need from me to write a detection.” After reading
the cited technical source, provide a claim, relevant log fields and values,
and benign overlap. Claude can then call `draft_custom_detection` with a safe
spec such as:

```json
{"event_family":"process_creation","platform":"windows","predicates":[
  {"field":"ParentImage","operator":"endswith","value":"w3wp.exe"},
  {"field":"CommandLine","operator":"contains","value":"certutil"}
]}
```

This example is a *hypothetical behavior*, not a CVE-specific rule. The result
is a review-only Sigma draft; ask for `review_detection_for_client` to see
duplicate coverage, field requirements, framework candidates and risk. When
no verified behavior is available, Claude should say **research needed** and
ask for a technical source or log evidence. Any CVE can be researched, but
some cannot support a reliable behavior rule yet.

## 3b. Open the analyst dashboard (no SIEM required)

```powershell
.\.venv\Scripts\python.exe -m threat_research.cli dashboard
```

Open http://127.0.0.1:8765/ for a Sources page (one card per feed, with last
refresh, latest publication date, record count, and any error), and a threat
detail page with source/evidence, detection inventory status, research and
risk (including MITRE ATT&CK/ATLAS/OWASP mapping), an analyst workspace, and
rule approval. See [DASHBOARD.md](DASHBOARD.md) for the full walkthrough,
what was fixed in the underlying pollers, and exact commands.

## 4. Keep collection running

On an always-on host, run `python -m threat_research.cli serve-live` using the
same virtual environment Python. This one process both polls approximately
every 15 minutes (`POLL_INTERVAL_MINUTES`) **and** checks for the daily digest
at your chosen local time (`DIGEST_TIME` in `DIGEST_TZ`, default `08:00`
`America/Los_Angeles`). Keep it running separately from Claude's on-demand
MCP process, against the same database, and never run two workers against
the same database at once.

**Email is optional and off by default.** Without `SMTP_HOST` and `DIGEST_TO`
set, the digest is written to a local text file (`digest-YYYY-MM-DD.txt`
beside the database) — nothing is ever sent, and nothing here claims
otherwise. Set real values yourself, once, directly in your own environment;
never put them in a file this repository tracks.

### Choose your local delivery time (PowerShell)

```powershell
[Environment]::SetEnvironmentVariable("DIGEST_TIME", "08:00", "User")
[Environment]::SetEnvironmentVariable("DIGEST_TZ", "America/Los_Angeles", "User")
```

`DIGEST_TZ` is any [IANA time zone name](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)
(e.g. `America/New_York`, `Europe/London`, `Asia/Kolkata`). `User`-scope
variables persist across reboots without editing any script or file, and a
new terminal or scheduled task picks them up automatically. Only add SMTP
variables the same way if you actually want email delivery:

```powershell
[Environment]::SetEnvironmentVariable("SMTP_HOST", "smtp.example.com", "User")
[Environment]::SetEnvironmentVariable("SMTP_FROM", "you@example.com", "User")
[Environment]::SetEnvironmentVariable("DIGEST_TO", "soc@example.com", "User")
[Environment]::SetEnvironmentVariable("SMTP_USER", "you@example.com", "User")
[Environment]::SetEnvironmentVariable("SMTP_PASSWORD", "<your real password>", "User")
```

### Run it unattended with Windows Task Scheduler

A tiny wrapper script avoids fragile quoting and gives you a real log file.
Run PowerShell **as Administrator** — `Register-ScheduledTask` returns
`Access is denied` otherwise. Replace the path, then run once as the
account that should own the worker:

```powershell
$dir = "C:\path\to\ThreatResearch-MCP"
$wrapper = Join-Path $dir "run-serve-live.ps1"

@"
`$exe = "$dir\.venv\Scripts\python.exe"
`$log = "$dir\serve-live.log"
Set-Location "$dir"
& `$exe -m threat_research.cli serve-live *>> `$log
"@ | Set-Content -Path $wrapper -Encoding utf8

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "ThreatResearchServeLive" `
    -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited
```

Verify, run it immediately for a smoke test, and tail the log:

```powershell
Get-ScheduledTask -TaskName "ThreatResearchServeLive"
Start-ScheduledTask -TaskName "ThreatResearchServeLive"
Get-Content "C:\path\to\ThreatResearch-MCP\serve-live.log" -Wait -Tail 20
```

To stop and remove it later:

```powershell
Unregister-ScheduledTask -TaskName "ThreatResearchServeLive" -Confirm:$false
```

For a headless server with no interactive logon, use `-AtStartup` instead of
`-AtLogOn` and supply `-User`/`-Password` (or a group-managed service account)
to `Register-ScheduledTask`; consult your own security policy before storing
a service account's credential, since that choice is outside this project.
A lighter alternative that skips the 15-minute poll and only sends the daily
digest is `serve-scheduler` (same executable, `-Argument` ending in
`serve-scheduler` instead of `serve-live`).

## 5. Add a team's environment later

Use `create-pack --directory <private-folder> --name "My SOC" --siem splunk`
(or `defender` or `generic`). Fill in verified `assets.csv`, telemetry mapping
in `profile.json`, and any existing mapped `inventory.json`. Then run
`inspect-pack --directory <private-folder>` and
`onboard-pack --directory <private-folder>`. `doctor --directory` checks the
pack's offline state. The generated `claude-mcp.json` points Claude to the
pack's isolated database. Start that team's worker with
`serve-live --directory <private-folder>`. Credentials belong in the local
process environment, never in the pack or GitHub.

`test-siem` runs read-only native queries when a supported SIEM and scoped
credentials are provided. Rule approval updates only local inventory; it
never publishes a detection to the team's SIEM. The
[SOC lab walkthrough](examples/soc_lab/README.md) explains the sample cases.

In Claude, ask: “Review detection RULE-ID for this client, including inventory
coverage, asset risk, SIEM fit, evidence, and current ATT&CK/ATLAS/OWASP
mapping.” Claude should call `review_detection_for_client`; the same review
is available through `review-detection --id RULE-ID`. Without verified client
assets, an environment risk score is unavailable. A framework match is a
versioned reference, not evidence that the technique occurred. The server
will say when a release cannot be fetched or a stored copy is older than 24
hours; no offline installation can promise fresh data.
