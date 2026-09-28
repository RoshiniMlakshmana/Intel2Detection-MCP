# ThreatResearch MCP

An evidence-gated threat intelligence and detection workflow for Claude, built on the [Model Context Protocol](https://py.sdk.modelcontextprotocol.io/). Runs as an MCP server, an optional continuous poller, and a local analyst dashboard — no SIEM required to start. Each organization runs its own installation and database.

## 1. What it does

Collects newly published threats, has Claude (or an analyst) research the *actual cited behavior* rather than guessing from a CVE title, checks whether matching detection coverage already exists, drafts a Sigma/KQL/SPL rule only when a behavior and its required telemetry are verified, and adds that draft to a local rule repository only after explicit analyst approval — never automatically, never deployed to a SIEM.

## 2. Impact

It removes the manual work of checking dozens of feeds each morning, reading past a headline for real technical detail, and hand-drafting a first-pass Sigma rule with its telemetry list. It does not measure or claim a specific time saved — that depends on your feeds, team, and review process.

## 3. Sources

- **CVE/advisories** — CISA KEV, NVD, GitHub Security Advisories, merged by CVE ID: **verified source facts**.
- **Research and news** — 33 RSS/Atom feeds (government, vendor research, security news; listed in `threat_research/research_feeds.py`), plus on-demand full-article inspection.
- **Ransomware leak-site claims** — RansomLook recent posts: **unverified claims**, never evidence.
- **Community detections** — 5 curated GitHub repos (Unit 42, Volexity, Meta, SigmaHQ, Microsoft Sentinel), commit subjects only, as **research leads**, never imported as coverage.

Only an analyst-recorded observation tied to a specific cited claim becomes **evidence** for a rule; everything else stays a lead until reviewed.

## 4. Install and connect to Claude Code

Tested on Windows PowerShell (Python 3.11+), from the project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m threat_research.cli doctor
claude mcp add --scope user threat-research -- "C:\path\to\ThreatResearch-MCP\.venv\Scripts\python.exe" -m threat_research.server
```

`doctor` should report `ready_for_research`. In Claude Code:

> Use threat-research to collect fresh CVEs and emerging threats, check inventory status, and draft a rule only where cited evidence and required telemetry support it.

Full setup, the analyst dashboard, and Claude Desktop config: **[QUICKSTART.md](QUICKSTART.md)**, **[DASHBOARD.md](DASHBOARD.md)**.

## 5. Deploy for a team

Each organization gets an isolated database and rule repository:

```powershell
.\.venv\Scripts\python.exe -m threat_research.cli create-pack --directory C:\ThreatResearch\Acme --name "Acme SOC" --siem splunk
```

`--siem` is `splunk`, `defender`, or `generic`. This writes `profile.json` (telemetry mapping), an empty `assets.csv` (only *confirmed* affected assets), and `inventory.json` (existing rules) — no credentials, no synthetic data. Fill those in, then:

```powershell
.\.venv\Scripts\python.exe -m threat_research.cli inspect-pack --directory C:\ThreatResearch\Acme
.\.venv\Scripts\python.exe -m threat_research.cli onboard-pack --directory C:\ThreatResearch\Acme
.\.venv\Scripts\python.exe -m threat_research.cli serve-live --directory C:\ThreatResearch\Acme
```

`inspect-pack`/`onboard-pack` validate both files before anything is scored or drafted. `serve-live` is a **separate, always-on polling worker** — run it apart from Claude's MCP process, against the same database. Credentials (`SPLUNK_TOKEN`, `GRAPH_TOKEN`, `SMTP_*`, `NVD_API_KEY`, `GITHUB_TOKEN`) go only in that worker's process environment — never in `profile.json` or `claude-mcp.json`. Details: **[QUICKSTART.md §5](QUICKSTART.md)**.

## 6. Limitations

- **Polling, not streaming** — latency is the poll interval (15 min default) plus each source's publish delay.
- **No cited behavior, no rule** — missing evidence returns "research needed," never a guess from a title.
- **Risk needs asset context** — without a confirmed inventory, priority stays `verify_*`/unknown, never a guessed score.
- **Drafts need native testing** — generated Sigma/KQL/SPL require target-SIEM validation with your own credentials.
- **Approval stays local** — it adds a rule to the local Git-ready repository only; nothing is deployed or pushed.

More detail and references: **[QUICKSTART.md](QUICKSTART.md)** · **[DASHBOARD.md](DASHBOARD.md)** · **[PUBLISHING.md](PUBLISHING.md)**.
