# Analyst dashboard (no SIEM required)

A local, read-and-annotate web dashboard over the same SQLite store the MCP
tools and CLI already use. It is a **pure Python standard-library** HTTP
server (`http.server`) — no Node, no npm, no new third-party dependency, and
nothing is sent anywhere except the public sources this project already
polls. It never claims a rule was deployed to a SIEM; approval only adds a
rule to the local detection repository (`rules` table), exactly like the
existing `implement_rule` MCP tool.

## What it shows

- **Sources page** (`/`): one card per configured source (CISA KEV, NVD,
  GitHub advisories, RansomLook, ThreatFox, 5 curated GitHub repos, 33 RSS
  feeds, plus MITRE ATT&CK/ATLAS/OWASP framework releases and the article
  review backlog) with its last successful refresh, latest publication date
  among its collected records, a persistent record count, and any collection
  error from the most recent poll. Filter tags for status (`ok`/`error`/
  `stale`/`backlogged`/`never_collected`) and category. Clicking a source
  opens its collected threats.
- **Threat detail page** (`/threat?id=...`): clicking a threat shows, in
  order —
  1. **Source and evidence** — publisher, URL, publication date, collection
     date, cited observed behavior, and what still needs verification.
  2. **Detection inventory** — `YES` only for reviewed matching coverage
     (an approved local rule or an analyst-imported external rule at the
     exact fingerprint), `NO` only once that comparison actually ran, `UNKNOWN`
     when no verified behavior exists yet to compare. Matching rules link
     down to their Approval card.
  3. **Research and risk** — affected environment and risk score/reasons
     (or an explicit "unknown, environment not configured" instead of a
     guess), required logs/fields, false-positive notes, attacker-adaptation
     **hypotheses** (always labeled as such), and the current MITRE ATT&CK /
     MITRE ATLAS / OWASP LLM mapping with each framework's retrieved version
     and retrieval date (`Unavailable/stale` if a refresh has not succeeded).
  4. **Analyst workspace** — forms to record a verified behavior + source
     citation, telemetry fields, a benign example, and free-form feedback.
     "Recheck inventory and draft" re-runs the same evidence-gated drafting
     logic as the `draft_detection` MCP tool; if the evidence does not
     support one of the three behavior templates, the page shows **Research
     needed** with the specific reason instead of a query.
  5. **Approval** — the full Sigma/KQL/SPL draft and its telemetry-fit
     validation status. Only clicking **"Approve and add to rule
     repository"** moves a draft to `approved` in the local inventory
     (never a SIEM). **Reject** keeps the draft stored with its reason for
     later review — nothing is ever deleted — and it can be reopened.
- Framework mapping never invents an entry: it only renders what
  `frameworks.retrieve()` returns from the actually retrieved MITRE/OWASP
  release, citing that release's own version and retrieval time.

## Run it (Windows PowerShell)

From the project folder, with the virtual environment already created per
[QUICKSTART.md](QUICKSTART.md):

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m threat_research.cli dashboard
```

or, after the editable install registers the console script:

```powershell
.\.venv\Scripts\threat-research-dashboard.exe
```

Then open **http://127.0.0.1:8765/**. On first start it runs one collection
immediately (so the Sources page is not empty) and then again once every 24
hours (**"refresh collection daily"**) for as long as the process runs — set
`DASHBOARD_AUTO_REFRESH=false` if you already run `serve-live` against the
same database and just want the dashboard to read it:

```powershell
$env:DASHBOARD_AUTO_REFRESH = "false"
.\.venv\Scripts\python.exe -m threat_research.cli serve-live
# in a second PowerShell window, same THREAT_RESEARCH_DB:
.\.venv\Scripts\python.exe -m threat_research.cli dashboard
```

Optional: `--host`, `--port`, or the `DASHBOARD_HOST` / `DASHBOARD_PORT`
environment variables to bind elsewhere; `DASHBOARD_REFRESH_SECONDS` to
change the 24h cadence (mainly for testing). The **"Collect now"** button in
the header runs one collection on demand instead of waiting for the timer.

### Run the MCP server alongside it

The dashboard and the MCP server are separate processes over the **same**
database (`THREAT_RESEARCH_DB`), exactly like `serve-live` and Claude's MCP
process already are:

```powershell
claude mcp add --scope user threat-research -- "C:\path\to\ThreatResearch-MCP\.venv\Scripts\python.exe" -m threat_research.server
```

Set `THREAT_RESEARCH_DB` to the **same absolute path** for both, or leave it
unset to use the shared default (`~/.threat-research/intel.sqlite3`) on that
machine. Approving a rule in the dashboard is visible to Claude through
`detection_rule`/`review_detection_for_client` immediately, since both read
the same SQLite file.

## Fixed poll failures

Each of the five previously-identified failures was reproduced live against
the real public source before fixing it, and re-verified live afterward:

| Failure | Root cause found live | Fix |
| --- | --- | --- |
| NVD page cap | `lastModStartDate`/`lastModEndDate` catch-up windows (up to the poller's 7-day retry floor) can return well over the old 800-record budget (100/page × 8 pages); a live 24h window alone measured 1,014 modified CVEs. | `resultsPerPage` raised to NVD's documented maximum (2000) and `max_pages` to 25 (≈50,000 capacity), with a rate-limit pause between pages (0.6s with `NVD_API_KEY`, 6s without, matching NVD's guidance). The `RuntimeError` safety net remains if a window still exceeds that. |
| ATLAS pointer | `dist/ATLAS-latest.yaml` in `mitre-atlas/atlas-data` is a **git symlink**; `raw.githubusercontent.com` does not resolve symlinks server-side, so a plain fetch returns the link target's path as literal text (`v6/ATLAS-latest.yaml`, itself another symlink to `ATLAS-2026.09.yaml`). `yaml.safe_load` of that text is a string, not a mapping — hence "ATLAS document is not a mapping". | `frameworks._fetch_atlas()` detects a short, single-line, non-mapping response and follows the pointer chain (bounded to 5 hops) to the real release file, dynamically — it does not hardcode the current `v6`/`2026.09` path, so a future re-pointing keeps working. Live-verified: resolves to `dist/v6/ATLAS-2026.09.yaml`, 208 techniques, zero errors. |
| OWASP size limit | Could not reproduce against the current release (its PDF is 2.4MB, well under the old 18MB cap); the cap was likely sized for an earlier, heavier edition or a transient response. | Raised with real headroom as defense in depth: PDF cap 18MB→40MB, and the two intermediate HTML-page discovery caps 500KB→1.5MB. Live-verified: refreshes cleanly, version `2026`, 10 categories. |
| Failed RSS sources | Live-diagnosed individually: **Google Project Zero** ships its entire non-paginated history in one `feed.xml` (~9MB, exceeding the old 2MB cap); **Zero Day Initiative** sits right at the old 2MB boundary (~1.9MB) and can tip over it; the DOCTYPE/ENTITY guard was blocking *any* `<!DOCTYPE ...>`, not just the actual XXE vector; **CISA advisories** returns HTTP 403 from bot-management (Akamai) regardless of headers tried, from this network; **JFrog** returns an AWS WAF "challenge" (202, empty body, `x-amzn-waf-action: challenge`) that a plain GET cannot satisfy; **Malpedia** actively refuses the TCP connection from this environment (DNS resolves fine; this looks like network/IP-range blocking on their end, not a header or protocol issue). | Default cap raised 2MB→3MB with per-feed overrides (Google Project Zero 16MB, Zero Day Initiative 4MB); the DOCTYPE guard now only blocks documents containing an actual `<!ENTITY` declaration (the real XXE/billion-laughs vector) and strips a bare external DOCTYPE before parsing; gzip `Content-Encoding` is now decompressed; an empty/202 challenge response now raises a clear diagnostic instead of a confusing XML parse error; one bounded retry (with backoff) on a transient connection error; browser-shaped request headers throughout. **CISA advisories, JFrog, and Malpedia remain genuinely blocked from this environment** even after these fixes — they are WAF/bot-management and (for Malpedia) apparent IP-level blocks that no client-side header change can bypass; they may succeed from a different network (e.g. a residential/office IP) and are surfaced clearly on the Sources page rather than silently hidden either way. |
| Article review backlog | A fixed batch of 6 per poll cycle (every 15 min default) could not keep pace with a burst of new campaign reports (33 were queued with only 1 inspected in one observed run). | Batch size is now configurable (`ARTICLE_REVIEW_BATCH_SIZE`, default 18, 1-40) and the same redirect/header fixes above reduce 403/301 losses in the article fetcher itself (bounded same-host HTTPS redirects are now followed instead of failing every 301, up to 3 hops). |

All five are shown, per-source, on the Sources page (`error` badge with the
exact message) rather than only in a JSON tool response.

## Live walkthrough (real data, not fixtures)

This was run against the live public sources, not synthetic data:

```powershell
.\.venv\Scripts\python.exe -m threat_research.cli poll-once
.\.venv\Scripts\python.exe -m threat_research.cli dashboard
```

Result: a real, currently-active CISA KEV entry (**CVE-2026-88771**, a Citrix
NetScaler vulnerability) was collected, opened on its threat detail page,
given an analyst observation citing Unit 42's real published threat brief
(`web_server_shell`, from `unit42.paloaltonetworks.com`), drafted into a
Sigma/KQL/SPL rule through the dashboard's "Recheck inventory and draft"
button, and approved through "Approve and add to rule repository." The page
then showed Detection inventory as `YES` linking that rule, and the Approval
section read **"Approved — not deployed to any SIEM"**, matching this
project's existing `implement_rule` guarantee. The same run also confirmed
Google Project Zero, MITRE ATT&CK, MITRE ATLAS, and OWASP LLM Top 10 all
collect with zero errors after the fixes above, and that CISA advisories,
JFrog, and Malpedia remain visibly (not silently) failing.

**No SIEM was contacted or claimed.** As with the rest of this project,
`evaluate_synthetic_soc_lab` (below) is the only place accuracy numbers are
reported, and it says explicitly that its 12-event measurement is a local
reference-matcher exercise on fictional fixtures, not a SIEM benchmark.

## Since this page was written

Five further gaps were closed on top of the dashboard above; see each
module's own docstring and `tests/test_rule_repository.py`,
`tests/test_inventory_declaration.py`, `tests/test_portable_onboarding.py`,
`tests/test_rule_reproducibility.py`, and `tests/test_live_poll_regressions.py`
for the full detail: a local Git-ready **rule repository** (`draft/`/`approved/`
JSON snapshots, `rule_repository.py`) mirrored on every draft/reject/reopen/
approve; a stricter **Yes/No/Unknown** inventory answer that requires an
explicit, complete, recent inventory declaration before it will ever say "No"
(`declare_inventory_scope`/`inventory_status`); confirmed **per-organization
isolation** of both database and rule repository in `enterprise.py`'s packs;
and **reproducible rule testing** (`test_rule_against_samples`) that hashes
the exact tested rule text and exports every match/miss into the repository.
41 MCP tools are exposed in total now (`grep -c "@mcp.tool()" threat_research/server.py`).

## Test results

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**114 tests, all passing**, ~40s on this machine — the 78 covered above,
unmodified in intent (one assertion in `test_dashboard.py` was updated to
match the stricter inventory-status rule above), plus 36 new tests across
the five files just listed. All fixtures remain fictional (`CVE-2099-...`
IDs, `example.test` domains — this project's isolated-lab convention from
`soc_lab.py`), covering:

- Source-name backfill and per-card record counts/errors (`DashboardDataTest`)
- Read-only detection-inventory status (`yes`/`no`/`unknown`) across the
  unknown → drafted → approved lifecycle
- Reject-keeps-the-draft / reopen-for-later-review, and that an approved
  rule cannot be rejected through that path
- Analyst workspace notes (validation, threat-existence check)
- The ATLAS symlink-pointer chain resolution (reproducing the exact live
  failure shape, plus a hop-limit safety test and a "don't mistake a real
  short mapping for a pointer" regression test)
- The RSS DOCTYPE/ENTITY fix (bare DOCTYPE now parses; an actual `<!ENTITY>`
  is still blocked), gzip decompression, and the empty/202-challenge
  diagnostic
- The expanded NVD page budget, including that the `RuntimeError` safety net
  still fires for a genuinely exceeded cap
- A full HTTP integration test against a running dashboard instance
  (ephemeral port): Sources page, source drill-down, threat detail's five
  sections, the full observe → draft → approve workflow, reject-and-reopen,
  the `Research needed` fallback when evidence doesn't support a template,
  the JSON `/api/sources` and `/api/threat` endpoints, 404 handling, and
  that a malicious record title (`<script>...`) is rendered escaped, never
  as live HTML

Two things this project has **never** claimed and this feature does not
change: rule approval only writes to the local `rules` table (never a SIEM),
and `evaluate_synthetic_soc_lab`'s measurement is a fictional-fixture,
local-reference-matcher exercise, not a real detection-accuracy benchmark.
