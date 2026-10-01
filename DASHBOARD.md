# Analyst dashboard (no SIEM required)

A local, read-and-annotate web dashboard over the same SQLite store the MCP
tools and CLI already use. It is a **pure Python standard-library** HTTP
server (`http.server`) — no Node, no npm, no new third-party dependency, and
nothing is sent anywhere except the public sources this project already
polls. It never claims a rule was deployed to a SIEM; approval only adds a
rule to the local detection repository (`rules` table), exactly like the
existing `implement_rule` MCP tool.

## Workup panel and triage tab

- The lead page's **Workup** panel renders `lead_workup(threat_id)` exactly. It shows:
  - the next analyst decision, source and dates;
  - quoted patterns with artifact sufficiency and the publisher's own reasoning;
  - inventory connection and Yes/No/Unknown coverage separately; each draft's cited paragraph, predicate support, Sigma, generic KQL/SPL templates, mapped query when available, tests and source-verification status;
  - the three separate risk measures and the asset/context connection state.
- The page's environment risk no longer derives a number from default inputs. With no confirmed asset and local event context it shows *Score unavailable* and the missing inputs.
- **Triaged open** tab: raw leads triage could not close. `triage_status()` gives each reason.

## Research backlog vs raw leads

The single "Research needed" tab (every collected lead without verified
behavior, 1,584 on the 2026-09-29 database) is split into disjoint queues,
each with its own tab and `list_leads(queue=...)` filter:

- **Research backlog**: CISA KEV CVEs, reports citing a KEV CVE, and reports
  with behavior leads that still need research. The automatic research pass
  works this queue each poll (`run_research_pass()`).
- **Raw leads**: everything else collected (non-KEV CVEs, leak claims,
  general news). Untriaged collection, not a research to-do list.
- **Research completed**: cited sources were read and none names a specific
  observable; the lead page shows the pages inspected (with times), cited
  excerpts, missing telemetry and an exposure/patch review offer.
- **Evidence recorded**: an analyst-verified observation exists.

The lead page's research step lists every page the pass tried. The Source
errors tab lists research-pass publisher blocks and unreadable pages
separately from source feed errors.

## 0.11.0: leads, per-lead progression, tabs

- **Tabs with live counts**: Research needed, Draft rules, Pending reviews,
  Approved rules, Source errors, plus **MCP tools** (`/tools`), which lists
  the MCP tool behind every view. Each page footer also names its MCP call.
- **All leads** (`/leads`): source dropdown, publication/collection date
  range, status (`research_needed`, `article_leads`, `evidence_recorded`),
  rule state (`none`, `draft`, `approved`, `rejected`) and kind filters. Shows
  50 per page with Previous/Next and a total count. Every row keeps
  publication date, collection date, original URL and its source's
  latest fetch status. The same query is `list_leads` over MCP. The page size
  is local display paging, not upstream API paging.
- **Lead detail progression**: research needed → cited behavior/evidence →
  required telemetry → inventory Yes/No/Unknown → candidate Sigma/KQL/SPL →
  labeled checks → analyst decision → versioned rule repository. **Research /
  Draft detection** appears only when a cited analyst observation supports a
  behavior; otherwise the page states the exact missing input. On an
  inventory match it shows the existing rule, any pending corroboration
  review, and a proposed corroboration (+1, never a status change) instead of a
  duplicate draft. Labeled JSONL events can be pasted to replay against a rule;
  the result is stored with the rule's content hash and nothing is approved.
  MCP: `lead_progression(threat_id)`.
- Cross-origin form posts are refused, so another web page cannot drive
  approvals on the local dashboard.

### Source failures from the 2026-09-28T19:36Z poll

That poll ran code older than this repository's first commit. Re-checked live
on 2026-09-29 with 0.11.0 against a copy of the same database:

| Source | Cause found | 0.11.0 result |
| --- | --- | --- |
| NVD page cap | Whole window was retried until it fit in one run's page budget | Day-sized chunks; a capped run ingests what arrived and checkpoints only fully paged days (`partial`, never "complete"). Live: 1,386 records, ok |
| CISA advisories 403 | CDN refuses Python's TLS 1.3 handshake regardless of headers; the same official RSS is served over TLS 1.2 | TLS 1.2 for this feed only, verification unchanged. Live: ok |
| Google Project Zero "too large" | ~9MB full-history feed | 16MB override (already in 0.10.0). Live: ok |
| Zero Day Initiative XML | Bare DOCTYPE was rejected | DOCTYPE stripped, ENTITY still blocked (0.10.0). Live: ok |
| JFrog empty response | `jfrog.com/blog` feeds return an empty HTTP 202 bot challenge to every automated client, curl included | Switched to JFrog's official `research.jfrog.com/rss.xml`. Live: ok |
| Malpedia refused / TLS | Valid chain to HARICA TLS RSA Root CA 2021, which Python on Windows does not see | Adds Mozilla's CA bundle (`certifi`) to the system store. Live: ok |
| Article 301 | Check Point redirects HTTPS to `http://` | Same-host redirect upgraded to HTTPS. Live: inspected |
| Article 403 (SecurityWeek) | Stored URL lacks the trailing slash; the WAF 403s that form for non-browser clients | Retries the canonical slash form. Live: inspected |
| Genuine publisher blocks | Dark Reading 403 on article pages | Reported as `publisher_blocked` after two attempts; read in a browser and record behavior manually. HTTP 429 is retried with backoff |
| ATLAS / OWASP | Symlink pointer and PDF size (fixed in 0.10.0) | Live: ATLAS 2026.09 (208), OWASP 2026 (10). A failed refresh keeps the last-known-good snapshot and says so |

`polling_status` now reports `last_result_age_minutes`, `last_result_stale`
and the collector version, so an old result cannot be mistaken for a current
failure.

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
- **Reviews page** (`/reviews`, nav item shows a live pending count): when a
  newly collected, cited article lead lexically matches an existing local or
  imported rule's behavior, it lands here as a durable pending review — the
  rule's ID/title, the new source and paragraph, current and proposed
  `pattern_score`, and why it matched — never scored automatically. Approving
  links the cited evidence and adds exactly +1; rejecting leaves the rule
  untouched. A repeated poll, retry, or a second review citing the same
  source can never increment the same rule twice.

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
the header starts one collection on demand and returns to the Sources page
immediately. A status message updates when the poll finishes; a second click
while collection is running does not start another poll. You may browse other
dashboard pages while it runs and return to Sources to see the result. The
Sources summary shows the completed poll's status, new lead count, source
fetch count and feed errors. Filter source cards by exact source, type or
fetch status. **All leads** defaults to newest collection date, so a newly
collected report with an older publication date appears near the top; switch
"Newest by" to publication date when needed. **Draft rules** shows stored
local drafts and expands each rule's Sigma, KQL and SPL. A GitHub detection
repository entry is a commit pointer, not a drafted or imported rule.

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
