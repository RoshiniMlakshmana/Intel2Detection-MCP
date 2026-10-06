"""Local analyst dashboard: a stdlib-only HTTP server over the same SQLite
store the MCP tools and CLI use. No SIEM, no external service and no new
third-party dependency is required to run it.

Every read renders data this project already collected and validated
elsewhere (core/rules/frameworks/environment); this module adds no new
collection, scoring, or mapping logic of its own. It never claims a rule was
deployed to a SIEM, and it never invents a framework mapping the retrieved
catalog does not contain.
"""

import hashlib
import html
import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import (core, corroboration, custom_rules, dashboard_data, environment, poller, proposal_pass,
               rules, soc_replay, store, workflow, workup)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
REFRESH_SECONDS = "DASHBOARD_REFRESH_SECONDS"  # override for tests; production uses hours

STYLE = """
:root{color-scheme:light dark;--bg:#0f1420;--panel:#171e2e;--panel2:#1e2740;--text:#e7ecf7;
--muted:#96a2bf;--line:#2a3450;--accent:#5b9dff;--ok:#3fbf7f;--warn:#e0b64b;--err:#e5636b;--mono:ui-monospace,Consolas,Menlo,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;gap:18px;align-items:center;flex-wrap:wrap}
header .brand{font-weight:700;letter-spacing:.02em}
header nav a{color:var(--muted);text-decoration:none;margin-right:14px;font-size:14px}
header nav a:hover{color:var(--text)}
main{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:22px;margin:0 0 6px} h2{font-size:17px;margin:22px 0 8px;color:var(--text)}
h3{font-size:14px;margin:14px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
p.lede{color:var(--muted);margin:0 0 16px}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.badge.ok{color:var(--ok);border-color:var(--ok)} .badge.error{color:var(--err);border-color:var(--err)}
.badge.backlogged{color:var(--err);border-color:var(--err)} .badge.stale{color:var(--warn);border-color:var(--warn)}
.badge.never_collected{color:var(--muted)} .badge.yes{color:var(--ok);border-color:var(--ok)}
.badge.no{color:var(--err);border-color:var(--err)} .badge.unknown{color:var(--warn);border-color:var(--warn)}
.tags{margin:10px 0 18px;display:flex;flex-wrap:wrap;gap:6px}
.tags a{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:99px;padding:3px 10px;text-decoration:none}
.tags a.active{background:var(--accent);border-color:var(--accent);color:#08101f;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card a.name{color:var(--text);font-weight:600;text-decoration:none}
.card a.name:hover{text-decoration:underline}
.card dl{margin:8px 0 0;font-size:13px;color:var(--muted)}
.card dl div{display:flex;justify-content:space-between;gap:8px;padding:2px 0}
.card .err{color:var(--err);font-size:12px;margin-top:8px;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
tr:hover td{background:var(--panel2)}
a{color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.flash{border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:14px}
.flash.ok{background:#123524;border:1px solid var(--ok);color:#c9f5df}
.flash.err{background:#3a1a1c;border:1px solid var(--err);color:#ffd7d9}
code,pre{font-family:var(--mono)}
pre{background:#0a0e18;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12.5px}
form.inline{display:inline}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
input[type=text],input[type=url],textarea,select{width:100%;background:#0a0e18;border:1px solid var(--line);
color:var(--text);border-radius:6px;padding:7px 9px;font:inherit}
textarea{min-height:70px;font-family:var(--mono)}
button{background:var(--accent);color:#08101f;border:0;border-radius:6px;padding:8px 14px;font-weight:700;cursor:pointer}
button.secondary{background:transparent;border:1px solid var(--line);color:var(--text)}
button.danger{background:var(--err);color:#fff}
.row{display:flex;gap:20px;flex-wrap:wrap} .col{flex:1;min-width:260px}
ul.bullets{margin:4px 0;padding-left:18px} ul.bullets li{margin:3px 0}
small.muted{color:var(--muted)}
details{margin:6px 0} summary{cursor:pointer;color:var(--accent)}
nav a .count{display:inline-block;min-width:18px;padding:0 6px;margin-left:4px;border-radius:9px;background:var(--panel2);color:var(--text);font-size:12px;text-align:center}
form.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin-bottom:14px}
form.filters div{min-width:140px;flex:1} form.filters label{margin-top:0}
form.filters details.advanced{flex:0 0 100%;margin:0} .filter-inner{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
.pager{display:flex;gap:12px;align-items:center;margin:12px 0;color:var(--muted);font-size:14px}
.table-wrap{overflow-x:auto}
ol.steps{list-style:none;margin:0;padding:0;counter-reset:step}
ol.steps>li{position:relative;padding:8px 10px 8px 40px;border-left:2px solid var(--line);margin-left:14px;counter-increment:step}
ol.steps>li::before{content:counter(step);position:absolute;left:-14px;top:8px;width:26px;height:26px;border-radius:50%;
background:var(--panel2);border:2px solid var(--line);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
ol.steps>li.done::before{background:var(--ok);border-color:var(--ok);color:#08101f}
ol.steps>li.current::before{background:var(--accent);border-color:var(--accent);color:#08101f}
ol.steps>li.attention::before{background:var(--warn);border-color:var(--warn);color:#08101f}
ol.steps>li.blocked{opacity:.75}
.missing{color:var(--warn);font-size:13px}
p.mcp{font-size:12px;color:var(--muted);margin-top:18px}
"""


def _e(value):
    return html.escape("" if value is None else str(value))


def _fmt(value):
    return _e(value) if value else "<span class=\"muted\">unknown</span>"


def _safe_href(url, text=None):
    """Only render a stored URL as a clickable link when its scheme is
    genuinely http/https; anything else (unexpected adapter data) is shown
    as escaped plain text instead of a clickable href, since HTML-escaping
    alone does not neutralize a javascript: or data: scheme."""
    text = text if text is not None else url
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        scheme = ""
    if scheme not in ("http", "https"):
        return _e(text)
    return f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">{_e(text)}</a>'


def _page(title, body, active=None, flash=None, path=None):
    counts = workflow.workflow_counts(path)

    def counted(label, key):
        return f'{label}<span class="count">{counts[key]}</span>'
    needs_count = counts["source_errors"] + counts["pending_reviews"] + counts["actionable_research_backlog"]
    nav_items = [("/", "Sources"), ("/leads", counted("Threat intel", "leads_total")),
                 ("/rules?state=draft", counted("Rules", "draft_rules")),
                 ("/attention", f'Needs attention<span class="count">{needs_count}</span>')]
    # Built without a backslash inside any f-string expression part: that
    # syntax is a SyntaxError on Python < 3.12 (PEP 701 lifted the
    # restriction only in 3.12), and this project supports 3.11+.
    active_style = "color:var(--text);font-weight:700"
    nav = "".join(f'<a href="{href}" style="{active_style}">{label}</a>' if href == active else
                  f'<a href="{href}">{label}</a>'
                  for href, label in nav_items)
    flash_html = ""
    if flash:
        kind, message = flash
        flash_html = f'<div class="flash {"ok" if kind == "ok" else "err"}">{_e(message)}</div>'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} · Threat Research Dashboard</title><style>{STYLE}</style></head>
<body><header><span class="brand">Threat Research Dashboard</span><nav>{nav}</nav>
<span style="margin-left:auto"><form class="inline" method="post" action="/collect-now">
<button class="secondary" type="submit">Collect now</button></form></span></header>
<main>{flash_html}{body}</main></body></html>"""


def _mcp_hint(*calls):
    return '<p class="mcp">Same data over MCP: ' + ", ".join(f"<code>{_e(c)}</code>" for c in calls) + "</p>"


def _flash_from_query(qs):
    if "flash" in qs:
        return ("ok" if qs.get("ok", ["1"])[0] == "1" else "err", qs["flash"][0])
    return None


# ---------------------------------------------------------------- Sources --

def _source_card(card):
    error_html = f'<div class="err">{_e(card["error"])}</div>' if card["error"] else ""
    name_html = (f'<a class="name" href="/leads?source={_url_escape(card["name"])}">{_e(card["name"])}</a>'
                 if card["record_count"] is not None and card["category"] != "internal backlog"
                 else f'<span class="name">{_e(card["name"])}</span>')
    fetched = (f'<div><span>Items fetched last attempt</span><span>{card["last_fetched_records"]}</span></div>'
               if card.get("last_fetched_records") is not None else "")
    progress = card.get("research_counts")
    research_html = (f'''<details><summary>Research and rules for these leads</summary><dl>
<div><span>Research attempted</span><span>{progress["research_attempted"]}</span></div>
<div><span>Readable cited page</span><span>{progress["readable_page_leads"]}</span></div>
<div><span>Publisher blocked</span><span>{progress["blocked_page_leads"]}</span></div>
<div><span>Unreadable or failed</span><span>{progress["unreadable_page_leads"]}</span></div>
<div><span>Host not allowed</span><span>{progress["not_allowlisted_leads"]}</span></div>
<div><span>Cited pattern or artifact</span><span>{progress["pattern_or_artifact_leads"]}</span></div>
<div><span>Leads with draft rules</span><span>{progress["draft_leads"]}</span></div>
</dl><small class="muted">Counts are leads attributed to this source. A cited page may be hosted elsewhere.
Drafts still need analyst review.</small></details>''' if progress else "")
    return f"""<div class="card" data-status="{card['status']}" data-category="{_e(card['category'])}">
<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline">
{name_html}<span class="badge {card['status']}">{card['status'].replace('_',' ')}</span></div>
<small class="muted">{_e(card['category'])}</small>
<dl>
<div><span>Latest fetch</span><span>{_fmt(card.get('latest_fetch'))}</span></div>
{fetched}
<div><span>Last successful refresh</span><span>{_fmt(card['last_success'])}</span></div>
<div><span>Latest publication</span><span>{_fmt(card['latest_publication'])}</span></div>
<div><span>Record count</span><span>{card['record_count'] if card['record_count'] is not None else '—'}</span></div>
</dl>{research_html}{error_html}</div>"""


def render_sources(path=None, qs=None):
    qs = qs or {}
    data = dashboard_data.sources_overview(path)
    active_filter = (qs.get("filter") or [None])[0]
    selected_source = _qs_one(qs, "source", "")
    selected_category = _qs_one(qs, "category", "")
    selected_status = _qs_one(qs, "status", "")
    statuses = sorted({c["status"] for c in data["sources"]})
    categories = sorted({c["category"] for c in data["sources"]})
    cards = data["sources"]
    if active_filter and active_filter != "all":
        cards = [c for c in cards if c["status"] == active_filter or c["category"] == active_filter]
    if selected_source:
        cards = [c for c in cards if c["name"] == selected_source]
    if selected_category:
        cards = [c for c in cards if c["category"] == selected_category]
    if selected_status:
        cards = [c for c in cards if c["status"] == selected_status]
    filters = f"""<form class="filters" method="get" action="/">
<div><label>Source</label><select name="source">{_options([(c["name"], c["name"]) for c in sorted(data["sources"], key=lambda c: c["name"])], selected_source, "all sources")}</select></div>
<div><label>Type</label><select name="category">{_options([(c, c) for c in categories], selected_category, "all types")}</select></div>
<div><label>Fetch status</label><select name="status">{_options([(s, s.replace("_", " ")) for s in statuses], selected_status, "all statuses")}</select></div>
<div style="flex:0"><button type="submit">Apply</button></div></form>"""
    draft_rules = workflow.list_rules(path, state="draft", per_page=1)
    draft_item = draft_rules["items"][0] if draft_rules["items"] else None
    draft_link = (f'<p><a href="/rules?state=draft">Draft rules ({draft_rules["total"]})</a>'
                  + (f' &middot; <a href="/threat?id={_url_escape(draft_item["threat_id"])}&from=rules#rule-{_e(draft_item["id"])}">'
                     f'{_e(draft_item["title"])}</a>' if draft_item else ' &middot; None drafted yet') + '</p>')
    last_poll = (f'<p><b>Last collection:</b> {_fmt(data["last_poll_completed"])} &middot; '
                 f'{_e(data["last_poll_status"] or "unknown")} &middot; '
                 f'<b>{_e(data["last_poll_new_records"] if data["last_poll_new_records"] is not None else "unknown")}</b> '
                 f'new leads &middot; {len(data["last_poll_source_counts"])} sources fetched &middot; '
                 f'{len(data["last_poll_source_errors"])} feed errors. '
                 '<a href="/leads?sort=collected">View newest collected leads</a>.</p>'
                 if data["last_poll_completed"] else '<p>No collection has completed yet.</p>')
    stale_html = (f'<div class="flash err">The last recorded poll is {data["last_result_age_minutes"]} minute(s) old or was '
                  f'produced by different collector code; errors below may already be fixed. Use <b>Collect now</b> '
                  f'to refresh.</div>' if data.get("last_result_stale") and data.get("last_result_age_minutes") is not None else "")
    collecting = _qs_one(qs, "collecting") == "1" or data["poll_running"]
    collection_html = """
<div class="flash ok" id="collection-status" role="status" aria-live="polite">
Collecting sources and reviewing articles. You can keep using the dashboard; this page will update when finished.
</div>
<script>
(() => {
  const label = document.getElementById('collection-status');
  let checking = false;
  async function check() {
    if (checking) return;
    checking = true;
    try {
      const response = await fetch('/api/collection', {cache: 'no-store'});
      if (!response.ok) throw new Error('status unavailable');
      const state = await response.json();
      if (!state.running) {
        const failed = state.status === 'failed' || state.status === 'unknown';
        const message = state.status === 'unknown' ? 'Collection status unavailable; check the Sources page.'
          : failed ? 'Collection failed: ' + (state.error || 'see the dashboard console')
          : state.status === 'degraded' ? 'Collection finished with some source errors. New leads: '
              + (state.new_records ?? 0) + '. See Needs attention.'
          : 'Collection finished. New records: ' + (state.new_records ?? 0) + '.';
        window.location.replace('/?flash=' + encodeURIComponent(message) + '&ok=' + (failed ? '0' : '1'));
        return;
      }
      label.textContent = 'Collecting sources and reviewing articles. You can keep using the dashboard; this page will update when finished.';
    } catch (error) {
      label.textContent = 'Collection status unavailable. Refresh this page to check again.';
    } finally {
      checking = false;
    }
  }
  check();
  setInterval(check, 2000);
})();
</script>""" if collecting else ""
    if collecting:
        stale_html = ""  # The old result is expected to be stale until the running poll completes.
    body = f"""<h1>Sources</h1>
<p class="lede">Choose a source to see what it collected. A successful refresh can add zero new leads if nothing is new.
GitHub detection entries are links to community work, not local rules. Refresh every {data['poll_interval_minutes']} minute(s).
{'Collecting now.' if data['poll_running'] else ''}</p>
<p><small class="muted">Database: <code>{_e(data['database'])}</code> &middot; collector: {_e(data['collector_version'])}</small></p>
<div class="panel">{last_poll}{draft_link}<p><a href="/attention">Collection and research problems</a></p></div>
{collection_html}{stale_html}{filters}
<p class="lede">Showing {len(cards)} of {len(data["sources"])} source and status cards. A stored count is the total
distinct leads from that source; items fetched on the last attempt can include leads already stored.
Open "Research and rules" on a source to see how far its leads went.</p>
<div class="grid">{''.join(_source_card(c) for c in cards) or '<p>No sources match these filters.</p>'}</div>
{_mcp_hint("list_sources()", "source_errors()", "polling_status()")}"""
    return _page("Sources", body, active="/", flash=_flash_from_query(qs), path=path)


def _qs_one(qs, key, default=None):
    return (qs.get(key) or [default])[0]


def _options(values, selected, blank="any"):
    items = [f'<option value="">{_e(blank)}</option>'] if blank is not None else []
    items += [f'<option value="{_e(v)}"{" selected" if v == selected else ""}>{_e(label)}</option>' for v, label in values]
    return "".join(items)


def _source_options(selected):
    """Keep the exact source filter, but make the long catalog navigable."""
    groups = {label: [] for label in ("Vulnerabilities and government", "GitHub advisories",
                                      "Open source detection rules", "GitHub threat intel",
                                      "Research and news", "Other feeds")}
    detections = {"GitHub: SigmaHQ community rules", "GitHub: Microsoft Sentinel detections"}
    for name, category in dashboard_data.source_catalog():
        if name in detections:
            group = "Open source detection rules"
        elif name == "GitHub advisories":
            group = "GitHub advisories"
        elif category == "curated GitHub repository":
            group = "GitHub threat intel"
        elif name in ("NVD", "CISA KEV") or category.startswith("government"):
            group = "Vulnerabilities and government"
        elif "RSS/Atom feed" in category:
            group = "Research and news"
        else:
            group = "Other feeds"
        groups[group].append(name)
    options = ['<option value="">All sources</option>']
    for label, names in groups.items():
        if names:
            options.append(f'<optgroup label="{_e(label)}">')
            options.extend(f'<option value="{_e(name)}"{" selected" if name == selected else ""}>'
                           f'{_e(name)}</option>' for name in names)
            options.append('</optgroup>')
    return "".join(options)


def _pager(base, params, result):
    def link(page):
        query = "&".join(f"{k}={_url_escape(v)}" for k, v in {**params, "page": page}.items() if v not in (None, ""))
        return f"{base}?{query}"
    start = (result["page"] - 1) * result["per_page"] + 1 if result["total"] else 0
    end = min(result["total"], result["page"] * result["per_page"])
    prev_html = f'<a href="{link(result["page"] - 1)}">&larr; Previous</a>' if result["has_previous"] else "<span>&larr; Previous</span>"
    next_html = f'<a href="{link(result["page"] + 1)}">Next &rarr;</a>' if result["has_next"] else "<span>Next &rarr;</span>"
    return (f'<div class="pager">{prev_html}<span>Showing {start}&ndash;{end} of <b>{result["total"]}</b> '
            f'&middot; page {result["page"]} of {result["pages"]}</span>{next_html}</div>')


def _lead_row(item, origin="intel"):
    kev = ' <span class="badge error">KEV</span>' if item.get("kev") else ""
    fetch = item["latest_fetch"]
    fetch_badge = {"ok": "ok", "partial": "stale", "error": "error"}.get(fetch["status"], "unknown")
    fetch_html = (f'<span class="badge {fetch_badge}" title="{_e(fetch.get("detail") or "")}">{_e(fetch["status"])}</span>'
                  f'<br><small class="muted">{_fmt(fetch.get("at"))}</small>')
    url_html = _safe_href(item["source_url"], "source") if item.get("source_url") else '<small class="muted">none</small>'
    display_status = {"research_completed": "Read: no rule detail", "research_backlog": "Research needed",
                      "triaged_open": "Source needs attention", "raw_unreviewed": "Not reviewed yet",
                      "evidence_recorded": "Evidence recorded"}.get(item["queue"], item["queue"].replace("_", " "))
    return (f'<tr><td><a href="/threat?id={_url_escape(item["id"])}&from={_e(origin)}">{_e(item["id"])}</a></td>'
            f'<td>{_e(item["title"][:110])}{kev}<br><small class="muted">{_e(item["kind"])}</small></td>'
            f'<td>{_e(item.get("source_name") or "unlabeled")}<br>{url_html}</td>'
            f'<td>{_fmt(item.get("published"))}</td><td>{_fmt(item.get("collected"))}</td>'
            f'<td>{fetch_html}</td><td>{_e(display_status)}</td><td>{_e(item["rule_state"])}</td></tr>')


QUEUE_HEADINGS = {"research_backlog": "Research needed", "raw_unreviewed": "Not reviewed yet",
                  "triaged_open": "Source needs attention",
                  "research_completed": "Read: no rule detail", "evidence_recorded": "Evidence recorded"}
QUEUE_LEDES = {
    "research_backlog": ("Actionable: CISA KEV CVEs, reports citing a KEV CVE and reports with behavior leads that "
                         "still need research. Polling and <code>run_research_pass()</code> read their cited pages "
                         "automatically."),
    "triaged_open": ("Raw leads that triage looked at but could not close: not researchable, no allowlisted "
                     "source, publisher blocked or unreadable. <code>triage_status()</code> gives each reason."),
    "raw_unreviewed": ("Everything else that was collected (non-KEV CVEs, leak claims, general news). Untriaged "
                       "collection, not a research to-do list."),
    "research_completed": ("Cited sources were read automatically and none names a specific observable for a rule. "
                           "Open a lead for the evidence, missing telemetry and the exposure/patch review offer."),
}


def _queue_lede(queue, path=None):
    if queue not in QUEUE_LEDES:
        return ""
    lede = f'<p class="lede"><b>{_e(QUEUE_HEADINGS[queue])}:</b> {QUEUE_LEDES[queue]}</p>'
    if queue == "triaged_open":
        from . import research_pass
        summary = research_pass.triage_summary(path, limit=1)
        lede += '<details><summary>Why these leads are waiting</summary>' + _bullets(
            [f'{name.replace("_", " ")}: {group["count"]}. {group["meaning"]} Next: {group["next_action"]}'
             for name, group in summary["groups"].items()]) + '</details>'
    return lede


def render_leads(path=None, qs=None):
    qs = qs or {}
    params = {key: _qs_one(qs, key, "") for key in ("source", "date_from", "date_to", "date_field", "queue",
                                                    "status", "rule_state", "kind", "sort")}
    params["date_field"] = params["date_field"] or "published"
    params["sort"] = params["sort"] or "collected"
    try:
        result = workflow.list_leads(path, page=_qs_one(qs, "page", "1"), **params)
        error_html = ""
    except ValueError as exc:
        result = workflow.list_leads(path)
        error_html = f'<div class="flash err">Filter ignored: {_e(exc)}</div>'
    date_fields = [("published", "publication date"), ("collected", "collection date")]
    form = f"""<form class="filters" method="get" action="/leads">
<div><label>Threat intel source</label><select name="source">{_source_options(params["source"])}</select></div>
<div><label>Newest by</label><select name="sort">{_options([("collected", "collection date"), ("published", "publication date")], params["sort"], None)}</select></div>
<div><label>Kind</label><select name="kind">{_options([(v, v) for v in workflow.KINDS], params["kind"])}</select></div>
<details class="advanced"><summary>More filters</summary><div class="filter-inner">
<div><label>Date field</label><select name="date_field">{_options(date_fields, params["date_field"], None)}</select></div>
<div><label>From</label><input type="date" name="date_from" value="{_e(params["date_from"])}"></div>
<div><label>To</label><input type="date" name="date_to" value="{_e(params["date_to"])}"></div>
<div><label>Work stage</label><select name="queue">{_options([(v, QUEUE_HEADINGS.get(v, v)) for v in workflow.QUEUES], params["queue"])}</select></div>
<div><label>Status</label><select name="status">{_options([(v, v.replace("_", " ")) for v in workflow.STATUSES], params["status"])}</select></div>
<div><label>Rule state</label><select name="rule_state">{_options([(v, v) for v in workflow.RULE_STATES], params["rule_state"])}</select></div>
</div></details>
<div style="flex:0"><button type="submit">Apply</button></div></form>"""
    rows = "".join(_lead_row(item) for item in result["items"]) or \
        '<tr><td colspan="8"><small class="muted">No leads match these filters.</small></td></tr>'
    heading = params["source"] or QUEUE_HEADINGS.get(params["queue"]) or (
        "Research needed" if params["status"] == "research_needed" else "All leads")
    call_args = ", ".join(f"{k}='{v}'" for k, v in params.items() if v and
                          not (k == "date_field" and v == "published") and
                          not (k == "sort" and v == "collected"))
    body = f"""<h1>{_e(heading)}</h1>
<p class="lede">Collected reports and CVEs. Filter by source; a collected item is not yet a detection rule.
See <a href="/rules?state=draft">Rules</a> for reviewable drafts.</p>{_queue_lede(params["queue"], path)}{error_html}{form}
{_pager("/leads", params, result)}
<div class="table-wrap"><table><thead><tr><th>ID</th><th>Title</th><th>Source / URL</th><th>Published</th><th>Collected</th>
<th>Latest fetch</th><th>Status</th><th>Rule</th></tr></thead><tbody>{rows}</tbody></table></div>
{_pager("/leads", params, result)}
{_mcp_hint(f"list_leads({call_args})" if call_args else "list_leads()")}"""
    return _page(heading, body, active="/leads", flash=_flash_from_query(qs), path=path)


def render_rules(path=None, qs=None):
    qs = qs or {}
    state = _qs_one(qs, "state", "draft")
    if state not in ("draft", "approved", "rejected"):
        state = "draft"
    result = workflow.list_rules(path, state=state, page=_qs_one(qs, "page", "1"))
    rows = []
    for item in result["items"]:
        rule = rules.get_rule(item["id"], path)
        check = item["labeled_checks"]
        if check:
            check_html = (f'TP {check["counts"]["tp"]} / FP {check["counts"]["fp"]} / '
                          f'FN {check["counts"]["fn"]} / TN {check["counts"]["tn"]}')
            if not check["tests_current_version"]:
                check_html += ' <span class="badge stale">older version</span>'
        else:
            check_html = '<small class="muted">not tested</small>'
        formats = '<details><summary>View Sigma / KQL / SPL</summary>' + ''.join(
            f'<h3>{name}</h3><pre>{_e(rule.get(field) or "Not generated")}</pre>'
            for name, field in (("Sigma", "sigma"), ("KQL", "kql"), ("SPL", "spl"))) + '</details>'
        rows.append(f'<tr><td><a href="/threat?id={_url_escape(item["threat_id"])}&from=rules#rule-{_e(item["id"])}">{_e(item["title"])}</a>'
                    f'<br><small class="muted"><code>{_e(item["id"])}</code></small>{formats}</td>'
                    f'<td><a href="/threat?id={_url_escape(item["threat_id"])}&from=rules">{_e(item["threat_id"])}</a></td>'
                    f'<td><code>{_e(item["behavior"])}</code></td><td>{item["pattern_score"]}</td>'
                    f'<td>{check_html}</td><td>{_fmt(item["created_at"])}</td></tr>')
    tabs = "".join(f'<a class="{"active" if s == state else ""}" href="/rules?state={s}">{s}</a>'
                   for s in ("draft", "approved", "rejected"))
    title = {"draft": "Draft rules", "approved": "Approved rules", "rejected": "Rejected rules"}[state]
    env = environment.status(path)
    last_poll = poller.poll_status(path)["last_result"] or {}
    backfill = (last_poll.get("research_pass") or {}).get("stored_draft_backfill") or {}
    if backfill.get("error"):
        backfill_html = f'<p>Last automatic stored-research review failed: {_e(backfill["error"])}</p>'
    elif "leads_processed" in backfill:
        backfill_html = (f'<p>Last automatic review: {backfill["leads_processed"]} researched leads checked, '
                         f'{backfill["drafts_created"]} new unverified drafts, {backfill["gaps_total"]} gaps; '
                         f'{backfill["remaining_researched_leads"]} older researched leads remain in this pass.</p>')
    else:
        backfill_html = '<p>Stored research has not yet had an automatic draft review on this installation.</p>'
    inventory_scope = rules.inventory_declaration_status(path)
    env_text = (f'Connected: {_e(env["siem"])}; {env["assets"]} assets on file.' if env["configured"] else
                'Not connected. Configure telemetry and assets to compare coverage, test in a SIEM, and score environment risk.')
    inventory_note = (f'Rule inventory scope: {_e(inventory_scope.get("scope"))} (complete and current).'
                      if inventory_scope["complete"] and inventory_scope["recent"] else
                      'Rule inventory not connected or incomplete. Import your rules and declare the current complete scope '
                      'before claiming a behavior is uncovered.')
    empty = '<tr><td colspan="6"><small class="muted">None.</small></td></tr>'
    body = f"""<h1>{title}</h1>
<p class="lede">Drafts are suggestions to check. Approval saves a rule locally; it does not deploy it.</p>
<div class="tags">{tabs}</div>
<div class="panel">{backfill_html}<small class="muted">Each collection checks up to 20 stored research leads for source-backed rules. Open a lead to see why a pattern was skipped.</small></div>
<div class="panel"><b>Live validation and risk:</b> {env_text}<br><small class="muted">{inventory_note}</small></div>
{_pager("/rules", {"state": state}, result)}
<div class="table-wrap"><table><thead><tr><th>Rule</th><th>Lead</th><th>Behavior</th><th>Pattern score</th>
<th>Latest labeled check</th><th>Created</th></tr></thead>
<tbody>{"".join(rows) or empty}</tbody></table></div>
{_mcp_hint(f"list_rules(state='{state}')", "rule_repository_status()")}"""
    return _page(title, body, active="/rules?state=draft",
                 flash=_flash_from_query(qs), path=path)


def render_attention(path=None, qs=None):
    """A short work list, with detailed failure queues kept one click away."""
    counts = workflow.workflow_counts(path)
    pending = corroboration.list_pending(path, limit=5)
    backlog = workflow.list_leads(path, queue="research_backlog", rule_state="none", per_page=10)
    errors = workflow.source_errors(path)
    error_rows = ''.join(f'<li>{_e(a["name"])}: {_e(a.get("detail") or a["status"])}</li>'
                         for a in errors["sources"][:8])
    if not error_rows:
        error_rows = '<li>No feed fetch errors.</li>'
    body = f"""<h1>Needs attention</h1>
<p class="lede">These items could not yet become a tested detection. A missing source or telemetry is shown as a gap, not a rule.</p>
<div class="panel"><h2>Source and article failures</h2><ul class="bullets">{error_rows}</ul>
<p>{len(errors["article_fetches"])} blocked or failed article fetches; {len(errors["research_publisher_blocks"])}
publisher blocks in research. <a href="/errors">See URLs and error details</a>.</p></div>
<div class="panel"><h2>Research without a draft ({backlog['total']})</h2>
<p>Read the cited technical source, confirm measurable behavior, then propose a draft.</p>
<ul class="bullets">{''.join(f'<li><a href="/threat?id={_url_escape(i["id"])}&from=attention">{_e(i["title"][:100])}</a> '
                           f'({_e(i.get("source_name") or "source unknown")})</li>' for i in backlog["items"])
                           or '<li>None in the priority research queue.</li>'}</ul>
<a href="/leads?queue=research_backlog&rule_state=none">See all research candidates</a></div>
<div class="panel"><h2>Analyst reviews ({counts['pending_reviews']})</h2>
<p>{'Reviews are waiting for a decision.' if pending else 'No pending corroboration reviews.'}
<a href="/reviews">Open reviews</a>.</p></div>
<details><summary>Other collected items still waiting</summary><p>{counts['raw_unreviewed_leads']} not reviewed;
{counts['triaged_open']} whose cited sources need a decision; {counts['research_completed_insufficient_detail']}
read without enough detail for a rule.</p>
<p><a href="/leads?queue=raw_unreviewed">Not reviewed</a> ·
<a href="/leads?queue=triaged_open">Source decisions</a> ·
<a href="/leads?queue=research_completed">Read without rule detail</a></p></details>"""
    return _page("Needs attention", body, active="/attention", flash=_flash_from_query(qs or {}), path=path)


def _research_rows(rows):
    return "".join(f'<tr><td>{_safe_href(r["url"])}</td><td>' + ", ".join(
        f'<a href="/threat?id={_url_escape(t)}">{_e(t)}</a>' for t in sorted(set((r["leads"] or "").split(",")))
        if t) + f'</td><td>{_fmt(r["inspected_at"])}</td><td>{_e(r["detail"])}</td></tr>' for r in rows) or \
        '<tr><td colspan="4"><small class="muted">None.</small></td></tr>'


def render_errors(path=None, qs=None):
    data = workflow.source_errors(path)
    rows = "".join(f'<tr><td>{_e(a["name"])}</td><td><span class="badge {"stale" if a["status"] == "partial" else "error"}">'
                   f'{_e(a["status"])}</span></td><td>{_fmt(a["attempted_at"])}</td><td>{_e(a["detail"])}</td></tr>'
                   for a in data["sources"]) or \
        '<tr><td colspan="4"><small class="muted">No source errors in the latest fetches.</small></td></tr>'
    articles = "".join(f'<tr><td><a href="/threat?id={_url_escape(a["threat_id"])}">{_e(a["threat_id"])}</a></td>'
                       f'<td>{_safe_href(a["source_url"])}</td><td>{_e(a["status"].replace("_", " "))}</td>'
                       f'<td>{a["attempts"]}</td><td>{_e(a["last_error"])}</td></tr>'
                       for a in data["article_fetches"]) or \
        '<tr><td colspan="5"><small class="muted">None.</small></td></tr>'
    body = f"""<h1>Source errors</h1>
<p class="lede">Latest fetch outcome per source. <b>partial</b> means records were ingested but the window was
not fully covered; the next poll resumes from the recorded checkpoint. Publisher blocks are shown as reported.</p>
<div class="table-wrap"><table><thead><tr><th>Source</th><th>Status</th><th>Attempted</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<h2>Blocked or failed article fetches</h2><p class="lede">{_e(data["note"])}</p>
<div class="table-wrap"><table><thead><tr><th>Lead</th><th>URL</th><th>Status</th><th>Attempts</th><th>Last error</th></tr></thead>
<tbody>{articles}</tbody></table></div>
<h2>Research pass: publisher blocks</h2>
<div class="table-wrap"><table><thead><tr><th>URL</th><th>Leads</th><th>Checked</th><th>Detail</th></tr></thead>
<tbody>{_research_rows(data["research_publisher_blocks"])}</tbody></table></div>
<h2>Research pass: unreadable or failed pages</h2>
<p class="lede">Fetched but no readable text (usually a script-rendered page), or a network error. Open in a browser.</p>
<div class="table-wrap"><table><thead><tr><th>URL</th><th>Leads</th><th>Checked</th><th>Detail</th></tr></thead>
<tbody>{_research_rows(data["research_unreadable_pages"])}</tbody></table></div>
{_mcp_hint("source_errors()", "polling_status()")}"""
    return _page("Source errors", body, active="/errors", flash=_flash_from_query(qs or {}), path=path)


MCP_TOOL_GROUPS = (
    ("Leads and sources", ("list_sources", "list_leads", "source_errors", "polling_status", "poll_now",
                           "threat_details", "behavior_review_leads")),
    ("Per-lead progression", ("lead_progression", "run_research_pass", "research_and_propose_detection", "research_lead",
                              "research_detection_plan", "inspect_cited_report",
                              "record_observed_behavior", "inventory_status", "declare_inventory_scope")),
    ("Drafting and checks", ("draft_detection", "draft_custom_detection", "check_detection_fit",
                             "test_rule_against_samples", "review_detection_for_client")),
    ("Decisions and repository", ("workflow_counts", "list_rules", "implement_rule", "reject_draft_rule",
                                  "reopen_rejected_rule", "pending_corroboration_reviews",
                                  "approve_corroboration_review", "reject_corroboration_review",
                                  "rule_repository_status")),
)


def render_tools(path=None, qs=None):
    from . import server
    described = {name: (getattr(server, name).__doc__ or "").strip().split("\n")[0]
                 for _, names in MCP_TOOL_GROUPS for name in names if hasattr(server, name)}
    sections = "".join(f'<h2>{_e(group)}</h2><table><tbody>' + "".join(
        f'<tr><td style="width:260px"><code>{_e(name)}</code></td><td>{_e(described.get(name, ""))}</td></tr>'
        for name in names) + "</tbody></table>" for group, names in MCP_TOOL_GROUPS)
    tabs = "".join(f'<li>{_e(tab.replace("_", " ").capitalize())}: <code>{_e(call)}</code></li>'
                   for tab, call in workflow.TAB_TOOLS.items())
    body = f"""<h1>MCP tools</h1>
<p class="lede">Every dashboard view has an MCP equivalent, so Claude and this page read the same database.</p>
<h2>Tabs</h2><ul class="bullets">{tabs}</ul>{sections}"""
    return _page("MCP tools", body, active="/tools", flash=_flash_from_query(qs or {}), path=path)


# ---------------------------------------------------------------- Threat ---

def _evidence_block(evidence):
    rows = []
    for e in evidence:
        kind_label = {"source_fact": "Publisher source", "analyst_observation": "Analyst-verified behavior",
                     "reference_pointer": "Reference (unverified)"}.get(e["kind"], e["kind"])
        behavior = f' &middot; behavior: <code>{_e(e["behavior"])}</code>' if e.get("behavior") else ""
        rows.append(f'<li><b>{kind_label}</b>{behavior} &middot; observed {_fmt(e["observed_at"])}<br>'
                    f'{_safe_href(e["source_url"])}<br>'
                    f'<small class="muted">{_e(e["claim"])}</small></li>')
    return "<ul class=\"bullets\">" + "".join(rows) + "</ul>" if rows else '<p><small class="muted">No evidence recorded yet.</small></p>'


def _inventory_declaration_line(declaration):
    if not declaration.get("declared"):
        return '<p><small class="muted">No inventory scope has been declared. A "No" answer is not possible until an ' \
               'analyst declares the complete, current rule inventory (declare_inventory_scope).</small></p>'
    status = "ok" if declaration.get("complete") and declaration.get("recent") else "stale"
    return (f'<p><small class="muted">Declared inventory scope: &ldquo;{_e(declaration.get("scope"))}&rdquo; '
            f'(declared {_fmt(declaration.get("declared_at"))}, '
            f'{"complete" if declaration.get("complete") else "not marked complete"}, '
            f'<span class="badge {status}">{"usable for No" if status == "ok" else "not usable for No"}</span>)</small></p>')


def _inventory_evidence_html(evidence):
    if not evidence:
        return ""
    items = "".join(f'<li>{_safe_href(e["source_url"])} &mdash; <small class="muted">{_e(e["claim"][:160])}</small></li>'
                    for e in evidence)
    return f'<details><summary>Evidence behind this answer ({len(evidence)})</summary><ul class="bullets">{items}</ul></details>'


def _inventory_block(inventory):
    declaration_html = _inventory_declaration_line(inventory.get("inventory_scope", {"declared": False}))
    if not inventory["behaviors"]:
        return f'<p><span class="badge unknown">Unknown</span> {_e(inventory["reason"])}</p>{declaration_html}'
    items = []
    for b in inventory["behaviors"]:
        link = f' &middot; <a href="#rule-{_e(b.get("rule_id",""))}">{_e(b.get("title") or b["rule_id"])}</a>' if b.get("rule_id") else ""
        note = f' &mdash; <small class="muted">{_e(b["note"])}</small>' if b.get("note") else ""
        scope = f'<br><small class="muted">{_e(b["scope"])}</small>' if b.get("scope") else ""
        evidence = _inventory_evidence_html(b.get("evidence"))
        items.append(f'<li><span class="badge {b["status"]}">{b["status"].upper()}</span> '
                     f'<code>{_e(b["behavior"])}</code>{link}{note}{scope}{evidence}</li>')
    return "<ul class=\"bullets\">" + "".join(items) + "</ul>" + declaration_html


def _bullets(items):
    return "<ul class=\"bullets\">" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>" if items else '<p><small class="muted">None.</small></p>'


def _framework_block(framework_context):
    if not framework_context:
        return '<p><small class="muted">No analyst-verified behavior yet, so no framework mapping is shown.</small></p>'
    parts = []
    for behavior, ctx in framework_context.items():
        parts.append(f"<h3>{_e(behavior)}</h3>")
        for fw_name, label in (("attack", "MITRE ATT&CK"), ("atlas", "MITRE ATLAS"), ("owasp", "OWASP LLM Top 10")):
            state = ctx["frameworks"].get(fw_name, {"status": "unavailable"})
            if state["status"] == "unavailable":
                parts.append(f'<p><b>{label}:</b> <span class="badge unknown">Unavailable/stale</span> not yet retrieved.</p>')
                continue
            status_badge = "ok" if state["status"] == "current" else "stale"
            parts.append(f'<p><b>{label}:</b> version {_e(state["version"])}, retrieved {_fmt(state["fetched_at"])} '
                        f'<span class="badge {status_badge}">{"Unavailable/stale" if status_badge == "stale" else "current"}</span></p>')
            matches = ctx["mappings"].get(fw_name, [])
            for m in matches:
                if "status" in m:
                    parts.append(f'<p><small class="muted">{_e(m["id"])}: not present in the current retrieved release.</small></p>')
                else:
                    link = _safe_href(m["url"], m["id"]) if m.get("url") else f'<code>{_e(m["id"])}</code>'
                    parts.append(f'<p>{link} {_e(m["name"])} &mdash; <small class="muted">{_e(m["relationship"])}</small></p>')
    return "".join(parts)


def _rule_card(rule, threat_id, path=None):
    validation = rule.get("validation", "")
    fit = None
    try:
        fit = environment.check_rule_fit(rule["id"], path)
    except (ValueError, KeyError):
        fit = None
    fit_html = ""
    if fit is not None:
        ready_badge = "ok" if fit.get("ready") else "warn"
        fit_html = (f'<p><b>Telemetry fit:</b> <span class="badge {"ok" if fit.get("ready") else "stale"}">'
                    f'{"ready" if fit.get("ready") else "not ready"}</span> '
                    f'{_e(fit.get("reason") or fit.get("validation") or "")}</p>')
    status = rule["status"]
    check = workflow.latest_check(rule["id"], path)
    if check:
        check_html = (f'<p><b>Labeled check:</b> TP {check["counts"]["tp"]} / FP {check["counts"]["fp"]} / '
                      f'FN {check["counts"]["fn"]} / TN {check["counts"]["tn"]} on {check["sample_size"]} events '
                      f'({_e(check["sample_source"])}, {_fmt(check["tested_at"])})'
                      + ('' if check["tests_current_version"] else ' <span class="badge stale">tested an older version</span>')
                      + '</p>')
    else:
        check_html = '<p class="missing">No labeled check has been run on this rule version.</p>'
    check_form = "" if status == "rejected" else (
        f'<details><summary>Run labeled check</summary><form method="post" action="/rule/check">'
        f'{_hidden(id=rule["id"], threat_id=threat_id)}'
        f'<label>Labeled events (JSONL: event_id, event_type, timestamp, scenario, expected_malicious, fields)</label>'
        f'<textarea name="events" required style="min-height:120px"></textarea>'
        f'<p><button class="secondary" type="submit">Replay against this rule</button></p></form></details>')
    reject_reason = f'<p><small class="muted">Rejected: {_e(rule.get("rejected_reason"))} ({_fmt(rule.get("rejected_at"))})</small></p>' if status == "rejected" else ""
    actions = ""
    if status == "draft":
        actions = (f'<form class="inline" method="post" action="/rule/approve">'
                   f'<input type="hidden" name="id" value="{_e(rule["id"])}">'
                   f'<input type="hidden" name="threat_id" value="{_e(threat_id)}">'
                   f'<button type="submit">Approve and add to rule repository</button></form> '
                   + ('' if check and check["tests_current_version"] else
                      '<small class="missing">Approving without a labeled check on this version. </small>') +
                   f'<form class="inline" method="post" action="/rule/reject">'
                   f'<input type="hidden" name="id" value="{_e(rule["id"])}">'
                   f'<input type="hidden" name="threat_id" value="{_e(threat_id)}">'
                   f'<input type="text" name="reason" placeholder="Rejection reason" required style="width:220px;display:inline-block">'
                   f'<button class="danger" type="submit">Reject</button></form>')
    elif status == "rejected":
        actions = (f'<form class="inline" method="post" action="/rule/reopen">'
                   f'<input type="hidden" name="id" value="{_e(rule["id"])}">'
                   f'<input type="hidden" name="threat_id" value="{_e(threat_id)}">'
                   f'<button class="secondary" type="submit">Reopen for later review</button></form>')
    else:
        actions = '<span class="badge ok">Approved &mdash; not deployed to any SIEM</span>'
    return f"""<div class="panel" id="rule-{_e(rule['id'])}">
<div style="display:flex;justify-content:space-between"><b>{_e(rule['title'])}</b>
<span class="badge {'ok' if status=='approved' else 'error' if status=='rejected' else 'stale'}">{status}</span></div>
<p><small class="muted">Behavior: <code>{_e(rule['behavior'])}</code> &middot; telemetry: {_e(rule.get('telemetry',''))}</small></p>
<p>{_e(rule.get('rationale',''))}</p>{reject_reason}{fit_html}{check_html}
<p><small class="muted">{_e(validation)}</small></p>
<details><summary>Full draft (Sigma / KQL / SPL)</summary>
<h3>Sigma</h3><pre>{_e(rule.get('sigma',''))}</pre>
<h3>KQL</h3><pre>{_e(rule.get('kql',''))}</pre>
<h3>SPL</h3><pre>{_e(rule.get('spl',''))}</pre></details>
{check_form}<p>{actions}</p></div>"""


STEP_BADGE = {"done": "ok", "current": "stale", "attention": "stale", "blocked": "unknown"}


def _hidden(**fields):
    return "".join(f'<input type="hidden" name="{_e(k)}" value="{_e(v)}">' for k, v in fields.items())


def _research_html(research):
    pages = "".join(
        f'<li>{_safe_href(pg["url"])} <small class="muted">({_e(pg["role"].replace("_", " "))})</small> '
        f'<span class="badge {RESEARCH_PAGE_BADGE.get(pg["status"], "unknown")}">{_e(pg["status"].replace("_", " "))}</span>'
        f' <small class="muted">{_e(pg["inspected_at"])}</small>'
        + (f'<br><small class="muted">{_e(pg["detail"])}</small>' if pg.get("detail") else "") + "</li>"
        for pg in research.get("pages") or [])
    evidence = "".join(f'<li>{_safe_href(e["url"])} &para;{e["paragraph"]}<br><small class="muted">'
                       f'{_e(e["excerpt"][:420])}</small></li>' for e in research.get("evidence") or [])
    parts = [f'<details open><summary>Pages inspected by the research pass ({len(research.get("pages") or [])})</summary>'
             f'<ul class="bullets">{pages}</ul></details>']
    if evidence:
        parts.append(f'<details><summary>Cited excerpts ({len(research["evidence"])}); untrusted source text</summary>'
                     f'<ul class="bullets">{evidence}</ul></details>')
    quoted = research.get("specific_details_to_verify") or []
    if quoted:
        parts.append(f'<details open><summary>Quoted claims to verify in the original publication ({len(quoted)}); '
                     'not indicators</summary><ul class="bullets">' + "".join(
                         f'<li>{_safe_href(d["url"])} &para;{d["paragraph"]}<br><small class="muted">'
                         f'{_e(d["excerpt"][:700])}</small></li>' for d in quoted) + "</ul></details>")
    if research.get("missing_telemetry"):
        parts.append("<p><b>Missing telemetry:</b></p>" + _bullets(research["missing_telemetry"]))
    offer = research.get("exposure_patch_review")
    if offer:
        parts.append(f'<p><b>Exposure/patch review offered:</b> {_e(offer["question"])} {_e(offer["how"])} '
                     f'<small class="muted">{_e(offer["note"])}</small></p>' + _bullets(offer["checks"]))
    return "".join(parts)


RESEARCH_PAGE_BADGE = {"inspected": "ok", "publisher_blocked": "error", "unreadable": "stale", "failed": "error",
                       "not_allowlisted": "unknown"}


def _step_extra(step, prog):
    key, parts = step["key"], []
    if key == "research" and step.get("research"):
        parts.append(_research_html(step["research"]))
    if key == "research" and step.get("untrusted_article_leads"):
        parts.append("<details><summary>Unverified article excerpts to check "
                     f"({len(step['untrusted_article_leads'])})</summary><ul class=\"bullets\">" + "".join(
                         f'<li><code>{_e(l["behavior"])}</code> &middot; {_safe_href(l["source_url"])} '
                         f'&para;{l["paragraph"]}<br><small class="muted">{_e(l["excerpt"][:400])}</small></li>'
                         for l in step["untrusted_article_leads"]) + "</ul></details>")
    if key == "inventory" and step.get("existing_rules"):
        parts.append("<ul class=\"bullets\">" + "".join(
            f'<li>Existing rule <b>{_e(b.get("title") or b["rule_id"])}</b> <code>{_e(b["rule_id"])}</code> '
            f'&middot; pattern_score {b.get("pattern_score")}</li>' for b in step["existing_rules"]) + "</ul>")
        for review in step.get("pending_corroboration_reviews", []):
            parts.append(f'<p>Pending corroboration review <a href="/reviews">#{review["id"]}</a> '
                         f'({_e(review["behavior"])}, paragraph {review["paragraph"]}).</p>')
        for proposal in step.get("proposed_corroboration", []):
            parts.append(f'<form class="inline" method="post" action="/rule/corroborate">'
                         f'{_hidden(rule_id=proposal["rule_id"], evidence_id=proposal["evidence_id"], threat_id=prog["threat_id"])}'
                         f'<p><small class="muted">Proposed corroboration: evidence #{proposal["evidence_id"]} &rarr; '
                         f'<code>{_e(proposal["rule_id"])}</code>. {_e(proposal["effect"])}</small><br>'
                         f'<button class="secondary" type="submit">Approve corroboration (+1)</button></p></form>')
    if key == "candidate":
        if prog["can_draft"]:
            options = "".join(f'<option value="{eid}">evidence #{eid}</option>' for eid in prog["draftable_evidence"])
            parts.append(f'<form method="post" action="/threat/draft">{_hidden(id=prog["threat_id"])}'
                         f'<select name="evidence_id" style="width:auto;display:inline-block">{options}</select> '
                         f'<button type="submit">Research / Draft detection</button></form>')
        else:
            parts.append(f'<p class="missing">Drafting unavailable: {_e(prog["draft_blocked_reason"])}</p>')
    if key == "repository" and step.get("files"):
        parts.append("<ul class=\"bullets\">" + "".join(
            f'<li><code>{_e(f["path"])}</code>{"" if f["exists"] else " (not written yet)"}</li>'
            for f in step["files"].values()) + "</ul>")
    return "".join(parts)


def _progression_html(prog):
    items = []
    for step in prog["steps"]:
        missing = f'<p class="missing">Missing: {_e(step["missing"])}</p>' if step.get("missing") else ""
        items.append(f'<li class="{step["state"]}"><b>{_e(step["title"])}</b> '
                     f'<span class="badge {STEP_BADGE.get(step["state"], "unknown")}">{_e(step["state"])}</span>'
                     f'<br><small class="muted">{_e(step["summary"])}</small>{missing}{_step_extra(step, prog)}</li>')
    action = f'<p><b>Next action:</b> {_e(prog["next_action"])}</p>' if prog.get("next_action") else ""
    return f'{action}<ol class="steps">{"".join(items)}</ol>'


def _workup_html(w):
    """Render lead_workup exactly; the MCP tool returns the same dict."""
    parts = [f'<p><b>Next analyst decision:</b> {_e(w["next_analyst_decision"])}</p>',
             f'<p><b>Source:</b> {_e(w["source"]["name"])} {_safe_href(w["source"]["url"]) if w["source"]["url"] else ""}'
             f' &middot; <b>Published:</b> {_fmt(w["published"])} &middot; <b>Collected:</b> {_fmt(w["collected"])}</p>']
    if w["research"].get("needs_extraction_refresh"):
        parts.append(f'<p class="missing">Stored research used an older extractor. Refresh it with '
                     f'<code>{_e(w["research"]["refresh_action"])}</code> before relying on missing findings.</p>')
    for hunt in w["research"].get("publisher_hunting_queries", [])[:8]:
        parts.append(f'<details><summary>Publisher {_e(hunt["language"].upper())} hunt '
                     f'<span class="badge stale">unverified</span> {_safe_href(hunt["source_url"])}</summary>'
                     f'<pre>{_e(hunt["text"][:6000])}</pre><p>{_e(hunt["note"])}</p></details>')
    for capture in w.get("browser_captures", [])[:5]:
        parts.append(f'<details><summary>Browser capture #{capture["id"]} '
                     f'<span class="badge stale">unverified</span> {_safe_href(capture["url"])}</summary>'
                     f'<p>Captured {_fmt(capture["captured_at"])}; {capture["paragraphs_scanned"]} paragraphs. '
                     'This is browser-supplied text, not analyst verification.</p>'
                     + _bullets([str(d.get("excerpt") or d.get("text") or d)[:500]
                                 for d in capture["specific_details_to_verify"][:5]])
                     + "".join(f'<p>Publisher {_e(h["language"].upper())} hunt (unverified):</p>'
                               f'<pre>{_e(h["text"][:6000])}</pre>'
                               for h in capture.get("publisher_hunting_queries", [])[:4]) + '</details>')
    patterns = w["pattern_analysis"]["patterns"]
    if not patterns:
        parts.append(f'<p class="missing">No pattern: {_e(w["pattern_analysis"].get("reason") or "no specific artifact in inspected text")}</p>')
    for item in patterns[:10]:
        artifacts = (item["observable"].get("artifacts") or [])
        why = item["why_malicious_per_source"]
        parts.append(
            f'<details><summary>{_safe_href(item["source_url"])} &para;{item["paragraph"]} '
            f'<span class="badge stale">{_e(item["status"])}</span></summary>'
            f'<p><small class="muted">Published {_fmt(item["published"])} &middot; collected {_fmt(item["collected"])} '
            f'&middot; inspected {_fmt(item["inspected_at"])}</small></p>'
            f'<blockquote>{_e(item["quoted_paragraph"][:1500])}</blockquote>'
            + _bullets([f'{a["value"]} ({a["kind"]}): {a["sufficiency"]}' for a in artifacts]
                       or [f'Lexical behavior: {item["observable"].get("lexical_behavior")}'])
            + f'<p><b>Why the source calls it malicious:</b> {_e(why["explanation"])}</p>'
            + _bullets([f'“{sentence}”' for sentence in why["publisher_statements"]])
            + f'<p><small class="muted">{_e(item["claim_scope"])}</small></p></details>')
    inv = w["inventory"]
    parts.append(f'<p><b>Inventory:</b> {_e(inv["answer"])} &middot; {_e(inv["connection"]["status"])} '
                 f'({_e(inv["connection"]["imported_rules"])} imported, '
                 f'{_e(inv["connection"]["local_approved_rules"])} approved local) &middot; <small class="muted">'
                 f'{_e((inv.get("scope") or {}).get("reason") or (inv.get("scope") or {}).get("scope") or "")}</small></p>')
    for draft in w["drafts"]:
        queries = draft["queries"]
        checks = draft["labeled_checks"]
        support = draft.get("supporting_text")
        parts.append(
            f'<h3>Draft {_e(draft["title"])} <code>{_e(draft["rule_id"])}</code></h3>'
            f'<p>Status <b>{_e(draft["status"])}</b> &middot; source verification <b>{_e(draft["source_verification"])}</b>'
            f' &middot; pattern_score {draft["pattern_score"]}</p>'
            f'<p><b>Required fields:</b> {_e(", ".join(draft["required_fields"] or []))}<br>'
            f'<small class="muted">{_e(draft["telemetry_requirements"])}</small></p>'
            f'<pre>{_e(draft["sigma"])}</pre>'
            + (f'<p><b>Supporting paragraph {support["paragraph"]}:</b> {_safe_href(support["url"])}</p>'
               f'<blockquote>{_e(support["quoted_text"][:1500])}</blockquote>'
               + _bullets([f'{p["predicate"]["field"]} {p["predicate"]["operator"]} '
                           f'{p["predicate"]["value"]}: source says {p["source_value"]}; {p["interpretation"]}'
                           for p in support["predicates"]])
               + f'<p><b>Why suspicious:</b> {_e(support["why_malicious_per_source"]["explanation"])}</p>'
               if support else '')
            + (f'<p><b>Mapped {_e(queries["siem"])} query:</b></p><pre>{_e(queries["query"])}</pre>'
               if queries.get("query") else
               '<p><b>SIEM field mapping:</b> not connected or incomplete; templates need mapping and testing.</p>')
            + (f'<p><b>Generic KQL template:</b></p><pre>{_e(queries["templates"]["kql"])}</pre>'
               f'<p><b>Generic SPL template:</b></p><pre>{_e(queries["templates"]["spl"])}</pre>'
               if queries.get("templates") else '')
            + f'<p><small class="muted">{_e((queries.get("templates") or {}).get("validation") or "")}</small></p>'
            +
            f'<p><b>Labeled checks:</b> {_e(checks.get("detail") if checks.get("status") == "not run" else checks.get("counts"))}'
            f' &middot; <b>Native SIEM test:</b> {_e(queries["native_test"]["status"])}</p>'
            + '<h3>Review path</h3><ol class="steps">' + "".join(
                f'<li class="{_e(step["state"])}"><b>{_e(step["title"])}</b> '
                f'<span class="badge {STEP_BADGE.get(step["state"], "unknown")}">{_e(step["state"])}</span>'
                f'<br><small class="muted">{_e(step["detail"])}</small>'
                + (f'<p class="missing">Needs from you: {_e(step["needs_from_analyst"])}</p>'
                   if step["needs_from_analyst"] and step["state"] != "done" else "") + "</li>"
                for step in draft.get("review_path", [])) + "</ol>")
    for review in w.get("manual_source_reviews", []):
        parts.append(f'<p><b>Manual source review #{review["id"]}</b> ({_e(review["provenance"])}, '
                     f'{_e(review["retrieved_via"])}, decision {_e(review["decision"])}) {_safe_href(review["url"])}'
                     f'<br><small class="muted">{_e(review["quoted_text"][:600])}</small></p>')
    if w["drafting_blocker"]:
        parts.append(f'<p class="missing">Drafting: {_e(w["drafting_blocker"])}</p>')
    risk = w["risk"]
    env = risk["environment_risk"]
    parts.append('<h3>Risk (three separate measures)</h3>'
                 + f'<p><b>Asset inventory:</b> {_e(env["connection"]["status"])} '
                   f'({_e(env["connection"]["asset_count"])} assets); '
                   f'local context recorded: {_e(env["connection"]["local_context_recorded"])}</p>'
                 + (f'<p><b>Environment risk:</b> {env["score"]}/100</p>'
                    + _bullets([f"{k}: {v}" for k, v in env["components"].items()])
                    if env["score"] is not None else
                    '<p><b>Environment risk:</b> score unavailable</p>' + _bullets(env["missing_inputs"]))
                 + f'<p><b>Threat priority:</b> {_e(risk["threat_priority"]["label"])}</p>'
                 + _bullets(risk["threat_priority"]["factors"])
                 + '<p><b>pattern_score:</b> '
                 + (_e("; ".join(f'{r["title"]}: {r["pattern_score"]}' for r in risk["pattern_score"])) or "no rules")
                 + f'</p><p><small class="muted">{_e(risk["note"])}</small></p>')
    for review in w["corroboration_reviews"]:
        parts.append(f'<p>Pending corroboration review <a href="/reviews">#{review["id"]}</a> for '
                     f'<code>{_e(review["rule_id"])}</code> from {_safe_href(review["source_url"])}.</p>')
    return "".join(parts)


def render_threat(threat_id, path=None, qs=None):
    qs = qs or {}
    view = dashboard_data.threat_detail_view(threat_id, path)
    if view is None:
        return None
    t = view["threat"]
    origin = _qs_one(qs, "from", "intel")
    origin_href = {"intel": "/leads", "rules": "/rules?state=draft", "attention": "/attention"}.get(origin, "/leads")
    origin_name = {"intel": "Threat intel", "rules": "Rules", "attention": "Needs attention"}.get(origin, "Threat intel")
    active = {"intel": "/leads", "rules": "/rules?state=draft", "attention": "/attention"}.get(origin, "/leads")
    progression = workflow.lead_progression(t["id"], path)
    behaviors_available = [b for b in rules.TEMPLATES]
    evidence_options = "".join(f'<option value="{e["id"]}">#{e["id"]} ({_e(e["kind"])}{" - " + _e(e["behavior"]) if e.get("behavior") else ""})</option>'
                               for e in t["evidence"] if e["kind"] == "analyst_observation")
    risk = view["environment_risk"]
    risk_html = (f'<p><b>Environment score:</b> {risk["score"]}/100 (asset {_e(risk.get("asset_id"))})</p>'
                 + _bullets([f"{k}: {v}" for k, v in (risk.get("components") or {}).items()])
                 if risk.get("score") is not None else
                 '<p><span class="badge unknown">Score unavailable</span></p>'
                 + _bullets(risk.get("missing_inputs") or []))
    telemetry_bullets = _bullets(sorted({rules.TEMPLATES[b]["telemetry"] for b in
                                          {e["behavior"] for e in t["evidence"] if e["kind"] == "analyst_observation" and e["behavior"] in rules.TEMPLATES}}))
    fp_bullets = _bullets(["Authorized administration or application maintenance can match the same pattern; "
                            "compare against a documented change window and account context before alerting."])
    body = f"""<p><a href="{origin_href}">&larr; {origin_name}</a></p>
<h1>{_e(t['id'])} <span class="badge {'error' if t.get('kev') else 'stale'}">{_e(t['kind'])}</span></h1>
<p class="lede">{_e(t['title'])}</p>
<div class="panel"><b>At a glance:</b> {len(view['rules'])} local rule(s). Research citations describe the publisher's findings;
they do not show activity in your environment. <a href="/rules?state=draft">See all drafts</a>.</div>

<details><summary>Research and review steps</summary><div class="panel">{_progression_html(progression)}</div></details>

<h2>Pattern and proposed detection</h2>
<div class="panel">{_workup_html(workup.lead_workup(t["id"], path))}</div>
<form method="post" action="/threat/propose"><input type="hidden" name="id" value="{_e(t['id'])}">
<p><button type="submit">Check cited patterns for a draft</button>
<small class="muted">Only a source paragraph with bounded predicates can create an unverified draft.</small></p></form>

<h2>1. Source and evidence</h2>
<div class="panel">
<p><b>Publication date:</b> {_fmt(t.get('published'))} &middot; <b>Collection date:</b> {_fmt(t.get('first_seen'))}
&middot; <b>Last seen:</b> {_fmt(t.get('last_seen'))}</p>
{_evidence_block(t['evidence'])}
<h3>Still needs verification</h3>{_bullets(view['verification_needed'])}
</div>

<h2>2. Detection inventory</h2>
<div class="panel">{_inventory_block(view['inventory_status'])}</div>

<h2>3. Research and risk</h2>
<div class="panel row">
<div class="col"><h3>Affected environment / risk</h3>{risk_html}
{f'<p><small class="muted">{_e(risk.get("rule_advice",""))}</small></p>' if risk.get('rule_advice') else ''}
<h3>Required logs and fields</h3>{telemetry_bullets}
<h3>False positives</h3>{fp_bullets}</div>
<div class="col"><h3>Attacker adaptation (hypotheses)</h3>{_bullets(view['research']['possible_next_steps'])}
<h3>Framework mapping</h3>{_framework_block(view['framework_context'])}</div>
</div>

<h2>4. Analyst workspace</h2>
<div class="panel row">
<div class="col">
<form method="post" action="/threat/observation">
<input type="hidden" name="id" value="{_e(t['id'])}">
<h3>Add verified behavior + source citation</h3>
<label>Source URL (HTTPS)</label><input type="url" name="source_url" required>
<label>Claim (what the source documents)</label><textarea name="claim" required></textarea>
<label>Behavior</label><select name="behavior">{''.join(f'<option value="{b}">{b}</option>' for b in behaviors_available)}</select>
<p><button type="submit">Record observation</button></p>
</form>
<form method="post" action="/threat/draft">
<input type="hidden" name="id" value="{_e(t['id'])}">
<h3>Generate Sigma / KQL / SPL draft</h3>
<label>From evidence</label><select name="evidence_id">{evidence_options or '<option disabled selected>No analyst observation recorded yet</option>'}</select>
<p><button type="submit" {'disabled' if not evidence_options else ''}>Recheck inventory and draft</button></p>
</form>
</div>
<div class="col">
<form method="post" action="/threat/note">
<input type="hidden" name="id" value="{_e(t['id'])}">
<h3>Telemetry fields</h3><textarea name="content" placeholder="e.g. ParentImage, Image, CommandLine, User"></textarea>
<input type="hidden" name="note_type" value="telemetry_fields"><p><button type="submit">Add</button></p>
</form>
<form method="post" action="/threat/note">
<input type="hidden" name="id" value="{_e(t['id'])}">
<h3>Benign example</h3><textarea name="content" placeholder="A known-benign event this pattern would also match"></textarea>
<input type="hidden" name="note_type" value="benign_example"><p><button type="submit">Add</button></p>
</form>
<form method="post" action="/threat/note">
<input type="hidden" name="id" value="{_e(t['id'])}">
<h3>Feedback</h3><textarea name="content" placeholder="Free-form analyst notes"></textarea>
<input type="hidden" name="note_type" value="feedback"><p><button type="submit">Add</button></p>
</form>
{_workspace_notes_html(view['workspace_notes'])}
</div>
</div>

<h2>5. Approval</h2>
{''.join(_rule_card(r, t['id'], path) for r in view['rules']) or '<p><small class="muted">No draft yet. Research needed: record a verified behavior above, then generate a draft.</small></p>'}
<p><small class="muted">Approval adds a rule to this local detection repository only. It is never deployed to a SIEM.
Rejected or unfinished drafts stay stored here for later review.</small></p>
"""
    body += _mcp_hint(f"lead_progression(threat_id='{t['id']}')", f"research_detection_plan(threat_id='{t['id']}')")
    return _page(t["id"], body, active=active, flash=_flash_from_query(qs), path=path)


def _workspace_notes_html(notes):
    if not notes:
        return '<p><small class="muted">No workspace notes yet.</small></p>'
    labels = {"telemetry_fields": "Telemetry fields", "benign_example": "Benign example", "feedback": "Feedback"}
    return "<h3>Recorded notes</h3><ul class=\"bullets\">" + "".join(
        f'<li><b>{_e(labels.get(n["note_type"], n["note_type"]))}</b> ({_fmt(n["created_at"])}): {_e(n["content"])}</li>'
        for n in notes) + "</ul>"


# --------------------------------------------------------------- Reviews --

def _review_card(review):
    return f"""<div class="panel">
<div style="display:flex;justify-content:space-between"><b>{_e(review['rule_title'] or review['rule_id'])}</b>
<span class="badge stale">pending</span></div>
<p><small class="muted">Matched rule: <code>{_e(review['rule_id'])}</code> ({_e(review['rule_kind'])}) &middot;
current status: {_e(review['rule_current_status'])} &middot;
current pattern_score: {review['current_pattern_score']} &middot;
proposed if approved: <b>{review['proposed_pattern_score']}</b></small></p>
<p><b>New behavior:</b> <code>{_e(review['behavior'])}</code> &middot; from threat
<a href="/threat?id={_e(review['threat_id'])}">{_e(review['threat_id'])}</a>, paragraph {review['paragraph']}</p>
<p>{_safe_href(review['source_url'])}</p>
<p><small class="muted">{_e(review['excerpt'])}</small></p>
<p><small class="muted">{_e(review['match_confidence'])}</small></p>
<p><small class="muted">{_e(review['note'])}</small></p>
<form class="inline" method="post" action="/review/approve">
<input type="hidden" name="review_id" value="{review['id']}">
<button type="submit">Approve (+1 pattern_score)</button></form>
<form class="inline" method="post" action="/review/reject">
<input type="hidden" name="review_id" value="{review['id']}">
<input type="text" name="reason" placeholder="Rejection reason" required style="width:220px;display:inline-block">
<button class="danger" type="submit">Reject</button></form>
</div>"""


def render_reviews(path=None, qs=None):
    pending = corroboration.list_pending(path, limit=50)
    body = f"""<h1>Corroboration reviews</h1>
<p class="lede">Newly collected, cited article leads that lexically match an existing rule's behavior. Nothing here
was attached or scored automatically -- approving links the cited evidence and adds exactly +1 to pattern_score;
rejecting leaves the rule, its evidence, and its score completely unchanged. A repeated poll, retry, or a second
review citing the same source can never increment the same rule twice.</p>
{''.join(_review_card(r) for r in pending) or '<p><small class="muted">No pending corroboration reviews.</small></p>'}
{_mcp_hint("pending_corroboration_reviews()", "approve_corroboration_review(review_id, 'implement this rule')")}"""
    return _page("Corroboration reviews", body, active="/reviews", flash=_flash_from_query(qs or {}), path=path)


# ------------------------------------------------------------- Handlers ---

class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatResearchDashboard/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # Avoid noisy stderr logging for a local analyst tool.

    def _db_path(self):
        return getattr(self.server, "db_path", None)

    def _collection_status(self, path):
        with self.server.collection_lock:
            local = dict(self.server.collection_state)
        recorded = poller.poll_status(path)
        if local["running"] or recorded["running"]:
            return {"running": True, "status": "running"}
        result = local["result"] if local["result"] and local["result"].get("status") != "already_running" else None
        latest = recorded["last_result"] or {}
        if not result or (result.get("completed") and latest.get("completed") and
                          latest["completed"] > result["completed"]):
            result = latest
        return {"running": False, "status": result.get("status", "unknown"),
                "new_records": result.get("new_records", 0), "error": result.get("error")}

    def _start_collection(self, path):
        with self.server.collection_lock:
            if self.server.collection_state["running"] or poller.poll_status(path)["running"]:
                return False
            self.server.collection_state = {"running": True, "result": None}

            def collect():
                try:
                    result = poller.run_poll(path)
                except Exception as exc:  # noqa: BLE001 - retain an actionable status for the page
                    result = {"status": "failed", "error": str(exc)[:300]}
                    print(json.dumps({"dashboard_collection": result}), flush=True)
                with self.server.collection_lock:
                    self.server.collection_state = {"running": False, "result": result}

            threading.Thread(target=collect, daemon=True, name="dashboard-collection").start()
            return True

    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location, flash=None, ok=True):
        if flash:
            sep = "&" if "?" in location else "?"
            location = f"{location}{sep}flash={_url_escape(flash)}&ok={'1' if ok else '0'}"
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _not_found(self):
        self._send(404, _page("Not found", "<h1>Not found</h1>", path=self._db_path()))

    def do_GET(self):
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        path = self._db_path()
        try:
            if parsed.path == "/":
                self._send(200, render_sources(path, qs))
            elif parsed.path == "/source":
                # Older links: /source?name=X is the leads list filtered to that source.
                self._send(200, render_leads(path, {**qs, "source": qs.get("name") or [""]}))
            elif parsed.path in ("/leads", "/threats"):
                self._send(200, render_leads(path, qs))
            elif parsed.path == "/rules":
                self._send(200, render_rules(path, qs))
            elif parsed.path == "/attention":
                self._send(200, render_attention(path, qs))
            elif parsed.path == "/errors":
                self._send(200, render_errors(path, qs))
            elif parsed.path == "/tools":
                self._send(200, render_tools(path, qs))
            elif parsed.path == "/reviews":
                self._send(200, render_reviews(path, qs))
            elif parsed.path == "/threat":
                ident = (qs.get("id") or [""])[0]
                out = render_threat(ident, path, qs)
                self._send(200, out) if out else self._not_found()
            elif parsed.path == "/api/sources":
                self._send(200, json.dumps(dashboard_data.sources_overview(path)), "application/json")
            elif parsed.path == "/api/collection":
                self._send(200, json.dumps(self._collection_status(path)), "application/json")
            elif parsed.path == "/api/threat":
                ident = (qs.get("id") or [""])[0]
                view = dashboard_data.threat_detail_view(ident, path)
                self._send(200, json.dumps(view, default=str) if view else json.dumps({"error": "unknown threat"}),
                           "application/json")
            elif parsed.path == "/api/leads":
                args = {k: v[0] for k, v in qs.items() if k in ("source", "date_from", "date_to", "date_field",
                                                                 "queue", "status", "rule_state", "kind", "page", "sort")}
                self._send(200, json.dumps(workflow.list_leads(path, **args), default=str), "application/json")
            elif parsed.path == "/api/progression":
                ident = (qs.get("id") or [""])[0]
                self._send(200, json.dumps(workflow.lead_progression(ident, path), default=str), "application/json")
            elif parsed.path == "/api/counts":
                self._send(200, json.dumps(workflow.workflow_counts(path)), "application/json")
            elif parsed.path == "/healthz":
                self._send(200, "ok", "text/plain")
            else:
                self._not_found()
        except Exception as exc:  # noqa: BLE001 - surface to the analyst, never a bare 500 with no context
            self._send(500, _page("Error", f'<h1>Error</h1><p>{_e(str(exc)[:400])}</p>', path=self._db_path()))

    def _same_origin(self):
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True  # Non-browser clients (tests, curl) send no Origin.
        host = self.headers.get("Host", "")
        parsed = urlsplit(origin)
        return parsed.scheme in ("http", "https") and parsed.netloc == host

    def do_POST(self):
        parsed = urlsplit(self.path)
        if not self._same_origin():
            self._send(403, "cross-origin form post refused", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 200_000:
            self._send(413, "form too large", "text/plain")
            return
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        path = self._db_path()
        try:
            self._handle_post(parsed.path, form, path)
        except ValueError as exc:
            if parsed.path.startswith("/review/"):
                self._redirect("/reviews", flash=f"Not applied: {str(exc)[:300]}", ok=False)
                return
            back = form.get("threat_id") or form.get("id") or ""
            target = f"/threat?id={_url_escape(back)}" if back else "/"
            self._redirect(target, flash=f"Research needed: {str(exc)[:300]}", ok=False)
        except Exception as exc:  # noqa: BLE001
            self._redirect("/", flash=f"Unexpected error: {str(exc)[:300]}", ok=False)

    def _handle_post(self, route, form, path):
        if route == "/collect-now":
            started = self._start_collection(path)
            self._redirect("/?collecting=1", flash="Collection started." if started else "Collection already running.")
        elif route == "/threat/observation":
            ident = form["id"]
            core.add_behavior_evidence(ident, form["source_url"], form["claim"], form["behavior"], path)
            self._redirect(f"/threat?id={_url_escape(ident)}", flash="Observation recorded.")
        elif route == "/threat/note":
            ident = form["id"]
            dashboard_data.add_workspace_note(ident, form["note_type"], form["content"], path)
            self._redirect(f"/threat?id={_url_escape(ident)}", flash="Note added.")
        elif route == "/threat/draft":
            ident = form["id"]
            result = rules.propose_rule(ident, int(form["evidence_id"]), path)
            self._redirect(f"/threat?id={_url_escape(ident)}", flash=f"Draft status: {result['status']}.")
        elif route == "/threat/propose":
            ident = form["id"]
            result = proposal_pass.propose_from_stored(ident, path)
            created = [p for p in result["proposals"] if p["status"] == "draft_unverified"]
            message = (f"Created {len(created)} unverified draft(s); see Rules."
                       if created else "No new draft: " + (result["gaps"][0]["reason"] if result["gaps"] else
                                                    "no sufficiently specific cited pattern was found."))
            self._redirect(f"/threat?id={_url_escape(ident)}&from=intel", flash=message)
        elif route == "/rule/approve":
            result = rules.implement_rule(form["id"], "implement this rule", path=path)
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}",
                          flash=f"{result['status']}; deployment: {result.get('deployment','not_deployed')}.")
        elif route == "/rule/check":
            raw = form.get("events", "").strip()
            if not raw:
                raise ValueError("paste at least one labeled JSONL event")
            with tempfile.TemporaryDirectory(prefix="threat-research-check-") as folder:
                events = Path(folder) / "labeled-events.jsonl"
                events.write_text(raw.replace("\r\n", "\n") + "\n", encoding="utf-8")
                label = "dashboard-pasted:" + hashlib.sha256(raw.encode()).hexdigest()[:16]
                result = soc_replay.test_rule_against_samples(form["id"], events, path, sample_label=label)
            counts = result["counts"]
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}",
                           flash=f"Labeled check: TP {counts['tp']} / FP {counts['fp']} / FN {counts['fn']} / TN {counts['tn']} "
                                 f"on {result['sample_size']} events; nothing was approved or deployed.")
        elif route == "/rule/corroborate":
            # Corroboration only links evidence (+1); it never changes a rule's approval status.
            result = (rules.corroborate_local_rule(form["rule_id"], int(form["evidence_id"]), path)
                      if rules.get_rule(form["rule_id"], path) else
                      rules.acknowledge_existing(form["rule_id"], int(form["evidence_id"]), "implement this rule", path))
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}",
                           flash=f"Corroboration: {result['status']}; pattern_score {result.get('pattern_score')}.")
        elif route == "/rule/reject":
            rules.reject_rule(form["id"], form["reason"], path)
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}", flash="Draft rejected and kept for later review.")
        elif route == "/rule/reopen":
            rules.reopen_rule(form["id"], path)
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}", flash="Draft reopened.")
        elif route == "/review/approve":
            result = corroboration.approve(int(form["review_id"]), "implement this rule", path)
            self._redirect("/reviews", flash=f"Approved; pattern_score now {result.get('pattern_score')}.")
        elif route == "/review/reject":
            corroboration.reject(int(form["review_id"]), form["reason"], path)
            self._redirect("/reviews", flash="Review rejected; rule unchanged.")
        else:
            self._not_found()


def _url_escape(value):
    from urllib.parse import quote
    return quote(str(value), safe="")


def _auto_refresh_loop(path, stop_event, interval_seconds):
    try:
        print(json.dumps(poller.run_poll(path)), flush=True)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "initial_collect_failed", "error": str(exc)[:300]}), flush=True)
    while not stop_event.wait(interval_seconds):
        try:
            print(json.dumps(poller.run_poll(path)), flush=True)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"status": "poll_failed", "error": str(exc)[:300]}), flush=True)


def serve(host=None, port=None, path: Path | None = None, auto_refresh=None, block=True):
    """Start the dashboard. By default this also refreshes collection once
    at startup and then once every 24h (DASHBOARD_REFRESH_SECONDS overrides
    the interval; auto_refresh=False or DASHBOARD_AUTO_REFRESH=false disables
    it entirely, e.g. when `threat-research serve-live` already polls)."""
    store.initialize(path)
    host = host or os.environ.get("DASHBOARD_HOST", DEFAULT_HOST)
    # port=0 (ephemeral, used by tests) is falsy but explicit, so it must be
    # distinguished from "not provided" rather than falling through to the
    # environment/default via `or`.
    port = int(os.environ.get("DASHBOARD_PORT", DEFAULT_PORT)) if port is None else int(port)
    if auto_refresh is None:
        auto_refresh = os.environ.get("DASHBOARD_AUTO_REFRESH", "true").lower() != "false"
    server = ThreadingHTTPServer((host, port), Handler)
    server.db_path = path
    server.collection_lock = threading.Lock()
    server.collection_state = {"running": False, "result": None}
    stop_event = threading.Event()
    thread = None
    if auto_refresh:
        interval = int(os.environ.get(REFRESH_SECONDS, str(24 * 3600)))
        thread = threading.Thread(target=_auto_refresh_loop, args=(path, stop_event, interval), daemon=True)
        thread.start()
    if not block:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        return server, stop_event
    try:
        print(f"Threat Research Dashboard: http://{host}:{port}/", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
    return server, stop_event


def stop(server, stop_event):
    """Cleanly stop a server started with block=False (used by tests)."""
    stop_event.set()
    server.shutdown()
    server.server_close()


def main():
    serve()


if __name__ == "__main__":
    main()
