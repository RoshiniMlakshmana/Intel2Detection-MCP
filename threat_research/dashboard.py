"""Local analyst dashboard: a stdlib-only HTTP server over the same SQLite
store the MCP tools and CLI use. No SIEM, no external service and no new
third-party dependency is required to run it.

Every read renders data this project already collected and validated
elsewhere (core/rules/frameworks/environment); this module adds no new
collection, scoring, or mapping logic of its own. It never claims a rule was
deployed to a SIEM, and it never invents a framework mapping the retrieved
catalog does not contain.
"""

import html
import json
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import core, corroboration, custom_rules, dashboard_data, environment, poller, rules, store

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
    pending = corroboration.pending_count(path)
    reviews_label = f"Reviews ({pending})" if pending else "Reviews"
    nav_items = [("/", "Sources"), ("/threats", "All threats"), ("/reviews", reviews_label)]
    nav = "".join(f'<a href="{href}"{" style=\"color:var(--text);font-weight:700\"" if href == active else ""}>{label}</a>'
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


def _flash_from_query(qs):
    if "flash" in qs:
        return ("ok" if qs.get("ok", ["1"])[0] == "1" else "err", qs["flash"][0])
    return None


# ---------------------------------------------------------------- Sources --

def _source_card(card):
    error_html = f'<div class="err">{_e(card["error"])}</div>' if card["error"] else ""
    name_html = (f'<a class="name" href="/source?name={_e(card["name"])}">{_e(card["name"])}</a>'
                 if card["record_count"] not in (None,) else f'<span class="name">{_e(card["name"])}</span>')
    return f"""<div class="card" data-status="{card['status']}" data-category="{_e(card['category'])}">
<div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline">
{name_html}<span class="badge {card['status']}">{card['status'].replace('_',' ')}</span></div>
<small class="muted">{_e(card['category'])}</small>
<dl>
<div><span>Last successful refresh</span><span>{_fmt(card['last_success'])}</span></div>
<div><span>Latest publication</span><span>{_fmt(card['latest_publication'])}</span></div>
<div><span>Record count</span><span>{card['record_count'] if card['record_count'] is not None else '—'}</span></div>
</dl>{error_html}</div>"""


def render_sources(path=None, qs=None):
    qs = qs or {}
    data = dashboard_data.sources_overview(path)
    active_filter = (qs.get("filter") or [None])[0]
    statuses = sorted({c["status"] for c in data["sources"]})
    categories = sorted({c["category"] for c in data["sources"]})
    tags = ["all"] + statuses + categories
    cards = data["sources"]
    if active_filter and active_filter != "all":
        cards = [c for c in cards if c["status"] == active_filter or c["category"] == active_filter]
    tag_html = "".join(
        f'<a class="{"active" if (t == active_filter or (t == "all" and not active_filter)) else ""}" '
        f'href="/?filter={_e(t)}">{_e(t)}</a>' for t in tags)
    body = f"""<h1>Sources</h1>
<p class="lede">Every configured collection source, its last successful refresh, latest publication date,
a persistent record count, and any collection error from the most recent poll. Poll interval:
{data['poll_interval_minutes']} minute(s){' (currently running)' if data['poll_running'] else ''}.
Last poll completed: {_fmt(data['last_poll_completed'])}. Email alerts:
{'configured' if data['email_configured'] else 'not configured'}.</p>
<div class="tags">{tag_html}</div>
<div class="grid">{''.join(_source_card(c) for c in cards)}</div>"""
    return _page("Sources", body, active="/", flash=_flash_from_query(qs), path=path)


def _threat_row(t):
    kev = ' <span class="badge error">KEV</span>' if t.get("kev") else ""
    return (f'<tr><td><a href="/threat?id={_e(t["id"])}">{_e(t["id"])}</a></td>'
            f'<td>{_e(t["title"][:110])}{kev}</td><td>{_e(t["kind"])}</td>'
            f'<td>{_fmt(t.get("published"))}</td></tr>')


def render_source_threats(name, path=None, qs=None):
    threats = dashboard_data.threats_for_source(name, path)
    rows = "".join(_threat_row(t) for t in threats) or '<tr><td colspan="4"><small class="muted">No records collected from this source yet.</small></td></tr>'
    body = f"""<p><a href="/">&larr; Sources</a></p>
<h1>{_e(name)}</h1>
<p class="lede">{len(threats)} record(s) collected from this source, most recent first. Every row retains
its original article URL and publication date on the threat detail page.</p>
<table><thead><tr><th>ID</th><th>Title</th><th>Kind</th><th>Published</th></tr></thead>
<tbody>{rows}</tbody></table>"""
    return _page(name, body, active="/", flash=_flash_from_query(qs or {}), path=path)


def render_threats(path=None, qs=None):
    qs = qs or {}
    kind = (qs.get("kind") or [None])[0]
    threats = dashboard_data.recent_threats(path, limit=100, kind=kind)
    kinds = ["advisory", "campaign", "ioc", "leak_claim", "research_update", "community_rule"]
    tag_html = "".join(f'<a class="{"active" if k == kind else ""}" href="/threats?kind={k}">{k}</a>' for k in kinds)
    tag_html = f'<a class="{"active" if not kind else ""}" href="/threats">all</a>' + tag_html
    rows = "".join(_threat_row(t) for t in threats) or '<tr><td colspan="4"><small class="muted">No records yet.</small></td></tr>'
    body = f"""<h1>All threats</h1><div class="tags">{tag_html}</div>
<table><thead><tr><th>ID</th><th>Title</th><th>Kind</th><th>Published</th></tr></thead>
<tbody>{rows}</tbody></table>"""
    return _page("All threats", body, active="/threats", flash=_flash_from_query(qs), path=path)


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
    reject_reason = f'<p><small class="muted">Rejected: {_e(rule.get("rejected_reason"))} ({_fmt(rule.get("rejected_at"))})</small></p>' if status == "rejected" else ""
    actions = ""
    if status == "draft":
        actions = (f'<form class="inline" method="post" action="/rule/approve">'
                   f'<input type="hidden" name="id" value="{_e(rule["id"])}">'
                   f'<input type="hidden" name="threat_id" value="{_e(threat_id)}">'
                   f'<button type="submit">Approve and add to rule repository</button></form> '
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
<p>{_e(rule.get('rationale',''))}</p>{reject_reason}{fit_html}
<p><small class="muted">{_e(validation)}</small></p>
<details><summary>Full draft (Sigma / KQL / SPL)</summary>
<h3>Sigma</h3><pre>{_e(rule.get('sigma',''))}</pre>
<h3>KQL</h3><pre>{_e(rule.get('kql',''))}</pre>
<h3>SPL</h3><pre>{_e(rule.get('spl',''))}</pre></details>
<p>{actions}</p></div>"""


def render_threat(threat_id, path=None, qs=None):
    qs = qs or {}
    view = dashboard_data.threat_detail_view(threat_id, path)
    if view is None:
        return None
    t = view["threat"]
    behaviors_available = [b for b in rules.TEMPLATES]
    evidence_options = "".join(f'<option value="{e["id"]}">#{e["id"]} ({_e(e["kind"])}{" - " + _e(e["behavior"]) if e.get("behavior") else ""})</option>'
                               for e in t["evidence"] if e["kind"] == "analyst_observation")
    risk = view["environment_risk"]
    risk_html = (f'<p><b>Score:</b> {risk.get("score")} &middot; <b>Priority:</b> {_e(risk.get("priority"))}</p>'
                if risk.get("score") is not None else
                f'<p><span class="badge unknown">Unknown</span> {_e(risk.get("reason") or "Environment not configured; score cannot be asserted.")}</p>')
    telemetry_bullets = _bullets(sorted({rules.TEMPLATES[b]["telemetry"] for b in
                                          {e["behavior"] for e in t["evidence"] if e["kind"] == "analyst_observation" and e["behavior"] in rules.TEMPLATES}}))
    fp_bullets = _bullets(["Authorized administration or application maintenance can match the same pattern; "
                            "compare against a documented change window and account context before alerting."])
    body = f"""<p><a href="/">&larr; Sources</a></p>
<h1>{_e(t['id'])} <span class="badge {'error' if t.get('kev') else 'stale'}">{_e(t['kind'])}</span></h1>
<p class="lede">{_e(t['title'])}</p>

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
    return _page(t["id"], body, active="/threats", flash=_flash_from_query(qs), path=path)


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
{''.join(_review_card(r) for r in pending) or '<p><small class="muted">No pending corroboration reviews.</small></p>'}"""
    return _page("Corroboration reviews", body, active="/reviews", flash=_flash_from_query(qs or {}), path=path)


# ------------------------------------------------------------- Handlers ---

class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatResearchDashboard/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # Avoid noisy stderr logging for a local analyst tool.

    def _db_path(self):
        return getattr(self.server, "db_path", None)

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
                name = (qs.get("name") or [""])[0]
                self._send(200, render_source_threats(name, path, qs))
            elif parsed.path == "/threats":
                self._send(200, render_threats(path, qs))
            elif parsed.path == "/reviews":
                self._send(200, render_reviews(path, qs))
            elif parsed.path == "/threat":
                ident = (qs.get("id") or [""])[0]
                out = render_threat(ident, path, qs)
                self._send(200, out) if out else self._not_found()
            elif parsed.path == "/api/sources":
                self._send(200, json.dumps(dashboard_data.sources_overview(path)), "application/json")
            elif parsed.path == "/api/threat":
                ident = (qs.get("id") or [""])[0]
                view = dashboard_data.threat_detail_view(ident, path)
                self._send(200, json.dumps(view, default=str) if view else json.dumps({"error": "unknown threat"}),
                           "application/json")
            elif parsed.path == "/healthz":
                self._send(200, "ok", "text/plain")
            else:
                self._not_found()
        except Exception as exc:  # noqa: BLE001 - surface to the analyst, never a bare 500 with no context
            self._send(500, _page("Error", f'<h1>Error</h1><p>{_e(str(exc)[:400])}</p>', path=self._db_path()))

    def do_POST(self):
        parsed = urlsplit(self.path)
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
            result = poller.run_poll(path)
            self._redirect("/", flash=f"Collection run: {result.get('status', 'unknown')}", ok=result.get("status") != "failed")
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
        elif route == "/rule/approve":
            result = rules.implement_rule(form["id"], "implement this rule", path=path)
            self._redirect(f"/threat?id={_url_escape(form.get('threat_id',''))}",
                          flash=f"{result['status']}; deployment: {result.get('deployment','not_deployed')}.")
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
