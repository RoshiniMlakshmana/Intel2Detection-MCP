"""Daily run with timezone-aware, once-per-local-day delivery."""

import os
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from . import environment, lead_queue, store
from .core import collect_daily, list_emerging, list_threats, now


def render_digest(threats, result, local_day, confirmed_counts=None, stale=False, claim_matches=None, leads=None):
    confirmed_counts = confirmed_counts or {}
    claim_matches = claim_matches or {}
    lines = [f"Threat research digest — {local_day}", "", f"New records: {result['new_records']}"]
    lines += [f"{source}: {count} records checked" for source, count in result["sources"].items()]
    if result["errors"]:
        lines += ["", "Source failures (digest may be incomplete):"]
        lines += [f"- {source}: {error}" for source, error in result["errors"].items()]
    if stale:
        lines += ["", "Asset snapshot is older than seven days; refresh it before trusting environment priority."]
    lines += ["", "Emerging threats and priority vulnerability research:"]
    if not threats:
        lines.append("No matching records in the current window. Check source health above.")
    for t in threats:
        context = (f"ThreatFox C2; confidence {t['confidence']}/100; expires {t['expires_at']}"
                   if t["kind"] == "ioc" else
                   "Unverified leak-site claim; verify entity and source" if t["kind"] == "leak_claim" else
                   "Community rule update; inspect diff and license" if t["kind"] == "community_rule" else
                   "GitHub research update; inspect diff and report" if t["kind"] == "research_update" else
                   "Research report; behavior needs review" if t["kind"] == "campaign" else
                   f"{'CISA KEV; ' if t['kev'] else ''}EPSS {t['epss'] if t['epss'] is not None else 'unknown'}")
        if confirmed_counts.get(t["id"]):
            context = f"{confirmed_counts[t['id']]} confirmed affected asset(s); " + context
        if claim_matches.get(t["id"]) in ("verify_organization_identity", "verify_supplier_identity"):
            context = "Possible name match; " + context
        lines += [f"- {t['id']} | {context} | {t['title'][:100]}",
                  f"  {t['sources'][0] if t['sources'] else 'source unavailable'}"]
    if leads:
        lines += ["", "Recent article behavior leads awaiting analyst review:"]
        for lead in leads[:5]:
            lines += [f"- {lead['threat_id']} | {lead['behavior']} | unverified article text",
                      f"  {lead['source_url']}"]
    lines += ["", "Rules require a cited observed behavior and available telemetry. A CVE description alone is not an exploit detection.",
              "Ask Claude for the source evidence, environment risk, and separate speculative next steps before approving a rule."]
    return "\n".join(lines) + "\n"


def send_email(body, subject, address):
    host = os.environ.get("SMTP_HOST", "")
    if not address or not host:
        return False
    sender = os.environ.get("SMTP_FROM", address)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = address
    message.set_content(body)
    port = int(os.environ.get("SMTP_PORT", "465"))
    if port == 465:
        client = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=20)
    with client:
        if port != 465:
            client.starttls(context=ssl.create_default_context())
        if os.environ.get("SMTP_USER"):
            client.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        client.send_message(message)
    return True


def _send_email(body, day):
    return send_email(body, f"Threat research digest — {day}", os.environ.get("DIGEST_TO", ""))


def run_daily(path: Path | None = None, collect=True):
    store.initialize(path)
    local = datetime.now(ZoneInfo(os.environ.get("DIGEST_TZ", "America/Los_Angeles")))
    day = local.date().isoformat()
    with store.connection(path) as db:
        previous = db.execute("SELECT channel FROM deliveries WHERE day=?", (day,)).fetchone()
        if previous and (previous["channel"] == "email" or not (os.environ.get("DIGEST_TO") and os.environ.get("SMTP_HOST"))):
            return {"status": "already_delivered" if previous["channel"] == "email" else "already_saved", "day": day}
    result = collect_daily(path) if collect else {"new_records": 0, "sources": {}, "errors": {}}
    environment_state = environment.status(path)
    confirmed_counts = environment.confirmed_cve_counts(path) if environment_state["configured"] else {}
    # Leak-site claims can be numerous and must not crowd out sourced behavior.
    emerging = []
    ceilings = {"leak_claim": 2, "ioc": 3, "campaign": 3, "research_update": 1, "community_rule": 1}
    emerging_candidates = list_emerging(path, 100)
    claim_matches = {item["id"]: environment.leak_claim_relevance(item["id"], path)["priority"]
                     for item in emerging_candidates if item["kind"] == "leak_claim" and environment_state["configured"]}
    claims = sorted((item for item in emerging_candidates if item["kind"] == "leak_claim"),
                    key=lambda item: ({"verify_organization_identity": 2, "verify_supplier_identity": 1}.get(
                        claim_matches.get(item["id"]), 0), item["published"] or ""), reverse=True)
    allowed_claims = {item["id"] for item in claims[:2]}
    for item in emerging_candidates:
        if item["kind"] == "leak_claim" and item["id"] not in allowed_claims:
            continue
        if ceilings.get(item["kind"], 0) and len(emerging) < 10:
            emerging.append(item)
            ceilings[item["kind"]] -= 1
    known = {item["id"] for item in emerging}
    candidates = [item for item in list_threats(path, 100, 2) if item["id"] not in known]
    candidates.sort(key=lambda item: (confirmed_counts.get(item["id"], 0), item["kev"], item["epss"] or 0), reverse=True)
    queue = emerging + candidates[:10]
    body = render_digest(queue, result, day, confirmed_counts, environment_state.get("asset_snapshot_stale", False),
                         claim_matches, lead_queue.list_leads(path, 5, days=2))
    target = (path or store.db_path()).parent / f"digest-{day}.txt"
    target.write_text(body, encoding="utf-8")
    # A configured SMTP failure raises; the run is not marked delivered and can retry.
    sent = _send_email(body, day)
    channel = "email" if sent else "local_file"
    with store.connection(path) as db:
        db.execute("INSERT INTO deliveries (day,delivered_at,channel) VALUES (?,?,?) "
                   "ON CONFLICT(day) DO UPDATE SET delivered_at=excluded.delivered_at,channel=excluded.channel",
                   (day, now(), channel))
    return {"status": "delivered" if sent else "saved_locally", "day": day, "channel": channel, "file": str(target), "collection": result}


def due_now():
    local = datetime.now(ZoneInfo(os.environ.get("DIGEST_TZ", "America/Los_Angeles")))
    hour, minute = map(int, os.environ.get("DIGEST_TIME", "08:00").split(":"))
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError("DIGEST_TIME must be HH:MM")
    return (local.hour, local.minute) >= (hour, minute)
