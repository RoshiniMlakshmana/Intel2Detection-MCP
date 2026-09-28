"""Portable environment onboarding and cautious, read-only telemetry checks."""

import csv
import io
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import sources, store
from .core import assess_risk, get_threat, now

FAMILIES = {
    "web_server_shell": "process_creation",
    "encoded_powershell": "process_creation",
    "mcp_unauthorized_execution": "mcp_audit",
    "ioc_network": "network_connection",
}
REQUIRED_SPLUNK = {
    "web_server_shell": {"EventCode", "ParentImage", "Image", "CommandLine"},
    "encoded_powershell": {"EventCode", "Image", "CommandLine"},
    "mcp_unauthorized_execution": {"event_type", "execution_status", "authorization_decision",
                                   "principal_id", "request_id", "tool_name", "resource_scope"},
    "ioc_network": {"EventCode", "DestinationIp", "DestinationPort", "Image"},
}
REQUIRED_DEFENDER = {
    "web_server_shell": {"Timestamp", "InitiatingProcessFileName", "FileName", "ProcessCommandLine"},
    "encoded_powershell": {"Timestamp", "FileName", "ProcessCommandLine"},
    "mcp_unauthorized_execution": {"TimeGenerated", "event_type_s", "execution_status_s",
                                   "authorization_decision_s", "principal_id_s", "request_id_s",
                                   "tool_name_s", "resource_scope_s"},
    "ioc_network": {"Timestamp", "RemoteIP", "RemotePort", "InitiatingProcessFileName"},
}
REQUIRED_GENERIC = {
    "web_server_shell": {"ParentImage", "Image", "CommandLine"},
    "encoded_powershell": {"Image", "CommandLine"},
    "mcp_unauthorized_execution": {"event_type", "execution_status", "authorization_decision",
                                   "principal_id", "request_id", "tool_name", "resource_scope"},
    "ioc_network": {"DestinationIp", "DestinationPort", "Image"},
}
SAFE_TOKEN = re.compile(r"^[a-zA-Z0-9_.:/-]{1,120}$")


def validate_profile(profile):
    if not isinstance(profile, dict) or not isinstance(profile.get("name"), str) or not 2 <= len(profile["name"]) <= 120:
        raise ValueError("profile needs a name (2-120 characters)")
    if profile.get("siem") not in ("splunk", "defender", "generic"):
        raise ValueError("siem must be splunk, defender, or generic")
    for key in ("organization_aliases", "supplier_aliases"):
        aliases = profile.get(key, [])
        if (not isinstance(aliases, list) or len(aliases) > 50 or any(
                not isinstance(name, str) or not 5 <= len(name.strip()) <= 120 for name in aliases)):
            raise ValueError(f"{key} must be a list of at most 50 specific names")
    telemetry = profile.get("telemetry")
    if not isinstance(telemetry, dict) or not telemetry:
        raise ValueError("provide at least one telemetry family")
    for family, config in telemetry.items():
        if family not in ("process_creation", "network_connection", "mcp_audit") or not isinstance(config, dict):
            raise ValueError("unsupported telemetry family")
        if profile["siem"] == "generic":
            mapping = config.get("field_map")
            if (not isinstance(config.get("source"), str) or not SAFE_TOKEN.fullmatch(config["source"])
                    or not isinstance(mapping, dict) or len(mapping) > 80 or any(
                        not isinstance(key, str) or not SAFE_TOKEN.fullmatch(key) or
                        not isinstance(value, str) or not SAFE_TOKEN.fullmatch(value)
                        for key, value in mapping.items())):
                raise ValueError(f"{family}: generic source and canonical-to-local field_map are required")
            continue
        fields = config.get("fields")
        if not isinstance(fields, list) or len(fields) > 80 or any(not isinstance(f, str) or not SAFE_TOKEN.fullmatch(f) for f in fields):
            raise ValueError(f"{family}: fields must be a list of safe field names")
        mapping = config.get("field_map", {})
        if not isinstance(mapping, dict) or len(mapping) > 80 or any(
                not isinstance(key, str) or not SAFE_TOKEN.fullmatch(key) or
                not isinstance(value, str) or not SAFE_TOKEN.fullmatch(value) for key, value in mapping.items()):
            raise ValueError(f"{family}: optional field_map must map safe canonical and local fields")
        if profile["siem"] == "splunk":
            for key in ("index", "sourcetype"):
                if not isinstance(config.get(key), str) or not SAFE_TOKEN.fullmatch(config[key]):
                    raise ValueError(f"{family}: Splunk {key} is required")
        else:
            expected = {"process_creation": "DeviceProcessEvents", "network_connection": "DeviceNetworkEvents", "mcp_audit": "MCPAudit_CL"}[family]
            if config.get("table") != expected:
                raise ValueError(f"{family}: current KQL template requires the {expected} table")
    if "splunk_url" in profile:
        url = urlsplit(profile["splunk_url"])
        if profile["siem"] != "splunk" or url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("splunk_url must be an HTTPS management API origin without credentials or path")
    return profile


def parse_assets(contents):
    """Only explicit confirmed CVEs establish affected status; absence stays unknown."""
    if len(contents.encode("utf-8")) > 5_000_000:
        raise ValueError("asset CSV is over 5 MB")
    reader = csv.DictReader(io.StringIO(contents))
    required = {"asset_id", "hostname", "product", "version", "confirmed_cves", "internet_exposed", "criticality", "asset_role"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError("asset CSV missing required columns: " + ", ".join(sorted(required - set(reader.fieldnames or []))))
    rows, seen = [], set()
    for row in reader:
        if len(rows) >= 10000:
            raise ValueError("asset CSV exceeds 10,000 rows")
        ident = (row.get("asset_id") or "").strip()
        criticality = (row.get("criticality") or "").strip().lower()
        role = (row.get("asset_role") or "").strip().lower()
        exposed = (row.get("internet_exposed") or "").strip().lower()
        cves = [x.strip().upper() for x in (row.get("confirmed_cves") or "").split(";") if x.strip()]
        if (not ident or len(ident) > 120 or ident in seen or criticality not in ("low", "medium", "high")
                or role not in ("general", "model_serving", "mcp_server", "agent_runtime")
                or exposed not in ("true", "false") or len(cves) > 200
                or any(not sources.CVE.fullmatch(c) for c in cves)
                or any(len(row.get(k) or "") > 200 for k in ("hostname", "product", "version"))):
            raise ValueError(f"invalid or duplicate asset row {reader.line_num}")
        seen.add(ident)
        rows.append({"asset_id": ident, "hostname": row["hostname"], "product": row["product"],
                     "version": row["version"], "confirmed_cves": sorted(set(cves)),
                     "internet_exposed": exposed == "true", "criticality": criticality, "asset_role": role})
    if not rows:
        raise ValueError("asset CSV has no assets")
    return rows


def onboard(profile, assets, path: Path | None = None):
    """Validate both files before atomically replacing this deployment's local context."""
    validate_profile(profile)
    if not isinstance(assets, list) or not assets:
        raise ValueError("a parsed non-empty asset list is required")
    # Revalidate caller-supplied objects, not only CLI CSV input.
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["asset_id", "hostname", "product", "version", "confirmed_cves", "internet_exposed", "criticality", "asset_role"])
    writer.writeheader()
    for item in assets:
        if not isinstance(item, dict):
            raise ValueError("asset must be an object")
        writer.writerow({**item, "confirmed_cves": ";".join(item.get("confirmed_cves", [])),
                         "internet_exposed": str(item.get("internet_exposed", "")).lower()})
    assets = parse_assets(buf.getvalue())
    store.initialize(path)
    at = now()
    with store.connection(path) as db:
        db.execute("INSERT INTO environment_config(id,profile,updated_at) VALUES (1,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET profile=excluded.profile,updated_at=excluded.updated_at",
                   (json.dumps(profile), at))
        db.execute("DELETE FROM environment_assets")
        db.executemany("INSERT INTO environment_assets VALUES (?,?,?,?,?,?,?,?,?)",
                       [(r["asset_id"], r["hostname"], r["product"], r["version"], json.dumps(r["confirmed_cves"]),
                         int(r["internet_exposed"]), r["criticality"], r["asset_role"], at) for r in assets])
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (at, "environment_onboarded", "environment", json.dumps({"assets": len(assets), "siem": profile["siem"]})))
    return {"status": "configured", "name": profile["name"], "siem": profile["siem"],
            "assets": len(assets), "confirmed_cve_assets": sum(bool(r["confirmed_cves"]) for r in assets),
            "telemetry_families": sorted(profile["telemetry"]), "updated_at": at,
            "note": "An absent CVE is unknown unless your inventory independently confirms the product is not present."}


def status(path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        row = db.execute("SELECT profile,updated_at FROM environment_config WHERE id=1").fetchone()
        if not row:
            return {"configured": False, "next_step": "Run onboard with a profile JSON and asset CSV."}
        count = db.execute("SELECT COUNT(*) FROM environment_assets").fetchone()[0]
    profile = json.loads(row["profile"])
    age = datetime.now(timezone.utc) - datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
    return {"configured": True, "name": profile["name"], "siem": profile["siem"],
            "telemetry_families": sorted(profile["telemetry"]), "assets": count,
            "updated_at": row["updated_at"], "asset_snapshot_stale": age > timedelta(days=7),
            "splunk_probe_configured": bool(profile.get("splunk_url") and os.environ.get("SPLUNK_TOKEN"))}


def confirmed_cve_counts(path: Path | None = None):
    """For digest ordering only; records without a match are still unknown."""
    store.initialize(path)
    with store.connection(path) as db:
        rows = db.execute("SELECT confirmed_cves FROM environment_assets").fetchall()
    counts = {}
    for row in rows:
        for cve in json.loads(row["confirmed_cves"]):
            counts[cve] = counts.get(cve, 0) + 1
    return counts


def leak_claim_relevance(ident, path: Path | None = None):
    """Name-based triage only; never assert that an entity is compromised."""
    threat = get_threat(ident, path)
    if not threat or threat["kind"] != "leak_claim":
        raise ValueError("a collected ransomware leak-site claim is required")
    with store.connection(path) as db:
        row = db.execute("SELECT profile FROM environment_config WHERE id=1").fetchone()
    if not row:
        return {"threat_id": ident, "priority": "configure_organization_names", "score": None,
                "reason": "No organization or supplier names have been configured."}
    profile = json.loads(row["profile"])
    def normalize(value):
        return " ".join(re.findall(r"[\w]+", value.casefold()))
    title = " " + normalize(threat["title"]) + " "
    matches = {}
    for key in ("organization_aliases", "supplier_aliases"):
        matches[key] = [alias for alias in profile.get(key, [])
                        if " " + normalize(alias) + " " in title]
    priority = ("verify_organization_identity" if matches["organization_aliases"] else
                "verify_supplier_identity" if matches["supplier_aliases"] else "no_configured_name_match")
    return {"threat_id": ident, "priority": priority, "score": None,
            "possible_matches": matches, "reason": "Name match in an unverified leak-site claim; it does not establish the entity's identity or an intrusion.",
            "next_step": "Independently verify the organization, source, and any incident evidence before escalation or detection work."}


def risk_from_assets(ident, path: Path | None = None, limit=20):
    """Evidence-based fleet assessment; no match never becomes an absent-asset claim."""
    threat = get_threat(ident, path)
    if not threat:
        raise ValueError("unknown threat")
    if not sources.CVE.fullmatch(ident.upper()):
        raise ValueError("fleet matching currently requires a CVE; use environment_risk for campaigns and IOCs")
    if not status(path)["configured"]:
        raise ValueError("run onboard first")
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM environment_assets").fetchall()
    matches = []
    assessment_cache = {}
    for row in rows:
        if ident.upper() not in json.loads(row["confirmed_cves"]):
            continue
        context = {"affected": True, "internet_exposed": bool(row["internet_exposed"]),
                   "criticality": row["criticality"], "asset_role": row["asset_role"]}
        key = (context["internet_exposed"], context["criticality"], context["asset_role"])
        if key not in assessment_cache:
            assessment_cache[key] = assess_risk(ident, context, path)
        matches.append({"asset_id": row["asset_id"], "hostname": row["hostname"],
                        "product": row["product"], "version": row["version"],
                        "assessment": assessment_cache[key]})
    matches.sort(key=lambda r: r["assessment"]["score"], reverse=True)
    unknown = assess_risk(ident, {"affected": "unknown"}, path)
    return {"threat_id": ident.upper(), "inventory_assets": len(rows), "confirmed_affected_count": len(matches),
            "confirmed_affected": matches[:max(1, min(limit, 100))],
            "other_assets": "unknown; inventory absence is not proof of non-exposure",
            "unmatched_asset_priority": unknown["priority"],
            "asset_snapshot_stale": status(path)["asset_snapshot_stale"]}


def check_rule_fit(rule_id, path: Path | None = None):
    """Map a draft to declared telemetry; report gaps, never claim native validation."""
    from .rules import get_rule
    rule = get_rule(rule_id, path)
    if not rule:
        raise ValueError("unknown local rule")
    if rule["behavior"] == "custom":
        from . import custom_rules
        return custom_rules.fit(rule_id, path)
    with store.connection(path) as db:
        row = db.execute("SELECT profile FROM environment_config WHERE id=1").fetchone()
    if not row:
        return {"ready": False, "reason": "run onboard first"}
    profile = json.loads(row["profile"])
    family = FAMILIES[rule["behavior"]]
    config = profile["telemetry"].get(family)
    if not config:
        return {"ready": False, "rule_id": rule_id, "family": family, "reason": "telemetry family not mapped"}
    if profile["siem"] == "generic":
        required = REQUIRED_GENERIC[rule["behavior"]]
        missing = sorted(required - set(config["field_map"]))
        return {"ready": not missing, "rule_id": rule_id, "siem": "generic", "family": family,
                "source": config["source"], "missing_canonical_fields": missing,
                "field_map": {k: config["field_map"][k] for k in sorted(required) if k in config["field_map"]},
                "sigma": rule["sigma"], "mapped_query": None,
                "validation": "Mapping declared only. A target-specific Sigma pipeline or manually reviewed query and native SIEM test are required; no local query is executed.",
                "next_step": "Convert and test the Sigma rule with an appropriate backend, then import verified coverage."}
    required = REQUIRED_SPLUNK if profile["siem"] == "splunk" else REQUIRED_DEFENDER
    missing = sorted(required[rule["behavior"]] - set(config["fields"]))
    query = rule["spl"] if profile["siem"] == "splunk" else rule["kql"]
    if profile["siem"] == "splunk":
        # Only replace the two anchored selectors in our own fixed template.
        expected = ("index=ai_security sourcetype=mcp:audit" if family == "mcp_audit" else
                    "index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
        if not query.startswith(expected):
            return {"ready": False, "rule_id": rule_id, "reason": "unexpected SPL template; review manually"}
        query = query.replace(expected, f"index={config['index']} sourcetype={config['sourcetype']}", 1)
    return {"ready": not missing, "rule_id": rule_id, "siem": profile["siem"], "family": family,
            "missing_declared_fields": missing, "mapped_query": query if not missing else None,
            "validation": "configuration and field names only; query syntax, event coverage, and false positives need SIEM testing",
            "next_step": "Use probe_splunk_telemetry for a recent sample event" if profile["siem"] == "splunk" else "Test KQL in your own environment"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def probe_splunk(family, path: Path | None = None, fetch=None):
    """Read at most one recent event through Splunk's v2 search export API."""
    if family not in ("process_creation", "network_connection", "mcp_audit"):
        raise ValueError("unsupported telemetry family")
    with store.connection(path) as db:
        row = db.execute("SELECT profile FROM environment_config WHERE id=1").fetchone()
    if not row:
        raise ValueError("run onboard first")
    profile = json.loads(row["profile"])
    if profile["siem"] != "splunk" or not profile.get("splunk_url"):
        raise ValueError("profile needs a Splunk HTTPS management API URL")
    config = profile["telemetry"].get(family)
    if not config:
        raise ValueError("telemetry family not mapped")
    validate_profile(profile)
    token = os.environ.get("SPLUNK_TOKEN", "")
    if not token and fetch is None:
        raise ValueError("SPLUNK_TOKEN environment variable is required")
    event_code = " EventCode=1" if family == "process_creation" else " EventCode=3" if family == "network_connection" else ""
    search = f"search index={config['index']} sourcetype={config['sourcetype']}{event_code} | head 1"
    endpoint = profile["splunk_url"].rstrip("/") + "/services/search/v2/jobs/export"
    data = urllib.parse.urlencode({"search": search, "earliest_time": "-24h", "latest_time": "now", "output_mode": "json"}).encode()
    if fetch is None:
        request = urllib.request.Request(endpoint, data=data, headers={"Authorization": "Bearer " + token,
                                         "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        context = ssl.create_default_context(cafile=os.environ.get("SPLUNK_CA_BUNDLE") or None)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
        with opener.open(request, timeout=12) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("Splunk probe response too large")
    else:
        raw = fetch(endpoint, data)
    events = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("unexpected Splunk response")
        if any(m.get("type") == "ERROR" for m in payload.get("messages", []) if isinstance(m, dict)):
            raise ValueError("Splunk reported a search error")
        if isinstance(payload.get("result"), dict):
            events.append(payload["result"])
    observed = set(events[0]) if events else set()
    expected = set(config["fields"])
    return {"family": family, "sample_found": bool(events), "observed_fields": sorted(observed),
            "missing_configured_fields": sorted(expected - observed) if events else [],
            "status": "sample_checked" if events else "inconclusive_no_recent_event",
            "note": "One event checks field presence only. It does not validate rule syntax, detection accuracy, or coverage."}
