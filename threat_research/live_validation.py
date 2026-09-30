"""Optional bounded SIEM checks. No alerts, saved searches, or rule writes."""

import hashlib
import json
import os
import ssl
import urllib.parse
import urllib.request

from . import environment, store
from . import rules
from .rules import get_rule


def _splunk_request(endpoint, token, data=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(endpoint, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
    context = ssl.create_default_context(cafile=os.environ.get("SPLUNK_CA_BUNDLE") or None)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), environment._NoRedirect())
    with opener.open(request, timeout=20) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("SIEM response is too large")
    return raw


def _graph_request(endpoint, token, data):
    if endpoint != "https://graph.microsoft.com/v1.0/security/runHuntingQuery":
        raise ValueError("unexpected Graph endpoint")
    request = urllib.request.Request(endpoint, data=data,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json", "Accept": "application/json"},
                                     method="POST")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                         environment._NoRedirect())
    with opener.open(request, timeout=20) as response:
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Graph response is too large")
    return raw


def _profile(path):
    store.initialize(path)
    with store.connection(path) as db:
        row = db.execute("SELECT profile FROM environment_config WHERE id=1").fetchone()
    if not row:
        raise ValueError("run onboard first")
    profile = json.loads(row["profile"])
    environment.validate_profile(profile)
    return profile


def _generated_rule_only(rule, path):
    """Refuse to execute modified local query text through the SIEM connector."""
    if rule["behavior"] in rules.TEMPLATES:
        template = rules.TEMPLATES[rule["behavior"]]
        if rule["spl"] == template["spl"] and rule["kql"] == template["kql"]:
            return
        raise ValueError("draft query differs from the generated template")
    if rule["behavior"] == "custom":
        from . import custom_rules
        spec = custom_rules.get_spec(rule["id"], path)
        if not spec or custom_rules.fingerprint(spec) != rule["fingerprint"] or rule["sigma"] != custom_rules._sigma(
                rule["title"], spec, _custom_false_positives(rule["sigma"]),
                **custom_rules.sigma_extras(rule["sigma"])):
            raise ValueError("custom draft differs from the generated spec")
        return
    if rule["behavior"] != "ioc_network":
        raise ValueError("unsupported draft behavior")
    from .core import get_threat
    threat = get_threat(rule["threat_id"], path)
    if not threat or not threat["indicator"] or rules.ioc_fingerprint(threat["indicator"]) != rule["fingerprint"]:
        raise ValueError("IOC source no longer matches the draft")
    ip, port = threat["indicator"].rsplit(":", 1)
    expected_spl = ("index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3 "
                    f"DestinationIp={ip} DestinationPort={int(port)}\n"
                    "| table _time host Image User DestinationIp DestinationPort Initiated")
    expected_kql = ("DeviceNetworkEvents\n"
                    f"| where RemoteIP == '{ip}' and RemotePort == {int(port)}\n"
                    "| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType")
    if rule["spl"] != expected_spl or rule["kql"] != expected_kql:
        raise ValueError("draft query differs from the generated IOC template")


def check_live_query(rule_id, path=None, splunk_fetch=None, graph_fetch=None):
    """Execute only a previously generated draft over 24h; return counts, never events."""
    fit = environment.check_rule_fit(rule_id, path)
    if not fit.get("ready"):
        return {"rule_id": rule_id, "status": "blocked_mapping", "fit": fit}
    rule = get_rule(rule_id, path)
    if rule["expired"]:
        return {"rule_id": rule_id, "status": "expired_ioc", "reason": "refresh IOC before executing"}
    _generated_rule_only(rule, path)
    profile = _profile(path)
    if profile["siem"] == "generic":
        return {"rule_id": rule_id, "status": "target_backend_required",
                "reason": "Generic mapping has no native SIEM query executor; convert and test the Sigma rule in that environment."}
    query = fit["mapped_query"]
    if profile["siem"] == "splunk":
        token = os.environ.get("SPLUNK_TOKEN", "")
        if not token and splunk_fetch is None:
            raise ValueError("SPLUNK_TOKEN is required")
        endpoint = profile.get("splunk_url", "").rstrip("/") + "/services/search/v2/jobs/export"
        if not profile.get("splunk_url"):
            raise ValueError("profile needs splunk_url")
        bounded = "search " + query + "\n| head 5"
        data = urllib.parse.urlencode({"search": bounded, "earliest_time": "-24h", "latest_time": "now",
                                       "output_mode": "json"}).encode()
        raw = splunk_fetch(endpoint, data) if splunk_fetch else _splunk_request(endpoint, token, data)
        if not isinstance(raw, bytes) or len(raw) > 2_000_000:
            raise ValueError("unexpected Splunk response")
        count = 0
        messages = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("unexpected Splunk result")
            for message in item.get("messages", []):
                if isinstance(message, dict):
                    if message.get("type") == "ERROR":
                        raise ValueError("Splunk rejected search: " + str(message.get("text", ""))[:160])
                    if message.get("type") == "WARN":
                        messages.append(str(message.get("text", ""))[:160])
            if isinstance(item.get("result"), dict):
                count += 1
        siem = "splunk"
    else:
        token = os.environ.get("GRAPH_TOKEN", "")
        if not token and graph_fetch is None:
            raise ValueError("GRAPH_TOKEN with ThreatHunting.Read.All is required")
        endpoint = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
        bounded = query + "\n| take 5"
        raw = graph_fetch(endpoint, json.dumps({"Query": bounded, "Timespan": "P1D"}).encode()) if graph_fetch else _graph_request(
            endpoint, token, json.dumps({"Query": bounded, "Timespan": "P1D"}).encode())
        if not isinstance(raw, bytes) or len(raw) > 2_000_000:
            raise ValueError("unexpected Graph response")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("unexpected Graph hunting response")
        count = len(payload["results"])
        messages = []
        siem = "defender_graph"
    return {"rule_id": rule_id, "siem": siem, "status": "query_executed", "syntax_accepted": True,
            "sample_matches": min(count, 5), "window": "past_24_hours",
            "query_sha256": hashlib.sha256(bounded.encode()).hexdigest(), "warnings": messages[:5],
            "validation": "Native query execution only; zero matches is inconclusive. Review positive and negative fixtures, benign baseline, and full rule coverage before deployment. No event contents returned."}


SIGNALS = {
    "web_server_shell": ("w3wp", "httpd", "nginx", "cmd.exe", "powershell.exe"),
    "encoded_powershell": ("powershell", "encodedcommand", "-enc"),
    "mcp_unauthorized_execution": ("authorization_decision", "execution_status", "tool_invocation"),
    "ioc_network": ("destinationip", "destinationport"),
}


def _custom_false_positives(sigma):
    """Read the generated scalar solely to verify an unchanged local draft."""
    marker = "falsepositives:\n  - "
    if marker not in sigma:
        raise ValueError("custom rule has no false-positive context")
    return json.loads(sigma.split(marker, 1)[1].splitlines()[0])


def compare_splunk_inventory(rule_id, path=None, fetch=None):
    """Inspect visible saved-search metadata; similarities require human query review."""
    rule = get_rule(rule_id, path)
    if not rule:
        raise ValueError("unknown rule")
    profile = _profile(path)
    if profile["siem"] != "splunk" or not profile.get("splunk_url"):
        raise ValueError("configured Splunk URL required")
    token = os.environ.get("SPLUNK_TOKEN", "")
    if not token and fetch is None:
        raise ValueError("SPLUNK_TOKEN is required")
    candidates, checked = [], 0
    for page in range(5):
        endpoint = profile["splunk_url"].rstrip("/") + "/servicesNS/-/-/saved/searches?" + urllib.parse.urlencode(
            {"output_mode": "json", "count": 100, "offset": 100 * page})
        raw = fetch(endpoint) if fetch else _splunk_request(endpoint, token)
        if not isinstance(raw, bytes) or len(raw) > 2_000_000:
            raise ValueError("unexpected saved-search response")
        payload = json.loads(raw)
        entries = payload.get("entry") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            raise ValueError("unexpected saved-search listing")
        checked += len(entries)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            content = entry.get("content") or {}
            if not isinstance(content, dict):
                continue
            title, search = entry.get("name", ""), content.get("search", "")
            if not isinstance(title, str) or not isinstance(search, str):
                continue
            haystack = (title + " " + search).lower()
            signals = SIGNALS.get(rule["behavior"])
            if signals is None:
                from . import custom_rules
                spec = custom_rules.get_spec(rule_id, path)
                signals = tuple(item["value"].lower() for item in spec["predicates"])
            hits = [s for s in signals if s in haystack]
            if rule["behavior"] == "ioc_network":
                threat_id = rule["threat_id"]
                with store.connection(path) as db:
                    indicator = db.execute("SELECT indicator FROM threats WHERE id=?", (threat_id,)).fetchone()
                if indicator and indicator["indicator"]:
                    ip, port = indicator["indicator"].rsplit(":", 1)
                    hits = ["endpoint_terms"] if ip.lower() in haystack and port in haystack else []
                else:
                    hits = []
            if len(hits) >= (1 if rule["behavior"] == "ioc_network" else 2):
                candidates.append({"name": title[:160], "matching_terms": hits,
                                   "disabled": str(content.get("disabled", "0")).lower() in ("1", "true"),
                                   "query_sha256": hashlib.sha256(search.encode()).hexdigest(),
                                   "source": entry.get("id", "")[:500]})
        if len(entries) < 100:
            break
    else:
        raise ValueError("saved-search inventory exceeds 500; narrow or export it for analyst mapping")
    return {"rule_id": rule_id, "saved_searches_checked": checked,
            "possible_matches": candidates[:30], "truncated_candidates": len(candidates) > 30,
            "coverage": "unverified; title and query terms cannot establish equivalent logic, enabled state, or historical execution",
            "next_step": "Inspect each candidate and use the curated import-inventory mapping only when its telemetry and logic truly match."}
