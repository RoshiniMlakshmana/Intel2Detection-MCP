"""Public-source adapters. Source text remains untrusted data, never instructions."""

import json
import hashlib
import ipaddress
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_URL = "https://cveawg.mitre.org/api/cve/"


def fetch_json(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatResearchMCP/0.1", "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f"source returned HTTP {response.status}")
        raw = response.read(8_000_001)
        if len(raw) > 8_000_000:
            raise ValueError("source response too large")
    return json.loads(raw)


def post_json(url, body, headers=None, timeout=20):
    raw_body = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=raw_body, headers={
        "User-Agent": "ThreatResearchMCP/0.1", "Content-Type": "application/json",
        "Accept": "application/json", **(headers or {})}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(4_000_001)
        if len(raw) > 4_000_000:
            raise ValueError("ThreatFox response too large")
    return json.loads(raw)


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def collect_kev(since, fetch=fetch_json):
    records = fetch(KEV_URL)["vulnerabilities"]
    for item in records:
        cve = item.get("cveID", "").upper()
        if not CVE.fullmatch(cve) or item.get("dateAdded", "") < since.date().isoformat():
            continue
        yield {
            "id": cve, "title": item.get("vulnerabilityName") or cve,
            "summary": item.get("shortDescription", ""), "published": item.get("dateAdded"),
            "updated": item.get("dateAdded"), "kev": True, "affected": [item.get("vendorProject", ""), item.get("product", "")],
            "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "claim": "CISA listed this CVE as known exploited in the wild.",
        }


def collect_nvd(since, until, fetch=fetch_json, max_pages=25, page_size=2000, rate_limit=True):
    """Page through NVD's modified-CVE window.

    A cold-start or post-outage catch-up window can span the full 7-day
    retry floor the poller allows, and NVD's lastModified filter also
    catches bulk revisions to existing records (observed: >1000/day is
    routine). 2000/page (NVD's documented maximum) x 25 pages covers that
    comfortably; the RuntimeError below remains as a last-resort signal if
    a window still exceeds it. NVD asks for a short pause between requests
    (0.6s with an API key, 6s without); rate_limit=False is for tests.
    """
    start = 0
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    for page in range(max_pages):
        if rate_limit and page > 0:
            time.sleep(0.6 if api_key else 6.0)
        params = urllib.parse.urlencode({
            "lastModStartDate": _iso(since), "lastModEndDate": _iso(until),
            "startIndex": start, "resultsPerPage": page_size,
        })
        data = fetch(f"{NVD_URL}?{params}", headers=headers)
        records = data.get("vulnerabilities", [])
        for item in records:
            cve = item.get("cve", {})
            ident = cve.get("id", "").upper()
            if not CVE.fullmatch(ident) or cve.get("vulnStatus") == "Rejected":
                continue
            description = next((x.get("value", "") for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = next((v[0].get("cvssData", {}).get("baseScore") for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") if (v := metrics.get(k))), None)
            yield {
                "id": ident, "title": ident, "summary": description,
                "published": cve.get("published"), "updated": cve.get("lastModified"),
                "cvss": score, "affected": [], "source": f"https://nvd.nist.gov/vuln/detail/{ident}",
                "claim": "NVD published or updated this vulnerability record.",
                "references": [r["url"] for r in cve.get("references", [])
                               if isinstance(r.get("url"), str) and r["url"].startswith("https://")][:20],
            }
        start += len(records)
        if not records or start >= data.get("totalResults", start):
            break
    else:
        raise RuntimeError("NVD page cap reached; narrow the collection window")


def collect_ghsa(since, fetch=fetch_json, max_pages=5):
    # The API's modified filter covers newly published and revised advisories.
    page = 1
    for _ in range(max_pages):
        params = urllib.parse.urlencode({"type": "reviewed", "modified": f">={since.date().isoformat()}", "per_page": 100, "page": page})
        data = fetch(f"{GHSA_URL}?{params}")
        if not isinstance(data, list):
            raise ValueError("unexpected GitHub advisories response")
        for item in data:
            ident = (item.get("cve_id") or item.get("ghsa_id") or "").upper()
            if not (CVE.fullmatch(ident) or ident.startswith("GHSA-")) or item.get("withdrawn_at"):
                continue
            yield {
                "id": ident, "title": item.get("summary") or ident,
                "summary": item.get("description") or "", "published": item.get("published_at"),
                "updated": item.get("updated_at"), "affected": [
                    f"{x.get('package', {}).get('ecosystem', '')}:{x.get('package', {}).get('name', '')} {x.get('vulnerable_version_range', '')}"
                    for x in item.get("vulnerabilities", []) if x.get("package")
                ],
                "source": item.get("html_url") or f"https://github.com/advisories/{item.get('ghsa_id')}",
                "claim": "GitHub reviewed security advisory includes this affected package/version range.",
            }
        if len(data) < 100:
            break
        page += 1
    else:
        raise RuntimeError("GitHub advisory page cap reached; narrow the collection window")


def enrich_epss(ids, fetch=fetch_json):
    result = {}
    for offset in range(0, len(ids), 100):
        batch = [c for c in ids[offset:offset + 100] if CVE.fullmatch(c)]
        if not batch:
            continue
        data = fetch(f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(batch)})}")
        for item in data.get("data", []):
            if item.get("cve") in batch:
                result[item["cve"]] = float(item["epss"])
    return result


def collect_cve_record(ident, fetch=fetch_json):
    """Fetch the CNA's record and preserve its references as unverified pointers."""
    ident = ident.upper()
    if not CVE.fullmatch(ident):
        raise ValueError("a valid CVE ID is required")
    data = fetch(CVE_URL + ident)
    if data.get("cveMetadata", {}).get("state") != "PUBLISHED":
        raise ValueError("CVE record is not published")
    cna = data.get("containers", {}).get("cna", {})
    description = next((x.get("value", "") for x in cna.get("descriptions", []) if x.get("lang") == "en"), "")
    affected = [f"{x.get('vendor', '')} {x.get('product', '')}".strip() for x in cna.get("affected", [])]
    refs = [x["url"] for x in cna.get("references", []) if isinstance(x.get("url"), str) and x["url"].startswith("https://")]
    return {
        "id": ident, "title": ident, "summary": description,
        "published": data.get("cveMetadata", {}).get("datePublished"),
        "updated": data.get("cveMetadata", {}).get("dateUpdated"),
        "affected": affected, "source": f"https://www.cve.org/CVERecord?id={ident}",
        "claim": "The CVE Program published the CNA's record; verify exact affected versions in the linked advisory.",
        "references": refs[:20],
    }


def collect_threatfox(since, post=post_json):
    """Recent high-confidence public C2 IPs; optional because an Auth-Key is required."""
    key = os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        return
    days = min(7, max(1, (datetime.now(timezone.utc) - since).days + 1))
    data = post("https://threatfox-api.abuse.ch/api/v1/", {"query": "get_iocs", "days": days},
                headers={"Auth-Key": key})
    if data.get("query_status") != "ok":
        raise ValueError(f"ThreatFox query failed: {data.get('query_status', 'unknown')}")
    for item in data.get("data") or []:
        if item.get("threat_type") != "botnet_cc" or item.get("ioc_type") != "ip:port":
            continue
        raw = item.get("ioc", "")
        try:
            ip, port = raw.rsplit(":", 1)
            address = ipaddress.ip_address(ip)
            if not address.is_global or not (1 <= int(port) <= 65535):
                continue
            confidence = int(item.get("confidence_level", 0))
        except (ValueError, TypeError):
            continue
        if confidence < 75:
            continue
        first_seen = item.get("first_seen", "")
        try:
            seen = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if seen < since:
            continue
        ident = "IOC-IP-" + hashlib.sha256(f"{address}:{port}".encode()).hexdigest()[:16].upper()
        expires = min(seen + timedelta(days=7), datetime.now(timezone.utc) + timedelta(days=7))
        source_id = str(item.get("id", ""))
        yield {
            "id": ident, "title": f"Reported C2 endpoint {address}:{port}",
            "summary": f"ThreatFox reports this IP:port as botnet C2, associated with {item.get('malware_printable') or 'unknown malware'}.",
            "published": _iso(seen), "updated": item.get("last_seen") or _iso(seen),
            "kind": "ioc", "indicator": f"{address}:{int(port)}", "indicator_type": "ip:port",
            "confidence": confidence, "expires_at": _iso(expires), "affected": [],
            "source": f"https://threatfox.abuse.ch/ioc/{source_id}/" if source_id.isdigit() else "https://threatfox.abuse.ch/",
            "claim": f"ThreatFox lists {address}:{port} as botnet C2 with confidence {confidence}/100; validate local matches and freshness.",
        }
