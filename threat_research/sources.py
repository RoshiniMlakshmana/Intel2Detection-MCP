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

from .net import tls_context

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_URL = "https://cveawg.mitre.org/api/cve/"


def fetch_json(url, headers=None, timeout=20, max_bytes=8_000_000, include_link=False):
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 32_000_000:
        raise ValueError("invalid bounded JSON response limit")
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatResearchMCP/0.1", "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as response:
        if response.status != 200:
            raise ValueError(f"source returned HTTP {response.status}")
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("source response too large")
        link = response.headers.get("Link") if include_link else None
    data = json.loads(raw)
    return (data, link) if include_link else data


def post_json(url, body, headers=None, timeout=20):
    raw_body = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=raw_body, headers={
        "User-Agent": "ThreatResearchMCP/0.1", "Content-Type": "application/json",
        "Accept": "application/json", **(headers or {})}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as response:
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


class PartialCollection(RuntimeError):
    """A source stopped before covering its whole window.

    Carries the records it did fetch and the timestamp through which the
    window is known to be complete, so the caller can ingest what arrived
    and checkpoint only the covered part. It is never reported as a complete
    collection.
    """

    def __init__(self, message, records, complete_through, resume_state=None):
        super().__init__(message)
        self.records = records
        self.complete_through = complete_through
        self.resume_state = resume_state


def _nvd_record(item):
    cve = item.get("cve", {})
    ident = cve.get("id", "").upper()
    if not CVE.fullmatch(ident) or cve.get("vulnStatus") == "Rejected":
        return None
    description = next((x.get("value", "") for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score = next((v[0].get("cvssData", {}).get("baseScore") for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") if (v := metrics.get(k))), None)
    return {
        "id": ident, "title": ident, "summary": description,
        "published": cve.get("published"), "updated": cve.get("lastModified"),
        "cvss": score, "affected": [], "source": f"https://nvd.nist.gov/vuln/detail/{ident}",
        "claim": "NVD published or updated this vulnerability record.",
        "references": [r["url"] for r in cve.get("references", [])
                       if isinstance(r.get("url"), str) and r["url"].startswith("https://")][:20],
    }


def collect_nvd(since, until, fetch=fetch_json, max_pages=25, page_size=500, rate_limit=True,
                chunk=timedelta(days=1)):
    """Page through NVD's modified-CVE window in chronological day-sized chunks.

    NVD's lastModified filter also catches bulk revisions to old records
    (observed: >1000/day is routine), so a catch-up window after an outage
    can be large. The window is split into chunks; each chunk is paged to
    completion before the next starts, sharing one page budget per run.
    If the budget runs out, PartialCollection carries every fetched record
    and the end of the last fully paged chunk, so the next run resumes from
    there instead of failing the whole window forever (the observed
    "NVD page cap reached" loop). NVD asks for a short pause between
    requests (0.6s with an API key, 6s without); rate_limit=False is for tests.
    A response that exceeds the 8 MB fetch cap retries the same startIndex
    with half as many records, without skipping data or advancing the checkpoint.
    """
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    records, pages = [], 0
    chunk_start = since
    while True:
        chunk_end = min(until, chunk_start + chunk)
        start = 0
        current_page_size = page_size
        while True:
            if pages >= max_pages:
                raise PartialCollection(
                    f"NVD page cap reached ({max_pages} pages); ingested {len(records)} records, "
                    f"complete through {_iso(chunk_start)}; the next poll resumes from there",
                    records, chunk_start)
            if rate_limit and pages > 0:
                time.sleep(0.6 if api_key else 6.0)
            params = urllib.parse.urlencode({
                "lastModStartDate": _iso(chunk_start), "lastModEndDate": _iso(chunk_end),
                "startIndex": start, "resultsPerPage": current_page_size,
            })
            pages += 1
            try:
                data = fetch(f"{NVD_URL}?{params}", headers=headers)
            except ValueError as exc:
                if "source response too large" not in str(exc):
                    raise
                if current_page_size <= 1:
                    raise PartialCollection(
                        "NVD single-record response exceeds size cap; no records skipped; "
                        f"complete through {_iso(chunk_start)}", records, chunk_start) from exc
                current_page_size = max(1, current_page_size // 2)
                continue
            batch = data.get("vulnerabilities", [])
            records.extend(r for r in map(_nvd_record, batch) if r)
            start += len(batch)
            if not batch or start >= data.get("totalResults", start):
                break
        if chunk_end >= until:
            return records
        chunk_start = chunk_end


def _ghsa_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or
            parsed.path != "/advisories" or parsed.fragment):
        raise ValueError("GitHub advisory cursor must stay on the official endpoint")
    return url


def collect_ghsa(since, fetch=fetch_json, max_pages=5, until=None, database=None):
    """Follow GitHub's Link cursors; persist bounded progress after ingestion.

    Injected fetches can return a list for one page, or (list, Link-header) to
    simulate pagination. No unsupported page-number parameter is used.
    """
    from . import store
    until = until or datetime.now(timezone.utc)
    since = datetime.fromisoformat(_iso(since).replace("Z", "+00:00"))
    until = datetime.fromisoformat(_iso(until).replace("Z", "+00:00"))
    if max_pages < 1 or until < since:
        raise ValueError("invalid GitHub advisory collection window or page budget")
    pending = None
    if database is not None:
        store.initialize(database)
        with store.connection(database) as db:
            row = db.execute("SELECT state FROM collection_cursors WHERE source='GitHub advisories'").fetchone()
        pending = json.loads(row["state"]) if row else None
    window_since = datetime.fromisoformat(pending["since"].replace("Z", "+00:00")) if pending else since
    window_until = datetime.fromisoformat(pending["until"].replace("Z", "+00:00")) if pending else until
    url = _ghsa_url(pending["next_url"]) if pending else None
    records, pages = [], 0
    completed_through = min(since, window_since)
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    while True:
        if not url:
            params = urllib.parse.urlencode({"type": "reviewed", "modified": window_since.date().isoformat() + ".." + window_until.date().isoformat(),
                                             "sort": "updated", "direction": "asc", "per_page": 100})
            url = f"{GHSA_URL}?{params}"
        state = {"since": _iso(window_since), "until": _iso(window_until), "next_url": url}
        if pages >= max_pages:
            raise PartialCollection("GitHub advisory page budget reached; saved cursor resumes after ingestion",
                                    records, completed_through, resume_state=state)
        try:
            response = (fetch(url, headers=headers, include_link=True) if fetch is fetch_json else fetch(url))
        except (OSError, ValueError) as exc:
            raise PartialCollection(f"GitHub advisory fetch interrupted: {exc}; cursor retained",
                                    records, completed_through, resume_state=state) from exc
        pages += 1
        data, link = response if isinstance(response, tuple) else (response, None)
        if not isinstance(data, list):
            raise PartialCollection("unexpected GitHub advisories response; cursor retained", records,
                                    completed_through, resume_state=state)
        for item in data:
            if not isinstance(item, dict):
                continue
            ident = (item.get("cve_id") or item.get("ghsa_id") or "").upper()
            if not (CVE.fullmatch(ident) or ident.startswith("GHSA-")) or item.get("withdrawn_at"):
                continue
            records.append({
                "id": ident, "title": item.get("summary") or ident,
                "summary": item.get("description") or "", "published": item.get("published_at"),
                "updated": item.get("updated_at"), "affected": [
                    f"{x.get('package', {}).get('ecosystem', '')}:{x.get('package', {}).get('name', '')} {x.get('vulnerable_version_range', '')}"
                    for x in item.get("vulnerabilities", []) if x.get("package")
                ],
                "source": item.get("html_url") or f"https://github.com/advisories/{item.get('ghsa_id')}",
                "claim": "GitHub reviewed security advisory includes this affected package/version range.",
            })
        next_link = re.search(r'<([^>]+)>\s*;\s*rel="next"', link or "")
        if next_link:
            try:
                url = _ghsa_url(next_link.group(1))
            except ValueError as exc:
                raise PartialCollection(str(exc), records, completed_through, resume_state=state) from exc
            continue
        completed_through = window_until
        if window_until >= until:
            return records
        # Complete the older pending snapshot before moving toward this poll.
        window_since, window_until, url = window_until, until, None


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
