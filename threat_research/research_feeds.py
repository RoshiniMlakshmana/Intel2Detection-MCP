"""Bounded, independent RSS/Atom intake for research leads.

Entries are metadata and untrusted excerpts. They are not observed behaviors.
"""

import gzip
import hashlib
import html
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Independent public-source catalog. Feed availability is checked on every run;
# a configured URL is not a promise that its publisher still serves RSS/Atom.
FEEDS = (
    ("CISA advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "government"),
    ("Cisco Talos research", "https://blog.talosintelligence.com/rss/", "research"),
    ("Fortinet threat signals", "https://filestore.fortinet.com/fortiguard/rss/threatsignal.xml", "research"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "research"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "research"),
    ("SentinelOne Labs", "https://www.sentinelone.com/labs/feed/", "research"),
    ("Google Project Zero", "https://projectzero.google/feed.xml", "research"),
    ("Zero Day Initiative", "https://www.thezdi.com/blog?format=rss", "research"),
    ("Check Point Research", "https://research.checkpoint.com/feed/", "research"),
    ("The DFIR Report", "https://thedfirreport.com/feed/", "research"),
    ("Malpedia", "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest", "research"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml", "research"),
    ("Securelist", "https://securelist.com/feed/", "research"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "research"),
    ("Proofpoint Threat Insights", "https://www.proofpoint.com/us/threat-insight-blog.xml", "research"),
    ("Datadog Security Labs", "https://securitylabs.datadoghq.com/rss/feed.xml", "research"),
    ("ReversingLabs", "https://www.reversinglabs.com/blog/rss.xml", "research"),
    ("Wiz", "https://www.wiz.io/feed/rss.xml", "research"),
    ("Malwarebytes", "https://www.malwarebytes.com/blog/feed/", "research"),
    ("Google Cloud Threat Intelligence", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "research"),
    ("ANY.RUN", "https://any.run/cybersecurity-blog/rss/", "research"),
    ("Qualys Security", "https://blog.qualys.com/feed", "research"),
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed", "research"),
    ("Aqua Security", "https://blog.aquasec.com/rss.xml", "research"),
    ("Objective-See", "https://objective-see.org/rss.xml", "research"),
    ("Snyk", "https://snyk.io/blog/feed/", "research"),
    ("Semgrep", "https://semgrep.dev/blog/rss/", "research"),
    ("JFrog Security Research", "https://jfrog.com/blog/tag/security-research/feed/", "research"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("SecurityWeek", "https://www.securityweek.com/feed/", "news"),
)

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
TAGS = re.compile(r"<[^>]{0,2000}>")
SPACE = re.compile(r"\s+")

DEFAULT_MAX_BYTES = 3_000_000
# A handful of publishers ship unusually large feeds (full-content entries,
# large archives). These are read-size overrides, not a promise the feed
# will otherwise succeed (WAF/bot-management blocks are separate failures).
# Google Project Zero in particular ships its entire non-paginated post
# history in one feed.xml (~9MB observed live); 16MB gives real headroom.
SIZE_OVERRIDES = {"Google Project Zero": 16_000_000, "Zero Day Initiative": 4_000_000}
# Some publisher WAFs (Cloudflare/CloudFront bot management) answer an
# automated GET with an empty interim response rather than a normal error;
# a browser-shaped header set reduces, but cannot fully eliminate, this.
FEED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 ThreatResearchMCP/0.10 "
                   "(+research feed reader; contact via project README)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, identity",
}


def fetch_feed(url, timeout=12, max_bytes=DEFAULT_MAX_BYTES):
    if urlsplit(url).scheme != "https":
        raise ValueError("feed URL must be HTTPS")
    req = urllib.request.Request(url, headers=FEED_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(max_bytes + 1)
        encoding = (response.headers.get("Content-Encoding") or "").lower()
        status = response.status
    if len(raw) > max_bytes:
        raise ValueError("feed response too large")
    if encoding == "gzip":
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise ValueError(f"feed sent gzip content that could not be decompressed: {exc}") from exc
    if not raw.strip():
        note = " (server returned an interim/challenge response with no body)" if status == 202 else ""
        raise ValueError(f"feed returned an empty response body{note}; publisher may block automated requests")
    return raw


def _plain(value):
    return SPACE.sub(" ", html.unescape(TAGS.sub(" ", value or ""))).strip()


def _element_text(node, names):
    for child in node:
        if child.tag.rsplit("}", 1)[-1].lower() in names:
            value = "".join(child.itertext())
            if value.strip():
                return value
    return ""


def _link(node):
    for child in node:
        if child.tag.rsplit("}", 1)[-1].lower() == "link":
            if child.attrib.get("rel", "alternate") == "alternate":
                return child.attrib.get("href") or (child.text or "")
    return ""


def _date(value):
    try:
        stamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        try:
            stamp = parsedate_to_datetime(value)
        except (ValueError, TypeError, IndexError):
            return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(timezone.utc)


def parse_feed(raw, name, kind, since, until=None, max_bytes=DEFAULT_MAX_BYTES):
    """Require a publication date and safely parse a bounded feed snapshot."""
    if len(raw) > max_bytes:
        raise ValueError("unsupported or oversized XML")
    if re.search(br"<!\s*ENTITY\b", raw, re.I):
        # Internal general entities are the actual XXE/billion-laughs vector;
        # reject those outright rather than the whole document class.
        raise ValueError("unsupported or oversized XML")
    if re.search(br"<!\s*DOCTYPE\b", raw, re.I):
        # A bare external DOCTYPE (no ENTITY) is common in validator-friendly
        # RSS (e.g. Squarespace-generated feeds); ElementTree/expat does not
        # fetch external subsets, but strip it anyway so parsing never
        # depends on that behavior.
        raw = re.sub(br"<!\s*DOCTYPE\b[^>\[]*(\[[^\]]*\])?\s*>", b"", raw, count=1, flags=re.I)
    root = ET.fromstring(raw)
    entries = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() in ("item", "entry")]
    if not entries or root.tag.rsplit("}", 1)[-1].lower() not in ("rss", "feed", "rdf"):
        raise ValueError("feed has no RSS/Atom entries")
    until = until or datetime.now(timezone.utc)
    results = []
    for node in entries[:100]:
        title = _plain(_element_text(node, {"title"}))[:300]
        excerpt = _plain(_element_text(node, {"description", "summary", "content", "encoded"}))[:1600]
        published = _date(_element_text(node, {"pubdate", "published", "updated", "date"}))
        link = _link(node).strip()
        parsed = urlsplit(link)
        if (not published or published < since or published > until or len(title) < 8
                or parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or len(link) > 500):
            continue
        query = urlencode(sorted((k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                               if not k.lower().startswith("utm_") and k.lower() not in ("fbclid", "gclid")))
        clean = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", query, ""))
        ident = "REPORT-" + hashlib.sha256(clean.encode()).hexdigest()[:16].upper()
        results.append({"id": ident, "kind": "campaign", "title": title,
                        "summary": excerpt or f"Feed published: {title}",
                        "published": published.isoformat().replace("+00:00", "Z"),
                        "updated": published.isoformat().replace("+00:00", "Z"),
                        "source": clean, "affected": [], "reported_by": "RSS: " + name,
                        "source_category": kind,
                        "mentioned_cves": sorted(set(x.upper() for x in CVE.findall(title + " " + excerpt)))[:20],
                        "claim": f"{name} published this article title/excerpt; full technical details and behavior are not verified."})
    return results


def collect_research(since, until=None, feeds=FEEDS, fetch=fetch_feed, max_workers=6, since_by_name=None, retries=0):
    """Return records, counts and per-feed errors; one failure cannot hide others."""
    until = until or datetime.now(timezone.utc)
    records, counts, errors = [], {}, {}
    names = [item[0] for item in feeds]
    if len(names) != len(set(names)):
        raise ValueError("duplicate feed names")

    def fetch_with_retry(url, limit):
        # A transient connection reset/refusal is worth one short retry; a
        # publisher-level error (403/oversized/empty) is not, so this only
        # retries OSError, not the ValueErrors raised above for those cases.
        last = None
        for attempt in range(retries + 1):
            try:
                return fetch(url, max_bytes=limit) if fetch is fetch_feed else fetch(url)
            except OSError as exc:
                last = exc
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
        raise last

    def task(feed):
        name, url, kind = feed
        effective_since = (since_by_name or {}).get("RSS: " + name, since)
        limit = SIZE_OVERRIDES.get(name, DEFAULT_MAX_BYTES)
        raw = fetch_with_retry(url, limit)
        return parse_feed(raw, name, kind, effective_since, until, max_bytes=limit)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 8))) as pool:
        futures = {pool.submit(task, feed): feed[0] for feed in feeds}
        for future in as_completed(futures):
            name = futures[future]
            try:
                rows = future.result()
                records.extend(rows)
                counts[name] = len(rows)
            except (OSError, ValueError, ET.ParseError, UnicodeError) as exc:
                errors[name] = str(exc)[:200]
    return records, counts, errors
