"""On-demand, bounded inspection of a cited public research article."""

import hashlib
import html
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from . import behavior_leads, research_feeds
from .net import tls_context
from .core import get_threat

ALLOWED_HOSTS = {urlsplit(url).hostname for _, url, _ in research_feeds.FEEDS} | {
    "unit42.paloaltonetworks.com", "thedfirreport.com", "www.thedfirreport.com",
    "www.cisa.gov", "security.googleblog.com", "cloud.google.com",
}
TERMS = re.compile(r"\b(CVE-\d{4}-\d{4,}|exploited|payload|powershell|command line|"
                   r"web shell|process|credential|lateral movement|persistence|"
                   r"indicator|telemetry|detection|compromise|initial access)\b", re.I)
MAX_BYTES = 600_000


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.parts = []
        self.active = False
        self.current = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "nav", "footer", "header", "form"):
            self.depth += 1
        elif not self.depth and tag in ("p", "li", "h1", "h2", "h3"):
            self.flush()
            self.active = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "nav", "footer", "header", "form"):
            self.depth = max(0, self.depth - 1)
        elif tag in ("p", "li", "h1", "h2", "h3"):
            self.flush()
            self.active = False

    def handle_data(self, data):
        if self.active and not self.depth:
            self.current.append(data)

    def flush(self):
        value = " ".join(" ".join(self.current).split())
        if 40 <= len(value) <= 5000:
            self.parts.append(value)
        self.current = []


class _SameHostRedirectOnly(urllib.request.HTTPRedirectHandler):
    """Permit only a bounded chain of same-host HTTPS redirects.

    Publishers routinely 301 a trailing-slash or http->https canonicalization
    on the exact URL we already cited; blocking every redirect turned those
    into permanent failures. Anything that would leave the original host is
    still refused, which is the actual SSRF/host-confusion protection.
    """
    def __init__(self):
        self.hops = 0

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        original_host = urlsplit(request.full_url).hostname
        self.hops += 1
        if parsed.scheme == "http" and parsed.hostname == original_host and parsed.port in (None, 80):
            # Some publishers (observed: research.checkpoint.com) canonicalize
            # the path but emit an http:// Location; the https form of that
            # same host/path serves the article, so never downgrade.
            parsed = parsed._replace(scheme="https", netloc=parsed.hostname)
            newurl = urlunsplit(parsed)
        if self.hops > 3 or parsed.scheme != "https" or parsed.hostname != original_host or parsed.username or parsed.password:
            return None
        return urllib.request.Request(newurl, headers=request.headers, method=request.get_method())


ARTICLE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 ThreatResearchMCP/0.11 "
                   "(+cited-article inspector; contact via project README)",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _open_article(url):
    request = urllib.request.Request(url, headers=ARTICLE_HEADERS)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls_context()),
                                         _SameHostRedirectOnly())
    with opener.open(request, timeout=12) as response:
        if response.headers.get_content_type() not in ("text/html", "application/xhtml+xml"):
            raise ValueError("article did not return HTML")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("article exceeds inspection limit")
    return raw


def _canonical_slash(url):
    """Feed URLs are stored without a trailing slash for stable IDs, but some
    publisher WAFs (observed: SecurityWeek) answer that non-canonical form
    with 403 for non-browser clients while serving the slash form normally."""
    parsed = urlsplit(url)
    last = parsed.path.rsplit("/", 1)[-1]
    if parsed.path.endswith("/") or not last or "." in last:
        return None
    return urlunsplit(parsed._replace(path=parsed.path + "/"))


def fetch_article(url, open_url=_open_article):
    """Fetch HTML from an explicit publisher host, bounded same-host redirects only, no credentials."""
    try:
        return open_url(url)
    except urllib.error.HTTPError as exc:
        first = exc
    alternate = _canonical_slash(url) if first.code in (301, 302, 403, 404) else None
    if alternate:
        try:
            return open_url(alternate)
        except urllib.error.HTTPError as exc:
            first = exc
    if first.code == 429:
        raise ValueError("HTTP 429: publisher rate limit; the queue retries later with backoff") from first
    if first.code in (401, 403):
        raise ValueError(f"HTTP {first.code}: publisher blocked the automated article fetch; "
                         "open the cited URL in a browser and record verified behavior manually") from first
    raise ValueError(f"HTTP {first.code}: {first.reason}") from first


def inspect_report(threat_id, source_url, path=None, fetch=fetch_article):
    """Return relevant excerpts with page hash; unreviewed text is never detection evidence."""
    parsed = urlsplit(source_url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.port not in (None, 443)
            or parsed.username or parsed.password or len(source_url) > 500):
        raise ValueError("report URL must be HTTPS on a configured publisher host")
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    cited = set(threat["sources"]) | {e["source_url"] for e in threat["evidence"]}
    if source_url not in cited:
        raise ValueError("source URL is not cited by this threat")
    return extract_report_html(threat_id, source_url, fetch(source_url))


def extract_report_html(threat_id, source_url, raw):
    """Parse supplied HTML; the caller must separately establish its provenance.

    The network-facing inspect_report performs allowlist and citation checks first.
    Offline fixture callers receive the same research-only extraction logic.
    """
    if not isinstance(raw, bytes):
        raise ValueError("article must be HTML bytes")
    if len(raw) > MAX_BYTES:
        raise ValueError("article exceeds inspection limit")
    if not re.search(br"<\s*(?:html|article|p|body)\b", raw[:10000], re.I):
        raise ValueError("article response is not recognizable HTML")
    parser = _Text()
    parser.feed(raw.decode("utf-8", errors="replace"))
    parser.flush()
    selected = []
    for index, paragraph in enumerate(parser.parts):
        if TERMS.search(paragraph) or threat_id.upper() in paragraph.upper():
            clean = html.unescape(paragraph)
            selected.append({"paragraph": index + 1, "excerpt": clean[:420],
                             "truncated": len(clean) > 420})
    return {"threat_id": threat_id.upper(), "source": source_url,
            "sha256": hashlib.sha256(raw).hexdigest(), "paragraphs_scanned": len(parser.parts),
            "relevant_paragraphs": len(selected), "excerpts": selected[:10],
            "behavior_leads": behavior_leads.from_paragraphs(parser.parts),
            "status": "research_leads_only",
            "next_step": "Read the linked full report, verify behavior and telemetry, then record a cited analyst observation."}
