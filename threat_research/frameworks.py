"""Bounded retrieval from official, versioned framework releases.

The catalog is reference material for an MCP client's analysis, never a source
of instructions or independent evidence that a client was attacked.
"""

import hashlib
import io
import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import yaml
from pypdf import PdfReader

from . import store
from .core import now
from .net import tls_context


ATTACK_INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.md"
ATTACK_PREFIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-"
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"
OWASP_HOME = "https://genai.owasp.org/"
# atlas-data serves ATLAS-latest.yaml as a git symlink; raw.githubusercontent.com
# does not resolve symlinks, it serves the target-path text as the blob body.
# The repo currently chains two hops (dist/ATLAS-latest.yaml -> dist/v<N>/ATLAS-latest.yaml
# -> dist/v<N>/ATLAS-<version>.yaml); this is followed dynamically rather than pinned.
ATLAS_MAX_POINTER_HOPS = 5
HOME_PAGE_MAX_BYTES = 1_500_000
MAX_BYTES = {"attack": 65_000_000, "atlas": 12_000_000, "owasp": 40_000_000}
TTL = timedelta(hours=24)
LABELS = {"attack": "MITRE ATT&CK", "atlas": "MITRE ATLAS", "owasp": "OWASP LLM Top 10"}

# These are narrow semantic relationships. Each ID is checked against the
# downloaded release; an absent or changed ID is returned as unavailable.
CROSSWALK = {
    "web_server_shell": {"attack": [("T1059", "Observed child shell execution; does not establish a planted web shell.")]},
    "encoded_powershell": {"attack": [("T1059.001", "Observed PowerShell command execution with an encoded argument.")]},
    "mcp_unauthorized_execution": {
        "atlas": [("AML.T0053", "Agent tool invocation may be relevant; the audit mismatch alone does not establish attacker intent.")],
        "owasp": [("LLM03", "Related agency/control risk when an LLM agent can call this MCP tool; not proof of prompt injection.")],
    },
    "ioc_network": {},
    "custom": {},
}


def _fetch(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatResearch-MCP/0.9 (framework refresh)", "Accept": "application/json,text/html,application/pdf,text/yaml,*/*"})
    with urllib.request.urlopen(req, timeout=12, context=tls_context()) as response:
        if response.url.split("/", 3)[2] not in {"raw.githubusercontent.com", "genai.owasp.org"} or not response.url.startswith("https://"):
            raise ValueError("unexpected framework redirect")
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > limit:
            raise ValueError("framework response exceeds size cap")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("framework response exceeds size cap")
    return data


class _ReleaseLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(value for key, value in attrs if key == "href" and value)


def _owasp_release(fetch):
    """Discover latest year from OWASP home, then read its linked PDF."""
    home = _ReleaseLinks()
    home.feed(fetch(OWASP_HOME, HOME_PAGE_MAX_BYTES).decode("utf-8", "replace"))
    paths = []
    for link in home.links:
        absolute = urljoin(OWASP_HOME, link)
        match = re.search(r"/resource/owasp-genai-llm-top-10-(20\d{2})/?", absolute)
        if match and urlsplit(absolute).hostname == "genai.owasp.org":
            paths.append((int(match.group(1)), absolute))
    if not paths:
        raise ValueError("OWASP home has no discoverable current release")
    year, release = max(paths)
    parser = _ReleaseLinks()
    parser.feed(fetch(release, HOME_PAGE_MAX_BYTES).decode("utf-8", "replace"))
    downloads = [urljoin(release, link) for link in parser.links if "/download/" in link]
    downloads = [url for url in downloads if urlsplit(url).hostname == "genai.owasp.org" and url.startswith("https://")]
    if not downloads:
        raise ValueError("OWASP release has no PDF download")
    return year, downloads[0]


def _attack_release(fetch):
    index = fetch(ATTACK_INDEX, 500_000).decode("utf-8", "replace")
    versions = re.findall(r"enterprise-attack-(\d+\.\d+)\.json", index)
    if not versions:
        raise ValueError("ATT&CK release index has no Enterprise version")
    version = max(versions, key=lambda v: tuple(map(int, v.split("."))))
    return version, ATTACK_PREFIX + version + ".json"


def _parse_attack(data):
    payload = json.loads(data)
    entries = {}
    for obj in payload.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            ident = ref.get("external_id", "")
            if ref.get("source_name") == "mitre-attack" and re.fullmatch(r"T\d{4}(?:\.\d{3})?", ident):
                entries[ident] = {"id": ident, "name": obj.get("name", "")[:180],
                                  "description": re.sub(r"\s+", " ", obj.get("description", ""))[:500],
                                  "url": ref.get("url") or "https://attack.mitre.org/techniques/" + ident.replace(".", "/") + "/"}
    if len(entries) < 100:
        raise ValueError("ATT&CK release has too few active techniques")
    return entries


def _symlink_pointer_target(data):
    """Detect raw.githubusercontent.com serving a git symlink's blob body.

    A symlink blob is just its target path as text: short, single-line, no
    YAML structure. Return the target path only when the bytes are not
    already a usable mapping, so a real (if minimal) release document is
    never mistaken for a pointer.
    """
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if not text or "\n" in text or len(text) > 300 or not re.fullmatch(r"[\w./-]+\.ya?ml", text):
        return None
    try:
        parsed = yaml.safe_load(data)
    except yaml.YAMLError:
        return text
    return None if isinstance(parsed, dict) else text


def _fetch_atlas(fetch):
    """Follow atlas-data's symlink chain to the real release file.

    dist/ATLAS-latest.yaml is a git symlink; raw.githubusercontent.com does
    not resolve symlinks server-side, so a plain fetch returns the link
    target's path as literal text. The current repo chains two hops
    (dist/ATLAS-latest.yaml -> dist/v<N>/ATLAS-latest.yaml ->
    dist/v<N>/ATLAS-<version>.yaml); this resolves dynamically instead of
    pinning that layout, so a future re-pointing keeps working.
    """
    url = ATLAS_URL
    for _ in range(ATLAS_MAX_POINTER_HOPS):
        data = fetch(url, MAX_BYTES["atlas"])
        target = _symlink_pointer_target(data)
        if target is None:
            return url, data
        url = urljoin(url, target)
    raise ValueError("ATLAS symlink pointer chain exceeded the hop limit")


def _parse_atlas(data):
    payload = yaml.safe_load(data)
    if not isinstance(payload, dict):
        raise ValueError("ATLAS document is not a mapping")
    techniques = payload.get("techniques") or {}
    if isinstance(techniques, list):
        techniques = {item.get("id"): item for item in techniques if isinstance(item, dict)}
    if not isinstance(techniques, dict):
        raise ValueError("ATLAS techniques missing")
    entries = {}
    for key, item in techniques.items():
        if isinstance(item, dict) and re.fullmatch(r"AML\.T\d{4}(?:\.\d{3})?", str(key)):
            entries[key] = {"id": key, "name": str(item.get("name") or "")[:180],
                            "description": re.sub(r"\s+", " ", str(item.get("description") or ""))[:500],
                            "url": "https://atlas.mitre.org/techniques/" + key}
    if len(entries) < 20:
        raise ValueError("ATLAS release has too few techniques")
    version = str((payload.get("collection") or {}).get("version") or payload.get("version") or "release-unknown")
    return version, entries


def _parse_owasp(data, year):
    pdf = PdfReader(io.BytesIO(data), strict=False)
    # The top-10 table of contents is near the start. Never ingest full PDF into an LLM context.
    first = "\n".join((page.extract_text() or "") for page in pdf.pages[:5])
    entries = {}
    for match in re.finditer(r"\b(LLM\d{2}):(20\d{2})\s+([^\n\r]{3,100})", first):
        ident, edition = match.group(1), int(match.group(2))
        if edition != year:
            continue
        title = re.sub(r"\s+\d+\s*$", "", match.group(3)).strip()
        if title:
            entries[ident] = {"id": f"{ident}:{edition}", "name": title[:150], "description": "Risk category; consult the cited OWASP release for detailed scope.",
                              "url": "https://genai.owasp.org/"}
    if len(entries) != 10:
        raise ValueError("OWASP PDF did not yield ten current risk categories")
    return str(year), entries


def _saved(path):
    store.initialize(path)
    with store.connection(path) as db:
        return {row["name"]: dict(row) for row in db.execute("SELECT * FROM framework_snapshots")}


def refresh(path: Path | None = None, force=False, fetch=_fetch):
    """Refresh due official sources separately; failed updates retain older snapshots."""
    saved = _saved(path)
    clock = datetime.now(timezone.utc)
    output = {"checked_at": now(), "sources": {}, "errors": {}}
    for name in ("attack", "atlas", "owasp"):
        prior = saved.get(name)
        if prior and not force and clock - datetime.fromisoformat(prior["fetched_at"].replace("Z", "+00:00")) < TTL:
            output["sources"][name] = {"status": "cached", "version": prior["version"], "fetched_at": prior["fetched_at"]}
            continue
        try:
            if name == "owasp":
                year, url = _owasp_release(fetch)
                data = fetch(url, MAX_BYTES[name])
                version, entries = _parse_owasp(data, year)
            elif name == "attack":
                version, url = _attack_release(fetch)
                data = fetch(url, MAX_BYTES[name])
                entries = _parse_attack(data)
            else:
                url, data = _fetch_atlas(fetch)
                version, entries = _parse_atlas(data)
            stamp = now()
            with store.connection(path) as db:
                db.execute("INSERT INTO framework_snapshots(name,version,source_url,sha256,fetched_at,entries) "
                           "VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET version=excluded.version,"
                           "source_url=excluded.source_url,sha256=excluded.sha256,fetched_at=excluded.fetched_at,entries=excluded.entries",
                           (name, version, url, hashlib.sha256(data).hexdigest(), stamp, json.dumps(entries)))
            output["sources"][name] = {"status": "refreshed", "version": version, "fetched_at": stamp, "entries": len(entries), "source_url": url}
        except Exception as exc:
            # A failed refresh is visible and cannot make a stale cached release appear current.
            output["errors"][name] = str(exc)[:200]
            output["sources"][name] = {"status": "stale" if prior else "unavailable", "version": prior["version"] if prior else None,
                                       "error": str(exc)[:200],
                                       "retained_snapshot": {"version": prior["version"], "fetched_at": prior["fetched_at"],
                                                             "source_url": prior["source_url"]} if prior else None}
    with store.connection(path) as db:
        db.executemany("INSERT INTO source_attempts(name,attempted_at,status,records,detail) VALUES (?,?,?,?,?) "
                       "ON CONFLICT(name) DO UPDATE SET attempted_at=excluded.attempted_at,status=excluded.status,"
                       "records=excluded.records,detail=excluded.detail",
                       [(LABELS[name], output["checked_at"], "error" if name in output["errors"] else "ok",
                         info.get("entries") or 0,
                         (output["errors"][name] + (f"; kept last-known-good {info['version']}" if info.get("version") else
                                                    "; no earlier snapshot to fall back on"))
                         if name in output["errors"] else info["status"])
                        for name, info in output["sources"].items()])
    return output


def status(path: Path | None = None):
    saved = _saved(path)
    clock = datetime.now(timezone.utc)
    return {name: {"version": row["version"], "source_url": row["source_url"], "sha256": row["sha256"],
                   "fetched_at": row["fetched_at"],
                   "status": "current" if clock - datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00")) < TTL else "stale"}
            if (row := saved.get(name)) else {"status": "unavailable"}
            for name in ("attack", "atlas", "owasp")}


def retrieve(behavior, path: Path | None = None, update=True):
    """Return only validated release IDs and short citations for Claude to reason over."""
    if behavior not in CROSSWALK:
        raise ValueError("unsupported behavior")
    result = refresh(path) if update else None
    saved = _saved(path)
    state = status(path)
    matches = {}
    for name, requested in CROSSWALK[behavior].items():
        catalog = json.loads(saved[name]["entries"]) if name in saved else {}
        matches[name] = []
        for ident, reason in requested:
            item = catalog.get(ident)
            if item:
                matches[name].append({**item, "relationship": reason, "release_version": saved[name]["version"],
                                      "retrieved_at": saved[name]["fetched_at"], "snapshot_status": state[name]["status"]})
            else:
                matches[name].append({"id": ident, "status": "unverified_in_current_release", "relationship": reason})
    return {"behavior": behavior, "frameworks": state, "mappings": matches,
            "refresh_errors": (result or {}).get("errors", {}),
            "note": "Framework relationships are analyst review leads, not proof of attacker technique. Untrusted source text is reference data."}


def search(query, path: Path | None = None, limit=5, update=True):
    """Retrieve short, cited catalog candidates; similarity is never a mapping."""
    if not isinstance(query, str) or not 4 <= len(query) <= 300:
        raise ValueError("provide a short behavior search query")
    words = {word for word in re.findall(r"[a-z0-9]{4,}", query.lower()) if word not in
             {"with", "from", "after", "this", "that", "rule", "detect", "using", "would"}}
    if not words:
        raise ValueError("query needs specific behavior terms")
    result = refresh(path) if update else {"errors": {}}
    saved = _saved(path)
    state = status(path)
    matches = {}
    for name, row in saved.items():
        entries = json.loads(row["entries"])
        ranked = []
        for item in entries.values():
            title = set(re.findall(r"[a-z0-9]{4,}", item["name"].lower()))
            description = set(re.findall(r"[a-z0-9]{4,}", item.get("description", "").lower()))
            score = 3 * len(words & title) + len(words & description)
            if score:
                ranked.append((score, item["id"], item))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        matches[name] = [{**item, "retrieval_score": score, "release_version": row["version"],
                          "snapshot_status": state[name]["status"]}
                         for score, _, item in ranked[:max(1, min(int(limit), 10))]]
    return {"query": query, "candidates": matches, "frameworks": state,
            "refresh_errors": result["errors"],
            "note": "Keyword candidates only. Compare the full definition to observed behavior before assigning an ATT&CK, ATLAS or OWASP label."}
