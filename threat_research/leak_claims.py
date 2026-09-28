"""Public ransomware leak-site claim metadata; never fetch leaked material."""

import hashlib
from datetime import datetime, timezone

from .sources import fetch_json

RANSOMLOOK_URL = "https://www.ransomlook.io/api/recent"
SOURCE_URL = "https://www.ransomlook.io/recent"


def collect_ransomlook(since, until=None, fetch=fetch_json):
    """Read metadata mirrored by an open-source tracker, not attacker websites."""
    until = until or datetime.now(timezone.utc)
    payload = fetch(RANSOMLOOK_URL)
    if isinstance(payload, dict):
        payload = payload.get("posts", payload.get("data", payload.get("results")))
    if not isinstance(payload, list):
        raise ValueError("unexpected RansomLook recent-post response")
    records = []
    for item in payload[:500]:
        if not isinstance(item, dict):
            continue
        title = item.get("post_title") or item.get("victim") or item.get("title")
        group = item.get("group_name") or item.get("group")
        stamp = item.get("discovered") or item.get("published")
        if not all(isinstance(x, str) for x in (title, group, stamp)) or not (2 <= len(title) <= 240 and 2 <= len(group) <= 100):
            continue
        try:
            discovered = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
            if discovered.tzinfo is None:
                # RansomLook describes its first-observed timestamps as UTC.
                discovered = discovered.replace(tzinfo=timezone.utc)
            discovered = discovered.astimezone(timezone.utc)
        except ValueError:
            continue
        if not since <= discovered <= until:
            continue
        # The same tracker claim is not corroboration when polled again.
        ident = "LEAK-" + hashlib.sha256(f"{group.casefold()}|{title.casefold()}|{discovered.date()}".encode()).hexdigest()[:16].upper()
        records.append({"id": ident, "kind": "leak_claim", "title": f"Unverified ransomware claim: {title}",
                        "summary": f"RansomLook reports a leak-site post attributed to {group}. The named entity and intrusion claim require independent verification.",
                        "published": discovered.isoformat().replace("+00:00", "Z"),
                        "updated": discovered.isoformat().replace("+00:00", "Z"),
                        "source": SOURCE_URL, "affected": [],
                        "claim": f"RansomLook first observed a post attributed to {group}; this is a self-reported leak-site claim, not verified compromise or exploit behavior."})
    return records
