"""Conservative translation of a small, explicit publisher KQL subset.

Unsupported queries stay visible as publisher hunts. Never execute source text
or silently discard a filtering clause while translating a draft.
"""

import re

from . import custom_rules

TABLES = {
    "DeviceFileEvents": ("file_event", {"SHA256": "SHA256", "FileName": "FileName",
                                       "FolderPath": "TargetFilename", "InitiatingProcessFileName": "InitiatingProcessFileName"}),
    "DeviceProcessEvents": ("process_creation", {"FileName": "Image", "ProcessCommandLine": "CommandLine",
                                                "InitiatingProcessFileName": "ParentImage"}),
    "DeviceNetworkEvents": ("network_connection", {"InitiatingProcessFileName": "Image",
                                                   "RemoteUrl": "DestinationHostname", "RemoteIP": "DestinationIp"}),
}
COMPARE = re.compile(r"\s*([A-Za-z][A-Za-z0-9_]*)\s*(==|=~|contains|endswith)\s*(['\"])([^'\"\n]{1,100})\3\s*", re.I)


def bounded_spec(text):
    """Return a spec only if every filtering clause is a supported literal AND."""
    if not isinstance(text, str) or len(text) > 5000:
        return None
    pieces = [p.strip() for p in text.split("|")]
    if not pieces or pieces[0] not in TABLES:
        return None
    family, field_map = TABLES[pieces[0]]
    # Device* tables exist on Windows and Linux. A query without a platform
    # cue must not be mislabeled Windows simply because it uses Defender.
    if re.search(r"(?i)\.exe\b|\.dll\b|[A-Za-z]:\\", text):
        platform = "windows"
    elif re.search(r"(?i)\b(?:linux|zimbra)\b|/(?:opt|bin|tmp|var)/", text):
        platform = "linux"
    else:
        return None
    filters = [p[6:].strip() for p in pieces[1:] if p.lower().startswith("where ")]
    if not filters or any(not (p.lower().startswith("where ") or re.fullmatch(r"project\s+[A-Za-z][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z][A-Za-z0-9_]*)*", p, re.I))
                                for p in pieces[1:]):
        return None
    if any(p.lower().startswith("project ") for p in pieces[1:-1]):
        return None  # Projection before filtering can change which fields exist.
    expression = " and ".join(filters)
    parts = re.split(r"\s+and\s+", expression, flags=re.I)
    if not 2 <= len(parts) <= 8:
        return None
    predicates = []
    for part in parts:
        match = COMPARE.fullmatch(part)
        if not match or match[1] not in field_map:
            return None
        predicates.append({"field": field_map[match[1]],
                           "operator": "equals" if match[2] in ("==", "=~") else match[2].lower(),
                           "value": match[4]})
        if match[2] == "==":
            predicates[-1]["case_sensitive"] = True
    try:
        return custom_rules.validate_spec({"event_family": family, "platform": platform,
                                           "predicates": predicates})
    except ValueError:
        return None
