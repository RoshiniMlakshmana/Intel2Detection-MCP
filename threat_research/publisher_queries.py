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
# Tokenize the entire input: quoted "and"/"|" are literals, not separators.
TOKEN = re.compile(r"\s*(?:(?P<literal>'[^'\n]{1,100}'|\"[^\"\n]{1,100}\")|(?P<op>==|=~)|(?P<word>[A-Za-z][A-Za-z0-9_]*)|(?P<punct>[|(),]))")


def bounded_spec(text):
    """Translate literal AND filters; reject any unconsumed syntax or clause."""
    if not isinstance(text, str) or len(text) > 5000:
        return None
    tokens, pos = [], 0
    while pos < len(text.rstrip()):
        match = TOKEN.match(text, pos)
        if not match:
            return None
        tokens.append(match.group(match.lastgroup))
        pos = match.end()
    if not tokens or tokens[0] not in TABLES:
        return None
    family, mapping = TABLES[tokens[0]]
    platform = ("windows" if re.search(r"(?i)\.exe\b|\.dll\b|[A-Za-z]:\\", text) else
                "linux" if re.search(r"(?i)\b(?:linux|zimbra)\b|/(?:opt|bin|tmp|var|usr)/", text) else None)
    if not platform:
        return None
    predicates, alternatives = [], []
    i = 1
    try:
        while i < len(tokens):
            if tokens[i] != "|":
                return None
            i += 1
            if tokens[i].lower() == "project":
                # Projection is optional and must be last; no computed fields.
                rest = tokens[i+1:]
                if not rest or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*" if j % 2 == 0 else ",", v)
                                   for j, v in enumerate(rest)) or len(rest) % 2 == 0:
                    return None
                i = len(tokens)
                break
            if tokens[i].lower() != "where":
                return None
            i += 1
            while True:
                field, op = tokens[i], tokens[i+1].lower()
                if field not in mapping or op not in ("==", "=~", "has", "contains", "endswith", "has_any", "has_all"):
                    return None
                i += 2
                values = []
                if op in ("has_any", "has_all"):
                    if tokens[i] != "(":
                        return None
                    i += 1
                    while True:
                        value = tokens[i]
                        if value[0] not in ("'", '"'):
                            return None
                        values.append(value[1:-1]); i += 1
                        if tokens[i] == ")":
                            i += 1; break
                        if tokens[i] != ",":
                            return None
                        i += 1
                else:
                    value = tokens[i]; i += 1
                    if value[0] not in ("'", '"'):
                        return None
                    values = [value[1:-1]]
                if op == "has_any" and alternatives:
                    return None  # Multiple independent OR groups need richer logic.
                target = alternatives if op == "has_any" else predicates
                for value in dict.fromkeys(values):
                    item = {"field": mapping[field], "operator": "equals" if op in ("==", "=~") else
                            "has" if op in ("has_all", "has_any") else op, "value": value}
                    if op == "==":
                        item["case_sensitive"] = True
                    if item not in target:
                        target.append(item)
                if i == len(tokens) or tokens[i] == "|":
                    break
                if tokens[i].lower() != "and":
                    return None
                i += 1
        spec = {"event_family": family, "platform": platform, "predicates": predicates}
        if alternatives:
            spec["any_of"] = alternatives
        return custom_rules.validate_spec(spec)
    except (IndexError, ValueError):
        return None
