"""Offline installation and environment-pack checks for a new deployment."""

import importlib.util
import os
import sqlite3
import sys
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__, enterprise, environment, poller, store


def check(directory=None):
    """Report setup gaps without fetching feeds or revealing credentials."""
    errors, warnings = [], []
    target = None
    if directory:
        try:
            target = enterprise.pack_database(directory)
        except ValueError as exc:
            errors.append(str(exc))
    else:
        target = store.db_path()
    sdk = importlib.util.find_spec("mcp") is not None
    if not sdk:
        errors.append("MCP Python SDK is missing; install this project with pip install -e .")
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer is required")
    db_check = "not_checked"
    if target is not None:
        try:
            store.initialize(target)
            with store.connection(target) as db:
                db_check = "ok" if db.execute("PRAGMA quick_check").fetchone()[0] == "ok" else "integrity_error"
            if db_check != "ok":
                errors.append("local SQLite integrity check failed")
        except (OSError, sqlite3.Error) as exc:
            db_check = "unavailable"
            errors.append("local database unavailable: " + str(exc)[:160])
    try:
        ZoneInfo(os.environ.get("DIGEST_TZ", "America/Los_Angeles"))
        hour, minute = map(int, os.environ.get("DIGEST_TIME", "08:00").split(":"))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError("time out of range")
    except (ZoneInfoNotFoundError, ValueError):
        errors.append("DIGEST_TZ or DIGEST_TIME is invalid; use an IANA timezone and HH:MM")
    try:
        interval = poller.interval_minutes()
    except ValueError as exc:
        errors.append(str(exc))
        interval = None
    email = bool(os.environ.get("SMTP_HOST") and os.environ.get("DIGEST_TO"))
    if bool(os.environ.get("SMTP_HOST")) != bool(os.environ.get("DIGEST_TO")):
        warnings.append("Daily email needs both SMTP_HOST and DIGEST_TO; local text digests still work")
    pack = None
    installed = None
    if directory and target is not None:
        try:
            pack = enterprise.inspect_pack(directory)
            installed = environment.status(target)
            if not pack["ready_to_onboard"]:
                warnings.append("Environment pack has unmapped telemetry or missing verified assets; research-only collection can still run")
            elif not installed["configured"]:
                warnings.append("Pack files are ready; run onboard-pack to load them into the local database")
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            errors.append("environment pack cannot be inspected: " + str(exc)[:160])
    return {"version": __version__, "python": sys.version.split()[0], "mcp_sdk_available": sdk,
            "database": str(target) if target else None, "database_check": db_check,
            "poll_interval_minutes": interval, "daily_email_configured": email,
            "environment_pack": pack, "environment_loaded": installed,
            "errors": errors, "warnings": warnings,
            "status": "ready_for_research" if not errors else "fix_setup_errors",
            "scope": "Offline setup checks only; feed reachability, telemetry fields and native SIEM queries require separate validation."}
