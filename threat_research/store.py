"""Small durable store. SQLite commits make repeated feed runs idempotent."""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


def db_path() -> Path:
    return Path(os.environ.get("THREAT_RESEARCH_DB", "~/.threat-research/intel.sqlite3")).expanduser()


@contextmanager
def connection(path: Path | None = None):
    target = path or db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize(path: Path | None = None):
    with connection(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL,
                published TEXT, updated TEXT, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, kev INTEGER NOT NULL DEFAULT 0,
                epss REAL, cvss REAL, affected TEXT NOT NULL DEFAULT '[]',
                sources TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'research_needed',
                kind TEXT NOT NULL DEFAULT 'advisory', indicator TEXT, indicator_type TEXT,
                confidence INTEGER, expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(id),
                source_url TEXT NOT NULL, claim TEXT NOT NULL, kind TEXT NOT NULL,
                behavior TEXT, observed_at TEXT NOT NULL,
                UNIQUE(threat_id,source_url,claim,kind)
            );
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(id),
                behavior TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL, sigma TEXT NOT NULL, kql TEXT NOT NULL,
                spl TEXT NOT NULL, telemetry TEXT NOT NULL, rationale TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft', pattern_score INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS rule_evidence (
                rule_id TEXT NOT NULL REFERENCES rules(id),
                evidence_id INTEGER NOT NULL REFERENCES evidence(id),
                PRIMARY KEY(rule_id,evidence_id)
            );
            CREATE TABLE IF NOT EXISTS external_inventory (
                id TEXT PRIMARY KEY, title TEXT NOT NULL, behavior TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE, source_url TEXT NOT NULL,
                pattern_score INTEGER NOT NULL DEFAULT 0, evidence_ids TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL,
                target TEXT NOT NULL, detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                day TEXT PRIMARY KEY, delivered_at TEXT NOT NULL, channel TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_cves (
                report_id TEXT NOT NULL, cve_id TEXT NOT NULL,
                PRIMARY KEY (report_id, cve_id)
            );
            CREATE TABLE IF NOT EXISTS environment_config (
                id INTEGER PRIMARY KEY CHECK(id=1), profile TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS environment_assets (
                asset_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, product TEXT NOT NULL,
                version TEXT NOT NULL, confirmed_cves TEXT NOT NULL,
                internet_exposed INTEGER NOT NULL, criticality TEXT NOT NULL,
                asset_role TEXT NOT NULL, imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS poll_state (
                id INTEGER PRIMARY KEY CHECK(id=1), lease_until TEXT,
                last_started TEXT, last_completed TEXT, last_result TEXT
            );
            CREATE TABLE IF NOT EXISTS source_state (
                name TEXT PRIMARY KEY, last_success TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_attempts (
                name TEXT PRIMARY KEY, attempted_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ok','partial','error')),
                records INTEGER NOT NULL DEFAULT 0, detail TEXT
            );
            CREATE TABLE IF NOT EXISTS alert_queue (
                threat_id TEXT PRIMARY KEY REFERENCES threats(id),
                queued_at TEXT NOT NULL, sent_at TEXT
            );
            CREATE TABLE IF NOT EXISTS article_inspection_queue (
                threat_id TEXT NOT NULL REFERENCES threats(id), source_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                next_try TEXT NOT NULL, last_error TEXT, inspected_at TEXT,
                PRIMARY KEY(threat_id,source_url)
            );
            CREATE TABLE IF NOT EXISTS article_behavior_leads (
                id INTEGER PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(id),
                source_url TEXT NOT NULL, sha256 TEXT NOT NULL, behavior TEXT NOT NULL,
                paragraph INTEGER NOT NULL, excerpt TEXT NOT NULL,
                first_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'analyst_review_required',
                UNIQUE(threat_id,source_url,sha256,behavior)
            );
            CREATE TABLE IF NOT EXISTS framework_snapshots (
                name TEXT PRIMARY KEY, version TEXT NOT NULL, source_url TEXT NOT NULL,
                sha256 TEXT NOT NULL, fetched_at TEXT NOT NULL, entries TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS custom_rule_specs (
                rule_id TEXT PRIMARY KEY REFERENCES rules(id), spec TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS custom_rule_observations (
                evidence_id INTEGER PRIMARY KEY REFERENCES evidence(id), fingerprint TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analyst_workspace_notes (
                id INTEGER PRIMARY KEY, threat_id TEXT NOT NULL REFERENCES threats(id),
                note_type TEXT NOT NULL CHECK(note_type IN ('telemetry_fields','benign_example','feedback')),
                content TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inventory_declaration (
                id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL,
                complete INTEGER NOT NULL, declared_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rule_tests (
                id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES rules(id),
                rule_hash TEXT NOT NULL, tested_at TEXT NOT NULL,
                sample_size INTEGER NOT NULL, counts TEXT NOT NULL, cases TEXT NOT NULL,
                sample_source TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS corroboration_reviews (
                id INTEGER PRIMARY KEY, rule_kind TEXT NOT NULL CHECK(rule_kind IN ('local','external')),
                rule_id TEXT NOT NULL, threat_id TEXT NOT NULL REFERENCES threats(id),
                source_url TEXT NOT NULL, paragraph INTEGER NOT NULL, behavior TEXT NOT NULL,
                excerpt TEXT NOT NULL, fingerprint TEXT NOT NULL, matched_rule_status TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
                decided_at TEXT, decided_reason TEXT, evidence_id INTEGER,
                UNIQUE(rule_kind,rule_id,threat_id,source_url,paragraph,behavior)
            );
            CREATE TABLE IF NOT EXISTS research_page_inspections (
                threat_id TEXT NOT NULL REFERENCES threats(id), url TEXT NOT NULL,
                role TEXT NOT NULL, via TEXT,
                status TEXT NOT NULL CHECK(status IN ('inspected','publisher_blocked','unreadable','failed','not_allowlisted')),
                detail TEXT, sha256 TEXT, paragraphs_scanned INTEGER, inspected_at TEXT NOT NULL,
                PRIMARY KEY(threat_id,url)
            );
            CREATE TABLE IF NOT EXISTS research_outcomes (
                threat_id TEXT PRIMARY KEY REFERENCES threats(id),
                status TEXT NOT NULL CHECK(status IN ('completed_insufficient_detail',
                    'observables_need_analyst_verification','no_readable_source')),
                completed_at TEXT NOT NULL, detail TEXT NOT NULL
            );
        """)
        # Existing local stores from the first release remain usable.
        for table, columns in {
            "threats": {"kind": "TEXT NOT NULL DEFAULT 'advisory'", "indicator": "TEXT",
                        "indicator_type": "TEXT", "confidence": "INTEGER", "expires_at": "TEXT"},
            "rules": {"expires_at": "TEXT", "rejected_reason": "TEXT", "rejected_at": "TEXT"},
            "evidence": {"source_name": "TEXT"},
            "source_state": {"total_records": "INTEGER NOT NULL DEFAULT 0",
                              "last_error": "TEXT", "last_error_at": "TEXT"},
        }.items():
            present = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in present:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def row_dict(row):
    if row is None:
        return None
    out = dict(row)
    for key in ("affected", "sources"):
        if key in out:
            out[key] = json.loads(out[key])
    return out
