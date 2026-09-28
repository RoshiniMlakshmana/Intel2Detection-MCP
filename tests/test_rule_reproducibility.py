"""Gap 5: reproducible rule checks. Replay a draft against analyst-labeled
positive/benign samples, record every match/miss with a hash of exactly what
was tested, and export the results -- clearly labeled as local reference
matching, with native SIEM validation left explicitly pending."""

import json
import tempfile
import unittest
from pathlib import Path

from threat_research import core, rule_repository, rules, soc_replay, store


def fictional_record(ident="CVE-2099-74001"):
    return {"id": ident, "title": "Fictional example vulnerability", "summary": "Synthetic fixture.",
            "source": "https://example.test/advisory", "claim": "Example advisory source.",
            "published": "2099-01-01", "updated": "2099-01-01", "kev": True, "affected": ["ExampleServer"]}


def write_events(directory, rows):
    file = Path(directory) / "events.jsonl"
    with file.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return file


SAMPLES = [
    {"event_id": "E01", "event_type": "process_creation", "timestamp": "2099-01-02T00:00:00Z",
     "scenario": "Fictional lab: web worker spawns cmd.exe after exploitation", "expected_malicious": True,
     "ParentImage": "C:\\inetpub\\w3wp.exe", "Image": "C:\\Windows\\System32\\cmd.exe"},
    {"event_id": "E02", "event_type": "process_creation", "timestamp": "2099-01-02T00:01:00Z",
     "scenario": "Fictional lab: routine service launches a shell", "expected_malicious": False,
     "ParentImage": "C:\\Windows\\System32\\services.exe", "Image": "C:\\Windows\\System32\\cmd.exe"},
    {"event_id": "E03", "event_type": "process_creation", "timestamp": "2099-01-02T00:02:00Z",
     "scenario": "Fictional lab: approved maintenance also spawns a shell from the web worker", "expected_malicious": False,
     "ParentImage": "C:\\inetpub\\w3wp.exe", "Image": "C:\\Windows\\System32\\cmd.exe"},
]


class RuleReproducibilityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "db.sqlite3"
        store.initialize(self.path)
        core.ingest([fictional_record()], self.path)
        eid = core.add_behavior_evidence("CVE-2099-74001", "https://example.test/report",
                                         "Observed web server launching cmd.exe", "web_server_shell", self.path)
        self.rule_id = rules.propose_rule("CVE-2099-74001", eid, self.path)["rule_id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_replay_records_every_match_and_miss_with_a_rule_hash(self):
        events_file = write_events(self.tmp.name, SAMPLES)
        result = soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        self.assertEqual(result["sample_size"], 3)
        self.assertEqual(result["counts"], {"tp": 1, "fp": 1, "fn": 0, "tn": 1})
        self.assertEqual(len(result["cases"]), 3)
        self.assertEqual(result["rule_id"], self.rule_id)
        self.assertEqual(len(result["rule_hash"]), 64)  # sha256 hex digest
        self.assertIn("Local reference matching against analyst-labeled samples", result["scope"])
        self.assertIn("not production SIEM accuracy", result["scope"])
        self.assertIn("native Splunk/Defender validation remains pending", result["scope"])

    def test_result_is_persisted_and_exported_into_the_repository_snapshot(self):
        events_file = write_events(self.tmp.name, SAMPLES)
        soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        with store.connection(self.path) as db:
            rows = db.execute("SELECT rule_id,rule_hash,sample_size FROM rule_tests WHERE rule_id=?", (self.rule_id,)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sample_size"], 3)

        repo_root = self.path.parent / "rule-repository"
        payload = json.loads((repo_root / "draft" / f"{self.rule_id}.json").read_text())
        self.assertEqual(len(payload["test_results"]), 1)
        self.assertEqual(payload["test_results"][0]["counts"], {"tp": 1, "fp": 1, "fn": 0, "tn": 1})
        self.assertEqual(payload["test_results"][0]["rule_hash"], rows[0]["rule_hash"])
        self.assertIn(str(events_file), payload["test_results"][0]["sample_source"])

    def test_hash_changes_when_the_tested_rule_text_changes(self):
        events_file = write_events(self.tmp.name, SAMPLES)
        first = soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET sigma=sigma||'\\n# analyst annotation' WHERE id=?", (self.rule_id,))
        second = soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        self.assertNotEqual(first["rule_hash"], second["rule_hash"])
        with store.connection(self.path) as db:
            count = db.execute("SELECT COUNT(*) FROM rule_tests WHERE rule_id=?", (self.rule_id,)).fetchone()[0]
        self.assertEqual(count, 2)  # both runs kept, not overwritten

    def test_multiple_runs_are_all_retained_for_reproducibility(self):
        events_file = write_events(self.tmp.name, SAMPLES)
        soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        payload = json.loads((self.path.parent / "rule-repository" / "draft" / f"{self.rule_id}.json").read_text())
        self.assertEqual(len(payload["test_results"]), 2)

    def test_unknown_rule_raises(self):
        events_file = write_events(self.tmp.name, SAMPLES)
        with self.assertRaisesRegex(ValueError, "unknown rule"):
            soc_replay.test_rule_against_samples("not-a-real-rule-id", events_file, self.path)

    def test_empty_events_file_raises(self):
        empty = write_events(self.tmp.name, [])
        with self.assertRaisesRegex(ValueError, "no records"):
            soc_replay.test_rule_against_samples(self.rule_id, empty, self.path)

    def test_expired_ioc_rule_cannot_be_tested_without_refresh(self):
        expiry_past = "2020-01-01T00:00:00Z"
        with store.connection(self.path) as db:
            db.execute("UPDATE rules SET expires_at=? WHERE id=?", (expiry_past, self.rule_id))
        events_file = write_events(self.tmp.name, SAMPLES)
        with self.assertRaisesRegex(ValueError, "expired"):
            soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)

    def test_malformed_or_unlabeled_sample_is_rejected_not_silently_skipped(self):
        bad = write_events(self.tmp.name, [{"event_id": "E01", "event_type": "process_creation",
                                            "timestamp": "2099-01-02T00:00:00Z", "scenario": "missing label"}])
        with self.assertRaisesRegex(ValueError, "scenario and a boolean"):
            soc_replay.test_rule_against_samples(self.rule_id, bad, self.path)

    def test_approved_rule_can_also_be_tested_and_snapshot_lands_in_approved_folder(self):
        rules.implement_rule(self.rule_id, "implement this rule", path=self.path)
        events_file = write_events(self.tmp.name, SAMPLES)
        soc_replay.test_rule_against_samples(self.rule_id, events_file, self.path)
        payload = json.loads((self.path.parent / "rule-repository" / "approved" / f"{self.rule_id}.json").read_text())
        self.assertEqual(payload["status"], "approved")
        self.assertEqual(len(payload["test_results"]), 1)


if __name__ == "__main__":
    unittest.main()
