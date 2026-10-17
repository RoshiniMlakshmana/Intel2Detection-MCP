"""External evidence must not be invented; incomplete data is refused or unscored."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_external_labels import evaluate


class ExternalLabeledReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.events = root / "events.jsonl"
        self.labels = root / "labels.json"
        self.db = root / "nonexistent.sqlite3"
        raw = json.dumps({
            "event_id": "external-e1", "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "process_creation", "Image": "C:\\Windows\\system32\\mmc.exe",
            "ParentImage": "C:\\Windows\\explorer.exe"
        }).encode() + b"\n"
        self.events.write_bytes(raw)
        self.manifest = {
            "schema_version": 1, "provenance": "externally_verified_event_labels",
            "external_dataset_url": "https://example.org/source",
            "independent_label_evidence_url": "https://example.org/labels",
            "events_sha256": hashlib.sha256(raw).hexdigest(),
            "labels": [{"event_id": "external-e1", "expected_malicious": False,
                        "evidence": "externally asserted benign in example label manifest"}]
        }

    def save(self):
        self.labels.write_text(json.dumps(self.manifest))

    def test_without_rules_is_unscored_not_true_negative(self):
        self.save()
        out = evaluate(self.events, self.labels, self.db)
        self.assertEqual(out["status"], "UNSCORED_NO_STORED_RULES")
        self.assertIsNone(out["counts"])
        self.assertEqual(out["event_count"], 1)

    def test_refuse_unlabeled_or_missing_evidence(self):
        self.manifest["labels"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "Nonempty"):
            evaluate(self.events, self.labels, self.db)
        self.manifest["labels"] = [{"event_id": "external-e1", "expected_malicious": True, "evidence": ""}]
        self.save()
        with self.assertRaisesRegex(ValueError, "independently evidenced"):
            evaluate(self.events, self.labels, self.db)

    def test_refuse_unsupported_attestation(self):
        self.manifest["provenance"] = "analyst_authored_synthetic_scenarios_not_real_incident_logs"
        self.save()
        with self.assertRaisesRegex(ValueError, "independent"):
            evaluate(self.events, self.labels, self.db)

    def test_refuse_source_modification(self):
        self.save()
        self.events.write_bytes(self.events.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            evaluate(self.events, self.labels, self.db)

    def test_refuse_missing_event(self):
        self.manifest["labels"][0]["event_id"] = "other"
        self.save()
        with self.assertRaisesRegex(ValueError, "Unlabeled"):
            evaluate(self.events, self.labels, self.db)

    def test_refuse_inband_truth(self):
        event = json.loads(self.events.read_text())
        event["expected_malicious"] = False
        raw = (json.dumps(event) + "\n").encode()
        self.events.write_bytes(raw)
        self.manifest["events_sha256"] = hashlib.sha256(raw).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, "smuggle"):
            evaluate(self.events, self.labels, self.db)


if __name__ == "__main__":
    unittest.main()
