"""Externally authored Sysmon event remains UNLABELED even if parser succeeds."""
import unittest
from pathlib import Path

from scripts import check_external_sysmon as target


class ExternalSysmonTests(unittest.TestCase):
    def test_external_event_parses_without_claiming_ground_truth(self):
        r = target.inspect(target.SAMPLE)
        self.assertEqual(r["sample_records"], 1)
        self.assertEqual(r["record_type"], "Sysmon Event 1")
        self.assertEqual(r["ground_truth_malicious_label"], None)
        self.assertEqual(r["rules_loaded"], 0)
        self.assertEqual(r["local_reference_match_count"], 0)
        self.assertTrue(r["observed_image"].lower().endswith("mmc.exe"))
        self.assertTrue(r["observed_parent_image"].lower().endswith("explorer.exe"))
        self.assertEqual(len(r["sha256_of_exact_xml_bytes"]), 64)

    def test_rejects_unrelated_event_and_unsafe_xml(self):
        sample = target.SAMPLE.read_bytes()
        with self.assertRaises(ValueError):
            target.parse_event(sample.replace(b"<EventID>1</EventID>", b"<EventID>3</EventID>"))
        with self.assertRaises(ValueError):
            target.parse_event(b'<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + sample)
        with self.assertRaises(ValueError):
            target.parse_event(b"x" * (target.LIMIT + 1))


if __name__ == "__main__":
    unittest.main()
