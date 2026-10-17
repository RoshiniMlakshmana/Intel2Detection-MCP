"""Observable detection on independently recorded 4103 semantics; mock tests are not proof."""
import unittest
from scripts.detect_external_powershell_4103 import inspect_record

class PowerShell4103Tests(unittest.TestCase):
    def test_encoded_switch_matches_and_redacts(self):
        result = inspect_record({
            "source_name":"Microsoft-Windows-PowerShell", "event_id":4103,
            "record_number":"1", "@timestamp":"2026-01-01T00:00:00Z",
            "message":"Context:\n Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -noP -enc UwBlAGMAcgBlAHQA\n"
        })
        self.assertIsNotNone(result)
        self.assertEqual(result["attack_verdict"], "UNKNOWN_REQUIRES_INVESTIGATION")
        self.assertNotIn("UwBlAGMA", str(result))
    def test_ignore_other_event_family_or_unencoded(self):
        d={"source_name":"Microsoft-Windows-PowerShell","event_id":4103,
           "message":"Host Application = powershell.exe -NoProfile"}
        self.assertIsNone(inspect_record(d))
        self.assertIsNone(inspect_record({**d,"event_id":1,
            "message":"Host Application = powershell.exe -enc AAA"}))
        self.assertIsNone(inspect_record({**d,"source_name":"Microsoft-Windows-Sysmon",
            "message":"Host Application = powershell.exe -enc AAA"}))
if __name__=="__main__":
    unittest.main()
