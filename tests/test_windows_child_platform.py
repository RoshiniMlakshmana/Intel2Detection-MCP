"""Platform typing regression: a Windows .exe CHILD is Windows process telemetry.

Synthetic prose only; no 2026 holdout report is ingested or rescored here.
"""
import unittest

from threat_research import custom_rules, proposal_pass


class ProcessPlatformTypingTests(unittest.TestCase):
    def spec(self, paragraph):
        return proposal_pass.behavior_spec({
            "quoted_paragraph": paragraph,
            "observable": {"lexical_behavior": "process_chain"}
        })

    def test_child_with_exe_extension_sets_windows_even_if_parent_has_no_extension(self):
        spec = self.spec(
            "The fictional attacker used PowerShell to launch helper.exe during a simulated malware run.")
        self.assertIsNotNone(spec)
        self.assertEqual(spec["event_family"], "process_creation")
        self.assertEqual(spec["platform"], "windows")
        self.assertEqual({p["field"]: p["value"] for p in spec["predicates"]},
                         {"ParentImage": "PowerShell", "Image": "helper.exe"})
        self.assertEqual(custom_rules.validate_spec(spec)["platform"], "windows")

    def test_windows_exe_parent_remains_windows(self):
        spec = self.spec("The attacker used cmd.exe to launch PowerShell during malware execution.")
        self.assertIsNotNone(spec)
        self.assertEqual(spec["platform"], "windows")
        self.assertEqual(spec["predicates"][0]["value"], "cmd.exe")

    def test_linux_bare_bash_child_stays_linux(self):
        spec = self.spec("The attacker used bash to launch curl during malicious activity.")
        self.assertIsNotNone(spec)
        self.assertEqual(spec["platform"], "linux")
        self.assertEqual({p["field"]: p["value"] for p in spec["predicates"]},
                         {"ParentImage": "bash", "Image": "curl"})

    def test_child_extension_in_mixed_case_remains_windows(self):
        spec = self.spec("The malicious loader used python to launch Helper.EXE on the device.")
        self.assertIsNotNone(spec)
        self.assertEqual(spec["platform"], "windows")


if __name__ == "__main__":
    unittest.main()
