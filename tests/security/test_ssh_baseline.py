from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SshBaselineTests(unittest.TestCase):
    def test_firewall_capture_uses_stateless_exact_port_rules(self) -> None:
        source = (ROOT / "scripts/capture_ssh_baseline.sh").read_text(encoding="utf-8")
        self.assertIn("'--stateless', 'list', 'ruleset'", source)
        self.assertIn("b'tcp dport 22'", source)
        self.assertIn("b'--dports'", source)
        self.assertNotIn("if b'22' in line", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
