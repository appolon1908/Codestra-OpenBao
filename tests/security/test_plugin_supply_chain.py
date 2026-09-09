from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_plugin_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("verify_plugin_supply_chain", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PluginSupplyChainTests(unittest.TestCase):
    def test_committed_plugin_has_zero_high_critical(self) -> None:
        components, observations = MODULE.validate(MODULE.SBOM, MODULE.REPORT)
        self.assertGreaterEqual(components, 50)
        self.assertEqual(observations, 0)

    def test_high_finding_fails_closed(self) -> None:
        report = json.loads(MODULE.REPORT.read_text(encoding="utf-8"))
        report["Results"][0].setdefault("Vulnerabilities", []).append(
            {"VulnerabilityID": "CVE-TEST", "PkgName": "test", "Severity": "HIGH"}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plugin_unresolved_high_critical"):
                MODULE.validate(MODULE.SBOM, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
