from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PreflightGuardTests(unittest.TestCase):
    def test_preflight_is_read_only_and_checks_ha_image_memory_and_ports(self) -> None:
        source = (ROOT / "scripts/preflight.sh").read_text(encoding="utf-8")
        for required in (
            "desiredVotingNodes",
            "docker image inspect",
            "RepoDigests",
            "validate_host_memory.py",
            "PortBindings",
            "OPENBAO_PLUGIN_BINARY",
            'Destination == "/openbao/plugins"',
            "OPENBAO_PREFLIGHT=PASS",
        ):
            self.assertIn(required, source)
        for forbidden in ("bao write", "bao delete", "docker compose up", "operator init"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
