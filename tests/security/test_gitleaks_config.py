from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GitleaksConfigTests(unittest.TestCase):
    def test_only_exact_documented_false_positives_are_allowed(self) -> None:
        source = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        self.assertEqual(source.count("[[allowlists]]"), 7)
        self.assertIn("useDefault = true", source)
        self.assertIn(r"^codestra/runtime-v1/desired-state\.json$", source)
        self.assertIn(r"^15m-default-1h-maximum$", source)
        self.assertIn("Non-secret database lease policy duration", source)
        self.assertEqual(source.count('condition = "AND"'), 6)
        self.assertEqual(source.count('regexTarget = "line"'), 6)
        self.assertIn(r"^upstream/builtin/credential/token/cli\.go$", source)
        self.assertIn(r"^upstream/builtin/credential/jwt/path_config\.go$", source)
        self.assertIn(
            r"^upstream/builtin/logical/transit/path_derive_key\.go$", source
        )
        self.assertIn(r"^upstream/sdk/helper/certutil/helpers\.go$", source)
        self.assertIn(r"^upstream/sdk/helper/certutil/types\.go$", source)
        self.assertIn(r"^scripts/prepare_openbao_source_build\.py$", source)
        self.assertIn(
            r'^\s*"google\.golang\.org/genproto/googleapis/(?:api|rpc)": "v0\.0\.0-20260526163538-3dc84a4a5aaa",\s*$',
            source,
        )
        self.assertIn(
            "Public Go module pseudo-version for the reviewed grpc-go genproto graph",
            source,
        )
        self.assertIn("reviewed 2026-09-01 by platform-security", source)
        self.assertIn("reviewed 2026-09-04 by platform-security", source)


    def test_historical_registry_allowlist_remains_path_and_line_scoped(self) -> None:
        config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
        entry = config["allowlists"][-1]
        self.assertEqual(entry["condition"], "AND")
        self.assertEqual(entry["regexTarget"], "line")
        self.assertEqual(entry["paths"], [r"^\.codestra/validate-promotion\.py$"])
        self.assertEqual(len(entry["regexes"]), 1)
        registry = (
            'SECTIONS=["ob-01-kv'
            '","ob-02-auth","ob-'
            '03-policy","ob-04-d'
            'ynamic-creds","ob-0'
            '5-pki","ob-06-trans'
            'it","ob-07-rotation'
            '","ob-08-tenancy","'
            'ob-09-audit","ob-10'
            '-ha","ob-11-seal","'
            'ob-12-dr","ob-13-co'
            'ntrol-api","ob-14-i'
            'ntegrations","ob-15'
            '-cicd","ob-16-certi'
            'fication"]'
        )
        pattern = entry["regexes"][0]
        self.assertTrue(re.search(pattern, registry))
        self.assertTrue(re.search(pattern, "context line\n" + registry + "\ncontext line"))
        self.assertFalse(re.search(pattern, registry + " # changed"))
        self.assertFalse(re.search(pattern, registry + " token=real-secret"))
        self.assertFalse(re.search(pattern, 'SECTIONS=["ob-01-kv"]'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
