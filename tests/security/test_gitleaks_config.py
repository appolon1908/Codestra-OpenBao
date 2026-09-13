from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GitleaksConfigTests(unittest.TestCase):
    def test_only_exact_documented_false_positives_are_allowed(self) -> None:
        source = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        self.assertEqual(source.count("[[allowlists]]"), 6)
        self.assertIn("useDefault = true", source)
        self.assertIn(r"^codestra/runtime-v1/desired-state\.json$", source)
        self.assertIn(r"^15m-default-1h-maximum$", source)
        self.assertIn("Non-secret database lease policy duration", source)
        self.assertEqual(source.count('condition = "AND"'), 5)
        self.assertEqual(source.count('regexTarget = "line"'), 5)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
