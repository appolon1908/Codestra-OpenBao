from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_environment_approval.sh"


class EnvironmentApprovalScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("jq") is None:
            self.skipTest("jq is required by the protected approval gate")
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.bin_dir = self.work / "bin"
        self.bin_dir.mkdir()
        self.response_file = self.work / "approvals.json"
        gh = self.bin_dir / "gh"
        gh.write_text(
            "#!/usr/bin/env bash\n"
            "set -Eeuo pipefail\n"
            "[[ \"$1\" == api ]]\n"
            "cat -- \"$GH_APPROVAL_RESPONSE_FILE\"\n",
            encoding="utf-8",
        )
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        if hasattr(self, "temp"):
            self.temp.cleanup()

    def run_gate(self, response: object) -> subprocess.CompletedProcess[str]:
        self.response_file.write_text(json.dumps(response), encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin_dir}:{env['PATH']}",
                "GH_APPROVAL_RESPONSE_FILE": str(self.response_file),
                "CODESTRA_ENVIRONMENT": "development",
                "GITHUB_REPOSITORY": "appolon1908-hue/Codestra-OpenBao",
                "GITHUB_RUN_ID": "123456",
                "OPENBAO_REQUIRED_REVIEWER": "kazan555",
                "OPENBAO_APPROVAL_ENVIRONMENT": "openbao-development-backup",
            }
        )
        return subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=self.work,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )

    def test_matching_top_level_approval_array_passes(self) -> None:
        result = self.run_gate(
            [
                {
                    "state": "approved",
                    "user": {"login": "kazan555"},
                    "environments": [{"name": "openbao-development-backup"}],
                }
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OPENBAO_PROTECTED_ENVIRONMENT_APPROVAL=PASS", result.stdout)

    def test_object_wrapper_fails_closed(self) -> None:
        result = self.run_gate(
            {
                "approvals": [
                    {
                        "state": "approved",
                        "user": {"login": "kazan555"},
                        "environments": [
                            {"name": "openbao-development-backup"}
                        ],
                    }
                ]
            }
        )
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_reviewer_fails_closed(self) -> None:
        result = self.run_gate(
            [
                {
                    "state": "approved",
                    "user": {"login": "not-kazan555"},
                    "environments": [{"name": "openbao-development-backup"}],
                }
            ]
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
