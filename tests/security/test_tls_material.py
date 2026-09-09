from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify_tls_material.sh"


class TlsMaterialTests(unittest.TestCase):
    def run_command(self, directory: Path, *arguments: str) -> None:
        subprocess.run(
            ["openssl", *arguments],
            cwd=directory,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def issue_certificate(
        self, directory: Path, name: str, common_name: str, extensions: str
    ) -> None:
        self.run_command(
            directory, "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr",
            "-subj", f"/CN={common_name}",
        )
        (directory / f"{name}.ext").write_text(extensions, encoding="utf-8")
        self.run_command(
            directory, "x509", "-req", "-in", f"{name}.csr",
            "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", f"{name}.crt", "-days", "60", "-extfile", f"{name}.ext",
        )

    def test_valid_chains_names_dates_and_key_pairs_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.run_command(
                directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", "ca.key", "-out", "ca.crt", "-days", "60",
                "-subj", "/CN=Codestra test CA",
            )
            self.issue_certificate(
                directory,
                "server",
                "codestra-bao-development-01",
                "subjectAltName=DNS:codestra-bao-development-01,DNS:bao-development.codestra.internal\nextendedKeyUsage=serverAuth\n",
            )
            self.issue_certificate(
                directory,
                "client",
                "openbao-health-development",
                "extendedKeyUsage=clientAuth\n",
            )
            environment = os.environ | {
                "CODESTRA_ENVIRONMENT": "development",
                "OPENBAO_SERVER_CERT_FILE": str(directory / "server.crt"),
                "OPENBAO_SERVER_KEY_FILE": str(directory / "server.key"),
                "OPENBAO_SERVER_CA_FILE": str(directory / "ca.crt"),
                "CODESTRA_CLIENT_CA_FILE": str(directory / "ca.crt"),
                "OPENBAO_HEALTH_CLIENT_CERT_FILE": str(directory / "client.crt"),
                "OPENBAO_HEALTH_CLIENT_KEY_FILE": str(directory / "client.key"),
            }
            result = subprocess.run(
                [SCRIPT], cwd=ROOT, env=environment, check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("OPENBAO_TLS_MATERIAL=PASS", result.stdout)

            environment["OPENBAO_SERVER_KEY_FILE"] = str(directory / "client.key")
            result = subprocess.run(
                [SCRIPT], cwd=ROOT, env=environment, check=False,
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
