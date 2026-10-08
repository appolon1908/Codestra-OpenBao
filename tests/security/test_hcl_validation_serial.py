from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class HclValidationSerialTests(unittest.TestCase):
    def test_validation_serial_never_falls_back_to_shared_tmp_name(self) -> None:
        source = (ROOT / "scripts/validate_hcl.sh").read_text(encoding="utf-8")
        self.assertIn('-CAserial "$verify_dir/ca-cert.srl" -CAcreateserial', source)
        self.assertIn("mktemp -d", source)
        self.assertIn("trap cleanup EXIT", source)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is not installed")
    def test_dot_named_temporary_root_keeps_ca_serial_private(self) -> None:
        # A dotted mktemp directory previously caused openssl to infer
        # /tmp/tmp.srl instead of a file inside the owned temp directory.
        with tempfile.TemporaryDirectory(prefix="codestra-bao-fixture.", dir="/tmp") as directory:
            root = Path(directory)
            ca_key, ca_cert = root / "ca-key", root / "ca-cert"
            csr, server_key = root / "server-csr", root / "server-key"
            serial, server_cert = root / "ca-cert.srl", root / "server-cert"
            extensions = root / "server-ext"
            extensions.write_text(
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                "extendedKeyUsage=serverAuth\n", encoding="utf-8"
            )
            cmds = [
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
                 "-subj", "/CN=Codestra OpenBao validation CA"],
                ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(server_key), "-out", str(csr),
                 "-subj", "/CN=codestra-bao-production-01",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                 "-CAkey", str(ca_key), "-CAserial", str(serial),
                 "-CAcreateserial", "-out", str(server_cert),
                 "-days", "1", "-extfile", str(extensions)],
            ]
            for command in cmds:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
            self.assertTrue(serial.is_file())
            self.assertTrue(server_cert.is_file())
            self.assertEqual(serial.parent, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
