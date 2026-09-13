from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
INITIALIZER = ROOT / "scripts" / "initialize.sh"


class PgpOfflineInitializationTests(unittest.TestCase):
    """Keep the original custody invariants in the repository's unittest gate."""

    def test_initializer_requires_pgp_encryption_for_all_recovery_material(self):
        text = INITIALIZER.read_text()
        self.assertIn("-key-shares=5", text)
        self.assertIn("-key-threshold=3", text)
        self.assertIn('-pgp-keys="$pgp_csv"', text)
        self.assertIn('-root-token-pgp-key="$root_token_pgp_key"', text)
        self.assertIn("OPENBAO_UNSEAL_PGP_KEY_FILES", text)
        self.assertIn("OPENBAO_ROOT_TOKEN_PGP_KEY_FILE", text)
        self.assertIn("PLAINTEXT_RECOVERY_MATERIAL_PERSISTED=NO", text)

    def test_initializer_uses_six_distinct_offline_public_keys(self):
        text = INITIALIZER.read_text()
        self.assertIn("Exactly five unseal PGP public-key files are required.", text)
        self.assertIn("All five unseal keys and the root-token key must be distinct.", text)
        self.assertIn('[[ "$unique_count" -eq 6 ]]', text)

    def test_raw_init_response_is_ram_backed_and_never_the_custody_artifact(self):
        text = INITIALIZER.read_text()
        self.assertIn("OPENBAO_INIT_RAM_ROOT:-/dev/shm", text)
        self.assertIn('raw_json="$raw_dir/init.json"', text)
        self.assertIn("bao operator init", text)
        self.assertIn('>"$raw_json"', text)
        self.assertIn('unseal-share-$((index + 1)).pgp.b64', text)
        self.assertIn("initial-root-token.pgp.b64", text)

    def test_old_plaintext_custody_contract_is_removed(self):
        text = INITIALIZER.read_text()
        self.assertNotIn("OPENBAO_INIT_CUSTODY_FILE", text)
        self.assertNotIn('bao operator init -key-shares=5 -key-threshold=3 -format=json > "$partial"', text)


if __name__ == "__main__":
    unittest.main()
