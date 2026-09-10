from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INITIALIZER = ROOT / "scripts" / "initialize.sh"


def test_initializer_requires_pgp_encryption_for_all_recovery_material():
    text = INITIALIZER.read_text()
    assert "-key-shares=5" in text
    assert "-key-threshold=3" in text
    assert "-pgp-keys=\"$pgp_csv\"" in text
    assert "-root-token-pgp-key=\"$root_token_pgp_key\"" in text
    assert "OPENBAO_UNSEAL_PGP_KEY_FILES" in text
    assert "OPENBAO_ROOT_TOKEN_PGP_KEY_FILE" in text
    assert "PLAINTEXT_RECOVERY_MATERIAL_PERSISTED=NO" in text


def test_initializer_uses_six_distinct_offline_public_keys():
    text = INITIALIZER.read_text()
    assert "Exactly five unseal PGP public-key files are required." in text
    assert "All five unseal keys and the root-token key must be distinct." in text
    assert '[[ "$unique_count" -eq 6 ]]' in text


def test_raw_init_response_is_ram_backed_and_never_the_custody_artifact():
    text = INITIALIZER.read_text()
    assert "OPENBAO_INIT_RAM_ROOT:-/dev/shm" in text
    assert 'raw_json="$raw_dir/init.json"' in text
    assert 'bao operator init \\' in text
    assert '>"$raw_json"' in text
    assert 'unseal-share-$((index + 1)).pgp.b64' in text
    assert "initial-root-token.pgp.b64" in text


def test_old_plaintext_custody_contract_is_removed():
    text = INITIALIZER.read_text()
    assert "OPENBAO_INIT_CUSTODY_FILE" not in text
    assert 'bao operator init -key-shares=5 -key-threshold=3 -format=json > "$partial"' not in text
