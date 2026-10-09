import json
from pathlib import Path

import pytest

from scripts.validate_environment_source_syntax import JSONC_FILES, parse_jsonc, validate_tree


def test_exact_typescript_jsonc_allowlist():
    assert JSONC_FILES == {
        "upstream/ui/tsconfig.json",
        "upstream/website/tsconfig.json",
    }
    for name in JSONC_FILES:
        parsed = parse_jsonc((Path(__file__).resolve().parents[1] / name).read_text())
        assert isinstance(parsed, dict) and "compilerOptions" in parsed


def test_jsonc_string_literal_and_comments():
    example = '{"url":"https://source.invalid/x//y", // comment\n "a":[1,2,],}'
    assert parse_jsonc(example) == {"url": "https://source.invalid/x//y", "a": [1, 2]}


def test_jsonc_broken_tokens_rejected():
    for text in ("{ bad }", '{"a":true, "b":}', '{"a": 1 /* unterminated'):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            parse_jsonc(text)


def test_non_typescript_json_cannot_use_comments(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.json").write_text('{"enabled":true // comment\n}')
    with pytest.raises(json.JSONDecodeError):
        validate_tree(tmp_path)
