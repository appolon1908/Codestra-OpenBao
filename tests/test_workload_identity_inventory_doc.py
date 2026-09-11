#!/usr/bin/env python3
"""Keep the workload identity inventory document aligned with generated source."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs/security/OPENBAO-WORKLOAD-IDENTITIES.md"
AUTHORITY = ROOT / "config/workload-secret-authority.v1.json"
INVENTORY = ROOT / "config/policies/workload-identities.v1.json"

ROW = re.compile(r"^\| `(?P<identity>[a-z0-9-]+)` \| (?P<owner>[a-z0-9-]+) \| (?P<environments>[a-z, ]+) \|")
COUNT = re.compile(r"There are (?P<roles>\d+)\s+prepared roles")
ALL_ENVIRONMENTS = ("development", "test", "staging", "production")


def documented_rows(text: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        match = ROW.match(line)
        if match:
            rows[match.group("identity")] = {
                "owner": match.group("owner"),
                "environments": match.group("environments").strip(),
            }
    return rows


class WorkloadIdentityInventoryDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = DOCUMENT.read_text(encoding="utf-8")
        cls.authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.rows = documented_rows(cls.document)
        cls.generated: dict[str, dict[str, object]] = {}
        for role in cls.authority["roles"]:
            entry = cls.generated.setdefault(
                role["serviceIdentity"], {"owner": role["owner"], "environments": []}
            )
            entry["environments"].append(role["environment"])

    def test_role_count_matches_generated_authority(self) -> None:
        match = COUNT.search(self.document)
        self.assertIsNotNone(match, "prepared role count sentence is missing")
        self.assertEqual(int(match.group("roles")), len(self.authority["roles"]))

    def test_every_generated_identity_is_documented_exactly_once(self) -> None:
        self.assertEqual(set(self.rows), set(self.generated))
        table_lines = [line for line in self.document.splitlines() if ROW.match(line)]
        self.assertEqual(len(table_lines), len(self.generated))

    def test_documented_owner_and_environments_match_authority(self) -> None:
        for identity, documented in self.rows.items():
            generated = self.generated[identity]
            self.assertEqual(documented["owner"], generated["owner"], identity)
            environments = generated["environments"]
            self.assertEqual(len(environments), len(set(environments)), identity)
            if set(environments) == set(ALL_ENVIRONMENTS):
                expected = "all"
            else:
                expected = ", ".join(e for e in ALL_ENVIRONMENTS if e in environments)
            self.assertEqual(documented["environments"], expected, identity)

    def test_inventory_and_authority_agree(self) -> None:
        inventory = {item["serviceIdentity"] for item in self.inventory["identities"]}
        self.assertEqual(inventory, set(self.generated))
        self.assertIs(self.inventory["runtimeBindingsAuthorized"], False)
        self.assertIs(self.authority["runtimeApplyAuthorized"], False)


if __name__ == "__main__":
    unittest.main()
