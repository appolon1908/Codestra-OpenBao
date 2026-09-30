"""The Postman collection stays read-only, token-free and inside the declared native API."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTION = ROOT / "tests/postman/openbao-native-readonly.postman_collection.json"
CONTRACT = ROOT / "codestra/api/service-contract.v1.json"


def template(path: str) -> re.Pattern[str]:
    return re.compile("^" + re.sub(r"\\\{[a-z]+\\\}", r"[^/]+", re.escape(path)) + "$")


class PostmanCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
        self.operations = json.loads(CONTRACT.read_text(encoding="utf-8"))["nativeApi"]["operations"]

    def test_every_request_maps_to_a_declared_read_only_operation(self) -> None:
        for item in self.collection["item"]:
            request = item["request"]
            path = request["url"].replace("{{baseUrl}}", "").replace("{{managedPolicy}}", "x")
            matches = [op for op in self.operations
                       if op["method"] == request["method"] and template(op["path"]).match(path)]
            with self.subTest(request=item["name"]):
                self.assertTrue(matches, path)
                self.assertTrue(all(op["access"] in {"read_only", "query"} for op in matches))

    def test_no_stored_tokens_side_requests_or_environment_values(self) -> None:
        text = COLLECTION.read_text(encoding="utf-8")
        self.assertNotIn("pm.sendRequest", text)
        self.assertNotIn("pm.environment.set", text)
        self.assertNotIn("baoToken\", \"value\"", text)
        keys = {variable["key"] for variable in self.collection["variable"]}
        self.assertNotIn("baoToken", keys)
        for item in self.collection["item"]:
            for header in item["request"].get("header", []):
                if header["key"] == "X-Vault-Token":
                    self.assertIn(header["value"], {"{{baoToken}}", "not-a-real-token"})

    def test_denial_cases_are_present(self) -> None:
        names = " ".join(item["name"] for item in self.collection["item"])
        self.assertIn("denied without a token", names)
        self.assertIn("forged token is denied", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
