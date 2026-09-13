from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "render_agent_config", ROOT / "scripts/render_agent_config.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AgentDeliveryTests(unittest.TestCase):
    def test_bundle_is_file_only_fail_closed_and_exactly_scoped(self) -> None:
        bundle = MODULE.render(
            "staging",
            "kong-gateway",
            "codestra/staging/kong/runtime",
            "/run/codestra-secrets/kong-gateway/runtime.json",
            10001,
            10001,
        )
        config = bundle["agent.hcl"]
        self.assertIn('method "jwt"', config)
        self.assertIn('role                        = "kong-gateway-staging"', config)
        self.assertIn('perms                = "0400"', config)
        self.assertIn("exit_on_retry_failure         = true", config)
        self.assertIn("error_on_missing_key = true", config)
        self.assertIn("remove_jwt_after_reading    = true", config)
        self.assertNotIn("sink ", config)
        self.assertNotIn("env_template", config)
        rendered_template = next(value for key, value in bundle.items() if key.endswith(".ctmpl"))
        self.assertIn('secret "codestra/data/staging/kong/runtime"', rendered_template)

    def test_cross_service_and_cross_environment_paths_are_rejected(self) -> None:
        for path in (
            "codestra/production/kong/runtime",
            "codestra/staging/middleware/api/runtime",
            "codestra/staging/kong/../middleware/runtime",
            "codestra/staging/kong/*",
        ):
            with self.assertRaises(ValueError):
                MODULE.render(
                    "staging",
                    "kong-gateway",
                    path,
                    "/run/codestra-secrets/kong-gateway/runtime.json",
                    10001,
                    10001,
                )

    def test_destination_cannot_escape_service_owned_runtime_directory(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.render(
                "staging",
                "kong-gateway",
                "codestra/staging/kong/runtime",
                "/run/codestra-secrets/middleware-api/runtime.json",
                10001,
                10001,
            )

    def test_root_owned_consumer_contract_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.render(
                "staging",
                "kong-gateway",
                "codestra/staging/kong/runtime",
                "/run/codestra-secrets/kong-gateway/runtime.json",
                0,
                0,
            )


if __name__ == "__main__":
    unittest.main()
