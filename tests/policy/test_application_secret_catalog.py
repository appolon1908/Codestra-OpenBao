"""Application coverage, isolation and file-delivery admission tests."""
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("application_renderer", ROOT / "scripts/render_application_secrets.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ApplicationSecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(MODULE.CATALOG.read_text())
        cls.authority = json.loads((ROOT / "config/workload-secret-authority.v1.json").read_text())

    def test_exact_requested_repository_coverage(self):
        expected = {"beyvra-frontend", "beyvra-backend", "Moneybee-frontend-", "Moneybee-Backend",
                    "transportaion-Frontend", "transportation-backend-", "LARIM-A-Fornt-end",
                    "LARIM-A-Backend", "Breero.com", "booked4seasons", "Frontend-Resturant-"}
        rows = self.catalog["repositories"]
        self.assertEqual(len(rows), 11)
        self.assertEqual({r["repository"] for r in rows}, {"appolon1908-hue/" + n for n in expected})
        self.assertIs(self.catalog["runtimeApplyAuthorized"], False)
        self.assertIs(self.catalog["browserSecretAccess"], False)
        self.assertTrue(all(r["runtimeVerified"] is False for r in rows))

    def test_browser_and_unimplemented_backends_have_no_secret_roles(self):
        owners = {w["repository"] for w in self.catalog["workloads"]}
        for row in self.catalog["repositories"]:
            if row["kind"] not in {"backend", "fullstack"}:
                self.assertNotIn(row["repository"], owners)

    def test_workload_namespaces_do_not_overlap(self):
        expected = {"moneybee-api", "larimia-api", "breero-api", "beyvra-api",
                    "beyvra-market-data", "beyvra-funding", "beyvra-trading-executor"}
        workloads = self.catalog["workloads"]
        self.assertEqual({w["serviceIdentity"] for w in workloads}, expected)
        self.assertEqual(len(workloads), len(expected))
        for workload in workloads:
            prefix = workload["namespacePrefix"]
            for other in workloads:
                if other is not workload:
                    self.assertFalse(prefix.startswith(other["namespacePrefix"]))
            for environment in ("development", "test", "staging", "production"):
                role = next(r for r in self.authority["roles"] if r["serviceIdentity"] == workload["serviceIdentity"] and r["environment"] == environment)
                self.assertEqual(role["pathPrefixes"], [f"codestra/{environment}/{prefix}"])
                self.assertEqual(role["operations"], ["read"])

    def test_all_bindings_render_with_private_files_and_exact_environment(self):
        for workload in self.catalog["workloads"]:
            for environment in ("development", "test", "staging", "production"):
                identity = workload["serviceIdentity"]
                with self.subTest(identity=identity, environment=environment):
                    bundle = MODULE.render(identity, environment, [b["setting"] for b in workload["bindings"]], 10001, 10001)
                    manifest = json.loads(bundle["manifest.json"])
                    self.assertEqual(len(manifest["bindings"]), len(workload["bindings"]))
                    self.assertEqual(bundle["agent.hcl"].count('method "jwt"'), 1)
                    self.assertNotIn("sink ", bundle["agent.hcl"])
                    self.assertNotIn("env_template", bundle["agent.hcl"])
                    self.assertEqual(bundle["agent.hcl"].count('perms                = "0400"'), len(workload["bindings"]))
                    for binding in manifest["bindings"]:
                        self.assertEqual(binding["logicalSecretPath"], f"codestra/{environment}/{workload['namespacePrefix']}{binding['secretName']}")
                        self.assertTrue(binding["destination"].startswith(f"/run/codestra-secrets/{identity}/"))
                    self.assertIs(manifest["secretValuesIncluded"], False)
                    self.assertIs(manifest["runtimeApplyAuthorized"], False)

    def test_optional_provider_secrets_are_not_required_for_disabled_integrations(self):
        bundle = MODULE.render("moneybee-api", "staging", [], 10001, 10001)
        self.assertNotIn("STRIPE_SECRET_KEY", bundle["consumer.env.example"])
        self.assertIn("DATABASE_URL_FILE", bundle["consumer.env.example"])

    def test_unknown_or_duplicate_secrets_fail_closed(self):
        for optional in (["ROOT_TOKEN"], ["DATABASE_URL", "DATABASE_URL"]):
            with self.assertRaises(ValueError):
                MODULE.render("moneybee-api", "production", optional, 10001, 10001)

    def test_browser_identity_and_wrong_environment_fail_closed(self):
        for identity, environment in (("beyvra-frontend", "production"), ("moneybee-api", "other")):
            with self.assertRaises(ValueError):
                MODULE.render(identity, environment, [], 10001, 10001)

    def test_beyvra_runtime_never_receives_financial_or_market_provider_keys(self):
        runtime = next(w for w in self.catalog["workloads"] if w["serviceIdentity"] == "beyvra-api")
        settings = {b["setting"] for b in runtime["bindings"]}
        self.assertFalse(settings & {"API_KEY_ALPACA", "API_SECRET_ALPACA", "STRIPE_SECRET_KEY", "POLYGON_API_KEY"})
        source = (ROOT / "openbao/policies/production/beyvra-api.hcl").read_text()
        grants = re.findall(r'path "([^"]+)" \{\s+capabilities = \["read"', source)
        self.assertFalse(any("/funding/" in p or "/execution/" in p or "/market-data/" in p for p in grants))

    def test_shared_saas_plan_covers_tenancy_billing_metering_and_client_integrations(self):
        plan = json.loads((ROOT / "config/shared-saas-api-plan.v1.json").read_text())
        self.assertEqual(plan["status"], "PLANNED_NOT_IMPLEMENTED")
        self.assertIs(plan["runtimeApplyAuthorized"], False)
        self.assertIs(plan["newSecretAdmissionAuthorized"], False)
        self.assertEqual(set(plan["products"]), {"beyvra", "moneybee", "larimia", "breero", "transportation", "klyrow", "telnexa", "social"})
        tenancy = plan["tenancy"]
        self.assertEqual(tenancy["productDataBoundary"], "workspace")
        self.assertIs(tenancy["emailDomainGrantsMembership"], False)
        self.assertIs(tenancy["loginGrantsSubscription"], False)
        self.assertIs(tenancy["gatewayValidationReplacesBackendAuthorization"], False)
        ids = {item["id"] for item in plan["saasApiCategories"]}
        self.assertTrue({"organizations-workspaces", "subscriptions", "billing-payments", "feature-access-quotas", "usage-metering", "developer-credentials", "webhooks"} <= ids)
        client_ids = {item["id"] for item in plan["clientApiCapabilities"]}
        self.assertTrue({"google-sign-in", "email-sending", "email-marketing", "gmail-connection", "social-connections", "publishing-scheduling", "social-analytics", "outgoing-webhooks"} <= client_ids)
        self.assertIs(plan["identityAndConnections"]["googleLoginAndMailboxConsentSeparate"], True)
        self.assertIs(plan["identityAndConnections"]["providerTokensInBrowser"], False)
        self.assertIs(plan["billing"]["subscriptionMayMoveProductFunds"], False)
        self.assertTrue({"trading_balances", "loan_disbursements", "shipment_settlements", "provider_payouts"} <= set(plan["billing"]["excludedFunds"]))
        self.assertIs(plan["metering"]["publicMeterWriteAllowed"], False)
        self.assertIs(plan["metering"]["quotaReservationAtomicAcrossPoolAndWorkspace"], True)
        self.assertIs(plan["webhooks"]["signedTimestampAndRawBody"], True)


if __name__ == "__main__":
    unittest.main()
