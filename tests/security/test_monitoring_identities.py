"""Monitoring-plane workload identities: exact prefixes, own-environment issuer, no cross reads."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
MONITORING_IDENTITIES = {
    "grafana-runtime": "observability/grafana/",
    "alertmanager-runtime": "observability/alertmanager/",
    "alloy-collector": "observability/alloy/",
    "otel-gateway": "observability/otel-gateway/",
    "loki-runtime": "observability/loki/",
    "tempo-runtime": "observability/tempo/",
    "redis-exporter": "observability/exporters/redis/",
    "postgres-exporter": "observability/exporters/postgres/",
    "superset-analytics": "analytics/superset/",
}
CREDENTIAL_FREE_COMPONENTS = ("node-exporter", "cadvisor", "blackbox-exporter")


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class MonitoringIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = load("config/workload-secret-authority.v1.json")
        self.roles = {(r["environment"], r["serviceIdentity"]): r for r in self.authority["roles"]}
        self.jwt = load("openbao/auth/jwt-roles.v1.json")
        self.jwt_roles = {r["name"]: r for r in self.jwt["roles"]}
        self.auth_config = load("config/auth/keycloak-jwt.v1.json")

    def test_every_monitoring_identity_exists_only_where_the_platform_runs(self) -> None:
        for identity, prefix in MONITORING_IDENTITIES.items():
            for environment in ("staging", "production"):
                role = self.roles[(environment, identity)]
                self.assertEqual(role["pathPrefixes"], [f"codestra/{environment}/{prefix}"])
                self.assertEqual(role["operations"], ["read"])
                self.assertEqual(role["tokenMaximumTtlSeconds"], 300)
                self.assertFalse(role["providerBusinessEffectsEnabled"])
                self.assertFalse(role["runtimeBindingAuthorized"])
            for environment in ("development", "test"):
                self.assertNotIn((environment, identity), self.roles)

    def test_credential_free_components_have_no_identity(self) -> None:
        identities = {r["serviceIdentity"] for r in self.authority["roles"]}
        for component in CREDENTIAL_FREE_COMPONENTS:
            self.assertNotIn(component, identities)

    def test_prometheus_reads_only_its_metrics_client_and_scrape_credentials(self) -> None:
        role = self.roles[("production", "prometheus-openbao")]
        self.assertEqual(
            role["pathPrefixes"],
            [
                "codestra/production/observability/openbao/metrics-client/",
                "codestra/production/observability/prometheus/scrape-credentials/",
            ],
        )
        policy = (ROOT / "openbao/policies/production/prometheus-openbao.hcl").read_text(encoding="utf-8")
        self.assertIn('path "sys/metrics"', policy)
        self.assertNotIn("observability/grafana", policy)

    def test_no_monitoring_identity_can_read_another_workload(self) -> None:
        for environment in ("staging", "production"):
            monitoring = {
                identity: self.roles[(environment, identity)]["pathPrefixes"]
                for identity in MONITORING_IDENTITIES
            }
            for identity, prefixes in monitoring.items():
                for other, other_prefixes in monitoring.items():
                    if other == identity:
                        continue
                    for prefix in prefixes:
                        for other_prefix in other_prefixes:
                            self.assertFalse(
                                other_prefix.startswith(prefix) or prefix.startswith(other_prefix),
                                f"{identity} and {other} overlap in {environment}",
                            )
                policy = (ROOT / f"openbao/policies/{environment}/{identity}.hcl").read_text(encoding="utf-8")
                self.assertNotIn("middleware/", policy)
                self.assertNotIn("odoo/", policy)
                self.assertNotIn('path "sys/metrics"', policy)
                self.assertIn('path "sys/*" {\n  capabilities = ["deny"]', policy)
                self.assertIn('path "auth/token/create*" {\n  capabilities = ["deny"]', policy)

    def test_superset_identity_reads_only_analytics_paths(self) -> None:
        for environment in ("staging", "production"):
            policy = (ROOT / f"openbao/policies/{environment}/superset-analytics.hcl").read_text(encoding="utf-8")
            self.assertIn(f'path "codestra/data/{environment}/analytics/superset/*"', policy)
            self.assertNotIn("observability/", policy)

    def test_every_role_binds_its_own_environment_issuer(self) -> None:
        expected = self.auth_config["issuersByEnvironment"]
        self.assertEqual(self.authority["issuersByEnvironment"], expected)
        self.assertEqual(expected["production"], PRODUCTION_ISSUER)
        self.assertEqual(expected["staging"], STAGING_ISSUER)
        self.assertFalse(self.auth_config["foreignIssuerAccepted"])
        for role in self.authority["roles"]:
            name = f"{role['serviceIdentity']}-{role['environment']}"
            expression = self.jwt_roles[name]["payload"]["cel_program"]["expression"]
            issuers = re.findall(r"claims\.iss == '([^']+)'", expression)
            self.assertEqual(issuers, [expected[role["environment"]]], name)
            self.assertIn(f"claims.codestra_environment == '{role['environment']}'", expression)
            self.assertIn(f"claims.azp == '{role['serviceIdentity']}'", expression)
            self.assertIn("'openbao' in claims.aud", expression)
            self.assertIn("int(claims.exp) - int(claims.iat) <= 300", expression)
            self.assertIn("'jti' in claims", expression)
            self.assertEqual(self.jwt_roles[name]["payload"]["bound_audiences"], ["openbao"])

    def test_only_the_production_mount_trusts_the_production_issuer(self) -> None:
        by_environment = self.jwt["mountConfigurationByEnvironment"]
        self.assertEqual(set(by_environment), {"development", "test", "staging", "production"})
        for environment, mount in by_environment.items():
            self.assertEqual(mount["jwt_supported_algs"], ["RS256"])
            self.assertEqual(mount["default_role"], "")
            if environment == "production":
                self.assertEqual(mount["bound_issuer"], PRODUCTION_ISSUER)
            else:
                self.assertNotEqual(mount["bound_issuer"], PRODUCTION_ISSUER)
                self.assertEqual(mount["bound_issuer"], STAGING_ISSUER)
        self.assertFalse(self.jwt["foreignIssuerAccepted"])

    def test_staging_roles_reject_production_issuer_and_environment(self) -> None:
        expression = self.jwt_roles["middleware-api-staging"]["payload"]["cel_program"]["expression"]
        self.assertNotIn(PRODUCTION_ISSUER, expression)
        self.assertIn("claims.codestra_environment == 'staging'", expression)
        policy = (ROOT / "openbao/policies/staging/middleware-api.hcl").read_text(encoding="utf-8")
        self.assertIn('path "codestra/data/production/*" {\n  capabilities = ["deny"]', policy)


if __name__ == "__main__":
    unittest.main()
