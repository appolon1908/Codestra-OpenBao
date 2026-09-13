from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class MonitoringContractTests(unittest.TestCase):
    def test_prometheus_uses_private_mtls_and_file_token(self) -> None:
        config = yaml.safe_load((ROOT / "monitoring/prometheus/openbao-scrape.yml").read_text())
        job = config["scrape_configs"][0]
        self.assertEqual(job["scheme"], "https")
        self.assertEqual(job["authorization"]["credentials_file"], "/run/secrets/openbao-prometheus-token")
        self.assertFalse(job["tls_config"]["insecure_skip_verify"])
        self.assertNotIn("bearer_token", job)
        self.assertEqual(job["static_configs"][0]["targets"], ["codestra-bao-production-01:8200"])
        policy = (ROOT / "openbao/policies/production/prometheus-openbao.hcl").read_text()
        self.assertIn('path "sys/metrics" {\n  capabilities = ["read"]', policy)
        self.assertIn('path "sys/*" {\n  capabilities = ["deny"]', policy)

    def test_alerts_cover_required_failures_without_secret_labels(self) -> None:
        source = (ROOT / "monitoring/alerts/openbao-alerts.yml").read_text()
        alerts = yaml.safe_load(source)["groups"][0]["rules"]
        names = {item["alert"] for item in alerts}
        self.assertTrue({
            "OpenBaoSealed", "OpenBaoNoActiveLeader", "OpenBaoAuditRequestFailure",
            "OpenBaoAuthFailureSurge", "OpenBaoBackupStale", "OpenBaoBackupFailure",
            "OpenBaoRotationFailure", "OpenBaoRevocationFailure", "OpenBaoDriftDetected",
            "OpenBaoNotInitialized", "OpenBaoRaftQuorumBelowDesired",
            "OpenBaoExcessiveTokenCreation", "OpenBaoCredentialNearExpiry",
            "OpenBaoRestartLoop",
        } <= names)
        metrics_unavailable = next(
            item for item in alerts if item["alert"] == "OpenBaoMetricsUnavailable"
        )
        self.assertIn('absent(up{job="codestra-openbao"})', metrics_unavailable["expr"])
        for forbidden in ("secret_value", "client_secret", "unseal_key"):
            self.assertNotIn(forbidden, source.lower())

        audit_source = (
            ROOT / "monitoring/alerts/openbao-audit-loki-rules.yml"
        ).read_text()
        audit_rules = yaml.safe_load(audit_source)["groups"][0]["rules"]
        audit_names = {item["alert"] for item in audit_rules}
        self.assertTrue({
            "OpenBaoAuditStreamSilent", "OpenBaoRootTokenUsage",
            "OpenBaoPermissionDenialSurge", "OpenBaoPolicyModified",
            "OpenBaoControlPlaneConfigurationModified",
            "OpenBaoInitializationFailure", "OpenBaoAuthenticationFailureSurge",
        } <= audit_names)
        self.assertIn('| json | __error__=""', audit_source)
        for forbidden in ("secret_value", "client_secret", "unseal_key"):
            self.assertNotIn(forbidden, audit_source.lower())

    def test_dashboard_is_read_only_and_source_backed(self) -> None:
        dashboard = json.loads((ROOT / "monitoring/dashboards/codestra-openbao.json").read_text())
        self.assertFalse(dashboard["editable"])
        self.assertGreaterEqual(len(dashboard["panels"]), 18)
        titles = {panel["title"] for panel in dashboard["panels"]}
        self.assertTrue({
            "Initialized state", "Unsealed nodes", "Active leaders", "Standby nodes",
            "Raft voting peers", "Request rate", "Request latency", "Current tokens",
            "Current leases", "Lease expiration and revocation", "Raft storage activity",
            "Process memory and CPU", "Filesystem capacity", "Container restarts",
        } <= titles)
        self.assertEqual(dashboard["uid"], "codestra-openbao-v1")

    def test_runtime_exporter_contains_only_sanitized_state(self) -> None:
        source = (ROOT / "scripts/export_runtime_metrics.sh").read_text()
        for metric in (
            "codestra_openbao_initialized", "codestra_openbao_sealed",
            "codestra_openbao_raft_voting_peers",
            "codestra_openbao_raft_desired_voting_peers",
            "codestra_openbao_container_restarts_total",
            "codestra_openbao_filesystem_free_bytes",
            "codestra_openbao_filesystem_size_bytes",
        ):
            self.assertIn(metric, source)
        for forbidden in ("secret_value", "client_secret", "unseal_key", "BAO_TOKEN"):
            self.assertNotIn(forbidden, source)

    def test_audit_device_is_declarative_and_api_creation_stays_disabled(self) -> None:
        server = (ROOT / "openbao/openbao.hcl").read_text()
        template = (ROOT / "openbao/templates/openbao.hcl.tpl").read_text()
        for source in (server, template):
            self.assertIn('audit "file" "file-audit"', source)
            self.assertIn('file_path = "/openbao/audit/openbao-audit.jsonl"', source)
            self.assertIn('log_raw = "false"', source)
        repository_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "scripts").glob("*")
            if path.is_file()
        )
        self.assertNotIn("bao audit enable", repository_source)
        self.assertNotIn("unsafe_allow_api_audit_creation", server)


if __name__ == "__main__":
    unittest.main(verbosity=2)
