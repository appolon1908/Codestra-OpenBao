"""Read-only access to the protected source authority the kernel decides from."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

from .canonical import digest, sha256_bytes

ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = ("development", "test", "staging", "production")
RUNTIME_AUTHORITY_FILES = (
    "config/workload-secret-authority.v1.json",
    "openbao/auth/jwt-roles.v1.json",
    "config/audit/audit.v1.json",
    "config/secrets/engines.v1.json",
    "plugins/codestra-jwt-replay/plugin.v1.json",
)


class AuthorityError(ValueError):
    """The protected authority is missing, inconsistent or refuses the request."""


class Authority:
    def __init__(self, root: Path = ROOT) -> None:
        self.root = Path(root)
        base = self.root / "config/change-kernel"
        self.classification = self._load(base / "risk-classification.v1.json")
        self.registry = self._load(base / "resource-registry.v1.json")
        self.contract = self._load(base / "change-kernel.v1.json")
        self.classes: dict[str, dict[str, Any]] = self.classification["classes"]

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthorityError(f"authority_unreadable:{path.name}") from exc
        if not isinstance(value, dict):
            raise AuthorityError(f"authority_not_object:{path.name}")
        return value

    # --- environment and exclusion -------------------------------------------------

    def environment(self, name: str) -> dict[str, Any]:
        if name not in ENVIRONMENTS:
            raise AuthorityError(f"unknown_environment:{name!r}")
        document = self._load(self.root / f"config/environments/{name}/environment.json")
        if document.get("environment") != name:
            raise AuthorityError(f"environment_document_mismatch:{name}")
        return document

    def exclusion_key(self, name: str) -> str:
        """Server-resolved mutation lock key for the cluster that serves one environment."""
        document = self.environment(name)
        host = urllib.parse.urlsplit(str(document.get("clusterAddress", ""))).hostname
        if not host:
            raise AuthorityError(f"cluster_address_missing:{name}")
        return f"openbao:{name}:{host.lower().rstrip('.')}"

    def production_gate(self, name: str) -> dict[str, Any]:
        document = self.environment(name)
        flags = {path: self._load(self.root / path).get("runtimeApplyAuthorized") is True
                 for path in RUNTIME_AUTHORITY_FILES}
        flags[f"config/environments/{name}/environment.json"] = document.get("runtimeApplyAuthorized") is True
        return {
            "environment": name,
            "production": document.get("production") is True,
            "desiredVotingNodes": document.get("desiredVotingNodes"),
            "runtimeApplyAuthorizedFlags": flags,
            "runtimeApplyAuthorized": all(flags.values()),
        }

    def production_gate_digest(self, name: str) -> str:
        return digest(self.production_gate(name))

    def current_authority_checksums(self, recorded: dict[str, str]) -> dict[str, str]:
        current = {}
        for relative in recorded:
            path = (self.root / relative).resolve()
            if self.root.resolve() not in path.parents:
                raise AuthorityError(f"authority_path_outside_repository:{relative}")
            try:
                current[relative] = sha256_bytes(path.read_bytes())
            except OSError as exc:
                raise AuthorityError(f"authority_file_missing:{relative}") from exc
        return current

    # --- classification ------------------------------------------------------------

    def rank(self, risk_class: str) -> int:
        return int(self.classes[risk_class]["rank"])

    def plan_operation(self, kind: str, action: str) -> tuple[str, str]:
        """Return (resource kind, risk class) for one saved-plan operation."""
        resource_kind = self.registry["planOperationKinds"].get(kind)
        if resource_kind is None:
            raise AuthorityError(f"unregistered_operation_kind:{kind}")
        if action not in {"create", "update"}:
            raise AuthorityError(f"destructive_or_unknown_action:{kind}:{action}")
        risk_class = self.classification["operationKindClass"].get(kind)
        resource = self.registry["resources"][resource_kind]
        if risk_class is None or risk_class != resource["riskClass"]:
            raise AuthorityError(f"classification_registry_disagree:{kind}")
        if not self.classes[risk_class]["kernelExecutable"] or resource["executor"] == "none":
            raise AuthorityError(f"not_kernel_executable:{kind}")
        return resource_kind, risk_class

    def effective_class(self, classes: list[str], environment: str) -> str:
        if not classes:
            raise AuthorityError("empty_plan")
        highest = max(classes, key=self.rank)
        mutates = any(self.classes[name]["mutatesOpenBao"] for name in classes)
        overlay = self.classification["environmentOverlay"].get(environment)
        if overlay and mutates and self.rank(overlay) > self.rank(highest):
            return overlay
        return highest

    def native_operation(self, operation: dict[str, Any]) -> tuple[str, bool]:
        """Classify a native API operation by semantics; never by HTTP method."""
        rules = self.classification["nativeOperationSemantics"]
        category = operation["category"]
        risk_class = rules["overrides"].get(operation["id"])
        if risk_class is None:
            risk_class = rules["categoryClass"].get(category)
            if risk_class is None:
                raise AuthorityError(f"unclassified_native_category:{category}")
            if (operation.get("access") in rules["readOnlyAccess"]
                    and category not in rules["readOnlyAccessNeverDowngrades"]):
                risk_class = "READ_ONLY"
        sensitive = category in rules["sensitiveCategories"]
        return risk_class, sensitive

    # --- approval --------------------------------------------------------------------

    @property
    def required_approver(self) -> str:
        return str(self.contract["approval"]["requiredApprover"])

    @property
    def approval_max_seconds(self) -> int:
        return int(self.contract["approval"]["maximumValiditySeconds"])

    @property
    def lease_bounds(self) -> tuple[int, int]:
        exclusion = self.contract["exclusion"]
        return int(exclusion["defaultLeaseSeconds"]), int(exclusion["maximumLeaseSeconds"])
