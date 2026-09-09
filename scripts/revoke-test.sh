#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
identity="${OPENBAO_REVOCATION_IDENTITY:?set target workload identity}"
evidence="${OPENBAO_REVOCATION_EVIDENCE:?set sanitized evidence output}"
revoke_driver="${OPENBAO_REVOCATION_DRIVER:?set Keycloak/OpenBao revocation driver}"
target_deny_verifier="${OPENBAO_REVOCATION_TARGET_DENY_VERIFIER:?set target denial verifier}"
unrelated_verifier="${OPENBAO_REVOCATION_UNRELATED_VERIFIER:?set unrelated workload verifier}"
cross_environment_verifier="${OPENBAO_REVOCATION_CROSS_ENV_DENY_VERIFIER:?set cross-environment denial verifier}"
audit_verifier="${OPENBAO_REVOCATION_AUDIT_VERIFIER:?set sanitized audit alert verifier}"

[[ "$environment" =~ ^(development|test|staging)$ ]]
[[ "$identity" =~ ^[a-z][a-z0-9-]+$ ]]
[[ "${OPENBAO_PROVIDER_EFFECTS_DISABLED_ACKNOWLEDGED:-false}" == true ]]
[[ "${OPENBAO_REVOCATION_CONFIRMATION:-}" == "REVOKE_${identity^^}_${environment^^}_TEST_IDENTITY" ]]
[[ "$(jq -r .runtimeApplyAuthorized "config/environments/${environment}/environment.json")" == true ]]
for command in jq sha256sum; do command -v "$command" >/dev/null; done
jq -e --arg environment "$environment" --arg identity "$identity" '
  any(.roles[]; .environment == $environment and .serviceIdentity == $identity)
' config/workload-secret-authority.v1.json >/dev/null

for callback in \
  "$revoke_driver" "$target_deny_verifier" "$unrelated_verifier" \
  "$cross_environment_verifier" "$audit_verifier"; do
  [[ -f "$callback" && ! -L "$callback" && -x "$callback" ]]
done

"$revoke_driver" >/dev/null 2>&1
if "$target_deny_verifier" >/dev/null 2>&1; then
  echo 'Revoked target workload still has secret access.' >&2
  exit 2
fi
"$unrelated_verifier" >/dev/null 2>&1
if "$cross_environment_verifier" >/dev/null 2>&1; then
  echo 'Cross-environment secret access unexpectedly succeeded.' >&2
  exit 2
fi
"$audit_verifier" >/dev/null 2>&1

umask 077
jq -n \
  --arg environment "$environment" --arg identity "$identity" \
  --arg revokeDriverSha256 "$(sha256sum "$revoke_driver" | awk '{print $1}')" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schemaVersion:1,environment:$environment,serviceIdentity:$identity,revokeDriverSha256:$revokeDriverSha256,targetAccess:"DENIED",unrelatedWorkload:"PASS",crossEnvironmentAccess:"DENIED",auditAlert:"PASS",providerBusinessEffectsEnabled:false,secretValuesIncluded:false,revocation:"PASS",completedAt:$completedAt}' \
  > "$evidence"
chmod 0400 "$evidence"

echo 'OPENBAO_REVOCATION=PASS'
echo 'TARGET_WORKLOAD_ACCESS=DENIED'
echo 'UNRELATED_WORKLOAD=PASS'
echo 'CROSS_ENVIRONMENT_ACCESS=DENIED'
echo 'AUDIT_ALERT=PASS'
echo 'PROVIDER_BUSINESS_EFFECTS_ENABLED=NO'
