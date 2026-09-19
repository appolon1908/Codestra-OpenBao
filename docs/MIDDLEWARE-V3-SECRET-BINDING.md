# Middleware V3 secret-reference binding (Lane E preparation)

Status: **PREPARED_DISABLED**. Nothing here initialises, unseals, rotates or binds a
runtime. It records how the Middleware V3 command kernel will consume OpenBao so that
the binding can be re-pinned and certified the moment `V3_FINAL_SHA` exists.

| Pin | Value |
| --- | --- |
| `MIDDLEWARE_PREP_BASE` | `22d023a9c65b0789a0f7ee6c28548753521a9eff` |
| `V3_FINAL_SHA` | `PENDING` |
| Secret-reference schema (canonical sha256) | `8762a999da747a9450d73dc876718a3f70a3fb47fd1e065689cdf2357849a665` |

## What the contract fixes

`contracts/middleware-v3-secret-reference-binding.v1.json`

* **References only.** Middleware stores `secret_ref`, `reference_uri`, `provider`,
  `environment`, `version`, lease metadata (`lease_id_hash` only) and rotation metadata.
  The schema's forbidden keys (`value`, `password`, `token`, `private_key`,
  `client_secret`, `secret`, `secret_value`, `unseal_key`, `recovery_key`, `root_token`)
  and every secret-shaped string are rejected at any depth. At the prep base Middleware
  vendors this schema byte-for-byte (`contracts/secrets/secret-reference.v1.schema.json`)
  and enforces it in `app/secret_reference.py`.
* **Resolved values never enter** the command payload, outbox, ledger, audit, logs,
  metrics, traces, incident timelines, reconciliation records, API responses, Git,
  images or environment variables. Values exist only as 0400 agent-rendered files inside
  the consuming process boundary.
* **Exact workload identity.** `middleware-api` and `middleware-worker` authenticate with
  Keycloak JWTs against `auth/jwt-codestra`: exact issuer per environment, audience
  `openbao`, exact `azp`, exact `codestra_environment`, all eight required claims,
  lifetime <= 300 s, `jti` replay denied, one CEL role and one policy per environment,
  read-only access beneath the approved `codestra/<env>/middleware/...` prefixes.
* **Fail closed.** Missing secret fails startup; a denied or unavailable read marks the
  reference (`denied` / `openbao_unavailable`) and keeps the dependent capability off;
  no environment-variable or Git fallback exists.

## Proofs in this repository

* `scripts/validate_middleware_v3_secret_binding.py` (wired into `scripts/validate.sh`)
  proves the contract is dark, that its schema pin equals the authority digest, and that
  every declared identity matches the reviewed role in
  `config/workload-secret-authority.v1.json` and the generated CEL role in
  `openbao/auth/jwt-roles.v1.json` literal for literal.
* `tests/security/test_middleware_v3_workload_negative.py` evaluates the negative matrix
  statically: wrong issuer, wrong audience, wrong client, wrong role, expired token,
  tampered token, foreign service, staging -> production, unapproved path and replayed
  `jti` are all **DENY**; the own-identity / own-environment / approved-path control is
  **ALLOW**.

## After `V3_FINAL_SHA` exists

1. Set `middleware.v3_final_sha`, re-verify the vendored schema pin at that SHA.
2. Confirm the V3 payload, outbox, ledger, audit, log, metric and trace schemas carry no
   secret value fields.
3. Run `scripts/certify_staging_identity.py` for `middleware-api-staging` and
   `middleware-worker-staging` (staging only).
4. Only then may the OpenBao owner flip `runtimeBindingAuthorized` for the middleware
   roles in a change of its own. Production initialisation, unseal and rotation stay
   outside Lane E.
