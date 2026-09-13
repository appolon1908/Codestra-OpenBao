# Codestra OpenBao repository inventory

Inventory timestamp: 2026-09-01 (Europe/Berlin)

Repository: `appolon1908-hue/Codestra-OpenBao`

Integration base: `development` at `2c199ee38ce372af4e0355c83e018f417e3afc8f`

Remediation branch: `remediation/openbao-production-completion-v1`

This inventory was produced after fetching every remote branch and pull-request
head. It records observed state; it does not claim that an unimplemented or
untested control passes.

## Protected and promotion branches

| Branch | Observed SHA | Ahead/behind `development` | Current protection | Head signature |
| --- | --- | ---: | --- | --- |
| `development` | `2c199ee38ce372af4e0355c83e018f417e3afc8f` | `0/0` | protected | valid |
| `test` | `6667709d257cdd97ceb22a97aeff798928c1bf28` | `2/0` | protected | valid |
| `staging` | `6e092ce5cf8e1cd76587118103653ebb7e7620b0` | `3/0` | protected | valid |
| `production` | `38ff3f3d7a2dcd9f03455415c26b2562a50adb34` | `0/68` | protected | unsigned |
| `main` | `5f5e3583585081e450f945440a1fab503bfa8399` | `1/62` | protected | unsigned |

The ahead/behind values are shown as `<branch ahead>/<branch behind>` relative
to `development`. The promotion branches are not linear today: `test` and
`staging` contain later integration merges, while `production` and `main` do
not contain the current development line. Promotion must therefore use reviewed
pull requests and exact synthetic merge validation, not ref movement or a
force-push.

All five promotion branches now require one approving review, CODEOWNER review,
stale-review dismissal, approval after the last push, conversation resolution,
linear history, signed commits, and enforcement for administrators. Force
pushes and deletion are disabled. Each requires the eleven uniquely named
`OpenBao / ...` status contexts. These protections were added during this
remediation; they were absent from four branches at initial inventory.

## All observed remote branches

| Branch | SHA | Disposition |
| --- | --- | --- |
| `main` | `5f5e3583585081e450f945440a1fab503bfa8399` | protected release destination; not a development workspace |
| `development` | `2c199ee38ce372af4e0355c83e018f417e3afc8f` | integration authority and remediation base |
| `test` | `6667709d257cdd97ceb22a97aeff798928c1bf28` | promotion target after development certification |
| `staging` | `6e092ce5cf8e1cd76587118103653ebb7e7620b0` | promotion target after test certification |
| `production` | `38ff3f3d7a2dcd9f03455415c26b2562a50adb34` | production source target; currently stale |
| `prod-readiness-20260901` | `ee547d16273fb6db5b1d5eb6afc2a8eec479d7a0` | one later readiness-gate document was reviewed; its fail-closed rules are fully represented in the more detailed production checklist and certification, with no unique implementation to import |
| `docs/repository-profile-v1` | `32f32f889b6fd7df36351e9ac3cde22d2006c79c` | reuse accurate profile concepts; do not replace newer source-sync logic |
| `feature/codestra-corporate-suite-v1-20260829` | `b280999a774e4c8dd59a4ad7767e5a9dd74bf610` | useful intake controls already evolved and merged into `development` |
| `feature/intake-monitoring-v1-20260830` | `21759128a11c5dfeb8d4c85ea7d93fc8121a48b1` | fully represented by later development history |
| `fix/corporate-review-hardening-v1-20260830` | `f5f71fbe846713c706a997505996636edbb3312f` | fully represented by later development history |
| `feature/private-bind-keycloak-oidc-v1` | `a3f6c4469cdf7acee032b024fcc3c707b7e71645` | preserve private-listener, mTLS and exact-OIDC controls through the newer `codestra/runtime-v1` authority; do not create a duplicate `config/codestra` tree |
| `integration/marketing-platform-staging-secrets-v1-20260830` | `853b3d20985a6fb1049a9128133933c6ffaa3bf8` | later versions already merged into `development` |
| `integration/middleware-immutable-digest-lock-v1-20260830` | `8941bfa48493d562e535042033ddd3c3a6a5a594` | retain immutable digest/evidence constraints from the development integration contracts |
| `integration/codestra-observability-suite-v1-20260830` | `e84b471acff573151c8deddbe77226278417fb6e` | controlled monitoring and activation contracts already merged into `development` |
| `integration/stage6-intake-observability-v1-20260830` | `b83bc6638de5897f767dc13697fcb21d5e55fbdf` | monitoring token, deny-path and scope controls already merged into `development` |
| `remediation/workload-secret-authority` | `7294d484825c7d661e8c4531d3c48cafd4966d70` | four production-quality commits reconciled onto the remediation branch |
| `security/openbao-protected-source-gates-20260901` | `576e31af648a051f1d46d36e4558548b84337ba1` | all later hardening commits reviewed and selectively reconciled; stale branch targeting and control regressions were excluded |

## Open pull requests

| PR | Head and exact SHA | Base | State at inventory | Disposition |
| --- | --- | --- | --- | --- |
| #19, production completion | `remediation/openbao-production-completion-v1` at inventory evidence SHA `6bb2e306bd65e0f1219993d311b7092de9a99530` | `development` | open; all eleven required contexts passed on that exact head; independent review blocked on pending collaborator acceptance | canonical promotion PR; do not bypass its required checks or review |
| #18, workload secret authority | `remediation/workload-secret-authority` at `7294d484825c7d661e8c4531d3c48cafd4966d70` | `main` | open; no CI check | superseded by reconciled implementation on the development-rooted remediation branch |
| #17, protected source gates | `security/openbao-protected-source-gates-20260901` at `576e31af648a051f1d46d36e4558548b84337ba1` | `main` | open; ten new hardening commits appeared after initial reconciliation | superseded after selectively retaining its complete push-command parser, immutable sync-branch authority, expanded credential scanning and syntax-preserving fixture sanitation; obsolete main targeting, reduced workflow validation and removed provenance ledger were not imported |
| #9, repository profile | `docs/repository-profile-v1` at `32f32f889b6fd7df36351e9ac3cde22d2006c79c` | `main` | draft; no CI check | reuse accurate text in the canonical profile; do not merge its stale workflow wholesale |

PRs #17 and #18 incorrectly target `main` for development work. Their useful
commits were replayed selectively on `remediation/openbao-production-completion-v1`,
which is rooted in protected-source `development`. The old PRs must not be used
as promotion substitutes.

## Implementation reconciliation

The current development line already contains the latest corporate profile,
private-edge/OIDC planning, workload policy generation, marketing staging
bindings, controlled-intake contracts, immutable Middleware evidence, and
Stage 6 monitoring-token controls. Older parallel directories are therefore not
merged wholesale.

The remediation branch additionally retains and reconciles:

- the exact-source importer and reviewed sync boundary from PR #17;
- the fail-closed workload authority and mutation tests from PR #18;
- the sanitized-fixture safety change present only on `main`;
- exact OpenBao `v2.6.2` source and Linux/AMD64 image identity;
- a repository-wide provider-token and private-key scanner with path-only error
  reporting; and
- upstream synchronization into `development`, preserving the mandated
  promotion order.

No runtime authorization was enabled during reconciliation.

## Repository authority gaps observed

- `.github/CODEOWNERS` is absent from every promotion branch.
- `README.md`, `REPOSITORY_PROFILE.md`, production preflight, restore
  certification, rollback and final certification evidence are absent from the
  current development line.
- Thirty branch-restricted deployment environment shells now exist for plan,
  runtime, initialization, certification, apply, backup, restore, observation
  and release jobs. Dispatch environments admit only their exact promotion
  branch; scheduled observation and production backup also admit `main`. Their
  custom branch policies are active. Required-reviewer installation is externally
  blocked until `@kazan555` accepts pending read-only collaborator invitation
  `331318935`; an empty reviewer rule is not represented as approval protection.
- Repository rulesets are empty.
- Repository Actions now permit GitHub-owned actions plus only the exact
  `sigstore/cosign-installer@d7543c93d881b35a8faa02e8e3605f69b7a1ce62`
  third-party action. Full-length commit-SHA pinning is enforced at repository
  level. The settings were applied and read back through the repository API on
  2026-09-01.
- Every workflow permission block was reviewed. Default workflow permissions
  are read-only and workflows cannot approve pull requests; writes exist only
  in protected release/deployment paths and isolated upstream synchronization.
- The protected branches do not yet contain remediation-source CODEOWNERS and
  workflows; those files take effect there only through the required promotion
  PRs. Protection itself is already active and will not be bypassed.
- Action dependencies are repository-wide enforced as immutable SHAs.
- Repository-level immutable releases are enabled and were read back through
  the repository API on 2026-09-01. No release tag exists yet; the protected
  production workflow will create a draft, attach and digest-check every asset,
  publish it, and read back the immutable signed release only after every
  certification gate passes.
- Current documentation describes source-prepared, non-deployed behavior and
  cannot serve as production certification.

## Required remediation boundary

The canonical source must be completed on the development-rooted remediation
branch, tested there, and promoted only through:

```text
remediation/openbao-production-completion-v1
  -> development -> test -> staging -> production -> main
```

Branch protection will not be weakened. Any protection or environment change
must add safety gates. Runtime deployment remains prohibited until staging,
backup/restore, immutable release and production preflight evidence pass. SSH
configuration and SSH firewall rules are explicitly outside scope and must
remain unchanged.

## Remediation branch update

The remediation branch now contains CODEOWNERS, Dependabot configuration,
repository-wide immutable action validation, the eleven uniquely named CI
contexts, protected plan/saved-plan apply workflows, a protected exact-artifact
runtime deploy path, release signing and provenance, backup/isolated restore
and drift workflows. Remote branch protection and exact environment branch
policies are installed. Required environment reviewers, variables, private
runners and runtime execution evidence remain open until external access and
promotion gates complete; this inventory does not retroactively mark them
deployed.

The exact-head evidence runs for `6bb2e306bd65e0f1219993d311b7092de9a99530`
were validation `33556780393`, policy/integration `33556780392`, immutable
image authority `33556780384`, and security `33556780373`. All eleven required
`OpenBao / ...` contexts completed successfully. This records a point-in-time
inventory result; later documentation commits must pass a fresh exact-head run.
