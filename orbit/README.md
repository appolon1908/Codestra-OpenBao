# Codestra Orbit adoption contract

## Classification

```text
repository=appolon1908-hue/Codestra-OpenBao
classification=vendor-operator-ui
adoptionMode=operator-theme-sso
status=blocked
runtimeApplyAuthorized=false
productionCertified=false
```

Codestra OpenBao is a restricted vendor operator interface. Orbit adoption is
therefore limited to supported theming and approved identity/session
integration. It is not a first-party corporate-shell replacement.

## Authority boundary

`adoption-manifest.json` conforms to the locally vendored Orbit v2 consumer
schema in `adoption-manifest.schema.json`. The schema mirrors the provisional
contract under review in `appolon1908-hue/SDK-repository` PR #75. This
repository does not publish Orbit packages and does not treat an unmerged or
unreviewed external branch as production authority.

The consumer validator additionally enforces OpenBao-specific invariants that
the generic schema cannot express:

- exact repository, classification, target branch and adoption mode;
- restricted, still-unverified `bao.codestra.media` domain status;
- native authentication fallback and native operational behavior preserved;
- browser token and secret exposure prohibited;
- native ports remain private;
- runtime application and production certification remain false;
- unresolved external, domain, identity, staging, recovery and promotion gates
  remain explicit blockers.

## Native behavior that must remain intact

Supported theming or SSO must not remove or replace native OpenBao policy,
namespace, lease, audit, seal/unseal, recovery, upgrade, rollback, session,
logout, token-revocation or break-glass behavior. No shared content, asset,
footer or browser API may receive secret values.

## Validation

Run:

```bash
python3 scripts/validate_orbit_adoption.py
python3 tests/test_orbit_adoption.py
```

These checks validate source only. They do not download packages, call a live
OpenBao API, change DNS or TLS, expose ports, initialize or unseal a cluster,
write a secret, issue a token, enable SSO or deploy production.
