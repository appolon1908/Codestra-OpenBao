# CAP registered-claim hardening

The isolated build overlay upgrades `github.com/hashicorp/cap` from v0.13.0
to v0.15.0 with exact old/new archive and module-file checksums. This supported
release also migrates CAP JWT/OIDC from retired JOSEv3 to fixed JOSEv4.1.6. Imported
OpenBao source and accepted plugin identity stay unchanged.

CAP is not the only JOSE importer. The isolated build also migrates the actual
Okta MFA consumer to supported SDK v6.1.7; see
[the MFA migration and its provider-free regressions](OKTA-SDK-MFA-MIGRATION.md).

CAP's maintainer fix rejects noncanonical names that Unicode-fold to one of the
seven registered JWT claims. Previously, a signed payload could contain
`sub` and `ſub` (U+017F): struct validation read one value while the returned map
exposed another. The new guard runs after signature verification in the shared
path used by both public validation methods. Canonical claims and unrelated
Unicode custom claims retain their behavior.

Signed P256 regressions cover subject/issuer homoglyph collisions, lone aliases,
case variants of all seven registered claims, canonical/custom Unicode claims,
bad signatures, issuer/subject/audience mismatch and expiry. The required versus
optional temporal-claim validation contract is preserved. An additional test in
the isolated Kubernetes consumer exercises its actual CAP call, role audience,
canonical service-account decoding, aliases, signatures, issuer and expiry.
The selected existing Kubernetes Login/issuer/projected-token/cancellation tests
use in-memory state and synthetic TokenReview; no live cluster is used. Full JWT,
replay, JOSE, CEL and diagnose tests remain wired.

The candidate evidence validator requires compiled CAP v0.15.0 and fixed
JOSEv4.1.6 in both image and replay plugin. Actual selected-package inventories,
vendor metadata, module files, compiled inventories and both SBOMs must exclude
JOSEv3 and the unmaintained `golang.org/x/crypto/openpgp` module/packages. The
build-only crypto overlay selects the official fixed parent-module boundary
v0.58.1-0.20261009181718-2f1f834330b2 with checksum-database records. Imported
upstream manifests and the accepted runtime plugin identity remain unchanged.

The attack regressions now use fixed v4 APIs with explicit algorithm lists;
RSA/JWK/JWS/JWE and signed claim tests remain active. Historical v3 patch files
are preserved, but no patch acceptance substitutes for the dependency migration.
Both actual candidates still require fresh builds, consumer tests and scans.
HIGH/CRITICAL/UNKNOWN policy, scan freshness, stored exact-image/VEX gates and
runtime restrictions are unchanged. No new dependency or source commit is
accepted merely because these offline contract tests pass.

Primary references:

- [CAP v0.15.0 release](https://github.com/hashicorp/cap/releases/tag/v0.15.0)
- [Maintainer claims-confusion fix](https://github.com/hashicorp/cap/pull/191)
- [Fixed JWT implementation](https://raw.githubusercontent.com/hashicorp/cap/v0.15.0/jwt/jwt.go)
- [Old checksum record](https://sum.golang.org/lookup/github.com/hashicorp/cap@v0.13.0)
- [New checksum record](https://sum.golang.org/lookup/github.com/hashicorp/cap@v0.15.0)
- [Supported JOSEv4 migration](https://github.com/hashicorp/cap/pull/211)
- [Official crypto advisory and fixed boundary](https://vuln.go.dev/ID/GO-2026-5932.json)
