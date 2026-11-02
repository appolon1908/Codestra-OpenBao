# CAP registered-claim hardening

The isolated build overlay upgrades `github.com/hashicorp/cap` from v0.13.0
to v0.14.0 with exact old/new archive and module-file checksums. Both releases
have the same `go.mod`, so this change requires no companion upgrade. Imported
OpenBao source and accepted plugin identity stay unchanged.

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

The candidate evidence validator requires compiled CAP v0.14.0 and corresponding
SBOM inventory in both image and replay plugin. Version drift fails closed.
This upgrade does **not** remove go-jose/v3 or resolve its retained scanner
finding: the maintainer-origin v3 backport and all attack regressions stay in
place, and HIGH/CRITICAL/UNKNOWN policy is unchanged. A new source commit needs
fresh exact-artifact evidence; earlier candidate assessments are not acceptance.

Primary references:

- [CAP v0.14.0 release](https://github.com/hashicorp/cap/releases/tag/v0.14.0)
- [Maintainer claims-confusion fix](https://github.com/hashicorp/cap/pull/191)
- [Fixed JWT implementation](https://raw.githubusercontent.com/hashicorp/cap/v0.14.0/jwt/jwt.go)
- [Old checksum record](https://sum.golang.org/lookup/github.com/hashicorp/cap@v0.13.0)
- [New checksum record](https://sum.golang.org/lookup/github.com/hashicorp/cap@v0.14.0)
