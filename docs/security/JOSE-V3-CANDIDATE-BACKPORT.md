# go-jose/v3 candidate parser backport

The isolated atomic source-artifact job backports the parser protections from
[maintainer commit a0111f8](https://github.com/go-jose/go-jose/commit/a0111f82742fa92bceec9ede40845e73319e6230)
for [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q).
The imported OpenBao tree, shared module cache, accepted plugin manifest/builder,
and protected production workflow remain unchanged.

patches/go-jose-v3/manifest.json pins the v3.0.5 baseline, the four changed files,
the exact patch, and the adapted v4 behavior. The build vendors verified modules
in an isolated copy, checks every original file, stages the complete patch, then
uses explicit vendor mode for both OpenBao and replay-plugin tests/builds.
RSA public/private modulus bounds and prime-product checks precede private-key
validation. JOSE headers reject private parameters before key processing, including
general JWS serialization and JWE ephemeral keys. Direct valid private-key loading
and JWT verification remain supported. The v3 API is preserved; the 4096-bit bound
has no mutable escape hatch.

The candidate job runs only on the assigned atomic branch, using the existing
hosted runner policy and read-only repository permissions. It builds both subjects
from the same prepared tree, records their actual binary hashes and compiled module
versions, packages a pinned non-root image, and scans both subjects against one
frozen Trivy database. Raw SBOMs/reports, DB metadata/checksum, tool versions,
prepared module/patch provenance, image configuration and a separately constructed
local OCI manifest survive policy failure via an always-running artifact upload.
A configuration ID or Docker-save checksum is never described as a registry digest.

The imported JWT tests contain deliberately removed signing keys and a sanitized
client-secret request with its old expected literal. A separate checksum-locked,
test-only transform restores a matching random P256 pair and a distinct wrong
signer in memory, and aligns the expected placeholder. Test bodies/assertions
remain intact. No reusable private key is stored. The transform's hashes are
bound into candidate evidence; credential-gated external tests retain their skips.

The candidate retains module identity v3.0.5. Version-based scanners may continue
reporting its advisory; findings remain visible and HIGH/CRITICAL/UNKNOWN findings
fail the gate. These artifacts do not constitute VEX, risk acceptance, signatures,
an accepted replacement for the existing plugin digest, certification, or runtime
authorization. Protected promotion and production release require their existing
independent exact-artifact review and governed gates.
