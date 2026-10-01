# OpenBao supply-chain authority

Codestra pins OpenBao v2.6.2 at upstream Git commit
`dd9c19c37a878cf4a81b18efb8d6f0599c7da923` and the official Linux/AMD64
manifest `sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff`.
The multi-architecture index is recorded separately and is not deployment
authority.

The checked image reports the same version and source SHA. The official GHCR
platform manifest did not contain a Cosign signature when checked on
2026-09-01. Therefore upstream signature verification is not marked PASS and a
production release must add Codestra signature and SLSA provenance to the exact
artifact before deployment.

Committed evidence includes:

- a CycloneDX SBOM;
- the complete Trivy JSON result;
- explicit, owner- and expiry-bound vulnerability dispositions;
- source/image identity; and
- `SHA256SUMS` for independent verification.

The current raw scan (Trivy 0.74.0, database of 2026-09-19, committed as the
exact bytes the VEX revision 2 was reviewed against) reports eleven
HIGH/CRITICAL observations. Five OpenBao observations are version-comparison
false positives caused by its embedded pseudo-version; the binary's Go build
info records upstream commit dd9c19c37a878cf4a81b18efb8d6f0599c7da923 and
`bao version` reports v2.6.2, later than each fixed release. The OpenSSL
observation is limited to the QUIC server listener; `bao` is a statically
linked Go binary that never loads the Alpine OpenSSL packages and declares only
a tcp listener. The archive finding is outside the execution path: go-archive
is linked only through Docker test-environment helpers that no server or API
path invokes, and runtime plugin installation is prohibited. The SSH library
finding is outside the execution path because OpenBao runs no SSH server and
the SSH engine is prohibited.

The image also contains grpc-go v1.82.1, affected by CVE-2026-84304 and
CVE-2026-84445. OpenBao does compile internal gRPC servers, so the code is not
declared absent. The time-bounded disposition applies only because no Codestra
OpenBao runtime is deployed or authorized, and release construction fails while
runtime authority and environment certification remain false. Revision 2 of
the VEX (reviewed 2026-09-20) expires on 2026-10-20; revision 1 is preserved
under `artifacts/supply-chain/historical/`. Any runtime activation must first
use the protected source-built image with grpc-go v1.83.2, or replace this
disposition with a new evidence-backed review.

The separately built replay plugin is a gRPC server and receives no such VEX
disposition. Its deterministic overlay upgrades grpc-go from v1.82.1 to
v1.83.2; the regenerated binary, SBOM, vulnerability report and checksums show
zero plugin High/Critical findings.

Every disposition has an expiration. `scripts/verify_vulnerability_gate.py`
fails when a HIGH/CRITICAL observation is missing, a disposition expires, the
image or source identity changes, or the committed scan no longer matches the
bytes the VEX was reviewed against. There are no blanket ignores. A future scanner
result must be reviewed rather than copied under the old VEX decision.

Both the image gate and `scripts/verify_plugin_supply_chain.py` also fail closed
on these conditions:

- A finding the scanner could not score (`Severity: UNKNOWN`) is gated exactly
  like HIGH/CRITICAL. An unscored finding is not evidence of low impact.
- A missing or unrecognised severity, a malformed `Results` structure, or a
  finding without an identifier or package fails the gate.
- CI passes the rebuilt plugin path into the verifier. Its SHA-256 must equal
  `plugin.v1.json.binarySha256`; a rootfs vulnerability report must name the
  exact scan root and inventory the expected Go binary. Evidence paths are
  normalized consistently for POSIX and Windows separators, and absolute
  binary targets outside the declared scan root are rejected.
- Freshness comes only from the report's machine-readable `CreatedAt`. The
  gate never reads it from prose. A scan older than 30 days, or dated in the
  future, fails. The image gate binds the fresh CI report to the exact image
  digest. It also requires the VEX `scanEvidence` (`scannedAt`,
  `scannerVersion`, `highCriticalObservations`, database date) to agree with
  the committed report, and it requires every statement to be reviewed on or
  after the scan date.
- The plugin report must use Trivy schema 2 and contain a `gobinary` result
  whose target is the plugin command (`codestra-jwt-replay`). A scan of an
  empty or wrong directory has zero findings. It cannot pass as a clean plugin
  scan.

`scripts/verify_branch_promotion.py` fails closed on an unset or unsupported
event. `workflow_dispatch` is accepted only on a protected branch or an
admissible `remediation/*` / `sync/openbao-upstream-*` head.

Open blockers (the gates stay red until each is resolved; neither is waived):

1. `GO-2026-5932` (`golang.org/x/crypto/openpgp` is unmaintained; the scanner
   reports it as `UNKNOWN`) appears in both the image scan (x/crypto v0.53.0)
   and the plugin scan (v0.55.0). Before this hardening the gates skipped it
   without reporting it. OpenBao's first-party source imports only
   `github.com/ProtonMail/go-crypto/openpgp`, but no reviewed evidence yet
   shows that no linked dependency pulls in the deprecated package.
   `govulncheck -mode=binary` on both binaries is the appropriate evidence for
   a security-owner disposition. Without it, the fix is a rebuild that drops
   the package.
   Local observation on 2026-09-25, recorded as input for that review. It is
   not a disposition and adds no VEX statement. `/usr/bin/bao` was copied from
   the exact pinned image digest (file sha256
   `8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00`).
   `go tool nm` lists symbols from 23 `golang.org/x/crypto/*` packages but none
   from `golang.org/x/crypto/openpgp`. `go version -m` shows
   `golang.org/x/crypto v0.53.0` and `github.com/ProtonMail/go-crypto v1.4.1`.
   Still missing: `govulncheck -mode=binary` output for both binaries (the
   local install timed out on the network) and the same symbol check on the
   plugin binary. The plugin binary requires the pinned Go 1.25.13 toolchain
   to rebuild.
2. The review mechanism requires CODEOWNER approval, and `.github/CODEOWNERS`
   names a single owner (`@kazan555`). That owner's collaborator acceptance
   is still pending (see the production certification). Independent security
   review therefore cannot be completed locally. It is a governance blocker
   that needs an organisational ownership decision, and the VEX `review.status`
   remains `PENDING_SECURITY_OWNER_APPROVAL`.

Primary upstream evidence:

- <https://github.com/openbao/openbao/releases/tag/v2.6.2>
- <https://github.com/openbao/openbao/security/advisories>
- <https://openbao.org/docs/install/>
- <https://github.com/grpc/grpc-go/security/advisories/GHSA-vp52-pcj8-j9qc>
- <https://github.com/grpc/grpc-go/security/advisories/GHSA-2v4p-qf9q-27wj>
