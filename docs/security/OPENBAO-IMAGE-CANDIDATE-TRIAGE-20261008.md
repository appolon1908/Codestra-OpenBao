# OpenBao official image candidate triage — 2026-10-08

**Release disposition: BLOCKED. No image authority or running service was changed.**

The existing production-safe source authority remains pinned to **OpenBao 2.6.2** at `ghcr.io/openbao/openbao@sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff`.
The protected `image-vulnerability` job correctly detects `CVE-2026-56851` in its old `golang.org/x/text` package, and must remain failing while that digest is a candidate for deployment.

## Immutable read-only candidate investigation

| Image | Current Trivy 0.75.0 assessment | Disposition |
| --- | --- | --- |
| Official 2.6.3 | HIGH 5; UNKNOWN 1; no longer sees CVE-2026-56851 | Rejected as a drop-in update |
| Official 2.7.1 Linux/AMD64 | HIGH 0; CRITICAL 0; UNKNOWN 1 (`GO-2026-5932`, `golang.org/x/crypto`) | **BLOCKED**, pending package reachability and independent disposition |

The precise 2.7.1 Linux/AMD64 OCI **manifest digest** assessed is:
`ghcr.io/openbao/openbao@sha256:a36ea8c27f0dcff5757664ad080425f96d3b6b2f33db3e76c4e2d3112fb17005`.

Its **OCI index digest** is different:
`sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf`.
Trivy also reports an **image config digest**
`sha256:c49c0f523d66da8f70aa942e50ecd5dd7863ee7620306c0267a96ec5353d3239`.
**These three digest types must not be confused or substituted.**

The immutable-digest vulnerability scan is committed at
`artifacts/security/openbao-v2.7.1-linux-amd64.trivy.json` and bound to
`artifacts/security/openbao-image-upgrade-candidate-20261008.json` by SHA-256. Run
`python3 scripts/validate_openbao_image_upgrade_candidate.py` to enforce
identity, digest, scan freshness, counter integrity, and fail-closed severity policy.
**Its expected result is BLOCKED and exit status 1**, never a release approval.

## Requirements before selecting a replacement

1. Obtain a signed, independently verified reachability assessment of `GO-2026-5932` for this exact image. A Go module's presence in build metadata alone does not prove an affected package is reachable, but **lack of evidence does not imply safety**.
2. Validate the 2.6.2 → 2.7.1 compatibility and Raft schema/restore path; do not change source authority or immutable image references until these checks pass.
3. Build or select the new immutable image and run full integration, authentication, tenant denial, secrets, audit, backup/restore, and exact-SHA tests with signed SBOM/VEX/provenance.
4. Reconcile OpenBao's registered `ob-15-cicd` subsection and independent control-plane certification. Apply the tested no-conflict repair branch only after the required checks for its exact commit have been satisfied.
5. Require separate approver/custodian sign-off on immutable-image promotion; never replace evidence just to obtain a green CI badge.

`STAGING_GO=NO`; `PRODUCTION_GO=NO`; `LIVE_CAPABILITIES_ENABLED=NO`; `EXTERNAL_EFFECTS=false`.
No initialization, unseal, secret write, DNS change, provider activation, runtime deployment, forced branch update, or protection bypass is authorized by this assessment.
