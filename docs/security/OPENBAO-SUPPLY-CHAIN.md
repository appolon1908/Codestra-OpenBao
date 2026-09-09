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

The current raw scan reports ten HIGH/CRITICAL observations. Five OpenBao observations
are version-comparison false positives caused by its embedded pseudo-version;
the binary is v2.6.2, later than each fixed release. The OpenSSL observation is
limited to QUIC server processing, which OpenBao does not enable. The archive
finding is outside workload reach because external runtime plugin installation
is prohibited. The SSH library finding is outside the execution path because
OpenBao is not an SSH server and the SSH engine is prohibited.

The image also contains grpc-go v1.82.1, affected by CVE-2026-84304. OpenBao
does compile internal gRPC servers, so the code is not declared absent. The
time-bounded disposition applies only because no Codestra OpenBao runtime is
deployed or authorized, and release construction fails while runtime authority
and environment certification remain false. It expires on 2026-09-09. Any
runtime activation must first use grpc-go v1.83.1 or later, or replace this
disposition with a new evidence-backed review.

The separately built replay plugin is a gRPC server and receives no such VEX
disposition. Its deterministic overlay upgrades grpc-go from v1.82.1 to
v1.83.1; the regenerated binary, SBOM, vulnerability report and checksums show
zero plugin High/Critical findings.

Every disposition has an expiration. `scripts/verify_vulnerability_gate.py`
fails when a HIGH/CRITICAL observation is missing, a disposition expires, or
the image identity changes. There are no blanket ignores. A future scanner
result must be reviewed rather than copied under the old VEX decision.

Primary upstream evidence:

- <https://github.com/openbao/openbao/releases/tag/v2.6.2>
- <https://github.com/openbao/openbao/security/advisories>
- <https://openbao.org/docs/install/>
- <https://github.com/grpc/grpc-go/security/advisories/GHSA-vp52-pcj8-j9qc>
