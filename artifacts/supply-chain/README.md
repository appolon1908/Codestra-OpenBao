# Supply-chain evidence

`SHA256SUMS` covers the committed, secret-free evidence for both runtime
executables:

- the exact official OpenBao v2.6.2 linux/amd64 image digest, with CycloneDX
  SBOM, Trivy report, source identity and expiring VEX dispositions; and
- the external `codestra-jwt-replay` v1.1.0 linux/amd64 binary, with CycloneDX
  SBOM and Trivy report showing zero HIGH/CRITICAL observations.

The plugin manifest locks its exact upstream SHA, patched Go toolchain,
security dependency resolution, overlay module checksums and binary checksum.
CI rebuilds the binary, regenerates both current scans and rejects package,
toolchain, digest or HIGH/CRITICAL drift. No executable binary is committed to
Git; the protected immutable release contains the reproduced binary and these
evidence files.
