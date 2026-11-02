# CEL and OpenTelemetry source-build repairs

The build-only overlay selects CEL **v0.30.0** for GHSA-gcjh-h69q-9w9g.
The maintainer advisory lists v0.22.0 through v0.29.2 as affected; its actual
v0.30.0 source excludes JSON-skipped fields from native lookup and conversion.
The scanner's historical v0.29.0 fixed-version field is insufficient. The module
path stays `github.com/google/cel-go`; this release has the same dependency
requirements as the imported v0.28.1.

The overlay selects OpenTelemetry SDK **v1.45.0** for
CVE-2026-81870 / GHSA-8wmf-6v46-5gfg. It aligns the root, metric and trace modules
to v1.45.0 and logr to v1.4.4. SDK metric v1.45.0 and metric/x v0.67.0 are allowed
only at their exact reviewed optional graph versions/checksums; their packages
are not forced into production binaries.

All baseline and replacement checksum pairs are explicit. Both imported module
files are checked before either is written; reconciliation rejects unrelated
module changes, downgrades and missing fixed checksums. Imported upstream bytes,
the accepted plugin identity, protected release policy and strict HIGH/UNKNOWN
gates are preserved.

The candidate job runs attack regressions that fail on the old releases:
native `json:"-"` fields cannot be read dynamically or exposed by JSON
conversion, and verbose trace-provider creation diagnostics cannot reveal a
custom exporter's harmless configuration canary for either processor type.
Positive controls check public claims, real span export and presence of the
diagnostic. JWT claims allow/deny/malformed cases, the actual OpenBao CEL
variables/email/JSON mixed-result semantics, the full existing JWT/replay tests,
and `TestDiagnoseOtelResults` cover compatibility.

Fresh candidate evidence verifies compiled and SBOM versions for both subjects.
The unused trace SDK package is required only in the OpenBao image. Both repaired
advisory IDs still fail the candidate gate at any severity. Historical raw scans
are retained; this source repair does not confer VEX acceptance, a release
certificate, controller admission or runtime activation.

Primary references:

- [CEL maintainer advisory](https://github.com/cel-expr/cel-go/security/advisories/GHSA-gcjh-h69q-9w9g)
- [CEL fixed source](https://github.com/cel-expr/cel-go/blob/v0.30.0/ext/native.go)
- [CEL v0.30.0 checksum record](https://sum.golang.org/lookup/github.com/google/cel-go@v0.30.0)
- [SDK maintainer advisory](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-8wmf-6v46-5gfg)
- [SDK maintainer regression and fix](https://github.com/open-telemetry/opentelemetry-go/commit/3a1412d2b3bc4e4231fbeac2ed42117ae541bb38)
- [SDK v1.45.0 module requirements](https://raw.githubusercontent.com/open-telemetry/opentelemetry-go/93a693edeed0e07ce5ebd1dfe67af42d1e2055d8/sdk/go.mod)
