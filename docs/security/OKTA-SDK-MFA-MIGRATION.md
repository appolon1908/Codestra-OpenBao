# Isolated Okta MFA dependency migration

CAP v0.15 removes one JOSE v3 dependency. The actual OpenBao MFA consumer also
imports Okta SDK v2.20.0, whose request executor and configuration compile JOSE
v3. SDK lines v3 through v5 retain that dependency; v6.1.7 uses JOSE v4.
The build overlay therefore selects v6.1.7 with official checksum records.

The imported `upstream/vault/login_mfa.go` remains unchanged. Only a temporary
build copy with SHA256
`76c2811dac10c2afacd24132d5c4073bb2d0904efd39db8d5fbee015fc63416c`
may receive the reviewed method/import migration in
`patches/okta-v6/validate_okta.go.fragment`. Other authentication methods keep
their imported bodies. The overlay records the before/after source hashes and
the migration hash; candidate build evidence binds the resulting MFA source.

The typed SDK APIs retain SSWS authentication, explicit uncached requests,
login/email filtering, exactly one user, push-factor selection, initial WAITING,
SUCCESS-only authorization, rejection/timeout/unknown/error denial and context
cancellation. Poll links must identify the same HTTPS origin and exact returned
user/factor transaction path; their transaction ID is passed to the SDK instead
of issuing an arbitrary supplied URL. An explicit organization port is retained.

`tests/go/oktamfa/security_test.go.fixture` exercises the actual Core method and
SDK through an isolated TLS HTTP server. Its transport rejects other origins;
there are no real Okta calls. It covers the states above, an uncached WAITING to
SUCCESS transition, quoted filter values, ambient configuration overrides and
malformed/missing/cross-origin polling links. The hosted artifact job runs this
suite before either binary is accepted for scanning.

The 14 exact records in `patches/okta-v6/dependencies.json` describe the reviewed
SDK/JWX metadata closure. They permit only those exact versions/checksums when
tidy actually retains them; they do not claim that every declared module is in
the compiled graph. Unexpected versions, checksums or unrelated graph changes
still fail. JOSE v3, legacy OpenPGP and the old Okta SDK remain denied in selected
module/package inventories, binaries and SBOMs. The image must contain v6.1.7.

[Hosted reconciliation at signed `94ab8d8`](https://github.com/appolon1908/Codestra-OpenBao/actions/runs/41553692632)
observed two additional removals after the SDK migration: the unused
`backoff/v4 v4.3.0` requirement and its two checksums, and only the historical
`go-cmp v0.5.9/go.mod` checksum while selected `go-cmp v0.7.0` stayed unchanged.
The validator permits precisely those version/checksum transitions only during
the exact Okta v2.20.0 to v6.1.7 migration. New records, other versions or
additional removals remain rejected; neither module receives a general allowance.

The real `vault` test package also reaches an imported workflow diagnostic that
prints `len(values)` with `%q`. The Go 1.26 printf analyzer restricts integer
`%q` operands to rune/byte; this value is an integer count. The build overlay
binds `vault/workflow_store.go` to SHA256
`9aeecd9af952adbb970669a50c6bacf86f4f4dfbd55c3ce42cd24c5d76fa731e`
and changes only that count verb to `%d`, preserving the separately quoted header
and all authorization behavior. Missing or changed source fails before any file
is written. Imported bytes and vet remain unchanged/enabled respectively.

Offline transform/provenance tests and Go syntax checks are source evidence.
Actual Go 1.26.10 compilation, consumer execution and fresh scans of both
subjects remain mandatory. No severity/freshness/VEX rules, accepted runtime
artifacts, production approvals or provider state change in this repair.

Primary sources:

- [Okta v6.1.7 module](https://github.com/okta/okta-sdk-golang/blob/v6.1.7/go.mod)
- [Typed factor API](https://github.com/okta/okta-sdk-golang/blob/v6.1.7/okta/api_user_factor.go)
- [Official SDK checksums](https://sum.golang.org/lookup/github.com/okta/okta-sdk-golang/v6@v6.1.7)
- [Retired SDK module](https://github.com/okta/okta-sdk-golang/blob/v2.20.0/go.mod)
- [Go 1.26 printf analyzer](https://github.com/golang/go/blob/go1.26.10/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/printf/printf.go#L832-L837)
