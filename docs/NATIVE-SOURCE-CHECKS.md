# Native GitHub source checks

The governance-only main branch validates its actual tracked JSON/YAML, Python and shell syntax, unchanged production-disabled metadata, exact checkout and committed base/head whitespace. It runs the existing MCR reference-authorization and generated-policy checks plus their negative regressions. The hosted job uses read-only permissions and cannot authorize installation, secret access or runtime promotion.

`OpenBao governance / source validation` applies to pull requests targeting main and pushes to main. Product-bearing branches have separate genuine product validation, isolated integration, source security and artifact security checks. Required-check settings must follow verified branch coverage; do not require missing product commands on the thin main tree or treat the governance check as their replacement.

The previous `pull_request_target` routing jobs and installed-controller caller are retired. The old fixed-workstation records are retained as historical evidence. Effective GitHub signature, independent-review, stale-review, thread-resolution and protection requirements remain authoritative. Production approval is separate and remains mandatory.

Upstream intake now performs read-only identity inspection of the declared official upstream branch and archives the resolved commit. It does not import source, sanitize a tree, commit, push, sign, test the upstream candidate or change protected refs. The report explicitly records those limits. A subsequent source import requires a separately prepared signed PR with actual source/security verification and independent review. Automatic pushes to main, staging and production have been removed.

This change does not accept OpenBao PR111/114 vulnerability evidence, change scan/VEX policies, deploy a service or certify runtime readiness. Existing product security failures must be resolved through genuine fresh evidence and reviewed source fixes.
