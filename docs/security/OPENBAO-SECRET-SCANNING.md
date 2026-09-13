# OpenBao secret scanning

Both the working tree and complete Git history are scanned. The repository
scanner rejects credential shapes, standard private-key headers, secret-file
suffixes, binary content and symbolic links. Gitleaks runs with redaction and
default rules across `--all` refs.

False-positive allowlists are exact and documented in `.gitleaks.toml`. The
historical `15m-default-1h-maximum` value is a database lease-duration policy.
The pinned official upstream source also contains four runtime-code patterns
that default Gitleaks rules misclassify: a UUID-format CLI example, an
intentionally invalid JWT used to exercise remote-key verification, a public
Transit algorithm identifier, and public Go private-key-type enum constants.
Each upstream exception requires both its exact path and reviewed source-line
syntax; it does not suppress other findings in the file. All five allowlists
record the platform-security review date. Upstream test, fixture, example and
documentation credentials are sanitized and checksummed instead of ignored.
Broad path, commit, rule, entropy or test-directory exclusions are prohibited.

Findings must be redacted in CI. Secret values must never be uploaded as scan
artifacts. A confirmed credential requires revocation first, history-impact
assessment, and a separately approved history-rewrite decision; deleting only
the current file is not remediation.
