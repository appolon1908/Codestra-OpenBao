# OpenBao activation mission evidence

Observation date: 2026-09-13

This directory contains sanitized, secret-free evidence collected while
assessing the complete staging and production activation mission from
`development` commit `15d8ded836f4b08746c791249d7cfd9f170168bf`.

The source baseline and isolated integration tests pass. Production activation
does not pass: required host authority, offline custody, PKI, a deployable
signed image, protected promotion, staging runtime certification, backup and
restore evidence, and explicit production authorization are absent.

The protected initialization workflow also exports a legacy custody-file
variable that is incompatible with the sole guarded initializer's required
custody directory and six public-key path inputs. The attempted workflow-only
repair was rejected by GitHub because the available OAuth credential lacks the
`workflow` scope; no credential scope was broadened.

No host, firewall, SSH, swap, network, OpenBao runtime, secret, DNS, Caddy,
provider, or business-effect state was changed while collecting this evidence.
No private key, credential, token, recovery share, secret value, database
connection string, session cookie, or sensitive environment value is included.

Files:

- `baseline.json` records the exact baseline and local validation outcome.
- `node-preflight.json` records sanitized host reachability and node 3 facts.
- `supply-chain.json` records image identity, SBOM, signature, provenance and
  vulnerability-gate facts.
- `governance.json` records protected-branch SHAs, signature verification,
  ancestry and visible protection controls.
- `blockers.json` records the authority and security gates that prevent staging
  certification, promotion and production activation.

`MISSION_RESULT=BLOCKED`
