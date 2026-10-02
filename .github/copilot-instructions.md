<!-- CODESTRA_AGENT_PROTOCOL_V1 -->
## Codestra coding-agent continuation contract

Canonical protocol:
https://github.com/appolon1908/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md

Before editing, read repository-local agent/mission files, the active Linear issue, linked Notion architecture, and exact Git/PR/CI state. Preserve existing work. Builder work uses an isolated worktree with exclusive issue ownership. Never weaken protected checks or cross the live-production approval boundary. End with the protocol's structured checkpoint.

<!-- CODESTRA_SINGLE_LANE_GOVERNANCE_V1 -->
## Monitoring single-lane entry contract
Read AGENTS.md first. Run scripts/agent_preflight.sh before editing. Use only the canonical worktree and active branch declared in .codestra-mission/ACTIVE-LANE.env. Preserve old lanes as read-only reconciliation evidence. Never bypass origin/base-SHA checks, route/header restrictions, no-production-effects policy, CI, or remote-head compare-and-swap.

## CODESTRA GLOBAL DEVELOPMENT GOVERNANCE v1.0
Read AGENTS.md and run scripts/agent_preflight.sh before editing. Obey .governance/authority.json. Do not create arbitrary lanes, touch protected branches, enable production effects, or publish from the development workstation.
<!-- /CODESTRA_SINGLE_LANE_GOVERNANCE_V1 -->
