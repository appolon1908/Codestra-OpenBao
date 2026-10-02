<!-- CODESTRA_AGENT_PROTOCOL_V1 -->
## Codestra continuation contract

Canonical protocol:
https://github.com/appolon1908/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md

Quick start:
https://github.com/appolon1908/codestra/blob/main/docs/AGENT-QUICKSTART.md

Before changing code:
1. Read `.codestra-mission/*` when present.
2. Read the active Linear issue and linked Notion architecture.
3. Inspect exact Git branch/HEAD/dirty/worktree/upstream/PR/CI state.
4. Preserve all existing local work.
5. If acting as Builder, verify exclusive issue ownership and use a dedicated worktree.
6. Do not invent or self-assign the next task.
7. Update GitHub + Linear + Notion + the mission checkpoint before handoff.
8. Do not cross the live-production approval boundary.

The canonical protocol's no-loss, one-writer, protected-merge, checkpoint, and production-boundary rules are mandatory.

<!-- CODESTRA_SINGLE_LANE_GOVERNANCE_V1 -->
# Monitoring Single-Lane Agent Contract

Mandatory entry: scripts/agent_preflight.sh

Repository: Codestra-OpenBao
Canonical active worktree: /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-OpenBao
Canonical branch: governance/single-active-lane-20260926
Recorded base: main at f2befac098b5468495ac182af6240c75afd2caa0

One-line continuation:
cd /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-OpenBao && ./scripts/agent_preflight.sh

Rules:
- Work only in the canonical active worktree and active branch above.
- Never edit protected main, detached HEAD, a dirty start, or a branch with the wrong upstream.
- .codestra-mission/ACTIVE-LANE.env is authority; stale base SHA or wrong origin fails closed.
- Preserve old lanes as read-only reconciliation evidence. Never reset, stash, discard, rewrite, force-push, or blindly delete history.
- Never add public /metrics or /internal exposure, wildcard CORS, alternate public monitoring ports, or auth/correlation/audit-header bypasses.
- Never add production-effect commands on this lane. Monitoring work remains read-only/no-effect.
- Before publication run scripts/agent_preflight.sh --certify and perform a fresh remote-head compare-and-swap.

## CODESTRA GLOBAL DEVELOPMENT GOVERNANCE v1.0
Before editing, run scripts/agent_preflight.sh. The .governance authority files are machine authority. Preserve unknown or dirty historical work. Never reset, stash, force-push, develop on main/master, or enable production effects. Finish with scripts/agent_finish.sh. Certification uses scripts/certify.sh plus repository-specific deterministic gates. Publication is Appolon-only and requires explicit remote-SHA compare-and-swap verification.
<!-- /CODESTRA_SINGLE_LANE_GOVERNANCE_V1 -->
