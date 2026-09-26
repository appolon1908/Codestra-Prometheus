# Monitoring Single-Lane Agent Contract

Mandatory entry: scripts/agent_preflight.sh

Repository: Codestra-Prometheus
Canonical active worktree: /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-Prometheus
Canonical branch: governance/single-active-lane-20260926
Recorded base: main at b14518b2e2d4dd2a4773b583687a94dfec12cfb1

One-line continuation:
cd /home/codestra/Worktrees/Monitoring-Active-20260926/Codestra-Prometheus && ./scripts/agent_preflight.sh

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
