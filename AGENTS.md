# Mandatory agent entry contract
Before changing product code run: bash scripts/agent_preflight.sh
Canonical writable worktree: /home/codestra/Worktrees/monitoring-governed/Codestra-Prometheus
Active branch: governance/single-lane-lock-20260926
Rules:
- Never develop on main, production, or detached HEAD.
- Never start from a dirty tree.
- Never reset, clean, stash, discard, force-push, or delete unproven history.
- /home/codestra/Documents/GitHub/Codestra-Prometheus is reconciliation-only during this mission.
- Upstream must be origin/governance/single-lane-lock-20260926 and remote SHA must match before publication.
- Production effects remain fail-closed.
- /metrics and /internal remain private.
- Middleware V3 remains cross-system orchestration authority.
- Certification order: preflight -> dependency install -> typecheck -> unit/security -> integration/migrations -> policy/mTLS -> signing/publisher -> build -> Docker/local API/Postman.
- Publish only after green certification and remote-head compare-and-swap verification.
- Record branch, SHA, PR, evidence, and continuation line in Linear/Notion.
Continuation: cd '/home/codestra/Worktrees/monitoring-governed/Codestra-Prometheus' && bash scripts/agent_preflight.sh && bash scripts/monitoring_certify.sh
