<!-- CODESTRA_AGENT_PROTOCOL_V1 -->
## Codestra continuation contract

Canonical protocol:
https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md

Quick start:
https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-QUICKSTART.md

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
## Codestra single-lane authority
Before any edit: read .codestra/active-lane and run bash scripts/agent_preflight.sh.
Work only on that active branch from a clean, current origin/main base.
Do not reset, clean, stash, delete, rewrite, or force-push unproven history.
Do not weaken CI, auth, secret, route/header, observability, or production-effect gates.
A failed preflight is a STOP condition.
<!-- /CODESTRA_SINGLE_LANE_GOVERNANCE_V1 -->
