#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
source .codestra/active-lane.env
fail(){ echo "PREFLIGHT_FAIL: $*" >&2; exit 1; }
branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" != HEAD ] || fail "detached HEAD"
[ "$branch" = "$CODESTRA_ACTIVE_BRANCH" ] || fail "wrong branch"
case "$branch" in main|master|production|production/*) fail "protected branch";; esac
if [ "\${CI:-false}" != true ]; then
  [ "$(pwd -P)" = "$(cd "$CODESTRA_CANONICAL_WORKTREE" && pwd -P)" ] || fail "wrong worktree"
fi
if [ "\${CODESTRA_ALLOW_DIRTY:-false}" != true ]; then
  [ -z "$(git status --porcelain)" ] || fail "dirty start"
fi
if git ls-remote --exit-code --heads "$CODESTRA_BASE_REMOTE" "$CODESTRA_ACTIVE_BRANCH" >/dev/null 2>&1; then
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  [ "$upstream" = "$CODESTRA_BASE_REMOTE/$CODESTRA_ACTIVE_BRANCH" ] || fail "wrong upstream"
  git fetch "$CODESTRA_BASE_REMOTE" "$CODESTRA_ACTIVE_BRANCH" >/dev/null
  [ "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)" ] || fail "stale or divergent SHA"
fi
[ "$CODESTRA_PRODUCTION_EFFECTS" = false ] || fail "production effects enabled"
echo "PREFLIGHT_PASS $CODESTRA_REPO $(git rev-parse HEAD)"
