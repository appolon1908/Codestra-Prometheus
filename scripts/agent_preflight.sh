#!/usr/bin/env bash
set -eo pipefail
die(){ echo "GOVERNANCE_FAIL: $*" >&2; exit 1; }
ok(){ echo "GOVERNANCE_OK: $*"; }
active=$(tr -d '\r\n' < .codestra/active-lane)
expected=$(cat .codestra/expected-origin)
origin=$(git remote get-url origin)
[ "$origin" = "$expected" ] || die "wrong origin: $origin"
git fetch --quiet origin main || die "cannot fetch origin/main"
base=$(git rev-parse origin/main)
branch=$(git branch --show-current)
mode=local
[ "$1" = "--ci" ] && mode=ci
if [ "$mode" = local ]; then
  [ -n "$branch" ] || die "detached HEAD"
  [ "$branch" != main ] || die "development on main forbidden"
  [ "$branch" = "$active" ] || die "wrong active branch: $branch"
  [ -z "$(git status --porcelain)" ] || die "dirty start"
fi
if [ "$mode" = ci ] && [ "$GITHUB_EVENT_NAME" = pull_request ]; then
  [ "$GITHUB_HEAD_REF" = "$active" ] || die "PR head is not active lane"
fi
git merge-base --is-ancestor "$base" HEAD || die "stale branch versus origin/main"
scan=$(git diff --unified=0 origin/main...HEAD || true)
echo "$scan" | grep -E '^\+.*(PRODUCTION_GO|LIVE_EFFECTS|ALLOW_PRODUCTION_EFFECTS|ENABLE_PSTN|ENABLE_LIVE_CALLS|ENABLE_LIVE_SMS|ENABLE_LIVE_EMAIL)[[:space:]]*[:=][[:space:]]*(true|1|yes|on)' >/dev/null && die "production effects enabled"
echo "$scan" | grep -Ei '^\+.*((/metrics|/internal).*(public|internet|0\.0\.0\.0)|(public|internet|0\.0\.0\.0).*(/metrics|/internal))' >/dev/null && die "public metrics/internal route detected"
echo "$scan" | grep -Ei '^\+.*(x-bypass-auth|x-disable-auth|x-skip-auth|authorization:[[:space:]]*none|auth[[:space:]_-]*disabled)' >/dev/null && die "auth bypass detected"
ok "active_lane=$active"
ok "origin_main=$base"
ok "head=$(git rev-parse HEAD)"
