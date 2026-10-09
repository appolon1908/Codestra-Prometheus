#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"; sha="$1"; [ -n "$sha" ] || sha=$(git rev-parse HEAD)
test "$(git rev-parse HEAD)" = "$sha" || { echo CERTIFY_FAIL_SHA_MISMATCH; exit 50; }
test -z "$(git status --porcelain)" || { echo CERTIFY_FAIL_CONTAMINATED_WORKTREE; exit 51; }
scripts/worktree_guard.sh; scripts/agent_preflight.sh --certify; git diff --check
echo "CERTIFICATION_COMMIT_SHA=$sha"; echo "CERTIFICATION_TREE_SHA=$(git rev-parse "$sha^{tree}")"
echo "CERTIFICATION_BASE_SHA=$(python3 -c 'import json;print(json.load(open(".governance/authority.json"))["base_sha"])')"
echo CERTIFICATION_CONTROL_GATE=PASS
