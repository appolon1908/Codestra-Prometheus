#!/usr/bin/env bash
set -euo pipefail
python3 -m json.tool .codestra/headers.v1.json >/dev/null
if git grep -InE '(PRODUCTION_EFFECTS|provider_effects_enabled|runtimeApplyAuthorized)[[:space:]:=]+(true|1|yes)' -- ':!docs/**' ':!test/**' ':!tests/**' ':!fixtures/**' >/tmp/codestra-prod-hits 2>/dev/null; then
  cat /tmp/codestra-prod-hits
  rm -f /tmp/codestra-prod-hits
  echo POLICY_FAIL >&2
  exit 1
fi
rm -f /tmp/codestra-prod-hits 2>/dev/null || true
echo POLICY_PASS
