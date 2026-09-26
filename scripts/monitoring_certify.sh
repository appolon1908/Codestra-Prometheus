#!/usr/bin/env bash
set -euo pipefail
bash scripts/agent_preflight.sh
if [ -f package-lock.json ]; then
  npm ci
  for gate in typecheck test:unit test:security test:integration test:migrations test:policy test:mtls test:signing test:publisher build; do
    if node -e "let p=require('./package.json');process.exit(p.scripts&&p.scripts['$gate']?0:1)" 2>/dev/null; then npm run "$gate"; else echo "N/A npm:$gate"; fi
  done
  npm audit --audit-level=high
else
  echo "N/A npm-ci"
fi
bash scripts/policy_guard.sh
if [ -f Dockerfile ]; then docker build --pull=false -t "codestra-cert-$(basename "$PWD" | tr '[:upper:]' '[:lower:]'):local" .; else echo "N/A docker-build"; fi
if [ -f compose.yaml ] || [ -f compose.yml ] || [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then docker compose config -q; else echo "N/A docker-compose"; fi
if command -v newman >/dev/null 2>&1; then
  collection="$(find . -maxdepth 4 -type f -iname '*postman*collection*.json' | head -n1 || true)"
  if [ -n "$collection" ]; then newman run "$collection"; else echo "N/A postman"; fi
else
  echo "N/A postman/newman"
fi
git diff --check
echo "CERTIFICATION_PASS $(git rev-parse HEAD)"
