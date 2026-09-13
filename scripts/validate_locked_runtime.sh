#!/usr/bin/env bash
set -Eeuo pipefail

source_sha="${1:?exact source SHA is required}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$source_sha"
image="$(jq -r '.image' codestra/release/runtime-image.lock.json)"
revision="$(jq -r '.upstreamTagCommit' codestra/release/runtime-image.lock.json)"
docker pull "$image"
digest="${image##*@}"
docker image inspect "$image" | jq -e --arg digest "$digest" '.[0].RepoDigests | any(endswith("@" + $digest))'
docker run --rm --network none --entrypoint /bin/prometheus "$image" --version 2>&1 | grep -F "$revision"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --entrypoint /bin/promtool \
  --volume "$PWD/codestra/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  --volume "$PWD/codestra/prometheus/rules:/etc/prometheus/rules:ro" \
  --volume "$PWD/codestra/prometheus/targets:/etc/prometheus/targets:ro" \
  --volume "$PWD/codestra/blackbox/targets-production.json:/etc/prometheus/blackbox-targets/production.json:ro" \
  "$image" check config /etc/prometheus/prometheus.yml
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --entrypoint /bin/promtool --workdir /workspace --volume "$PWD:/workspace:ro" \
  "$image" check rules codestra/prometheus/rules/*.yml
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --entrypoint /bin/promtool --workdir /workspace --volume "$PWD:/workspace:ro" \
  "$image" test rules codestra/prometheus/tests/*.test.yml
echo "PROMETHEUS_LOCKED_RUNTIME_VALIDATION=PASS"
