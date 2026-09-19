# Middleware V3 metrics contract (Lane E preparation)

Status: **PREPARED_DISABLED**. `MIDDLEWARE_PREP_BASE=22d023a9c65b0789a0f7ee6c28548753521a9eff`,
`V3_FINAL_SHA=PENDING`. Prometheus collects, stores and queries; Middleware never becomes a
telemetry database.

## Scrape contract (`codestra/contracts/middleware-v3-metrics.v1.json`)

* Job `codestra-middleware-metrics`: `GET /metrics` on `middleware-integration-api:8095`,
  OAuth2 client `monitoring-readonly`, scope `metrics.read`, audience `middleware-api`,
  client secret from `/run/secrets/monitoring-readonly-client-secret` (OpenBao-rendered).
* Never public: Caddy answers `/metrics` with 404 ahead of Kong; no Kong route publishes it.
* Evidence at the prep base: the canonical API verifies `monitoring-readonly` +
  `metrics.read` as the first statement of `GET /metrics` (`app/appolon_routes.py`); worker
  and narrow-service processes mount an unauthenticated `prometheus_client` app at
  `/metrics` on the private network only - classified **PRIVATE_REQUIRED**, V3 should
  authenticate or keep it strictly private.
* The job's `labeldrop` guard now also removes `customer`, `command_id`, `operation_id`,
  `incident_id`, `fingerprint`, `lease_id`, `secret_ref`, `reference_uri` and `jti`; the
  repository validator rejects the same identifiers as target labels.

## V3 metric expectations

All 18 mission metrics are declared `EXPECTED_PENDING_V3` with the `middleware_*`
candidate names observed on the (unmerged) V3 kernel branch, their types and label sets.
Allowed labels: `service`, `environment`, `adapter`, `command_family`, `state`, `result`;
bounded closed-enum extensions seen on the candidate: `stage`, `reason`, `mode`,
`operation`, `dependency`. Forbidden as labels: `customer`, `email`, `phone`, `command_id`,
`operation_id`, `correlation_id` and every other identifier in the contract. Two names need
reconciliation at re-pin: `dead_letters_total` (mission, counter) vs `middleware_dead_letters`
(candidate, gauge) and `dependency_health` (no candidate metric yet).

## Prepared (dark) rules

`codestra/prometheus/rules-prepared/middleware-v3/kernel-alerts.yml` holds twelve
`MiddlewareV3*` alerts (failure ratio, reconciliation backlog, outbox age and depth, dead
letters, lease expirations, adapter failure ratio and p95, safety and policy denial surges,
idempotent replay surge, kernel stage p95). `codestra/compose.yaml` mounts only
`codestra/prometheus/rules`, so nothing evaluates until the owner moves the file after
`V3_FINAL_SHA` is pinned. No absence alert exists: a metric that does not exist yet never pages.

## Validation

`python codestra/scripts/validate_middleware_v3_metrics.py` and
`python -m unittest discover -s codestra/tests -p 'test_middleware_v3_metrics.py'` run in
`.github/workflows/codestra-observability.yml`. The same change repairs the `py_compile`
continuation in that workflow (a literal `\n` made `py_compile` look for a file named `n`).
