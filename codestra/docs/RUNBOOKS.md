# Codestra Prometheus Runbooks

These runbooks are source-side operating procedures. They do not authorize deployment, alert delivery, provider changes, communications delivery, trading, lending, or other externally effective actions.

## SLO fast burn

1. Confirm the alert is present on the exact Prometheus head and inspect both the 5-minute and 1-hour burn rates.
2. Filter by `codestra_business`, `environment`, `application`, `service`, `region`, and `deployment`.
3. Correlate the first error-budget increase with deployment/version metrics and Grafana deployment annotations.
4. Review p95/p99 latency, dependency latency, database latency, queue/backlog, provider failure, and capability-state metrics.
5. Use exemplars to open representative traces, then use trace IDs to locate redacted logs.
6. Apply the owning service's approved rollback or containment procedure. Never enable a disabled external capability to clear an alert.
7. Record the incident ID, customer impact, deployment ID, mitigation, and evidence that the burn rate returned below threshold.

## SLO slow burn

1. Verify sustained burn in both the 6-hour and 3-day windows.
2. Segment by deployment and service version to distinguish chronic product defects from a recent release.
3. Compare business traffic volume and response-class mix to avoid interpreting a low-volume ratio without context.
4. Open a service-owned corrective action with an error-budget recovery plan, capacity assessment, and target date.
5. Do not silently raise the SLO threshold or metric budget. Any objective change requires documented business and reliability approval.

## Sample budget

1. Inspect `scrape_samples_post_metric_relabeling`, scrape duration, and the target's active-series contribution.
2. Identify the metric families and labels that expanded after the last deployment.
3. Confirm no customer, user, request, trace, message, order, raw URL, SQL, container, or pod-UID values became labels.
4. Fix instrumentation or metric relabeling before increasing the budget.
5. Keep the target `activation="pending"` if its cardinality cannot be bounded.

## Head series capacity

1. Check `prometheus_tsdb_head_series`, ingestion rate, memory, disk free space, compaction, WAL, and query latency.
2. Correlate growth with newly activated targets and recent deployments.
3. Rank jobs by active series and sample count, then isolate the largest unplanned change.
4. Remove unsafe/unbounded labels or temporarily return an unproven target to pending through the reviewed configuration path.
5. Capacity expansion requires immutable infrastructure changes, backup/restore review, and staging evidence.

## Rule evaluation failures

1. Inspect `prometheus_rule_evaluation_failures_total` by rule group and the Prometheus logs.
2. Run the repository's exact `promtool check rules` gate on the deployed commit.
3. Check for absent metrics, invalid joins, excessive query cost, and label-shape drift.
4. Repair through a reviewed branch; do not edit live rule files outside Git authority.
5. Prove all rule groups evaluate successfully before closing the incident.

## Notification failures

1. Verify Prometheus is evaluating alerts and isolate failure to notification delivery.
2. Check private network reachability, TLS/auth configuration when applicable, and Alertmanager health.
3. Confirm the Alertmanager endpoint and credentials come from approved runtime configuration and secrets.
4. Use the approved incident continuity path while alert delivery is impaired.
5. Do not add direct email, SMS, voice, Odoo, n8n, or provider receivers to Prometheus as a workaround.

## Operations dashboard API

1. Confirm the deployed Middleware, Kong, Keycloak, SDK, Grafana, and Prometheus commit SHAs match the approved release evidence.
2. Check the `/v1/operations-dashboard/*` endpoints with a `monitoring-readonly` token carrying `health.read`, `X-Tenant-ID`, and `X-Correlation-ID`.
3. Verify no-token, invalid-token, wrong-scope, wrong-tenant, and wrong-product calls still fail closed before trusting the dashboard.
4. Compare dashboard API p95 latency, 5xx ratio, release-gate state, and provider canary state against the live auth matrix.
5. If release gates or canaries are pending, keep capability flags disabled until staging read-back evidence exists.
6. Do not expose customer identifiers, secrets, bearer tokens, raw request paths, idempotency keys, or correlation IDs as metric labels.
