# Intake forms and surveys monitoring

Prometheus owns operational metrics and alert evaluation for the unified Codestra intake path:

`website/widget -> intake SDK -> same-origin BFF -> Caddy -> Kong -> Middleware durable intake -> approved destinations`.

It does not store form fields, survey answers, contact information, consent text, messages, transcripts, campaign identifiers or customer-level data.

## Raw application metrics

Middleware and its intake workers expose:

- `lead_submissions_total`
- `lead_duplicates_total`
- `lead_validation_failures_total`
- `lead_odoo_delivery_total`
- `lead_odoo_delivery_failures_total`
- `lead_processing_duration_seconds`
- `survey_responses_total`
- `survey_validation_failures_total`
- `survey_processing_duration_seconds`
- `intake_inbox_backlog`
- `intake_outbox_backlog`
- `intake_oldest_pending_seconds`
- `intake_rate_limit_rejections_total`
- `intake_spam_rejections_total`

Only bounded operational dimensions are permitted: `codestra_business`, `application`, `service`, `environment`, `channel`, `form_kind`, `survey_kind`, `result`, `reason`, `delivery_target`, and boolean `anonymous`.

## Lead validation failures

Check schema/version compatibility, required consent policy, payload-size limits, accepted channel/form taxonomy and SDK/BFF release drift. Never log or attach the rejected payload to an alert.

## Duplicate ratio

Confirm idempotency-key propagation from BFF to Kong and Middleware, durable inbox uniqueness and retry behavior. A high duplicate ratio may represent double-clicks, browser retries, replay, abusive traffic or a broken idempotency contract. Do not delete inbox records to clear this alert.

## Processing latency

Review Middleware saturation, Redis latency, durable inbox/outbox age, worker concurrency and downstream dependency latency. Preserve accepted submissions; use backpressure rather than dropping data.

## Odoo delivery

Confirm Odoo health, adapter credentials, circuit-breaker state and outbox retries. Lead acceptance and Odoo delivery are separate states. Do not report a lead as lost merely because delivery is delayed.

## Durable backlog

Inspect queue depth and oldest age together. Scale workers only within approved capacity limits. Never purge pending lead or survey records as an alert-remediation shortcut.

## Survey validation

Check survey-definition version, expiration, branching contract, anonymous-mode rules and sensitive-field policy. Anonymous responses must not carry contact or lead identifiers.

## Survey processing

Confirm survey persistence and analytics read-model health. Survey answers remain separate from CRM lead fields and are never metric labels.

## Rate limit and abuse

Review Caddy/Kong rate limiting, spam/risk rejection reasons and affected channel. Blackbox probes are GET/HEAD readiness probes only and must never submit synthetic leads or surveys.

## Release safety

All targets remain pending until service-owned instrumentation, private-network connectivity, label-cardinality review and staging evidence exist. Configuration merge does not deploy or enable live Odoo, n8n, SMS, email or voice behavior.
