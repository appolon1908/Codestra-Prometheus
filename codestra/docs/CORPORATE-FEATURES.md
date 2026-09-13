# Codestra Prometheus Corporate Features

## Mission

Prometheus is the authoritative Codestra metrics collection, recording-rule, SLI/SLO, capacity-signal, and alert-evaluation engine. It provides one operational metric language across the Codestra platform and every managed business while keeping Alertmanager responsible for routing and Grafana responsible for presentation.

The native Prometheus UI and API remain private. DNS assignment does not authorize Internet exposure.

## Corporate business representation

Every product and platform target carries these bounded labels:

- `codestra_business`
- `application`
- `service`
- `environment`
- `server`
- `region`
- `deployment`

The portfolio catalogue includes Codestra, MoneyBee, Beyvra, Breero, LARIM-A, Transportation, Booked4Seasons, Codestra Social, Klyrow, Telnexa, Kyqra, Restaurant, and Provisioning. Shared infrastructure uses `codestra_business="platform"`.

Product endpoints remain `activation="pending"` until the service-owned metrics contract, private network route, ownership, and staging evidence are proven. A pending target represents corporate coverage planning; it does not claim the endpoint is live.

## Application metric contract

Backend services should expose stable metric families for:

- request count, response class, and duration;
- dependency and database latency;
- queue depth and worker failures;
- inbox/outbox backlog and oldest age;
- webhook delivery, retry, and terminal failure;
- authentication failure and authorization denial;
- idempotency conflict and concurrency rejection;
- reconciliation failure and provider health;
- deployment/version information;
- externally effective capability state.

Routes must be normalized templates. Provider, dependency, operation, result, response class, queue, and bounded error-code labels are allowed only from governed enumerations.

## Privacy and cardinality boundary

Customer IDs, end-tenant IDs, account IDs, user IDs, email addresses, phone numbers, message IDs, request/correlation/trace/span IDs, order IDs, workflow/execution IDs, raw URLs, query strings, SQL statements, container IDs, pod UIDs, exception text, credentials, and payload content are forbidden as metric labels.

Prometheus strips unsafe resource attributes at ingestion as defense in depth. OpenTelemetry and application instrumentation must also remove them before export.

## Corporate feature set

- service and business health rollups;
- request rate, error ratio, and p50/p95/p99 latency;
- dependency, database, queue, worker, inbox, outbox, and webhook views;
- security and authorization signals;
- provider, reconciliation, and capability-state signals;
- SLI/SLO evaluation and multi-window burn-rate alerts;
- target-down, scrape-staleness, rule-evaluation, and notification-path monitoring;
- TSDB series, ingestion, memory, disk, and query saturation monitoring;
- cardinality and scrape-sample budgets;
- deployment/version correlation and rollback visibility;
- blackbox availability, TLS, DNS, and TCP probe inputs;
- exemplar-compatible latency histograms for trace drill-down;
- future remote-write readiness without making a remote system authoritative.

## Initial SLO model

SLO values are engineering defaults until calibrated with staging evidence and approved per service tier.

- Tier 1 external/customer paths: 99.9% monthly availability objective.
- Tier 2 internal business paths: 99.5% monthly availability objective.
- Tier 3 batch/administrative paths: service-owned objective and deadline-based SLIs.

Fast and slow multi-window burn rates are recorded so alerts represent sustained customer impact rather than one noisy sample. Error-budget policy never auto-enables a deployment, provider, communications delivery, trading, or financial capability.

## Financial and trading boundary

Beyvra metrics may expose aggregate order-path latency, provider health, reconciliation state, error rates, stale market-data state, and capability state. Prometheus must never receive trading credentials, signing material, balances, positions, account IDs, order IDs, raw trade payloads, or trade-mutation authority.

## Release and evidence rule

Configuration is promoted `feature/* -> development -> test -> staging -> production -> main`. CI validates Prometheus configuration, rules, corporate labels, target activation state, immutable images, and absence of unsafe labels. Production still requires private-network evidence, immutable artifacts, backup/restore proof, capacity evidence, rollback instructions, and human approval. Merge does not authorize deployment.
