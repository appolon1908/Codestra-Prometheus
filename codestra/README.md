# Codestra Prometheus authority

This directory is the authoritative source for Codestra metrics collection, target discovery, recording rules, and alert evaluation. Service repositories own metric exposure; this repository owns scraping, labels, aggregation, alerts, and the canonical service catalogue. Alertmanager owns routing and notification credentials. Grafana must query recording rules instead of repeatedly evaluating expensive raw PromQL.

## Safety and labels

Metrics stay on the private `codestra-observability` network. Prometheus binds to loopback for reverse-proxy access; exporters and application endpoints are never published to the internet. Every target carries `environment`, `server`, `application`, `service`, and `tenant_scope`. Central metrics use `tenant_scope=aggregate`; raw tenant, customer, account, user, email, phone, token, session, request, trace, message, order, workflow, webhook, idempotency, raw path, URL, and query labels are rejected or stripped.

## Backend contract

Backends expose normalized `codestra_http_requests_total`, `codestra_http_request_duration_seconds`, dependency/database latency histograms, queue depth, worker failures, outbox/inbox count and oldest age, webhook delivery/retry counters, authentication/authorization failures, idempotency conflicts, reconciliation failures, provider failures, `codestra_deployment_info`, and `codestra_capability_state`. Capability modes are `disabled`, `simulation`, `shadow`, or `enabled`; live external-effect capabilities require `approval_state=approved` and production evidence.

## Activation

Targets marked `activation=pending` are catalogued but deliberately not scraped. Flip a target to `active` only after its service-owned PR, private-network attachment, endpoint contract test, and cardinality review pass. MoneyBee remains excluded under the owner's standing no-change directive.

Promotion is `feature/* -> development -> test -> staging -> production -> main`. Merging does not deploy or enable live application behavior.

## Immutable runtime preflight

The Compose candidate no longer accepts one free-form image string. Each image is assembled as:

```text
IMAGE_REPOSITORY@sha256:IMAGE_DIGEST
```

Repository inputs must contain no tag or digest. Digest inputs must be exactly 64 lowercase hexadecimal characters. Every render, release packet, and deployment procedure must run the preflight against the exact environment file before invoking Compose:

```bash
python codestra/scripts/validate_runtime_images.py --env-file /run/codestra/prometheus.env
docker compose --env-file /run/codestra/prometheus.env -f codestra/compose.yaml config
```

A direct `docker compose up` that bypasses this preflight is not an approved Codestra deployment path. CI negative-tests mutable tags, embedded digests, uppercase hashes, short hashes, and non-digest values.

## Validation and rollout

```bash
python codestra/scripts/validate.py
python codestra/scripts/validate_runtime_images.py --env-file /run/codestra/prometheus.env
cd upstream && go build -o ../.bin/promtool ./cmd/promtool
../.bin/promtool check config ../codestra/prometheus/prometheus.yml
../.bin/promtool check rules ../codestra/prometheus/rules/*.yml
```

Deploy exporters first, then built-in service metrics, then application instrumentation. Verify all required targets, send a synthetic Alertmanager alert, remove it, and complete a 24-hour staging soak before production promotion. Never delete backlog rows or enable live delivery to clear an alert.

## Governed observability API integration

The machine-readable contract at `catalog/observability-api-contract.v1.yml` defines the private Prometheus, Alertmanager, OpenTelemetry, Loki, Tempo, Grafana, Alloy, and exporter endpoints. Metrics use pull semantics: Prometheus scrapes the OpenTelemetry Collector's HTTPS metrics endpoint. Logs and traces continue through OTLP. All governed native endpoints require service identity and mTLS.

Run the read-only integration probe only from the private observability network with externally supplied certificates:

```bash
python codestra/scripts/probe_observability_integrations.py \
  --ca-file /run/secrets/observability/ca.crt \
  --cert-file /run/secrets/observability/prometheus.crt \
  --key-file /run/secrets/observability/prometheus.key \
  --output /tmp/observability-integration-evidence.json
```

The probe permits only GET/HEAD checks, never records URLs or certificate material in evidence, writes evidence mode `0600`, and exits nonzero if any governed check fails. It does not activate pending targets, deliver alerts, query customer data, or perform business writes.

## Authenticated scrapes and OpenBao

Middleware `/metrics` and OpenBao `/v1/sys/metrics` are scraped by dedicated jobs, never by the unauthenticated `codestra-targets` catalogue:

- `codestra-middleware-metrics` authenticates with the Keycloak `monitoring-readonly` client (`scope=metrics.read`, audience `middleware-api`) through `oauth2.client_secret_file`; the secret is rendered by the OpenBao agent from `codestra/<environment>/observability/prometheus/scrape-credentials/monitoring-readonly-client` (identity `prometheus-openbao`). The target is the canonical private runtime `middleware-integration-api:8095`.
- `codestra-openbao` uses `params.format=[prometheus]`, mTLS material and a short-lived bearer from `credentials_file`, all rendered outside Git; the token is bound to the `workload-prometheus-openbao-<environment>` policy, which grants `sys/metrics` read only. It stays `activation=pending` until the OpenBao runtime is certified.
- No `bearer_token`, `password`, `client_secret` or `credentials` value may appear inline; `codestra/scripts/validate.py` fails closed on any of them and on any Middleware/OpenBao entry in the file_sd catalogue.
- Blackbox targets may select a reviewed read-only module through the `probe_module` label (`https_2xx`, `http_2xx_internal`, `tcp_connect`, `https_openbao_health`, `dns_a_record`, `tls_expiry`); `https_openbao_health` issues only `GET /v1/sys/health`, accepts active/standby and never unseals.
- `rules/openbao-alerts.yml` covers metrics availability, sealed/leader state, health-probe failure and latency, audit-device failure or silence, authentication-failure surges, lease revocation surges and scrape-token expiry; `rules/monitoring-platform-alerts.yml` monitors the monitor (Middleware scrape identity, Alertmanager -> Middleware incident ingestion, log/trace pipelines, OTel export failures, safe probes, the TEST_SYN certification signal).

`promtool check config` in CI runs `--syntax-only` because the referenced credential files exist only at runtime; the runtime preflight proves their presence.
