# Codestra Prometheus Authority

Principal repository: `appolon1908-hue/Codestra-Prometheus`

Canonical service host: `prom.codestra.media`
Canonical DNS target: `37.27.128.39`

No alternate service hostname is authoritative. Config, docs, examples, scrape URLs and smoke tests use `prom.codestra.media` only when a DNS hostname is required.

## Ownership
Own Prometheus server configuration, scrape jobs, recording rules, alerting rules, retention/storage settings, service discovery, validation and upgrade runbooks. Do not own Grafana dashboards, Alertmanager routing, application code, exporters, Caddy or secrets.

## Exposure
Prometheus is private/internal. DNS may exist, but its service port must not be publicly exposed. Access is restricted to approved private networks, Grafana, Alertmanager integrations, operators through protected paths, and monitoring automation.

## Integration
Upstream: Node Exporter, cAdvisor, PostgreSQL Exporter, Redis Exporter, Blackbox Exporter, application `/metrics` endpoints and approved OpenTelemetry/Alloy metrics pipelines.
Downstream: Grafana queries and Alertmanager alert delivery.

## Branch policy
Persistent: `main`, `development`, `test`, `staging`, `production`.
Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`.
Promotion: work -> development -> test -> staging -> production -> main.
