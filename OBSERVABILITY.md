# Observability normalization — ingtrader21-spec/Codestra-Prometheus

Component class: **metrics-scraper-tsdb**

## Canonical Codestra observability flow

- Metrics: services/exporters -> **Prometheus** -> **Alertmanager**
- Logs: services/collectors -> **Loki**
- Traces: services/collectors -> **Tempo**
- Collection/forwarding: **Alloy / OpenTelemetry**
- Operations dashboards: **Grafana**
- Analytics dashboards: **Superset**

This repository may own only its observability function. It must not become a business-command or provider-effect path.

## Security and exposure

- /metrics and internal telemetry endpoints are private.
- Public dashboards, when intentionally exposed, go through Caddy/Kong and the approved identity boundary.
- No provider credentials are committed. Secrets use OpenBao/governed references.
- Observability writes are telemetry writes only; they may not trigger calling, messaging, billing, social publishing, provisioning, or other business effects.

## Service catalog

This component must be representable in Middleware /platform/v1/services with owner, repository, environment, health/metrics endpoints, dependencies, SLO, deployment SHA and status.

## Existing source signals

- monitoring-integration.v1.json detected: **true**
- Prometheus reference: **true**
- Alertmanager reference: **true**
- Loki reference: **false**
- Tempo reference: **false**
- Alloy/OpenTelemetry reference: **true**
- Grafana reference: **false**

These are source observations, not runtime certification. Runtime endpoints/ports remain governed by the repository's existing configuration and staging readback.
