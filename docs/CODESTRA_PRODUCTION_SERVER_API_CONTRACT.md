# Codestra Prometheus Production Server and Native API Contract

## Authority

- Repository: `appolon1908-hue/Codestra-Prometheus`
- Role: corporate metrics, recording-rule, SLI/SLO, and alert-evaluation authority
- Canonical hostname: `prom.codestra.media`
- Central production host: `37.27.128.39`
- Core host `65.109.65.169`: approved scrape/remote-metric source only
- Status: `SOURCE_CONTRACT_PREPARED_NOT_DEPLOYED`

This repository owns Prometheus configuration, rules, target policy, native API access, image/release evidence, retention/recovery, and rollback. It does not own alert delivery, application telemetry collection, business mutation, or provider actions.

## Native API surface

| Method | Path | Purpose | Boundary |
|---|---|---|---|
| `GET` | `/-/ready` | readiness | private/read-only |
| `GET` | `/-/healthy` | process health | private/read-only |
| `GET` | `/metrics` | Prometheus self-metrics | private |
| `GET` | `/api/v1/query` | bounded instant query | authenticated operator/read-only |
| `GET` | `/api/v1/query_range` | bounded range query | authenticated operator/read-only |
| `GET` | `/api/v1/rules` | rule state | authenticated/read-only |
| `GET` | `/api/v1/alerts` | alert-evaluation state | authenticated/read-only |

Administrative lifecycle, reload, delete-series, clean-tombstones, snapshot, and other mutation-capable endpoints must not be publicly or generally network-accessible. A `405` response to an unsupported probe method is **not** evidence that an administrative endpoint is protected: certification must test each route using its supported mutation methods, including `POST` and `PUT` where registered, and require network denial or authenticated `401`/`403` before a request reaches the mutation handler.

Expected protected responses may be `401`, `403`, `422`, or `429`. A `405` is acceptable only for an intentionally unsupported method on a read-only endpoint and never satisfies the administrative-denial gate. Unexpected `404` on required read-only routes and unexpected `5xx` are blockers.

## Target and label policy

- Native ports stay private on `37.27.128.39`.
- Targets are allowlisted and source-controlled.
- `codestra_business`, `application`, `service`, `environment`, `server`, `region`, and `deployment` are the canonical dimensions.
- Customer, tenant, user, request, trace, message, order, payment, transaction, URL, container-ID, and pod-UID values are prohibited metric labels.
- Scrape credentials come from approved runtime secret files/OpenBao, never Git.
- Down, stale, duplicate, high-cardinality, or source-drifted targets block certification.

## Production gates

```text
PROTECTED_PRODUCTION_SHA=PASS
PROMTOOL_CONFIG=PASS
PROMTOOL_RULES=PASS
RECORDING_RULE_TESTS=PASS
TARGET_ALLOWLIST=PASS
ADMIN_MUTATION_METHODS_DENIED=PASS
IMMUTABLE_IMAGE_DIGEST=PASS
IMAGE_SIGNATURE=PASS
SBOM=PASS
PROVENANCE=PASS
SECRET_SCAN=PASS
VULNERABILITY_GATE=PASS
SNAPSHOT_OR_BACKUP=PASS
RESTORE_VALIDATION=PASS
ROLLBACK_MANIFEST=PASS
```

No mutable tag, placeholder digest, unreviewed server patch, force push, or admin merge bypass is permitted.

## Runtime certification

```text
GET_/-/ready=PASS
GET_/-/healthy=PASS
GET_/metrics=PASS
GET_/api/v1/query_ROUTE_EXISTS=PASS
GET_/api/v1/query_range_ROUTE_EXISTS=PASS
GET_/api/v1/rules_ROUTE_EXISTS=PASS
GET_/api/v1/alerts_ROUTE_EXISTS=PASS
POST_OR_PUT_/-/reload=DENIED_401_403_OR_NETWORK
POST_OR_PUT_/api/v1/admin/tsdb/delete_series=DENIED_401_403_OR_NETWORK
POST_OR_PUT_/api/v1/admin/tsdb/clean_tombstones=DENIED_401_403_OR_NETWORK
POST_OR_PUT_/api/v1/admin/tsdb/snapshot=DENIED_401_403_OR_NETWORK
ADMIN_DENIAL_ACCEPTS_405=NO
ADMIN_ENDPOINTS_PUBLIC=NO
UNEXPECTED_404=0
UNEXPECTED_5XX=0
TARGETS_DOWN=0
SOURCE_RUNTIME_DRIFT=0
```

Administrative-denial tests use harmless invalid or empty fixtures and stop at the authentication/network boundary; they must not delete series, clean tombstones, create snapshots, or reload production configuration.

Prove Node Exporter, cAdvisor, Redis Exporter, Blackbox Exporter, and approved OpenTelemetry metrics flow into Prometheus, then into Grafana. Alert delivery remains governed outside this repository.

## Repository-first remediation

A runtime defect must be fixed here with a regression test, committed, pushed, reviewed, merged, rebuilt, signed, and added to the production BOM before retrying the server wave. Do not patch Prometheus directly on the host and leave GitHub behind.

## Safety

This document does not deploy Prometheus or activate scrapes. SSH changes, business writes, communications delivery, provider mutation, lending, payments, and trading remain outside scope and disabled.