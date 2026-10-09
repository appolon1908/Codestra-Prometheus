#!/usr/bin/env python3
"""Fail-closed validation for the Codestra Prometheus corporate overlay."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUSINESSES = {
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
}
APPROVED_BUSINESS_LABELS = BUSINESSES | {"platform"}
CORPORATE_LABELS = {
    "codestra_business",
    "environment",
    "region",
    "deployment",
    "server",
    "application",
    "service",
}
REQUIRED_TARGET_LABELS = CORPORATE_LABELS | {
    "activation",
    "job_class",
    "tenant_scope",
}
ALLOWED_ENVIRONMENTS = {"development", "test", "staging", "production"}
ALLOWED_ACTIVATION = {"active", "pending"}
ALLOWED_TENANT_SCOPES = {"aggregate", "system", "isolated"}
ALLOWED_SEVERITIES = {"critical", "high", "warning", "informational"}
REQUIRED_ALERT_LABELS = {
    "severity",
    "owner",
    "codestra_business",
    "service",
    "environment",
}
REQUIRED_ALERT_ANNOTATIONS = {"summary", "description", "runbook_url"}
EXPECTED_JOBS = {
    "prometheus",
    "codestra-targets",
    "otel-application-metrics",
    "blackbox",
    "codestra-middleware-metrics",
    "codestra-openbao",
}
FORBIDDEN = re.compile(
    r"(?i)^(tenant_id|tenant_name|organization_id|organization_name|"
    r"customer_id|customer_name|account_id|user_id|user_name|email|phone|"
    r"consumer|workspace|token|secret|password|session_id|request_id|"
    r"correlation_id|trace_id|span_id|lead_id|order_id|message_id|workflow_id|"
    r"execution_id|webhook_id|idempotency_key|raw_path|path|uri|url|query|"
    r"query_string|client_address|network_peer_address|db_statement|http_target|"
    r"http_url|url_full|service_instance_id|host_id|container_id|image_id|"
    r"process_pid|pod_uid|exception_message|id)$"
)
REQUIRED_SERVICES = {
    "node-exporter",
    "cadvisor",
    "postgres-exporter",
    "redis-exporter",
    "caddy",
    "kong",
    "middleware",
    "keycloak",
    "n8n",
    "odoo",
    "opentelemetry-collector",
    "alertmanager",
    "loki",
    "tempo",
    "grafana",
    "alloy",
    "openbao",
    "codestra-backend",
    "moneybee-backend",
    "beyvra-backend",
    "breero-backend",
    "larim-a-backend",
    "transportation-backend",
    "booked4seasons-backend",
    "social-codestra",
    "klyrow-gateway",
    "telnexa-gateway",
    "kyqra-crawler",
    "restaurant-backend",
    "provisioning-api",
}
REQUIRED_SLO_RECORDS = {
    "codestra:slo_http_error_ratio:5m",
    "codestra:slo_http_error_ratio:1h",
    "codestra:slo_http_error_ratio:6h",
    "codestra:slo_http_error_ratio:3d",
    "codestra:slo_http_burn_rate:5m",
    "codestra:slo_http_burn_rate:1h",
    "codestra:slo_http_burn_rate:6h",
    "codestra:slo_http_burn_rate:3d",
}
REQUIRED_CONTROL_ALERTS = {
    "CodestraWatchdog",
    "CodestraSLOFastBurn",
    "CodestraSLOSlowBurn",
    "CodestraTargetSampleBudgetExceeded",
    "CodestraPrometheusRuleEvaluationFailures",
    "CodestraPrometheusNotificationFailures",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - diagnostic path
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def validate_profile() -> None:
    path = ROOT / "enterprise-profile.v1.json"
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid enterprise profile: {exc}")
    if profile.get("schemaVersion") != "1.1":
        fail("enterprise profile schemaVersion must be 1.1")
    if profile.get("canonicalHostname") != "prom.codestra.media":
        fail("canonical Prometheus hostname mismatch")
    if profile.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("Prometheus profile must remain CONFIG_PREPARED_NOT_DEPLOYED")
    if profile.get("exposure") != "internal_private":
        fail("native Prometheus exposure must remain internal_private")
    if set(profile.get("businessScope", [])) != BUSINESSES:
        fail("enterprise profile does not represent the complete Codestra portfolio")
    if set(profile.get("requiredTargetLabels", [])) != CORPORATE_LABELS:
        fail("enterprise profile corporate target labels do not match policy")
    required_features = {
        "recordingRules",
        "businessRollups",
        "sliAndSloEvaluation",
        "multiWindowBurnRates",
        "cardinalityBudgets",
        "alertmanagerIntegration",
        "pendingTargetActivationGates",
        "selfMonitoring",
    }
    disabled = sorted(
        name for name in required_features
        if profile.get("features", {}).get(name) is not True
    )
    if disabled:
        fail(f"required corporate Prometheus features are disabled: {disabled}")


def validate_catalog() -> None:
    catalog = load_yaml(ROOT / "catalog" / "services.yml")
    if catalog.get("version") != 2:
        fail("service catalogue version must be 2")
    catalogue_businesses = {
        entry.get("id")
        for entry in catalog.get("businesses", [])
        if isinstance(entry, dict)
    }
    if catalogue_businesses != BUSINESSES:
        fail("service catalogue business list is incomplete or contains unknown IDs")
    if set(catalog.get("required_labels", [])) != REQUIRED_TARGET_LABELS:
        fail("service catalogue required_labels must match the governed target contract")
    application_services = [
        entry
        for entry in catalog.get("application_services", [])
        if isinstance(entry, dict)
    ]
    product_businesses = {entry.get("codestra_business") for entry in application_services}
    if product_businesses != BUSINESSES:
        fail("application service catalogue must include every managed business")
    for entry in application_services:
        if entry.get("activation") != "pending":
            fail(f"business service must remain pending until evidence exists: {entry}")


def validate_target_groups(
    path: Path,
    required_labels: set[str],
) -> tuple[set[str], set[str]]:
    try:
        groups = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid target JSON {path.relative_to(ROOT)}: {exc}")
    if not isinstance(groups, list) or not groups:
        fail(f"target file must contain a non-empty list: {path.relative_to(ROOT)}")

    services: set[str] = set()
    businesses: set[str] = set()
    for group in groups:
        if not isinstance(group, dict) or not group.get("targets"):
            fail(f"target group without targets in {path.relative_to(ROOT)}")
        labels = group.get("labels", {})
        missing = required_labels - labels.keys()
        if missing:
            fail(f"target {group['targets']} missing labels {sorted(missing)}")
        if labels["codestra_business"] not in APPROVED_BUSINESS_LABELS:
            fail(f"target {group['targets']} has unknown business label")
        if labels["environment"] not in ALLOWED_ENVIRONMENTS:
            fail(f"target {group['targets']} has invalid environment")
        if not str(labels.get("region", "")).strip():
            fail(f"target {group['targets']} has empty region")
        if not str(labels.get("deployment", "")).strip():
            fail(f"target {group['targets']} has empty deployment")
        if "activation" in required_labels and labels["activation"] not in ALLOWED_ACTIVATION:
            fail(f"target {group['targets']} has invalid activation")
        if "tenant_scope" in required_labels and labels["tenant_scope"] not in ALLOWED_TENANT_SCOPES:
            fail(f"target {group['targets']} has invalid tenant_scope")
        if (
            "activation" in required_labels
            and labels["codestra_business"] in BUSINESSES
            and labels.get("activation") != "pending"
        ):
            fail(f"business target must remain pending before service-owned evidence: {group['targets']}")
        forbidden = [key for key in labels if FORBIDDEN.fullmatch(key)]
        if forbidden:
            fail(f"target {group['targets']} has forbidden labels {forbidden}")
        services.add(labels["service"])
        businesses.add(labels["codestra_business"])
    return services, businesses


# Jobs that authenticate to their target and therefore carry their own static
# targets instead of the unauthenticated file_sd catalogue.
DEDICATED_JOBS = {
    "codestra-middleware-metrics": "middleware",
    "codestra-openbao": "openbao",
}
INLINE_CREDENTIAL_KEYS = {"bearer_token", "password", "client_secret", "credentials"}
SAFE_PROBE_MODULES = {
    "https_2xx", "http_2xx_internal", "tcp_connect", "https_openbao_health",
    "dns_a_record", "tls_expiry",
}


def dedicated_job_services(config: dict[str, Any]) -> set[str]:
    services: set[str] = set()
    jobs = {job.get("job_name"): job for job in config.get("scrape_configs", [])}
    for job_name, service in DEDICATED_JOBS.items():
        job = jobs.get(job_name)
        if job is None:
            fail(f"dedicated scrape job {job_name} is missing")
        for group in job.get("static_configs", []):
            labels = group.get("labels", {})
            missing = REQUIRED_TARGET_LABELS - labels.keys()
            if missing:
                fail(f"{job_name} static target missing labels {sorted(missing)}")
            if labels.get("service") != service:
                fail(f"{job_name} must scrape service {service}")
            if labels.get("activation") not in ALLOWED_ACTIVATION:
                fail(f"{job_name} static target has invalid activation")
            services.add(labels["service"])
    return services


def validate_no_inline_credentials(config: dict[str, Any]) -> None:
    def walk(value: Any, trail: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in INLINE_CREDENTIAL_KEYS and isinstance(item, str) and item:
                    fail(f"inline credential in prometheus.yml at {trail}.{key}; use a *_file rendered from OpenBao")
                walk(item, f"{trail}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{trail}[{index}]")

    walk(config, "prometheus")


def validate_dedicated_jobs(jobs: dict[str, Any]) -> None:
    middleware = jobs["codestra-middleware-metrics"]
    oauth = middleware.get("oauth2", {})
    if oauth.get("client_id") != "monitoring-readonly":
        fail("Middleware metrics scrape must authenticate as monitoring-readonly")
    if not str(oauth.get("client_secret_file", "")).startswith("/run/secrets/"):
        fail("monitoring-readonly client secret must be an OpenBao-rendered file under /run/secrets")
    if "client_secret" in oauth:
        fail("monitoring-readonly client secret must never be inline")
    if oauth.get("scopes") != ["metrics.read"]:
        fail("Middleware metrics scrape must request exactly the metrics.read scope")
    if not str(oauth.get("token_url", "")).startswith("https://auth.codestra.co/realms/codestra/"):
        fail("Middleware metrics scrape must use the canonical Keycloak token endpoint over HTTPS")
    if middleware.get("metrics_path", "/metrics") != "/metrics":
        fail("Middleware metrics path drifted")
    targets = [t for group in middleware.get("static_configs", []) for t in group.get("targets", [])]
    if targets != ["middleware-integration-api:8095"]:
        fail("Middleware metrics scrape must target the canonical private runtime middleware-integration-api:8095")
    if not any(rule.get("action") == "labeldrop" for rule in middleware.get("metric_relabel_configs", [])):
        fail("Middleware metrics scrape requires defense-in-depth label stripping")

    openbao = jobs["codestra-openbao"]
    if openbao.get("scheme") != "https" or openbao.get("metrics_path") != "/v1/sys/metrics":
        fail("OpenBao scrape must use https and /v1/sys/metrics")
    if openbao.get("params", {}).get("format") != ["prometheus"]:
        fail("OpenBao scrape must request format=prometheus")
    authorization = openbao.get("authorization", {})
    if authorization.get("type") != "Bearer" or not str(authorization.get("credentials_file", "")).startswith("/run/secrets/"):
        fail("OpenBao scrape must present a short-lived bearer from a file under /run/secrets")
    tls = openbao.get("tls_config", {})
    if tls.get("insecure_skip_verify") is not False or not tls.get("ca_file") or not tls.get("cert_file") or not tls.get("key_file"):
        fail("OpenBao scrape must use verified mTLS material from files")
    for group in openbao.get("static_configs", []):
        if group.get("labels", {}).get("activation") != "pending":
            fail("OpenBao scrape stays pending until the OpenBao runtime is certified")
    if not any(rule.get("action") == "labeldrop" for rule in openbao.get("metric_relabel_configs", [])):
        fail("OpenBao scrape requires label stripping of token, accessor, lease and path labels")


def validate_blackbox_modules() -> None:
    modules = load_yaml(ROOT / "blackbox" / "blackbox.yml").get("modules", {})
    unsafe = {"POST", "PUT", "PATCH", "DELETE"}
    for name, module in modules.items():
        method = str(module.get("http", {}).get("method", "GET")).upper()
        if method in unsafe:
            fail(f"blackbox module {name} uses unsafe method {method}")
        if module.get("http", {}).get("body"):
            fail(f"blackbox module {name} must not send a body")
    health = modules.get("https_openbao_health", {})
    if health.get("http", {}).get("valid_status_codes") != [200, 429]:
        fail("https_openbao_health must accept only active (200) and standby (429)")
    if health.get("http", {}).get("tls_config", {}).get("insecure_skip_verify") is not False:
        fail("https_openbao_health must verify TLS")
    body_checks = health.get("http", {}).get("fail_if_body_not_matches_regexp", [])
    if not any("initialized" in check for check in body_checks) or not any("sealed" in check for check in body_checks):
        fail("https_openbao_health must require initialized=true and sealed=false in the body")
    targets = json.loads((ROOT / "blackbox" / "targets-production.json").read_text(encoding="utf-8"))
    for group in targets:
        module = group.get("labels", {}).get("probe_module")
        if module is not None and module not in SAFE_PROBE_MODULES:
            fail(f"blackbox target {group['targets']} selects an unreviewed module {module}")
        for target in group.get("targets", []):
            if "/v1/sys/health" in target and module != "https_openbao_health":
                fail("the OpenBao health target must use the https_openbao_health module")


def validate_targets() -> None:
    services, businesses = validate_target_groups(
        ROOT / "prometheus" / "targets" / "production.json",
        REQUIRED_TARGET_LABELS,
    )
    config = load_yaml(ROOT / "prometheus" / "prometheus.yml")
    validate_no_inline_credentials(config)
    services |= dedicated_job_services(config)
    for service in DEDICATED_JOBS.values():
        generic = [g["targets"] for g in json.loads((ROOT / "prometheus" / "targets" / "production.json").read_text(encoding="utf-8")) if g["labels"].get("service") == service]
        if generic:
            fail(f"{service} must be scraped only through its authenticated dedicated job, not the file_sd catalogue: {generic}")
    validate_blackbox_modules()
    missing_services = REQUIRED_SERVICES - services
    if missing_services:
        fail(f"missing required services {sorted(missing_services)}")
    if not BUSINESSES.issubset(businesses):
        fail(f"production target catalogue is missing businesses {sorted(BUSINESSES - businesses)}")

    blackbox_labels = CORPORATE_LABELS | {"tenant_scope", "probe_enabled"}
    validate_target_groups(
        ROOT / "blackbox" / "targets-production.json",
        blackbox_labels,
    )


def validate_scrape_config() -> None:
    config = load_yaml(ROOT / "prometheus" / "prometheus.yml")
    jobs = {job.get("job_name"): job for job in config.get("scrape_configs", [])}
    if set(jobs) != EXPECTED_JOBS:
        fail(f"unexpected scrape jobs {sorted(jobs)}")
    if not config.get("alerting", {}).get("alertmanagers"):
        fail("Alertmanager is required")

    external_labels = config.get("global", {}).get("external_labels", {})
    for label in ("codestra_business", "environment", "region", "deployment"):
        if not external_labels.get(label):
            fail(f"global external label is required: {label}")

    budgets = {
        "sample_limit",
        "label_limit",
        "label_name_length_limit",
        "label_value_length_limit",
        "body_size_limit",
    }
    for job_name, job in jobs.items():
        missing = budgets - job.keys()
        if missing:
            fail(f"scrape job {job_name} is missing budgets {sorted(missing)}")

    validate_dedicated_jobs(jobs)
    blackbox_relabel = jobs["blackbox"].get("relabel_configs", [])
    if not any(rule.get("target_label") == "__param_module" and rule.get("source_labels") == ["probe_module"] for rule in blackbox_relabel):
        fail("blackbox job must map the reviewed probe_module label to the module parameter")

    self_configs = jobs["prometheus"].get("static_configs", [])
    if len(self_configs) != 1 or not CORPORATE_LABELS.issubset(
        self_configs[0].get("labels", {})
    ):
        fail("Prometheus self-scrape requires all corporate labels")

    otel_job = jobs["otel-application-metrics"]
    if otel_job.get("honor_labels") is not True:
        fail("OTLP application scrape must preserve sanitized canonical labels")
    static_configs = otel_job.get("static_configs", [])
    if len(static_configs) != 1:
        fail("OTLP application scrape must have one governed static target")
    otel_labels = static_configs[0].get("labels", {})
    if otel_labels.get("activation") != "pending":
        fail("OTLP application scrape must remain pending until staging evidence passes")
    if not CORPORATE_LABELS.issubset(otel_labels):
        fail("OTLP application target requires all corporate labels")
    if static_configs[0].get("targets") != ["otel-collector:8889"]:
        fail("OTLP application scrape must target otel-collector:8889")
    metric_rules = otel_job.get("metric_relabel_configs", [])
    if not any(rule.get("action") == "labeldrop" for rule in metric_rules):
        fail("OTLP application scrape requires defense-in-depth label stripping")
    if not any(
        rule.get("action") == "drop" and "target_info" in str(rule.get("regex", ""))
        for rule in metric_rules
    ):
        fail("OTLP application scrape must drop resource metadata helper series")


def validate_rules() -> None:
    records: set[str] = set()
    alerts: set[str] = set()
    rule_files = sorted((ROOT / "prometheus" / "rules").glob("*.yml"))
    if not rule_files:
        fail("no Prometheus rule files found")
    for path in rule_files:
        doc = load_yaml(path)
        for group in doc.get("groups", []):
            for rule in group.get("rules", []):
                if not isinstance(rule.get("expr"), str) or not rule["expr"].strip():
                    fail(f"empty rule in {path.name}")
                if "record" in rule:
                    if rule["record"] in records:
                        fail(f"duplicate recording rule {rule['record']}")
                    records.add(rule["record"])
                if "alert" in rule:
                    alert = rule["alert"]
                    if alert in alerts:
                        fail(f"duplicate alert {alert}")
                    alerts.add(alert)
                    labels = rule.get("labels", {})
                    annotations = rule.get("annotations", {})
                    missing_labels = REQUIRED_ALERT_LABELS - labels.keys()
                    missing_annotations = REQUIRED_ALERT_ANNOTATIONS - annotations.keys()
                    if missing_labels:
                        fail(f"alert {alert} missing labels {sorted(missing_labels)}")
                    if missing_annotations:
                        fail(f"alert {alert} missing annotations {sorted(missing_annotations)}")
                    if labels["severity"] not in ALLOWED_SEVERITIES:
                        fail(f"alert {alert} has invalid severity {labels['severity']}")
                    if not str(annotations["runbook_url"]).startswith("https://"):
                        fail(f"alert {alert} runbook_url must be HTTPS")

    missing_records = REQUIRED_SLO_RECORDS - records
    if missing_records:
        fail(f"missing SLO recording rules {sorted(missing_records)}")
    missing_alerts = REQUIRED_CONTROL_ALERTS - alerts
    if missing_alerts:
        fail(f"missing control alerts {sorted(missing_alerts)}")


def validate_runtime() -> None:
    compose = load_yaml(ROOT / "compose.yaml")
    services = compose.get("services", {})
    if not services:
        fail("runtime candidate must define services")
    for name, service in services.items():
        image = str(service.get("image", ""))
        if "${" not in image or "@sha256:" not in image:
            fail(f"{name} must require an immutable image")
        if service.get("read_only") is not True:
            fail(f"{name} must use a read-only root filesystem")
        if "ALL" not in service.get("cap_drop", []):
            fail(f"{name} must drop all Linux capabilities")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            fail(f"{name} must set no-new-privileges")
        for port in service.get("ports", []):
            rendered = str(port)
            if (
                "127.0.0.1" not in rendered
                and "${PROMETHEUS_LISTEN_ADDRESS:-127.0.0.1:9090}" not in rendered
            ):
                fail(f"{name} may publish only a loopback-bound port")


def validate_secret_safety() -> None:
    # Build signatures in pieces so this validator does not match its own source.
    marker = "-" * 5
    signatures = (
        marker + "BEGIN " + "PRIVATE KEY" + marker,
        marker + "BEGIN " + "OPENSSH PRIVATE KEY" + marker,
        "AK" + "IA",
    )
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for signature in signatures:
            if signature in text:
                fail(
                    "secret-shaped material found in Codestra overlay: "
                    f"{path.relative_to(ROOT)}"
                )



def validate_observability_api_contract() -> None:
    contract = load_yaml(ROOT / "catalog" / "observability-api-contract.v1.yml")
    if contract.get("version") != 1:
        fail("observability API contract version must be 1")
    if contract.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("observability API contract must remain fail-closed before runtime evidence")
    security = contract.get("security", {})
    if security.get("transport") != "mtls":
        fail("observability service transport must require mTLS")
    if security.get("service_identity") != "required":
        fail("observability service identity must be required")
    if security.get("public_native_apis") != "forbidden":
        fail("native observability APIs must remain private")

    services = contract.get("services", {})
    required = {
        "prometheus", "alertmanager", "telemetry", "loki", "tempo", "grafana",
        "alloy", "node_exporter", "cadvisor", "postgres_exporter",
        "redis_exporter", "blackbox_exporter",
    }
    if set(services) != required:
        fail(f"observability API service set mismatch: {sorted(set(services) ^ required)}")

    expected_authorities = {
        "prometheus": "ingtrader21-spec/Codestra-Prometheus",
        "alertmanager": "ingtrader21-spec/Codestra-Alertmanager",
        "telemetry": "ingtrader21-spec/Codestra-Telemetry",
        "loki": "ingtrader21-spec/Codestra-Loki",
        "tempo": "ingtrader21-spec/Codestra-Tempo",
        "grafana": "ingtrader21-spec/Codestra-Grafana-",
        "alloy": "ingtrader21-spec/Codestra-Alloy",
        "node_exporter": "ingtrader21-spec/Codestra-Node-Exporter",
        "cadvisor": "ingtrader21-spec/Codestra-cAdvisor",
        "postgres_exporter": "ingtrader21-spec/Codestra-Postgres-Exporter",
        "redis_exporter": "ingtrader21-spec/Codestra-Redis-Exporter",
        "blackbox_exporter": "ingtrader21-spec/Codestra-Blackbox-Exporter",
    }
    for name, authority in expected_authorities.items():
        if services[name].get("authority") != authority:
            fail(f"{name} authority mismatch")

    if services["prometheus"]["alert_delivery"].get("target") != "https://alertmanager:9093/api/v2/alerts":
        fail("Prometheus must deliver alerts to the Alertmanager v2 API")
    for name, service in services.items():
        for key in ("base_url",):
            value = service.get(key)
            if value is not None and not str(value).startswith("https://"):
                fail(f"{name} {key} must use HTTPS for mTLS")
        for key in ("health", "readiness", "metrics", "application_metrics", "probe"):
            endpoint = service.get(key, {}).get("endpoint")
            if endpoint is not None and not str(endpoint).startswith("https://"):
                fail(f"{name} {key} endpoint must use HTTPS for mTLS")

    metrics_export = services["telemetry"]["exports"]["metrics"]
    if metrics_export != {
        "target": "https://otel-collector:8889/metrics",
        "protocol": "prometheus_scrape",
        "producer": "telemetry",
        "consumer": "prometheus",
    }:
        fail("Prometheus must scrape the governed telemetry metrics endpoint")
    if services["telemetry"]["exports"]["logs"].get("target") != "https://loki:3100/otlp":
        fail("Telemetry must export logs to Loki OTLP")
    if services["telemetry"]["exports"]["traces"].get("target") != "tempo:4317":
        fail("Telemetry must export traces to Tempo OTLP/gRPC")
    if set(services["alloy"].get("exports", [])) != {"telemetry", "loki", "tempo"}:
        fail("Alloy must export to telemetry, Loki, and Tempo")
    expected_producers = {
        ("alertmanager", "alerts"): {"prometheus", "loki"},
        ("loki", "otlp_logs"): {"telemetry", "alloy"},
        ("tempo", "otlp_grpc"): {"telemetry", "alloy"},
        ("tempo", "otlp_http"): {"telemetry", "alloy"},
    }
    for (service_name, endpoint_name), producers in expected_producers.items():
        actual = set(services[service_name][endpoint_name].get("producers", []))
        if actual != producers:
            fail(
                f"{service_name} {endpoint_name} producer relationship mismatch: "
                f"expected {sorted(producers)}"
            )

    expected_consumers = {
        ("prometheus", "query"): {"grafana"},
        ("alertmanager", "status"): {"grafana"},
        ("loki", "query"): {"grafana"},
        ("tempo", "search"): {"grafana"},
    }
    for (service_name, endpoint_name), consumers in expected_consumers.items():
        actual = set(services[service_name][endpoint_name].get("consumers", []))
        if actual != consumers:
            fail(
                f"{service_name} {endpoint_name} consumer relationship mismatch: "
                f"expected {sorted(consumers)}"
            )

    exporter_endpoints = {
        "node_exporter": "metrics",
        "cadvisor": "metrics",
        "postgres_exporter": "metrics",
        "redis_exporter": "metrics",
        "blackbox_exporter": "probe",
    }
    for service_name, endpoint_name in exporter_endpoints.items():
        consumer = services[service_name][endpoint_name].get("consumer")
        if consumer != "prometheus":
            fail(f"{service_name} {endpoint_name} consumer must be prometheus")
    if set(services["grafana"].get("datasources", [])) != {"prometheus", "loki", "tempo"}:
        fail("Grafana must use Prometheus, Loki, and Tempo data sources")
    if services["telemetry"]["application_metrics"].get("activation") != "pending":
        fail("application telemetry must remain pending until staging evidence passes")

    required_flows = {
        "prometheus_scrapes_telemetry", "telemetry_to_loki", "telemetry_to_tempo",
        "alloy_to_loki", "alloy_to_tempo",
        "prometheus_to_alertmanager", "loki_to_alertmanager",
        "exporters_to_prometheus", "grafana_to_prometheus",
        "grafana_to_loki", "grafana_to_tempo",
    }
    if set(contract.get("required_flows", [])) != required_flows:
        fail("observability required-flow set is incomplete")


def validate_target_inventory() -> None:
    """The committed per-target inventory must describe exactly this configuration."""
    spec = importlib.util.spec_from_file_location(
        "target_inventory", ROOT / "scripts" / "target_inventory.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    inventory = module.build_inventory()
    problems = module.check_invariants(inventory)
    if problems:
        fail("target inventory invariant: " + "; ".join(problems))
    committed = json.loads(
        (ROOT / "target-inventory.v1.json").read_text(encoding="utf-8")
    )
    if committed != inventory:
        fail(
            "codestra/target-inventory.v1.json is stale; "
            "regenerate with target_inventory.py --write"
        )


def main() -> int:
    validate_profile()
    validate_target_inventory()
    validate_catalog()
    validate_observability_api_contract()
    validate_targets()
    validate_scrape_config()
    validate_rules()
    validate_runtime()
    validate_secret_safety()
    print("Codestra Prometheus corporate authority validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
