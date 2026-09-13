#!/usr/bin/env python3
"""Fail-closed validation for the Codestra Prometheus corporate overlay."""

from __future__ import annotations

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


def validate_targets() -> None:
    services, businesses = validate_target_groups(
        ROOT / "prometheus" / "targets" / "production.json",
        REQUIRED_TARGET_LABELS,
    )
    production_groups = json.loads(
        (ROOT / "prometheus" / "targets" / "production.json").read_text(encoding="utf-8")
    )
    if any(group.get("labels", {}).get("activation") != "pending" for group in production_groups):
        fail("repository production targets must remain pending before runtime certification")
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
    blackbox_groups = json.loads(
        (ROOT / "blackbox" / "targets-production.json").read_text(encoding="utf-8")
    )
    if any(group.get("labels", {}).get("probe_enabled") != "false" for group in blackbox_groups):
        fail("repository Blackbox probes must remain disabled before runtime certification")


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
        if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
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


def main() -> int:
    validate_profile()
    validate_catalog()
    validate_targets()
    validate_scrape_config()
    validate_rules()
    validate_runtime()
    validate_secret_safety()
    print("Codestra Prometheus corporate authority validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
