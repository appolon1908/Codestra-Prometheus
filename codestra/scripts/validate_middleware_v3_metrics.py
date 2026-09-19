#!/usr/bin/env python3
"""Fail-closed validation of the Middleware V3 metrics contract and its dark rule file.

``codestra/contracts/middleware-v3-metrics.v1.json`` fixes the private Middleware
scrape contract (monitoring-readonly / metrics.read, never public), the V3
command-kernel metric expectations and a closed low-cardinality label policy.
This validator proves from source that the contract is dark and pinned, that the
``codestra-middleware-metrics`` job in ``prometheus.yml`` matches it (OAuth2 client
and scope, secret from a runtime file, private endpoint, labeldrop covering every
forbidden label), and that the prepared V3 rule file references only expected
metric names, aggregates only by allowed labels, carries the corporate alert
labels and annotations, and is not mounted by the runtime compose file.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "middleware-v3-metrics.v1.json"
PROMETHEUS = ROOT / "prometheus" / "prometheus.yml"
COMPOSE = ROOT / "compose.yaml"
PREPARED_RULES = ROOT / "prometheus" / "rules-prepared" / "middleware-v3" / "kernel-alerts.yml"
JOB = "codestra-middleware-metrics"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
METRIC_TOKEN = re.compile(r"\b(middleware_[a-z0-9_]+)\b")
BY_CLAUSE = re.compile(r"\bby\s*\(([^)]*)\)")
LABEL_MATCHER = re.compile(r"\{([^}]*)\}")
REQUIRED_ALERT_LABELS = {"severity", "owner", "codestra_business", "service", "environment"}
REQUIRED_ANNOTATIONS = {"summary", "description", "runbook_url"}
ALLOWED_SEVERITIES = {"critical", "high", "warning", "informational"}
MISSION_METRICS = {
    "commands_received_total", "commands_completed_total", "commands_failed_total",
    "commands_reconciliation_required_total", "command_duration_seconds", "idempotency_duplicates_total",
    "policy_denials_total", "safety_denials_total", "outbox_backlog", "outbox_oldest_seconds",
    "active_leases", "lease_expirations_total", "adapter_requests_total", "adapter_failures_total",
    "adapter_latency_seconds", "dead_letters_total", "reconciliation_backlog", "dependency_health",
}
MISSION_ALLOWED = {"service", "environment", "adapter", "command_family", "state", "result"}
MISSION_FORBIDDEN = {"customer", "email", "phone", "command_id", "operation_id", "correlation_id"}


def fail(message: str) -> None:
    print(f"MIDDLEWARE_V3_METRICS_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: Path) -> Any:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def validate_contract(contract: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    if contract.get("schema_version") != "1.0" or contract.get("contract_id") != "middleware-v3-metrics":
        fail("contract identity drift")
    if contract.get("status") != "PREPARED_DISABLED":
        fail("the V3 metrics contract must stay PREPARED_DISABLED until V3_FINAL_SHA is pinned")
    if contract.get("activation_enabled") is not False or contract.get("provider_effects_enabled") is not False:
        fail("activation_enabled and provider_effects_enabled must be false")
    middleware = contract.get("middleware", {})
    if not SHA40.fullmatch(str(middleware.get("prep_base_sha", ""))):
        fail("middleware.prep_base_sha must be a 40-hex commit")
    final = middleware.get("v3_final_sha")
    if final != "PENDING" and not SHA40.fullmatch(str(final)):
        fail("middleware.v3_final_sha must be PENDING or a 40-hex commit")

    scrape = contract.get("scrape_contract", {})
    identity = scrape.get("identity", {})
    if scrape.get("job_name") != JOB or scrape.get("metrics_path") != "/metrics" or scrape.get("method") != "GET":
        fail("scrape contract must describe GET /metrics on the codestra-middleware-metrics job")
    if identity.get("client_id") != "monitoring-readonly" or identity.get("scope") != "metrics.read":
        fail("the scrape identity must be monitoring-readonly with scope metrics.read")
    if identity.get("audience") != "middleware-api":
        fail("the scrape token audience must be middleware-api")
    if scrape.get("public_exposure") is not False:
        fail("/metrics is never public")
    if not str(identity.get("client_secret_source", "")).startswith("/run/secrets/"):
        fail("the scrape client secret must come from a runtime-rendered file")
    if scrape.get("evidence_at_prep_base", {}).get("worker_metrics_exposure_classification") != "PRIVATE_REQUIRED":
        fail("worker /metrics exposure must be classified PRIVATE_REQUIRED")

    policy = contract.get("label_policy", {})
    allowed = set(policy.get("allowed", []))
    extension = set(policy.get("bounded_extension_observed_on_v3_candidate", {}))
    forbidden = set(policy.get("forbidden", []))
    if allowed != MISSION_ALLOWED:
        fail(f"allowed labels must be exactly {sorted(MISSION_ALLOWED)}")
    if not MISSION_FORBIDDEN <= forbidden:
        fail(f"forbidden labels must include {sorted(MISSION_FORBIDDEN)}")
    if (allowed | extension) & forbidden:
        fail("a label cannot be both allowed and forbidden")

    metrics = contract.get("expected_metrics")
    if not isinstance(metrics, list) or not metrics:
        fail("expected_metrics is required")
    names = {m.get("name") for m in metrics}
    if names != MISSION_METRICS:
        fail(f"expected metric set drift: missing {sorted(MISSION_METRICS - names)} extra {sorted(names - MISSION_METRICS)}")
    candidates: set[str] = set()
    for metric in metrics:
        if metric.get("status") != "EXPECTED_PENDING_V3" or metric.get("present_at_prep_base") is not False:
            fail(f"{metric.get('name')}: every V3 metric is EXPECTED_PENDING_V3 and absent at the prep base")
        if metric.get("type") not in {"counter", "gauge", "histogram"}:
            fail(f"{metric.get('name')}: unknown metric type")
        candidate = str(metric.get("v3_candidate_name", ""))
        if not candidate.startswith("middleware_"):
            fail(f"{metric.get('name')}: v3_candidate_name must carry the middleware_ prefix")
        candidates.add(candidate)
        bad = [label for label in metric.get("labels", []) if label not in allowed | extension]
        if bad:
            fail(f"{metric.get('name')}: labels {bad} are outside the allowed set")
        if any(label in forbidden for label in metric.get("labels", [])):
            fail(f"{metric.get('name')}: forbidden label")
    prepared = contract.get("prepared_rules", {})
    if prepared.get("loaded_by_runtime") is not False:
        fail("prepared rules must be declared dark")
    if Path(str(prepared.get("path", ""))) != PREPARED_RULES.relative_to(ROOT.parent):
        fail("prepared_rules.path drift")
    return candidates, allowed | extension, forbidden


def validate_scrape_job(forbidden: set[str]) -> None:
    config = load_yaml(PROMETHEUS)
    jobs = {job.get("job_name"): job for job in config.get("scrape_configs", [])}
    job = jobs.get(JOB)
    if job is None:
        fail(f"{JOB} job is missing from prometheus.yml")
    if job.get("metrics_path") != "/metrics":
        fail(f"{JOB} must scrape /metrics")
    oauth = job.get("oauth2", {})
    if oauth.get("client_id") != "monitoring-readonly" or oauth.get("scopes") != ["metrics.read"]:
        fail(f"{JOB} must authenticate as monitoring-readonly with scope metrics.read")
    if "client_secret" in oauth or not str(oauth.get("client_secret_file", "")).startswith("/run/secrets/"):
        fail(f"{JOB} client secret must be a /run/secrets file, never inline")
    if not str(oauth.get("token_url", "")).startswith("https://auth.codestra.co/realms/codestra/"):
        fail(f"{JOB} token_url must be the Codestra realm")
    for group in job.get("static_configs", []):
        for target in group.get("targets", []):
            host = str(target).split(":")[0]
            if host in {"0.0.0.0", "localhost", "127.0.0.1"} or "." in host and not host.endswith(".internal"):
                fail(f"{JOB} target {target} is not a private service name")
            if not str(target).startswith("middleware-integration-api:8095"):
                fail(f"{JOB} must target middleware-integration-api:8095")
    drops = [rule for rule in job.get("metric_relabel_configs", []) if rule.get("action") == "labeldrop"]
    if not drops:
        fail(f"{JOB} needs a labeldrop guard")
    pattern = re.compile(drops[0]["regex"])
    uncovered = sorted(label for label in forbidden if not pattern.fullmatch(label))
    if uncovered:
        fail(f"{JOB} labeldrop does not cover forbidden labels {uncovered}")


def validate_prepared_rules(candidates: set[str], allowed: set[str], forbidden: set[str]) -> None:
    if not PREPARED_RULES.is_file():
        fail("prepared V3 rule file is missing")
    compose = COMPOSE.read_text(encoding="utf-8")
    if "rules-prepared" in compose:
        fail("prepared rules must not be mounted by codestra/compose.yaml until V3 is pinned")
    doc = load_yaml(PREPARED_RULES)
    groups = doc.get("groups") if isinstance(doc, dict) else None
    if not groups:
        fail("prepared rule file has no groups")
    seen: set[str] = set()
    for group in groups:
        for rule in group.get("rules", []):
            expr = rule.get("expr")
            if not isinstance(expr, str) or not expr.strip():
                fail("empty prepared rule expression")
            if "absent(" in expr or "absent_over_time(" in expr:
                fail("prepared rules must not page on metrics that do not exist yet")
            metrics = set(METRIC_TOKEN.findall(expr))
            unknown = sorted(m for m in metrics if m not in candidates and not any(m == f"{c}_bucket" or m == f"{c}_sum" or m == f"{c}_count" for c in candidates))
            if unknown:
                fail(f"prepared rule references unexpected metrics {unknown}")
            for clause in BY_CLAUSE.findall(expr):
                labels = {item.strip() for item in clause.split(",") if item.strip()}
                bad = sorted(labels - allowed - {"le"})
                if bad:
                    fail(f"prepared rule aggregates by disallowed labels {bad}")
            for matcher in LABEL_MATCHER.findall(expr):
                for item in matcher.split(","):
                    key = item.split("=")[0].strip().rstrip("!~")
                    if key in forbidden:
                        fail(f"prepared rule selects on forbidden label {key}")
            if "alert" not in rule:
                continue
            name = rule["alert"]
            if name in seen:
                fail(f"duplicate prepared alert {name}")
            seen.add(name)
            labels = rule.get("labels", {})
            annotations = rule.get("annotations", {})
            if REQUIRED_ALERT_LABELS - labels.keys():
                fail(f"{name} missing labels {sorted(REQUIRED_ALERT_LABELS - labels.keys())}")
            if REQUIRED_ANNOTATIONS - annotations.keys():
                fail(f"{name} missing annotations {sorted(REQUIRED_ANNOTATIONS - annotations.keys())}")
            if labels["severity"] not in ALLOWED_SEVERITIES:
                fail(f"{name} has invalid severity {labels['severity']}")
            if not str(annotations["runbook_url"]).startswith("https://"):
                fail(f"{name} runbook_url must be HTTPS")
            if labels.get("service") != "middleware" or labels.get("codestra_business") != "platform":
                fail(f"{name} must be owned by the platform middleware service")
    if len(seen) < 10:
        fail("prepared kernel alert coverage is incomplete")


def main() -> None:
    contract = load_json(CONTRACT)
    candidates, allowed, forbidden = validate_contract(contract)
    validate_scrape_job(forbidden)
    validate_prepared_rules(candidates, allowed, forbidden)
    print(
        "MIDDLEWARE_V3_METRICS=PASS status=PREPARED_DISABLED "
        f"prep_base={contract['middleware']['prep_base_sha'][:12]} v3_final={contract['middleware']['v3_final_sha']} "
        f"metrics={len(contract['expected_metrics'])}"
    )


if __name__ == "__main__":
    main()
