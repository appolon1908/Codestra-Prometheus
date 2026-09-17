"""Middleware and OpenBao are scraped only through authenticated, credential-file-backed jobs."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prometheus_validate", ROOT / "scripts" / "validate.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def config() -> dict:
    return yaml.safe_load((ROOT / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))


def jobs_of(document: dict) -> dict:
    return {job["job_name"]: job for job in document["scrape_configs"]}


def test_committed_configuration_passes_every_check():
    MODULE.validate_targets()
    MODULE.validate_scrape_config()
    MODULE.validate_rules()


def test_middleware_is_scraped_as_monitoring_readonly_with_a_file_secret_and_metrics_read_only():
    job = jobs_of(config())["codestra-middleware-metrics"]
    assert job["oauth2"]["client_id"] == "monitoring-readonly"
    assert job["oauth2"]["scopes"] == ["metrics.read"]
    assert job["oauth2"]["client_secret_file"].startswith("/run/secrets/")
    assert "client_secret" not in job["oauth2"]
    assert job["static_configs"][0]["targets"] == ["middleware-integration-api:8095"]
    generic = json.loads((ROOT / "prometheus" / "targets" / "production.json").read_text(encoding="utf-8"))
    assert not [g for g in generic if g["labels"]["service"] in {"middleware", "openbao"}]


def test_openbao_is_scraped_privately_with_format_prometheus_and_no_long_lived_credential():
    job = jobs_of(config())["codestra-openbao"]
    assert job["metrics_path"] == "/v1/sys/metrics" and job["params"]["format"] == ["prometheus"]
    assert job["authorization"]["credentials_file"].startswith("/run/secrets/")
    assert "bearer_token" not in job and "credentials" not in job["authorization"]
    assert job["tls_config"]["insecure_skip_verify"] is False
    assert job["static_configs"][0]["labels"]["activation"] == "pending"


@pytest.mark.parametrize("mutate,message", [
    (lambda j: j["codestra-middleware-metrics"]["oauth2"].__setitem__("client_secret", "plain"), "never be inline"),
    (lambda j: j["codestra-middleware-metrics"]["oauth2"].__setitem__("scopes", ["metrics.read", "secret.read"]), "exactly the metrics.read scope"),
    (lambda j: j["codestra-middleware-metrics"]["oauth2"].__setitem__("client_id", "middleware-api"), "monitoring-readonly"),
    (lambda j: j["codestra-openbao"]["tls_config"].__setitem__("insecure_skip_verify", True), "verified mTLS"),
    (lambda j: j["codestra-openbao"].__setitem__("params", {"format": ["json"]}), "format=prometheus"),
    (lambda j: j["codestra-openbao"]["static_configs"][0]["labels"].__setitem__("activation", "active"), "stays pending"),
])
def test_dedicated_job_drift_fails_closed(mutate, message):
    jobs = jobs_of(copy.deepcopy(config()))
    mutate(jobs)
    with pytest.raises(SystemExit) as raised:
        MODULE.validate_dedicated_jobs(jobs)
    assert message in str(raised.value) or raised.value.code == 1


def test_inline_credentials_anywhere_are_rejected():
    document = copy.deepcopy(config())
    document["scrape_configs"][0]["bearer_token"] = "hvs.notallowed"
    with pytest.raises(SystemExit):
        MODULE.validate_no_inline_credentials(document)


def test_blackbox_modules_stay_read_only(monkeypatch, tmp_path):
    modules = yaml.safe_load((ROOT / "blackbox" / "blackbox.yml").read_text(encoding="utf-8"))
    assert all(str(m.get("http", {}).get("method", "GET")).upper() in {"GET", "HEAD"} for m in modules["modules"].values())
    poisoned = copy.deepcopy(modules)
    poisoned["modules"]["https_2xx"]["http"]["method"] = "POST"
    original = MODULE.load_yaml

    def fake_load(path):
        if path.name == "blackbox.yml":
            return poisoned
        return original(path)

    monkeypatch.setattr(MODULE, "load_yaml", fake_load)
    with pytest.raises(SystemExit):
        MODULE.validate_blackbox_modules()


def test_openbao_alerts_carry_required_governance_labels():
    document = yaml.safe_load((ROOT / "prometheus" / "rules" / "openbao-alerts.yml").read_text(encoding="utf-8"))
    names = {rule["alert"] for group in document["groups"] for rule in group["rules"]}
    assert {"OpenBaoSealed", "OpenBaoHealthProbeFailure", "OpenBaoAuditDeviceFailure", "OpenBaoAuthFailureSurge", "OpenBaoMetricsUnavailable"} <= names
    for group in document["groups"]:
        for rule in group["rules"]:
            assert {"severity", "owner", "service", "environment"} <= set(rule["labels"])
            assert rule["annotations"]["runbook_url"].startswith("https://")
            assert "secret_value" not in rule["expr"] and "unseal_key" not in rule["expr"]
