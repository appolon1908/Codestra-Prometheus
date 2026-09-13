#!/usr/bin/env python3
"""Collect fail-closed staging evidence for the private Middleware metrics boundary.

The collector never writes business data. It performs GET requests only, never
prints bearer tokens, and writes a canonical allowlisted JSON evidence document
plus its SHA-256 checksum.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

EXPECTED_METRIC_FAMILIES = {
    "codestra_http_requests",
    "codestra_http_request_duration_seconds",
    "codestra_http_active_requests",
    "codestra_auth_denials",
    "codestra_readiness",
    "codestra_release_info",
    "codestra_start_time_seconds",
    "lead_submissions",
    "lead_duplicates",
    "lead_validation_failures",
    "lead_processing_duration_seconds",
    "lead_odoo_delivery",
    "lead_odoo_delivery_failures",
    "survey_responses",
    "survey_validation_failures",
    "survey_processing_duration_seconds",
    "intake_inbox_backlog",
    "intake_outbox_backlog",
    "intake_oldest_pending_seconds",
    "intake_backlog_collection_success",
    "intake_rate_limit_rejections",
    "intake_spam_rejections",
}

EXPECTED_EXTERNAL_EFFECT_KEYS = {
    "SEND_EVENTS",
    "ENABLE_EXTERNAL_DELIVERY",
    "LIVE_WRITE",
    "LIVE_WRITES",
    "ODOO_WRITE",
    "CALLBACK_DISPATCH",
    "N8N_DELIVERY_ENABLED",
    "VICIDIAL_WRITES_ENABLED",
    "EXTERNAL_DIAL_ENABLED",
    "PRODUCTION_CALLBACKS_ENABLED",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "FORM_ODOO_DELIVERY_ENABLED",
    "CRAWLER_ODOO_DELIVERY_ENABLED",
    "SCRAPPER_ODOO_DELIVERY_ENABLED",
    "CRAWLER_EXTERNAL_CONTACT_ENABLED",
    "SCRAPPER_EXTERNAL_CONTACT_ENABLED",
    "SMS_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED",
    "CRAWLER_EXECUTION_ENABLED",
    "SCRAPPER_EXECUTION_ENABLED",
    "LIVE_SMS_DELIVERY",
    "LIVE_EMAIL_DELIVERY",
    "UNRESTRICTED_CRAWLING",
}

EXPECTED_UMBRELLA_CONTROL_KEYS = {
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
}

EXPECTED_RUNTIME_SAFETY_KEYS = {
    "schema_version",
    "service",
    "environment",
    "runtime_profile_id",
    "release",
    "persistence",
    "dispatch",
    "external_effects",
    "umbrella_controls",
    "production_dialing",
    "production_activation_configured",
    "provider_effects_disabled",
    "all_external_effects_disabled",
    "staging_safe",
}

ALLOWED_LABEL_NAMES = {
    "codestra_business", "application", "service", "component", "environment",
    "operation", "method", "status", "dependency", "release_sha", "image_digest",
    "schema_or_migration_head", "version", "channel", "form_kind", "result",
    "reason", "survey_kind", "anonymous", "delivery_target", "queue", "le", "quantile",
}

IDENTITY_LABEL_PATTERNS = {
    "release_sha": re.compile(r"[0-9a-f]{40}"),
    "image_digest": re.compile(r"sha256:[0-9a-f]{64}"),
    "schema_or_migration_head": re.compile(r"[0-9]{4}_[a-z0-9_]{3,96}"),
    "version": re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?"),
}

FORBIDDEN_LABEL_RE = re.compile(
    r"(?i)^(tenant(_id|_name)?|organization(_id|_name)?|customer(_id|_name)?|"
    r"account_id|user(_id|_name)?|email|phone|consumer|workspace|token|secret|"
    r"password|session_id|request_id|correlation_id|trace_id|span_id|lead_id|"
    r"order_id|message_id|workflow_id|execution_id|webhook_id|idempotency_key|"
    r"raw_path|uri|url|query|query_string|client_address|network_peer_address|"
    r"db_statement|http_target|http_url|url_full|service_instance_id|host_id|"
    r"container_id|image_id|process_pid|pod_uid|exception_message|id)$"
)

SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~-]+"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:\+?\d[\d(). -]{8,}\d)\b"),
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)https?://"),
)

SAMPLE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+"
    r"(?P<value>[-+]?([0-9]*\.?[0-9]+|Inf|NaN)([eE][-+]?[0-9]+)?)"
    r"(?:\s+[0-9]+)?$"
)


class EvidenceError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EvidenceError(f"redirects are prohibited ({code})")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read_private_file(path: Path, *, maximum_bytes: int = 65536) -> str:
    if path.is_symlink():
        raise EvidenceError(f"secret path must not be a symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceError(f"secret path is not a regular file: {path}")
    if info.st_mode & 0o077:
        raise EvidenceError(f"secret path permissions must be 0600 or stricter: {path}")
    if info.st_size <= 0 or info.st_size > maximum_bytes:
        raise EvidenceError(f"secret file has invalid size: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise EvidenceError(f"secret file is empty: {path}")
    return value


def decode_jwt_metadata(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise EvidenceError("monitoring token is not a compact JWT")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception as exc:
        raise EvidenceError("monitoring token payload cannot be decoded") from exc
    issued = payload.get("iat")
    expires = payload.get("exp")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)):
        raise EvidenceError("token iat is missing")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        raise EvidenceError("token exp is missing")
    ttl = int(expires - issued)
    if ttl < 60 or ttl > 300:
        raise EvidenceError(f"token lifetime is outside 60-300 seconds: {ttl}")
    scopes_raw = payload.get("scope", "")
    scopes = sorted(set(scopes_raw.split())) if isinstance(scopes_raw, str) else []
    audience = payload.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or "middleware-api" not in audiences:
        raise EvidenceError("token audience does not include middleware-api")
    if payload.get("azp") != "monitoring-readonly":
        raise EvidenceError("token azp is not monitoring-readonly")
    return {
        "client_id": "monitoring-readonly",
        "ttl_seconds": ttl,
        "scopes": scopes,
        "audience": "middleware-api",
        "token_sha256": sha256_bytes(token.encode("utf-8")),
    }


def validate_base_url(raw: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(raw.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EvidenceError("base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise EvidenceError("base URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise EvidenceError("base URL must not contain a path")
    host = parsed.hostname.lower()
    blocked = {"api.codestra.co", "codestra.co", "www.codestra.co"}
    if host in blocked or re.search(r"(^|[-.])(prod|production)([-.]|$)", host):
        raise EvidenceError("production or public Codestra targets are prohibited")
    try:
        resolved = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))}
    except socket.gaierror as exc:
        raise EvidenceError(f"staging host cannot be resolved: {host}") from exc
    if not resolved:
        raise EvidenceError("staging host resolved to no addresses")
    for address in resolved:
        ip = ipaddress.ip_address(address)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise EvidenceError(f"staging endpoint resolved to a public address: {address}")
    return raw.rstrip("/"), host


def request(url: str, token: str | None = None, *, timeout: float = 10.0) -> tuple[int, dict[str, str], bytes]:
    headers = {"Accept": "application/json, text/plain; q=0.9", "User-Agent": "codestra-staging-evidence-collector/1.0"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method="GET", headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()
    except EvidenceError:
        raise
    except Exception as exc:
        raise EvidenceError(f"GET request failed for {urllib.parse.urlsplit(url).path}") from exc


def split_labels(raw: str) -> Iterable[str]:
    current: list[str] = []
    quoted = False
    escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == "," and not quoted:
            yield "".join(current)
            current = []
        else:
            current.append(char)
    if current:
        yield "".join(current)


def parse_label_set(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    labels: dict[str, str] = {}
    for item in split_labels(raw):
        name, separator, value = item.partition("=")
        if separator != "=" or not value.startswith('"') or not value.endswith('"'):
            raise EvidenceError("invalid Prometheus label syntax")
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise EvidenceError("invalid Prometheus label escaping") from exc
        if name in labels:
            raise EvidenceError(f"duplicate Prometheus label: {name}")
        labels[name] = decoded
    return labels


def family_name(metric_name: str) -> str:
    for suffix in ("_created", "_total", "_bucket", "_sum", "_count"):
        if metric_name.endswith(suffix):
            return metric_name[:-len(suffix)]
    return metric_name


def analyze_metrics(payload: bytes, *, max_series: int, max_family_series: int) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("metrics response is not UTF-8") from exc
    if len(payload) > 8 * 1024 * 1024:
        raise EvidenceError("metrics response exceeds 8 MiB")
    declared_families: set[str] = set()
    sampled_families: set[str] = set()
    series_by_family: dict[str, int] = {}
    sample_count = 0
    intake_samples = 0
    privacy_findings: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("# HELP ") or line.startswith("# TYPE "):
            parts = line.split()
            if len(parts) >= 3:
                declared_families.add(family_name(parts[2]))
            continue
        if line.startswith("#"):
            continue
        match = SAMPLE_RE.fullmatch(line)
        if not match:
            raise EvidenceError(f"invalid Prometheus sample line: {line[:120]}")
        name = match.group("name")
        family = family_name(name)
        labels = parse_label_set(match.group("labels"))
        sample_count += 1
        series_by_family[family] = series_by_family.get(family, 0) + 1
        sampled_families.add(family)
        unknown_labels = set(labels) - ALLOWED_LABEL_NAMES
        forbidden_labels = {label for label in labels if FORBIDDEN_LABEL_RE.fullmatch(label)}
        if unknown_labels or forbidden_labels:
            raise EvidenceError("forbidden or unknown metric labels: " + ",".join(sorted(unknown_labels | forbidden_labels)))
        for label_name, value in labels.items():
            if len(value) > 256:
                raise EvidenceError(f"metric label value too long: {label_name}")
            identity_pattern = IDENTITY_LABEL_PATTERNS.get(label_name)
            if identity_pattern is not None and identity_pattern.fullmatch(value) is None:
                raise EvidenceError(f"metric identity label has invalid format: {label_name}")
            for pattern in SENSITIVE_VALUE_PATTERNS:
                if pattern.search(value):
                    privacy_findings.append(f"{family}:{label_name}")
        if family in EXPECTED_METRIC_FAMILIES:
            intake_samples += 1
            if family.startswith(("lead_", "survey_", "intake_")):
                expected = {"codestra_business": "platform", "application": "integration", "service": "middleware-api", "environment": "staging"}
                for key, value in expected.items():
                    if labels.get(key) != value:
                        raise EvidenceError(f"intake metric {family} has invalid {key}")
    missing = EXPECTED_METRIC_FAMILIES - sampled_families
    if missing:
        raise EvidenceError("required metric families are missing: " + ",".join(sorted(missing)))
    if sample_count <= 0 or sample_count > max_series:
        raise EvidenceError(f"series count outside limit: {sample_count}")
    oversized = {family: count for family, count in series_by_family.items() if count > max_family_series}
    if oversized:
        raise EvidenceError("per-family cardinality exceeded: " + json.dumps(oversized, sort_keys=True))
    if privacy_findings:
        raise EvidenceError("PII-like values detected in metric labels: " + ",".join(sorted(set(privacy_findings))))
    return {
        "payload_sha256": sha256_bytes(payload),
        "payload_bytes": len(payload),
        "series_count": sample_count,
        "family_count": len(sampled_families),
        "declared_family_count": len(declared_families),
        "sampled_metric_families": sorted(sampled_families),
        "intake_sample_count": intake_samples,
        "maximum_family_series": max(series_by_family.values(), default=0),
        "required_metric_families": sorted(EXPECTED_METRIC_FAMILIES),
        "missing_metric_families": [],
        "privacy_findings": [],
    }


def validate_runtime_safety(payload: bytes, expected_source: str, expected_digest: str) -> dict[str, Any]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise EvidenceError("runtime-safety response is not JSON") from exc
    if not isinstance(data, dict) or set(data) != EXPECTED_RUNTIME_SAFETY_KEYS:
        raise EvidenceError("runtime-safety response contains missing or unexpected fields")
    if data["schema_version"] != "1.1" or data["service"] != "middleware-api":
        raise EvidenceError("runtime-safety identity is invalid")
    if data["environment"] != "staging":
        raise EvidenceError("runtime environment is not staging")
    if data["runtime_profile_id"] != "codestra-middleware-staging-v1":
        raise EvidenceError("runtime profile does not match the immutable image")

    release = data["release"]
    if not isinstance(release, dict) or set(release) != {"source_sha", "image_digest", "schema_head", "build_time"}:
        raise EvidenceError("runtime release evidence shape is invalid")
    if release["source_sha"] != expected_source:
        raise EvidenceError("runtime source SHA does not match immutable release")
    if release["image_digest"] != expected_digest:
        raise EvidenceError("runtime image digest does not match immutable release")
    if release["schema_head"] != "0003_immutable_event_ledger":
        raise EvidenceError("runtime schema head is not certified")
    if not isinstance(release["build_time"], str) or not release["build_time"].strip():
        raise EvidenceError("runtime build time is missing")

    persistence = data["persistence"]
    if persistence != {"in_memory": False}:
        raise EvidenceError("in-memory persistence is prohibited in staging")
    dispatch = data["dispatch"]
    if dispatch != {"outbox_enabled": False, "nats_mode": "disabled", "temporal_worker_mode": "disabled"}:
        raise EvidenceError("dispatch controls are not fully disabled")

    effects = data["external_effects"]
    if not isinstance(effects, dict) or set(effects) != EXPECTED_EXTERNAL_EFFECT_KEYS:
        raise EvidenceError("external-effects evidence is empty or incomplete")
    if any(value is not False for value in effects.values()):
        raise EvidenceError("one or more external effects are enabled")
    umbrella_controls = data["umbrella_controls"]
    if (
        not isinstance(umbrella_controls, dict)
        or set(umbrella_controls) != EXPECTED_UMBRELLA_CONTROL_KEYS
    ):
        raise EvidenceError("umbrella-control evidence is empty or incomplete")
    if any(value is not False for value in umbrella_controls.values()):
        raise EvidenceError("one or more umbrella controls are enabled")
    if data["production_dialing"] != "DISABLED":
        raise EvidenceError("production dialing is not disabled")
    if data["production_activation_configured"] is not False:
        raise EvidenceError("production activation must not be configured")
    for key in ("provider_effects_disabled", "all_external_effects_disabled", "staging_safe"):
        if data[key] is not True:
            raise EvidenceError(f"runtime safety flag is not true: {key}")

    return {
        "schema_version": data["schema_version"],
        "service": data["service"],
        "environment": data["environment"],
        "runtime_profile_id": data["runtime_profile_id"],
        "release": {
            "source_sha": release["source_sha"],
            "image_digest": release["image_digest"],
            "schema_head": release["schema_head"],
            "build_time": release["build_time"],
        },
        "persistence": {"in_memory": False},
        "dispatch": {"outbox_enabled": False, "nats_mode": "disabled", "temporal_worker_mode": "disabled"},
        "external_effects": {name: False for name in sorted(EXPECTED_EXTERNAL_EFFECT_KEYS)},
        "umbrella_controls": {
            name: False for name in sorted(EXPECTED_UMBRELLA_CONTROL_KEYS)
        },
        "production_dialing": "DISABLED",
        "production_activation_configured": False,
        "provider_effects_disabled": True,
        "all_external_effects_disabled": True,
        "staging_safe": True,
    }


def canonical_write(path: Path, data: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
    path.write_bytes(encoded)
    os.chmod(path, 0o600)
    return sha256_bytes(encoded)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--metrics-token-file", type=Path, required=True)
    parser.add_argument("--health-token-file", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksum-output", type=Path, required=True)
    parser.add_argument("--max-series", type=int, default=5000)
    parser.add_argument("--max-family-series", type=int, default=500)
    parser.add_argument("--scrape-delay-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha):
        raise EvidenceError("expected source SHA must be 40 lowercase hexadecimal characters")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_image_digest):
        raise EvidenceError("expected image digest must be sha256:<64 lowercase hex>")
    base_url, host = validate_base_url(args.base_url)
    metrics_token = read_private_file(args.metrics_token_file)
    health_token = read_private_file(args.health_token_file)
    if hashlib.sha256(metrics_token.encode()).digest() == hashlib.sha256(health_token.encode()).digest():
        raise EvidenceError("metrics and health tokens must be independently issued")
    metrics_metadata = decode_jwt_metadata(metrics_token)
    health_metadata = decode_jwt_metadata(health_token)
    if "metrics.read" not in metrics_metadata["scopes"]:
        raise EvidenceError("metrics token is missing metrics.read")
    if "health.read" not in health_metadata["scopes"]:
        raise EvidenceError("health token is missing health.read")
    checks: dict[str, Any] = {}
    unauth_status, _, _ = request(base_url + "/metrics")
    if unauth_status != 401:
        raise EvidenceError(f"unauthenticated /metrics returned {unauth_status}, expected 401")
    checks["unauthenticated_metrics_denied"] = True
    wrong_status, _, _ = request(base_url + "/metrics", "invalid-staging-evidence-token")
    if wrong_status != 401:
        raise EvidenceError(f"wrong-token /metrics returned {wrong_status}, expected 401")
    checks["wrong_token_metrics_denied"] = True
    scrapes: list[dict[str, Any]] = []
    for index in range(2):
        status, headers, body = request(base_url + "/metrics", metrics_token)
        if status != 200:
            raise EvidenceError(f"authenticated /metrics returned {status}")
        if "text/plain" not in headers.get("content-type", ""):
            raise EvidenceError("metrics content type is not text/plain")
        scrapes.append(analyze_metrics(body, max_series=args.max_series, max_family_series=args.max_family_series))
        if index == 0:
            time.sleep(max(args.scrape_delay_seconds, 0.0))
    checks["authenticated_metrics_scrapes"] = 2
    safety_status, safety_headers, safety_body = request(base_url + "/v1/runtime/safety", health_token)
    if safety_status != 200:
        raise EvidenceError(f"authenticated runtime-safety returned {safety_status}")
    if "application/json" not in safety_headers.get("content-type", ""):
        raise EvidenceError("runtime-safety content type is not JSON")
    safety = validate_runtime_safety(safety_body, args.expected_source_sha, args.expected_image_digest)
    checks["runtime_safety"] = "PASS"
    evidence = {
        "schema_version": "1.0",
        "suite_id": "codestra-controlled-intake-monitoring-v1",
        "evidence_type": "private-staging-runtime-certification",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": "staging",
        "target": {"hostname": host, "private_network_only": True, "methods_used": ["GET"], "business_writes_performed": False},
        "middleware_release": {"source_sha": args.expected_source_sha, "image_digest": args.expected_image_digest, "schema_head": "0003_immutable_event_ledger"},
        "token_evidence": {"metrics": metrics_metadata, "health": health_metadata, "token_values_recorded": False, "storage": "ephemeral-files-outside-git"},
        "checks": checks,
        "metrics": {"scrapes": scrapes, "cardinality_budget": {"maximum_total_series": args.max_series, "maximum_series_per_family": args.max_family_series}, "forbidden_label_findings": [], "pii_or_secret_findings": []},
        "runtime_safety": safety,
        "activation": {"prometheus_target_state": "pending", "blackbox_target_state": "pending", "production_authorized": False},
        "overall_result": "PASS",
    }
    checksum = canonical_write(args.output, evidence)
    args.checksum_output.parent.mkdir(parents=True, exist_ok=True)
    args.checksum_output.write_text(checksum + "\n", encoding="utf-8")
    os.chmod(args.checksum_output, 0o600)
    print("STAGING_INTAKE_EVIDENCE=PASS")
    print(f"EVIDENCE_SHA256={checksum}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"STAGING_INTAKE_EVIDENCE=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
