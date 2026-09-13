from __future__ import annotations

import base64
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "codestra/scripts/collect_staging_intake_evidence.py"
spec = importlib.util.spec_from_file_location("collector", MODULE_PATH)
collector = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(collector)

SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
DIGEST = "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"


def token(jti: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "iat": 100,
        "exp": 400,
        "azp": "monitoring-readonly",
        "aud": ["middleware-api"],
        "scope": "metrics.read health.read",
        "jti": jti,
    }).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature-{jti}"


def metrics_payload() -> bytes:
    rows: list[str] = []
    for family in sorted(collector.EXPECTED_METRIC_FAMILIES):
        rows.extend((f"# HELP {family} test", f"# TYPE {family} gauge"))
        if family == "codestra_release_info":
            rows.append(f'{family}{{service="middleware-api",component="api",environment="staging",release_sha="{SOURCE}",image_digest="{DIGEST}",schema_or_migration_head="0003_immutable_event_ledger",version="0.1.0"}} 1')
        elif family.startswith(("lead_", "survey_", "intake_")):
            rows.append(f'{family}{{codestra_business="platform",application="integration",service="middleware-api",environment="staging"}} 0')
        else:
            rows.append(f"{family} 0")
    return ("\n".join(rows) + "\n").encode()


def safety_document() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "service": "middleware-api",
        "environment": "staging",
        "runtime_profile_id": "codestra-middleware-staging-v1",
        "release": {
            "source_sha": SOURCE,
            "image_digest": DIGEST,
            "schema_head": "0003_immutable_event_ledger",
            "build_time": "2026-08-30T13:24:37Z",
        },
        "persistence": {"in_memory": False},
        "dispatch": {"outbox_enabled": False, "nats_mode": "disabled", "temporal_worker_mode": "disabled"},
        "external_effects": {name: False for name in collector.EXPECTED_EXTERNAL_EFFECT_KEYS},
        "umbrella_controls": {
            name: False for name in collector.EXPECTED_UMBRELLA_CONTROL_KEYS
        },
        "production_dialing": "DISABLED",
        "production_activation_configured": False,
        "provider_effects_disabled": True,
        "all_external_effects_disabled": True,
        "staging_safe": True,
    }


class Handler(BaseHTTPRequestHandler):
    metrics_token = token("metrics")
    health_token = token("health")

    def log_message(self, *_args):
        pass

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        if self.path == "/metrics":
            if authorization != f"Bearer {self.metrics_token}":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(metrics_payload())
            return
        if self.path == "/v1/runtime/safety":
            if authorization != f"Bearer {self.health_token}":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(safety_document()).encode())
            return
        self.send_response(404)
        self.end_headers()


class CollectorTests(unittest.TestCase):
    def test_metric_contract_and_privacy(self):
        result = collector.analyze_metrics(metrics_payload(), max_series=5000, max_family_series=500)
        self.assertEqual(result["missing_metric_families"], [])
        self.assertEqual(set(result["sampled_metric_families"]), collector.EXPECTED_METRIC_FAMILIES)
        declarations_only = b"\n".join(
            f"# TYPE {family} gauge".encode()
            for family in sorted(collector.EXPECTED_METRIC_FAMILIES)
        ) + b"\ncodestra_release_info 1\n"
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(declarations_only, max_series=5000, max_family_series=500)
        bad = metrics_payload() + b'intake_inbox_backlog{codestra_business="platform",application="integration",service="middleware-api",environment="staging",customer_id="123"} 1\n'
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(bad, max_series=5000, max_family_series=500)

    def test_identity_labels_are_format_checked_and_scanned(self):
        bad = metrics_payload() + b'codestra_release_info{service="middleware-api",component="api",environment="staging",release_sha="operator@example.invalid",image_digest="sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820",schema_or_migration_head="0003_immutable_event_ledger",version="0.1.0"} 1\n'
        with self.assertRaises(collector.EvidenceError):
            collector.analyze_metrics(bad, max_series=5000, max_family_series=500)

    def test_runtime_safety_rejects_empty_or_unknown_evidence(self):
        empty = safety_document()
        empty["external_effects"] = {}
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(json.dumps(empty).encode(), SOURCE, DIGEST)
        unknown = safety_document()
        unknown["diagnostic"] = {"credential": "must-not-be-persisted"}
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(json.dumps(unknown).encode(), SOURCE, DIGEST)
        missing_umbrella = safety_document()
        missing_umbrella.pop("umbrella_controls")
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(
                json.dumps(missing_umbrella).encode(), SOURCE, DIGEST
            )
        enabled_umbrella = safety_document()
        enabled_umbrella["umbrella_controls"]["EXTERNAL_MODEL_CALLS_ENABLED"] = True
        with self.assertRaises(collector.EvidenceError):
            collector.validate_runtime_safety(
                json.dumps(enabled_umbrella).encode(), SOURCE, DIGEST
            )

    def test_runtime_safety_returns_allowlisted_projection(self):
        projected = collector.validate_runtime_safety(json.dumps(safety_document()).encode(), SOURCE, DIGEST)
        self.assertEqual(set(projected), collector.EXPECTED_RUNTIME_SAFETY_KEYS)
        self.assertEqual(set(projected["external_effects"]), collector.EXPECTED_EXTERNAL_EFFECT_KEYS)
        self.assertTrue(all(value is False for value in projected["external_effects"].values()))
        self.assertEqual(
            set(projected["umbrella_controls"]),
            collector.EXPECTED_UMBRELLA_CONTROL_KEYS,
        )
        self.assertTrue(
            all(value is False for value in projected["umbrella_controls"].values())
        )

    def test_full_get_only_evidence_collection(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                metrics = root / "metrics.token"
                health = root / "health.token"
                metrics.write_text(Handler.metrics_token)
                health.write_text(Handler.health_token)
                os.chmod(metrics, 0o600)
                os.chmod(health, 0o600)
                output = root / "evidence.json"
                checksum = root / "evidence.sha256"
                old = list(__import__("sys").argv)
                __import__("sys").argv = [
                    "collector",
                    "--base-url", f"http://127.0.0.1:{server.server_port}",
                    "--metrics-token-file", str(metrics),
                    "--health-token-file", str(health),
                    "--expected-source-sha", SOURCE,
                    "--expected-image-digest", DIGEST,
                    "--output", str(output),
                    "--checksum-output", str(checksum),
                    "--scrape-delay-seconds", "0",
                ]
                try:
                    self.assertEqual(collector.main(), 0)
                finally:
                    __import__("sys").argv = old
                evidence_text = output.read_text()
                evidence = json.loads(evidence_text)
                self.assertEqual(evidence["overall_result"], "PASS")
                self.assertEqual(evidence["target"]["methods_used"], ["GET"])
                self.assertNotIn(Handler.metrics_token, evidence_text)
                self.assertNotIn(Handler.health_token, evidence_text)
                self.assertEqual(set(evidence["runtime_safety"]), collector.EXPECTED_RUNTIME_SAFETY_KEYS)
                self.assertTrue(checksum.read_text().startswith("sha256:"))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
