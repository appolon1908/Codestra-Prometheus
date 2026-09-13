from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parents[1]
COLLECTOR_PATH = ROOT / "codestra/scripts/collect_staging_intake_evidence.py"
WRAPPER_PATH = ROOT / "codestra/scripts/collect_staging_intake_evidence_v2.py"

collector_spec = importlib.util.spec_from_file_location(
    "collect_staging_intake_evidence", COLLECTOR_PATH
)
collector = importlib.util.module_from_spec(collector_spec)
assert collector_spec and collector_spec.loader
collector_spec.loader.exec_module(collector)
sys.modules["collect_staging_intake_evidence"] = collector

wrapper_spec = importlib.util.spec_from_file_location("collector_v2", WRAPPER_PATH)
wrapper = importlib.util.module_from_spec(wrapper_spec)
assert wrapper_spec and wrapper_spec.loader
wrapper_spec.loader.exec_module(wrapper)

SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
DIGEST = "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"


def token(scope: str, jti: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "iat": 100,
                "exp": 400,
                "azp": "monitoring-readonly",
                "aud": ["middleware-api"],
                "scope": scope,
                "jti": jti,
            }
        ).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}.signature-{jti}"


def metrics_payload() -> bytes:
    rows: list[str] = []
    for family in sorted(collector.EXPECTED_METRIC_FAMILIES):
        rows.extend((f"# HELP {family} test", f"# TYPE {family} gauge"))
        if family == "codestra_release_info":
            rows.append(
                f'{family}{{service="middleware-api",component="api",environment="staging",release_sha="{SOURCE}",image_digest="{DIGEST}",schema_or_migration_head="0003_immutable_event_ledger",version="0.1.0"}} 1'
            )
        elif family.startswith(("lead_", "survey_", "intake_")):
            rows.append(
                f'{family}{{codestra_business="platform",application="integration",service="middleware-api",environment="staging"}} 0'
            )
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
        "dispatch": {
            "outbox_enabled": False,
            "nats_mode": "disabled",
            "temporal_worker_mode": "disabled",
        },
        "external_effects": {
            name: False for name in collector.EXPECTED_EXTERNAL_EFFECT_KEYS
        },
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
    metrics_token = token("metrics.read", "metrics")
    health_token = token("health.read", "health")

    def log_message(self, *_args):
        pass

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        if self.path == "/metrics":
            if not authorization:
                self.send_response(401)
                self.end_headers()
                return
            if authorization == f"Bearer {self.health_token}":
                self.send_response(403)
                self.end_headers()
                return
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
            if not authorization:
                self.send_response(401)
                self.end_headers()
                return
            if authorization == f"Bearer {self.metrics_token}":
                self.send_response(403)
                self.end_headers()
                return
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


class ScopeIsolationCollectorTests(unittest.TestCase):
    def test_exact_scope_metadata_rejects_combined_or_wrong_scope(self):
        self.assertEqual(
            wrapper.exact_scope_metadata(token("metrics.read", "one"), "metrics.read")[
                "scopes"
            ],
            ["metrics.read"],
        )
        with self.assertRaises(collector.EvidenceError):
            wrapper.exact_scope_metadata(
                token("metrics.read health.read", "combined"), "metrics.read"
            )
        with self.assertRaises(collector.EvidenceError):
            wrapper.exact_scope_metadata(token("health.read", "wrong"), "metrics.read")

    def test_authorization_metadata_is_normalized_and_fail_closed(self):
        self.assertEqual(
            wrapper.authorization_metadata(" chg-test12345 ", "SHA256:" + "A" * 64),
            {
                "change_id": "CHG-TEST12345",
                "execution_reason_sha256": "sha256:" + "a" * 64,
            },
        )
        for change_id, reason_sha256 in (
            ("CHG-short", "sha256:" + "a" * 64),
            ("CHG-TEST12345", "sha256:invalid"),
        ):
            with self.assertRaises(collector.EvidenceError):
                wrapper.authorization_metadata(change_id, reason_sha256)

    def test_full_get_only_scope_isolated_collection(self):
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
                old = list(sys.argv)
                sys.argv = [
                    "collector-v2",
                    "--base-url",
                    f"http://127.0.0.1:{server.server_port}",
                    "--metrics-token-file",
                    str(metrics),
                    "--health-token-file",
                    str(health),
                    "--expected-source-sha",
                    SOURCE,
                    "--expected-image-digest",
                    DIGEST,
                    "--output",
                    str(output),
                    "--checksum-output",
                    str(checksum),
                    "--authorization-change-id",
                    "chg-test12345",
                    "--authorization-reason-sha256",
                    "sha256:" + "a" * 64,
                    "--scrape-delay-seconds",
                    "0",
                ]
                try:
                    self.assertEqual(wrapper.main(), 0)
                finally:
                    sys.argv = old
                evidence_text = output.read_text()
                evidence = json.loads(evidence_text)
                self.assertEqual(evidence["schema_version"], "1.1")
                self.assertEqual(evidence["overall_result"], "PASS")
                self.assertEqual(evidence["authorization"], {
                    "change_id": "CHG-TEST12345",
                    "execution_reason_sha256": "sha256:" + "a" * 64,
                })
                self.assertEqual(
                    evidence["token_evidence"]["metrics"]["scopes"],
                    ["metrics.read"],
                )
                self.assertEqual(
                    evidence["token_evidence"]["health"]["scopes"],
                    ["health.read"],
                )
                self.assertTrue(evidence["checks"]["health_token_metrics_denied"])
                self.assertTrue(
                    evidence["checks"]["metrics_token_runtime_safety_denied"]
                )
                self.assertEqual(
                    evidence["checks"]["token_scope_isolation"], "PASS"
                )
                self.assertNotIn(Handler.metrics_token, evidence_text)
                self.assertNotIn(Handler.health_token, evidence_text)
                self.assertTrue(checksum.read_text().startswith("sha256:"))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
