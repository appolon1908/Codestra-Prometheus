"""Target inventory: desired records match the configuration; runtime merge and invariants fail closed."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("target_inventory", ROOT / "scripts" / "target_inventory.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)
COMMITTED = ROOT / "target-inventory.v1.json"


class TargetInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = MODULE.build_inventory()

    def test_committed_inventory_matches_configuration(self):
        self.assertEqual(json.loads(COMMITTED.read_text(encoding="utf-8")), self.inventory)
        self.assertEqual(MODULE.check_invariants(self.inventory), [])
        self.assertEqual(self.inventory["config_digest"], MODULE.lf_digest(MODULE.CONFIG))

    def test_every_record_has_section_10_fields(self):
        for record in self.inventory["records"]:
            for field in ("job", "service_id", "environment", "activation", "expected_endpoint", "authentication", "scrape_interval_seconds", "source"):
                self.assertIn(field, record)
                self.assertIsNotNone(record[field], f"{record['job']} {field}")

    def test_middleware_is_scraped_on_the_8095_authority_only(self):
        middleware = [r for r in self.inventory["records"] if r["service_id"] in MODULE.MIDDLEWARE_SERVICES]
        self.assertTrue(middleware)
        for record in middleware:
            endpoint = record["expected_endpoint"]
            self.assertIn("middleware-integration-api:8095", endpoint)
            self.assertNotIn(":8080", endpoint)
        metrics = next(r for r in middleware if r["job"] == "codestra-middleware-metrics")
        self.assertEqual(metrics["authentication"], "oauth2 client=monitoring-readonly scopes=metrics.read secret=file")
        self.assertFalse(any(r["service_id"] in MODULE.MIDDLEWARE_SERVICES and r["job"] == "codestra-targets" for r in self.inventory["records"]))

    def test_openbao_scrape_and_probe_are_authenticated_and_safe(self):
        openbao = next(r for r in self.inventory["records"] if r["job"] == "codestra-openbao")
        self.assertEqual(openbao["metrics_path"], "/v1/sys/metrics")
        self.assertIn("mtls", openbao["authentication"])
        self.assertIn("bearer credentials=file", openbao["authentication"])
        self.assertEqual(openbao["activation"], "pending")
        probe = next(r for r in self.inventory["records"] if r["service_id"] == "openbao-health")
        self.assertEqual(probe["probe_module"], "https_openbao_health")
        self.assertEqual(probe["activation"], "pending")
        for record in self.inventory["records"]:
            if record["probe_module"]:
                self.assertIn(record["probe_module"], MODULE.SAFE_PROBE_MODULES)

    def test_legacy_middleware_port_is_rejected(self):
        broken = copy.deepcopy(self.inventory)
        record = next(r for r in broken["records"] if r["job"] == "codestra-middleware-metrics")
        record["expected_endpoint"] = "middleware-integration-api:8080"
        problems = MODULE.check_invariants(broken)
        self.assertTrue(any("legacy port 8080" in p for p in problems), problems)
        unsafe = copy.deepcopy(self.inventory)
        probe = next(r for r in unsafe["records"] if r["job"] == "blackbox")
        probe["probe_module"] = "http_post_2xx"
        self.assertTrue(any("not a reviewed safe module" in p for p in MODULE.check_invariants(unsafe)))

    def test_runtime_merge_reports_actual_endpoint_status_and_freshness(self):
        now = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
        runtime = {"status": "success", "data": {"activeTargets": [
            {"labels": {"job": "codestra-middleware-metrics", "instance": "middleware-integration-api:8095", "service": "middleware"}, "scrapeUrl": "http://middleware-integration-api:8095/metrics", "health": "up", "lastScrape": (now - timedelta(seconds=9)).isoformat(), "lastError": ""},
            {"labels": {"job": "codestra-targets", "instance": "redis-exporter:9121", "service": "redis-exporter"}, "scrapeUrl": "http://redis-exporter:9121/metrics", "health": "down", "lastScrape": (now - timedelta(seconds=400)).isoformat(), "lastError": "context deadline exceeded Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"},
            {"labels": {"job": "blackbox", "instance": "http://middleware-integration-api:8095/readiness"}, "scrapeUrl": "http://blackbox-exporter:9115/probe?module=http_2xx_internal&target=http%3A%2F%2Fmiddleware-integration-api%3A8095%2Freadiness", "health": "up", "lastScrape": (now - timedelta(seconds=3)).isoformat(), "lastError": ""},
            {"labels": {"job": "codestra-targets", "instance": "rogue:9999", "service": "rogue"}, "scrapeUrl": "http://rogue:9999/metrics", "health": "up", "lastScrape": now.isoformat(), "lastError": ""},
        ], "droppedTargets": [{"discoveredLabels": {"job": "codestra-targets"}}]}}
        merged = MODULE.merge_runtime(self.inventory, runtime, now=now)
        by = {(r["job"], r["expected_endpoint"]): r for r in merged["records"]}
        middleware = by[("codestra-middleware-metrics", "middleware-integration-api:8095")]
        self.assertEqual((middleware["actual_endpoint"], middleware["scrape_status"], middleware["metric_freshness"], middleware["endpoint_matches"]), ("middleware-integration-api:8095", "up", "fresh", True))
        redis = by[("codestra-targets", "redis-exporter:9121")]
        self.assertEqual((redis["scrape_status"], redis["metric_freshness"]), ("down", "stale"))
        self.assertIn("[REDACTED]", redis["scrape_error"])
        self.assertNotIn("eyJ", json.dumps(merged))
        probe = by[("blackbox", "http://middleware-integration-api:8095/readiness")]
        self.assertEqual(probe["actual_endpoint"], "http://middleware-integration-api:8095/readiness")
        openbao = by[("codestra-openbao", "codestra-bao-production-01:8200")]
        self.assertEqual((openbao["scrape_status"], openbao["actual_endpoint"]), ("pending", None))
        self.assertEqual(merged["runtime"]["unexpected_active"], ["codestra-targets@rogue:9999"])
        self.assertEqual((merged["runtime"]["up"], merged["runtime"]["down"], merged["runtime"]["dropped_targets"]), (3, 1, 1))

    def test_cli_check_and_runtime_file_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(MODULE.main(["--check", str(COMMITTED)]), 0)
            runtime = out / "targets.json"
            runtime.write_text(json.dumps({"status": "success", "data": {"activeTargets": [], "droppedTargets": []}}), encoding="utf-8")
            self.assertEqual(MODULE.main(["--runtime-file", str(runtime), "--output", str(out / "report")]), 0)
            report = json.loads((out / "report" / "target-inventory.runtime.json").read_text(encoding="utf-8"))
            self.assertTrue(all(r["scrape_status"] in {"not-active", "pending"} for r in report["records"]))
            self.assertTrue((out / "report" / "target-inventory.runtime.md").read_text(encoding="utf-8").startswith("| job |"))
            self.assertEqual(MODULE.main(["--runtime-file", str(runtime), "--output", "relative"]), 1)
            stale = out / "stale.json"
            stale.write_text("{}", encoding="utf-8")
            self.assertEqual(MODULE.main(["--check", str(stale)]), 1)


if __name__ == "__main__":
    unittest.main()
