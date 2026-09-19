"""The Middleware V3 metrics contract stays dark, pinned and low-cardinality."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_middleware_v3_metrics", ROOT / "scripts" / "validate_middleware_v3_metrics.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class MiddlewareV3MetricsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(VALIDATOR.CONTRACT.read_text(encoding="utf-8"))
        cls.candidates, cls.allowed, cls.forbidden = VALIDATOR.validate_contract(cls.contract)

    def reject(self, contract: dict) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate_contract(contract)

    def test_source_passes_end_to_end(self) -> None:
        VALIDATOR.validate_scrape_job(self.forbidden)
        VALIDATOR.validate_prepared_rules(self.candidates, self.allowed, self.forbidden)

    def test_pins(self) -> None:
        self.assertEqual(self.contract["middleware"]["prep_base_sha"], "22d023a9c65b0789a0f7ee6c28548753521a9eff")
        self.assertEqual(self.contract["middleware"]["v3_final_sha"], "PENDING")
        self.assertTrue(self.contract["middleware"]["repin_required_after_v3_merge"])

    def test_activation_is_rejected(self) -> None:
        for key, value in (("status", "ACTIVE"), ("activation_enabled", True), ("provider_effects_enabled", True)):
            mutated = copy.deepcopy(self.contract)
            mutated[key] = value
            self.reject(mutated)

    def test_public_or_anonymous_scrape_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["scrape_contract"]["public_exposure"] = True
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["scrape_contract"]["identity"]["scope"] = "metrics.write"
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["scrape_contract"]["identity"]["client_secret_source"] = "inline"
        self.reject(mutated)

    def test_high_cardinality_labels_are_rejected(self) -> None:
        for label in ("command_id", "operation_id", "correlation_id", "customer", "email", "phone"):
            mutated = copy.deepcopy(self.contract)
            mutated["expected_metrics"][0]["labels"] = [label]
            self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["label_policy"]["forbidden"].remove("command_id")
        self.reject(mutated)
        mutated = copy.deepcopy(self.contract)
        mutated["label_policy"]["allowed"].append("customer")
        self.reject(mutated)

    def test_every_mission_metric_is_declared_pending(self) -> None:
        names = {m["name"] for m in self.contract["expected_metrics"]}
        self.assertEqual(names, VALIDATOR.MISSION_METRICS)
        for metric in self.contract["expected_metrics"]:
            self.assertEqual(metric["status"], "EXPECTED_PENDING_V3")
            self.assertFalse(metric["present_at_prep_base"])
            self.assertTrue(metric["v3_candidate_name"].startswith("middleware_"))
        mutated = copy.deepcopy(self.contract)
        mutated["expected_metrics"].pop()
        self.reject(mutated)

    def test_middleware_job_labeldrop_covers_every_forbidden_label(self) -> None:
        import yaml

        config = yaml.safe_load(VALIDATOR.PROMETHEUS.read_text(encoding="utf-8"))
        job = next(j for j in config["scrape_configs"] if j["job_name"] == VALIDATOR.JOB)
        pattern = re.compile(next(r for r in job["metric_relabel_configs"] if r["action"] == "labeldrop")["regex"])
        for label in self.forbidden:
            self.assertIsNotNone(pattern.fullmatch(label), label)
        for label in self.allowed:
            self.assertIsNone(pattern.fullmatch(label), label)
        self.assertEqual(job["oauth2"]["client_id"], "monitoring-readonly")
        self.assertEqual(job["oauth2"]["scopes"], ["metrics.read"])
        self.assertNotIn("client_secret", job["oauth2"])

    def test_prepared_rules_are_dark_and_bounded(self) -> None:
        compose = VALIDATOR.COMPOSE.read_text(encoding="utf-8")
        self.assertNotIn("rules-prepared", compose)
        text = VALIDATOR.PREPARED_RULES.read_text(encoding="utf-8")
        self.assertNotIn("absent(", text)
        for label in VALIDATOR.MISSION_FORBIDDEN:
            self.assertNotRegex(text, rf"\b{label}\b")
        names = re.findall(r"^\s+- alert: (\S+)$", text, re.MULTILINE)
        self.assertGreaterEqual(len(names), 10)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(name.startswith("MiddlewareV3") for name in names))

    def test_repository_validator_shares_the_forbidden_set(self) -> None:
        """codestra/scripts/validate.py must reject the same identifiers as target labels."""
        spec = importlib.util.spec_from_file_location("codestra_validate", ROOT / "scripts" / "validate.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for label in VALIDATOR.MISSION_FORBIDDEN | {"incident_id", "fingerprint", "lease_id", "secret_ref", "jti"}:
            self.assertIsNotNone(module.FORBIDDEN.fullmatch(label), label)


if __name__ == "__main__":
    unittest.main()
