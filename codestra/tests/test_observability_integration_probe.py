from __future__ import annotations

import importlib.util
import tempfile
import unittest
from unittest import mock

import yaml
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "probe_observability_integrations.py"
SPEC = importlib.util.spec_from_file_location("probe_observability_integrations", SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)

VALIDATOR_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location("codestra_validate", VALIDATOR_SCRIPT)
assert VALIDATOR_SPEC and VALIDATOR_SPEC.loader
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(validator)

CONTRACT = Path(__file__).resolve().parents[1] / "catalog" / "observability-api-contract.v1.yml"


class FakeResponse:
    def __init__(self, final_url: str):
        self.status = 200
        self.final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size: int) -> bytes:
        return b"ok"[:size]

    def geturl(self) -> str:
        return self.final_url


class FakeOpener:
    def __init__(self, final_url: str):
        self.final_url = final_url

    def open(self, request, timeout: float):
        return FakeResponse(self.final_url)


class IntegrationProbeTests(unittest.TestCase):
    def contract(self):
        return {
            "version": 1,
            "status": "CONFIG_PREPARED_NOT_DEPLOYED",
            "security": {"transport": "mtls"},
            "services": {
                "prometheus": {
                    "base_url": "https://prometheus:9090",
                    "health": {"method": "GET", "path": "/-/healthy"},
                    "query": {"method": "POST", "path": "/api/v1/query"},
                },
                "telemetry": {
                    "metrics": {
                        "method": "GET",
                        "endpoint": "https://otel-collector:8889/metrics",
                    }
                },
            },
        }

    def test_collects_only_read_only_https_probes(self):
        probes = probe.collect_probes(self.contract())
        self.assertEqual(
            probes,
            [
                ("prometheus", "health", "GET", "https://prometheus:9090/-/healthy"),
                (
                    "telemetry",
                    "metrics",
                    "GET",
                    "https://otel-collector:8889/metrics",
                ),
            ],
        )

    def test_rejects_plaintext_endpoint(self):
        contract = self.contract()
        contract["services"]["prometheus"]["base_url"] = "http://prometheus:9090"
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            probe.collect_probes(contract)

    def test_requires_fail_closed_contract(self):
        contract = self.contract()
        contract["status"] = "ACTIVE"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.yml"
            path.write_text(yaml.safe_dump(contract), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fail-closed"):
                probe.load_contract(path)

    def test_rejects_empty_probe_set(self):
        contract = self.contract()
        contract["services"] = {"tempo": {"otlp_grpc": {"protocol": "otlp_grpc"}}}
        with self.assertRaisesRegex(ValueError, "no read-only probes"):
            probe.collect_probes(contract)

    def test_redirected_probe_is_rejected(self):
        contract = self.contract()
        contract["services"] = {"prometheus": contract["services"]["prometheus"]}
        final_url = "http://plaintext.invalid/-/healthy"
        with mock.patch.object(
            probe.urllib.request,
            "build_opener",
            return_value=FakeOpener(final_url),
        ) as build_opener:
            evidence = probe.probe(contract, mock.sentinel.context, 1.0)

        self.assertIsInstance(build_opener.call_args.args[0], probe.RejectRedirectHandler)
        self.assertEqual(evidence["summary"], {"passed": 0, "failed": 1, "total": 1})
        self.assertEqual(evidence["results"][0]["error_class"], "redirect")


class ContractRelationshipTests(unittest.TestCase):
    def contract(self):
        return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    def validate(self, contract):
        with mock.patch.object(validator, "load_yaml", return_value=contract):
            validator.validate_observability_api_contract()

    def test_rejects_missing_alert_producer_relationship(self):
        contract = self.contract()
        contract["services"]["alertmanager"]["alerts"]["producers"].remove("loki")
        with self.assertRaisesRegex(SystemExit, "producer relationship mismatch"):
            self.validate(contract)

    def test_rejects_missing_grafana_consumer_relationship(self):
        contract = self.contract()
        contract["services"]["tempo"]["search"]["consumers"] = []
        with self.assertRaisesRegex(SystemExit, "consumer relationship mismatch"):
            self.validate(contract)

    def test_rejects_exporter_with_wrong_consumer(self):
        contract = self.contract()
        contract["services"]["redis_exporter"]["metrics"]["consumer"] = "grafana"
        with self.assertRaisesRegex(SystemExit, "consumer must be prometheus"):
            self.validate(contract)


if __name__ == "__main__":
    unittest.main()
