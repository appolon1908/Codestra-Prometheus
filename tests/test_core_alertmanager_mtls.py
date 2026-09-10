import copy
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("transport", Path(__file__).resolve().parents[1] / "scripts/configure_core_alertmanager_mtls.py")
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)


def source():
    return {
        "global": {"external_labels": {"environment": "production"}},
        "rule_files": ["/etc/prometheus/rules/*.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [transport.TARGET]}]}]},
        "scrape_configs": [{"job_name": "existing", "static_configs": [{"targets": ["existing:9090"]}]}],
    }


class CoreAlertmanagerTLS(unittest.TestCase):
    def test_preserves_rules_labels_and_other_jobs(self):
        original = source()
        result = transport.configure(original)
        for key in ("global", "rule_files", "scrape_configs"):
            self.assertEqual(original[key], result[key])
        manager = result["alerting"]["alertmanagers"][0]
        self.assertEqual(manager["scheme"], "https")
        self.assertEqual(manager["api_version"], "v2")
        self.assertEqual(manager["tls_config"], transport.TLS)

    def test_idempotent_without_mutating_input(self):
        original = source()
        before = copy.deepcopy(original)
        result = transport.configure(original)
        self.assertEqual(original, before)
        self.assertEqual(transport.configure(result), result)

    def test_migrates_an_existing_alertmanager_scrape(self):
        original = source()
        original["scrape_configs"].append({"job_name": "am", "static_configs": [{"targets": [transport.TARGET]}]})
        result = transport.configure(original)
        self.assertEqual(result["scrape_configs"][-1]["tls_config"], transport.TLS)

    def test_rejects_mixed_scrape_targets(self):
        original = source()
        original["scrape_configs"].append({"job_name": "mixed", "static_configs": [{"targets": [transport.TARGET, "other:9093"]}]})
        with self.assertRaises(ValueError):
            transport.configure(original)

    def test_rejects_unknown_discovery_auth_or_trust(self):
        for key, value in [("dns_sd_configs", [{}]), ("authorization", {}), ("tls_config", {"insecure_skip_verify": True}), ("api_version", "v1")]:
            original = source()
            original["alerting"]["alertmanagers"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                transport.configure(original)

    def test_rejects_missing_or_different_destination(self):
        for managers in [[], [{"static_configs": [{"targets": ["other:9093"]}]}]]:
            original = source()
            original["alerting"]["alertmanagers"] = managers
            with self.assertRaises(ValueError):
                transport.configure(original)
