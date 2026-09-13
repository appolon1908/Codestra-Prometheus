from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ProductionEvidenceAuthorityTests(unittest.TestCase):
    def test_evidence_producer_is_private_read_only_and_protected(self) -> None:
        workflow = (ROOT / ".github/workflows/collect-staging-intake-evidence.yml").read_text()
        for required in (
            "github.ref == 'refs/heads/staging'",
            "runs-on: [self-hosted, linux, x64, codestra-staging-observability]",
            "environment: codestra-staging-observability-certification",
            "/run/secrets/codestra/prometheus/middleware-staging-metrics-token",
            "/run/secrets/codestra/prometheus/middleware-staging-health-token",
            "collect_staging_intake_evidence_v2.py",
            '--authorization-change-id "${CHANGE_ID^^}"',
            '--authorization-reason-sha256 "$reason_sha256"',
            '" ".join(os.environ["EXECUTION_REASON"].split())',
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "METHODS_USED=GET_ONLY",
            "BUSINESS_WRITES_PERFORMED=NO",
            "PRODUCTION_AUTHORIZED=NO",
            "EVIDENCE_BASENAME:",
            "$RUNNER_TEMP/$EVIDENCE_BASENAME",
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("${{ secrets.", workflow)
        self.assertNotIn("EVIDENCE_ROOT: ${{ runner.temp }}", workflow)

        actionlint_config = (ROOT / ".github/actionlint.yaml").read_text()
        self.assertIn("codestra-staging-observability", actionlint_config)
        actionlint_image = (
            "rhysd/actionlint@sha256:"
            "1d74bfc9fd1963af8f89a7c22afaaafd42f49aad711a09951d02cb996398f61d"
        )
        for validation_workflow in (
            ".github/workflows/validate-repository-readiness.yml",
            ".github/workflows/validate-repository-readiness-protected.yml",
        ):
            text = (ROOT / validation_workflow).read_text()
            self.assertIn(actionlint_image, text)
            self.assertIn("collect-staging-intake-evidence.yml", text)

    def test_activation_consumes_exact_successful_artifact(self) -> None:
        workflow = (ROOT / ".github/workflows/controlled-intake-staging-activation-gate.yml").read_text()
        for required in (
            "staging_evidence_run_id:",
            "staging_evidence_artifact_name:",
            ".github/workflows/collect-staging-intake-evidence.yml",
            "test \"$(jq -r '.head_sha'",
            "and .expired == false",
            "gh run download",
            'computed = "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()',
            'evidence_document.get("schema_version") != "1.1"',
            'evidence_document.get("authorization") != expected_authorization',
            'Execution reason SHA-256:',
            'sampled_metric_families',
            'generated_at < now - timedelta(hours=24)',
        ):
            self.assertIn(required, workflow)
        self.assertNotIn("Why executed:", workflow)

    def test_production_discovery_is_environment_specific(self) -> None:
        config = (ROOT / "codestra/prometheus/prometheus.yml").read_text()
        self.assertIn('/etc/prometheus/targets/production.json', config)
        self.assertNotIn('/etc/prometheus/targets/*.json', config)


if __name__ == "__main__":
    unittest.main()
