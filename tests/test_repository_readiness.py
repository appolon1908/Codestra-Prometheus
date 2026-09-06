from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ReadinessTests(unittest.TestCase):
    def test_validator(self) -> None:
        subprocess.run(["python3", "scripts/validate_repository_readiness.py"], cwd=ROOT, check=True)

    def test_bundle_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            one, two = Path(directory) / "one.tar.gz", Path(directory) / "two.tar.gz"
            for output in (one, two):
                subprocess.run(["python3", "scripts/build_config_bundle.py", "--output", str(output)], cwd=ROOT, check=True)
            self.assertEqual(hashlib.sha256(one.read_bytes()).digest(), hashlib.sha256(two.read_bytes()).digest())
            manifest = json.loads((ROOT / "codestra/release/config-bundle.manifest.json").read_text())
            with tarfile.open(one) as archive:
                self.assertEqual(set(archive.getnames()), set(manifest["files"]) | {"codestra/release/config-bundle.manifest.json"})

    def test_targets_default_pending(self) -> None:
        targets = json.loads((ROOT / "codestra/prometheus/targets/production.json").read_text())
        probes = json.loads((ROOT / "codestra/blackbox/targets-production.json").read_text())
        self.assertTrue(all(group["labels"]["activation"] == "pending" for group in targets))
        self.assertTrue(all(group["labels"]["probe_enabled"] == "false" for group in probes))

    def test_compose_owns_only_prometheus(self) -> None:
        compose = yaml.safe_load((ROOT / "codestra/compose.yaml").read_text())
        self.assertEqual(set(compose["services"]), {"prometheus"})

    def test_protected_validation_supplies_locked_image_inputs(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/validate-repository-readiness-protected.yml").read_text()
        )
        job = workflow["jobs"]["validate-protected"]
        self.assertEqual(job["env"]["PROMETHEUS_IMAGE_REPOSITORY"], "prom/prometheus")
        self.assertEqual(
            job["env"]["PROMETHEUS_IMAGE_DIGEST"],
            "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996",
        )


if __name__ == "__main__": unittest.main()
