from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_source_authority as authority  # noqa: E402


class SourceAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = authority.load_json(ROOT / "CODESTRA_UPSTREAM.json")
        self.lock = authority.load_json(ROOT / "CODESTRA_UPSTREAM_LOCK.json")
        self.runtime = authority.load_json(
            ROOT / "codestra/release/runtime-image.lock.json"
        )
        self.workflows = {
            "corporate": (
                ROOT / ".github/workflows/codestra-observability.yml"
            ).read_text(encoding="utf-8"),
            "corporate_runtime": (
                ROOT / ".github/workflows/validate-codestra-corporate-runtime-v1.yml"
            ).read_text(encoding="utf-8"),
            "source": (
                ROOT / ".github/workflows/upstream-source-sync.yml"
            ).read_text(encoding="utf-8"),
        }
        self.readiness = (
            ROOT / "scripts/validate_repository_readiness.py"
        ).read_text(encoding="utf-8")

    def validate(
        self,
        *,
        source: dict[str, object] | None = None,
        lock: dict[str, object] | None = None,
        runtime: dict[str, object] | None = None,
        actual_tree: str | None = None,
        workflows: dict[str, str] | None = None,
        readiness: str | None = None,
    ) -> None:
        authority.validate_documents(
            source or self.source,
            lock or self.lock,
            runtime or self.runtime,
            actual_upstream_tree=actual_tree or authority.repository_tree("upstream"),
            workflows=workflows or self.workflows,
            readiness_source=readiness or self.readiness,
        )

    def test_repository_passes(self) -> None:
        authority.validate_repository()

    def test_mutable_source_ref_is_rejected(self) -> None:
        source = copy.deepcopy(self.source)
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "source authority drift: upstream_ref"):
            self.validate(source=source)

    def test_vendored_tree_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "vendored upstream tree"):
            self.validate(actual_tree="0" * 40)

    def test_vendored_source_cannot_validate_runtime(self) -> None:
        workflows = dict(self.workflows)
        workflows["corporate_runtime"] += (
            "\n- uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"
        )
        with self.assertRaisesRegex(ValueError, "vendored source used"):
            self.validate(workflows=workflows)

    def test_stage6_requires_bounded_tmpfs(self) -> None:
        workflows = dict(self.workflows)
        workflows["corporate"] = workflows["corporate"].replace(
            authority.EXPECTED_STAGE6_TMPFS,
            "--tmpfs /tmp:rw,size=1g",
        )
        with self.assertRaisesRegex(ValueError, "bounded writable test storage"):
            self.validate(workflows=workflows)

    def test_source_workflow_cannot_write(self) -> None:
        workflows = dict(self.workflows)
        workflows["source"] = workflows["source"].replace(
            "contents: read", "contents: write"
        )
        with self.assertRaisesRegex(ValueError, "may mutate GitHub"):
            self.validate(workflows=workflows)

    def test_runtime_image_drift_is_rejected(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["image"] = "docker.io/prom/prometheus:latest"
        with self.assertRaisesRegex(ValueError, "runtime image lock drift: image"):
            self.validate(runtime=runtime)

    def test_readiness_must_invoke_source_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not invoke source"):
            self.validate(
                readiness=self.readiness.replace(
                    "validate_source_authority()", "pass"
                )
            )


if __name__ == "__main__":
    unittest.main()
