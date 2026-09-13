#!/usr/bin/env python3
"""Validate exact upstream provenance and runtime-tool authority."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_REPOSITORY = "appolon1908-hue/Codestra-Prometheus"
EXPECTED_UPSTREAM = "prometheus/prometheus"
EXPECTED_URL = "https://github.com/prometheus/prometheus.git"
EXPECTED_SOURCE_COMMIT = "e06b2dc5a6149e20ca82fe936fb044a6dfe45958"
EXPECTED_SOURCE_TREE = "9f3cc4b95e5d0ea24656c2c237a13aa26aa62f29"
EXPECTED_RUNTIME_COMMIT = "8be3a9560fbdd18a94dedec4b747c35178177202"
EXPECTED_RUNTIME_IMAGE = "docker.io/prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
EXPECTED_STAGE6_TMPFS = "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m"
PERSISTENT_BRANCHES = ["main", "development", "test", "staging", "production"]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"required regular JSON file missing: {path.relative_to(ROOT)}")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path.relative_to(ROOT)}")
    return value


def repository_tree(path: str) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", f"HEAD:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    if not HEX40.fullmatch(value):
        raise ValueError(f"invalid Git tree identity for {path}")
    return value


def _require(document: Mapping[str, object], expected: Mapping[str, object], label: str) -> None:
    for key, value in expected.items():
        if document.get(key) != value:
            raise ValueError(f"{label} drift: {key}")


def validate_documents(
    source: Mapping[str, object],
    lock: Mapping[str, object],
    runtime: Mapping[str, object],
    *,
    actual_upstream_tree: str,
    workflows: Mapping[str, str],
    readiness_source: str,
) -> None:
    source_expected = {
        "schema_version": "1.1",
        "component": "prometheus",
        "codestra_repository": EXPECTED_REPOSITORY,
        "upstream_repository": EXPECTED_UPSTREAM,
        "upstream_clone_url": EXPECTED_URL,
        "trusted_upstream_ref": "refs/heads/main",
        "upstream_ref": EXPECTED_SOURCE_COMMIT,
        "upstream_tree": EXPECTED_SOURCE_TREE,
        "import_path": "upstream",
        "import_mode": "exact-git-tree-reference",
        "source_role": "NON_RUNTIME_REFERENCE",
        "runtime_authority": "codestra/release/runtime-image.lock.json",
        "runtime_validation_image": EXPECTED_RUNTIME_IMAGE,
        "preserve_upstream_license": True,
        "branches": PERSISTENT_BRANCHES,
        "deployment_enabled": False,
    }
    lock_expected = {
        "schema_version": "1.1",
        "upstream_clone_url": EXPECTED_URL,
        "trusted_upstream_ref": "refs/heads/main",
        "upstream_ref": EXPECTED_SOURCE_COMMIT,
        "upstream_commit": EXPECTED_SOURCE_COMMIT,
        "upstream_tree": EXPECTED_SOURCE_TREE,
        "import_path": "upstream",
        "source_role": "NON_RUNTIME_REFERENCE",
        "runtime_validation_image": EXPECTED_RUNTIME_IMAGE,
        "synchronized_at": "2026-08-29T08:13:44Z",
        "deployment_enabled": False,
    }
    _require(source, source_expected, "source authority")
    _require(lock, lock_expected, "source lock")

    if actual_upstream_tree != EXPECTED_SOURCE_TREE:
        raise ValueError(
            "vendored upstream tree does not match the declared exact source tree"
        )

    runtime_expected = {
        "schemaVersion": "1.0.0",
        "artifactModel": "verified-upstream-image-plus-signed-config",
        "upstreamRepository": EXPECTED_UPSTREAM,
        "upstreamVersion": "v3.5.0",
        "upstreamTagCommit": EXPECTED_RUNTIME_COMMIT,
        "image": EXPECTED_RUNTIME_IMAGE,
        "linuxAmd64Manifest": "sha256:8672a850efe2f9874702406c8318704edb363587f8c2ca88586b4c8fdb5cea24",
        "productionActivation": False,
    }
    _require(runtime, runtime_expected, "runtime image lock")

    if runtime.get("upstreamSignature") != {
        "available": False,
        "verification": "NO_SIGSTORE_SIGNATURE_PUBLISHED",
    }:
        raise ValueError("runtime signature disposition drift")

    corporate = workflows.get("corporate", "")
    corporate_runtime = workflows.get("corporate_runtime", "")
    source_workflow = workflows.get("source", "")
    combined_runtime = corporate + "\n" + corporate_runtime

    forbidden_runtime_tokens = (
        "upstream/go.mod",
        "upstream/go.sum",
        "working-directory: upstream",
        "actions/setup-go@",
        "go build",
        ".tmp-promtool",
        ".bin/promtool",
    )
    for token in forbidden_runtime_tokens:
        if token in combined_runtime:
            raise ValueError(f"vendored source used as runtime validator: {token}")

    if corporate.count(EXPECTED_RUNTIME_IMAGE) < 3:
        raise ValueError("corporate validation is not consistently bound to the runtime image")
    if corporate_runtime.count(EXPECTED_RUNTIME_IMAGE) < 1:
        raise ValueError("corporate runtime validation is not bound to the runtime image")

    stage6_marker = "- name: Execute Stage 6 alert evaluations with exact runtime promtool"
    if stage6_marker not in corporate:
        raise ValueError("Stage 6 alert evaluation step missing")
    stage6_section = corporate.split(stage6_marker, 1)[1].split("\n      - name:", 1)[0]
    if EXPECTED_STAGE6_TMPFS not in stage6_section:
        raise ValueError("Stage 6 alert evaluation lacks bounded writable test storage")

    forbidden_source_workflow_tokens = (
        "contents: write",
        "pull-requests: write",
        "actions: write",
        "git push",
        "gh pr create",
        "persist-credentials: true",
    )
    for token in forbidden_source_workflow_tokens:
        if token in source_workflow:
            raise ValueError(f"source verification workflow may mutate GitHub: {token}")
    for token in (
        "permissions:",
        "contents: read",
        "persist-credentials: false",
        "python scripts/validate_source_authority.py",
        "merge-base --is-ancestor",
        "git rev-parse HEAD:upstream",
        EXPECTED_RUNTIME_IMAGE,
    ):
        if token not in source_workflow:
            raise ValueError(f"source verification boundary missing: {token}")

    if "validate_source_authority()" not in readiness_source:
        raise ValueError("repository readiness does not invoke source authority validation")


def validate_repository() -> None:
    source = load_json(ROOT / "CODESTRA_UPSTREAM.json")
    lock = load_json(ROOT / "CODESTRA_UPSTREAM_LOCK.json")
    runtime = load_json(ROOT / "codestra/release/runtime-image.lock.json")
    upstream = ROOT / "upstream"
    if not upstream.is_dir() or upstream.is_symlink() or (upstream / ".git").exists():
        raise ValueError("upstream must be a regular vendored Git tree without nested metadata")

    workflow_paths = {
        "corporate": ROOT / ".github/workflows/codestra-observability.yml",
        "corporate_runtime": ROOT / ".github/workflows/validate-codestra-corporate-runtime-v1.yml",
        "source": ROOT / ".github/workflows/upstream-source-sync.yml",
    }
    workflow_sources: dict[str, str] = {}
    for key, path in workflow_paths.items():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required workflow missing: {path.relative_to(ROOT)}")
        workflow_sources[key] = path.read_text(encoding="utf-8")

    readiness_path = ROOT / "scripts/validate_repository_readiness.py"
    if not readiness_path.is_file() or readiness_path.is_symlink():
        raise ValueError("repository readiness validator missing")

    validate_documents(
        source,
        lock,
        runtime,
        actual_upstream_tree=repository_tree("upstream"),
        workflows=workflow_sources,
        readiness_source=readiness_path.read_text(encoding="utf-8"),
    )


def main() -> None:
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"PROMETHEUS_SOURCE_AUTHORITY=FAIL ERROR={error}") from error
    print("PROMETHEUS_SOURCE_AUTHORITY=PASS")
    print(f"VENDORED_SOURCE_COMMIT={EXPECTED_SOURCE_COMMIT}")
    print(f"VENDORED_SOURCE_TREE={EXPECTED_SOURCE_TREE}")
    print(f"RUNTIME_VALIDATION_IMAGE={EXPECTED_RUNTIME_IMAGE}")
    print("VENDORED_SOURCE_IS_RUNTIME_AUTHORITY=NO")


if __name__ == "__main__":
    main()
