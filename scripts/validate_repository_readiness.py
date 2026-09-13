#!/usr/bin/env python3
"""Validate repository-only Prometheus release readiness."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from validate_repository_alias_authority import (
    validate_repository as validate_repository_alias_authority,
)
from validate_source_authority import validate_repository as validate_source_authority

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
AUTHORITY = "appolon1908-hue/Codestra-Telemetry/.github/workflows/reusable-release-config-bundle.yml@777292781faeca9348d0e2ecdce6ac3f50c91d93"
REQUIRED = (
    "README.md",
    "REPOSITORY_PROFILE.md",
    "SECURITY.md",
    ".github/CODEOWNERS",
    ".github/workflows/upstream-source-sync.yml",
    ".github/workflows/codestra-observability.yml",
    ".github/workflows/validate-codestra-corporate-runtime-v1.yml",
    ".github/workflows/validate-repository-alias-authority.yml",
    "CODESTRA_UPSTREAM.json",
    "CODESTRA_UPSTREAM_LOCK.json",
    "docs/BACKUP_RESTORE_ROLLBACK.md",
    "docs/REPOSITORY_NAME_AUTHORITY.md",
    "docs/UPGRADE.md",
    "docs/UPSTREAM_SOURCE_AUTHORITY.md",
    ".gitleaks.toml",
    "codestra/catalog/repository-name-aliases.v1.json",
    "codestra/release/runtime-image.lock.json",
    "codestra/release/config-bundle.manifest.json",
    "scripts/build_config_bundle.py",
    "scripts/validate_locked_runtime.sh",
    "scripts/validate_repository_alias_authority.py",
    "scripts/validate_source_authority.py",
    "tests/test_repository_alias_authority.py",
    ".github/workflows/release-config-bundle.yml",
    "requirements-validation.txt",
)


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load(relative: str) -> dict:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{relative} must contain an object")
    return value


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing readiness files: {missing}")

    validate_source_authority()
    validate_repository_alias_authority()

    lock = load("codestra/release/runtime-image.lock.json")
    if (
        lock.get("artifactModel") != "verified-upstream-image-plus-signed-config"
        or lock.get("productionActivation") is not False
    ):
        fail("runtime lock model/activation mismatch")
    if not IMAGE.fullmatch(str(lock.get("image", ""))):
        fail("runtime image is mutable")
    if not re.fullmatch(r"[0-9a-f]{40}", str(lock.get("upstreamTagCommit", ""))):
        fail("upstream tag commit invalid")
    if not re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(lock.get("linuxAmd64Manifest", ""))
    ):
        fail("linux/amd64 manifest invalid")
    if lock.get("upstreamSignature") != {
        "available": False,
        "verification": "NO_SIGSTORE_SIGNATURE_PUBLISHED",
    }:
        fail("upstream signature disposition inaccurate")

    manifest = load("codestra/release/config-bundle.manifest.json")
    if (
        manifest.get("component") != "prometheus"
        or manifest.get("repository") != "appolon1908-hue/Codestra-Prometheus"
        or manifest.get("productionActivation") is not False
    ):
        fail("configuration manifest identity/activation mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict) or len(files) != 17:
        fail("configuration manifest must govern exactly 17 files")
    for relative, expected in files.items():
        path = ROOT / relative
        if not path.is_file() or not SHA256.fullmatch(str(expected)):
            fail(f"invalid manifest entry: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            fail(f"configuration checksum mismatch: {relative}")

    compose = yaml.safe_load((ROOT / "codestra/compose.yaml").read_text())
    if set(compose.get("services", {})) != {"prometheus"}:
        fail("Prometheus Compose may not own exporter workloads")
    service = compose["services"]["prometheus"]
    if (
        service.get("image") != lock["image"]
        or service.get("ports")
        != ["${PROMETHEUS_LISTEN_ADDRESS:-127.0.0.1:9090}:9090"]
    ):
        fail("Prometheus immutable image or loopback exposure mismatch")
    if (
        service.get("privileged") is True
        or service.get("network_mode") == "host"
        or service.get("pid") == "host"
    ):
        fail("unsafe Prometheus runtime boundary")
    commands = service.get("command", [])
    if (
        "--web.enable-admin-api=false" not in commands
        or "--web.enable-lifecycle=false" not in commands
    ):
        fail("mutable Prometheus APIs must remain disabled")

    targets = json.loads(
        (ROOT / "codestra/prometheus/targets/production.json").read_text()
    )
    if any(
        group.get("labels", {}).get("activation") != "pending"
        for group in targets
    ):
        fail("uncertified production target is active")
    probes = json.loads(
        (ROOT / "codestra/blackbox/targets-production.json").read_text()
    )
    if any(
        group.get("labels", {}).get("probe_enabled") != "false"
        for group in probes
    ):
        fail("uncertified Blackbox probe is active")

    release = yaml.safe_load(
        (ROOT / ".github/workflows/release-config-bundle.yml").read_text()
    )
    job = release.get("jobs", {}).get("release", {})
    if (
        job.get("uses") != AUTHORITY
        or job.get("with", {}).get("component_id") != "prometheus"
    ):
        fail("release authority mismatch")

    build_call = 'bash scripts/validate_locked_runtime.sh "$GITHUB_SHA"'
    for relative in (
        ".github/workflows/validate-repository-readiness.yml",
        ".github/workflows/validate-repository-readiness-protected.yml",
    ):
        if build_call not in (ROOT / relative).read_text():
            fail(f"merge/protected runtime validation missing: {relative}")

    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        text = workflow.read_text()
        for reference in re.findall(
            r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text
        ):
            if not reference.startswith("./") and not re.fullmatch(
                r"[^@\s]+@[0-9a-f]{40}", reference
            ):
                fail(f"mutable action: {workflow.name}: {reference}")
        if re.search(
            r"git push\s+origin\s+HEAD:(?:main|development|test|staging|production)",
            text,
        ):
            fail(f"direct protected-branch push: {workflow.name}")

    print("PROMETHEUS_REPOSITORY_READINESS_SOURCE=PASS")
    print("ARTIFACT_MODEL=SIGNED_CONFIGURATION_BUNDLE")
    print("PRODUCTION_ACTIVATION=NO")


if __name__ == "__main__":
    main()
