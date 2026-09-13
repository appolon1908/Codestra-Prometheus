#!/usr/bin/env python3
"""Validate Prometheus runtime image repository and digest inputs before Compose use."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from collections.abc import Mapping

CODESTRA = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = CODESTRA / "compose.yaml"

REPOSITORY_RE = re.compile(
    r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_INPUTS = {
    "prometheus": ("PROMETHEUS_IMAGE_REPOSITORY", "PROMETHEUS_IMAGE_DIGEST"),
}
EXPECTED_COMPOSE_IMAGES = {
    "prometheus": (
        "image: docker.io/prom/prometheus@sha256:"
        "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
    ),
}


def fail(message: str) -> None:
    print(f"PROMETHEUS_IMAGE_POLICY_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read environment file {path}: {exc}")
    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"invalid environment assignment at {path}:{line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in values:
            fail(f"empty or duplicate environment key at {path}:{line_number}")
        values[key] = value.strip()
    return values


def validate_compose_template() -> None:
    try:
        text = COMPOSE.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {COMPOSE}: {exc}")
    for component, fragment in EXPECTED_COMPOSE_IMAGES.items():
        if fragment not in text:
            fail(
                f"{component} image must be structurally assembled as "
                "repository@sha256:digest"
            )
    for forbidden in (
        "${PROMETHEUS_IMAGE:",
        ":latest",
    ):
        if forbidden in text:
            fail(f"Compose contains mutable or legacy image input: {forbidden}")


def validate_inputs(values: Mapping[str, str]) -> dict[str, str]:
    references: dict[str, str] = {}
    for component, (repository_key, digest_key) in IMAGE_INPUTS.items():
        repository = values.get(repository_key, "").strip()
        digest = values.get(digest_key, "").strip()
        if not repository:
            fail(f"{repository_key} is required")
        if not REPOSITORY_RE.fullmatch(repository):
            fail(
                f"{repository_key} must be a repository-only reference without a tag or digest"
            )
        if "@" in repository or repository.endswith(":latest"):
            fail(f"{repository_key} may not contain a tag or digest")
        if not DIGEST_RE.fullmatch(digest):
            fail(f"{digest_key} must be exactly 64 lowercase hexadecimal characters")
        references[component] = f"{repository}@sha256:{digest}"
    return references


def prove_policy() -> None:
    valid = {
        "PROMETHEUS_IMAGE_REPOSITORY": "prom/prometheus",
        "PROMETHEUS_IMAGE_DIGEST": "0" * 64,
    }
    validate_inputs(valid)
    unsafe = (
        {**valid, "PROMETHEUS_IMAGE_REPOSITORY": "prom/prometheus:latest"},
        {**valid, "PROMETHEUS_IMAGE_REPOSITORY": "prom/prometheus@sha256:" + "0" * 64},
        {**valid, "PROMETHEUS_IMAGE_DIGEST": "latest"},
        {**valid, "PROMETHEUS_IMAGE_DIGEST": "A" * 64},
    )
    for sample in unsafe:
        try:
            validate_inputs(sample)
        except SystemExit:
            continue
        fail(f"image policy negative test unexpectedly passed: {sample}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--env-file",
        type=pathlib.Path,
        help="Validate image inputs from a deployment environment file instead of process env.",
    )
    args = parser.parse_args()
    validate_compose_template()
    prove_policy()
    values: Mapping[str, str]
    values = parse_env_file(args.env_file) if args.env_file else os.environ
    references = validate_inputs(values)
    for component, reference in sorted(references.items()):
        print(f"CODESTRA_IMMUTABLE_IMAGE[{component}]={reference}")
    print("CODESTRA_PROMETHEUS_RUNTIME_IMAGE_VALIDATION_PASS=1")


if __name__ == "__main__":
    main()
