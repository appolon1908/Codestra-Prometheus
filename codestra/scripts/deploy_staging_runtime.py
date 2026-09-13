#!/usr/bin/env python3
"""Render or deploy only the exact merged staging Prometheus authority."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "codestra" / "deploy" / "compose.staging.yaml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
CANONICAL_REPOSITORY = "https://github.com/appolon1908-hue/Codestra-Prometheus.git"
CANONICAL_DEVELOPMENT_REF = "refs/remotes/codestra-canonical/development"


class PreflightError(RuntimeError):
    pass


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise PreflightError("Git source identity could not be verified")
    return result.stdout.strip()


def validate_source(source_sha: str, *, require_merged: bool) -> None:
    if not SHA40.fullmatch(source_sha):
        raise PreflightError("source SHA must be exactly 40 lowercase hexadecimal characters")
    if git_output("rev-parse", "HEAD") != source_sha:
        raise PreflightError("source SHA does not match the checked-out exact head")
    if git_output("status", "--porcelain"):
        raise PreflightError("deployment checkout is not clean")
    if require_merged:
        refreshed = subprocess.run(
            [
                "git",
                "fetch",
                "--quiet",
                "--no-tags",
                CANONICAL_REPOSITORY,
                f"+refs/heads/development:{CANONICAL_DEVELOPMENT_REF}",
            ],
            cwd=REPO,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if refreshed.returncode != 0:
            raise PreflightError("canonical development branch could not be refreshed")
        merged = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                source_sha,
                CANONICAL_DEVELOPMENT_REF,
            ],
            cwd=REPO,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if merged.returncode != 0:
            raise PreflightError("source SHA is not merged into canonical development")


def validate_secret_file(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise PreflightError("metrics client secret must be an absolute non-symlink file")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size < 16 or info.st_size > 4096:
        raise PreflightError("metrics client secret file is missing or malformed")
    if info.st_uid != 65534:
        raise PreflightError("metrics client secret must be owned by Prometheus uid 65534")
    if stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
        raise PreflightError("metrics client secret mode must be 0400 or 0600")
    secret = resolved.read_bytes()
    normalized = secret.strip()
    if (
        secret != normalized
        or not 16 <= len(normalized) <= 4096
        or b"\x00" in normalized
    ):
        raise PreflightError("metrics client secret content is missing or malformed")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("render", "deploy"), required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()

    validate_source(args.source_sha, require_merged=args.mode == "deploy")
    secret_file = (
        validate_secret_file(args.secret_file)
        if args.mode == "deploy"
        else args.secret_file
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PROMETHEUS_SOURCE_SHA": args.source_sha,
            "MIDDLEWARE_METRICS_CLIENT_SECRET_FILE": str(secret_file),
        }
    )
    command = ["docker", "compose", "-f", str(COMPOSE)]
    if args.mode == "render":
        command.extend(("config", "--quiet"))
    else:
        command.extend(
            (
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "120",
                "prometheus-staging",
            )
        )
    result = subprocess.run(
        command,
        cwd=REPO,
        env=environment,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise PreflightError(f"staging Prometheus {args.mode} failed")
    print(f"PROMETHEUS_STAGING_{args.mode.upper()}=PASS")
    print(f"PROMETHEUS_SOURCE_SHA={args.source_sha}")
    print("SECCOMP_DISABLED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.TimeoutExpired, PreflightError) as exc:
        print(f"PROMETHEUS_STAGING_PREFLIGHT=FAIL: {exc}")
        raise SystemExit(1)
