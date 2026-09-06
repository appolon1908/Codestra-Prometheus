#!/usr/bin/env python3
"""Validate an exact target-only pending-to-active staging PR."""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

import validate_staging_intake_observability as source

REPO = Path(__file__).resolve().parents[2]
TARGET = "codestra/prometheus/targets/staging.json"


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), *args], text=True
    ).strip()


def validate_target_only_diff(base_sha: str) -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", base_sha)
    head_sha = git("rev-parse", "HEAD")
    assert re.fullmatch(r"[0-9a-f]{40}", head_sha)
    changed = [
        line
        for line in git("diff", "--name-only", f"{base_sha}..{head_sha}").splitlines()
        if line
    ]
    assert changed == [TARGET], changed
    diff = git("diff", "--unified=0", f"{base_sha}..{head_sha}", "--", TARGET)
    removed = [line for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
    added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    assert len(removed) == 1 and '"activation": "pending"' in removed[0]
    assert len(added) == 1 and '"activation": "active"' in added[0]


def validate() -> None:
    source.validate("active")
    contract = source.json.loads(
        (REPO / "integration/staging-activation-contract-v1.json").read_text()
    )
    policy = contract["activation_policy"]
    assert policy["prometheus_target_current_state"] == "pending"
    assert policy["prometheus_target_allowed_next_state"] == "active"
    assert policy["only_prometheus_target_may_transition"] is True
    assert policy["blackbox_target_current_state"] == "pending"
    assert policy["blackbox_must_remain_pending"] is True
    assert policy["production_activation_authorized"] is False
    assert all(value is False for value in contract["runtime_effects"].values())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    args = parser.parse_args()
    validate()
    validate_target_only_diff(args.base_sha)
    print("PROMETHEUS_ACTIVATION_GATE=PASS")
    print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")
    print("PRODUCTION_ACTIVATION_AUTHORIZED=NO")


if __name__ == "__main__":
    main()
