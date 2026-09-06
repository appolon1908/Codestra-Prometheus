#!/usr/bin/env python3
"""Route CI to the source or activation validator from the target state."""
from __future__ import annotations

import json
import os

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation


def main() -> None:
    targets = json.loads(source.TARGETS_PATH.read_text())
    state = targets[0]["labels"]["activation"]
    if state == "pending":
        source.main()
        return
    if state == "active":
        base_sha = os.environ.get("ACTIVATION_BASE_SHA", "").strip().lower()
        if not base_sha:
            raise SystemExit("ACTIVATION_BASE_SHA is required for an active target")
        activation.validate()
        activation.validate_target_only_diff(base_sha)
        print("PROMETHEUS_ACTIVATION_GATE=PASS")
        print("BLACKBOX_ACTIVATION_GATE=NOT_YET_REQUIRED")
        print("PRODUCTION_ACTIVATION_AUTHORIZED=NO")
        return
    raise SystemExit(f"unsupported staging activation state: {state!r}")


if __name__ == "__main__":
    main()
