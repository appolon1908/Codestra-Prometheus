from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "codestra/scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_staging_intake_observability as source
import validate_staging_intake_observability_activation as activation


class StagingIntakeActivationContractTests(unittest.TestCase):
    def test_source_and_activation_states_are_separate(self) -> None:
        targets = json.loads(source.TARGETS_PATH.read_text())
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory) / "staging.json"
            original = source.TARGETS_PATH
            source.TARGETS_PATH = fixture_path
            try:
                targets[0]["labels"]["activation"] = "pending"
                fixture_path.write_text(json.dumps(targets))
                source.validate("pending")

                targets[0]["labels"]["activation"] = "active"
                fixture_path.write_text(json.dumps(targets))
                with self.assertRaises(AssertionError):
                    source.validate("pending")
                activation.validate()
            finally:
                source.TARGETS_PATH = original


if __name__ == "__main__":
    unittest.main()
