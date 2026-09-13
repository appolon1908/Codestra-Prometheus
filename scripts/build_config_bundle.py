#!/usr/bin/env python3
"""Build the deterministic Codestra Prometheus configuration archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "codestra/release/config-bundle.manifest.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist/prometheus-config.tar.gz")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    paths: list[Path] = []
    for relative, expected in sorted(manifest["files"].items()):
        path = ROOT / relative
        actual = digest(path)
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {relative}: {actual} != {expected}")
        paths.append(path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in paths + [MANIFEST]:
                    relative = path.relative_to(ROOT)
                    info = archive.gettarinfo(str(path), arcname=str(relative))
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    with path.open("rb") as source:
                        archive.addfile(info, source)
    print(f"CONFIG_BUNDLE={args.output}")
    print(f"CONFIG_BUNDLE_SHA256={digest(args.output)}")


if __name__ == "__main__": main()
