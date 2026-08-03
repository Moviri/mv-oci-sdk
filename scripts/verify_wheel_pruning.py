#!/usr/bin/env python3
"""Verify that every synchronized prune target is absent from a built wheel."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "upstream" / "prune-paths.txt"


def read_prune_targets(manifest_path: Path) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def wheel_target(source_target: str) -> str:
    if not source_target.startswith("src/oci/"):
        raise RuntimeError(f"Unexpected prune target outside src/oci: {source_target}")
    return source_target.removeprefix("src/").rstrip("/")


def verify_wheel(wheel_path: Path, prune_targets: tuple[str, ...]) -> int:
    with zipfile.ZipFile(wheel_path) as wheel:
        members = set(wheel.namelist())

    violations = []
    for source_target in prune_targets:
        target = wheel_target(source_target)
        if target in members or any(member.startswith(f"{target}/") for member in members):
            violations.append(source_target)

    if violations:
        raise RuntimeError(
            "Built wheel contains pruned targets: " + ", ".join(sorted(violations))
        )
    return len(prune_targets)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    prune_targets = read_prune_targets(args.manifest)
    verified = verify_wheel(args.wheel, prune_targets)
    print(f"{verified}/{len(prune_targets)} prune targets absent from {args.wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
