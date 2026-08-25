#!/usr/bin/env python3
"""Build or validate the RedAgent operator skill release manifest."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.skill_release import (
    build_skill_release_manifest,
    manifest_to_json,
    validate_skill_release_manifest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the RedAgent operator skill release manifest.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository root.")
    parser.add_argument("--output", default=None, help="Optional output JSON path.")
    parser.add_argument("--json", action="store_true", help="Print manifest JSON with validation status.")
    args = parser.parse_args(argv)

    manifest = build_skill_release_manifest(args.root)
    issues = validate_skill_release_manifest(manifest)
    manifest_json = manifest_to_json(manifest)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(manifest_json, encoding="utf-8")
    if args.json:
        print(
            manifest_to_json(
                build_skill_release_manifest(args.root)
            ).rstrip()
        )
    else:
        print(f"release_manifest_valid={str(not issues).lower()}")
        for issue in issues:
            print(f"issue={issue}")
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
