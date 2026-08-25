#!/usr/bin/env python3
"""Validate repo-local RedAgent operator skill packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.skill_validation import validate_default_skill_packages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate RedAgent operator skill packages.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Repository root to validate.")
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON.")
    args = parser.parse_args(argv)

    reports = validate_default_skill_packages(args.root)
    passed = all(report.passed for report in reports)
    payload = {
        "passed": passed,
        "report_count": len(reports),
        "reports": [report.to_jsonable() for report in reports],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for report in reports:
            status = "PASS" if report.passed else "FAIL"
            print(f"{status} {report.platform}: {report.skill_root}")
            for issue in report.issues:
                print(f"  - {issue.code}: {issue.message} ({issue.path})")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
