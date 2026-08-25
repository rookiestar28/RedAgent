#!/usr/bin/env python3
"""Run the fixed loopback-only compat_123 qualification/status client."""

from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.campaign_service.cli import run_cli  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(run_cli(REPO_ROOT))
