from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence


# CRITICAL: this compatibility entry must remain a thin alias. Reintroducing a
# stage inventory or receipt schema here recreates the compat_118 authority drift.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_validation_gate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compatibility alias for the canonical forced-G2 validation gate"
    )
    parser.parse_args(argv)
    return run_validation_gate.main(["run", "--force-full", "--legacy-full"])


if __name__ == "__main__":
    raise SystemExit(main())
