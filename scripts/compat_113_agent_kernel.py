"""Generate the deterministic compat_113 no-network qualification receipt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    # IMPORTANT: direct script execution must resolve the repo package without a global install.
    sys.path.insert(0, str(ROOT))

from redagent_platform.agent_kernel.qualification import qualify_agent_kernel


OUTPUT = ROOT / "runtime-assets" / "attestations" / "260712-R113_AGENT_KERNEL_QUALIFICATION.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("qualify",))
    parser.add_argument("--confirm-r113-deterministic-no-external-provider", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r113_deterministic_no_external_provider:
        parser.error("explicit deterministic no-external-provider confirmation required")
    receipt = qualify_agent_kernel()
    if receipt["status"] != "passed":
        raise SystemExit("r113_qualification_failed")
    OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"r113_qualification_passed:{OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
