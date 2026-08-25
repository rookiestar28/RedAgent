"""Export the deterministic public OpenAPI contract for the shared compat_095 clients."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "frontend" / "openapi.json"
sys.path.insert(0, str(ROOT))

from redagent_platform.api.app import create_app  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    schema = create_app(test_issuer_enabled=True).openapi()
    serialized = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != serialized:
            print("openapi_drift_detected", file=sys.stderr)
            return 1
        print("openapi_contract_current")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    # IMPORTANT: generated contracts use LF on every OS so staged drift checks remain deterministic.
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as output:
        output.write(serialized)
    print(f"openapi_path={OUTPUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
