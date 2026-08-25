from __future__ import annotations

import json
from pathlib import Path

from redagent_platform.finding_operations.qualification import qualify_finding_operations


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    receipt = qualify_finding_operations()
    path = ROOT / "runtime-assets/attestations/260712-R115_FINDING_OPERATIONS_QUALIFICATION.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "receipt_sha256": receipt["receipt_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
