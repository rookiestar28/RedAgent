from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.mcp_broker.qualification import qualify_mcp_workbench


def main() -> int:
    if sys.argv[1:] != ["qualify", "--confirm-r114-deterministic-no-external-io"]:
        raise SystemExit("confirmation_required")
    receipt = qualify_mcp_workbench()
    path = ROOT / "runtime-assets/attestations/260712-R114_MCP_WORKBENCH_QUALIFICATION.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "path": str(path.relative_to(ROOT))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
