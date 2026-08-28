"""Create the current data-only artifact-posture qualification inputs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compat_110_artifact_lab import qualify  # noqa: E402


ATTESTATIONS = ROOT / "runtime-assets" / "attestations"
QUALIFICATION = ATTESTATIONS / "260828-ARTIFACT_POSTURE_QUALIFICATION_V2.json"
RUNTIME_LOCK = ROOT / "config" / "artifact-posture-runtime-v2.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("qualify",))
    parser.add_argument("--confirm-canonical-data-only", action="store_true")
    parser.add_argument("--issued-at", required=True)
    args = parser.parse_args()
    if not args.confirm_canonical_data_only:
        raise SystemExit("artifact_posture_canonical_data_confirmation_required")
    issued_at = _time(args.issued_at)
    _write_qualification(issued_at)
    print(
        json.dumps(
            {
                "status": "passed",
                "qualification": QUALIFICATION.relative_to(ROOT).as_posix(),
                "source_sha256": json.loads(QUALIFICATION.read_text(encoding="utf-8"))[
                    "source_sha256"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def _write_qualification(issued_at: datetime) -> None:
    qualification = qualify()
    qualification["schema"] = "redagent.artifact-posture-qualification/v2"
    qualification["qualified_at"] = issued_at.isoformat()
    qualification["profiles"] = ["r110-repository-snapshot-v1"]
    qualification["source_sha256"] = _source_sha256()
    qualification.pop("receipt_sha256", None)
    qualification["receipt_sha256"] = _digest(qualification)
    _write_json(QUALIFICATION, qualification)

    runtime_lock = {
        "schema": "redagent.artifact-posture-runtime-lock/v2",
        "source_sha256": qualification["source_sha256"],
        "qualification_file_sha256": _file_sha256(QUALIFICATION),
        "qualification_receipt_sha256": qualification["receipt_sha256"],
        "profile_id": "r110-repository-snapshot-v1",
        "network_allowed": False,
        "subprocess_allowed": False,
        "credential_allowed": False,
        "package_lifecycle_allowed": False,
        "project_config_allowed": False,
        "external_adapter_execution": False,
        "archive_extraction_allowed": False,
        "production_qualified": False,
    }
    _write_json(RUNTIME_LOCK, runtime_lock)


def _source_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform" / "artifact_pipeline").glob("*.py")):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("artifact_posture_time_invalid")
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


if __name__ == "__main__":
    raise SystemExit(main())
