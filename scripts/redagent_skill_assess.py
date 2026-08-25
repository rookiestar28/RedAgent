#!/usr/bin/env python3
"""CLI entry point for the compat_047 skill command contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.skill_command_contract import evaluate_skill_assessment_request, load_request_json
from redagent_platform.skill_invocation import SkillInvocationRecordingError, record_skill_invocation_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a RedAgent skill assessment request.")
    parser.add_argument("--request", required=True, help="Path to JSON request file.")
    parser.add_argument("--mode", default=None, help="Optional mode override: dry_run or execute.")
    parser.add_argument("--record-artifacts", action="store_true", help="Write sanitized local evidence/report artifacts.")
    parser.add_argument("--artifact-root", default=str(REPO_ROOT), help="Repository root for artifact paths.")
    parser.add_argument("--ui-log-path", default=None, help="Optional repo-relative UI log preview path.")
    args = parser.parse_args(argv)

    try:
        raw = Path(args.request).read_text(encoding="utf-8")
    except OSError as exc:
        decision = evaluate_skill_assessment_request({"mode": args.mode or "dry_run", "request_id": "unreadable_request"})
        output = decision.to_jsonable()
        output["reason"] = "request_file_unreadable"
        output["refusal_reason"] = "request_file_unreadable"
        print(json.dumps(output, sort_keys=True))
        print(f"request_file_unreadable: {exc}", file=sys.stderr)
        return 2

    request, parse_error = load_request_json(raw)
    if parse_error:
        output = parse_error.to_jsonable()
        print(json.dumps(output, sort_keys=True))
        print(output["reason"], file=sys.stderr)
        return 2

    decision = evaluate_skill_assessment_request(request or {}, mode_override=args.mode)
    output = decision.to_jsonable()
    if args.record_artifacts:
        if not decision.allowed:
            output["artifact_recording"] = {
                "status": "skipped",
                "reason": "decision_not_allowed",
            }
        else:
            try:
                artifacts = record_skill_invocation_artifacts(
                    request or {},
                    output,
                    repo_root=Path(args.artifact_root),
                    ui_log_path=args.ui_log_path,
                )
            except SkillInvocationRecordingError as exc:
                output.update(
                    {
                        "decision": "deny",
                        "reason": "artifact_recording_failed",
                        "exit_classification": "invalid_input",
                        "policy_decision": {
                            "outcome": "deny",
                            "reason": exc.reason,
                        },
                        "refusal_reason": exc.reason,
                        "artifact_recording": {
                            "status": "failed",
                            "reason": exc.reason,
                        },
                    }
                )
            else:
                output["artifact_recording"] = artifacts.to_jsonable()
    print(json.dumps(output, sort_keys=True))
    print(f"{output['decision']}:{output['reason']}", file=sys.stderr)
    return 0 if output["decision"] == "allow" else 2


if __name__ == "__main__":
    raise SystemExit(main())
