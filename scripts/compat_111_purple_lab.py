"""Run the compat_111 owned benign marker ability qualification in a disposable local lab."""

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

from redagent_platform.purple_runtime.adapter import OwnedMarkerAdapter
from redagent_platform.purple_runtime.lifecycle import PurpleRun, PurpleRunState, complete_purple_run, transition_purple_run
from redagent_platform.purple_runtime.telemetry import OwnedFileTelemetryCollector
from redagent_platform.purple_runtime.testing import compiled_marker_plan


OUTPUT = ROOT / "runtime-assets/attestations/260711-R111_PURPLE_RUNTIME_QUALIFICATION.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("qualify",))
    parser.add_argument("--confirm-r111-owned-disposable-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r111_owned_disposable_lab:
        raise SystemExit("r111_owned_disposable_lab_confirmation_required")
    receipt = qualify(workspace=ROOT, now=datetime.now(timezone.utc).replace(microsecond=0))
    OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(OUTPUT), "sha256": receipt["receipt_sha256"]}))
    return 0


def qualify(*, workspace: Path, now: datetime) -> dict[str, object]:
    plan = compiled_marker_plan(now=now); adapter = OwnedMarkerAdapter(workspace_root=workspace)
    run = PurpleRun(run_id="qualification-r111", state=PurpleRunState.PLANNED, lease_id=plan.lease_id)
    prepared = adapter.prepare(plan=plan, run_id=run.run_id, occurred_at=now); run = transition_purple_run(run, PurpleRunState.PREPARED)
    executed = adapter.execute(plan=plan, run_id=run.run_id, occurred_at=now); run = transition_purple_run(run, PurpleRunState.EXECUTED)
    run = transition_purple_run(run, PurpleRunState.OBSERVING)
    telemetry = OwnedFileTelemetryCollector().observe(plan=plan, run_id=run.run_id, marker_path=executed.marker_path, occurred_at=now)
    run = transition_purple_run(run, PurpleRunState.CLEANING); cleanup = adapter.cleanup(plan=plan, run_id=run.run_id, occurred_at=now)
    final, completion = complete_purple_run(run, occurred_at=now, detection_observed=telemetry.observed,
        residual_resource_ids=(), teardown_verified=cleanup.teardown_verified)
    body: dict[str, object] = {
        "schema": "redagent.r111-qualification/v1", "qualified_at": now.isoformat(), "status": "passed",
        "scope": "repo-owned-disposable-filesystem-lab", "source_sha256": _source_digest(),
        "ability_id": plan.ability_id, "ability_sha256": plan.ability_sha256, "adapter_sha256": plan.adapter_sha256,
        "plan_sha256": plan.plan_sha256, "attack_technique_id": plan.attack_technique_id,
        "detection": {"strategy_id": plan.detection_strategy_id, "analytic_id": plan.analytic_id,
            "event_schema": plan.event_schema, "collector_id": telemetry.collector_id, "event_sha256": telemetry.event_sha256,
            "observed": telemetry.observed},
        "lifecycle": {"before_entry_count": prepared.before_entry_count, "marker_sha256": executed.marker_sha256,
            "final_state": final.state.value, "residual_resource_count": completion.residual_resource_count,
            "teardown_verified": completion.teardown_verified},
        "safety": {"network_contact_count": executed.network_contact_count, "subprocess_count": executed.subprocess_count,
            "privilege_use_count": executed.privilege_use_count, "external_reference_execution_count": 0,
            "production_contact_count": 0, "third_party_contact_count": 0, "persistent_agent_count": 0},
    }
    if not telemetry.observed or final.state is not PurpleRunState.SUCCEEDED or not completion.zero_residual or any(body["safety"].values()):  # type: ignore[union-attr]
        raise RuntimeError("r111_qualification_failed")
    body["receipt_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


def _source_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform/purple_runtime").glob("*.py")):
        digest.update(path.name.encode()); digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
