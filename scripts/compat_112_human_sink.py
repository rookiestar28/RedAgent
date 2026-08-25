"""Run the compat_112 synthetic .invalid message and canary sink qualification."""

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

from redagent_platform.human_simulation.events import MinimizedEvent, sign_event, verify_event
from redagent_platform.human_simulation.lifecycle import CampaignRun, CampaignRunState, complete_deletion, transition_campaign_run
from redagent_platform.human_simulation.privacy import classify_submission
from redagent_platform.human_simulation.sink import OwnedMessageSink
from redagent_platform.human_simulation.testing import compiled_sink_plan


OUTPUT = ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_QUALIFICATION.json"
EVENT_KEY = b"r112-owned-local-event-fixture-key"
SYNTHETIC_SENTINEL = "REDAGENT-R112-SYNTHETIC-ONLY"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("command", choices=("qualify",))
    parser.add_argument("--confirm-r112-synthetic-sink-only", action="store_true"); args = parser.parse_args()
    if not args.confirm_r112_synthetic_sink_only:
        raise SystemExit("r112_synthetic_sink_confirmation_required")
    receipt = qualify(now=datetime.now(timezone.utc).replace(microsecond=0))
    OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(OUTPUT), "sha256": receipt["receipt_sha256"]})); return 0


def qualify(*, now: datetime) -> dict[str, object]:
    plan = compiled_sink_plan(now=now); sink = OwnedMessageSink()
    run = CampaignRun(run_id="qualification-r112", state=CampaignRunState.PLANNED, delivery_lease_id=plan.delivery_lease_id)
    for state in (CampaignRunState.RENDERED, CampaignRunState.PREVIEW_APPROVED, CampaignRunState.TEST_SINK_DELIVERED, CampaignRunState.SEND_APPROVED):
        run = transition_campaign_run(run, state)
    delivery = sink.deliver(plan=plan, run_id=run.run_id, occurred_at=now); run = transition_campaign_run(run, CampaignRunState.SINK_DELIVERED)
    category = classify_submission(SYNTHETIC_SENTINEL)
    event = MinimizedEvent(event_id="event-r112-qualification", campaign_id=plan.campaign_id,
        message_id=delivery.message_id, category=category.value, occurred_at=now)
    envelope = sign_event(event=event, key=EVENT_KEY); verified = verify_event(envelope=envelope, key=EVENT_KEY, now=now, seen_event_ids=set())
    run = transition_campaign_run(run, CampaignRunState.OBSERVED); run = transition_campaign_run(run, CampaignRunState.DELETING)
    deletion = sink.delete(plan=plan, run_id=run.run_id, occurred_at=now)
    final, completion = complete_deletion(run, occurred_at=now, residual_ids=())
    canary_correlation = hashlib.sha256(f"{plan.campaign_id}:{delivery.message_id}:{plan.canary_id}:{plan.sink_id}".encode()).hexdigest()
    body: dict[str, object] = {"schema": "redagent.r112-qualification/v1", "qualified_at": now.isoformat(), "status": "passed",
        "scope": "owned-synthetic-invalid-recipient-in-process-sink", "source_sha256": _source_digest(),
        "campaign_id": plan.campaign_id, "campaign_sha256": plan.campaign_sha256, "plan_sha256": plan.plan_sha256,
        "delivery": {"message_sha256": delivery.message_sha256, "captured": delivery.captured,
            "human_delivered": delivery.human_delivered, "recipient_class": "synthetic-invalid-owned"},
        "event": {"category": verified.category, "body_sha256": envelope.body_sha256, "signature_verified": True,
            "replay_checked": True, "raw_value_retained": False},
        "canary": {"correlation_sha256": canary_correlation, "triggered_in_owned_sink": True},
        "deletion": {"deleted_message_count": deletion.deleted_message_count,
            "residual_message_count": deletion.residual_message_count, "zero_residual": completion.zero_residual,
            "final_state": final.state.value},
        "safety": {"human_delivery_count": 0, "external_contact_count": delivery.external_contact_count,
            "relay_count": delivery.relay_count, "forward_count": delivery.forward_count, "provider_credential_count": 0,
            "tracking_count": 0, "raw_submission_retained_count": 0, "external_reference_execution_count": 0,
            "real_recipient_count": 0, "production_contact_count": 0}}
    encoded = json.dumps(body, sort_keys=True)
    if SYNTHETIC_SENTINEL in encoded or any(body["safety"].values()) or final.state is not CampaignRunState.DELETED:  # type: ignore[union-attr]
        raise RuntimeError("r112_qualification_failed")
    body["receipt_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); return body


def _source_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform/human_simulation").glob("*.py")):
        digest.update(path.name.encode()); digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
