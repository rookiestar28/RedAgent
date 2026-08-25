from datetime import datetime, timezone

import pytest

from redagent_platform.human_simulation.privacy import SubmissionCategory, classify_submission
from redagent_platform.human_simulation.sink import OwnedMessageSink
from redagent_platform.human_simulation.testing import compiled_sink_plan


NOW = datetime(2026, 7, 11, 16, 30, tzinfo=timezone.utc)


def test_sink_captures_fixed_message_without_human_or_external_delivery_and_deletes():
    plan = compiled_sink_plan(now=NOW); sink = OwnedMessageSink()
    receipt = sink.deliver(plan=plan, run_id="run-r112", occurred_at=NOW)
    assert receipt.captured and not receipt.human_delivered and receipt.external_contact_count == 0
    assert sink.count == 1
    deleted = sink.delete(plan=plan, run_id="run-r112", occurred_at=NOW)
    assert deleted.deleted_message_count == 1 and deleted.residual_message_count == 0 and sink.count == 0


def test_submission_classifier_discards_values_and_has_closed_categories():
    synthetic = "REDAGENT-R112-SYNTHETIC-ONLY"
    assert classify_submission(synthetic) is SubmissionCategory.SYNTHETIC_ACCEPTED
    assert classify_submission("") is SubmissionCategory.EMPTY
    assert classify_submission("real-looking-password") is SubmissionCategory.REJECTED_REAL_OR_UNKNOWN
    assert synthetic not in repr(classify_submission(synthetic))


def test_sink_rejects_plan_tamper():
    plan = compiled_sink_plan(now=NOW)
    with pytest.raises(ValueError, match="human_plan_integrity_invalid"):
        OwnedMessageSink().deliver(plan=plan.__class__(**{**plan.__dict__, "plan_sha256": "f" * 64}),
            run_id="run-r112", occurred_at=NOW)
