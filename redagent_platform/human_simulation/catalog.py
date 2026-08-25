"""First certified compat_112 owned synthetic sink campaign."""

from datetime import datetime, timezone
import hashlib

from redagent_platform.human_simulation.contracts import CampaignManifest


SUBJECT = "RedAgent synthetic awareness rehearsal"
BODY = "Synthetic sink-only rehearsal. Canary: canary-r112-owned-0001. No action is required."


def certified_campaign() -> CampaignManifest:
    template_sha = hashlib.sha256((SUBJECT + "\n" + BODY).encode()).hexdigest()
    return CampaignManifest(campaign_id="r112-sink-email-canary-v1", revision=1,
        purpose="synthetic-security-awareness-sink-qualification", jurisdiction_review_id="jurisdiction-r112-local",
        privacy_review_id="privacy-r112-minimized", roster_sha256=hashlib.sha256(b"simulation-recipient@redagent.invalid").hexdigest(),
        suppression_sha256=hashlib.sha256(b"no-real-recipients-allowed").hexdigest(), template_sha256=template_sha,
        sender="awareness@redagent.invalid", recipient="simulation-recipient@redagent.invalid", subject=SUBJECT, body=BODY,
        canary_id="canary-r112-owned-0001", sink_id="sink-r112-owned", scheduled_at=datetime(2026, 7, 11, 16, tzinfo=timezone.utc),
        max_deliveries=1, rate_per_minute=1, retention_seconds=300, post_notice_id="notice-r112-synthetic")
