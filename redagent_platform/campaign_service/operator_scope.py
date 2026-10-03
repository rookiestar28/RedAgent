"""Immutable native scope for normal operator intents; legacy owners remain separate."""

from sqlalchemy import select

from redagent_platform.campaign_service.application_contracts import ApplicationBindingConflict
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.persistence.models import metadata


async def current_operator_scope(session, *, tenant_id, engagement_id, target_id, objective_label, lock=False):
    owners = []
    for name, condition in (
        ("engagements", metadata.tables["engagements"].c.id == engagement_id),
        ("targets", (metadata.tables["targets"].c.id == target_id) & (metadata.tables["targets"].c.engagement_id == engagement_id)),
        ("roe_versions", (metadata.tables["roe_versions"].c.engagement_id == engagement_id) & (metadata.tables["roe_versions"].c.status == "approved")),
    ):
        table = metadata.tables[name]
        query = select(table).where(table.c.tenant_id == tenant_id, condition)
        if name == "roe_versions":
            query = query.order_by(table.c.revision.desc()).limit(1)
        if lock:
            query = query.with_for_update(read=True)
        owner = (await session.execute(query)).mappings().one_or_none()
        if owner is None:
            raise ApplicationBindingConflict("operator_native_source_changed")
        owners.append(owner)
    engagement, target, roe = owners
    return {
        "schema_version": "redagent.operator-native-scope/v1", "tenant_id": tenant_id,
        "engagement_id": engagement_id, "engagement_version": int(engagement["version"]),
        "engagement_name": str(engagement["name"]), "engagement_owner_id": str(engagement["owner_user_id"]),
        "target_id": target_id, "target_version": int(target["version"]),
        "target_type": str(target["target_type"]), "target_value": str(target["normalized_value"]),
        "roe_id": str(roe["id"]), "roe_revision": int(roe["revision"]), "roe_version": int(roe["version"]),
        "roe_document_sha256": canonical_planning_sha256(roe["document"]), "objective_label": objective_label,
    }


async def read_operator_scope(session, *, tenant_id, campaign_id):
    events = metadata.tables["autonomous_campaign_application_events"]
    payload = await session.scalar(select(events.c.event_payload).where(
        events.c.tenant_id == tenant_id, events.c.application_id == campaign_id,
        events.c.event_sequence == 1, events.c.event_type == "autonomous_campaign.intent.created.v1",
    ))
    snapshot = None if not isinstance(payload, dict) else payload.get("native_scope")
    if snapshot is None:
        campaigns = metadata.tables["campaigns"]
        workflow = await session.scalar(select(campaigns.c.workflow_id).where(
            campaigns.c.tenant_id == tenant_id, campaigns.c.id == campaign_id,
        ))
        if isinstance(workflow, str) and workflow.startswith("intent-"):
            raise ApplicationBindingConflict("operator_native_scope_missing")
        return None
    if (not isinstance(snapshot, dict) or snapshot.get("tenant_id") != tenant_id
            or snapshot.get("schema_version") != "redagent.operator-native-scope/v1"
            or canonical_planning_sha256(snapshot) != payload.get("native_scope_sha256")):
        raise ApplicationBindingConflict("operator_native_scope_invalid")
    return snapshot


async def assert_operator_scope_current(session, *, tenant_id, campaign_id, lock=True):
    snapshot = await read_operator_scope(session, tenant_id=tenant_id, campaign_id=campaign_id)
    if snapshot is None:
        return
    # CRITICAL: target IDs survive edits. Compare retained values and ROE content under shared
    # owner locks; a fresh signed context alone cannot authorize a changed human-previewed scope.
    current = await current_operator_scope(session, tenant_id=tenant_id,
        engagement_id=snapshot["engagement_id"], target_id=snapshot["target_id"],
        objective_label=snapshot["objective_label"], lock=lock)
    if current != snapshot:
        raise ApplicationBindingConflict("operator_native_source_changed")
