"""SQLAlchemy table registrations for the finding operations domain."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "finding_import_sessions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("import_id", String(100), nullable=False),
    Column("adapter_id", String(100), nullable=False),
    Column("run_id", String(100), nullable=False),
    Column("baseline_run_id", String(100)),
    Column("coverage_state", String(32), nullable=False),
    Column("recipe_version", String(64), nullable=False),
    Column("import_sha256", String(64), nullable=False),
    Column("record_count", Integer, nullable=False),
    Column("import_state", String(32), nullable=False),
    Column("imported_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "import_id", name="uq_finding_import_tenant_id"),
)

Table(
    "finding_import_records",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("import_record_id", String(100), nullable=False),
    Column("import_record_ref", String(64), ForeignKey("finding_import_sessions.id"), nullable=False),
    Column("source_record_id", String(100), nullable=False),
    Column("source_record_sha256", String(64), nullable=False),
    Column("issue_fingerprint", String(64), nullable=False),
    Column("candidate_sha256", String(64), nullable=False),
    Column("reason_codes_sha256", String(64), nullable=False),
    Column("correlation_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "import_record_ref", "source_record_id", name="uq_finding_import_record_tenant_source"
    ),
)

Table(
    "managed_issues",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("issue_id", String(100), nullable=False),
    Column("issue_fingerprint", String(64), nullable=False),
    Column("fingerprint_recipe", String(64), nullable=False),
    Column("title", String(500), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("confidence", String(32), nullable=False),
    Column("taxonomy_sha256", String(64), nullable=False),
    Column("controls_sha256", String(64), nullable=False),
    Column("disposition", String(32), nullable=False),
    Column("disposition_revision", Integer, nullable=False),
    Column("owner_id", String(64)),
    Column("sla_due_at", DateTime(timezone=True)),
    Column("remediation_sha256", String(64), nullable=False),
    Column("first_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("issue_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "issue_id", name="uq_managed_issue_tenant_id"),
    UniqueConstraint("tenant_id", "issue_fingerprint", name="uq_managed_issue_tenant_fingerprint"),
)

Table(
    "finding_occurrences",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("occurrence_id", String(100), nullable=False),
    Column("issue_record_id", String(64), ForeignKey("managed_issues.id"), nullable=False),
    Column("import_record_ref", String(64), ForeignKey("finding_import_records.id"), nullable=False),
    Column("resource_sha256", String(64), nullable=False),
    Column("location_sha256", String(64), nullable=False),
    Column("tool_id", String(100), nullable=False),
    Column("tool_version", String(100), nullable=False),
    Column("rule_id", String(200), nullable=False),
    Column("rule_version", String(100), nullable=False),
    Column("database_version", String(100), nullable=False),
    Column("coverage_state", String(32), nullable=False),
    Column("occurrence_state", String(32), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "occurrence_id", name="uq_finding_occurrence_tenant_id"),
)

Table(
    "finding_evidence_links",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("evidence_link_id", String(100), nullable=False),
    Column("occurrence_record_id", String(64), ForeignKey("finding_occurrences.id"), nullable=False),
    Column("evidence_id", String(100), nullable=False),
    Column("evidence_sha256", String(64), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    Column("purpose", String(32), nullable=False),
    Column("link_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "evidence_link_id", name="uq_finding_evidence_link_tenant_id"),
)

Table(
    "finding_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("operation_id", String(100), nullable=False),
    Column("issue_record_id", String(64), ForeignKey("managed_issues.id"), nullable=False),
    Column("operation_kind", String(64), nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("from_state", String(32), nullable=False),
    Column("to_state", String(32), nullable=False),
    Column("operation_sha256", String(64), nullable=False),
    Column("predecessor_sha256", String(64), nullable=False),
    Column("successor_sha256", String(64), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "operation_id", name="uq_finding_operation_tenant_id"),
)

Table(
    "finding_comments",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("comment_id", String(100), nullable=False),
    Column("issue_record_id", String(64), ForeignKey("managed_issues.id"), nullable=False),
    Column("author_id", String(64), nullable=False),
    Column("comment_sha256", String(64), nullable=False),
    Column("visibility", String(32), nullable=False),
    Column("comment_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "comment_id", name="uq_finding_comment_tenant_id"),
)

Table(
    "finding_risk_acceptances",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("acceptance_id", String(100), nullable=False),
    Column("issue_record_id", String(64), ForeignKey("managed_issues.id"), nullable=False),
    Column("approver_id", String(64), nullable=False),
    Column("rationale_sha256", String(64), nullable=False),
    Column("accepted_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("acceptance_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "acceptance_id", name="uq_finding_acceptance_tenant_id"),
)

Table(
    "finding_retests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("retest_id", String(100), nullable=False),
    Column("issue_record_id", String(64), ForeignKey("managed_issues.id"), nullable=False),
    Column("baseline_run_id", String(100), nullable=False),
    Column("retest_run_id", String(100)),
    Column("coverage_state", String(32), nullable=False),
    Column("result_state", String(32), nullable=False),
    Column("requested_by", String(64), nullable=False),
    Column("requested_at", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "retest_id", name="uq_finding_retest_tenant_id"),
)

Table(
    "finding_report_snapshots",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("report_id", String(100), nullable=False),
    Column("audience", String(32), nullable=False),
    Column("reviewed_snapshot_sha256", String(64), nullable=False),
    Column("policy_revision", String(100), nullable=False),
    Column("roe_version_id", String(100), nullable=False),
    Column("coverage_state", String(32), nullable=False),
    Column("report_sha256", String(64), nullable=False),
    Column("generation_profile", String(64), nullable=False),
    Column("publication_block_sha256", String(64), nullable=False),
    Column("report_state", String(32), nullable=False),
    Column("generated_by", String(64), nullable=False),
    Column("generated_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "report_id", "report_sha256", name="uq_finding_report_tenant_digest"),
)

Table(
    "finding_report_claims",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("claim_id", String(100), nullable=False),
    Column("report_record_id", String(64), ForeignKey("finding_report_snapshots.id"), nullable=False),
    Column("claim_sha256", String(64), nullable=False),
    Column("evidence_set_sha256", String(64), nullable=False),
    Column("provenance", String(32), nullable=False),
    Column("reviewer_adopted", Boolean, nullable=False),
    Column("claim_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "claim_id", name="uq_finding_report_claim_tenant_id"),
)

Table(
    "finding_publications",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("publication_id", String(100), nullable=False),
    Column("report_record_id", String(64), ForeignKey("finding_report_snapshots.id"), nullable=False),
    Column("report_sha256", String(64), nullable=False),
    Column("reviewer_id", String(64), nullable=False),
    Column("publisher_id", String(64), nullable=False),
    Column("publication_state", String(32), nullable=False),
    Column("published_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "publication_id", name="uq_finding_publication_tenant_id"),
)

Table(
    "finding_connector_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("profile_revision", Integer, nullable=False),
    Column("connector_kind", String(32), nullable=False),
    Column("destination_allowlist_sha256", String(64), nullable=False),
    Column("field_allowlist_sha256", String(64), nullable=False),
    Column("credential_reference_id", String(100)),
    Column("callback_key_reference_id", String(100)),
    Column("network_enabled", Boolean, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "profile_id", "profile_revision", name="uq_finding_connector_profile_tenant_revision"
    ),
)

Table(
    "finding_connector_deliveries",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("delivery_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("finding_connector_profiles.id"), nullable=False),
    Column("report_record_id", String(64), ForeignKey("finding_report_snapshots.id"), nullable=False),
    Column("snapshot_sha256", String(64), nullable=False),
    Column("destination_key_sha256", String(64), nullable=False),
    Column("fields_sha256", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("delivery_state", String(32), nullable=False),
    Column("next_attempt_at", DateTime(timezone=True)),
    Column("attempt_count", Integer, nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "profile_record_id", "idempotency_key", name="uq_finding_connector_delivery_tenant_key"
    ),
)

Table(
    "finding_connector_attempts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("attempt_id", String(100), nullable=False),
    Column("delivery_record_id", String(64), ForeignKey("finding_connector_deliveries.id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("response_sha256", String(64)),
    Column("reason_code", String(100), nullable=False),
    Column("attempt_state", String(32), nullable=False),
    Column("network_contact_count", Integer, nullable=False),
    Column("attempted_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "delivery_record_id", "attempt_number", name="uq_finding_connector_attempt_tenant_number"
    ),
)

Table(
    "finding_connector_callbacks",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("callback_id", String(100), nullable=False),
    Column("delivery_record_id", String(64), ForeignKey("finding_connector_deliveries.id"), nullable=False),
    Column("nonce_sha256", String(64), nullable=False),
    Column("envelope_sha256", String(64), nullable=False),
    Column("signature_sha256", String(64), nullable=False),
    Column("callback_state", String(32), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "nonce_sha256", name="uq_finding_connector_callback_tenant_nonce"),
)

Table(
    "finding_connector_reconciliations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("reconciliation_id", String(100), nullable=False),
    Column("delivery_record_id", String(64), ForeignKey("finding_connector_deliveries.id"), nullable=False),
    Column("internal_state", String(32), nullable=False),
    Column("external_state", String(32), nullable=False),
    Column("external_object_sha256", String(64), nullable=False),
    Column("reconciliation_state", String(32), nullable=False),
    Column("reconciled_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "reconciliation_id", name="uq_finding_connector_reconciliation_tenant_id"),
)
