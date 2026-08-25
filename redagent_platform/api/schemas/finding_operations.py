"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
    datetime,
)

from redagent_platform.api.schemas.common import (
    StrictModel,
)

class FindingOperationsImportRequest(StrictModel):
    import_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    run_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    source_record_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    resource_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    evidence_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    evidence_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    coverage_state: Literal["complete", "partial", "unknown"]
    baseline_run_id: str | None = Field(default=None, min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r115-fixture-import"]

class FindingOperationsReviewRequest(StrictModel):
    operation_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    disposition: Literal[
        "confirmed", "false_positive", "risk_accepted", "duplicate", "mitigated",
        "out_of_scope", "closed", "needs_review",
    ]
    reason_code: str = Field(min_length=10, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r115-reviewed-disposition"]

class FindingOperationsReportRequest(StrictModel):
    report_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    audience: Literal["technical", "executive", "customer", "internal"]
    reviewed_snapshot_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    coverage_state: Literal["complete", "partial"] = "complete"
    partial_coverage_disclosed: bool = False
    confirmation: Literal["--confirm-r115-deterministic-report"]

class FindingOperationsDeliveryRequest(StrictModel):
    delivery_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    profile_id: Literal["fixture-ticket-v1"]
    report_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    report_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    destination_object_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    confirmation: Literal["--confirm-r115-fixture-delivery"]

class FindingOperationsPublishRequest(StrictModel):
    publication_id: str = Field(min_length=1, max_length=100, pattern=OPAQUE_ID)
    report_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirmation: Literal["--confirm-r115-independent-publication"]

class FindingOperationsImportData(StrictModel):
    import_id: str; import_sha256: str; issue_ids: list[str]; replayed: bool

class FindingOperationsIssueData(StrictModel):
    issue_id: str; issue_fingerprint: str; title: str; severity: str; confidence: str
    disposition: str; disposition_revision: int = Field(ge=1); owner_id: str | None
    sla_due_at: datetime | None; first_seen_at: datetime; last_seen_at: datetime
    issue_state: str; version: int = Field(ge=1)

class FindingOperationsOccurrenceData(StrictModel):
    occurrence_id: str; issue_id: str; tool_id: str; tool_version: str; rule_id: str
    rule_version: str; database_version: str; coverage_state: str; occurrence_state: str
    evidence_id: str; evidence_sha256: str; redaction_state: str
    observed_at: datetime; version: int = Field(ge=1)

class FindingOperationsReportData(StrictModel):
    report_id: str; audience: str; reviewed_snapshot_sha256: str; policy_revision: str
    roe_version_id: str; coverage_state: str; report_sha256: str; generation_profile: str
    report_state: str; generated_by: str; generated_at: datetime; version: int = Field(ge=1)

class FindingOperationsPublicationData(StrictModel):
    publication_id: str; report_id: str; report_sha256: str; reviewer_id: str; publisher_id: str
    publication_state: str; published_at: datetime | None; version: int = Field(ge=1)

class FindingOperationsDeliveryData(StrictModel):
    delivery_id: str; profile_id: str; report_id: str; snapshot_sha256: str
    delivery_state: str; attempt_count: int = Field(ge=0); network_contact_count: int = Field(ge=0)
    next_attempt_at: datetime | None; version: int = Field(ge=1)

class FindingOperationsDashboardData(StrictModel):
    issues: list[FindingOperationsIssueData]
    occurrences: list[FindingOperationsOccurrenceData]
    reports: list[FindingOperationsReportData]
    publications: list[FindingOperationsPublicationData]
    deliveries: list[FindingOperationsDeliveryData]

class FindingOperationsImportResponse(StrictModel): data: FindingOperationsImportData

class FindingOperationsIssueResponse(StrictModel): data: FindingOperationsIssueData

class FindingOperationsReportResponse(StrictModel): data: FindingOperationsReportData

class FindingOperationsPublicationResponse(StrictModel): data: FindingOperationsPublicationData

class FindingOperationsDeliveryResponse(StrictModel): data: FindingOperationsDeliveryData

class FindingOperationsDashboardResponse(StrictModel): data: FindingOperationsDashboardData

__all__ = (
    "FindingOperationsImportRequest",
    "FindingOperationsReviewRequest",
    "FindingOperationsReportRequest",
    "FindingOperationsDeliveryRequest",
    "FindingOperationsPublishRequest",
    "FindingOperationsImportData",
    "FindingOperationsIssueData",
    "FindingOperationsOccurrenceData",
    "FindingOperationsReportData",
    "FindingOperationsPublicationData",
    "FindingOperationsDeliveryData",
    "FindingOperationsDashboardData",
    "FindingOperationsImportResponse",
    "FindingOperationsIssueResponse",
    "FindingOperationsReportResponse",
    "FindingOperationsPublicationResponse",
    "FindingOperationsDeliveryResponse",
    "FindingOperationsDashboardResponse",
)
