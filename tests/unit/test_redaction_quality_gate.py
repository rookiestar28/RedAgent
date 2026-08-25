from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import evidence_chain, redaction, redaction_quality_gate


NOW = datetime(2026, 7, 9, 15, 25, tzinfo=timezone.utc)


def artifact(**overrides: object) -> redaction_quality_gate.ClassifiedArtifact:
    values = {
        "artifact_id": "artifact-1",
        "artifact_class": redaction.RedactionArtifactClass.REPORT,
        "classification": redaction_quality_gate.DataClassification.INTERNAL,
        "redaction_status": evidence_chain.RedactionStatus.REDACTED,
        "content": "sanitized report content",
        "high_risk_field_names": (),
        "evidence_attestation_hash": "a" * 64,
    }
    values.update(overrides)
    return redaction_quality_gate.ClassifiedArtifact(**values)  # type: ignore[arg-type]


def request(
    *artifacts: redaction_quality_gate.ClassifiedArtifact,
    **overrides: object,
) -> redaction_quality_gate.RedactionQualityGateRequest:
    values = {
        "gate_id": "gate-1",
        "organization_id": "org-1",
        "requested_by_user_id": "reviewer-1",
        "requested_at": NOW,
        "artifacts": artifacts or (artifact(),),
        "canary_markers": ("CANARY-R081",),
        "manual_override": None,
    }
    values.update(overrides)
    return redaction_quality_gate.RedactionQualityGateRequest(**values)  # type: ignore[arg-type]


def test_canary_leak_detection_blocks_export() -> None:
    leaked = artifact(content="report contains CANARY-R081", redaction_status=evidence_chain.RedactionStatus.REDACTED)

    result = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(leaked),
        evidence_chain.EvidenceChain(),
    )

    assert not result.allowed
    assert result.artifact_results[0].reason == "canary_leak_detected"
    assert result.artifact_results[0].findings[0].risk is redaction_quality_gate.RedactionQualityRisk.CANARY_LEAK


def test_http_log_and_sarif_outputs_require_sanitized_redaction() -> None:
    raw_http = artifact(
        artifact_id="raw-http",
        artifact_class=redaction.RedactionArtifactClass.HTTP_METADATA,
        content="Authorization: Bearer raw-token-value",
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
    )
    sanitized_http = artifact(
        artifact_id="sanitized-http",
        artifact_class=redaction.RedactionArtifactClass.HTTP_METADATA,
        content="Authorization: [redacted]",
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
    )
    sanitized_log = artifact(
        artifact_id="sanitized-log",
        artifact_class=redaction.RedactionArtifactClass.COMMAND_LOG,
        content="operator output password=[redacted]",
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
    )
    sanitized_sarif = artifact(
        artifact_id="sanitized-sarif",
        artifact_class=redaction.RedactionArtifactClass.JSON_SARIF,
        content='{"message":"contact [redacted-email]"}',
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
    )

    denied = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(raw_http),
        evidence_chain.EvidenceChain(),
    )
    allowed = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(sanitized_http, sanitized_log, sanitized_sarif),
        evidence_chain.EvidenceChain(),
    )

    assert not denied.allowed
    assert denied.artifact_results[0].findings[0].risk is redaction_quality_gate.RedactionQualityRisk.RAW_AUTH_MATERIAL
    assert allowed.allowed
    assert {result.classification for result in allowed.artifact_results} == {
        redaction_quality_gate.DataClassification.INTERNAL
    }
    assert {result.redaction_status for result in allowed.artifact_results} == {
        evidence_chain.RedactionStatus.REDACTED
    }


def test_manual_override_requires_reviewer_reason_scope_expiry_and_audit_evidence() -> None:
    with pytest.raises(ValueError, match="missing_reviewer_user_id"):
        redaction_quality_gate.build_manual_review_override(
            override_id="override-1",
            organization_id="org-1",
            reviewer_user_id="",
            reason="False positive review.",
            scope_artifact_ids=("artifact-1",),
            approved_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            allowed_risks=(redaction_quality_gate.RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,),
            audit_chain=evidence_chain.EvidenceChain(),
        )

    override, chain = redaction_quality_gate.build_manual_review_override(
        override_id="override-1",
        organization_id="org-1",
        reviewer_user_id="reviewer-1",
        reason="False positive reviewed for this one field.",
        scope_artifact_ids=("artifact-1",),
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        allowed_risks=(redaction_quality_gate.RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,),
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert override.audit_event_hash == chain.audit_events[-1].event_hash
    assert override.scope_artifact_ids == ("artifact-1",)
    assert override.override_hash


def test_blocked_report_export_for_private_key_material() -> None:
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    blocked = artifact(
        artifact_class=redaction.RedactionArtifactClass.REPORT,
        content=f"{begin}\nfake-key-material\n{end}",
        redaction_status=evidence_chain.RedactionStatus.BLOCKED,
    )

    result = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(blocked),
        evidence_chain.EvidenceChain(),
    )

    assert not result.allowed
    assert result.artifact_results[0].reason == "key_material_detected"


def test_false_positive_safe_override_allows_scoped_high_risk_review_only() -> None:
    high_risk = artifact(
        classification=redaction_quality_gate.DataClassification.CONFIDENTIAL,
        redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        content="Field name looks sensitive but contains no secret value.",
        high_risk_field_names=("business_impact",),
    )
    override, chain = redaction_quality_gate.build_manual_review_override(
        override_id="override-1",
        organization_id="org-1",
        reviewer_user_id="reviewer-1",
        reason="Reviewed as safe false positive for this artifact only.",
        scope_artifact_ids=("artifact-1",),
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        allowed_risks=(redaction_quality_gate.RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,),
        audit_chain=evidence_chain.EvidenceChain(),
    )

    denied = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(high_risk),
        evidence_chain.EvidenceChain(),
    )
    allowed = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(high_risk, manual_override=override),
        chain,
    )

    assert not denied.allowed
    assert denied.artifact_results[0].reason == "unreviewed_high_risk_field"
    assert allowed.allowed
    assert allowed.audit_chain.audit_events[-1].subject_type == "redaction_quality_gate"


def test_manual_override_cannot_bypass_raw_secret_or_expiry() -> None:
    raw_secret = artifact(
        content="token=raw-secret-value",
        redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
    )
    with pytest.raises(ValueError, match="manual_override_non_overridable_risk"):
        redaction_quality_gate.build_manual_review_override(
            override_id="override-unsafe",
            organization_id="org-1",
            reviewer_user_id="reviewer-1",
            reason="Do not allow this.",
            scope_artifact_ids=("artifact-1",),
            approved_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            allowed_risks=(redaction_quality_gate.RedactionQualityRisk.RAW_AUTH_MATERIAL,),
            audit_chain=evidence_chain.EvidenceChain(),
        )
    expired, _ = redaction_quality_gate.build_manual_review_override(
        override_id="override-expired",
        organization_id="org-1",
        reviewer_user_id="reviewer-1",
        reason="Expired high-risk review.",
        scope_artifact_ids=("artifact-1",),
        approved_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
        allowed_risks=(redaction_quality_gate.RedactionQualityRisk.UNREVIEWED_HIGH_RISK_FIELD,),
        audit_chain=evidence_chain.EvidenceChain(),
    )

    with pytest.raises(ValueError, match="manual_override_expired"):
        redaction_quality_gate.evaluate_redaction_quality_gate(
            request(raw_secret, manual_override=expired),
            evidence_chain.EvidenceChain(),
        )

    result = redaction_quality_gate.evaluate_redaction_quality_gate(
        request(raw_secret),
        evidence_chain.EvidenceChain(),
    )

    assert not result.allowed
    assert result.artifact_results[0].reason == "raw_auth_material_detected"
