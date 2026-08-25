from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, evidence_store, redaction


NOW = datetime(2026, 7, 9, 13, 0, tzinfo=timezone.utc)


def test_central_redaction_returns_sanitized_text_and_evidence() -> None:
    text = "\n".join(
        (
            "Authorization: Bearer sample-value",
            "Cookie: session=raw-cookie-value",
            "user ray@example.com",
            "password=raw-password",
            "CANARY-R057",
        )
    )

    result = redaction.sanitize_text(
        text,
        redaction.RedactionArtifactClass.COMMAND_LOG,
        redaction.RedactionConfig(canary_markers=("CANARY-R057",)),
    )

    assert result.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert result.redacted
    assert result.original_hash != result.sanitized_hash
    assert "sample-value" not in result.sanitized_text
    assert "raw-cookie-value" not in result.sanitized_text
    assert "ray@example.com" not in result.sanitized_text
    assert "raw-password" not in result.sanitized_text
    assert "CANARY-R057" not in result.sanitized_text
    assert {finding.category for finding in result.evidence} >= {
        redaction.RedactionCategory.AUTH_HEADER,
        redaction.RedactionCategory.SENSITIVE_ASSIGNMENT,
        redaction.RedactionCategory.EMAIL,
        redaction.RedactionCategory.CANARY,
    }


def test_private_key_material_is_blocked() -> None:
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"

    result = redaction.sanitize_text(
        f"{begin}\nfake-key-material\n{end}",
        redaction.RedactionArtifactClass.EVIDENCE_ARTIFACT,
    )

    assert result.redaction_status is evidence_chain.RedactionStatus.BLOCKED
    assert result.blocked_reason == "key_material_blocked"
    assert "fake-key-material" not in result.sanitized_text


def test_mapping_redaction_preserves_structure() -> None:
    sanitized, result = redaction.sanitize_mapping(
        {
            "headers": {"Authorization": "Bearer sample-value"},
            "body": "contact ray@example.com",
        },
        redaction.RedactionArtifactClass.HTTP_METADATA,
    )

    assert result.redacted
    assert sanitized["headers"] == {"Authorization": "Bearer [redacted]"}
    assert sanitized["body"] == "contact [redacted-email]"


def test_assert_no_sensitive_output_fails_closed() -> None:
    redaction.assert_no_sensitive_output("ordinary sanitized text", redaction.RedactionArtifactClass.REPORT)

    with pytest.raises(ValueError, match="sensitive_output_not_redacted"):
        redaction.assert_no_sensitive_output(
            "api_key=raw-value",
            redaction.RedactionArtifactClass.REPORT,
        )


def test_evidence_store_blocks_private_key_before_persistence(tmp_path) -> None:
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)

    result = store.write_artifact(
        evidence_store.EvidenceArtifactWriteRequest(
            evidence_id="evidence-r057",
            organization_id="org-1",
            source_job_id="job-1",
            kind=domain.EvidenceKind.COMMAND_LOG,
            created_at=NOW,
            redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            retention_class=evidence_chain.RetentionClass.STANDARD,
            access_policy=evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=f"{begin}\nfake-key-material\n{end}".encode("utf-8"),
            contains_sensitive_capture=False,
            artifact_metadata={"source": "unit-test"},
            operator_user_id="operator-1",
            runner_id="runner-1",
        ),
        evidence_chain.EvidenceChain(),
    )

    assert result.evidence_record.redaction_status is evidence_chain.RedactionStatus.BLOCKED
    assert result.manifest.artifact_path is None
    assert result.manifest.artifact_metadata["redaction_pipeline"]["blocked_reason"] == "key_material_blocked"
    assert not (tmp_path / "artifacts" / "evidence-r057.bin").exists()
