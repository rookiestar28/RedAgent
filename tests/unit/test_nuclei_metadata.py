import pytest

from redagent_platform import domain, nuclei_metadata


def template(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": "exposure-header-check",
        "info": {
            "name": "Exposure Header Check",
            "severity": "low",
            "tags": "exposure,headers",
            "reference": ["https://example.test/advisory"],
            "classification": {
                "cwe-id": ["CWE-200"],
                "cvss-score": "3.1",
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            },
        },
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}],
    }
    values.update(overrides)
    return values


def test_import_extracts_nuclei_template_metadata() -> None:
    imported = nuclei_metadata.import_nuclei_template_metadata(template())

    assert imported.template_id == "exposure-header-check"
    assert imported.name == "Exposure Header Check"
    assert imported.severity is nuclei_metadata.NucleiSeverity.LOW
    assert imported.tags == ("exposure", "headers")
    assert imported.references == ("https://example.test/advisory",)
    assert imported.classification.cwe_ids == ("CWE-200",)
    assert imported.classification.cvss_score == 3.1
    assert imported.protocol_types == ("http",)
    assert imported.risk_class is domain.TestRiskClass.PASSIVE
    assert imported.metadata_only
    assert not imported.execution_enabled


def test_high_risk_protocols_and_tags_are_labeled_by_default() -> None:
    imported = nuclei_metadata.import_nuclei_template_metadata(
        template(
            info={
                "name": "Headless OAST Check",
                "severity": "medium",
                "tags": ["oast", "credential"],
            },
            headless=[{"steps": "not imported"}],
        )
    )

    assert imported.risk_class is domain.TestRiskClass.ACTIVE_INTRUSIVE
    assert "protocol:headless" in imported.high_risk_reasons
    assert "tag:oast" in imported.high_risk_reasons
    assert "tag:credential" in imported.high_risk_reasons


def test_unclear_or_high_severity_template_is_high_risk() -> None:
    imported = nuclei_metadata.import_nuclei_template_metadata(
        template(
            info={"name": "Unclear Critical", "severity": "critical", "tags": "api"},
            payloads={"user": ["admin"]},
        )
    )

    assert "severity:critical" in imported.high_risk_reasons
    assert "unclear_behavior" in imported.high_risk_reasons
    assert imported.risk_class is domain.TestRiskClass.ACTIVE_INTRUSIVE


def test_review_workflow_can_approve_reject_or_require_sandbox_only() -> None:
    low_risk = nuclei_metadata.import_nuclei_template_metadata(template())
    high_risk = nuclei_metadata.import_nuclei_template_metadata(template(info={"name": "Code", "severity": "high"}, code=[{}]))

    approved = nuclei_metadata.review_nuclei_template(
        low_risk,
        reviewer_user_id="reviewer-1",
        status=nuclei_metadata.NucleiReviewStatus.APPROVED,
        reason="Metadata-only low-risk template.",
    )
    rejected = nuclei_metadata.review_nuclei_template(
        high_risk,
        reviewer_user_id="reviewer-1",
        status=nuclei_metadata.NucleiReviewStatus.REJECTED,
        reason="Code protocol not allowed.",
    )
    sandbox = nuclei_metadata.review_nuclei_template(
        high_risk,
        reviewer_user_id="reviewer-1",
        status=nuclei_metadata.NucleiReviewStatus.SANDBOX_ONLY_REQUIRED,
        reason="Requires isolated sandbox review.",
    )

    assert approved.status is nuclei_metadata.NucleiReviewStatus.APPROVED
    assert rejected.status is nuclei_metadata.NucleiReviewStatus.REJECTED
    assert sandbox.status is nuclei_metadata.NucleiReviewStatus.SANDBOX_ONLY_REQUIRED
    assert not approved.execution_enabled
    assert not sandbox.execution_enabled


def test_high_risk_template_cannot_be_approved_for_general_use() -> None:
    high_risk = nuclei_metadata.import_nuclei_template_metadata(template(info={"name": "Code", "severity": "high"}, code=[{}]))

    with pytest.raises(ValueError, match="high_risk_template_requires_sandbox_or_reject"):
        nuclei_metadata.review_nuclei_template(
            high_risk,
            reviewer_user_id="reviewer-1",
            status=nuclei_metadata.NucleiReviewStatus.APPROVED,
            reason="No.",
        )


def test_import_rejects_missing_required_metadata_and_never_exposes_execution() -> None:
    with pytest.raises(ValueError, match="missing_template_id"):
        nuclei_metadata.import_nuclei_template_metadata(template(id=""))

    with pytest.raises(ValueError, match="missing_protocol_type"):
        nuclei_metadata.import_nuclei_template_metadata({"id": "x", "info": {"name": "x", "severity": "info"}})

    imported = nuclei_metadata.import_nuclei_template_metadata(template())
    assert not hasattr(nuclei_metadata, "execute_template")
    assert not imported.execution_enabled
