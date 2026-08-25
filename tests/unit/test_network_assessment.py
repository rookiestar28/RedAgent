from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, network_assessment


NOW = datetime(2026, 7, 8, 19, 0, tzinfo=timezone.utc)


def roe(**overrides: object) -> network_assessment.NetworkROE:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "network_ranges": (
            network_assessment.NetworkRange(
                cidr="192.0.2.0/24",
                ownership_attested=True,
                description="RFC 5737 documentation lab range used as local fixture.",
            ),
        ),
        "host_allowlist": (
            network_assessment.HostAllowlistEntry(
                value="192.0.2.10",
                ownership_attested=True,
                description="Approved lab host fixture.",
            ),
        ),
        "window_start": NOW - timedelta(minutes=5),
        "window_end": NOW + timedelta(hours=1),
        "max_rate_per_second": 1.0,
        "max_connection_count": 10,
        "max_concurrent_jobs": 1,
        "emergency_stop_contact": "email:security@example.test",
        "local_lab_validated": True,
        "allowed_modes": (
            network_assessment.NetworkAssessmentMode.INVENTORY_ONLY,
            network_assessment.NetworkAssessmentMode.PASSIVE_METADATA,
        ),
    }
    values.update(overrides)
    return network_assessment.NetworkROE(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> network_assessment.NetworkAssessmentRequest:
    values = {
        "job_id": "net-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": "192.0.2.10",
        "mode": network_assessment.NetworkAssessmentMode.INVENTORY_ONLY,
        "requested_at": NOW,
        "projected_connection_count": 1,
        "requested_rate_per_second": 0.5,
        "requested_activities": (),
        "operator_user_id": "operator-1",
        "runner_id": "runner-1",
    }
    values.update(overrides)
    return network_assessment.NetworkAssessmentRequest(**values)  # type: ignore[arg-type]


def test_network_roe_requires_explicit_scope_limits_window_and_emergency_contact() -> None:
    network_assessment.validate_network_roe(roe())

    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"network_ranges": ()}, "network_ranges_required"),
        ({"host_allowlist": ()}, "host_allowlist_required"),
        ({"window_start": NOW + timedelta(hours=2)}, "invalid_network_testing_window"),
        ({"max_rate_per_second": 0}, "invalid_network_rate_limit"),
        ({"max_connection_count": 0}, "invalid_network_connection_limit"),
        ({"max_concurrent_jobs": 0}, "invalid_network_concurrency_limit"),
        ({"emergency_stop_contact": ""}, "missing_emergency_stop_contact"),
    )
    for overrides, expected in cases:
        with pytest.raises(ValueError, match=expected):
            network_assessment.validate_network_roe(roe(**overrides))


def test_passive_inventory_mode_is_allowed_before_active_probe_mode() -> None:
    decision = network_assessment.evaluate_network_assessment(roe(), request())

    assert decision.allowed
    assert decision.reason == "network_passive_inventory_allowed"
    assert decision.normalized_target == "192.0.2.10"

    active = network_assessment.evaluate_network_assessment(
        roe(allowed_modes=(network_assessment.NetworkAssessmentMode.ACTIVE_PROBE,)),
        request(mode=network_assessment.NetworkAssessmentMode.ACTIVE_PROBE),
    )

    assert not active.allowed
    assert active.reason == "active_network_probe_not_implemented"


def test_network_policy_blocks_internet_wide_third_party_and_forbidden_activity() -> None:
    with pytest.raises(ValueError, match="internet_wide_scanning_forbidden"):
        network_assessment.validate_network_roe(
            roe(
                network_ranges=(
                    network_assessment.NetworkRange(
                        cidr="0.0.0.0/0",
                        ownership_attested=True,
                        description="Forbidden internet-wide range.",
                    ),
                )
            )
        )

    with pytest.raises(ValueError, match="third_party_network_range_forbidden"):
        network_assessment.validate_network_roe(
            roe(
                network_ranges=(
                    network_assessment.NetworkRange(
                        cidr="198.51.100.0/24",
                        ownership_attested=False,
                        description="Unattested third-party range.",
                    ),
                )
            )
        )

    forbidden = network_assessment.evaluate_network_assessment(
        roe(),
        request(requested_activities=(network_assessment.NetworkForbiddenActivity.EXPLOIT_VALIDATION,)),
    )

    assert not forbidden.allowed
    assert forbidden.reason == "forbidden_network_activity_requested"


def test_local_lab_or_owned_infrastructure_validation_is_required() -> None:
    with pytest.raises(ValueError, match="local_lab_validation_required"):
        network_assessment.validate_network_roe(roe(local_lab_validated=False))

    unowned_host = network_assessment.HostAllowlistEntry(
        value="192.0.2.10",
        ownership_attested=False,
        description="Unattested host.",
    )
    with pytest.raises(ValueError, match="third_party_host_forbidden"):
        network_assessment.validate_network_roe(roe(host_allowlist=(unowned_host,)))


def test_network_evidence_records_scope_method_counts_timestamps_operator_runner_and_redaction() -> None:
    observation = network_assessment.NetworkEvidenceObservation(
        job_id="net-job-1",
        organization_id="org-1",
        scope_summary="192.0.2.0/24 host 192.0.2.10 inventory-only",
        method=network_assessment.NetworkAssessmentMode.INVENTORY_ONLY,
        request_count=1,
        connection_count=0,
        started_at=NOW,
        ended_at=NOW + timedelta(seconds=1),
        operator_user_id="operator-1",
        runner_id="runner-1",
        redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        notes="No active network interaction performed.",
    )

    result = network_assessment.append_network_evidence(
        chain=evidence_chain.EvidenceChain(),
        observation=observation,
        evidence_id="net-evidence-1",
    )

    assert result.record.kind is domain.EvidenceKind.SCANNER_OUTPUT
    assert result.content["scope"] == observation.scope_summary
    assert result.content["method"] == "inventory_only"
    assert result.content["request_count"] == 1
    assert result.content["connection_count"] == 0
    assert result.content["started_at"] == NOW.isoformat()
    assert result.content["ended_at"] == (NOW + timedelta(seconds=1)).isoformat()
    assert result.content["operator_user_id"] == "operator-1"
    assert result.content["runner_id"] == "runner-1"
    assert result.content["redaction_status"] == "not_applicable"
