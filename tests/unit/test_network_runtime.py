from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    domain,
    evidence_chain,
    job_queue,
    lab_validation,
    network_assessment,
    network_runtime,
    target_inventory,
)
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.CIDR, value="192.0.2.10")


def roe(**overrides: object) -> network_assessment.NetworkROE:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "network_ranges": (
            network_assessment.NetworkRange(
                cidr="192.0.2.0/24",
                ownership_attested=True,
                description="Owned lab range.",
            ),
        ),
        "host_allowlist": (
            network_assessment.HostAllowlistEntry(
                value="192.0.2.10",
                ownership_attested=True,
                description="Owned lab host.",
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


def assessment_request(**overrides: object) -> network_assessment.NetworkAssessmentRequest:
    values = {
        "job_id": "network-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": "192.0.2.10",
        "mode": network_assessment.NetworkAssessmentMode.PASSIVE_METADATA,
        "requested_at": NOW,
        "projected_connection_count": 2,
        "requested_rate_per_second": 0.5,
        "requested_activities": (),
        "operator_user_id": "operator-1",
        "runner_id": "runner-1",
    }
    values.update(overrides)
    return network_assessment.NetworkAssessmentRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> network_runtime.NetworkRuntimeProfile:
    values = {
        "profile_id": "network-runtime-profile",
        "module_id": "network-runtime",
        "allowed_modes": (
            network_assessment.NetworkAssessmentMode.INVENTORY_ONLY,
            network_assessment.NetworkAssessmentMode.PASSIVE_METADATA,
        ),
        "max_rate_per_second": 1.0,
        "max_connection_count": 10,
        "timeout_seconds": 120,
        "lab_profile": lab_validation.ScannerPolicyProfile(
            profile_id="network-runtime-profile",
            module_id="network-runtime",
            allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
            required_fixture_kinds=(lab_validation.LabValidationFixtureKind.PASSIVE_WEB,),
            max_age_seconds=86_400,
        ),
    }
    values.update(overrides)
    return network_runtime.NetworkRuntimeProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.PASSIVE_SCAN,),
        "policy_token_reference": "policy-ref-1",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "network_results"),
        "cleanup_callback": "cleanup://runner-1/network-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def inventory() -> target_inventory.InventoryTarget:
    return target_inventory.InventoryTarget(
        id="net-target-1",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="Security Lab",
        target_type=domain.TargetType.CIDR,
        value="192.0.2.10",
        environment=target_inventory.EnvironmentType.STAGING,
        data_sensitivity=target_inventory.DataSensitivity.INTERNAL,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
        explicit_review=True,
        review_reason="approved network fixture",
    )


def validation_record() -> lab_validation.LabValidationRecord:
    return lab_validation.LabValidationRecord(
        validation_id="network-validation-1",
        policy_profile_id="network-runtime-profile",
        module_id="network-runtime",
        lab_target_id="network-lab",
        fixture_ids=("network-runtime-profile:passive_web",),
        sanitized_artifact_ids=("sanitized:network-runtime-profile:passive_web",),
        validated_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(days=1),
        passed=True,
    )


def runtime_request(**overrides: object) -> network_runtime.NetworkRuntimeRequest:
    values = {
        "runtime_id": "network-runtime-1",
        "profile": profile(),
        "roe": roe(),
        "assessment_request": assessment_request(),
        "runner": runner(),
        "inventory_target": inventory(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "lab_validation_records": (validation_record(),),
    }
    values.update(overrides)
    return network_runtime.NetworkRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[network_runtime.NetworkRuntimeResultItem, ...]:
    return tuple(
        network_runtime.NetworkRuntimeResultItem(
            item_id=f"item-{index}",
            kind=kind,
            summary=f"{kind.value} summary",
            connection_count=0,
            request_count=0,
            redaction_status=evidence_chain.RedactionStatus.REDACTED
            if kind is network_runtime.NetworkRuntimeResultKind.SERVICE_EXPOSURE
            else evidence_chain.RedactionStatus.NOT_APPLICABLE,
            notes="sanitized network metadata only",
        )
        for index, kind in enumerate(network_runtime.NetworkRuntimeResultKind, start=1)
    )


def test_runtime_requires_owned_scope_and_lab_validation() -> None:
    unowned_range = network_assessment.NetworkRange(
        cidr="192.0.2.0/24",
        ownership_attested=False,
        description="Unowned range.",
    )
    with pytest.raises(ValueError, match="third_party_network_range_forbidden"):
        network_runtime.build_network_runtime_plan(runtime_request(roe=roe(network_ranges=(unowned_range,))))

    with pytest.raises(ValueError, match="matching_lab_validation_required"):
        network_runtime.build_network_runtime_plan(runtime_request(lab_validation_records=()))


def test_runtime_denies_out_of_scope_active_probe_and_rate_cap() -> None:
    with pytest.raises(ValueError, match="network_assessment_denied:target_not_allowlisted"):
        network_runtime.build_network_runtime_plan(runtime_request(assessment_request=assessment_request(target="198.51.100.10")))

    active_request = assessment_request(mode=network_assessment.NetworkAssessmentMode.ACTIVE_PROBE)
    active_runner = runner(capabilities=(domain.TestMode.ACTIVE_SCAN,))
    with pytest.raises(ValueError, match="network_assessment_denied:active_network_probe_not_implemented"):
        network_runtime.build_network_runtime_plan(
            runtime_request(
                profile=profile(allowed_modes=(network_assessment.NetworkAssessmentMode.ACTIVE_PROBE,)),
                roe=roe(allowed_modes=(network_assessment.NetworkAssessmentMode.ACTIVE_PROBE,)),
                assessment_request=active_request,
                runner=active_runner,
            )
        )

    with pytest.raises(ValueError, match="network_runtime_rate_cap_exceeded"):
        network_runtime.build_network_runtime_plan(runtime_request(assessment_request=assessment_request(requested_rate_per_second=2.0)))


def test_kill_switch_blocks_network_runtime_before_dispatch() -> None:
    request = runtime_request()
    plan = network_runtime.build_network_runtime_plan(request)
    result = network_runtime.execute_network_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=network_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.PASSIVE_SCAN,),
        ),
    )

    assert not result.allowed
    assert result.reason == "kill_switch_active"
    assert result.state.jobs[0].status is domain.JobStatus.QUEUED


def test_runtime_imports_distinct_result_kinds_with_redacted_evidence() -> None:
    request = runtime_request()
    plan = network_runtime.build_network_runtime_plan(request)
    result = network_runtime.execute_network_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert {item.kind for item in result.result_items} == set(network_runtime.NetworkRuntimeResultKind)
    assert len(result.imported_evidence_ids) == len(network_runtime.NetworkRuntimeResultKind)
    assert any(record.redaction_status is evidence_chain.RedactionStatus.REDACTED for record in result.evidence_chain.evidence_records)
