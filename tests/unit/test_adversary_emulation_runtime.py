from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    adversary_emulation_runtime,
    attack_campaigns,
    atomic_runner,
    domain,
    evidence_chain,
    job_queue,
    telemetry_feedback,
)
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
LAB_SCOPE = ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value="lab-target-1")


def technique(**overrides: object) -> attack_campaigns.AttackTechniqueSelection:
    values = {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "subtechnique_id": None,
    }
    values.update(overrides)
    return attack_campaigns.AttackTechniqueSelection(**values)  # type: ignore[arg-type]


def telemetry(source: attack_campaigns.TelemetrySource, event_name: str) -> attack_campaigns.ExpectedTelemetry:
    return attack_campaigns.ExpectedTelemetry(
        source=source,
        event_name=event_name,
        detection_owner="blue-team",
        success_criteria=f"{event_name} is observed in the lab telemetry pipeline.",
    )


def campaign(**overrides: object) -> attack_campaigns.AttackCampaign:
    values = {
        "campaign_id": "campaign-1",
        "name": "Lab execution telemetry validation",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target_classes": (domain.TargetType.LAB_TARGET,),
        "techniques": (technique(),),
        "prerequisites": (
            attack_campaigns.CampaignPrerequisite(
                name="Approved lab target",
                description="Approved local lab host is ready.",
                required_permission="lab_operator",
            ),
        ),
        "allowed_windows": (
            attack_campaigns.CampaignWindow(
                start=NOW - timedelta(minutes=10),
                end=NOW + timedelta(hours=1),
                timezone_label="Asia/Taipei",
            ),
        ),
        "expected_telemetry": (
            telemetry(attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.lab.execution_marker"),
            telemetry(attack_campaigns.TelemetrySource.SIEM, "siem.lab.rule"),
        ),
        "safety_class": attack_campaigns.AttackSafetyClass.LAB_ONLY,
        "risk_class": domain.TestRiskClass.LAB_ONLY,
        "detection_objectives": ("Validate expected lab execution telemetry routing.",),
        "cleanup_needs": ("Remove temporary lab marker and preserve sanitized logs.",),
        "created_by_user_id": "planner-1",
        "created_at": NOW - timedelta(hours=1),
    }
    values.update(overrides)
    return attack_campaigns.AttackCampaign(**values)  # type: ignore[arg-type]


def atomic_metadata(**overrides: object) -> atomic_runner.AtomicTestMetadata:
    values: dict[str, object] = {
        "test_id": "atomic-T1059-001",
        "name": "Lab command telemetry metadata",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "supported_platforms": ("windows", "linux"),
        "executor_name": "manual-lab",
        "prerequisite_summary": "Approved lab host is available.",
        "execution_summary": "Manual checkpoint records synthetic lab execution metadata only.",
        "cleanup_summary": "Remove temporary lab marker.",
        "expected_telemetry": ("application_log", "siem"),
        "command": "RAW COMMAND BODY MUST NOT BE STORED",
    }
    values.update(overrides)
    return atomic_runner.import_atomic_metadata(values)


def target(**overrides: object) -> atomic_runner.LabTargetContext:
    values = {
        "target_id": "lab-target-1",
        "target_type": domain.TargetType.LAB_TARGET,
        "environment": "local-lab",
        "platform": "windows",
        "is_lab_target": True,
        "approved_by_user_id": "lead-1",
    }
    values.update(overrides)
    return atomic_runner.LabTargetContext(**values)  # type: ignore[arg-type]


def reviewed(**overrides: object) -> adversary_emulation_runtime.ReviewedTechnique:
    values = {
        "technique_id": "T1059",
        "reviewed_by_user_id": "reviewer-1",
        "reviewed_at": NOW - timedelta(minutes=30),
        "approved": True,
    }
    values.update(overrides)
    return adversary_emulation_runtime.ReviewedTechnique(**values)  # type: ignore[arg-type]


def confirmation(**overrides: object) -> adversary_emulation_runtime.OperatorConfirmation:
    values = {
        "confirmed": True,
        "confirmed_by_user_id": "operator-1",
        "confirmed_at": NOW - timedelta(minutes=5),
        "cleanup_plan": "Remove temporary lab marker and verify lab host baseline.",
        "manual_checkpoint_acknowledged": True,
    }
    values.update(overrides)
    return adversary_emulation_runtime.OperatorConfirmation(**values)  # type: ignore[arg-type]


def telemetry_definition(**overrides: object) -> telemetry_feedback.TelemetryEnabledTestDefinition:
    values = {
        "test_definition_id": "campaign-1",
        "expected_logs": (
            telemetry_feedback.TelemetryExpectation(
                expectation_id="log-1",
                source=attack_campaigns.TelemetrySource.APPLICATION_LOG,
                event_name="app.lab.execution_marker",
                detection_owner="blue-team",
                success_criteria="Application log marker is observed.",
            ),
        ),
        "siem_events": (
            telemetry_feedback.TelemetryExpectation(
                expectation_id="siem-1",
                source=attack_campaigns.TelemetrySource.SIEM,
                event_name="siem.lab.rule",
                detection_owner="blue-team",
                success_criteria="SIEM rule is observed.",
            ),
        ),
        "edr_detections": (),
        "cloud_audit_events": (),
        "detection_owner": "blue-team",
    }
    values.update(overrides)
    return telemetry_feedback.TelemetryEnabledTestDefinition(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> adversary_emulation_runtime.EmulationProfile:
    values = {
        "profile_id": "emulation-profile",
        "module_id": "adversary-emulation-runtime",
        "allowed_campaign_ids": ("campaign-1",),
        "allowed_atomic_test_ids": ("atomic-T1059-001",),
        "supported_platforms": ("windows", "linux"),
        "allowed_modes": (
            adversary_emulation_runtime.EmulationRunMode.DRY_RUN,
            adversary_emulation_runtime.EmulationRunMode.MANUAL_CHECKPOINT,
        ),
        "max_techniques": 3,
        "timeout_seconds": 120,
        "kill_switch_enabled": True,
        "actions": (
            adversary_emulation_runtime.EmulationAction.IMPORT_TELEMETRY,
            adversary_emulation_runtime.EmulationAction.PREPARE_DRY_RUN,
            adversary_emulation_runtime.EmulationAction.RECORD_MANUAL_CHECKPOINT,
        ),
    }
    values.update(overrides)
    return adversary_emulation_runtime.EmulationProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.ADVERSARY_EMULATION,),
        "policy_token_reference": "policy-ref-emulation",
        "target_scope": LAB_SCOPE,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "emulation_report_rows"),
        "cleanup_callback": "cleanup://runner-1/adversary-emulation",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> adversary_emulation_runtime.EmulationOrchestrationRequest:
    values = {
        "runtime_id": "emulation-runtime-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "campaign": campaign(),
        "atomic_tests": (atomic_metadata(),),
        "target": target(),
        "reviewed_techniques": (reviewed(),),
        "telemetry_definition": telemetry_definition(),
        "operator_confirmation": confirmation(),
        "profile": profile(),
        "runner": runner(),
        "requested_mode": adversary_emulation_runtime.EmulationRunMode.DRY_RUN,
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return adversary_emulation_runtime.EmulationOrchestrationRequest(**values)  # type: ignore[arg-type]


def observed(
    expectation_id: str,
    source: attack_campaigns.TelemetrySource,
    event_name: str,
) -> telemetry_feedback.ObservedTelemetryEvent:
    return telemetry_feedback.ObservedTelemetryEvent(
        expectation_id=expectation_id,
        source=source,
        event_name=event_name,
        observed_at=NOW,
        evidence_id=f"evidence-{expectation_id}",
        status=telemetry_feedback.TelemetryObservationStatus.OBSERVED,
    )


def test_plan_requires_lab_target_reviewed_techniques_confirmation_cleanup_telemetry_and_kill_switch() -> None:
    plan = adversary_emulation_runtime.build_emulation_orchestration_plan(request())

    assert plan.campaign_id == "campaign-1"
    assert plan.job.mode is domain.TestMode.ADVERSARY_EMULATION
    assert plan.mode is adversary_emulation_runtime.EmulationRunMode.DRY_RUN
    assert plan.technique_ids == ("T1059",)
    assert plan.atomic_test_ids == ("atomic-T1059-001",)
    assert plan.telemetry_expectation_ids == ("log-1", "siem-1")
    assert plan.manual_checkpoint_required

    with pytest.raises(ValueError, match="lab_target_required"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(target=target(target_type=domain.TargetType.WEB_ORIGIN, is_lab_target=False))
        )

    with pytest.raises(ValueError, match="unreviewed_technique_denied"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(request(reviewed_techniques=()))

    with pytest.raises(ValueError, match="missing_cleanup"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(atomic_tests=(atomic_metadata(cleanup_summary=None),))
        )

    with pytest.raises(ValueError, match="kill_switch_required"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(profile=profile(kill_switch_enabled=False))
        )

    with pytest.raises(ValueError, match="manual_checkpoint_required"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(operator_confirmation=confirmation(manual_checkpoint_acknowledged=False))
        )


def test_unsupported_platform_and_automated_or_payload_actions_are_denied() -> None:
    with pytest.raises(ValueError, match="unsupported_platform"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(atomic_tests=(atomic_metadata(supported_platforms=("linux",)),))
        )

    with pytest.raises(ValueError, match="emulation_mode_not_allowed"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(requested_mode=adversary_emulation_runtime.EmulationRunMode.AUTOMATED_LAB_RUN)
        )

    with pytest.raises(ValueError, match="payload_or_automated_execution_action_not_allowed"):
        adversary_emulation_runtime.build_emulation_orchestration_plan(
            request(
                profile=profile(
                    actions=(
                        adversary_emulation_runtime.EmulationAction.IMPORT_TELEMETRY,
                        adversary_emulation_runtime.EmulationAction.PREPARE_DRY_RUN,
                        adversary_emulation_runtime.EmulationAction.EXECUTE_ATOMIC_COMMAND,
                    )
                )
            )
        )


def test_execution_imports_telemetry_comparison_and_report_mapping_without_running_campaign() -> None:
    request_obj = request()
    plan = adversary_emulation_runtime.build_emulation_orchestration_plan(request_obj)
    result = adversary_emulation_runtime.execute_emulation_orchestration_plan(
        plan=plan,
        telemetry_definition=request_obj.telemetry_definition,
        observed_events=(observed("log-1", attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.lab.execution_marker"),),
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.imported_evidence_ids == ("emulation-runtime-1:telemetry-comparison",)
    assert result.telemetry_evidence is not None
    assert result.detection_report is not None
    assert len(result.report_rows) == 2
    assert result.report_rows[0].status is telemetry_feedback.TelemetryObservationStatus.OBSERVED
    assert result.report_rows[1].status is telemetry_feedback.TelemetryObservationStatus.MISSING
    assert result.detection_report.gaps[0]["expectation_id"] == "siem-1"


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = request()
    plan = adversary_emulation_runtime.build_emulation_orchestration_plan(request_obj)
    blocked = adversary_emulation_runtime.execute_emulation_orchestration_plan(
        plan=plan,
        telemetry_definition=request_obj.telemetry_definition,
        observed_events=(),
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        kill_switch_scope=adversary_emulation_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=LAB_SCOPE,
            modes=(domain.TestMode.ADVERSARY_EMULATION,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = adversary_emulation_runtime.execute_emulation_orchestration_plan(
        plan=plan,
        telemetry_definition=request_obj.telemetry_definition,
        observed_events=(),
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
    )

    assert cancelled.allowed
    assert cancelled.reason == "cancelled"
    assert not cancelled.cancellation_evidence[0].credential_revoked
