from datetime import datetime, timezone

import pytest

from redagent_platform import (
    domain,
    evidence_chain,
    job_queue,
    supply_chain,
    supply_chain_runtime,
)
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 21, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.REPOSITORY, value="repo-1")


def repository(**overrides: object) -> supply_chain.RepositoryAllowlistEntry:
    values = {
        "repository_id": "repo-1",
        "repository_path": "B:/owned/repo",
        "owner_user_id": "owner-1",
        "trusted": True,
    }
    values.update(overrides)
    return supply_chain.RepositoryAllowlistEntry(**values)  # type: ignore[arg-type]


def pipeline(**overrides: object) -> supply_chain.PipelineAllowlistEntry:
    values = {
        "pipeline_id": "pipeline-1",
        "repository_id": "repo-1",
        "owner_user_id": "owner-1",
    }
    values.update(overrides)
    return supply_chain.PipelineAllowlistEntry(**values)  # type: ignore[arg-type]


def scope(**overrides: object) -> supply_chain.SupplyChainScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "repositories": (repository(),),
        "pipelines": (pipeline(),),
        "external_verification_approved": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainScope(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> supply_chain.SupplyChainAssessmentRequest:
    values = {
        "job_id": "supply-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "repository_id": "repo-1",
        "pipeline_id": "pipeline-1",
        "check_kinds": (
            supply_chain.SupplyChainCheckKind.STATIC_ANALYSIS,
            supply_chain.SupplyChainCheckKind.DEPENDENCY_INVENTORY,
            supply_chain.SupplyChainCheckKind.SBOM_IMPORT,
            supply_chain.SupplyChainCheckKind.SENSITIVE_VALUE_SCAN,
            supply_chain.SupplyChainCheckKind.PROVENANCE_CHECK,
        ),
        "requested_at": NOW,
        "external_verification_requested": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainAssessmentRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> supply_chain_runtime.SupplyChainRuntimeProfile:
    values = {
        "profile_id": "supply-chain-runtime-profile",
        "module_id": "supply-chain-runtime",
        "allowed_repository_ids": ("repo-1",),
        "allowed_pipeline_ids": ("pipeline-1",),
        "allowed_check_kinds": (
            supply_chain.SupplyChainCheckKind.STATIC_ANALYSIS,
            supply_chain.SupplyChainCheckKind.DEPENDENCY_INVENTORY,
            supply_chain.SupplyChainCheckKind.SBOM_IMPORT,
            supply_chain.SupplyChainCheckKind.SENSITIVE_VALUE_SCAN,
            supply_chain.SupplyChainCheckKind.PROVENANCE_CHECK,
        ),
        "max_results": 20,
        "timeout_seconds": 120,
        "actions": (supply_chain_runtime.SupplyChainRuntimeAction.IMPORT_RESULTS,),
    }
    values.update(overrides)
    return supply_chain_runtime.SupplyChainRuntimeProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.SUPPLY_CHAIN_POSTURE,),
        "policy_token_reference": "policy-ref-supply",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "supply_chain_findings", "supply_chain_report_rows"),
        "cleanup_callback": "cleanup://runner-1/supply-chain-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def runtime_request(**overrides: object) -> supply_chain_runtime.SupplyChainRuntimeRequest:
    values = {
        "runtime_id": "supply-chain-runtime-1",
        "profile": profile(),
        "scope": scope(),
        "assessment_request": request(),
        "runner": runner(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return supply_chain_runtime.SupplyChainRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[supply_chain_runtime.SupplyChainRuntimeResultItem, ...]:
    return (
        supply_chain_runtime.SupplyChainRuntimeResultItem(
            item_id="sbom-1",
            kind=supply_chain_runtime.SupplyChainRuntimeResultKind.SBOM,
            location_type=supply_chain.SupplyChainLocationType.SOURCE_FILE,
            location="sbom/redagent.json",
            control_category=supply_chain.SupplyChainControlCategory.SBOM_COVERAGE,
            severity=supply_chain_runtime.Severity.INFO,
            remediation_guidance="Keep SBOM generation in the full gate.",
            false_positive_workflow="Reviewer can suppress with build provenance evidence.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized SBOM import summary.",
            detector_name="local-sbom-import",
            repository_id="repo-1",
        ),
        supply_chain_runtime.SupplyChainRuntimeResultItem(
            item_id="scorecard-1",
            kind=supply_chain_runtime.SupplyChainRuntimeResultKind.SCORECARD,
            location_type=supply_chain.SupplyChainLocationType.SOURCE_FILE,
            location=".github/workflows/ci.yml",
            control_category=supply_chain.SupplyChainControlCategory.ARTIFACT_INTEGRITY,
            severity=supply_chain_runtime.Severity.MEDIUM,
            remediation_guidance="Pin workflow actions by full commit SHA.",
            false_positive_workflow="Reviewer can suppress with signed internal action evidence.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized Scorecard-style workflow finding.",
            detector_name="scorecard-style-import",
            repository_id="repo-1",
            pipeline_id="pipeline-1",
        ),
        supply_chain_runtime.SupplyChainRuntimeResultItem(
            item_id="sensitive-1",
            kind=supply_chain_runtime.SupplyChainRuntimeResultKind.SENSITIVE_VALUE,
            location_type=supply_chain.SupplyChainLocationType.SOURCE_FILE,
            location="src/config.py",
            control_category=supply_chain.SupplyChainControlCategory.SENSITIVE_VALUE_EXPOSURE,
            severity=supply_chain_runtime.Severity.HIGH,
            remediation_guidance="Remove the sensitive value and rotate the affected credential.",
            false_positive_workflow="Reviewer can suppress only with expired canary evidence.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized sensitive-value detector finding.",
            detector_name="gitleaks-style-import",
            repository_id="repo-1",
            redacted_locations=("src/config.py:12 [redacted]",),
            raw_value_recorded=False,
            canary_markers=("CANARY-SUPPLY",),
            contains_sensitive_material=True,
        ),
        supply_chain_runtime.SupplyChainRuntimeResultItem(
            item_id="provenance-1",
            kind=supply_chain_runtime.SupplyChainRuntimeResultKind.PROVENANCE,
            location_type=supply_chain.SupplyChainLocationType.PIPELINE_OBJECT,
            location="pipeline-1:release",
            control_category=supply_chain.SupplyChainControlCategory.BUILD_PROVENANCE,
            severity=supply_chain_runtime.Severity.MEDIUM,
            remediation_guidance="Require signed provenance for release artifacts.",
            false_positive_workflow="Reviewer can suppress with signed attestation evidence.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized provenance finding.",
            detector_name="slsa-style-import",
            repository_id="repo-1",
            pipeline_id="pipeline-1",
        ),
    )


def test_plan_accepts_only_allowlisted_trusted_repositories_and_pipelines() -> None:
    plan = supply_chain_runtime.build_supply_chain_runtime_plan(runtime_request())

    assert plan.repository_id == "repo-1"
    assert plan.pipeline_id == "pipeline-1"
    assert plan.local_only
    assert plan.job.mode is domain.TestMode.SUPPLY_CHAIN_POSTURE

    with pytest.raises(ValueError, match="supply_chain_assessment_denied:trusted_repository_required"):
        supply_chain_runtime.build_supply_chain_runtime_plan(
            runtime_request(scope=scope(repositories=(repository(trusted=False),)))
        )

    with pytest.raises(ValueError, match="supply_chain_runtime_pipeline_not_allowlisted"):
        supply_chain_runtime.build_supply_chain_runtime_plan(
            runtime_request(profile=profile(allowed_pipeline_ids=()), assessment_request=request(pipeline_id="pipeline-1"))
        )


def test_external_verification_and_scanner_actions_are_disabled_by_default() -> None:
    with pytest.raises(ValueError, match="supply_chain_assessment_denied:external_verification_not_approved"):
        supply_chain_runtime.build_supply_chain_runtime_plan(
            runtime_request(assessment_request=request(external_verification_requested=True))
        )

    with pytest.raises(ValueError, match="supply_chain_runtime_external_or_scanner_action_not_allowed"):
        supply_chain_runtime.build_supply_chain_runtime_plan(
            runtime_request(
                profile=profile(
                    actions=(
                        supply_chain_runtime.SupplyChainRuntimeAction.IMPORT_RESULTS,
                        supply_chain_runtime.SupplyChainRuntimeAction.RUN_SCANNER,
                    )
                )
            )
        )


def test_runtime_rejects_raw_sensitive_values_and_canary_leaks() -> None:
    request_obj = runtime_request()
    plan = supply_chain_runtime.build_supply_chain_runtime_plan(request_obj)
    raw_value = result_items()[2].__class__(
        **{**result_items()[2].__dict__, "raw_value_recorded": True}
    )
    canary_leak = result_items()[2].__class__(
        **{**result_items()[2].__dict__, "redacted_locations": ("src/config.py:12 CANARY-SUPPLY",)}
    )

    with pytest.raises(ValueError, match="raw_sensitive_value_forbidden"):
        supply_chain_runtime.execute_supply_chain_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(raw_value,),
        )

    with pytest.raises(ValueError, match="canary_marker_leaked"):
        supply_chain_runtime.execute_supply_chain_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(canary_leak,),
        )


def test_runtime_imports_sbom_scorecard_sensitive_value_and_provenance_results() -> None:
    request_obj = runtime_request()
    plan = supply_chain_runtime.build_supply_chain_runtime_plan(request_obj)
    result = supply_chain_runtime.execute_supply_chain_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert len(result.imported_evidence_ids) == 4
    assert len(result.findings) == 4
    assert len(result.report_rows) == 4
    assert result.report_rows[0].kind is supply_chain_runtime.SupplyChainRuntimeResultKind.SBOM
    assert result.report_rows[1].kind is supply_chain_runtime.SupplyChainRuntimeResultKind.SCORECARD
    assert result.report_rows[2].kind is supply_chain_runtime.SupplyChainRuntimeResultKind.SENSITIVE_VALUE
    assert result.report_rows[2].evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert result.report_rows[3].control_category is supply_chain.SupplyChainControlCategory.BUILD_PROVENANCE
    assert result.findings[0].source == "supply_chain_runtime"


def test_report_rows_do_not_include_raw_sensitive_or_canary_values() -> None:
    request_obj = runtime_request()
    plan = supply_chain_runtime.build_supply_chain_runtime_plan(request_obj)
    result = supply_chain_runtime.execute_supply_chain_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    rendered = str(result.report_rows)
    assert "CANARY-SUPPLY" not in rendered
    assert "raw-value" not in rendered
    assert "src/config.py:12 [redacted]" not in rendered


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = runtime_request()
    plan = supply_chain_runtime.build_supply_chain_runtime_plan(request_obj)
    blocked = supply_chain_runtime.execute_supply_chain_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=supply_chain_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.SUPPLY_CHAIN_POSTURE,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = supply_chain_runtime.execute_supply_chain_runtime_plan(
        plan=plan,
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
