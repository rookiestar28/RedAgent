"""Exact zero-execution artifact-posture adapter for the closed campaign dispatcher."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable

from redagent_platform.artifact_pipeline.analysis import (
    ComponentInput,
    PipelineFixture,
    PipelineResult,
    PromotedDatabase,
    PromotedRules,
    WorkflowInput,
    analyze_fixture,
)
from redagent_platform.artifact_pipeline.compiler import compile_artifact_plan
from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization, ArtifactKind
from redagent_platform.artifact_pipeline.lifecycle import (
    ArtifactRun,
    ArtifactRunState,
    complete_artifact_cleanup,
    transition_artifact_run,
)
from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.artifact_pipeline.promotion import verify_current_artifact_promotion
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)
from redagent_platform.runner_service.campaign_result import (
    AdapterResultMaterialV1,
    AdapterResultWriter,
    NormalizedAdapterFindingV1,
)


class ArtifactCampaignAdapter:
    """Run only the certified R110 canonical data fixture and persist its real result."""

    adapter_id = "redagent-canonical-artifact"
    adapter_version = "1.0.0-r110.1"

    def __init__(
        self,
        workspace: Path,
        result_writer: AdapterResultWriter,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        root = workspace.resolve()
        if not root.is_dir():
            raise ValueError("artifact_campaign_workspace_invalid")
        self._workspace = root
        self._result_writer = result_writer
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def dispatch(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt:
        _validate_request(request)
        now = self._clock()
        promotion = verify_current_artifact_promotion(self._workspace, now=now)
        artifact_sha256, manifest_sha256 = _qualification(self._workspace)
        profile = certified_profiles()["r110-repository-snapshot-v1"]
        authorization = ArtifactAuthorization(
            authorization_id=f"authorization-{request.invocation_id}",
            policy_decision_id=f"policy-{request.effect_id}",
            policy_revision="artifact-posture-policy-v2",
            reservation_id=f"reservation-{request.effect_id}",
            artifact_lease_id=promotion.receipt.receipt_id,
            artifact_binding_id=promotion.receipt.receipt_id,
            artifact_sha256=artifact_sha256,
            artifact_kind=ArtifactKind.REPOSITORY_SNAPSHOT,
            manifest_sha256=manifest_sha256,
            profile_id=profile.profile_id,
            stage_ids=tuple(item.value for item in profile.stages),
            approved_at=now,
            expires_at=min(now + timedelta(seconds=profile.timeout_seconds), promotion.receipt.expires_at),
        )
        compiled = compile_artifact_plan(profile=profile, authorization=authorization, now=now)
        result = analyze_fixture(
            fixture=_fixture(compiled.artifact_sha256, compiled.manifest_sha256),
            rules=PromotedRules(
                bundle_id="r110-rules-v1",
                bundle_sha256="3" * 64,
                schema_sha256="4" * 64,
            ),
            database=PromotedDatabase(
                database_id="r110-database-v1",
                database_sha256="5" * 64,
                schema_sha256="6" * 64,
                advisories={"pkg:npm/synthetic@1.0.0": ("R110-ADVISORY-1", "high")},
            ),
            analyzed_at=now,
        )
        run = ArtifactRun(
            run_id=request.invocation_id,
            state=ArtifactRunState.PLANNED,
            lease_id=promotion.receipt.receipt_id,
        )
        for state in (
            ArtifactRunState.RESERVED,
            ArtifactRunState.VALIDATING,
            ArtifactRunState.INVENTORYING,
            ArtifactRunState.CHECKING,
            ArtifactRunState.NORMALIZING,
            ArtifactRunState.CLEANING,
        ):
            run = transition_artifact_run(run, state)
        run, cleanup = complete_artifact_cleanup(
            run,
            occurred_at=now,
            residual_resource_ids=(),
            untrusted_execution_count=result.untrusted_execution_count,
        )
        if (
            run.state is not ArtifactRunState.SUCCEEDED
            or result.external_contact_count != 0
            or result.untrusted_execution_count != 0
        ):
            # CRITICAL: never rewrite execution/contact truth into a successful campaign result.
            raise ValueError("artifact_campaign_zero_execution_violation")
        findings = _findings(result)
        report = {
            "schema": "redagent.artifact-posture-campaign-result/v1",
            "adapter_id": self.adapter_id,
            "profile_id": profile.profile_id,
            "plan_sha256": compiled.plan_sha256,
            "result_sha256": result.result_sha256,
            "output_complete": result.complete,
            "coverage_state": "complete" if result.complete else "partial",
            "untrusted_execution_count": result.untrusted_execution_count,
            "external_contact_count": result.external_contact_count,
            "findings": [asdict(item) for item in findings],
            "cleanup": {
                "residual_resource_count": cleanup.residual_resource_count,
                "inventory_sha256": cleanup.inventory_sha256,
            },
        }
        return await self._result_writer.persist(
            AdapterResultMaterialV1(
                request=request,
                report_safe_content=json.dumps(
                    report, sort_keys=True, separators=(",", ":")
                ).encode("utf-8"),
                findings=findings,
                coverage_state=(
                    CoverageState.COMPLETE if result.complete else CoverageState.PARTIAL
                ),
                cleanup_receipt_id=_stable_id("cleanup-r129", request),
                observed_at=now,
            )
        )

    async def lookup(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt | None:
        _validate_request(request)
        return await self._result_writer.lookup(
            request,
            cleanup_receipt_id=_stable_id("cleanup-r129", request),
        )


def _validate_request(request: CampaignAdapterRequest) -> None:
    expected = closed_execution_registry()["artifact-posture@1"]
    if (
        request.capability_key != expected.capability_key
        or (request.adapter_id, request.adapter_version)
        != (expected.adapter_id, expected.adapter_version)
        or (request.profile_id, request.profile_revision, request.profile_sha256)
        != (expected.profile_id, expected.profile_revision, expected.profile_sha256)
        or any(
            value is not None
            for value in (request.bundle_id, request.bundle_revision, request.bundle_sha256)
        )
    ):
        raise ValueError("artifact_campaign_binding_mismatch")


def _qualification(workspace: Path) -> tuple[str, str]:
    try:
        value = json.loads(
            (
                workspace
                / "runtime-assets/attestations/260828-ARTIFACT_POSTURE_QUALIFICATION_V2.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("artifact_campaign_qualification_invalid") from exc
    credential_finding = value.get("credential_finding")
    artifact_sha256 = (
        credential_finding.get("artifact_sha256")
        if isinstance(credential_finding, dict)
        else None
    )
    manifest_sha256 = value.get("manifest_sha256")
    if (
        not isinstance(value, dict)
        or value.get("status") != "passed"
        or value.get("profiles") != ["r110-repository-snapshot-v1"]
        or not isinstance(artifact_sha256, str)
        or len(artifact_sha256) != 64
        or not isinstance(manifest_sha256, str)
        or len(manifest_sha256) != 64
    ):
        raise ValueError("artifact_campaign_qualification_invalid")
    return artifact_sha256, manifest_sha256


def _fixture(artifact_sha256: str, manifest_sha256: str) -> PipelineFixture:
    return PipelineFixture(
        artifact_sha256=artifact_sha256,
        manifest_sha256=manifest_sha256,
        components=(
            ComponentInput(
                component_id="component-r110",
                component_type="npm",
                name="synthetic",
                version="1.0.0",
                purl="pkg:npm/synthetic@1.0.0",
                license_expression="MIT",
            ),
        ),
        workflows=(
            WorkflowInput(
                workflow_id="workflow-r110",
                trigger="pull_request_target",
                checks_out_untrusted_ref=True,
                interpolates_untrusted_context=True,
                action_refs=("owner/action@main",),
                token_permissions=("contents:write",),
            ),
        ),
        mobile=(),
        complete=True,
        partial_reasons=(),
    )


def _findings(result: PipelineResult) -> tuple[NormalizedAdapterFindingV1, ...]:
    values: list[NormalizedAdapterFindingV1] = []
    records = [
        (item.advisory_id, item.component_id, item.severity)
        for item in result.vulnerabilities
    ]
    records.extend(
        (item.rule_id, item.resource_id, item.severity)
        for item in result.static_findings
    )
    for rule_id, resource, severity in records:
        values.append(
            NormalizedAdapterFindingV1(
                source_record_id=f"artifact-{len(values) + 1}",
                tool="redagent-canonical-artifact",
                tool_version="1.0.0-r110.1",
                rule_id=rule_id,
                rule_version="1",
                database_version="r110-v1",
                title=f"Artifact posture finding: {rule_id}",
                resource_identity=resource,
                location="canonical-repository-snapshot",
                severity=severity,
                confidence="confirmed",
                taxonomy_ids=("CWE-110",),
                control_ids=("R110",),
            )
        )
    return tuple(values)


def _stable_id(prefix: str, request: CampaignAdapterRequest) -> str:
    digest = hashlib.sha256(
        f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
    ).hexdigest()[:24]
    return f"{prefix}-{digest}"
