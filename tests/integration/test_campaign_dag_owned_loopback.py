from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.dag_execution_activity import (
    DagActivityAction,
    DagActivityMaterialV1,
    DagExecutionActivity,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.service import (
    AuthorityRecheck,
    CampaignEffectCoordinator,
    EffectDispatchCommand,
)
from redagent_platform.nuclei_service.campaign_adapter import NucleiCampaignAdapter
from redagent_platform.nuclei_service.campaign_transport import NucleiDockerTransport
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    ClosedCampaignDispatcher,
)
from redagent_platform.runner_service.campaign_result import AdapterResultMaterialV1
from redagent_platform.runner_service.contracts import (
    JobManifestDraft,
    JobManifestDraftV2,
    ResourceLimits,
    sign_job_manifest_v2,
)
from redagent_platform.zap_service.campaign_adapter import ZapCampaignAdapter
from redagent_platform.zap_service.campaign_transport import ZapDockerTransport


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 29, 8, tzinfo=timezone.utc)
LIVE = (
    os.environ.get("REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION")
    == "owned-loopback-zap-v1"
)


@pytest.mark.skipif(
    not LIVE,
    reason="requires explicit autonomous-planner repo-owned loopback ZAP qualification authority",
)
def test_dag_activity_executes_only_certified_zap_owned_loopback() -> None:
    asyncio.run(_allowed_scenario())


@pytest.mark.parametrize(
    "reason",
    ("policy_denied", "rate_limit_exhausted", "concurrency_limit_exhausted"),
)
def test_safety_denial_stops_before_owned_loopback_adapter(reason: str) -> None:
    asyncio.run(_denied_scenario(reason))


async def _allowed_scenario() -> None:
    suffix = uuid4().hex[:12]
    command = _command(suffix)
    writer = _QualificationResultWriter()
    closed_dispatcher, nuclei_writer = _closed_dispatcher(writer)
    dispatcher = _CountingDispatcher(
        closed_dispatcher
    )
    store = _TransitionStore()
    clock_values = iter(
        (NOW + timedelta(seconds=1), NOW + timedelta(seconds=2))
    )
    coordinator = CampaignEffectCoordinator(
        _Authority((True, True)),
        store,
        _ManifestIssuer(),
        dispatcher,
        _ResultOwner(),
        clock=lambda: next(clock_values),
    )
    state = _ActivityState(command)

    snapshot = await DagExecutionActivity(state, coordinator).execute(
        state.request,
        now=NOW,
    )

    assert snapshot.state is DagRunState.COMPLETED
    assert dispatcher.dispatch_calls == 1
    assert [event[0] for event in store.events] == [
        "claim",
        "dispatching",
        "confirm",
    ]
    confirmation = store.events[-1][1]
    assert confirmation["external_contact_count"] == 0
    assert confirmation["output_complete"] is True
    assert confirmation["cleanup_receipt_id"]
    assert len(writer.materials) == 1
    assert len(writer.materials[0].findings) >= 1
    assert nuclei_writer.materials == []


async def _denied_scenario(reason: str) -> None:
    suffix = uuid4().hex[:12]
    writer = _QualificationResultWriter()
    closed_dispatcher, nuclei_writer = _closed_dispatcher(writer)
    dispatcher = _CountingDispatcher(
        closed_dispatcher
    )
    coordinator = CampaignEffectCoordinator(
        _Authority((False,), denial_reason=reason),
        _TransitionStore(),
        _ManifestIssuer(),
        dispatcher,
        _ResultOwner(),
        clock=lambda: NOW,
    )

    with pytest.raises(RuntimeError, match=f"effect_authority_denied:{reason}"):
        await coordinator.dispatch(_command(suffix), now=NOW)

    assert dispatcher.dispatch_calls == 0
    assert writer.materials == []
    assert nuclei_writer.materials == []


class _ActivityState:
    def __init__(self, command: EffectDispatchCommand) -> None:
        self.command = command
        self.request = DagWorkflowInputV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            tenant_id=command.tenant_id,
            execution_run_id=f"run-{command.effect_id[-12:]}",
            input_sha256="1" * 64,
            plan_sha256="2" * 64,
            max_activity_attempts=2,
            max_transitions=8,
        )

    async def prepare(self, request, *, now):
        assert request == self.request and now == NOW
        return DagActivityMaterialV1(
            action=DagActivityAction.DISPATCH,
            snapshot=_snapshot(self.request, DagRunState.RUNNING),
            effect_command=self.command,
            reconciliation_command=None,
        )

    async def snapshot(self, request, *, now):
        assert request == self.request and now == NOW
        return _snapshot(self.request, DagRunState.COMPLETED)


class _Authority:
    def __init__(
        self, allowed: tuple[bool, ...], *, denial_reason: str = "policy_denied"
    ) -> None:
        self.allowed = list(allowed)
        self.denial_reason = denial_reason

    async def recheck(self, command, *, now):
        del command, now
        allowed = self.allowed.pop(0)
        return AuthorityRecheck(
            allowed,
            "allowed" if allowed else self.denial_reason,
            "runner-planner",
            "spiffe://redagent.test/runner/planner",
        )


class _TransitionStore:
    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []

    async def claim(self, command, *, now):
        del now
        self.events.append(("claim", command.effect_id))
        return 1

    async def mark_dispatching(
        self,
        command,
        *,
        expected_claim_version,
        request_sha256,
        runner_id,
        workload_identity,
        now,
    ):
        del command, runner_id, workload_identity, now
        assert expected_claim_version == 1
        self.events.append(("dispatching", request_sha256))
        return 2

    async def confirm(
        self,
        command,
        *,
        expected_claim_version,
        receipt_sha256,
        receipt_payload,
        now,
    ):
        del command, receipt_sha256, now
        assert expected_claim_version == 2
        self.events.append(("confirm", receipt_payload))
        return receipt_payload

    async def ambiguity(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("allowed owned-loopback path must not become ambiguous")


class _ManifestIssuer:
    async def issue(self, command, *, authority, now):
        del authority
        draft = JobManifestDraftV2(
            v1=JobManifestDraft(
                schema_version="1.0",
                manifest_id=f"manifest-{command.effect_id[-12:]}",
                job_id=f"job-{command.effect_id[-12:]}",
                tenant_id=command.tenant_id,
                engagement_id=command.engagement_id,
                roe_version_id="roe-planner",
                environment="local",
                runner_class_id="runner-class-planner",
                network_plane="isolated-target",
                adapter_id=command.binding.adapter_id,
                adapter_version=command.binding.adapter_version,
                capability_digest=command.binding.execution_manifest_sha256,
                image_digest="sha256:" + "9" * 64,
                artifact_receipt_id="artifact-planner",
                policy_revision="policy-planner",
                policy_decision_id="decision-planner",
                target_ids=(command.target_id,),
                target_hashes=("8" * 64,),
                limits=ResourceLimits(
                    cpu_millis=1000,
                    memory_mib=512,
                    pids=64,
                    timeout_seconds=60,
                    evidence_bytes=1024 * 1024,
                ),
                egress_profile="owned-loopback",
                evidence_schema=("zap-alert-v1",),
                secret_reference_ids=(),
                issued_at=now,
                expires_at=now + timedelta(minutes=1),
                nonce=f"nonce-{command.effect_id[-12:]}",
            ),
            capability_id=command.binding.capability_id,
            capability_revision=command.binding.capability_revision,
            execution_manifest_sha256=command.binding.execution_manifest_sha256,
            profile_id=command.binding.profile_id,
            profile_revision=command.binding.profile_revision,
            profile_sha256=command.binding.profile_sha256,
            bundle_id=command.binding.bundle_id,
            bundle_revision=command.binding.bundle_revision,
            bundle_sha256=command.binding.bundle_sha256,
        )
        return sign_job_manifest_v2(
            draft,
            Ed25519PrivateKey.generate(),
            key_id="planner-test-key",
        )


class _CountingDispatcher:
    def __init__(self, delegate: ClosedCampaignDispatcher) -> None:
        self.delegate = delegate
        self.dispatch_calls = 0

    async def dispatch(self, request):
        self.dispatch_calls += 1
        return await self.delegate.dispatch(request)

    async def lookup(self, request):
        return await self.delegate.lookup(request)


class _ResultOwner:
    async def finalize(self, command, receipt, *, now, reconciliation=False):
        del command, now, reconciliation
        return receipt


class _QualificationResultWriter:
    def __init__(self) -> None:
        self.materials: list[AdapterResultMaterialV1] = []

    async def persist(self, material: AdapterResultMaterialV1) -> AdapterTerminalReceipt:
        self.materials.append(material)
        digest = hashlib.sha256(material.report_safe_content).hexdigest()[:24]
        return AdapterTerminalReceipt(
            invocation_id=material.request.invocation_id,
            effect_id=material.request.effect_id,
            state="confirmed",
            external_receipt_id=f"planner-result-{digest}",
            evidence_ids=(f"planner-evidence-{digest}",),
            cleanup_receipt_id=material.cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(self, request, *, cleanup_receipt_id):
        del request, cleanup_receipt_id
        return None


def _closed_dispatcher(
    zap_writer: _QualificationResultWriter,
) -> tuple[ClosedCampaignDispatcher, _QualificationResultWriter]:
    nuclei_writer = _QualificationResultWriter()
    return (
        ClosedCampaignDispatcher(
            (
                ZapCampaignAdapter(ZapDockerTransport(ROOT), zap_writer),
                NucleiCampaignAdapter(NucleiDockerTransport(ROOT), nuclei_writer),
            )
        ),
        nuclei_writer,
    )


def _binding() -> CapabilityBindingKeyV1:
    closed = closed_execution_registry()["zap-controlled-runtime@2"]
    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=closed.capability_id,
        capability_revision=closed.capability_revision,
        execution_manifest_sha256="a" * 64,
        adapter_id=closed.adapter_id,
        adapter_version=closed.adapter_version,
        profile_id=closed.profile_id,
        profile_revision=closed.profile_revision,
        profile_sha256=closed.profile_sha256,
        bundle_id=closed.bundle_id,
        bundle_revision=closed.bundle_revision,
        bundle_sha256=closed.bundle_sha256,
        semantics_revision=1,
        semantics_sha256="b" * 64,
        normalized_output_sha256="c" * 64,
        projection_revision=1,
        projection_sha256="d" * 64,
    )


def _command(suffix: str) -> EffectDispatchCommand:
    return EffectDispatchCommand(
        tenant_id="tenant-planner-live",
        principal_id="principal-planner-live",
        engagement_id="engagement-planner-live",
        target_id="target-planner-live",
        effect_id=f"effect-planner-{suffix}",
        invocation_id=f"invocation-planner-{suffix}",
        effect_intent_sha256="e" * 64,
        envelope_sha256="f" * 64,
        expected_claim_version=0,
        expected_dispatch_attempt=0,
        expected_dispatch_generation=0,
        claim_owner="dag-planner-live",
        binding=_binding(),
    )


def _snapshot(
    request: DagWorkflowInputV1,
    state: DagRunState,
) -> DagExecutionSnapshotV1:
    terminal = state is DagRunState.COMPLETED
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=request.execution_run_id,
        workflow_request_sha256=dag_workflow_request_sha256(request),
        state=state,
        revision=3 if terminal else 2,
        transition_count=2 if terminal else 1,
        current_node_id=None if terminal else "node-planner-live",
        current_node_state=None if terminal else DagNodeState.RESERVED,
        stop_requested=False,
        terminal_reason="all_nodes_confirmed" if terminal else None,
    )
