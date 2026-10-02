from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.service import (
    AuthorityRecheck,
    EffectAmbiguityPersistenceError,
    EffectDispatchCommand,
    EffectReconciliationCommand,
    CampaignEffectCoordinator,
)
from redagent_platform.runner_service.contracts import (
    JobManifestDraft,
    JobManifestDraftV2,
    ResourceLimits,
    sign_job_manifest_v2,
)
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)


NOW = datetime(2026, 8, 24, 1, tzinfo=timezone.utc)
COMPLETED = NOW + timedelta(seconds=1)


def _binding() -> CapabilityBindingKeyV1:
    closed = closed_execution_registry()["nuclei-trusted-runtime@3"]
    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id="nuclei-trusted-runtime",
        capability_revision=3,
        execution_manifest_sha256="a" * 64,
        adapter_id="nuclei-service",
        adapter_version="3.11.1-r105.3",
        profile_id="nuclei-http-header-v1",
        profile_revision=1,
        profile_sha256=closed.profile_sha256,
        bundle_id=closed.bundle_id,
        bundle_revision=closed.bundle_revision,
        bundle_sha256=closed.bundle_sha256,
        semantics_revision=1,
        semantics_sha256="d" * 64,
        normalized_output_sha256="e" * 64,
        projection_revision=1,
        projection_sha256="f" * 64,
    )


def _command() -> EffectDispatchCommand:
    return EffectDispatchCommand(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="engagement-r123",
        target_id="target-r123",
        effect_id="effect-r123",
        invocation_id="invocation-r123",
        effect_intent_sha256="2" * 64,
        envelope_sha256="1" * 64,
        expected_claim_version=0,
        expected_dispatch_attempt=0,
        expected_dispatch_generation=0,
        claim_owner="relay-r123",
        binding=_binding(),
    )


class Authority:
    def __init__(self, decisions: tuple[AuthorityRecheck, ...]) -> None:
        self.decisions = list(decisions)
        self.calls: list[str] = []
        self.times: list[datetime] = []

    async def recheck(self, command: EffectDispatchCommand, *, now: datetime) -> AuthorityRecheck:
        self.calls.append(command.effect_id)
        self.times.append(now)
        return self.decisions.pop(0)


class Store:
    def __init__(
        self,
        *,
        confirm_failures: int = 0,
        confirm_cancellations: int = 0,
        ambiguity_fail: bool = False,
    ) -> None:
        self.events: list[tuple[str, object]] = []
        self.confirm_failures = confirm_failures
        self.confirm_cancellations = confirm_cancellations
        self.ambiguity_fail = ambiguity_fail

    async def claim(self, command: EffectDispatchCommand, *, now: datetime) -> int:
        self.events.append(("claim", command.effect_id))
        return 1

    async def mark_dispatching(
        self, command: EffectDispatchCommand, *, expected_claim_version: int,
        request_sha256: str, runner_id: str, workload_identity: str, now: datetime,
    ) -> int:
        self.events.append(("dispatching", request_sha256))
        return 2

    async def confirm(
        self, command: EffectDispatchCommand, *, expected_claim_version: int,
        receipt_sha256: str, receipt_payload: dict[str, object], now: datetime,
    ) -> object:
        self.events.append(("confirm", (receipt_sha256, receipt_payload)))
        if self.confirm_cancellations:
            self.confirm_cancellations -= 1
            raise asyncio.CancelledError
        if self.confirm_failures:
            self.confirm_failures -= 1
            raise RuntimeError("synthetic-confirm-response-lost")
        return receipt_payload

    async def ambiguity(
        self, command: EffectDispatchCommand, *, expected_claim_version: int,
        failure_code: str, now: datetime,
    ) -> None:
        self.events.append(("ambiguity", failure_code))
        if self.ambiguity_fail:
            raise RuntimeError("synthetic-ambiguity-write-failed")

    async def not_applied(
        self, command: EffectDispatchCommand, *, expected_claim_version: int,
        receipt_sha256: str, receipt_payload: dict[str, object], now: datetime,
    ) -> object:
        self.events.append(("not_applied", (receipt_sha256, receipt_payload)))
        return {"state": "not_applied"}

    async def lookup_unavailable(
        self, command: EffectDispatchCommand, *, expected_claim_version: int,
        failure_code: str, now: datetime,
    ) -> object:
        self.events.append(("lookup_unavailable", failure_code))
        return {
            "state": "reconciliation_required",
            "next_retry_at": now + timedelta(seconds=5),
        }


def test_effect_receipt_preserves_durable_dispatch_clock_after_fresh_authority_check():
    class StrictClockStore(Store):
        async def mark_dispatching(self, command, **kwargs):
            self.started_at = kwargs["now"]
            return await super().mark_dispatching(command, **kwargs)

        async def confirm(self, command, **kwargs):
            expected = self.started_at.isoformat().replace("+00:00", "Z")
            if kwargs["receipt_payload"]["started_at"] != expected:
                raise RuntimeError("effect_receipt_claim_conflict")
            return await super().confirm(command, **kwargs)

    authority = Authority((AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),) * 2)
    store = StrictClockStore()
    dispatcher = Dispatcher()
    moments = iter((NOW + timedelta(milliseconds=200), COMPLETED))
    coordinator = CampaignEffectCoordinator(authority, store, Issuer(), dispatcher, ResultOwner(), clock=lambda: next(moments))
    receipt = asyncio.run(coordinator.dispatch(_command(), now=NOW))
    assert receipt["started_at"] == NOW.isoformat().replace("+00:00", "Z")
    assert authority.times == [NOW, NOW + timedelta(milliseconds=200)]
    assert dispatcher.calls == 1
    assert not any(event[0] == "ambiguity" for event in store.events)


class Issuer:
    async def issue(self, command: EffectDispatchCommand, *, authority: AuthorityRecheck, now: datetime):
        v1 = JobManifestDraft(
            schema_version="1.0", manifest_id="manifest-r123", job_id="job-r123",
            tenant_id=command.tenant_id, engagement_id=command.engagement_id,
            roe_version_id="roe-r123", environment="local", runner_class_id="runner-class-r123",
            network_plane="isolated-target", adapter_id=command.binding.adapter_id,
            adapter_version=command.binding.adapter_version,
            capability_digest=command.binding.execution_manifest_sha256,
            image_digest="sha256:" + "9" * 64, artifact_receipt_id="artifact-r123",
            policy_revision="policy-r123", policy_decision_id="decision-r123",
            target_ids=(command.target_id,), target_hashes=("8" * 64,),
            limits=ResourceLimits(cpu_millis=1000, memory_mib=512, pids=64,
                                  timeout_seconds=60, evidence_bytes=1024 * 1024),
            egress_profile="owned-loopback", evidence_schema=("nuclei-result-v1",),
            secret_reference_ids=(), issued_at=now, expires_at=now + timedelta(minutes=1),
            nonce="nonce-r123",
        )
        draft = JobManifestDraftV2(
            v1=v1, capability_id=command.binding.capability_id,
            capability_revision=command.binding.capability_revision,
            execution_manifest_sha256=command.binding.execution_manifest_sha256,
            profile_id=command.binding.profile_id,
            profile_revision=command.binding.profile_revision,
            profile_sha256=command.binding.profile_sha256,
            bundle_id=command.binding.bundle_id, bundle_revision=command.binding.bundle_revision,
            bundle_sha256=command.binding.bundle_sha256,
        )
        return sign_job_manifest_v2(
            draft, Ed25519PrivateKey.generate(), key_id="r123-test-key"
        )


class Dispatcher:
    def __init__(
        self,
        *,
        fail: bool = False,
        lookup_receipt: AdapterTerminalReceipt | None = None,
        lookup_fail: bool = False,
    ) -> None:
        self.fail = fail
        self.calls = 0
        self.lookup_receipt = lookup_receipt
        self.lookup_fail = lookup_fail
        self.lookup_calls = 0

    async def dispatch(self, request):
        self.calls += 1
        if self.fail:
            raise RuntimeError("adapter_receipt_commit_unknown")
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id, effect_id=request.effect_id,
            state="confirmed", external_receipt_id="adapter-receipt-r123",
            evidence_ids=("evidence-r123",), cleanup_receipt_id="cleanup-r123",
            output_complete=True, external_contact_count=0, failure_code=None,
        )

    async def lookup(self, request):
        self.lookup_calls += 1
        if self.lookup_fail:
            raise RuntimeError("synthetic-status-lookup-outage")
        return self.lookup_receipt


class CancelledDispatcher(Dispatcher):
    async def dispatch(self, request):
        del request
        self.calls += 1
        raise asyncio.CancelledError


class ResultOwner:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = []
        self.reconciliation_flags = []

    async def finalize(self, command, receipt, *, now, reconciliation=False):
        self.calls.append((command, receipt))
        self.reconciliation_flags.append(reconciliation)
        if self.fail:
            raise RuntimeError("trusted_result_persistence_failed")
        return receipt


def _reconciliation_command() -> EffectReconciliationCommand:
    command = replace(
        _command(),
        expected_claim_version=3,
        expected_dispatch_attempt=1,
        expected_dispatch_generation=1,
    )
    binding = command.binding
    request = CampaignAdapterRequest(
        tenant_id=command.tenant_id,
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
        invocation_id=command.invocation_id,
        effect_id=command.effect_id,
        envelope_sha256=command.envelope_sha256,
        manifest_v2_sha256="9" * 64,
    )
    request_sha256 = hashlib.sha256(
        json.dumps(asdict(request), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return EffectReconciliationCommand(
        effect_command=command,
        request=request,
        request_sha256=request_sha256,
        runner_id="runner-r123",
        workload_identity="spiffe://redagent/runner/r123",
        started_at=NOW,
    )


def test_effect_coordinator_rechecks_authority_issues_exact_manifest_and_confirms_once() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store()
    dispatcher = Dispatcher()
    result_owner = ResultOwner()
    coordinator = CampaignEffectCoordinator(
        authority,
        store,
        Issuer(),
        dispatcher,
        result_owner,
        clock=lambda: COMPLETED,
    )

    result = asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert result["reconciliation_state"] == "confirmed"
    assert authority.calls == ["effect-r123", "effect-r123"]
    assert authority.times == [NOW, COMPLETED]
    assert [event[0] for event in store.events] == ["claim", "dispatching", "confirm"]
    assert dispatcher.calls == 1
    assert len(result_owner.calls) == 1
    receipt_sha, payload = store.events[-1][1]
    assert len(receipt_sha) == 64
    assert payload == {
        "schema_version": "redagent.r123-effect-receipt/v1",
        "effect_id": "effect-r123",
        "effect_intent_sha256": "2" * 64,
        "envelope_sha256": "1" * 64,
        "dispatch_attempt": 1,
        "dispatch_generation": 1,
        "runner_id": "runner-r123",
        "workload_identity": "spiffe://redagent/runner/r123",
        "request_sha256": store.events[1][1],
        "started_at": NOW.isoformat().replace("+00:00", "Z"),
        "completed_at": COMPLETED.isoformat().replace("+00:00", "Z"),
        "adapter_accepted": True,
        "external_status": "confirmed",
        "external_receipt_id": "adapter-receipt-r123",
        "evidence_ids": ["evidence-r123"],
        "cleanup_receipt_id": "cleanup-r123",
        "output_complete": True,
        "external_contact_count": 0,
        "reconciliation_state": "confirmed",
        "reconciliation_evidence_ids": ["evidence-r123"],
        "redispatch_permitted": False,
        "failure_code": None,
    }


def test_effect_coordinator_uses_fresh_clock_for_pre_io_authority_recheck() -> None:
    expired = NOW + timedelta(seconds=2)

    class ExpiringAuthority(Authority):
        async def recheck(
            self, command: EffectDispatchCommand, *, now: datetime
        ) -> AuthorityRecheck:
            self.calls.append(command.effect_id)
            self.times.append(now)
            return AuthorityRecheck(
                now < expired,
                "allowed" if now < expired else "lease_expired",
                "runner-r123",
                "spiffe://redagent/runner/r123",
            )

    moments = iter((NOW + timedelta(seconds=3), NOW + timedelta(seconds=4)))
    authority = ExpiringAuthority(())
    store = Store()
    dispatcher = Dispatcher()
    coordinator = CampaignEffectCoordinator(
        authority,
        store,
        Issuer(),
        dispatcher,
        ResultOwner(),
        clock=lambda: next(moments),
    )

    with pytest.raises(RuntimeError, match="effect_dispatch_reconciliation_required"):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert authority.times == [NOW, NOW + timedelta(seconds=3)]
    assert dispatcher.calls == 0
    assert [event[0] for event in store.events] == ["claim", "dispatching", "ambiguity"]


@pytest.mark.parametrize("failure", (RuntimeError("synthetic-current-authority-loss"), asyncio.CancelledError()))
def test_effect_coordinator_persists_ambiguity_when_current_authority_recheck_aborts(
    failure: BaseException,
) -> None:
    class AbortingAuthority(Authority):
        async def recheck(
            self, command: EffectDispatchCommand, *, now: datetime
        ) -> AuthorityRecheck:
            self.calls.append(command.effect_id)
            self.times.append(now)
            if len(self.calls) == 2:
                raise failure
            return AuthorityRecheck(
                True,
                "allowed",
                "runner-r123",
                "spiffe://redagent/runner/r123",
            )

    store = Store()
    dispatcher = Dispatcher()
    coordinator = CampaignEffectCoordinator(
        AbortingAuthority(()),
        store,
        Issuer(),
        dispatcher,
        ResultOwner(),
        clock=lambda: COMPLETED,
    )

    expected = asyncio.CancelledError if isinstance(failure, asyncio.CancelledError) else RuntimeError
    with pytest.raises(expected):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert dispatcher.calls == 0
    assert store.events[-1] == ("ambiguity", "pre_io_authority_recheck_unknown")


def test_effect_coordinator_records_ambiguity_and_never_redispatches_after_possible_acceptance() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store()
    dispatcher = Dispatcher(fail=True)
    coordinator = CampaignEffectCoordinator(
        authority, store, Issuer(), dispatcher, ResultOwner()
    )

    with pytest.raises(RuntimeError, match="effect_dispatch_reconciliation_required"):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert [event[0] for event in store.events] == ["claim", "dispatching", "ambiguity"]


def test_effect_coordinator_denies_before_claim_and_rejects_manifest_substitution() -> None:
    denied = Authority((AuthorityRecheck(False, "policy_revoked", "runner-r123", "spiffe://redagent/runner/r123"),))
    store = Store()
    dispatcher = Dispatcher()
    coordinator = CampaignEffectCoordinator(
        denied, store, Issuer(), dispatcher, ResultOwner()
    )
    with pytest.raises(RuntimeError, match="effect_authority_denied:policy_revoked"):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))
    assert store.events == [] and dispatcher.calls == 0

    class WrongIssuer(Issuer):
        async def issue(self, command, *, authority, now):
            signed = await super().issue(command, authority=authority, now=now)
            return replace(
                signed,
                manifest=replace(signed.manifest, profile_sha256="0" * 64),
            )

    allowed = Authority((AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),))
    with pytest.raises(ValueError, match="manifest_v2_profile_mismatch"):
        asyncio.run(CampaignEffectCoordinator(
            allowed, Store(), WrongIssuer(), Dispatcher(), ResultOwner()
        ).dispatch(
            _command(), now=NOW
        ))


def test_effect_coordinator_requires_trusted_result_persistence_before_confirmation() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store()
    dispatcher = Dispatcher()
    result_owner = ResultOwner(fail=True)

    with pytest.raises(RuntimeError, match="effect_dispatch_reconciliation_required"):
        asyncio.run(
            CampaignEffectCoordinator(
                authority, store, Issuer(), dispatcher, result_owner
            ).dispatch(_command(), now=NOW)
        )

    assert dispatcher.calls == 1 and len(result_owner.calls) == 1
    assert [event[0] for event in store.events] == [
        "claim",
        "dispatching",
        "ambiguity",
    ]


def test_effect_coordinator_preserves_cancellation_after_recording_ambiguity() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store()
    dispatcher = CancelledDispatcher()
    coordinator = CampaignEffectCoordinator(
        authority, store, Issuer(), dispatcher, ResultOwner()
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert store.events[-1] == ("ambiguity", "adapter_receipt_commit_unknown")


@pytest.mark.parametrize(("confirm_failures", "recovers"), ((1, True), (2, False)))
def test_effect_coordinator_replays_only_the_canonical_receipt_after_confirm_response_loss(
    confirm_failures,
    recovers,
) -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store(confirm_failures=confirm_failures)
    dispatcher = Dispatcher()
    coordinator = CampaignEffectCoordinator(
        authority,
        store,
        Issuer(),
        dispatcher,
        ResultOwner(),
        clock=lambda: COMPLETED,
    )

    if recovers:
        result = asyncio.run(coordinator.dispatch(_command(), now=NOW))
        assert result["reconciliation_state"] == "confirmed"
    else:
        with pytest.raises(RuntimeError, match="effect_dispatch_reconciliation_required"):
            asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert [name for name, _ in store.events].count("confirm") == 2
    assert [name for name, _ in store.events].count("ambiguity") == (0 if recovers else 1)


def test_effect_coordinator_preserves_confirm_cancellation_after_exact_receipt_replay() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store(confirm_cancellations=1)
    dispatcher = Dispatcher()
    coordinator = CampaignEffectCoordinator(
        authority,
        store,
        Issuer(),
        dispatcher,
        ResultOwner(),
        clock=lambda: COMPLETED,
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(coordinator.dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert [name for name, _ in store.events].count("confirm") == 2
    assert [name for name, _ in store.events].count("ambiguity") == 0


def test_effect_coordinator_does_not_mask_cancellation_when_ambiguity_write_fails() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store(ambiguity_fail=True)
    dispatcher = CancelledDispatcher()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(CampaignEffectCoordinator(
            authority, store, Issuer(), dispatcher, ResultOwner()
        ).dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert store.events[-1] == ("ambiguity", "adapter_receipt_commit_unknown")


def test_effect_coordinator_exposes_ambiguity_persistence_failure_for_activity_fallback() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store(ambiguity_fail=True)

    with pytest.raises(
        EffectAmbiguityPersistenceError,
        match="effect_ambiguity_persistence_failed",
    ):
        asyncio.run(CampaignEffectCoordinator(
            authority, store, Issuer(), Dispatcher(fail=True), ResultOwner()
        ).dispatch(_command(), now=NOW))

    assert store.events[-1] == ("ambiguity", "adapter_receipt_commit_unknown")


def test_effect_coordinator_reconciles_receipt_construction_failure_without_redispatch() -> None:
    authority = Authority((
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
        AuthorityRecheck(True, "allowed", "runner-r123", "spiffe://redagent/runner/r123"),
    ))
    store = Store()
    dispatcher = Dispatcher()

    moments: list[object] = [NOW, RuntimeError("synthetic-completion-clock-failed")]

    def broken_clock() -> datetime:
        value = moments.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    with pytest.raises(RuntimeError, match="effect_dispatch_reconciliation_required"):
        asyncio.run(CampaignEffectCoordinator(
            authority,
            store,
            Issuer(),
            dispatcher,
            ResultOwner(),
            clock=broken_clock,
        ).dispatch(_command(), now=NOW))

    assert dispatcher.calls == 1
    assert [name for name, _ in store.events] == ["claim", "dispatching", "ambiguity"]


def test_effect_reconciliation_confirms_lookup_receipt_without_redispatch() -> None:
    receipt = AdapterTerminalReceipt(
        invocation_id="invocation-r123",
        effect_id="effect-r123",
        state="confirmed",
        external_receipt_id="adapter-receipt-r123",
        evidence_ids=("evidence-r123",),
        cleanup_receipt_id="cleanup-r123",
        output_complete=True,
        external_contact_count=0,
        failure_code=None,
    )
    dispatcher = Dispatcher(lookup_receipt=receipt)
    store = Store()
    result_owner = ResultOwner()
    coordinator = CampaignEffectCoordinator(
        Authority(()), store, Issuer(), dispatcher, result_owner
    )

    result = asyncio.run(coordinator.reconcile(_reconciliation_command(), now=COMPLETED))

    assert result["reconciliation_state"] == "confirmed"
    assert dispatcher.calls == 0 and dispatcher.lookup_calls == 1
    assert len(result_owner.calls) == 1
    assert result_owner.reconciliation_flags == [True]
    assert [name for name, _ in store.events] == ["confirm"]


@pytest.mark.parametrize(
    ("confirm_failures", "expected_state"),
    ((1, "confirmed"), (2, "reconciliation_required")),
)
def test_effect_reconciliation_replays_only_the_canonical_receipt_after_confirm_response_loss(
    confirm_failures,
    expected_state,
) -> None:
    receipt = AdapterTerminalReceipt(
        invocation_id="invocation-r123",
        effect_id="effect-r123",
        state="confirmed",
        external_receipt_id="adapter-receipt-r123",
        evidence_ids=("evidence-r123",),
        cleanup_receipt_id="cleanup-r123",
        output_complete=True,
        external_contact_count=0,
        failure_code=None,
    )
    dispatcher = Dispatcher(lookup_receipt=receipt)
    store = Store(confirm_failures=confirm_failures)
    coordinator = CampaignEffectCoordinator(
        Authority(()), store, Issuer(), dispatcher, ResultOwner()
    )

    result = asyncio.run(coordinator.reconcile(_reconciliation_command(), now=COMPLETED))

    assert result["reconciliation_state" if expected_state == "confirmed" else "state"] == expected_state
    assert dispatcher.calls == 0 and dispatcher.lookup_calls == 1
    assert [name for name, _ in store.events].count("confirm") == 2
    assert [name for name, _ in store.events].count("lookup_unavailable") == (
        0 if expected_state == "confirmed" else 1
    )


@pytest.mark.parametrize(
    ("confirm_failures", "expected_lookup_count"),
    ((0, 0), (1, 1)),
)
def test_effect_reconciliation_preserves_cancellation_after_one_exact_receipt_replay(
    confirm_failures,
    expected_lookup_count,
) -> None:
    receipt = AdapterTerminalReceipt(
        invocation_id="invocation-r123",
        effect_id="effect-r123",
        state="confirmed",
        external_receipt_id="adapter-receipt-r123",
        evidence_ids=("evidence-r123",),
        cleanup_receipt_id="cleanup-r123",
        output_complete=True,
        external_contact_count=0,
        failure_code=None,
    )
    dispatcher = Dispatcher(lookup_receipt=receipt)
    store = Store(confirm_cancellations=1, confirm_failures=confirm_failures)
    coordinator = CampaignEffectCoordinator(
        Authority(()), store, Issuer(), dispatcher, ResultOwner()
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(coordinator.reconcile(_reconciliation_command(), now=COMPLETED))

    assert dispatcher.calls == 0 and dispatcher.lookup_calls == 1
    assert [name for name, _ in store.events].count("confirm") == 2
    assert [name for name, _ in store.events].count("lookup_unavailable") == (
        expected_lookup_count
    )


def test_effect_reconciliation_proves_not_applied_without_redispatch() -> None:
    receipt = AdapterTerminalReceipt(
        invocation_id="invocation-r123",
        effect_id="effect-r123",
        state="not_applied",
        external_receipt_id="lookup-receipt-r123",
        evidence_ids=("lookup-evidence-r123",),
        cleanup_receipt_id="cleanup-r123",
        output_complete=True,
        external_contact_count=0,
        failure_code=None,
    )
    dispatcher = Dispatcher(lookup_receipt=receipt)
    store = Store()
    coordinator = CampaignEffectCoordinator(
        Authority(()), store, Issuer(), dispatcher, ResultOwner()
    )

    result = asyncio.run(coordinator.reconcile(_reconciliation_command(), now=COMPLETED))

    assert result["state"] == "not_applied"
    assert dispatcher.calls == 0 and dispatcher.lookup_calls == 1
    assert [name for name, _ in store.events] == ["not_applied"]
    _, (receipt_sha256, payload) = store.events[0]
    assert payload["external_status"] == "not_applied"
    assert payload["external_receipt_id"] == "lookup-receipt-r123"
    assert payload["evidence_ids"] == ["lookup-evidence-r123"]
    assert payload["cleanup_receipt_id"] == "cleanup-r123"
    assert payload["redispatch_permitted"] is True
    assert receipt_sha256 == hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@pytest.mark.parametrize("lookup_fail", (False, True))
def test_effect_reconciliation_persists_lookup_unavailability_without_redispatch(
    lookup_fail,
) -> None:
    dispatcher = Dispatcher(lookup_fail=lookup_fail)
    store = Store()
    coordinator = CampaignEffectCoordinator(
        Authority(()), store, Issuer(), dispatcher, ResultOwner()
    )

    result = asyncio.run(coordinator.reconcile(_reconciliation_command(), now=COMPLETED))

    assert result["state"] == "reconciliation_required"
    assert dispatcher.calls == 0 and dispatcher.lookup_calls == 1
    assert store.events == [
        ("lookup_unavailable", "adapter_status_lookup_unavailable")
    ]
