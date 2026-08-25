from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redagent_platform.orchestration.contracts import CONTRACT_SCHEMA_VERSION, RunnerDispatchCommand
from redagent_platform.runner_service.dispatch import (
    PreparedSyntheticDispatch,
    RunnerCurrentFacts,
    SyntheticRunnerDispatcher,
)
from redagent_platform.runner_service.sdk import (
    AdapterExecutionRequest,
    RunnerExecutionCoordinator,
    SyntheticConformanceAdapter,
)
from redagent_platform.secret_service.contracts import SecretMaterial
from tests.unit.test_compat_100_adapter_sdk import capability


NOW = datetime(2026, 7, 10, 17, 0, tzinfo=timezone.utc)


class PolicyResult:
    def __init__(self, decision_id: str, receipt_id: str) -> None:
        self.decision_id = decision_id
        self.receipt_id = receipt_id


class Policy:
    def __init__(self, *, deny_action: str | None = None) -> None:
        self.calls: list[str] = []
        self.deny_action = deny_action

    async def enforce_runner(self, **values):
        action = values["action"]
        self.calls.append(action)
        if action == self.deny_action:
            raise RuntimeError("policy_boundary_denied")
        return PolicyResult(f"decision-{len(self.calls)}", f"receipt-{len(self.calls)}")


class Backend:
    def __init__(
        self, tmp_path: Path, *, requires_secret: bool = True,
        fail_persistence: bool = False,
    ) -> None:
        self.tmp_path = tmp_path
        self.requires_secret = requires_secret
        self.fail_persistence = fail_persistence
        self.events: list[str] = []
        self.material = SecretMaterial({"password": bytearray(b"R100-SYNTHETIC-DISPATCH")})  # pragma: allowlist secret

    async def current_facts(self, command, *, action, occurred_at):
        self.events.append(f"facts:{action}")
        states = {
            "runner.manifest.issue": ("draft", "absent", "certified"),
            "runner.manifest.claim": ("issued", "absent", "certified"),
            "runner.secret.resolve": ("claimed", "claimed", "verified"),
            "runner.execute": ("claimed", "claimed", "verified"),
            "runner.evidence.submit": ("running", "claimed", "verified"),
        }
        manifest, lease, sandbox = states[action]
        return RunnerCurrentFacts(
            tenant_id=command.tenant_id, runner_id="runner-1", job_id=command.job_id,
            registration_state="active", capability_status="certified",
            artifact_status="verified", manifest_state=manifest, lease_state=lease,
            identity_generation=2, runner_generation=2, sandbox_status=sandbox,
            cleanup_required=True, policy_reference=command.policy_reference,
            roe_version_id=command.roe_version_id,
        )

    async def issue_manifest(self, command, *, authorization, occurred_at, correlation_id):
        self.events.append("issue")
        request = AdapterExecutionRequest(
            execution_id="execution-1", tenant_id=command.tenant_id, runner_id="runner-1",
            lease_id="lease-1", job_id=command.job_id, manifest_sha256="a" * 64,
            policy_decision_id=authorization.decision_id, capability=capability(),
            workspace_root=self.tmp_path / "runner-work", requested_at=occurred_at,
            deadline=occurred_at + timedelta(seconds=5), cancel_requested=False,
        )
        return PreparedSyntheticDispatch(
            request=request, adapter=SyntheticConformanceAdapter(require_secret=self.requires_secret),
            requires_secret=self.requires_secret,
        )

    async def claim_manifest(self, prepared, *, authorization, occurred_at, correlation_id):
        self.events.append("claim")

    async def resolve_secret(self, prepared, *, authorization, occurred_at, correlation_id):
        self.events.append("resolve_secret")
        return self.material

    async def mark_running(self, prepared, *, execution_receipt, occurred_at, correlation_id):
        self.events.append("running")

    async def submit_evidence(self, prepared, artifact, *, execution_receipt, authorization, occurred_at, correlation_id):
        self.events.append("evidence")
        assert artifact.content == b'{"result":"synthetic-ok"}'
        return ("evidence-1",)

    async def revoke_secret(self, prepared, *, occurred_at, correlation_id):
        self.events.append("revoke_secret")

    async def finalize(self, prepared, *, evidence_ids, execution_receipt, policy_receipt_ids, occurred_at, correlation_id):
        self.events.append("finalize")
        assert len(policy_receipt_ids) == 5

    async def fail(self, prepared, *, failure_code, execution_receipt, occurred_at, correlation_id):
        self.events.append(f"fail:{failure_code}")
        if self.fail_persistence:
            raise RuntimeError("synthetic_failure_store_outage")


def _command() -> RunnerDispatchCommand:
    return RunnerDispatchCommand(
        schema_version=CONTRACT_SCHEMA_VERSION, tenant_id="tenant-1", job_id="job-1",
        engagement_id="engagement-1", roe_version_id="roe-1",
        policy_reference="policy:compat_099:1", expected_revision=3,
        dispatch_id="r100-job-1-3",
    )


def test_dispatcher_rechecks_five_boundaries_and_links_secret_evidence_cleanup(tmp_path: Path) -> None:
    policy, backend = Policy(), Backend(tmp_path)
    result = asyncio.run(SyntheticRunnerDispatcher(
        policy, backend, RunnerExecutionCoordinator(),
    ).dispatch(_command(), occurred_at=NOW, correlation_id="temporal:job-1:run-1"))

    assert result.state == "succeeded" and result.cleanup_completed
    assert result.evidence_ids == ("evidence-1",)
    assert policy.calls == [
        "runner.manifest.issue", "runner.manifest.claim", "runner.secret.resolve",
        "runner.execute", "runner.evidence.submit",
    ]
    assert backend.material.cleared
    assert backend.events[-5:] == [
        "running", "facts:runner.evidence.submit", "evidence", "revoke_secret", "finalize",
    ]


def test_policy_denial_before_execute_revokes_secret_and_never_runs_or_submits_evidence(tmp_path: Path) -> None:
    policy, backend = Policy(deny_action="runner.execute"), Backend(tmp_path)
    result = asyncio.run(SyntheticRunnerDispatcher(
        policy, backend, RunnerExecutionCoordinator(),
    ).dispatch(_command(), occurred_at=NOW, correlation_id="temporal:job-1:run-1"))

    assert result.state == "failed" and result.failure_code == "runner_policy_denied"
    assert "evidence" not in backend.events
    assert "revoke_secret" in backend.events
    assert backend.material.cleared


def test_failure_receipt_outage_is_not_hidden_from_workflow(tmp_path: Path) -> None:
    policy = Policy(deny_action="runner.execute")
    backend = Backend(tmp_path, fail_persistence=True)

    with pytest.raises(RuntimeError, match="runner_failure_persistence_failed"):
        asyncio.run(SyntheticRunnerDispatcher(
            policy, backend, RunnerExecutionCoordinator(),
        ).dispatch(_command(), occurred_at=NOW, correlation_id="temporal:job-1:run-1"))
