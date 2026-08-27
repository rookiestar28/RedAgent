"""Deterministic Temporal workflows for compat_096 job and campaign lifecycles."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import ActivityError
from temporalio.workflow import ActivityCancellationType

from redagent_platform.orchestration.contracts import (
    ActivityCommand,
    ActivityResult,
    CampaignActivityResult,
    CampaignSnapshot,
    CampaignWorkflowInput,
    CommandAction,
    ContainmentActivityCommand,
    ContainmentActivityResult,
    EmergencyStopSignal,
    JobSnapshot,
    JobWorkflowInput,
    OperatorCommand,
    RunnerDispatchCommand,
    RunnerDispatchResult,
    ClosedLoopCampaignSnapshot,
    ClosedLoopCampaignWorkflowInput,
    ClosedLoopContainActivityCommand,
    ClosedLoopContainActivityResult,
    ClosedLoopDispatchActivityCommand,
    ClosedLoopDispatchActivityResult,
    ClosedLoopReconcileActivityCommand,
    ClosedLoopReconcileActivityResult,
    ClosedLoopStopSignal,
    WorkflowState,
    deterministic_job_workflow_id,
    command_request_hash,
    stop_request_hash,
    system_request_hash,
    closed_loop_workflow_request_sha256,
)
from redagent_platform.orchestration.state import CommandDecision, CommandRejected, LifecycleReducer


_NON_RETRYABLE = (
    "AuthorizationDenied",
    "InvalidWorkflowInput",
    "PolicyDenied",
    "ScopeDenied",
    "UnsupportedCapability",
    "WorkflowVersionConflict",
)

_R123_NON_RETRYABLE = (*_NON_RETRYABLE, "ExecutionDisabled", "DispatchDenied")


def activity_retry_policy(maximum_attempts: int) -> RetryPolicy:
    if isinstance(maximum_attempts, bool) or not 1 <= maximum_attempts <= 5:
        raise ValueError("activity_attempts_invalid")
    return RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=10),
        maximum_attempts=maximum_attempts,
        non_retryable_error_types=_NON_RETRYABLE,
    )


def closed_loop_activity_retry_policy(maximum_attempts: int) -> RetryPolicy:
    """R123-only permanent failures without changing historical compat_096 replay policy."""
    if isinstance(maximum_attempts, bool) or not 1 <= maximum_attempts <= 5:
        raise ValueError("activity_attempts_invalid")
    return RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=10),
        maximum_attempts=maximum_attempts,
        non_retryable_error_types=_R123_NON_RETRYABLE,
    )


@workflow.defn(name="redagent.r096.job-lifecycle.v1")
class JobLifecycleWorkflow:
    def __init__(self) -> None:
        self._reducer: LifecycleReducer | None = None
        self._input: JobWorkflowInput | None = None
        self._pending_stop: EmergencyStopSignal | None = None
        self._dispatch_handle = None

    @workflow.run
    async def run(self, request: JobWorkflowInput) -> JobSnapshot:
        self._input = request
        self._reducer = LifecycleReducer(request.job_id)
        await workflow.execute_activity(
            "r096_admit_job",
            request,
            result_type=ActivityResult,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=activity_retry_policy(request.max_activity_attempts),
        )
        self._reducer.admit()
        while WorkflowState(self._reducer.snapshot.state) not in {
            WorkflowState.CANCELLED, WorkflowState.STOP_REQUESTED, WorkflowState.SUCCEEDED,
        }:
            if self._pending_stop is not None:
                await self._persist_stop(self._pending_stop)
                self._reducer.request_stop(self._pending_stop.signal_id)
                continue
            if WorkflowState(self._reducer.snapshot.state) is WorkflowState.AWAITING_APPROVAL:
                try:
                    await workflow.wait_condition(
                        lambda: self._pending_stop is not None
                        or WorkflowState(self._required_reducer().snapshot.state) is not WorkflowState.AWAITING_APPROVAL,
                        timeout=timedelta(seconds=request.approval_timeout_seconds),
                        timeout_summary="r096 approval deadline",
                    )
                except TimeoutError:
                    await self._record_system_state("approval_timeout")
                    self._reducer.fail("approval_timeout")
            elif (
                WorkflowState(self._reducer.snapshot.state) is WorkflowState.READY
                and request.runner_dispatch_enabled
            ):
                await self._record_system_state("dispatch_started")
                dispatching = self._reducer.begin_dispatch()
                try:
                    self._dispatch_handle = workflow.start_activity(
                        "r100_dispatch_synthetic_job",
                        RunnerDispatchCommand(
                            schema_version=request.schema_version,
                            tenant_id=request.tenant_id,
                            job_id=request.job_id,
                            engagement_id=request.engagement_id,
                            roe_version_id=request.roe_version_id,
                            policy_reference=request.policy_reference,
                            expected_revision=dispatching.revision,
                            dispatch_id=f"r100-{request.job_id}-{dispatching.revision}",
                        ),
                        result_type=RunnerDispatchResult,
                        start_to_close_timeout=timedelta(seconds=90),
                        heartbeat_timeout=timedelta(seconds=2),
                        cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                        retry_policy=activity_retry_policy(request.max_activity_attempts),
                    )
                    result = await self._dispatch_handle
                except Exception:  # noqa: BLE001
                    if self._pending_stop is None:
                        self._reducer.fail("runner_dispatch_failed")
                else:
                    if self._pending_stop is not None:
                        continue
                    if result.state == "succeeded" and result.cleanup_completed:
                        self._reducer.complete_dispatch()
                    else:
                        self._reducer.fail(result.failure_code or "runner_dispatch_failed")
                finally:
                    self._dispatch_handle = None
            else:
                await workflow.wait_condition(
                    lambda: self._pending_stop is not None
                    or WorkflowState(self._required_reducer().snapshot.state)
                    in {
                        WorkflowState.AWAITING_APPROVAL,
                        WorkflowState.CANCELLED, WorkflowState.STOP_REQUESTED,
                    }
                    or (
                        request.runner_dispatch_enabled
                        and WorkflowState(self._required_reducer().snapshot.state) is WorkflowState.READY
                    )
                )
        if WorkflowState(self._reducer.snapshot.state) is WorkflowState.STOP_REQUESTED:
            stop = self._pending_stop
            if stop is None:
                self._reducer.fail("containment_signal_missing")
            else:
                try:
                    containment = await workflow.execute_activity(
                        "r101_contain_synthetic_job",
                        ContainmentActivityCommand(
                            schema_version=request.schema_version,
                            tenant_id=request.tenant_id,
                            job_id=request.job_id,
                            stop_id=stop.signal_id,
                            control_id=stop.control_id or stop.signal_id,
                            actor_user_id=stop.actor_user_id,
                            policy_reference=stop.policy_reference,
                            expected_revision=self._reducer.snapshot.revision,
                            reason_hash=hashlib.sha256(stop.reason.strip().encode()).hexdigest(),
                        ),
                        result_type=ContainmentActivityResult,
                        start_to_close_timeout=timedelta(seconds=30),
                        heartbeat_timeout=timedelta(seconds=2),
                        cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                        retry_policy=activity_retry_policy(request.max_activity_attempts),
                    )
                except Exception:  # noqa: BLE001
                    await self._record_system_state("containment_failed")
                    self._reducer.complete_stop(
                        outcome="containment_failed", failure_code="containment_activity_failed",
                    )
                else:
                    system_action = {
                        "contained": "containment_completed",
                        "contained_with_residual_risk": "containment_completed_with_residual_risk",
                        "containment_failed": "containment_failed",
                    }[containment.outcome]
                    await self._record_system_state(system_action)
                    self._reducer.complete_stop(
                        outcome=containment.outcome,
                        failure_code=(containment.residual_risk_codes[0] if containment.residual_risk_codes else None),
                    )
        return self._reducer.snapshot

    @workflow.query(name="status")
    def status(self) -> JobSnapshot:
        return self._required_reducer().snapshot

    @workflow.signal(name="emergency_stop")
    def emergency_stop(self, request: EmergencyStopSignal) -> None:
        if self._pending_stop is not None and self._pending_stop != request:
            raise CommandRejected("workflow_stop_signal_conflict")
        self._pending_stop = request
        if self._dispatch_handle is not None:
            self._dispatch_handle.cancel()

    @workflow.update(name="approve")
    async def approve(self, command: OperatorCommand) -> CommandDecision:
        return await self._apply_command(command, CommandAction.APPROVE)

    @approve.validator
    def approve_validator(self, command: OperatorCommand) -> None:
        self._validate_command(command, CommandAction.APPROVE)

    @workflow.update(name="pause")
    async def pause(self, command: OperatorCommand) -> CommandDecision:
        return await self._apply_command(command, CommandAction.PAUSE)

    @pause.validator
    def pause_validator(self, command: OperatorCommand) -> None:
        self._validate_command(command, CommandAction.PAUSE)

    @workflow.update(name="resume")
    async def resume(self, command: OperatorCommand) -> CommandDecision:
        return await self._apply_command(command, CommandAction.RESUME)

    @resume.validator
    def resume_validator(self, command: OperatorCommand) -> None:
        self._validate_command(command, CommandAction.RESUME)

    @workflow.update(name="retry")
    async def retry(self, command: OperatorCommand) -> CommandDecision:
        return await self._apply_command(command, CommandAction.RETRY)

    @retry.validator
    def retry_validator(self, command: OperatorCommand) -> None:
        self._validate_command(command, CommandAction.RETRY)

    @workflow.update(name="cancel")
    async def cancel(self, command: OperatorCommand) -> CommandDecision:
        return await self._apply_command(command, CommandAction.CANCEL)

    @cancel.validator
    def cancel_validator(self, command: OperatorCommand) -> None:
        self._validate_command(command, CommandAction.CANCEL)

    async def _apply_command(self, command: OperatorCommand, expected_action: CommandAction) -> CommandDecision:
        reducer = self._required_reducer()
        replay = reducer.replay(command)
        if replay is not None:
            return replay
        self._validate_command(command, expected_action)
        request = self._required_input()
        await workflow.execute_activity(
            "r096_apply_command",
            ActivityCommand(
                schema_version=command.schema_version,
                tenant_id=request.tenant_id,
                job_id=request.job_id,
                command_id=command.command_id,
                action=command.action,
                actor_user_id=command.actor_user_id,
                expected_revision=command.expected_revision,
                policy_reference=command.policy_reference,
                request_hash=command_request_hash(command),
            ),
            result_type=ActivityResult,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=activity_retry_policy(request.max_activity_attempts),
        )
        return reducer.apply(command)

    def _validate_command(self, command: OperatorCommand, expected_action: CommandAction) -> None:
        if CommandAction(command.action) is not expected_action:
            raise CommandRejected("workflow_command_action_mismatch")
        self._required_reducer().validate(command)

    async def _persist_stop(self, request: EmergencyStopSignal) -> None:
        workflow_input = self._required_input()
        await workflow.execute_activity(
            "r096_apply_command",
            ActivityCommand(
                schema_version=request.schema_version,
                tenant_id=workflow_input.tenant_id,
                job_id=workflow_input.job_id,
                command_id=request.signal_id,
                action="emergency_stop",
                actor_user_id=request.actor_user_id,
                expected_revision=self._required_reducer().snapshot.revision,
                policy_reference=request.policy_reference,
                request_hash=stop_request_hash(request),
            ),
            result_type=ActivityResult,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=activity_retry_policy(workflow_input.max_activity_attempts),
        )

    async def _record_system_state(self, action: str) -> None:
        request = self._required_input()
        await workflow.execute_activity(
            "r096_record_system_state",
            ActivityCommand(
                schema_version=request.schema_version,
                tenant_id=request.tenant_id,
                job_id=request.job_id,
                command_id=f"system-{action}-{self._required_reducer().snapshot.revision}",
                action=action,
                actor_user_id="redagent-workflow",
                expected_revision=self._required_reducer().snapshot.revision,
                policy_reference=request.policy_reference,
                request_hash=system_request_hash(
                    tenant_id=request.tenant_id,
                    job_id=request.job_id,
                    action=action,
                    revision=self._required_reducer().snapshot.revision,
                ),
            ),
            result_type=ActivityResult,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=activity_retry_policy(request.max_activity_attempts),
        )

    def _required_reducer(self) -> LifecycleReducer:
        if self._reducer is None:
            raise RuntimeError("workflow_not_initialized")
        return self._reducer

    def _required_input(self) -> JobWorkflowInput:
        if self._input is None:
            raise RuntimeError("workflow_not_initialized")
        return self._input


@workflow.defn(name="redagent.r096.campaign-lifecycle.v1")
class CampaignLifecycleWorkflow:
    def __init__(self) -> None:
        self._snapshot: CampaignSnapshot | None = None

    @workflow.run
    async def run(self, request: CampaignWorkflowInput) -> CampaignSnapshot:
        child_ids: list[str] = []
        for job in request.jobs:
            child_id = deterministic_job_workflow_id(request.tenant_id, job.job_id)
            await workflow.start_child_workflow(
                JobLifecycleWorkflow.run,
                job,
                id=child_id,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
            child_ids.append(child_id)
        await workflow.execute_activity(
            "r096_admit_campaign",
            request,
            result_type=CampaignActivityResult,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=activity_retry_policy(3),
        )
        self._snapshot = CampaignSnapshot(
            schema_version=request.schema_version,
            campaign_id=request.campaign_id,
            child_workflow_ids=tuple(child_ids),
            state="children_started",
        )
        await workflow.wait_condition(lambda: False)
        return self._snapshot

    @workflow.query(name="status")
    def status(self) -> CampaignSnapshot:
        if self._snapshot is None:
            raise RuntimeError("campaign_workflow_not_initialized")
        return self._snapshot


@workflow.defn(name="redagent.r123.campaign-closed-loop.v1")
class ClosedLoopWorkflow:
    """Durable control only; every business transition is owned by PostgreSQL Activities."""

    def __init__(self) -> None:
        self._request: ClosedLoopCampaignWorkflowInput | None = None
        self._snapshot: ClosedLoopCampaignSnapshot | None = None
        self._pending_stop: ClosedLoopStopSignal | None = None
        self._dispatch_handle = None

    @workflow.run
    async def run(self, request: ClosedLoopCampaignWorkflowInput) -> ClosedLoopCampaignSnapshot:
        self._request = request
        request_sha256 = closed_loop_workflow_request_sha256(request)
        self._snapshot = ClosedLoopCampaignSnapshot(
            schema_version=request.schema_version,
            campaign_id=request.campaign_id,
            strategy_revision_id=request.strategy_revision_id,
            workflow_request_sha256=request_sha256,
            state="running",
            revision=1,
            depth=0,
            replan_count=0,
            current_node_id=None,
            terminal_reason=None,
            stop_requested=False,
        )
        for _ in range(12):
            if self._pending_stop is not None:
                return await self._contain(self._pending_stop)
            snapshot = self._required_snapshot()
            result = await workflow.execute_activity(
                "redagent.r123.reconcile-level.v1",
                ClosedLoopReconcileActivityCommand(
                    schema_version=request.schema_version,
                    tenant_id=request.tenant_id,
                    campaign_id=request.campaign_id,
                    strategy_revision_id=request.strategy_revision_id,
                    envelope_sha256=request.envelope_sha256,
                    workflow_request_sha256=request_sha256,
                    revision=snapshot.revision,
                    stop_requested=False,
                ),
                result_type=ClosedLoopReconcileActivityResult,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=closed_loop_activity_retry_policy(request.max_activity_attempts),
            )
            self._validate_reconcile(result, request)
            self._snapshot = ClosedLoopCampaignSnapshot(
                schema_version=request.schema_version,
                campaign_id=request.campaign_id,
                strategy_revision_id=request.strategy_revision_id,
                workflow_request_sha256=request_sha256,
                state=result.outcome,
                revision=result.revision,
                depth=result.depth,
                replan_count=result.replan_count,
                current_node_id=result.node_id,
                terminal_reason=result.reason if result.terminal else None,
                stop_requested=False,
            )
            if result.terminal:
                return self._required_snapshot()
            if result.outcome == "retry_at":
                await workflow.sleep(timedelta(seconds=result.retry_delay_seconds or 1))
                continue
            if result.outcome != "dispatch_once":
                continue
            self._dispatch_handle = workflow.start_activity(
                "redagent.r123.dispatch-effect.v1",
                ClosedLoopDispatchActivityCommand(
                    schema_version=request.schema_version,
                    tenant_id=request.tenant_id,
                    campaign_id=request.campaign_id,
                    strategy_revision_id=request.strategy_revision_id,
                    node_id=result.node_id or "",
                    effect_id=result.effect_id or "",
                    envelope_sha256=request.envelope_sha256,
                    expected_revision=result.revision,
                ),
                result_type=ClosedLoopDispatchActivityResult,
                start_to_close_timeout=timedelta(seconds=90),
                heartbeat_timeout=timedelta(seconds=2),
                cancellation_type=ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=closed_loop_activity_retry_policy(request.max_activity_attempts),
            )
            try:
                dispatch = await self._dispatch_handle
            except (asyncio.CancelledError, ActivityError):
                if self._pending_stop is None:
                    raise
                continue
            finally:
                self._dispatch_handle = None
            if (
                dispatch.campaign_id != request.campaign_id
                or dispatch.effect_id != result.effect_id
                or dispatch.revision <= result.revision
            ):
                raise RuntimeError("r123_dispatch_result_binding_invalid")
            self._snapshot = ClosedLoopCampaignSnapshot(
                schema_version=request.schema_version,
                campaign_id=request.campaign_id,
                strategy_revision_id=request.strategy_revision_id,
                workflow_request_sha256=request_sha256,
                state=dispatch.state,
                revision=dispatch.revision,
                depth=result.depth,
                replan_count=result.replan_count,
                current_node_id=result.node_id,
                terminal_reason=dispatch.failure_code,
                stop_requested=False,
            )
        snapshot = self._required_snapshot()
        self._snapshot = ClosedLoopCampaignSnapshot(
            schema_version=snapshot.schema_version,
            campaign_id=snapshot.campaign_id,
            strategy_revision_id=snapshot.strategy_revision_id,
            workflow_request_sha256=snapshot.workflow_request_sha256,
            state="terminal_failure",
            revision=snapshot.revision,
            depth=snapshot.depth,
            replan_count=snapshot.replan_count,
            current_node_id=snapshot.current_node_id,
            terminal_reason="transition_budget_exhausted",
            stop_requested=snapshot.stop_requested,
        )
        return self._snapshot

    @workflow.query(name="status")
    def status(self) -> ClosedLoopCampaignSnapshot:
        return self._required_snapshot()

    @workflow.signal(name="emergency_stop")
    def emergency_stop(self, request: ClosedLoopStopSignal) -> None:
        if self._pending_stop is not None and self._pending_stop != request:
            raise RuntimeError("r123_stop_signal_conflict")
        self._pending_stop = request
        snapshot = self._required_snapshot()
        self._snapshot = ClosedLoopCampaignSnapshot(
            schema_version=snapshot.schema_version,
            campaign_id=snapshot.campaign_id,
            strategy_revision_id=snapshot.strategy_revision_id,
            workflow_request_sha256=snapshot.workflow_request_sha256,
            state=snapshot.state,
            revision=snapshot.revision,
            depth=snapshot.depth,
            replan_count=snapshot.replan_count,
            current_node_id=snapshot.current_node_id,
            terminal_reason=snapshot.terminal_reason,
            stop_requested=True,
        )
        if self._dispatch_handle is not None:
            self._dispatch_handle.cancel()

    async def _contain(self, signal: ClosedLoopStopSignal) -> ClosedLoopCampaignSnapshot:
        request = self._required_request()
        snapshot = self._required_snapshot()
        result = await workflow.execute_activity(
            "redagent.r123.contain.v1",
            ClosedLoopContainActivityCommand(
                schema_version=request.schema_version,
                tenant_id=request.tenant_id,
                campaign_id=request.campaign_id,
                strategy_revision_id=request.strategy_revision_id,
                signal_id=signal.signal_id,
                actor_user_id=signal.actor_user_id,
                reason_sha256=signal.reason_sha256,
                expected_revision=snapshot.revision,
            ),
            result_type=ClosedLoopContainActivityResult,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=closed_loop_activity_retry_policy(request.max_activity_attempts),
        )
        if result.campaign_id != request.campaign_id or result.revision <= snapshot.revision:
            raise RuntimeError("r123_containment_result_binding_invalid")
        self._snapshot = ClosedLoopCampaignSnapshot(
            schema_version=request.schema_version,
            campaign_id=request.campaign_id,
            strategy_revision_id=request.strategy_revision_id,
            workflow_request_sha256=snapshot.workflow_request_sha256,
            state=result.state,
            revision=result.revision,
            depth=snapshot.depth,
            replan_count=snapshot.replan_count,
            current_node_id=snapshot.current_node_id,
            terminal_reason=result.reason,
            stop_requested=True,
        )
        return self._snapshot

    def _validate_reconcile(
        self,
        result: ClosedLoopReconcileActivityResult,
        request: ClosedLoopCampaignWorkflowInput,
    ) -> None:
        snapshot = self._required_snapshot()
        if (
            result.campaign_id != request.campaign_id
            or result.strategy_revision_id != request.strategy_revision_id
            or result.revision <= snapshot.revision
            or result.depth > request.max_depth
            or result.replan_count > request.max_replan_count
        ):
            raise RuntimeError("r123_reconcile_result_binding_invalid")

    def _required_request(self) -> ClosedLoopCampaignWorkflowInput:
        if self._request is None:
            raise RuntimeError("r123_workflow_not_initialized")
        return self._request

    def _required_snapshot(self) -> ClosedLoopCampaignSnapshot:
        if self._snapshot is None:
            raise RuntimeError("r123_workflow_not_initialized")
        return self._snapshot
