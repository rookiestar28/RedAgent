"""Typed Temporal client gateway used by API and integration boundaries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Any

from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.converter import DataConverter
from temporalio.exceptions import WorkflowAlreadyStartedError

from redagent_platform.orchestration.codec import AesGcmPayloadCodec
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.contracts import (
    CampaignSnapshot,
    CampaignWorkflowInput,
    EmergencyStopSignal,
    JobSnapshot,
    JobWorkflowInput,
    OperatorCommand,
    deterministic_campaign_workflow_id,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.workflow import CampaignLifecycleWorkflow, JobLifecycleWorkflow
from redagent_platform.orchestration.state import CommandDecision


class OrchestrationUnavailable(RuntimeError):
    """Stable failure when Temporal cannot accept or serve a lifecycle request."""


COMMAND_REVISION_SYNC_TIMEOUT_SECONDS = 1.0
COMMAND_REVISION_SYNC_POLL_SECONDS = 0.01


@dataclass(frozen=True, slots=True)
class WorkflowReference:
    workflow_id: str
    run_id: str | None
    replayed: bool


def temporal_data_converter(settings: TemporalSettings) -> DataConverter:
    return replace(
        DataConverter.default,
        payload_codec=AesGcmPayloadCodec(key=settings.codec_key, key_id=settings.codec_key_id),
    )


async def connect_temporal(settings: TemporalSettings) -> Client:
    try:
        return await Client.connect(
            settings.target,
            namespace=settings.namespace,
            tls=settings.tls,
            data_converter=temporal_data_converter(settings),
            identity="redagent-r096-control-plane",
        )
    except Exception as exc:
        raise OrchestrationUnavailable("temporal_connection_unavailable") from exc


class TemporalOrchestrationGateway:
    def __init__(self, client: Client, settings: TemporalSettings) -> None:
        self._client = client
        self._settings = settings

    async def health(self) -> bool:
        try:
            return bool(await self._client.service_client.check_health())
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_health_unavailable") from exc

    async def start_job(self, request: JobWorkflowInput) -> WorkflowReference:
        workflow_id = deterministic_job_workflow_id(request.tenant_id, request.job_id)
        try:
            handle = await self._client.start_workflow(
                JobLifecycleWorkflow.run,
                request,
                id=workflow_id,
                task_queue=self._settings.task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
            return WorkflowReference(workflow_id, _started_run_id(handle), False)
        except WorkflowAlreadyStartedError as exc:
            return WorkflowReference(workflow_id, getattr(exc, "run_id", None), True)
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_start_job_failed") from exc

    async def start_campaign(self, request: CampaignWorkflowInput) -> WorkflowReference:
        workflow_id = deterministic_campaign_workflow_id(request.tenant_id, request.campaign_id)
        try:
            handle = await self._client.start_workflow(
                CampaignLifecycleWorkflow.run,
                request,
                id=workflow_id,
                task_queue=self._settings.task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
            return WorkflowReference(workflow_id, _started_run_id(handle), False)
        except WorkflowAlreadyStartedError as exc:
            return WorkflowReference(workflow_id, getattr(exc, "run_id", None), True)
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_start_campaign_failed") from exc

    async def query_job(self, workflow_id: str) -> JobSnapshot:
        try:
            return await self._client.get_workflow_handle(workflow_id).query(
                "status", result_type=JobSnapshot
            )
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_query_job_failed") from exc

    async def query_campaign(self, workflow_id: str) -> CampaignSnapshot:
        try:
            return await self._client.get_workflow_handle(workflow_id).query(
                "status", result_type=CampaignSnapshot
            )
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_query_campaign_failed") from exc

    async def command_job(self, workflow_id: str, command: OperatorCommand) -> Any:
        try:
            handle = self._client.get_workflow_handle(workflow_id)
            await self._await_command_revision(handle, command.expected_revision)
            return await handle.execute_update(
                command.action,
                command,
                id=command.command_id,
                result_type=CommandDecision,
            )
        except OrchestrationUnavailable:
            raise
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_command_job_failed") from exc

    async def _await_command_revision(self, handle: Any, expected_revision: int) -> None:
        # IMPORTANT: the database projection can commit before the workflow reducer catches up.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + COMMAND_REVISION_SYNC_TIMEOUT_SECONDS
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise OrchestrationUnavailable("temporal_command_revision_sync_timeout")
            try:
                snapshot = await asyncio.wait_for(
                    handle.query("status", result_type=JobSnapshot),
                    timeout=remaining,
                )
            except TimeoutError as exc:
                raise OrchestrationUnavailable("temporal_command_revision_sync_timeout") from exc
            if snapshot.revision >= expected_revision:
                return
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise OrchestrationUnavailable("temporal_command_revision_sync_timeout")
            await asyncio.sleep(min(COMMAND_REVISION_SYNC_POLL_SECONDS, remaining))

    async def stop_job(self, workflow_id: str, request: EmergencyStopSignal) -> None:
        try:
            await self._client.get_workflow_handle(workflow_id).signal("emergency_stop", request)
        except Exception as exc:
            raise OrchestrationUnavailable("temporal_stop_job_failed") from exc


def _started_run_id(handle: Any) -> str | None:
    return getattr(handle, "first_execution_run_id", None) or getattr(handle, "run_id", None)
