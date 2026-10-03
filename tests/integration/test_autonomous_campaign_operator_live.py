"""Opt-in normal browser journey with real confined owners and synthetic authority.

The browser uses ordinary registered campaign handlers. Read-only fixture events
coordinate workers before admission and observe the native second-node frontier.
They do not create, stage, approve, admit, stop or complete a campaign.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import pytest
from sqlalchemy import select
from temporalio.client import Client
import uvicorn

from redagent_platform.api.runtime import build_runtime_app
from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter
from redagent_platform.campaign_service.admission_start_contracts import AutonomousCampaignAdmissionContextV1
from redagent_platform.campaign_service.admission_start_service import AutonomousCampaignAdmissionStartService
from redagent_platform.campaign_service.admission_start_store import PostgresAutonomousCampaignAdmissionStartStore
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import PostgresAutonomousCampaignApplicationRepository, _json_payload, _verified_preview_from_payload
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignApprovalContextV1
from redagent_platform.campaign_service.authority_envelope import CampaignApproverRequirementV2, SignedCampaignAuthorityEnvelopeV2, sign_campaign_authority
from redagent_platform.campaign_service.child_lineage import PostgresChildLineageVerifier
from redagent_platform.campaign_service.child_replan_store import PostgresCanonicalChildReplanStore
from redagent_platform.campaign_service.composition import build_runner_owned_campaign_dispatcher
from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignRootPlanMaterialV1
from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner, _effect_result_owners, project_operator_result
from redagent_platform.campaign_service.operator_evidence import RetainedOperatorBundleV1, native_operator_result_sha256
from redagent_platform.campaign_service.operator_service import AutonomousCampaignOperatorService
from redagent_platform.campaign_service.operations import _read_source
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1, canonical_planning_sha256
from redagent_platform.campaign_service.planner_evidence import (
    REQUIRED_LINEAGE_ARTIFACT_KINDS, CampaignEvidenceTrustAnchorV1, CampaignLineageArtifactInputV1,
    LineageArtifactKind, LineageArtifactState, build_campaign_evidence_bundle, campaign_context_sha256,
    lineage_source_schema_version, write_campaign_evidence_bundle,
)
from redagent_platform.campaign_service.planning.owned_sequential import (
    OWNED_SEQUENTIAL_VALIDATOR_SHA256, OWNED_SEQUENTIAL_VALIDATOR_VERSION,
    derive_owned_sequential_search_limits, plan_owned_sequential_attack_path, validate_owned_sequential_candidate_plan,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.serde import _decode_dataclass
from redagent_platform.campaign_service.planning.validation import VALIDATOR_SHA256, VALIDATOR_VERSION, validate_candidate_plan
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.replanning_contracts import BoundedReplanProposalV1
from redagent_platform.campaign_service.repository import PostgresCampaignCoreAuthorizedOptionOwner
from redagent_platform.campaign_service.runtime import PostgresRunnerIdentityOwner, _verify_current_nuclei, _verify_current_zap
from redagent_platform.campaign_service.service import CampaignCoreService
from redagent_platform.campaign_service.status import PostgresCampaignCorePresentationOwner
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.service import EvidenceService, _stored_from_artifact
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.orchestration.dag_execution_gateway import DagExecutionTemporalStartGateway
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from scripts import opa_conformance
from tests.integration import test_compat_124_campaign_core as native_fixture
from tests.integration.test_autonomous_campaign_operator_journey import NoLegacyStart
from tests.integration.test_bounded_child_live import _execute, _write_history_bytes
from tests.integration.test_migrations import _alembic, _create_database, _drop_database
from tests.integration.test_owned_execution_live import _ObservedDispatcher, _install_runner
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_authority_envelope import lifecycle, trusted_key
from tests.unit.test_campaign_planning_contracts import authority, domain, limits, operator, world
from tests.unit.test_child_replan_subset import owned_planning_material
from tests.unit.test_owned_execution_mode import _full_binding


ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("REDAGENT_OPERATOR_LIVE_TEST") == "owned-operator-v1"


class OwnedOperatorSource:
    """Explicit synthetic test signer; exact current native bindings, never HTTP inputs."""

    def __init__(self, prepared, mode, capabilities):
        self.prepared, self.mode, self.capabilities = prepared, mode, capabilities
        self.key = Ed25519PrivateKey.generate()
        self.trusted_keys = {"operator-owned-key": trusted_key(self.key, key_id="operator-owned-key", approver_id=prepared.command.actor_user_id)}
        self.approval = None
        self.retained = {}
        self.ready = asyncio.Event()
        self.validation_limits = ValidationLimitsV1(2, 1, 32) if mode is AutonomousCampaignMode.BOUNDED_REPLAN else limits()
        self.validator_version = OWNED_SEQUENTIAL_VALIDATOR_VERSION if mode is AutonomousCampaignMode.BOUNDED_REPLAN else VALIDATOR_VERSION
        self.validator_sha256 = OWNED_SEQUENTIAL_VALIDATOR_SHA256 if mode is AutonomousCampaignMode.BOUNDED_REPLAN else VALIDATOR_SHA256

    async def read_root_plan(self, *, application, now):
        p = self.prepared
        assert (application.tenant_id, application.engagement_id, application.target_id) == (p.tenant, p.engagement, p.target)
        envelope = authority(envelope_id="authority-" + application.campaign_id[-40:], tenant_id=p.tenant,
            engagement_id=p.engagement, target_ids=(p.target,), valid_from=now,
            expires_at=now + timedelta(seconds=180), policy_revision="r099-v1",
            bounds=replace(authority().bounds, max_duration_seconds=180),
            required_approvers=(CampaignApproverRequirementV2(p.command.actor_user_id, "campaign-owner"),))
        if self.mode is AutonomousCampaignMode.BOUNDED_REPLAN:
            current_domain, human, initial, _ = owned_planning_material()
            current_domain = replace(current_domain, operators=tuple(replace(op, capability=replace(op.capability,
                execution_manifest_sha256=canonical_capability_sha256(self.capabilities[op.capability.capability_id]))) for op in current_domain.operators))
            envelope = replace(envelope, capability_ids=human.capability_ids, objective_ids=human.objective_ids,
                success_condition_ids=human.success_condition_ids, bounds=human.bounds)
            search = derive_owned_sequential_search_limits(current_domain, envelope)
            planned = plan_owned_sequential_attack_path(current_domain, envelope, initial, search)
            validator = validate_owned_sequential_candidate_plan
        else:
            binding = closed_execution_registry()["zap-controlled-runtime@3"]
            capability = replace(operator().capability, **{name: getattr(binding, name) for name in (
                "capability_id", "capability_revision", "adapter_id", "adapter_version", "profile_id", "profile_revision",
                "profile_sha256", "bundle_id", "bundle_revision", "bundle_sha256")},
                execution_manifest_sha256=canonical_capability_sha256(self.capabilities[binding.capability_id]))
            action = replace(operator(), capability=capability, max_duration_seconds=60, max_requests=20,
                max_rate_per_minute=60, max_evidence_bytes=10 * 1024 * 1024, max_data_bytes=20 * 1024 * 1024)
            current_domain, initial, search = domain(operators=(action,)), world(), search_limits()
            envelope = replace(envelope, capability_ids=(binding.capability_id,), bounds=replace(envelope.bounds,
                max_requests=20, max_rate_per_minute=60, max_concurrency=1, max_width=1,
                max_evidence_bytes=action.max_evidence_bytes, max_data_bytes=action.max_data_bytes))
            planned = plan_attack_path(current_domain, envelope, initial, search)
            validator = validate_candidate_plan
        assert planned.revision is not None
        self.planner_receipt = planned.receipt
        certificate = validator(planned.revision.candidate_plan, current_domain, envelope,
            limits=self.validation_limits, validated_at=now)
        signature = sign_campaign_authority(envelope, self.key, approver_id=p.command.actor_user_id,
            approver_role="campaign-owner", key_id="operator-owned-key", approved_at=now, expires_at=now + timedelta(seconds=170))
        signed = SignedCampaignAuthorityEnvelopeV2(envelope, (signature,))
        current_lifecycle = lifecycle(envelope, observed_at=now, valid_until=now + timedelta(seconds=175))
        self.approval = AutonomousCampaignApprovalContextV1(tenant_id=p.tenant, campaign_id=application.campaign_id,
            signed_authority=signed, authority_lifecycle=current_lifecycle,
            execution_bindings=tuple(sorted((_full_binding(op.capability) for op in current_domain.operators), key=lambda item: item.capability_id)))
        p.campaign = application.campaign_id
        p.context = AutonomousCampaignAdmissionContextV1(tenant_id=p.tenant, campaign_id=p.campaign,
            signed_authority=signed, authority_lifecycle=current_lifecycle,
            domain=current_domain, revision=planned.revision, certificate=certificate)
        p.trusted_keys = self.trusted_keys
        self.ready.set()
        return AutonomousCampaignRootPlanMaterialV1(self.approval, current_domain, initial, search)

    async def read_current_approval_context(self, *, tenant_id, campaign_id):
        return self.approval if self.approval is not None and (tenant_id, campaign_id) == (self.prepared.tenant, self.prepared.campaign) else None

    async def read_current_admission_context(self, *, tenant_id, campaign_id):
        p = self.prepared
        if self.approval is None or (tenant_id, campaign_id) != (p.tenant, p.campaign):
            return None
        async with p.sessions() as session, session.begin():
            await native_fixture._set_tenant(session, p.tenant)
            rows = metadata.tables["campaign_replan_proposals"]
            row = (await session.execute(select(rows).where(rows.c.tenant_id == p.tenant,
                rows.c.campaign_id == p.campaign).order_by(rows.c.created_at.desc()).limit(1))).mappings().one_or_none()
        if row is not None:
            proposal = _decode_dataclass(BoundedReplanProposalV1, row["proposal_payload"])
            p.context = replace(p.context, revision=proposal.child_revision, certificate=proposal.validation_certificate)
        return p.context

    async def read_current_bundle(self, *, tenant_id, campaign_id, execution_run_id, preview_sha256, now):
        return self.retained.get((tenant_id, campaign_id, execution_run_id, preview_sha256))


class ObservedHttpAdmission(AutonomousCampaignAdmissionStartService):
    async def admit_and_queue(self, command):
        result = await super().admit_and_queue(command)
        if result.execution_run_id is not None and not result.replayed:
            self.prepared.command = command
            self.results.put_nowait(result)
        return result


class ObservedOperatorStatus(PostgresAutonomousCampaignOperatorOwner):
    async def read_status(self, **kwargs):
        try:
            status = await super().read_status(**kwargs)
            observation = (status["lifecycle_state"], status["operations"]["authority"]["state"], tuple(status["attention"]))
            if observation != getattr(self, "last_observation", None):
                print(json.dumps({"native_operator_state": observation[0], "admission_authority_state": observation[1],
                    "attention": observation[2]}), flush=True)
                self.last_observation = observation
            return status
        except Exception as error:
            code = str(error)
            print(json.dumps({"native_operator_status_error": type(error).__name__,
                "code": code if re.fullmatch(r"[a-z][a-z0-9_]{0,150}", code) else "opaque_failure"}), flush=True)
            async with self._sessions() as session, session.begin():
                await native_fixture._set_tenant(session, kwargs["tenant_id"])
                snapshot = await _read_source(session, tenant_id=kwargs["tenant_id"], campaign_id=kwargs["campaign_id"])
            directory = ROOT / ".tmp/owned-operator-proofs/status-failures"
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / (kwargs["campaign_id"] + ".json")
            path.write_bytes((json.dumps(_json_payload(snapshot), sort_keys=True, indent=2) + "\n").encode())
            raise


@pytest.mark.skipif(not LIVE, reason="requires explicit exact confined normal operator runtime authority")
@pytest.mark.parametrize("mode", [AutonomousCampaignMode.OWNED_LOOPBACK_AUTO, AutonomousCampaignMode.BOUNDED_REPLAN])
def test_normal_browser_to_actual_owned_runtime_and_retained_results(monkeypatch, mode):
    with opa_conformance.opa_fixture_lease():
        assert opa_conformance._provision()["ok"]
        try:
            asyncio.run(_scenario(monkeypatch, mode))
        finally:
            opa_conformance._scoped_cleanup()


async def _scenario(monkeypatch, mode):
    source_subject = _source_subject()
    settings = load_database_settings(ROOT, env=os.environ)
    name = "owned_operator_" + uuid4().hex
    directory = ROOT / ".local/redagent/test-databases" / name
    directory.mkdir(parents=True, exist_ok=False)
    secret = directory / "database-url"
    secret.write_text(settings.url.set(database=name).render_as_string(hide_password=False), encoding="utf-8")
    previous = os.environ.get("REDAGENT_DATABASE_URL_FILE")
    p, server, server_task, browser = None, None, None, None
    state = {"worker_ready": False, "stop_ready": False, "parent_terminal": False, "child_ready": False, "finished": False, "failed": False}
    try:
        await _create_database(settings.url.set(database="postgres"), name)
        migrated = _alembic(secret, "upgrade", "head")
        assert migrated.returncode == 0, migrated.stderr
        os.environ["REDAGENT_DATABASE_URL_FILE"] = str(secret)
        now = datetime.now(timezone.utc)
        zap_artifact, _ = _verify_current_zap(ROOT, now=now)
        nuclei_artifact, _, _ = _verify_current_nuclei(ROOT, now=now)
        capabilities = {item.capability_id: item for item in (
            build_zap_capability_manifest(platform="linux/amd64", artifact_receipt_id=zap_artifact.receipt_id),
            build_nuclei_capability_manifest(platform="linux/amd64", artifact_receipt_id=nuclei_artifact.receipt_id))}
        suffix = uuid4().hex[:16]
        tenant, actor, engagement, target, roe = (prefix + suffix for prefix in (
            "tenant-operator-", "actor-operator-", "eng-operator-", "target-operator-", "roe-operator-"))
        engine, sessions = native_fixture._database()
        p = SimpleNamespace(engine=engine, sessions=sessions, tenant=tenant, engagement=engagement, target=target,
            command=SimpleNamespace(actor_user_id=actor), campaign=None, context=None)
        monkeypatch.setattr(native_fixture, "NOW", now)
        await native_fixture._bootstrap(sessions, tenant=tenant, actor=actor, engagement=engagement, target=target, roe=roe)
        p.repository = PostgresAutonomousCampaignApplicationRepository(sessions)
        source = OwnedOperatorSource(p, mode, capabilities)
        backend = LocalAppendOnlyBackend(ROOT / ".tmp/owned-operator-evidence" / name, profile="synthetic-local")
        lineage = PostgresChildLineageVerifier(sessions, evidence_backend=backend, context_provider=source,
            trusted_keys=source.trusted_keys, actor_user_id=actor)
        runner_suffixes = {}
        for cap in capabilities.values():
            suffix = uuid4().hex
            runner_suffixes[cap.capability_id] = suffix
            await _install_runner(p, cap, suffix, datetime.now(timezone.utc), class_identity="owned-closed-" + cap.capability_id,
                certificate_fingerprint=hashlib.sha256(("owned-fixture-certificate:" + suffix).encode()).hexdigest())
        dispatcher = _ObservedDispatcher(build_runner_owned_campaign_dispatcher(ROOT, sessions,
            runner_identity_owner=PostgresRunnerIdentityOwner(sessions), evidence_service=EvidenceService(sessions, backend),
            actor_user_id=actor, kms_reference="kms:redagent:synthetic-local", owned_execution=True))
        client = await Client.connect("127.0.0.1:62001")
        results = asyncio.Queue()
        async with httpx.AsyncClient(timeout=5) as http:
            policy = OpaPolicyDecisionProvider(http, endpoint=opa_conformance.opa_endpoint(), token_source=lambda: opa_conformance.APP_TOKEN)
            def operator_factory(configured_sessions):
                application = AutonomousCampaignApplicationService(PostgresAutonomousCampaignApplicationRepository(configured_sessions),
                    mode=mode, approval_context_provider=source, trusted_approval_keys=source.trusted_keys,
                    validation_limits=source.validation_limits, trusted_validator_version=source.validator_version,
                    trusted_validator_sha256=source.validator_sha256, child_lineage_verifier=lineage,
                    canonical_child_store=PostgresCanonicalChildReplanStore(configured_sessions, evidence_backend=backend))
                return AutonomousCampaignOperatorService(CampaignCoreService(PostgresCampaignCoreAuthorizedOptionOwner(configured_sessions),
                    NoLegacyStart(), presentation=PostgresCampaignCorePresentationOwner(configured_sessions)), application,
                    root_plan_source=source, validation_limits=source.validation_limits,
                    native_owner=ObservedOperatorStatus(configured_sessions, bundle_source=source, evidence_backend=backend),
                    stop_gateway=DagExecutionTemporalStartGateway(client, task_queue="owned-operator-unused"))
            def admission_factory(configured_sessions):
                service = ObservedHttpAdmission(source=PostgresAutonomousCampaignApplicationRepository(configured_sessions),
                    context_provider=source, store_factory=lambda command, bundle, context: PostgresAutonomousCampaignAdmissionStartStore(
                        configured_sessions, command=command, bundle=bundle, context=context, child_lineage_verifier=lineage),
                    policy=AdmissionPolicyAdapter(policy, required_revision="r099-v1", trusted_bundle_sha256=authority().policy_bundle_sha256),
                    trusted_keys=source.trusted_keys, validation_limits=source.validation_limits,
                    trusted_validator_version=source.validator_version, trusted_validator_sha256=source.validator_sha256, lease_seconds=300)
                service.prepared, service.results = p, results
                return service
            app = build_runtime_app(ROOT, env={"REDAGENT_DATABASE_URL_FILE": str(secret), "REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": mode.value},
                test_issuer_enabled=True, autonomous_campaign_operator_service_factory=operator_factory,
                autonomous_campaign_admission_start_service_factory=admission_factory)
            headers = {"X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": tenant,
                "X-RedAgent-Test-Permissions": "campaign:read,campaign:create,campaign:approve,campaign:admit,campaign:stop,campaign:revoke",
                "X-RedAgent-Policy-Reference": "policy:synthetic-owned-operator"}
            @app.get("/__test_fixture__")
            async def fixture():
                return {"scope": "synthetic-authority-real-owned-operator", "mode": mode.value, "headers": headers, **state}
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=4311, log_level="warning"))
            server_task = asyncio.create_task(server.serve())
            while not server.started:
                assert not server_task.done(), "owned API failed before readiness"
                await asyncio.sleep(0.05)
            browser = await asyncio.create_subprocess_exec("node", "node_modules/@playwright/test/cli.js", "test",
                "autonomous-campaign-owned.spec.js", "--workers=1", cwd=ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "REDAGENT_E2E_PORT": "4310", "REDAGENT_OPERATOR_LIVE_TEST": "owned-operator-v1"})
            print(json.dumps({"owned_browser_pid": browser.pid}), flush=True)
            browser_output = asyncio.create_task(browser.communicate())
            source_ready = asyncio.create_task(source.ready.wait())
            done, _ = await asyncio.wait((source_ready, browser_output), timeout=45, return_when=asyncio.FIRST_COMPLETED)
            if browser_output in done:
                output, _ = await browser_output
                raise AssertionError(output.decode())
            assert source_ready in done, "normal root preparation unavailable"
            worker_ready = asyncio.Event()
            async def observe_worker():
                await worker_ready.wait()
                state["worker_ready"] = True
            readiness = asyncio.create_task(observe_worker())
            async def normal_stop(admitted):
                state["stop_ready"] = True
                deadline = asyncio.get_running_loop().time() + 30
                while asyncio.get_running_loop().time() < deadline:
                    async with sessions() as session, session.begin():
                        await native_fixture._set_tenant(session, tenant)
                        runs = metadata.tables["campaign_execution_runs"]
                        row = (await session.execute(select(runs.c.stop_requested).where(runs.c.tenant_id == tenant,
                            runs.c.id == admitted.execution_run_id))).one()
                    if row.stop_requested:
                        return
                    await asyncio.sleep(0.1)
                raise AssertionError("browser did not commit a normal native stop")
            admitted, history = await _execute(p, capabilities["zap-controlled-runtime"], backend, lineage, client, policy,
                stop_before_second=mode is AutonomousCampaignMode.BOUNDED_REPLAN,
                runner_suffix=runner_suffixes["zap-controlled-runtime"], dispatcher=dispatcher,
                admit=lambda: asyncio.wait_for(results.get(), 45), worker_ready=worker_ready, request_stop=normal_stop)
            await readiness
            histories = [(admitted, history)]
            if mode is AutonomousCampaignMode.BOUNDED_REPLAN:
                state["parent_terminal"] = True
                state["worker_ready"] = False
                # Child context is supplied only after the ordinary handler commits its canonical proposal.
                deadline = asyncio.get_running_loop().time() + 100
                while asyncio.get_running_loop().time() < deadline:
                    current = await p.repository.read(tenant_id=tenant, campaign_id=p.campaign)
                    if current.lifecycle_state.value == "APPROVED":
                        break
                    if browser_output.done():
                        output, _ = await browser_output
                        raise AssertionError(output.decode())
                    await asyncio.sleep(0.1)
                assert current.lifecycle_state.value == "APPROVED", "normal child approval unavailable"
                await source.read_current_admission_context(tenant_id=tenant, campaign_id=p.campaign)
                child_ready = asyncio.Event()
                async def observe_child_worker():
                    await child_ready.wait()
                    state["child_ready"] = True
                child_readiness = asyncio.create_task(observe_child_worker())
                child, child_history = await _execute(p, capabilities["nuclei-trusted-runtime"], backend, lineage, client, policy,
                    stop_before_second=False, runner_suffix=runner_suffixes["nuclei-trusted-runtime"], dispatcher=dispatcher,
                    admit=lambda: asyncio.wait_for(results.get(), 45), worker_ready=child_ready, previous_run=admitted)
                await child_readiness
                histories.append((child, child_history))
            bundle_proof = await _publish_retained_bundle(p, source, backend, histories[-1][0], name)
            state["finished"] = True
            output, _ = await asyncio.wait_for(browser_output, 40)
            print(output.decode(), flush=True)
            assert browser.returncode == 0, "normal owned browser journey failed"
            proof_dir = ROOT / ".tmp/owned-operator-proofs" / name
            proof_dir.mkdir(parents=True, exist_ok=True)
            history_hashes = [_write_history_bytes(proof_dir / (result.execution_run_id + "-history.json"), history) for result, history in histories]
            async with sessions() as session, session.begin():
                await native_fixture._set_tenant(session, tenant)
                effects = metadata.tables["campaign_effects"]
                rows = [dict(row) for row in (await session.execute(select(effects).where(effects.c.tenant_id == tenant))).mappings()]
            assert len(rows) == len(histories)
            for row in rows:
                receipt = row["effect_receipt_payload"]
                assert row["effect_state"] == "confirmed" and receipt["external_contact_count"] == 0
                assert receipt["output_complete"] and receipt["cleanup_receipt_id"]
            proof = {"schema_version": "redagent.normal-owned-operator-proof/v1", "identity_kind": "explicit-synthetic-test-issuer",
                "source_subject": source_subject,
                "authority_kind": "synthetic-current-campaign-authority", "mode": mode.value, "tenant_id": tenant, "campaign_id": p.campaign,
                "admissions": [_json_payload(result) for result, _ in histories], "history_hashes": history_hashes,
                "effects": rows, "bundle": bundle_proof, "temporal_replay": "PASS", "external_contact_count": 0}
            assert _source_subject() == source_subject, "owned operator source changed during physical verification"
            path = proof_dir / "proof.json"
            path.write_bytes((json.dumps(_json_payload(proof), sort_keys=True, indent=2) + "\n").encode())
            print(json.dumps({"proof": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "normal_http_browser": "PASS", "external_contacts": 0, "dispatches": len(rows), "replay": "PASS"}), flush=True)
    finally:
        if browser is not None and browser.returncode is None:
            # Let Playwright fail through its own teardown while this exact fixture remains reachable.
            state["failed"] = True
            try:
                await asyncio.wait_for(asyncio.shield(browser_output), 8)
            except asyncio.TimeoutError:
                browser.terminate()
                await browser.wait()
        if server is not None:
            server.should_exit = True
        if server_task is not None:
            await server_task
        if p is not None:
            await p.engine.dispose()
        if previous is None:
            os.environ.pop("REDAGENT_DATABASE_URL_FILE", None)
        else:
            os.environ["REDAGENT_DATABASE_URL_FILE"] = previous
        await _drop_database(settings.url.set(database="postgres"), name)
        secret.unlink(missing_ok=True)
        directory.rmdir()
        print("owned operator disposable database/API/secret pointer cleaned", flush=True)


def _source_subject():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, timeout=15)
    paths = sorted(set(path.decode("utf-8") for path in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0") if path))
    files = []
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise AssertionError("owned source inventory boundary invalid")
        files.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None})
    return {"revision": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "status": git("status", "--porcelain=v1", "--untracked-files=all").decode(),
        "files": files, "inventory_sha256": canonical_planning_sha256(files)}


async def _publish_retained_bundle(p, source, backend, admitted, name):
    """Retain actual owner hashes, then configure a separate exact-scope test trust anchor."""
    async with p.sessions() as session, session.begin():
        await native_fixture._set_tenant(session, p.tenant)
        native = await _read_source(session, tenant_id=p.tenant, campaign_id=p.campaign)
        assert native.execution["id"] == admitted.execution_run_id
        previews = metadata.tables["autonomous_campaign_plan_previews"]
        row = (await session.execute(select(previews).where(previews.c.tenant_id == p.tenant,
            previews.c.application_id == p.campaign).order_by(previews.c.created_at.desc()).limit(1))).mappings().one()
        preview = _verified_preview_from_payload(row["preview_payload"], row["preview_sha256"])
        effects = tuple(item for item in native.effects if item["execution_run_id"] == admitted.execution_run_id)
        owners = tuple([await _effect_result_owners(session, p.tenant, item) for item in effects])
        retained_rows = {}
        for table_name in ("campaign_execution_authority_observations", "policy_decisions", "campaign_budget_events",
            "campaign_child_capacity_settlements", "autonomous_campaign_child_replans", "campaign_replan_proposals",
            "autonomous_campaign_plan_approval_receipts", "autonomous_campaign_execution_starts",
            "campaign_execution_runs", "campaign_execution_nodes", "runner_execution_receipts", "evidence_artifacts",
            "finding_import_sessions", "finding_import_records"):
            table = metadata.tables[table_name]
            retained_rows[table_name] = [dict(item) for item in (await session.execute(select(table).where(table.c.tenant_id == p.tenant))).mappings()]
    now = datetime.now(timezone.utc)
    projected = project_operator_result(effects, owners, run_state=native.execution["run_state"], now=now)
    assert projected["cleanup_state"] == "complete" and projected["evidence_state"] == "retained_pending_verification"
    for owned in owners:
        assert backend.verify_exact(_stored_from_artifact(owned["artifact"])).ok
    assert retained_rows["campaign_execution_authority_observations"] and retained_rows["campaign_budget_events"]
    fingerprint = native_operator_result_sha256(execution_run_id=admitted.execution_run_id,
        preview_sha256=preview.preview_sha256, effects=effects, owners=owners)
    receipt = admitted.admission_receipt
    records = {
        LineageArtifactKind.AUTHORIZATION: p.context.signed_authority,
        LineageArtifactKind.AUTHORITY_LIFECYCLE: p.context.authority_lifecycle,
        LineageArtifactKind.PLANNING_DOMAIN: p.context.domain,
        LineageArtifactKind.TRUSTED_CONTEXT: retained_rows["campaign_execution_authority_observations"],
        LineageArtifactKind.PLAN_REVISION: p.context.revision,
        LineageArtifactKind.PLANNER_RECEIPT: retained_rows["campaign_replan_proposals"] or source.planner_receipt,
        LineageArtifactKind.VALIDATION_CERTIFICATE: p.context.certificate,
        LineageArtifactKind.SUBSET_PROOF: {"admission_subset_proof_sha256": receipt.subset_proof_sha256},
        LineageArtifactKind.ADMISSION_POLICY: {field: getattr(receipt, field) for field in (
            "policy_decision_id", "policy_input_sha256", "policy_bundle_revision", "policy_bundle_sha256")},
        LineageArtifactKind.ADMISSION_RECEIPT: receipt,
        LineageArtifactKind.BUDGET_RESERVATION: {"ledger": native.ledger, "reservations": native.reservations},
        LineageArtifactKind.NODE_INTENT: {"nodes": native.nodes, "effects": effects},
        LineageArtifactKind.EFFECT_POLICY_DECISION: {"effects": effects, "decisions": retained_rows["policy_decisions"]},
        LineageArtifactKind.CREDENTIAL_LEASE: {"credential_class": "none", "execution_run_id": admitted.execution_run_id},
        LineageArtifactKind.RUNNER_RESULT: [owned["receipt"] for owned in owners],
        LineageArtifactKind.EVIDENCE: fingerprint,
        LineageArtifactKind.TRUSTED_OBSERVATION: native.observations,
        LineageArtifactKind.REPLAN: retained_rows["autonomous_campaign_child_replans"],
        LineageArtifactKind.CLEANUP: [owned["receipt"] for owned in owners],
        LineageArtifactKind.CONTAINMENT: [item for item in retained_rows["campaign_execution_runs"] if item["run_state"] == "contained"],
        LineageArtifactKind.BUDGET_RECONCILIATION: {"events": retained_rows["campaign_budget_events"],
            "settlements": retained_rows["campaign_child_capacity_settlements"], "reservations": native.reservations},
    }
    artifacts, previous = [], None
    for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS:
        data = records[kind]
        digest = fingerprint if kind is LineageArtifactKind.EVIDENCE else canonical_planning_sha256(
            {"kind": kind.value, "native_source": _json_payload({"value": data})})
        absent = kind is LineageArtifactKind.CREDENTIAL_LEASE or (kind in {
            LineageArtifactKind.TRUSTED_OBSERVATION, LineageArtifactKind.REPLAN, LineageArtifactKind.CONTAINMENT} and not data)
        artifacts.append(CampaignLineageArtifactInputV1(kind=kind, source_schema_version=lineage_source_schema_version(kind),
            source_record_sha256=digest, source_parent_sha256s=() if previous is None else (previous,),
            record_index=0, record_count=1, state=LineageArtifactState.NOT_APPLICABLE if absent else LineageArtifactState.COMPLETE))
        previous = digest
    bundle = build_campaign_evidence_bundle(tenant_id=p.tenant, campaign_id=p.campaign,
        signed_authority_sha256=preview.signed_authority_sha256, artifacts=tuple(artifacts))
    directory = ROOT / ".tmp/owned-operator-evidence" / name / "retained-bundle"
    write_campaign_evidence_bundle(bundle, directory)
    anchor = CampaignEvidenceTrustAnchorV1(expected_manifest_sha256=bundle.manifest_sha256,
        expected_signed_authority_sha256=preview.signed_authority_sha256,
        expected_tenant_sha256=campaign_context_sha256(p.tenant), expected_campaign_sha256=campaign_context_sha256(p.campaign))
    reference = RetainedOperatorBundleV1(directory, anchor, fingerprint, min(owned["artifact"]["retain_until"] for owned in owners))
    # Independent configuration lives outside the retained bundle and is never inferred by a status read.
    proof_dir = ROOT / ".tmp/owned-operator-proofs" / name
    proof_dir.mkdir(parents=True, exist_ok=True)
    custody = {"reference": {"directory": directory.relative_to(ROOT).as_posix(), "trust_anchor": _json_payload(anchor),
        "native_result_sha256": fingerprint, "retain_until": reference.retain_until.isoformat()}, "sources": records,
        "native_source": native, "owners": owners, "rows": retained_rows, "preview": preview,
        "signed_authority": p.context.signed_authority, "authority_lifecycle": p.context.authority_lifecycle}
    path = proof_dir / "native-bundle-custody.json"
    path.write_bytes((json.dumps(_json_payload(custody), sort_keys=True, indent=2) + "\n").encode())
    source.retained[(p.tenant, p.campaign, admitted.execution_run_id, preview.preview_sha256)] = reference
    status = await PostgresAutonomousCampaignOperatorOwner(p.sessions, bundle_source=source, evidence_backend=backend).read_status(
        tenant_id=p.tenant, campaign_id=p.campaign, principal_id=p.command.actor_user_id, now=now)
    assert status["result"]["evidence_state"] == "verified"
    assert status["lifecycle_state"] == "EVIDENCE_PENDING" and status["result"]["export_state"] == "unavailable_export_not_configured"
    print(json.dumps({"retained_native_bundle": "VERIFIED", "manifest_sha256": bundle.manifest_sha256,
        "native_result_sha256": fingerprint, "custody_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}), flush=True)
    return {"manifest_sha256": bundle.manifest_sha256, "native_result_sha256": fingerprint,
        "custody_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
