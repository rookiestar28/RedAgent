"""Fixed Docker transport primitives for the compat_123 Nuclei product adapter."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

from redagent_platform.nuclei_service.artifact_promotion import (
    verify_current_nuclei_artifact_promotion,
)
from redagent_platform.nuclei_service.contracts import (
    NucleiProfileId,
    NucleiTargetBinding,
    TARGET_NETWORK,
)
from redagent_platform.nuclei_service.normalization import normalize_nuclei_jsonl
from redagent_platform.nuclei_service.promotion import (
    verify_current_nuclei_bundle_promotion,
)
from redagent_platform.nuclei_service.campaign_adapter import (
    NUCLEI_FIXED_ARGV,
    NucleiFixedInvocation,
    NucleiRuntimeReceipt,
)
from redagent_platform.runner_service.campaign_result import NormalizedAdapterFindingV1


_IMAGE = "redagent/r105-nuclei:3.11.1-r105.2"
_OWNER = "redagent.owner=r123-nuclei"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
NUCLEI_EXECUTION_TIMEOUT_SECONDS = 60
NUCLEI_RESPONSE_BYTES_LIMIT = 1_048_576


@dataclass(frozen=True, slots=True)
class NucleiDockerResources:
    worker: str
    target: str
    gateway: str
    worker_network: str
    target_network: str


def nuclei_docker_resources(invocation_id: str) -> NucleiDockerResources:
    if not _ID.fullmatch(invocation_id):
        raise ValueError("r123_nuclei_invocation_id_invalid")
    suffix = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()[:12]
    return NucleiDockerResources(
        worker=f"redagent-r123-nuclei-worker-{suffix}",
        target=f"redagent-r123-nuclei-target-{suffix}",
        gateway=f"redagent-r123-nuclei-gateway-{suffix}",
        worker_network=f"redagent-r123-nuclei-worker-net-{suffix}",
        target_network=f"redagent-r123-nuclei-target-net-{suffix}",
    )


def build_nuclei_worker_command(
    workspace: Path,
    *,
    invocation: NucleiFixedInvocation,
    network: str,
    results_path: Path,
) -> tuple[str, ...]:
    """Return the only executable Nuclei command admitted by the compat_123 product path."""
    root = workspace.resolve()
    template = _contained(
        root, root / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml"
    )
    certificate = _contained(root, root / "config/trust/r105-nuclei-user.crt")
    results = _contained(root, results_path)
    resources = nuclei_docker_resources(invocation.invocation_id)
    if (
        invocation.profile_id != "nuclei-http-header-v1"
        or invocation.argv != NUCLEI_FIXED_ARGV
        or network != resources.worker_network
    ):
        raise ValueError("r123_nuclei_transport_binding_invalid")
    return (
        "docker",
        "run",
        "--name",
        resources.worker,
        "--label",
        "redagent.owner=r123-nuclei",
        "--label",
        f"redagent.invocation={invocation.invocation_id}",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/home/redagent:rw,noexec,nosuid,nodev,size=32m,mode=1777",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--mount",
        f"type=bind,source={template},target=/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml,readonly",
        "--mount",
        f"type=bind,source={certificate},target=/run/redagent/nuclei-user.crt,readonly",
        "--mount",
        f"type=bind,source={results},target=/work/results.jsonl",
        "-e",
        "NUCLEI_USER_CERTIFICATE=/run/redagent/nuclei-user.crt",
        _IMAGE,
        *invocation.argv,
    )


def _contained(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError("r123_nuclei_transport_path_forbidden")
    return resolved


class NucleiDockerTransport:
    """Exact local Docker implementation; no caller-controlled target, template, or flags."""

    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace.resolve()
        self._runtime = _contained(
            self._workspace, self._workspace / ".local/redagent/r123-nuclei"
        )

    async def execute(self, invocation: NucleiFixedInvocation) -> NucleiRuntimeReceipt:
        resources = nuclei_docker_resources(invocation.invocation_id)
        cancelled = threading.Event()
        task = asyncio.create_task(
            asyncio.to_thread(self._execute, invocation, resources, cancelled)
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # CRITICAL: cancelling to_thread alone leaves Docker work alive; remove only this invocation.
            cancelled.set()
            try:
                await asyncio.to_thread(
                    self._cleanup,
                    resources,
                    invocation.invocation_id,
                )
            except BaseException:  # noqa: BLE001
                # CRITICAL: cleanup failure must not replace the caller's cancellation signal.
                pass
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
            except Exception:  # noqa: BLE001
                # IMPORTANT: an adapter failure after cancellation must not mask CancelledError.
                if not task.done():
                    task.add_done_callback(_consume_background_result)
            raise

    async def lookup(self, invocation_id: str) -> NucleiRuntimeReceipt | None:
        return await asyncio.to_thread(self._lookup, invocation_id)

    def _execute(
        self,
        invocation: NucleiFixedInvocation,
        resources: NucleiDockerResources,
        cancelled: threading.Event,
    ) -> NucleiRuntimeReceipt:
        started_at = datetime.now(timezone.utc).replace(microsecond=0)
        lock = self._validate_locked_inputs(invocation, now=started_at)
        existing = self._lookup(invocation.invocation_id)
        if existing is not None:
            if existing.terminal_state != "not_applied":
                return existing
            _receipt_path(self._runtime, invocation.invocation_id).unlink(missing_ok=True)
        _raise_if_cancelled(cancelled, "nuclei")
        self._cleanup(resources, invocation.invocation_id)
        self._runtime.mkdir(parents=True, exist_ok=True)
        run_root = _contained(
            self._workspace,
            self._runtime / hashlib.sha256(invocation.invocation_id.encode()).hexdigest()[:24],
        )
        run_root.mkdir(parents=True, exist_ok=True)
        results = run_root / "results.jsonl"
        # CRITICAL: a crash-retry must never accept or be blocked by stale output.
        results.unlink(missing_ok=True)
        results.touch(exist_ok=False)
        scanner_started = False
        failure_before_scanner = False
        primary_failure = False
        try:
            self._docker(
                "network", "create", "--internal", "--label", _OWNER,
                "--label", f"redagent.invocation={invocation.invocation_id}",
                resources.worker_network,
            )
            _raise_if_cancelled(cancelled, "nuclei")
            self._docker(
                "network", "create", "--internal", "--label", _OWNER,
                "--label", f"redagent.invocation={invocation.invocation_id}",
                resources.target_network,
            )
            _raise_if_cancelled(cancelled, "nuclei")
            self._docker(
                *self._service_prefix(
                    resources.target,
                    resources.target_network,
                    invocation.invocation_id,
                ),
                "--network-alias", "redagent-r105-target",
                "redagent/r105-target:1.0.1",
            )
            _raise_if_cancelled(cancelled, "nuclei")
            target_ip = self._container_ip(resources.target, resources.target_network)
            policy = {
                "schema": "redagent.r105-gateway-policy/v1",
                "expected_target_ip": target_ip,
                "allowed_paths": ["/nuclei/missing-header"],
                "request_limit": 20,
                "request_rate_per_second": 2,
                "concurrency": 1,
                "timeout_seconds": 60,
                "response_bytes_limit": NUCLEI_RESPONSE_BYTES_LIMIT,
            }
            policy_path = run_root / "gateway-policy.json"
            policy_path.write_text(
                json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            gateway = [
                *self._service_prefix(
                    resources.gateway,
                    resources.target_network,
                    invocation.invocation_id,
                ),
                "--network-alias",
                "redagent-r105-gateway",
                "--mount",
                f"type=bind,source={policy_path.resolve()},target=/run/redagent/gateway-policy.json,readonly",
                "redagent/r105-gateway:1.0.1",
            ]
            self._docker(*gateway)
            self._docker(
                "network", "connect", "--alias", "redagent-r105-gateway",
                resources.worker_network, resources.gateway,
            )
            _raise_if_cancelled(cancelled, "nuclei")
            self._assert_topology(resources)
            command = build_nuclei_worker_command(
                self._workspace,
                invocation=invocation,
                network=resources.worker_network,
                results_path=results,
            )
            _raise_if_cancelled(cancelled, "nuclei")
            scanner_started = True
            self._run(command, timeout=NUCLEI_EXECUTION_TIMEOUT_SECONDS)
            _raise_if_cancelled(cancelled, "nuclei")
            observed_at = datetime.now(timezone.utc).replace(microsecond=0)
            bundle = self._verify_promotions(lock, now=observed_at)
            target = self._trusted_target(
                observed_at, target_ip, resources.target_network
            )
            normalized = normalize_nuclei_jsonl(results.read_bytes(), bundle=bundle, target=target)
            if len(normalized) != 1 or normalized[0].affected_resource != "/nuclei/missing-header":
                raise RuntimeError("r123_nuclei_expected_finding_mismatch")
            evidence_sha = hashlib.sha256(results.read_bytes()).hexdigest()
            findings = tuple(
                NormalizedAdapterFindingV1(
                    source_record_id=f"nuclei-{item.fingerprint[:24]}",
                    tool="nuclei",
                    tool_version="3.11.1",
                    rule_id=item.template_id,
                    rule_version="r105",
                    database_version="r105-http-header-bundle:2",
                    title=item.title,
                    resource_identity=f"owned-loopback:{item.affected_resource}",
                    location=item.affected_resource,
                    severity=item.severity,
                    confidence="high",
                    taxonomy_ids=(),
                    control_ids=(),
                )
                for item in normalized
            )
            receipt = NucleiRuntimeReceipt(
                invocation_id=invocation.invocation_id,
                effect_id=invocation.effect_id,
                terminal_state="completed",
                bundle_id=bundle.bundle_id,
                bundle_revision=bundle.revision,
                bundle_sha256=bundle.bundle_sha256,
                signed_bundle_verified=True,
                output_complete=True,
                result_count=len(normalized),
                external_contact_count=0,
                evidence_ids=(f"evidence-r123-nuclei-{evidence_sha[:24]}",),
                cleanup_receipt_id=f"cleanup-{invocation.invocation_id}",
                external_receipt_id=f"receipt-{invocation.invocation_id}",
                report_safe_payload={
                    "schema": "redagent.r123-result/v1",
                    "adapter_id": "nuclei-service",
                    "output_complete": True,
                    "findings": [asdict(item) for item in findings],
                },
                normalized_findings=findings,
                observed_at=observed_at,
            )
        except BaseException:
            primary_failure = True
            failure_before_scanner = not scanner_started
            raise
        finally:
            cleanup_complete = False
            try:
                cleanup_complete = self._cleanup(resources, invocation.invocation_id)
                results.unlink(missing_ok=True)
                if failure_before_scanner and cleanup_complete:
                    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
                    digest = hashlib.sha256(
                        f"{invocation.invocation_id}\0not-applied".encode()
                    ).hexdigest()[:24]
                    self._write_receipt(
                        NucleiRuntimeReceipt(
                            invocation_id=invocation.invocation_id,
                            effect_id=invocation.effect_id,
                            terminal_state="not_applied",
                            bundle_id=invocation.bundle_id,
                            bundle_revision=invocation.bundle_revision,
                            bundle_sha256=invocation.bundle_sha256,
                            signed_bundle_verified=False,
                            output_complete=True,
                            result_count=0,
                            external_contact_count=0,
                            evidence_ids=(f"evidence-r123-nuclei-status-{digest}",),
                            cleanup_receipt_id=f"cleanup-{invocation.invocation_id}",
                            external_receipt_id=f"status-not-applied-{invocation.invocation_id}",
                            report_safe_payload=None,
                            normalized_findings=(),
                            observed_at=observed_at,
                            coverage_state="unknown",
                        )
                    )
            except BaseException:
                # CRITICAL: cleanup/proof failure must not mask the root transport failure.
                if not primary_failure:
                    raise
        if not cleanup_complete:
            raise RuntimeError("r123_nuclei_cleanup_incomplete")
        self._write_receipt(receipt)
        return receipt

    def _verify_promotions(
        self,
        lock: dict[str, object],
        *,
        now: datetime,
    ):
        attestations = self._workspace / "runtime-assets" / "attestations"
        qualification = (
            attestations / "260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes()
        artifact, _ = verify_current_nuclei_artifact_promotion(
            promotion_bytes=(attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.json").read_bytes(),
            signature_bundle_bytes=(
                attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.sigstore.json"
            ).read_bytes(),
            public_key_bytes=(attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.pub").read_bytes(),
            runtime_lock_bytes=(self._workspace / "config/r105-nuclei-runtime-v2.json").read_bytes(),
            qualification_bytes=qualification,
            now=now,
        )
        bundle = verify_current_nuclei_bundle_promotion(
            manifest_bytes=(self._workspace / "bundles/r105-nuclei/bundle-manifest-v2.json").read_bytes(),
            signature_bundle_bytes=(
                attestations / "260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.sigstore.json"
            ).read_bytes(),
            public_key_bytes=(attestations / "260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.pub").read_bytes(),
            template_bytes=(self._workspace / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
            certificate_bytes=(self._workspace / "config/trust/r105-nuclei-user.crt").read_bytes(),
            qualification_bytes=qualification,
            now=now,
        )
        if artifact.image_digest != lock["engine_image_id"]:
            raise RuntimeError("r123_nuclei_artifact_runtime_mismatch")
        return bundle

    def _trusted_target(
        self,
        now: datetime,
        target_ip: str,
        target_network: str,
    ) -> NucleiTargetBinding:
        return NucleiTargetBinding(
            target_id="r123-owned-loopback-nuclei",
            attestation_sha256=hashlib.sha256(
                f"{target_ip}\0{target_network}\0r123".encode()
            ).hexdigest(),
            endpoint="http://redagent-r105-gateway:8080",
            allowed_paths=("/nuclei/missing-header",),
            # CRITICAL: the per-invocation Docker name is attestation material, not policy identity.
            network_id=TARGET_NETWORK,
            non_production=True,
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        )

    def _validate_locked_inputs(
        self,
        invocation: NucleiFixedInvocation,
        *,
        now: datetime,
    ) -> dict[str, object]:
        value = self._lock()
        # CRITICAL: runtime-lock identity is not current engine/bundle promotion authority.
        self._verify_promotions(value, now=now)
        expected = {
            _IMAGE: value["local_image_id"],
            "redagent/r105-target:1.0.1": value["target_image_id"],
            "redagent/r105-gateway:1.0.1": value["gateway_image_id"],
        }
        for image, image_id in expected.items():
            if self._docker("image", "inspect", image, "--format", "{{.Id}}").stdout.strip() != image_id:
                raise RuntimeError("r123_nuclei_image_identity_mismatch")
        if invocation.argv != NUCLEI_FIXED_ARGV:
            raise ValueError("r123_nuclei_target_forbidden")
        return value

    def _lock(self) -> dict[str, object]:
        value = json.loads((self._workspace / "config/r105-nuclei-runtime-v2.json").read_text(encoding="utf-8"))
        if (
            value.get("schema") != "redagent.r105-runtime-lock/v2"
            or value.get("runtime_update_allowed") is not False
            or value.get("community_templates_allowed") is not False
            or value.get("external_target_allowed") is not False
        ):
            raise RuntimeError("r123_nuclei_runtime_lock_invalid")
        return {**value, "local_image_id": value.get("engine_image_id")}

    def _service_prefix(
        self,
        name: str,
        network: str,
        invocation_id: str,
    ) -> tuple[str, ...]:
        return (
            "run", "-d", "--name", name, "--label", _OWNER,
            "--label", f"redagent.invocation={invocation_id}", "--network", network,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        )

    def _assert_topology(self, resources: NucleiDockerResources) -> None:
        target = self._inspect(resources.target)
        gateway = self._inspect(resources.gateway)
        if set(target["NetworkSettings"]["Networks"]) != {resources.target_network} or set(
            gateway["NetworkSettings"]["Networks"]
        ) != {resources.target_network, resources.worker_network}:
            raise RuntimeError("r123_nuclei_network_boundary_invalid")

    def _container_ip(self, name: str, network: str) -> str:
        return str(self._inspect(name)["NetworkSettings"]["Networks"][network]["IPAddress"])

    def _inspect(self, name: str) -> dict[str, object]:
        return json.loads(self._docker("inspect", name).stdout)[0]

    def _cleanup(
        self,
        resources: NucleiDockerResources,
        invocation_id: str,
    ) -> bool:
        for name in (resources.worker, resources.gateway, resources.target):
            result = self._docker("inspect", name, check=False)
            if result.returncode != 0:
                if _docker_resource_absent(result):
                    continue
                raise RuntimeError("r123_nuclei_cleanup_state_unknown")
            value = json.loads(result.stdout)[0]
            labels = value.get("Config", {}).get("Labels", {})
            if (
                labels.get("redagent.owner") != "r123-nuclei"
                or labels.get("redagent.invocation") != invocation_id
            ):
                raise RuntimeError("r123_nuclei_resource_ownership_mismatch")
            removed = self._docker("rm", "-f", name, check=False)
            if removed.returncode != 0:
                raise RuntimeError("r123_nuclei_cleanup_remove_failed")
        for name in (resources.worker_network, resources.target_network):
            result = self._docker("network", "inspect", name, check=False)
            if result.returncode != 0:
                if _docker_resource_absent(result):
                    continue
                raise RuntimeError("r123_nuclei_cleanup_state_unknown")
            value = json.loads(result.stdout)[0]
            labels = value.get("Labels", {})
            if (
                labels.get("redagent.owner") != "r123-nuclei"
                or labels.get("redagent.invocation") != invocation_id
            ):
                raise RuntimeError("r123_nuclei_resource_ownership_mismatch")
            removed = self._docker("network", "rm", name, check=False)
            if removed.returncode != 0:
                raise RuntimeError("r123_nuclei_cleanup_remove_failed")
        for name in (resources.worker, resources.gateway, resources.target):
            result = self._docker("inspect", name, check=False)
            if result.returncode == 0:
                return False
            if not _docker_resource_absent(result):
                raise RuntimeError("r123_nuclei_cleanup_state_unknown")
        for name in (resources.worker_network, resources.target_network):
            result = self._docker("network", "inspect", name, check=False)
            if result.returncode == 0:
                return False
            if not _docker_resource_absent(result):
                raise RuntimeError("r123_nuclei_cleanup_state_unknown")
        return True

    def _write_receipt(self, receipt: NucleiRuntimeReceipt) -> None:
        self._runtime.mkdir(parents=True, exist_ok=True)
        path = _receipt_path(self._runtime, receipt.invocation_id)
        payload = asdict(receipt)
        if receipt.observed_at is not None:
            payload["observed_at"] = receipt.observed_at.isoformat()
        _atomic_write_text(
            path,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        )

    def _lookup(self, invocation_id: str) -> NucleiRuntimeReceipt | None:
        if not _ID.fullmatch(invocation_id):
            raise ValueError("r123_nuclei_invocation_id_invalid")
        path = _receipt_path(self._runtime, invocation_id)
        if not path.is_file():
            return None
        if not 1 <= path.stat().st_size <= 1_048_576:
            raise ValueError("r123_nuclei_receipt_size_invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("invocation_id") != invocation_id:
            raise ValueError("r123_nuclei_receipt_binding_mismatch")
        value["evidence_ids"] = tuple(value["evidence_ids"])
        value["normalized_findings"] = tuple(
            NormalizedAdapterFindingV1(**item)
            for item in value.get("normalized_findings", ())
        )
        if value.get("observed_at") is not None:
            value["observed_at"] = datetime.fromisoformat(value["observed_at"])
        return NucleiRuntimeReceipt(**value)

    def _docker(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run(("docker", *args), check=check)
    def _run(
        self, command: tuple[str, ...], *, check: bool = True, timeout: int = 60
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=self._workspace,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if check and result.returncode:
            raise RuntimeError(f"r123_nuclei_docker_failed:{command[1]}:{result.returncode}")
        return result


def _docker_resource_absent(result: subprocess.CompletedProcess[str]) -> bool:
    """CRITICAL: only Docker's explicit not-found responses prove cleanup absence."""
    message = (result.stderr or "").strip().lower()
    return result.returncode != 0 and (
        any(
            marker in message
            for marker in ("no such object", "no such container", "no such network")
        )
        or (
            message.startswith("error response from daemon: network ")
            and message.endswith(" not found")
        )
    )


def _raise_if_cancelled(cancelled: threading.Event, adapter: str) -> None:
    if cancelled.is_set():
        raise RuntimeError(f"r123_{adapter}_cancelled")


def _consume_background_result(task: asyncio.Task[object]) -> None:
    try:
        task.exception()
    except BaseException:  # noqa: BLE001
        pass


def _receipt_path(runtime: Path, invocation_id: str) -> Path:
    digest = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()
    return runtime / f"receipt-{digest}.json"


def _atomic_write_text(path: Path, value: str) -> None:
    # IMPORTANT: receipt lookup is a reconciliation boundary; never expose a partial JSON file.
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
