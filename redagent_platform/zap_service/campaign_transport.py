"""Fixed Docker transport primitives for the compat_123 passive ZAP product adapter."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading

from redagent_platform.zap_service.contracts import (
    CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM,
    CURRENT_R104_TARGET_IMAGE_ID,
    CURRENT_R104_GATEWAY_IMAGE_ID,
    CertifiedProfileId,
    ZAP_ADDON_INVENTORY_COUNT,
    ZAP_ADDON_INVENTORY_SHA256,
)
from redagent_platform.zap_service.normalization import normalize_alerts
from redagent_platform.zap_service.promotion import verify_current_zap_promotion
from redagent_platform.zap_service.campaign_adapter import ZAP_FIXED_ARGV, ZapFixedInvocation, ZapRuntimeReceipt
from redagent_platform.runner_service.campaign_result import NormalizedAdapterFindingV1, parse_normalized_adapter_finding


_IMAGE = "redagent/r104-zap:2.17.0-r104.3"
_OWNER = "redagent.owner=r123-zap"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ZAP_EXECUTION_TIMEOUT_SECONDS = 60
ZAP_GATEWAY_TIMEOUT_SECONDS = 60
ZAP_RESPONSE_BYTES_LIMIT = 1_048_576


@dataclass(frozen=True, slots=True)
class ZapDockerResources:
    worker: str
    target: str
    gateway: str
    worker_network: str
    target_network: str


def zap_docker_resources(invocation_id: str) -> ZapDockerResources:
    if not _ID.fullmatch(invocation_id):
        raise ValueError("r123_zap_invocation_id_invalid")
    suffix = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()[:12]
    return ZapDockerResources(
        worker=f"redagent-r123-zap-worker-{suffix}",
        target=f"redagent-r123-zap-target-{suffix}",
        gateway=f"redagent-r123-zap-gateway-{suffix}",
        worker_network=f"redagent-r123-zap-worker-net-{suffix}",
        target_network=f"redagent-r123-zap-target-net-{suffix}",
    )


def build_zap_worker_command(
    workspace: Path,
    *,
    invocation: ZapFixedInvocation,
    network: str,
    runtime: Path,
) -> tuple[str, ...]:
    """Return the only executable ZAP command admitted by the compat_123 product path."""
    root = workspace.resolve()
    plan = _contained(root, root / "config/r123-zap-passive.yaml")
    runtime_path = _contained(root, runtime)
    resources = zap_docker_resources(invocation.invocation_id)
    if (
        invocation.profile_id != "zap-passive-v1"
        or invocation.allowed_paths != ("/passive/missing-header",)
        or network != resources.worker_network
        or invocation.argv != ZAP_FIXED_ARGV
    ):
        raise ValueError("r123_zap_transport_binding_invalid")
    # CRITICAL: launch the signed immutable ID; a mutable tag may drift after preflight.
    return (
        "docker",
        "run",
        "--name",
        resources.worker,
        "--label",
        "redagent.owner=r123-zap",
        "--label",
        f"redagent.invocation={invocation.invocation_id}",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        # CRITICAL: keep the worker PID ceiling within the signed capability's 128-process limit.
        # Raising this command alone lets runtime resources exceed approved manifest authority.
        "--pids-limit",
        "128",
        "--memory",
        "2048m",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--tmpfs",
        "/home/zap:rw,nosuid,nodev,size=768m,uid=1000,gid=1000,mode=0700",
        "--mount",
        f"type=bind,source={plan},target=/run/redagent/r123-zap-passive.yaml,readonly",
        "--mount",
        f"type=bind,source={runtime_path},target=/work",
        "--entrypoint",
        invocation.argv[0],
        CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
        *invocation.argv[1:],
    )


def _contained(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError("r123_zap_transport_path_forbidden")
    return resolved


class ZapDockerTransport:
    """Exact passive local Docker implementation with durable read-only receipt lookup."""

    def __init__(self, workspace: Path, *, owned_execution: bool = False) -> None:
        if not isinstance(owned_execution, bool):
            raise ValueError("owned_execution_transport_mode_invalid")
        self._request_rate = 1 if owned_execution else 2
        self._workspace = workspace.resolve()
        self._runtime = _contained(self._workspace, self._workspace / ".local/redagent/r123-zap")

    async def execute(self, invocation: ZapFixedInvocation) -> ZapRuntimeReceipt:
        resources = zap_docker_resources(invocation.invocation_id)
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

    async def lookup(self, invocation_id: str) -> ZapRuntimeReceipt | None:
        return await asyncio.to_thread(self._lookup, invocation_id)

    def _execute(
        self,
        invocation: ZapFixedInvocation,
        resources: ZapDockerResources,
        cancelled: threading.Event,
    ) -> ZapRuntimeReceipt:
        started_at = datetime.now(timezone.utc).replace(microsecond=0)
        value = self._validate_locked_inputs(invocation, now=started_at)
        existing = self._lookup(invocation.invocation_id)
        if existing is not None:
            if existing.terminal_state != "not_applied":
                return existing
            _receipt_path(self._runtime, invocation.invocation_id).unlink(missing_ok=True)
        _raise_if_cancelled(cancelled, "zap")
        self._cleanup(resources, invocation.invocation_id)
        self._runtime.mkdir(parents=True, exist_ok=True)
        run_root = _contained(
            self._workspace,
            self._runtime / hashlib.sha256(invocation.invocation_id.encode()).hexdigest()[:24],
        )
        run_root.mkdir(parents=True, exist_ok=True)
        report_path = run_root / "zap-report.json"
        # CRITICAL: a crash-retry must never accept output from an earlier attempt.
        report_path.unlink(missing_ok=True)
        auth = run_root / "r104-auth"
        auth.write_text(hashlib.sha256(invocation.envelope_sha256.encode()).hexdigest(), encoding="utf-8")
        scanner_started = False
        failure_before_scanner = False
        primary_failure = False
        try:
            self._docker(
                "network", "create", "--internal", "--label", _OWNER,
                "--label", f"redagent.invocation={invocation.invocation_id}",
                resources.worker_network,
            )
            _raise_if_cancelled(cancelled, "zap")
            self._docker(
                "network", "create", "--internal", "--label", _OWNER,
                "--label", f"redagent.invocation={invocation.invocation_id}",
                resources.target_network,
            )
            _raise_if_cancelled(cancelled, "zap")
            self._docker(
                *self._service_prefix(
                    resources.target,
                    resources.target_network,
                    invocation.invocation_id,
                ),
                "--network-alias", "redagent-r104-target",
                "--mount", f"type=bind,source={auth.resolve()},target=/run/redagent/r104-auth,readonly",
                CURRENT_R104_TARGET_IMAGE_ID,
            )
            _raise_if_cancelled(cancelled, "zap")
            target_ip = self._container_ip(resources.target, resources.target_network)
            policy = {
                "schema": "redagent.r104-gateway-policy/v1",
                "profile_id": "zap-passive-v1",
                "expected_target_ip": target_ip,
                "allowed_paths": ["/passive/missing-header"],
                "request_limit": 20,
                "request_rate_per_second": self._request_rate,
                "concurrency": 1,
                "timeout_seconds": ZAP_GATEWAY_TIMEOUT_SECONDS,
                "response_bytes_limit": ZAP_RESPONSE_BYTES_LIMIT,
                "max_query_bytes": 0,
                "inject_auth": False,
            }
            policy_path = run_root / "gateway-policy.json"
            policy_path.write_text(
                json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            self._docker(
                *self._service_prefix(
                    resources.gateway,
                    resources.target_network,
                    invocation.invocation_id,
                ),
                "--network-alias", "redagent-r104-gateway",
                "--mount", f"type=bind,source={policy_path.resolve()},target=/run/redagent/gateway-policy.json,readonly",
                "--mount", f"type=bind,source={auth.resolve()},target=/run/redagent/r104-auth,readonly",
                CURRENT_R104_GATEWAY_IMAGE_ID,
            )
            self._docker(
                "network", "connect", "--alias", "redagent-r104-gateway",
                resources.worker_network, resources.gateway,
            )
            _raise_if_cancelled(cancelled, "zap")
            self._assert_topology(resources)
            command = build_zap_worker_command(
                self._workspace,
                invocation=invocation,
                network=resources.worker_network,
                runtime=run_root,
            )
            _raise_if_cancelled(cancelled, "zap")
            scanner_started = True
            self._run(command, timeout=ZAP_EXECUTION_TIMEOUT_SECONDS)
            _raise_if_cancelled(cancelled, "zap")
            if not report_path.is_file() or not 1 <= report_path.stat().st_size <= 1024 * 1024:
                raise RuntimeError("r123_zap_output_incomplete")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            alerts = _report_alerts(report)
            selected = _canonical_zap_alerts(alerts, rule_id="10021")
            normalized = normalize_alerts(selected, profile_id=CertifiedProfileId.PASSIVE)
            if not normalized:
                raise RuntimeError("r123_zap_expected_alert_missing")
            evidence_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            findings = tuple(
                NormalizedAdapterFindingV1(
                    source_record_id=f"zap-{item.fingerprint[:24]}",
                    tool="zap",
                    tool_version="2.17.0",
                    rule_id=item.rule_id,
                    rule_version="r104",
                    database_version="r104",
                    title=item.title,
                    resource_identity=f"owned-loopback:{item.affected_resource}",
                    location=item.affected_resource,
                    severity=item.severity,
                    confidence=item.confidence,
                    taxonomy_ids=(),
                    control_ids=(),
                )
                for item in normalized
            )
            observed_at = datetime.now(timezone.utc).replace(microsecond=0)
            self._verify_promotion(value, now=observed_at)
            receipt = ZapRuntimeReceipt(
                invocation_id=invocation.invocation_id,
                effect_id=invocation.effect_id,
                terminal_state="completed",
                automation_plan_complete=True,
                addon_inventory_count=ZAP_ADDON_INVENTORY_COUNT,
                addon_inventory_sha256=ZAP_ADDON_INVENTORY_SHA256,
                output_complete=True,
                active_request_count=0,
                external_contact_count=0,
                evidence_ids=(f"evidence-r123-zap-{evidence_sha[:24]}",),
                cleanup_receipt_id=f"cleanup-{invocation.invocation_id}",
                external_receipt_id=f"receipt-{invocation.invocation_id}",
                report_safe_payload={
                    "schema": "redagent.r123-result/v1",
                    "adapter_id": "zap-service",
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
                auth.unlink(missing_ok=True)
                if failure_before_scanner and cleanup_complete:
                    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
                    digest = hashlib.sha256(
                        f"{invocation.invocation_id}\0not-applied".encode()
                    ).hexdigest()[:24]
                    self._write_receipt(
                        ZapRuntimeReceipt(
                            invocation_id=invocation.invocation_id,
                            effect_id=invocation.effect_id,
                            terminal_state="not_applied",
                            automation_plan_complete=False,
                            addon_inventory_count=0,
                            addon_inventory_sha256="0" * 64,
                            output_complete=True,
                            active_request_count=0,
                            external_contact_count=0,
                            evidence_ids=(f"evidence-r123-zap-status-{digest}",),
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
            raise RuntimeError("r123_zap_cleanup_incomplete")
        self._write_receipt(receipt)
        return receipt

    def _validate_locked_inputs(
        self,
        invocation: ZapFixedInvocation,
        *,
        now: datetime,
    ) -> dict[str, object]:
        lock_path = self._workspace / "config/r104-zap-runtime-v3.json"
        value = json.loads(lock_path.read_text(encoding="utf-8"))
        if (
            value.get("schema") != "redagent.r104-runtime-lock/v3"
            or value.get("runtime_update_allowed") is not False
            or value.get("external_target_allowed") is not False
            or value.get("zap_addon_inventory_count") != ZAP_ADDON_INVENTORY_COUNT
            or value.get("zap_addon_inventory_sha256") != ZAP_ADDON_INVENTORY_SHA256
        ):
            raise RuntimeError("r123_zap_runtime_lock_invalid")
        # CRITICAL: runtime-lock identity is not current promotion authority.
        self._verify_promotion(value, now=now)
        for image, expected in (
            (_IMAGE, value["engine_image_id"]),
            (value["target_local_tag"], value["target_image_id"]),
            (value["gateway_local_tag"], value["gateway_image_id"]),
        ):
            if self._docker("image", "inspect", image, "--format", "{{.Id}}").stdout.strip() != expected:
                raise RuntimeError("r123_zap_image_identity_mismatch")
        if invocation.argv != ZAP_FIXED_ARGV:
            raise ValueError("r123_zap_command_forbidden")
        return value

    def _verify_promotion(self, lock: dict[str, object], *, now: datetime) -> None:
        attestations = self._workspace / "runtime-assets" / "attestations"
        receipt, _ = verify_current_zap_promotion(
            promotion_bytes=(
                attestations / "261002-R104_ZAP_ARTIFACT_PROMOTION_V3.json"
            ).read_bytes(),
            bundle_bytes=(
                attestations / "261002-R104_ZAP_ARTIFACT_PROMOTION_V3.sigstore.json"
            ).read_bytes(),
            public_key_bytes=(
                attestations / "261002-R104_ZAP_ARTIFACT_PROMOTION_V3.pub"
            ).read_bytes(),
            runtime_lock_bytes=(
                self._workspace / "config/r104-zap-runtime-v3.json"
            ).read_bytes(),
            qualification_bytes=(
                attestations / "261002-R104_ZAP_RUNTIME_QUALIFICATION_V3.json"
            ).read_bytes(),
            now=now,
        )
        if receipt.image_digest != lock["engine_image_id"]:
            raise RuntimeError("r123_zap_promotion_runtime_mismatch")

    def _service_prefix(
        self,
        name: str,
        network: str,
        invocation_id: str,
    ) -> tuple[str, ...]:
        return (
            "run", "-d", "--name", name, "--label", _OWNER,
            "--label", f"redagent.invocation={invocation_id}", "--network", network,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1m",
        )

    def _assert_topology(self, resources: ZapDockerResources) -> None:
        target = self._inspect(resources.target)
        gateway = self._inspect(resources.gateway)
        if set(target["NetworkSettings"]["Networks"]) != {resources.target_network} or set(
            gateway["NetworkSettings"]["Networks"]
        ) != {resources.target_network, resources.worker_network}:
            raise RuntimeError("r123_zap_network_boundary_invalid")

    def _container_ip(self, name: str, network: str) -> str:
        return str(self._inspect(name)["NetworkSettings"]["Networks"][network]["IPAddress"])

    def _inspect(self, name: str) -> dict[str, object]:
        return json.loads(self._docker("inspect", name).stdout)[0]

    def _cleanup(
        self,
        resources: ZapDockerResources,
        invocation_id: str,
    ) -> bool:
        for name in (resources.worker, resources.gateway, resources.target):
            result = self._docker("inspect", name, check=False)
            if result.returncode != 0:
                if _docker_resource_absent(result):
                    continue
                raise RuntimeError("r123_zap_cleanup_state_unknown")
            value = json.loads(result.stdout)[0]
            labels = value.get("Config", {}).get("Labels", {})
            if (
                labels.get("redagent.owner") != "r123-zap"
                or labels.get("redagent.invocation") != invocation_id
            ):
                raise RuntimeError("r123_zap_resource_ownership_mismatch")
            removed = self._docker("rm", "-f", name, check=False)
            if removed.returncode != 0:
                raise RuntimeError("r123_zap_cleanup_remove_failed")
        for name in (resources.worker_network, resources.target_network):
            result = self._docker("network", "inspect", name, check=False)
            if result.returncode != 0:
                if _docker_resource_absent(result):
                    continue
                raise RuntimeError("r123_zap_cleanup_state_unknown")
            value = json.loads(result.stdout)[0]
            labels = value.get("Labels", {})
            if (
                labels.get("redagent.owner") != "r123-zap"
                or labels.get("redagent.invocation") != invocation_id
            ):
                raise RuntimeError("r123_zap_resource_ownership_mismatch")
            removed = self._docker("network", "rm", name, check=False)
            if removed.returncode != 0:
                raise RuntimeError("r123_zap_cleanup_remove_failed")
        for name in (resources.worker, resources.gateway, resources.target):
            result = self._docker("inspect", name, check=False)
            if result.returncode == 0:
                return False
            if not _docker_resource_absent(result):
                raise RuntimeError("r123_zap_cleanup_state_unknown")
        for name in (resources.worker_network, resources.target_network):
            result = self._docker("network", "inspect", name, check=False)
            if result.returncode == 0:
                return False
            if not _docker_resource_absent(result):
                raise RuntimeError("r123_zap_cleanup_state_unknown")
        return True

    def _write_receipt(self, receipt: ZapRuntimeReceipt) -> None:
        self._runtime.mkdir(parents=True, exist_ok=True)
        path = _receipt_path(self._runtime, receipt.invocation_id)
        payload = asdict(receipt)
        if receipt.observed_at is not None:
            payload["observed_at"] = receipt.observed_at.isoformat()
        _atomic_write_text(
            path,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        )

    def _lookup(self, invocation_id: str) -> ZapRuntimeReceipt | None:
        if not _ID.fullmatch(invocation_id):
            raise ValueError("r123_zap_invocation_id_invalid")
        path = _receipt_path(self._runtime, invocation_id)
        if not path.is_file():
            return None
        if not 1 <= path.stat().st_size <= 1_048_576:
            raise ValueError("r123_zap_receipt_size_invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("invocation_id") != invocation_id:
            raise ValueError("r123_zap_receipt_binding_mismatch")
        value["evidence_ids"] = tuple(value["evidence_ids"])
        value["normalized_findings"] = tuple(
            parse_normalized_adapter_finding(item)
            for item in value.get("normalized_findings", ())
        )
        if value.get("observed_at") is not None:
            value["observed_at"] = datetime.fromisoformat(value["observed_at"])
        return ZapRuntimeReceipt(**value)

    def _docker(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run(("docker", *args), check=check)
    def _run(
        self, command: tuple[str, ...], *, check: bool = True, timeout: int = 60
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command, cwd=self._workspace, text=True, encoding="utf-8", errors="replace",
            capture_output=True, check=False, timeout=timeout,
        )
        if check and result.returncode:
            raise RuntimeError(f"r123_zap_docker_failed:{command[1]}:{result.returncode}")
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


def _report_alerts(value: object) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "alerts" and isinstance(item, list):
                alerts.extend(entry for entry in item if isinstance(entry, dict))
            else:
                alerts.extend(_report_alerts(item))
    elif isinstance(value, list):
        for item in value:
            alerts.extend(_report_alerts(item))
    return alerts


def _canonical_zap_alerts(
    alerts: list[dict[str, object]],
    *,
    rule_id: str,
) -> list[dict[str, object]]:
    """Map the two reviewed ZAP JSON shapes into the strict compat_104 normalizer schema."""
    if len(alerts) > 1000:
        raise ValueError("r123_zap_alert_count_exceeded")
    risk = {"0": "informational", "1": "low", "2": "medium", "3": "high"}
    confidence = {"1": "low", "2": "medium", "3": "high", "4": "confirmed"}
    output: list[dict[str, object]] = []
    for alert in alerts:
        api_rule = alert.get("pluginId")
        report_rule = alert.get("pluginid")
        if api_rule is not None and report_rule is not None and api_rule != report_rule:
            raise ValueError("r123_zap_alert_rule_ambiguous")
        observed_rule = api_rule if api_rule is not None else report_rule
        if str(observed_rule) != rule_id:
            continue
        if api_rule is not None:
            output.append({
                name: alert.get(name)
                for name in ("pluginId", "name", "risk", "confidence", "method", "url")
            })
            continue
        instances = alert.get("instances")
        if not isinstance(instances, list) or not 1 <= len(instances) <= 100:
            raise ValueError("r123_zap_alert_instances_invalid")
        mapped_risk = risk.get(str(alert.get("riskcode")))
        mapped_confidence = confidence.get(str(alert.get("confidence")))
        title = alert.get("name")
        if mapped_risk is None or mapped_confidence is None or not isinstance(title, str):
            raise ValueError("r123_zap_alert_summary_invalid")
        for instance in instances:
            if not isinstance(instance, dict):
                raise ValueError("r123_zap_alert_instance_invalid")
            output.append({
                "pluginId": rule_id,
                "name": title,
                "risk": mapped_risk,
                "confidence": mapped_confidence,
                "method": instance.get("method"),
                "url": instance.get("uri"),
            })
    if len(output) > 1000:
        raise ValueError("r123_zap_alert_count_exceeded")
    return output
