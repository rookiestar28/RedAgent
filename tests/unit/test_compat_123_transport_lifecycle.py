from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time

import pytest

from redagent_platform.nuclei_service.campaign_adapter import (
    NucleiFixedInvocation,
    NucleiRuntimeReceipt,
)
from redagent_platform.nuclei_service.campaign_transport import (
    NucleiDockerTransport,
    nuclei_docker_resources,
)
from redagent_platform.zap_service.campaign_adapter import (
    ZapFixedInvocation,
    ZapRuntimeReceipt,
)
from redagent_platform.zap_service.campaign_transport import (
    ZapDockerTransport,
    zap_docker_resources,
)


class _CancellingZapTransport(ZapDockerTransport):
    def __init__(self, workspace, *, cleanup_fails: bool = False):
        super().__init__(workspace)
        self.started = threading.Event()
        self.cleaned: list[str] = []
        self.cleanup_fails = cleanup_fails

    def _execute(self, invocation, resources, cancelled):
        del invocation
        self.started.set()
        while not cancelled.is_set():
            time.sleep(0.01)
        # Deliberately use an adapter-internal exception outside the transport's
        # previously enumerated types; cancellation must remain the public outcome.
        raise KeyError("synthetic-zap-cancelled")

    def _cleanup(self, resources, invocation_id):
        del resources
        self.cleaned.append(invocation_id)
        if self.cleanup_fails:
            raise RuntimeError("synthetic-zap-cleanup-failed")
        return True


class _CancellingNucleiTransport(NucleiDockerTransport):
    def __init__(self, workspace, *, cleanup_fails: bool = False):
        super().__init__(workspace)
        self.started = threading.Event()
        self.cleaned: list[str] = []
        self.cleanup_fails = cleanup_fails

    def _execute(self, invocation, resources, cancelled):
        del invocation
        self.started.set()
        while not cancelled.is_set():
            time.sleep(0.01)
        raise KeyError("synthetic-nuclei-cancelled")

    def _cleanup(self, resources, invocation_id):
        del resources
        self.cleaned.append(invocation_id)
        if self.cleanup_fails:
            raise RuntimeError("synthetic-nuclei-cleanup-failed")
        return True


@pytest.mark.parametrize(
    ("transport_type", "invocation"),
    (
        (
            _CancellingZapTransport,
            ZapFixedInvocation(
                invocation_id="invocation-zap-cancel",
                effect_id="effect-zap-cancel",
                profile_id="zap-passive-v1",
                allowed_paths=("/passive/missing-header",),
                argv=(
                    "/zap/zap.sh",
                    "-cmd",
                    "-autorun",
                    "/run/redagent/r123-zap-passive.yaml",
                ),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
        (
            _CancellingNucleiTransport,
            NucleiFixedInvocation(
                invocation_id="invocation-nuclei-cancel",
                effect_id="effect-nuclei-cancel",
                profile_id="nuclei-http-header-v1",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="c" * 64,
                argv=("-target", "http://redagent-r105-gateway:8080"),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
    ),
)
def test_transport_cancellation_signals_the_worker_thread_and_cleans_only_its_invocation(
    tmp_path,
    transport_type,
    invocation,
) -> None:
    transport = transport_type(tmp_path)

    async def scenario() -> None:
        task = asyncio.create_task(transport.execute(invocation))
        assert await asyncio.to_thread(transport.started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert transport.cleaned == [invocation.invocation_id]


@pytest.mark.parametrize(
    ("transport_type", "invocation"),
    (
        (
            _CancellingZapTransport,
            ZapFixedInvocation(
                invocation_id="invocation-zap-cancel-cleanup-failure",
                effect_id="effect-zap-cancel-cleanup-failure",
                profile_id="zap-passive-v1",
                allowed_paths=("/passive/missing-header",),
                argv=(
                    "/zap/zap.sh",
                    "-cmd",
                    "-autorun",
                    "/run/redagent/r123-zap-passive.yaml",
                ),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
        (
            _CancellingNucleiTransport,
            NucleiFixedInvocation(
                invocation_id="invocation-nuclei-cancel-cleanup-failure",
                effect_id="effect-nuclei-cancel-cleanup-failure",
                profile_id="nuclei-http-header-v1",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="c" * 64,
                argv=("-target", "http://redagent-r105-gateway:8080"),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
    ),
)
def test_transport_cleanup_failure_does_not_mask_cancellation(
    tmp_path,
    transport_type,
    invocation,
) -> None:
    transport = transport_type(tmp_path, cleanup_fails=True)

    async def scenario() -> None:
        task = asyncio.create_task(transport.execute(invocation))
        assert await asyncio.to_thread(transport.started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert transport.cleaned == [invocation.invocation_id]


@pytest.mark.parametrize(
    ("transport_type", "resource_factory", "invocation"),
    (
        (
            ZapDockerTransport,
            zap_docker_resources,
            ZapFixedInvocation(
                invocation_id="invocation-zap-before-scanner",
                effect_id="effect-zap-before-scanner",
                profile_id="zap-passive-v1",
                allowed_paths=("/passive/missing-header",),
                argv=("/zap/zap.sh", "-cmd", "-autorun", "/run/redagent/r123-zap-passive.yaml"),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
        (
            NucleiDockerTransport,
            nuclei_docker_resources,
            NucleiFixedInvocation(
                invocation_id="invocation-nuclei-before-scanner",
                effect_id="effect-nuclei-before-scanner",
                profile_id="nuclei-http-header-v1",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="c" * 64,
                argv=("-target", "http://redagent-r105-gateway:8080"),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
        ),
    ),
)
def test_transport_persists_not_applied_proof_when_failure_precedes_scanner(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
    invocation,
) -> None:
    transport = transport_type(tmp_path)
    monkeypatch.setattr(
        transport,
        "_validate_locked_inputs",
        lambda invocation, now: {},
    )
    monkeypatch.setattr(transport, "_cleanup", lambda resources, invocation_id: True)

    def fail_before_scanner(*args, **kwargs):
        raise RuntimeError("synthetic-pre-scanner-failure")

    monkeypatch.setattr(transport, "_docker", fail_before_scanner)

    with pytest.raises(RuntimeError, match="synthetic-pre-scanner-failure"):
        transport._execute(
            invocation,
            resource_factory(invocation.invocation_id),
            threading.Event(),
        )

    receipt = transport._lookup(invocation.invocation_id)
    assert receipt is not None
    assert receipt.terminal_state == "not_applied"
    assert receipt.output_complete is True
    assert receipt.external_contact_count == 0
    assert receipt.evidence_ids and receipt.cleanup_receipt_id


@pytest.mark.parametrize(
    ("transport_type", "resource_factory"),
    (
        (ZapDockerTransport, zap_docker_resources),
        (NucleiDockerTransport, nuclei_docker_resources),
    ),
)
def test_cleanup_failure_does_not_mask_the_primary_transport_failure(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
) -> None:
    if transport_type is ZapDockerTransport:
        invocation = ZapFixedInvocation(
            invocation_id="invocation-zap-primary-failure",
            effect_id="effect-zap-primary-failure",
            profile_id="zap-passive-v1",
            allowed_paths=("/passive/missing-header",),
            argv=("/zap/zap.sh", "-cmd", "-autorun", "/run/redagent/r123-zap-passive.yaml"),
            envelope_sha256="a" * 64,
            manifest_v2_sha256="b" * 64,
        )
    else:
        invocation = NucleiFixedInvocation(
            invocation_id="invocation-nuclei-primary-failure",
            effect_id="effect-nuclei-primary-failure",
            profile_id="nuclei-http-header-v1",
            bundle_id="r105-http-header-bundle",
            bundle_revision=2,
            bundle_sha256="c" * 64,
            argv=("-target", "http://redagent-r105-gateway:8080"),
            envelope_sha256="a" * 64,
            manifest_v2_sha256="b" * 64,
        )
    transport = transport_type(tmp_path)
    monkeypatch.setattr(transport, "_validate_locked_inputs", lambda invocation, now: {})
    cleanup_calls = 0

    def cleanup_then_fail(resources, invocation_id):
        nonlocal cleanup_calls
        del resources, invocation_id
        cleanup_calls += 1
        if cleanup_calls == 2:
            raise RuntimeError("synthetic-cleanup-failure")
        return True

    monkeypatch.setattr(transport, "_cleanup", cleanup_then_fail)

    def fail_before_scanner(*args, **kwargs):
        raise RuntimeError("synthetic-primary-failure")

    monkeypatch.setattr(transport, "_docker", fail_before_scanner)

    with pytest.raises(RuntimeError, match="synthetic-primary-failure"):
        transport._execute(
            invocation,
            resource_factory(invocation.invocation_id),
            threading.Event(),
        )

    assert cleanup_calls == 2
    assert transport._lookup(invocation.invocation_id) is None


@pytest.mark.parametrize(
    ("transport_type", "resource_factory", "owner", "error"),
    (
        (
            ZapDockerTransport,
            zap_docker_resources,
            "r123-zap",
            "r123_zap_resource_ownership_mismatch",
        ),
        (
            NucleiDockerTransport,
            nuclei_docker_resources,
            "r123-nuclei",
            "r123_nuclei_resource_ownership_mismatch",
        ),
    ),
)
def test_cleanup_refuses_a_same_name_resource_owned_by_another_invocation(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
    owner,
    error,
) -> None:
    invocation_id = "invocation-current"
    resources = resource_factory(invocation_id)
    transport = transport_type(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_docker(*args: str, check: bool = True):
        del check
        calls.append(args)
        if args == ("inspect", resources.worker):
            payload = [
                {
                    "Config": {
                        "Labels": {
                            "redagent.owner": owner,
                            "redagent.invocation": "invocation-other",
                        }
                    }
                }
            ]
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        return subprocess.CompletedProcess(args, 1, "", "not found")

    monkeypatch.setattr(transport, "_docker", fake_docker)

    with pytest.raises(RuntimeError, match=error):
        transport._cleanup(resources, invocation_id)

    assert not any(call[0] in {"rm", "network"} and "rm" in call for call in calls)


@pytest.mark.parametrize(
    ("transport_type", "resource_factory", "error"),
    (
        (ZapDockerTransport, zap_docker_resources, "r123_zap_cleanup_state_unknown"),
        (NucleiDockerTransport, nuclei_docker_resources, "r123_nuclei_cleanup_state_unknown"),
    ),
)
def test_cleanup_does_not_treat_docker_inspect_failure_as_resource_absence(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
    error,
) -> None:
    invocation_id = "invocation-inspect-unknown"
    resources = resource_factory(invocation_id)
    transport = transport_type(tmp_path)

    def fake_docker(*args: str, check: bool = True):
        del check
        return subprocess.CompletedProcess(
            args,
            1,
            "",
            "error during connect: access is denied",
        )

    monkeypatch.setattr(transport, "_docker", fake_docker)

    with pytest.raises(RuntimeError, match=error):
        transport._cleanup(resources, invocation_id)


@pytest.mark.parametrize(
    ("transport_type", "resource_factory"),
    (
        (ZapDockerTransport, zap_docker_resources),
        (NucleiDockerTransport, nuclei_docker_resources),
    ),
)
def test_cleanup_accepts_docker_29_explicit_network_not_found(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
) -> None:
    invocation_id = "invocation-docker-29-absent"
    resources = resource_factory(invocation_id)
    transport = transport_type(tmp_path)

    def fake_docker(*args: str, check: bool = True):
        del check
        if args[:2] == ("network", "inspect"):
            message = f"Error response from daemon: network {args[2]} not found\n"
        else:
            message = f"error: no such object: {args[-1]}\n"
        return subprocess.CompletedProcess(args, 1, "[]\n", message)

    monkeypatch.setattr(transport, "_docker", fake_docker)

    assert transport._cleanup(resources, invocation_id) is True


@pytest.mark.parametrize(
    ("transport_type", "resource_factory", "owner", "error"),
    (
        (
            ZapDockerTransport,
            zap_docker_resources,
            "r123-zap",
            "r123_zap_cleanup_remove_failed",
        ),
        (
            NucleiDockerTransport,
            nuclei_docker_resources,
            "r123-nuclei",
            "r123_nuclei_cleanup_remove_failed",
        ),
    ),
)
def test_cleanup_fails_closed_when_owned_resource_removal_fails(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
    owner,
    error,
) -> None:
    invocation_id = "invocation-remove-failed"
    resources = resource_factory(invocation_id)
    transport = transport_type(tmp_path)

    def fake_docker(*args: str, check: bool = True):
        del check
        if args == ("inspect", resources.worker):
            payload = [{
                "Config": {
                    "Labels": {
                        "redagent.owner": owner,
                        "redagent.invocation": invocation_id,
                    }
                }
            }]
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        if args == ("rm", "-f", resources.worker):
            return subprocess.CompletedProcess(args, 1, "", "permission denied")
        return subprocess.CompletedProcess(args, 1, "", "Error: No such object")

    monkeypatch.setattr(transport, "_docker", fake_docker)

    with pytest.raises(RuntimeError, match=error):
        transport._cleanup(resources, invocation_id)


@pytest.mark.parametrize(
    ("transport_type", "resource_factory", "invocation", "runtime_relative", "output_name"),
    (
        (
            ZapDockerTransport,
            zap_docker_resources,
            ZapFixedInvocation(
                invocation_id="invocation-zap-restart",
                effect_id="effect-zap-restart",
                profile_id="zap-passive-v1",
                allowed_paths=("/passive/missing-header",),
                argv=(
                    "/zap/zap.sh",
                    "-cmd",
                    "-autorun",
                    "/run/redagent/r123-zap-passive.yaml",
                ),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
            Path(".local/redagent/r123-zap"),
            "zap-report.json",
        ),
        (
            NucleiDockerTransport,
            nuclei_docker_resources,
            NucleiFixedInvocation(
                invocation_id="invocation-nuclei-restart",
                effect_id="effect-nuclei-restart",
                profile_id="nuclei-http-header-v1",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="c" * 64,
                argv=("-target", "http://redagent-r105-gateway:8080"),
                envelope_sha256="a" * 64,
                manifest_v2_sha256="b" * 64,
            ),
            Path(".local/redagent/r123-nuclei"),
            "results.jsonl",
        ),
    ),
)
def test_transport_restart_clears_stale_output_before_creating_docker_resources(
    tmp_path,
    monkeypatch,
    transport_type,
    resource_factory,
    invocation,
    runtime_relative,
    output_name,
) -> None:
    run_key = hashlib.sha256(invocation.invocation_id.encode()).hexdigest()[:24]
    run_root = tmp_path / runtime_relative / run_key
    run_root.mkdir(parents=True)
    output = run_root / output_name
    output.write_bytes(b"stale-output-must-not-be-trusted")
    transport = transport_type(tmp_path)

    monkeypatch.setattr(
        transport,
        "_validate_locked_inputs",
        lambda invocation, *, now: {},
    )
    monkeypatch.setattr(transport, "_cleanup", lambda resources, invocation_id: True)

    def stop_at_first_docker(*args: str, **kwargs: object):
        del args, kwargs
        assert not output.exists() or output.read_bytes() == b""
        raise RuntimeError("synthetic-stop-after-output-reset")

    monkeypatch.setattr(transport, "_docker", stop_at_first_docker)

    with pytest.raises(RuntimeError, match="synthetic-stop-after-output-reset"):
        transport._execute(
            invocation,
            resource_factory(invocation.invocation_id),
            threading.Event(),
        )


@pytest.mark.parametrize(
    ("transport_type", "receipt"),
    (
        (
            ZapDockerTransport,
            ZapRuntimeReceipt(
                invocation_id="invocation:portable",
                effect_id="effect-portable-zap",
                terminal_state="completed",
                automation_plan_complete=True,
                addon_inventory_count=1,
                addon_inventory_sha256="a" * 64,
                output_complete=True,
                active_request_count=0,
                external_contact_count=0,
                evidence_ids=("evidence-portable-zap",),
                cleanup_receipt_id="cleanup-portable-zap",
                external_receipt_id="receipt-portable-zap",
                observed_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
            ),
        ),
        (
            NucleiDockerTransport,
            NucleiRuntimeReceipt(
                invocation_id="invocation:portable",
                effect_id="effect-portable-nuclei",
                terminal_state="completed",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="b" * 64,
                signed_bundle_verified=True,
                output_complete=True,
                result_count=1,
                external_contact_count=0,
                evidence_ids=("evidence-portable-nuclei",),
                cleanup_receipt_id="cleanup-portable-nuclei",
                external_receipt_id="receipt-portable-nuclei",
                observed_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
            ),
        ),
    ),
)
def test_transport_receipt_round_trip_uses_a_cross_platform_atomic_filename(
    tmp_path,
    transport_type,
    receipt,
) -> None:
    transport = transport_type(tmp_path)
    transport._runtime.mkdir(parents=True)

    transport._write_receipt(receipt)

    files = list(transport._runtime.iterdir())
    assert len(files) == 1
    assert files[0].name.startswith("receipt-") and files[0].name.endswith(".json")
    assert ":" not in files[0].name and files[0].stat().st_size > 0
    assert transport._lookup(receipt.invocation_id) == receipt
