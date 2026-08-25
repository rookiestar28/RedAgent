from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import shutil

import httpx

from redagent_platform.policy_service.contracts import PolicyBoundary, PolicyDecisionInput
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from scripts import opa_conformance


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / ".local" / "redagent" / "opa"
SERVER_BUNDLE = RUNTIME / "server" / "redagent.tar.gz"
TOKEN = "redagent-r099-app"  # pragma: allowlist secret


def test_live_tamper_outage_rollback_restart_and_decision_log_mask() -> None:
    # IMPORTANT: this mutates the one workspace-local bundle; do not let a parallel
    # live OPA check observe a deliberate tamper or outage as an unrelated failure.
    with opa_conformance.opa_fixture_lease():
        try:
            asyncio.run(_scenario())
        finally:
            # IMPORTANT: this scenario mutates the one local fixture; do not
            # leave it running or carrying an altered bundle into another test.
            opa_conformance._scoped_cleanup()


async def _scenario() -> None:
    rollback_build = opa_conformance._build_rollback_fixture()
    assert rollback_build["ok"] is True
    # IMPORTANT: the enclosing test owns the fixture lease, so use the lease-held
    # helper instead of re-entering the public provisioning boundary.
    provisioned = opa_conformance._provision()
    assert provisioned["ok"] is True
    endpoint = opa_conformance.opa_endpoint()
    rollback = RUNTIME / "redagent-r099-v0.tar.gz"
    assert SERVER_BUNDLE.is_file() and rollback.is_file()
    original = SERVER_BUNDLE.read_bytes()
    bundle_server_stopped = False
    try:
        await _wait_revision(endpoint, "r099-v1")

        tampered = bytearray(original)
        tampered[len(tampered) // 2] ^= 0x01
        SERVER_BUNDLE.write_bytes(tampered)
        await _wait_revision(endpoint, "r099-v1", require_error=True)
        await _assert_decision(endpoint, "r099-v1")

        SERVER_BUNDLE.write_bytes(original)
        await _wait_revision(endpoint, "r099-v1", require_error=False)

        _compose("stop", "bundle-server")
        bundle_server_stopped = True
        await _wait_revision(endpoint, "r099-v1", require_error=True)
        await _assert_decision(endpoint, "r099-v1")
        _compose("start", "bundle-server")
        bundle_server_stopped = False
        await _wait_revision(endpoint, "r099-v1", require_error=False)

        shutil.copyfile(rollback, SERVER_BUNDLE)
        await _wait_revision(endpoint, "r099-v0", require_error=False)
        await _assert_decision(endpoint, "r099-v0")

        SERVER_BUNDLE.write_bytes(original)
        await _wait_revision(endpoint, "r099-v1", require_error=False)
        _compose("restart", "opa")
        await _wait_revision(endpoint, "r099-v1", require_error=False)
        await _assert_decision(endpoint, "r099-v1")

        logs = _compose("logs", "--no-color", "--since", "5m", "opa").stdout
        assert '"msg":"Decision Log"' in logs
        assert '"/input/roles"' in logs and '"/input/permissions"' in logs
        assert "job:create" not in logs and "operator-r099-log" not in logs
    finally:
        SERVER_BUNDLE.write_bytes(original)
        try:
            if bundle_server_stopped:
                _compose("start", "bundle-server")
            await _wait_revision(endpoint, "r099-v1", require_error=False)
        except (AssertionError, opa_conformance.ConformanceError):
            reprovisioned = opa_conformance._provision()
            assert reprovisioned["ok"] is True
            await _wait_revision(endpoint, "r099-v1", require_error=False)


async def _wait_revision(
    endpoint: str,
    revision: str,
    *,
    require_error: bool | None = None,
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + 20
    headers = {"Authorization": f"Bearer {TOKEN}"}
    observed: dict[str, object] = {}
    async with httpx.AsyncClient(timeout=2) as client:
        while asyncio.get_running_loop().time() < deadline:
            try:
                response = await client.get(f"{endpoint}/v1/status", headers=headers)
                payload = response.json()
                observed = payload.get("result", {}).get("bundles", {}).get("redagent", {})
                errored = any(key in observed for key in ("code", "message", "errors", "http_code"))
                if response.status_code == 200 and observed.get("active_revision") == revision:
                    if require_error is None or errored is require_error:
                        return observed
            except (httpx.HTTPError, ValueError, AttributeError):
                pass
            await asyncio.sleep(0.25)
    raise AssertionError(f"opa_revision_timeout:{revision}:{require_error}:{observed}")


async def _assert_decision(endpoint: str, revision: str) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = PolicyDecisionInput(
        boundary=PolicyBoundary.API, action="job.create", tenant_id="tenant-r099-log",
        subject_id="operator-r099-log", roles=("operator-r099-log",),
        permissions=("job:create",), resource_type="job", resource_id="job-r099-log",
        policy_reference="policy:compat_099:1", roe_version_id="roe-r099-log",
        correlation_id=f"lifecycle-{revision}", requested_at=now,
        attributes={"job_status": "pending", "resource_version": 1},
    )
    async with httpx.AsyncClient(timeout=5) as client:
        decision = await OpaPolicyDecisionProvider(
            client, endpoint=endpoint, token_source=lambda: TOKEN,
        ).decide(request, required_revision=revision, now=now)
    assert decision.allowed and decision.bundle_revision == revision


def _compose(*arguments: str):
    return opa_conformance._compose(*arguments)
