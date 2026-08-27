from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.activity_coordinator import CampaignActivityCoordinator
from redagent_platform.campaign_service.composition import (
    CampaignWorkerReadinessFactsOwner,
    build_campaign_activity_coordinator,
    build_stock_campaign_api_service_factory,
    build_stock_campaign_coordinator_factory,
    build_stock_campaign_relay_factory,
    build_stock_campaign_activity_coordinator,
    load_campaign_signing_identity,
)
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend


class _Sessions:
    def __call__(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def scalar(self, statement):
        del statement
        return 1


class _Dependency:
    pass


class _TemporalProbe:
    def __init__(self, ready: bool) -> None:
        self.ready = ready
        self.calls = 0

    async def __call__(self) -> bool:
        self.calls += 1
        return self.ready


def test_enabled_r123_composition_builds_one_closed_owner_path() -> None:
    coordinator = build_campaign_activity_coordinator(
        Path(__file__).resolve().parents[2],
        _Sessions(),
        resolver=_Dependency(),
        readiness_facts_owner=_Dependency(),
        envelope_verifier=_Dependency(),
        runner_identity_owner=_Dependency(),
        evidence_service=_Dependency(),
        signing_key=Ed25519PrivateKey.generate(),
        signing_key_id="r123-worker-key",
    )

    assert isinstance(coordinator, CampaignActivityCoordinator)


def test_stock_composition_owns_resolver_envelope_and_runner_identity_reads() -> None:
    coordinator = build_stock_campaign_activity_coordinator(
        Path(__file__).resolve().parents[2],
        _Sessions(),
        readiness_facts_owner=_Dependency(),
        evidence_service=_Dependency(),
        signing_key=Ed25519PrivateKey.generate(),
        signing_key_id="r123-worker-key",
    )

    assert isinstance(coordinator, CampaignActivityCoordinator)


def test_r123_signing_identity_is_repo_local_ed25519_and_all_or_nothing(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / ".local" / "r123-signing.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    loaded, key_id = load_campaign_signing_identity(tmp_path, {
        "REDAGENT_R123_SIGNING_KEY_FILE": str(key_path),
        "REDAGENT_R123_SIGNING_KEY_ID": "r123-local-signing-v1",
    })
    assert loaded.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert key_id == "r123-local-signing-v1"

    with pytest.raises(ValueError, match="r123_signing_configuration_incomplete"):
        load_campaign_signing_identity(tmp_path, {
            "REDAGENT_R123_SIGNING_KEY_FILE": str(key_path),
        })
    with pytest.raises(ValueError, match="r123_signing_key_outside_workspace"):
        load_campaign_signing_identity(tmp_path, {
            "REDAGENT_R123_SIGNING_KEY_FILE": str(tmp_path.parent / "outside.pem"),
            "REDAGENT_R123_SIGNING_KEY_ID": "r123-local-signing-v1",
        })


def test_stock_worker_factory_is_disabled_without_touching_dependencies_and_closed_when_enabled(
    tmp_path: Path,
) -> None:
    assert build_stock_campaign_coordinator_factory(tmp_path, {}) is None

    with pytest.raises(ValueError, match="r123_signing_configuration_incomplete"):
        build_stock_campaign_coordinator_factory(
            tmp_path,
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
        )

    key_path = tmp_path / ".local" / "r123-signing.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    factory = build_stock_campaign_coordinator_factory(tmp_path, {
        "REDAGENT_STRATEGY_LOOP_MODE": "two_capability",
        "REDAGENT_R123_SIGNING_KEY_FILE": str(key_path),
        "REDAGENT_R123_SIGNING_KEY_ID": "r123-local-signing-v1",
        "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
        "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
        "REDAGENT_EVIDENCE_LOCAL_ROOT": str(tmp_path / ".local" / "evidence"),
    })
    assert callable(factory)

    relay_factory = build_stock_campaign_relay_factory({
        "REDAGENT_STRATEGY_LOOP_MODE": "two_capability",
    })
    assert callable(relay_factory)
    relay = relay_factory(
        _Sessions(),
        object(),
        type("Settings", (), {"task_queue": "redagent-r123-v1"})(),
    )
    assert callable(relay.run)


def test_worker_readiness_requires_current_promotions_before_image_identity_probe(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    owner = CampaignWorkerReadinessFactsOwner(
        Path(__file__).resolve().parents[2],
        _Sessions(),
        LocalAppendOnlyBackend(tmp_path / "evidence", profile="synthetic-local"),
        image_probe=lambda adapter: calls.append(adapter) is None,
    )
    current = asyncio.run(owner.read(
        tenant_id="tenant-r123",
        capability_id="zap-controlled-runtime",
        now=datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc),
    ))
    assert current.zap_adapter_ready is True
    assert current.nuclei_adapter_ready is True
    assert calls == ["zap", "nuclei"]

    calls.clear()
    expired = asyncio.run(owner.read(
        tenant_id="tenant-r123",
        capability_id="zap-controlled-runtime",
        now=datetime(2026, 9, 23, 9, 4, tzinfo=timezone.utc),
    ))
    assert expired.zap_adapter_ready is False
    assert expired.nuclei_adapter_ready is False
    assert calls == []


def test_stock_image_probe_reads_only_current_revision_two_lock_keys(monkeypatch) -> None:
    root = Path(__file__).resolve().parents[2]
    expected: dict[str, str] = {}
    for relative in (
        "config/r104-zap-runtime-v2.json",
        "config/r105-nuclei-runtime-v2.json",
    ):
        lock = json.loads((root / relative).read_text(encoding="utf-8"))
        expected.update({
            lock["engine_local_tag"]: lock["engine_image_id"],
            lock["target_local_tag"]: lock["target_image_id"],
            lock["gateway_local_tag"]: lock["gateway_image_id"],
        })
    calls: list[str] = []

    def inspect_image(argv, **kwargs):
        del kwargs
        tag = argv[3]
        calls.append(tag)
        return subprocess.CompletedProcess(argv, 0, expected[tag] + "\n", "")

    monkeypatch.setattr(subprocess, "run", inspect_image)
    owner = CampaignWorkerReadinessFactsOwner(
        root,
        _Sessions(),
        LocalAppendOnlyBackend(root / ".tmp" / "r123-readiness", profile="synthetic-local"),
    )

    assert owner._locked_images_ready("zap") is True
    assert owner._locked_images_ready("nuclei") is True
    assert calls == [
        "redagent/r104-zap:2.17.0-r104.2",
        "redagent/r104-target:1.0.1",
        "redagent/r104-gateway:1.0.1",
        "redagent/r105-nuclei:3.11.1-r105.2",
        "redagent/r105-target:1.0.1",
        "redagent/r105-gateway:1.0.1",
    ]


def test_readiness_tracks_temporal_health_loss_and_recovery(tmp_path: Path) -> None:
    temporal = _TemporalProbe(False)
    owner = CampaignWorkerReadinessFactsOwner(
        Path(__file__).resolve().parents[2],
        _Sessions(),
        LocalAppendOnlyBackend(tmp_path / "evidence", profile="synthetic-local"),
        image_probe=lambda adapter: adapter in {"zap", "nuclei"},
        temporal_probe=temporal,
    )

    unavailable = asyncio.run(owner.read(
        tenant_id="tenant-r123",
        capability_id="zap-controlled-runtime",
        now=datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc),
    ))
    temporal.ready = True
    recovered = asyncio.run(owner.read(
        tenant_id="tenant-r123",
        capability_id="zap-controlled-runtime",
        now=datetime(2026, 8, 24, 9, 31, tzinfo=timezone.utc),
    ))

    assert unavailable.temporal_ready is False
    assert recovered.temporal_ready is True
    assert temporal.calls == 2


def test_stock_api_factory_composes_dynamic_tenant_safe_qualification_services(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / ".local" / "r123-signing.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    factory = build_stock_campaign_api_service_factory(tmp_path, {
        "REDAGENT_STRATEGY_LOOP_MODE": "two_capability",
        "REDAGENT_R123_SIGNING_KEY_FILE": str(key_path),
        "REDAGENT_R123_SIGNING_KEY_ID": "r123-local-signing-v1",
        "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
        "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
        "REDAGENT_EVIDENCE_LOCAL_ROOT": str(tmp_path / ".local" / "evidence"),
    })
    services = factory(_Sessions())
    assert services.qualification_service is not None
    assert services.status_service.mode.value == "two_capability"
    assert services.campaign_status_owner is not None
