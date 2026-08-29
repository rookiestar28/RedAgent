from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.dag_execution_activity_store import (
    PostgresDagExecutionActivityStateOwner,
)
from redagent_platform.campaign_service.service import CampaignEffectCoordinator
from redagent_platform.orchestration.dag_execution_activities import (
    DagExecutionTemporalActivities,
)
from redagent_platform.campaign_service.dag_composition import (
    build_dag_execution_temporal_activities,
    build_stock_campaign_dag_factory,
    build_stock_campaign_dag_relay_factory,
)


class Dependency:
    pass


def test_dag_composition_builds_only_the_execution_lineage_activity_graph() -> None:
    result = build_dag_execution_temporal_activities(
        sessions=Dependency(),
        resolver=Dependency(),
        lifecycle=Dependency(),
        policy=Dependency(),
        dispatcher=Dependency(),
        containment=Dependency(),
        signing_key=Ed25519PrivateKey.generate(),
        signing_key_id="dag-signing-a",
    )

    assert isinstance(result, DagExecutionTemporalActivities)
    assert isinstance(result._state, PostgresDagExecutionActivityStateOwner)
    assert isinstance(result._application._coordinator, CampaignEffectCoordinator)
    assert result._application._coordinator._manifest_issuer._lineage_owner.__class__.__name__ == (
        "PostgresDagManifestLineageOwner"
    )
    assert result._containment.__class__.__name__ == "PostgresDagContainmentOwner"


def test_stock_dag_factories_are_absent_when_disabled_and_fail_closed_when_enabled(
    tmp_path: Path,
) -> None:
    assert build_stock_campaign_dag_factory(tmp_path, {}) is None
    assert build_stock_campaign_dag_relay_factory({}) is None

    with pytest.raises(ValueError, match="r123_signing_configuration_incomplete"):
        build_stock_campaign_dag_factory(
            tmp_path,
            {"REDAGENT_DAG_EXECUTION_MODE": "owned_loopback"},
        )

    key_path = tmp_path / ".local" / "dag-signing.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    base = {
        "REDAGENT_DAG_EXECUTION_MODE": "owned_loopback",
        "REDAGENT_R123_SIGNING_KEY_FILE": str(key_path),
        "REDAGENT_R123_SIGNING_KEY_ID": "dag-local-signing-v1",
        "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
        "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
        "REDAGENT_EVIDENCE_LOCAL_ROOT": str(tmp_path / ".local" / "evidence"),
    }
    with pytest.raises(ValueError, match="redagent_policy_profile_required"):
        build_stock_campaign_dag_factory(tmp_path, base)
    with pytest.raises(ValueError, match="dag_execution_opa_required"):
        build_stock_campaign_dag_factory(tmp_path, {
            **base,
            "REDAGENT_POLICY_PROFILE": "synthetic-local",
            "REDAGENT_POLICY_PROVIDER": "fake",
        })

    token_path = tmp_path / ".local" / "opa.token"
    public_key_path = tmp_path / ".local" / "opa-bundle.pub"
    token_path.write_text("test-token", encoding="utf-8")
    public_key_path.write_text("test-public-key", encoding="utf-8")
    factory = build_stock_campaign_dag_factory(tmp_path, {
        **base,
        "REDAGENT_POLICY_PROFILE": "local-conformance",
        "REDAGENT_POLICY_PROVIDER": "opa",
        "REDAGENT_POLICY_ENDPOINT": "http://127.0.0.1:8181",
        "REDAGENT_POLICY_REQUIRED_REVISION": "dag-policy-v1",
        "REDAGENT_POLICY_TOKEN_FILE": str(token_path),
        "REDAGENT_POLICY_BUNDLE_PUBLIC_KEY_FILE": str(public_key_path),
    })
    assert callable(factory)

    relay_factory = build_stock_campaign_dag_relay_factory({
        "REDAGENT_DAG_EXECUTION_MODE": "owned_loopback",
    })
    assert callable(relay_factory)
    relay = relay_factory(
        Dependency(),
        Dependency(),
        type("Settings", (), {"task_queue": "redagent-dag-v1"})(),
    )
    assert callable(relay.run)
