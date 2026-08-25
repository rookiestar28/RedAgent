from __future__ import annotations

from datetime import datetime, timezone

import pytest

from redagent_platform.cloud_connectors.offline import (
    OfflineArtifactBinding,
    OfflineCheck,
    OfflineCheckKind,
    OfflineInput,
    evaluate_offline,
    offline_input_digest,
)


NOW = datetime(2026, 7, 11, 15, 0, tzinfo=timezone.utc)


def binding(**overrides: object) -> OfflineArtifactBinding:
    values = {
        "engine_id": "redagent-offline-v1",
        "engine_sha256": "1" * 64,
        "policy_pack_id": "r108-baseline-v1",
        "policy_sha256": "2" * 64,
        "database_id": "r108-synthetic-db-v1",
        "database_sha256": "3" * 64,
        "network_allowed": False,
        "subprocess_allowed": False,
        "repository_config_allowed": False,
        "external_modules_allowed": False,
        "max_files": 20,
        "max_bytes": 65_536,
        "max_results": 20,
    }
    values.update(overrides)
    return OfflineArtifactBinding(**values)  # type: ignore[arg-type]


def input_data(**overrides: object) -> OfflineInput:
    files = (
        {
            "path": "k8s/deployment.json",
            "size": 320,
            "resources": [
                {"resource_id": "deployment/payments", "read_only_root_filesystem": False},
                {"resource_id": "deployment/catalog", "read_only_root_filesystem": True},
            ],
        },
    )
    values = {
        "input_id": "fixture-iac-v1",
        "kind": OfflineCheckKind.IAC,
        "input_sha256": offline_input_digest(kind=OfflineCheckKind.IAC, files=files),
        "files": files,
    }
    values.update(overrides)
    return OfflineInput(**values)  # type: ignore[arg-type]


def checks() -> tuple[OfflineCheck, ...]:
    return (
        OfflineCheck(
            check_id="R108-IAC-001",
            kind=OfflineCheckKind.IAC,
            attribute="read_only_root_filesystem",
            expected=True,
            severity="high",
        ),
    )


def test_offline_checker_is_deterministic_bounded_and_per_resource() -> None:
    first = evaluate_offline(binding=binding(), input_data=input_data(), checks=checks(), evaluated_at=NOW)
    second = evaluate_offline(binding=binding(), input_data=input_data(), checks=checks(), evaluated_at=NOW)
    assert first == second
    assert first.input_sha256 == input_data().input_sha256
    assert first.policy_sha256 == "2" * 64 and first.database_sha256 == "3" * 64
    assert [(row.resource_id, row.passed) for row in first.results] == [
        ("deployment/catalog", True),
        ("deployment/payments", False),
    ]
    assert len(first.result_sha256) == 64


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        ({"network_allowed": True}, "offline_sandbox_not_closed"),
        ({"subprocess_allowed": True}, "offline_sandbox_not_closed"),
        ({"repository_config_allowed": True}, "offline_sandbox_not_closed"),
        ({"external_modules_allowed": True}, "offline_sandbox_not_closed"),
    ],
)
def test_offline_binding_denies_network_code_and_repository_control(changed: dict[str, object], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        binding(**changed)


def test_offline_checker_rejects_path_escape_symlink_size_kind_and_digest_drift() -> None:
    with pytest.raises(ValueError, match="offline_path_escape_denied"):
        input_data(files=({"path": "../secret", "size": 1, "resources": []},))
    with pytest.raises(ValueError, match="offline_symlink_denied"):
        input_data(files=({"path": "safe.json", "size": 1, "symlink": True, "resources": []},))
    with pytest.raises(ValueError, match="offline_input_limit_exceeded"):
        evaluate_offline(
            binding=binding(max_bytes=10), input_data=input_data(), checks=checks(), evaluated_at=NOW
        )
    with pytest.raises(ValueError, match="offline_check_kind_mismatch"):
        evaluate_offline(
            binding=binding(),
            input_data=input_data(kind=OfflineCheckKind.IMAGE),
            checks=checks(),
            evaluated_at=NOW,
        )
    with pytest.raises(ValueError, match="offline_input_digest_mismatch"):
        evaluate_offline(
            binding=binding(),
            input_data=input_data(input_sha256="f" * 64),
            checks=checks(),
            evaluated_at=NOW,
        )
