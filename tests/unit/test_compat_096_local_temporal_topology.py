from __future__ import annotations

from pathlib import Path

from redagent_platform.local_stack_config import load_local_stack_config


ROOT = Path(__file__).resolve().parents[2]


def test_temporal_cli_server_image_is_exact_current_digest_and_not_deprecated_auto_setup() -> None:
    config = load_local_stack_config(ROOT, env={})
    temporal = config.image_map["temporal"]

    assert temporal.tag == "1.7.3"
    assert temporal.index_digest == "sha256:906f9765cde508333ef191aab908bc724657b5f736cb5ead13921d9a45b33622"
    assert temporal.platform_digest == "sha256:1683f097876c2af71ba833bd9418910601be12d4a25422f2c4ebec45113e1bc2"
    assert temporal.reference.startswith("docker.io/temporalio/temporal:1.7.3@sha256:")
    assert "auto-setup" not in temporal.reference
    assert config.temporal_port == 57233


def test_compose_temporal_service_is_headless_persistent_non_root_and_loopback_only() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert "temporal:" in compose
    assert "REDAGENT_TEMPORAL_IMAGE" in compose
    assert '"server", "start-dev"' in compose
    assert '"--headless"' in compose
    assert '"--db-filename", "/home/temporal/temporal.db"' in compose
    assert "REDAGENT_BIND_HOST" in compose and "REDAGENT_TEMPORAL_PORT" in compose
    assert "7233" in compose
    assert "user: \"1000:1000\"" in compose
    assert "no-new-privileges:true" in compose
    assert "redagent_temporal_data" in compose
    assert "8233" not in compose
