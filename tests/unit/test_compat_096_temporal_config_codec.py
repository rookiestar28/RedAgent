from __future__ import annotations

import base64
import asyncio
from pathlib import Path

import pytest
from temporalio.api.common.v1 import Payload

from redagent_platform.orchestration.codec import AesGcmPayloadCodec, PayloadCodecError
from redagent_platform.orchestration.config import TemporalConfigError, load_temporal_settings


def _write_key(path: Path, value: bytes = b"k" * 32) -> Path:
    path.write_text(base64.urlsafe_b64encode(value).decode("ascii") + "\n", encoding="ascii")
    return path


def test_local_temporal_settings_are_loopback_bounded_and_key_file_only(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    key = _write_key(root / "temporal-codec-key")
    settings = load_temporal_settings(
        root,
        env={
            "REDAGENT_PROFILE": "local",
            "REDAGENT_TEMPORAL_TARGET": "127.0.0.1:57233",
            "REDAGENT_TEMPORAL_NAMESPACE": "redagent-local",
            "REDAGENT_TEMPORAL_TASK_QUEUE": "redagent-r096-v1",
            "REDAGENT_TEMPORAL_CODEC_KEY_FILE": str(key),
            "REDAGENT_TEMPORAL_CODEC_KEY_ID": "local-r096-v1",
        },
    )

    assert settings.target == "127.0.0.1:57233"
    assert settings.namespace == "redagent-local"
    assert settings.task_queue == "redagent-r096-v1"
    assert settings.codec_key == b"k" * 32
    assert settings.tls is False
    assert "kkkk" not in repr(settings)


@pytest.mark.parametrize(
    ("env", "reason"),
    [
        ({"REDAGENT_TEMPORAL_CODEC_KEY": "inline"}, "inline_temporal_codec_key_forbidden"),
        ({"REDAGENT_PROFILE": "local", "REDAGENT_TEMPORAL_TARGET": "0.0.0.0:57233"}, "local_temporal_target_must_be_loopback"),
        ({"REDAGENT_PROFILE": "production", "REDAGENT_TEMPORAL_TLS": "false"}, "production_temporal_tls_required"),
        ({"REDAGENT_TEMPORAL_TASK_QUEUE": "../../queue"}, "temporal_task_queue_invalid"),
    ],
)
def test_temporal_settings_fail_closed_before_connecting(
    tmp_path: Path, env: dict[str, str], reason: str
) -> None:
    key = _write_key(tmp_path / "key")
    values = {
        "REDAGENT_PROFILE": "local",
        "REDAGENT_TEMPORAL_TARGET": "127.0.0.1:57233",
        "REDAGENT_TEMPORAL_NAMESPACE": "redagent-local",
        "REDAGENT_TEMPORAL_TASK_QUEUE": "redagent-r096-v1",
        "REDAGENT_TEMPORAL_CODEC_KEY_FILE": str(key),
        "REDAGENT_TEMPORAL_CODEC_KEY_ID": "local-r096-v1",
        **env,
    }
    with pytest.raises(TemporalConfigError, match=reason):
        load_temporal_settings(tmp_path, env=values)


def test_payload_codec_encrypts_authenticates_and_round_trips_without_plaintext() -> None:
    asyncio.run(_assert_codec_round_trip())


async def _assert_codec_round_trip() -> None:
    codec = AesGcmPayloadCodec(key=b"a" * 32, key_id="test-r096-v1")
    plaintext = b'\"plaintext-r096-canary\"'
    original = Payload(metadata={"encoding": b"json/plain"}, data=plaintext)

    encoded = await codec.encode([original])

    assert len(encoded) == 1
    assert plaintext not in encoded[0].data
    assert encoded[0].metadata["encoding"] == b"binary/encrypted+aesgcm"
    assert encoded[0].metadata["redagent-key-id"] == b"test-r096-v1"
    decoded = await codec.decode(encoded)
    assert decoded == [original]


def test_payload_codec_rejects_tamper_wrong_key_and_unknown_encoding() -> None:
    asyncio.run(_assert_codec_denials())


async def _assert_codec_denials() -> None:
    codec = AesGcmPayloadCodec(key=b"a" * 32, key_id="test-r096-v1")
    encoded = (await codec.encode([Payload(metadata={"encoding": b"json/plain"}, data=b"canary")]))[0]
    tampered = Payload(metadata=encoded.metadata, data=encoded.data[:-1] + bytes([encoded.data[-1] ^ 1]))

    with pytest.raises(PayloadCodecError, match="temporal_payload_authentication_failed"):
        await codec.decode([tampered])
    with pytest.raises(PayloadCodecError, match="temporal_payload_key_mismatch"):
        await AesGcmPayloadCodec(key=b"b" * 32, key_id="other-r096-v1").decode([encoded])
    with pytest.raises(PayloadCodecError, match="temporal_payload_encoding_unsupported"):
        await codec.decode([Payload(metadata={"encoding": b"json/plain"}, data=b"not encrypted")])
