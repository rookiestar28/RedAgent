from __future__ import annotations

from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.application_repository import _json_payload
from tests.unit.test_owned_completion_observations import _source


def _verify(fresh, stored, sha, now):
    return importlib.import_module("redagent_platform.campaign_service.child_lineage").verify_child_source_provenance(
        fresh_source=fresh, stored_payload=stored, expected_sha256=sha, now=now)


def test_fresh_backend_proof_keeps_immutable_original_source_binding_without_reusing_its_clock():
    original = _source()
    now = original.verified_at + timedelta(seconds=65)
    fresh = _source(verified_at=now)
    _verify(fresh, _json_payload(original), original.provenance_sha256, now)
    assert fresh.verified_at == now
    assert fresh.provenance_sha256 != original.provenance_sha256


@pytest.mark.parametrize("drift", [False, True])
def test_settlement_time_projection_uses_the_exact_persistence_codec(drift):
    source = _source()
    times = {"latest_effect_completed_at": source.effect_receipt.completed_at,
             "capacity_available_at": source.verified_at + timedelta(seconds=60),
             "settled_at": source.verified_at + timedelta(seconds=61)}
    payload = _json_payload(times)
    assert payload["settled_at"].endswith("Z")
    if drift:
        payload["settled_at"] = _json_payload({"time": times["settled_at"] + timedelta(microseconds=1)})["time"]
    verify = importlib.import_module("redagent_platform.campaign_service.child_lineage").verify_settlement_time_projection
    if drift:
        with pytest.raises(RuntimeError, match="time_projection_mismatch"):
            verify(payload=payload, **times)
    else:
        verify(payload=payload, **times)


@pytest.mark.parametrize("drift", [False, True])
def test_observation_promotion_time_matches_the_same_canonical_source_clock(drift):
    source = _source()
    clock = _json_payload({"at": source.verified_at})["at"]
    verify = importlib.import_module("redagent_platform.campaign_service.child_lineage").verify_observation_promotion_time
    if drift:
        with pytest.raises(RuntimeError, match="promotion_time_projection_mismatch"):
            verify(received_at=source.verified_at, source_verified_at=clock, promoted_at=source.verified_at.isoformat())
    else:
        verify(received_at=source.verified_at, source_verified_at=clock, promoted_at=clock)


@pytest.mark.parametrize("kind", ["digest", "report", "epoch", "stale", "future", "not_fresh"])
def test_child_source_denies_old_or_changed_owner_proof(kind):
    original = _source()
    now = original.verified_at + timedelta(seconds=65)
    fresh = _source(verified_at=now)
    stored, sha = _json_payload(original), original.provenance_sha256
    if kind == "digest":
        sha = "a" * 64
    elif kind == "report":
        fresh = _source(report_sha256="a" * 64, verified_at=now)
    elif kind == "epoch":
        fresh = _source(lifecycle_epoch=fresh.lifecycle_epoch + 1, verified_at=now)
    elif kind == "stale":
        now += timedelta(seconds=121)
        fresh = _source(verified_at=now)
    elif kind == "future":
        stored["verified_at"] = (now + timedelta(seconds=1)).isoformat()
    else:
        fresh = original
    with pytest.raises((ValueError, RuntimeError)):
        _verify(fresh, stored, sha, now)
