"""Closed catalog containing the first RedAgent-owned benign ability only."""

from types import MappingProxyType
from typing import Mapping
import hashlib

from redagent_platform.purple_runtime.contracts import AbilityManifest, AbilityPhase, DetectionExpectation


MARKER_BYTES = b"REDAGENT_R111_SYNTHETIC_FILE_STAGE_MARKER_V1\n"
ADAPTER_SHA256 = hashlib.sha256(b"redagent-owned-marker-adapter/1.0.0").hexdigest()


def certified_abilities() -> Mapping[str, AbilityManifest]:
    ability = AbilityManifest(
        ability_id="r111-file-stage-marker-v1", revision=1, attack_version="enterprise-v18",
        attack_technique_id="T1074.001", adapter_id="redagent-owned-marker-adapter",
        adapter_sha256=ADAPTER_SHA256, content_sha256=hashlib.sha256(MARKER_BYTES).hexdigest(),
        platform="redagent-disposable-filesystem-lab", phases=tuple(AbilityPhase),
        detection=DetectionExpectation(strategy_id="DET-r111-file-create", analytic_id="AN-r111-owned-marker",
            event_schema="redagent.r111-owned-file-event-v1", collector_id="collector-r111-owned"),
        marker_relative_path="r111-file-stage-marker-v1.marker", marker_sha256=hashlib.sha256(MARKER_BYTES).hexdigest(),
        timeout_seconds=5,
    )
    return MappingProxyType({ability.ability_id: ability})
