"""Business-aware authorization differential oracle for R106."""

from __future__ import annotations

from dataclasses import dataclass
import re

from redagent_platform.api_differential_service.contracts import IdentityRelation


_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class DifferentialObservation:
    case_id: str
    operation_id: str
    relation: IdentityRelation
    privileged_status: int
    lower_status: int
    privileged_properties: tuple[str, ...]
    lower_properties: tuple[str, ...]
    expected_lower_outcomes: tuple[str, ...]
    protected_properties: tuple[str, ...]
    resource_lineage_sha256: str


@dataclass(frozen=True, kw_only=True)
class DifferentialDecision:
    violated: bool
    reason: str
    finding_type: str | None
    exposed_properties: tuple[str, ...]


def evaluate_authorization_differential(observation: DifferentialObservation) -> DifferentialDecision:
    if not _SHA.fullmatch(observation.resource_lineage_sha256):
        raise ValueError("api_observation_lineage_invalid")
    if not all(100 <= status <= 599 for status in (observation.privileged_status, observation.lower_status)):
        raise ValueError("api_observation_status_invalid")
    lower_class = str(observation.lower_status)
    protected = set(observation.protected_properties)
    exposed = tuple(sorted(protected.intersection(observation.lower_properties)))
    if lower_class in observation.expected_lower_outcomes:
        return DifferentialDecision(violated=False, reason="authorized_negative", finding_type=None, exposed_properties=())
    if observation.lower_status == 200 and "200_filtered" in observation.expected_lower_outcomes and not exposed:
        return DifferentialDecision(
            violated=False, reason="authorized_filtered_success", finding_type=None, exposed_properties=(),
        )
    if 200 <= observation.lower_status < 300:
        if observation.relation is IdentityRelation.LOWER_ROLE:
            finding_type = "bfla"
        elif observation.relation is IdentityRelation.PROPERTY_RESTRICTED:
            finding_type = "bopla"
        else:
            finding_type = "bola"
        if exposed or not protected:
            return DifferentialDecision(
                violated=True, reason="authorization_predicate_violated",
                finding_type=finding_type, exposed_properties=exposed,
            )
    return DifferentialDecision(
        violated=False, reason="ambiguous_or_unconfirmed", finding_type=None, exposed_properties=exposed,
    )
