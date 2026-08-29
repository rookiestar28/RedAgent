import json

import pytest

from redagent_platform.campaign_service.planning.contracts import (
    canonical_planning_bytes,
)
from redagent_platform.campaign_service.planning.serde import (
    parse_attack_path_dag_revision,
    parse_planning_domain,
)
from tests.unit.test_campaign_dag_execution import revision
from tests.unit.test_campaign_planning_contracts import domain


def _payload(value: object) -> dict[str, object]:
    payload = json.loads(canonical_planning_bytes(value))
    assert isinstance(payload, dict)
    return payload


def test_canonical_planning_payload_round_trips_to_exact_typed_contracts() -> None:
    expected_domain = domain()
    expected_revision = revision()

    assert parse_planning_domain(_payload(expected_domain)) == expected_domain
    assert parse_attack_path_dag_revision(_payload(expected_revision)) == expected_revision


def test_parser_rejects_unknown_keys_and_scalar_coercion() -> None:
    domain_payload = _payload(domain())
    domain_payload["opaque_action"] = "forbidden"
    with pytest.raises(ValueError, match="planning_payload_shape_invalid"):
        parse_planning_domain(domain_payload)

    revision_payload = _payload(revision())
    revision_payload["node_count"] = "1"
    with pytest.raises(ValueError, match="planning_payload_type_invalid"):
        parse_attack_path_dag_revision(revision_payload)
