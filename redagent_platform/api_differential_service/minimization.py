"""Security-semantics-preserving replay minimization for R106."""

from __future__ import annotations

from dataclasses import dataclass

from redagent_platform.api_differential_service.contracts import IdentityRelation


@dataclass(frozen=True, kw_only=True)
class MinimizedReplay:
    case_id: str
    operation_id: str
    relation: IdentityRelation
    privileged_identity_handle: str
    lower_identity_handle: str
    resource_lineage_sha256: str
    violated_predicate: str
    sequence_steps: tuple[str, ...]
    public_values: tuple[tuple[str, str], ...]
    seed: int


def minimize_replay(
    *,
    case_id: str,
    operation_id: str,
    relation: IdentityRelation,
    privileged_identity_handle: str,
    lower_identity_handle: str,
    resource_lineage_sha256: str,
    violated_predicate: str,
    sequence_steps: tuple[str, ...],
    required_steps: tuple[str, ...],
    public_values: dict[str, str],
    required_value_names: tuple[str, ...],
    seed: int,
) -> MinimizedReplay:
    if not required_steps or any(step not in sequence_steps for step in required_steps):
        raise ValueError("api_replay_required_steps_invalid")
    if any(name not in public_values for name in required_value_names):
        raise ValueError("api_replay_required_values_invalid")
    minimized: list[tuple[str, str]] = []
    for name in sorted(required_value_names):
        value = public_values[name]
        if not isinstance(value, str) or not value:
            raise ValueError("api_replay_public_value_invalid")
        minimized.append((name, value[0]))
    return MinimizedReplay(
        case_id=case_id, operation_id=operation_id, relation=relation,
        privileged_identity_handle=privileged_identity_handle,
        lower_identity_handle=lower_identity_handle,
        resource_lineage_sha256=resource_lineage_sha256,
        violated_predicate=violated_predicate, sequence_steps=required_steps,
        public_values=tuple(minimized), seed=seed,
    )
