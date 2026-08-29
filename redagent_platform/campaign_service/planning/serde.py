"""Strict rehydration for immutable canonical planning payloads."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

from redagent_platform.campaign_service.planning.contracts import PlanningDomainV1
from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathDagRevisionV1,
)


def parse_planning_domain(payload: dict[str, object]) -> PlanningDomainV1:
    return _decode_dataclass(PlanningDomainV1, payload)


def parse_attack_path_dag_revision(
    payload: dict[str, object],
) -> AttackPathDagRevisionV1:
    return _decode_dataclass(AttackPathDagRevisionV1, payload)


def _decode_dataclass(contract: type[Any], payload: object) -> Any:
    if not isinstance(payload, dict) or not is_dataclass(contract):
        raise ValueError("planning_payload_shape_invalid")
    declared = fields(contract)
    names = {field.name for field in declared}
    if set(payload) != names:
        raise ValueError("planning_payload_shape_invalid")
    hints = get_type_hints(contract)
    values = {
        field.name: _decode_value(hints[field.name], payload[field.name])
        for field in declared
    }
    return contract(**values)


def _decode_value(annotation: object, value: object) -> object:
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is tuple:
        if not isinstance(value, list):
            raise ValueError("planning_payload_type_invalid")
        if len(arguments) != 2 or arguments[1] is not Ellipsis:
            raise ValueError("planning_payload_type_invalid")
        return tuple(_decode_value(arguments[0], item) for item in value)
    if origin in {types.UnionType, Union}:
        for candidate in arguments:
            try:
                return _decode_value(candidate, value)
            except (TypeError, ValueError):
                continue
        raise ValueError("planning_payload_type_invalid")
    if annotation is type(None):
        if value is not None:
            raise ValueError("planning_payload_type_invalid")
        return None
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("planning_payload_type_invalid") from exc
    if annotation is datetime:
        if not isinstance(value, str):
            raise ValueError("planning_payload_type_invalid")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("planning_payload_type_invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("planning_payload_type_invalid")
        return parsed
    if isinstance(annotation, type) and is_dataclass(annotation):
        return _decode_dataclass(annotation, value)
    if annotation in {str, int, bool}:
        if type(value) is not annotation:
            raise ValueError("planning_payload_type_invalid")
        return value
    raise ValueError("planning_payload_type_invalid")
