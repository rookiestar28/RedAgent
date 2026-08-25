from __future__ import annotations

from dataclasses import replace

from hypothesis import find, settings
import pytest
import schemathesis

from redagent_platform.api_differential_service.compiler import CompiledDifferentialCase
from redagent_platform.api_differential_service.contracts import IdentityRelation, OperationRisk
from redagent_platform.api_differential_service.schemathesis_adapter import (
    generated_public_case,
    load_certified_generator_schema,
    strategy_for_operation,
)
from redagent_platform.api_differential_service.specification import validate_and_snapshot_spec
from tests.unit.test_compat_106_api_differential_contracts import spec


def compiled_case() -> CompiledDifferentialCase:
    return CompiledDifferentialCase(
        case_id="compat_106:getDocument:cross_owner", operation_id="getDocument", method="GET",
        path_template="/documents/{documentId}", risk=OperationRisk.READ,
        relation=IdentityRelation.CROSS_OWNER, privileged_identity_handle="identity-owner",
        lower_identity_handle="identity-peer", gateway_origin="http://redagent-r106-gateway:8080",
        expected_lower_outcomes=("403", "404", "200_filtered"),
    )


def test_exact_engine_loads_only_canonical_in_memory_spec_and_generates_public_values() -> None:
    assert schemathesis.__version__ == "4.22.4"
    snapshot = validate_and_snapshot_spec(spec())
    schema = load_certified_generator_schema(snapshot)
    strategy = strategy_for_operation(schema, compiled_case(), negative=False)
    generated = find(strategy, lambda _: True, settings=settings(max_examples=20, derandomize=True, database=None))
    public = generated_public_case(generated, compiled_case())
    assert public.operation_id == "getDocument" and public.method == "GET"
    assert public.path_parameters and public.body is None
    assert public.headers == () and public.cookies == ()
    assert "Authorization" not in repr(public) and "Bearer" not in repr(public)
    assert public.serialized_size_bytes <= 4096


def test_adapter_rejects_operation_drift_secret_transport_and_oversized_values() -> None:
    snapshot = validate_and_snapshot_spec(spec())
    schema = load_certified_generator_schema(snapshot)
    generated = find(
        strategy_for_operation(schema, compiled_case(), negative=False),
        lambda _: True,
        settings=settings(max_examples=20, derandomize=True, database=None),
    )
    with pytest.raises(ValueError, match="api_generated_operation_mismatch"):
        generated_public_case(generated, replace(compiled_case(), operation_id="getAudit"))
    generated.headers = {"Authorization": "Bearer secret"}
    with pytest.raises(ValueError, match="api_generated_transport_material_forbidden"):
        generated_public_case(generated, compiled_case())
    generated.headers = {}
    generated.path_parameters = {"documentId": "x" * 5000}
    with pytest.raises(ValueError, match="api_generated_case_too_large"):
        generated_public_case(generated, compiled_case())
