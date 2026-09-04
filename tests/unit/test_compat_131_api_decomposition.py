from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute

from redagent_platform.api import schemas as api_schemas
from redagent_platform.api.openapi_compatibility import LEGACY_COMPONENT_NAMES
from redagent_platform.api.app import create_app


WORKSPACE = Path(__file__).resolve().parents[2]
EXPECTED_ROUTE_COUNT = 142
EXPECTED_ROUTE_MANIFEST_SHA256 = (
    "c6692dfbe4ec87dff539591740bdf6879b7559173503c9b0c293414a5a554f20"  # pragma: allowlist secret
)
EXPECTED_SCHEMA_EXPORT_COUNT = 337
EXPECTED_SCHEMA_EXPORT_SHA256 = (
    "29feb59872549e4dd93c71c108d35aa353b975f66e7eabf4b7e6ba1035f5a807"  # pragma: allowlist secret
)
EXPECTED_ROUTER_MODULES = {
    "access.py",
    "agent.py",
    "api_differential.py",
    "artifact.py",
    "campaigns.py",
    "cloud.py",
    "containment.py",
    "evidence.py",
    "finding_operations.py",
    "findings.py",
    "foundation.py",
    "human_simulation.py",
    "identity_saas.py",
    "jobs.py",
    "lab.py",
    "network.py",
    "nuclei.py",
    "observability.py",
    "policy.py",
    "purple.py",
    "runners.py",
    "secrets.py",
    "workbench.py",
    "zap.py",
}


def _primitive_closure(call: object) -> dict[str, object]:
    values: dict[str, object] = {}
    closure = getattr(call, "__closure__", None) or ()
    names = getattr(getattr(call, "__code__", None), "co_freevars", ())
    for name, cell in zip(names, closure, strict=True):
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if isinstance(value, str | int | float | bool) or value is None:
            values[name] = value
    return values


def _route_manifest() -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []
    for route in create_app(test_issuer_enabled=True).routes:
        if not isinstance(route, APIRoute):
            continue
        if not (route.path.startswith("/api/") or route.path.startswith("/health/")):
            continue
        dependencies = []
        for dependency in route.dependant.dependencies:
            call = dependency.call
            dependencies.append(
                {
                    "name": getattr(call, "__name__", type(call).__name__),
                    "closure": _primitive_closure(call),
                }
            )
        response_model = route.response_model
        response_model_name = getattr(response_model, "__name__", str(response_model))
        manifest.append(
            {
                "path": route.path,
                "methods": sorted(route.methods or []),
                "operation_id": route.operation_id,
                "name": route.name,
                "status_code": route.status_code,
                # compat_135 changes Python identities while the fail-closed OpenAPI map preserves
                # the public response-model contract. No other compat_131 manifest field is normalized.
                "response_model": LEGACY_COMPONENT_NAMES.get(response_model_name, response_model_name),
                "dependencies": dependencies,
            }
        )
    return manifest


def test_r131_composed_route_manifest_is_behaviorally_frozen() -> None:
    manifest = _route_manifest()
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()

    assert len(manifest) == EXPECTED_ROUTE_COUNT
    assert hashlib.sha256(encoded).hexdigest() == EXPECTED_ROUTE_MANIFEST_SHA256


def test_r131_app_factory_contains_no_inline_route_body() -> None:
    app_path = WORKSPACE / "redagent_platform" / "api" / "app.py"
    module = ast.parse(app_path.read_text(encoding="utf-8"))
    create_app_node = next(
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "create_app"
    )

    inline_routes = []
    for node in create_app_node.body:
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            called = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (
                isinstance(called, ast.Attribute)
                and isinstance(called.value, ast.Name)
                and called.value.id == "app"
                and called.attr in {"get", "post", "put", "patch", "delete", "options", "head"}
            ):
                inline_routes.append(node.name)

    assert inline_routes == []


def test_r131_domain_router_and_schema_packages_own_the_surface() -> None:
    api_root = WORKSPACE / "redagent_platform" / "api"
    router_root = api_root / "routers"
    schema_root = api_root / "schemas"

    assert router_root.is_dir()
    assert EXPECTED_ROUTER_MODULES <= {path.name for path in router_root.glob("*.py")}
    assert schema_root.is_dir()
    assert (schema_root / "__init__.py").is_file()
    assert not (api_root / "schemas.py").exists()

    encoded_exports = json.dumps(
        list(api_schemas.__all__),
        separators=(",", ":"),
    ).encode()
    assert len(api_schemas.__all__) == EXPECTED_SCHEMA_EXPORT_COUNT
    assert hashlib.sha256(encoded_exports).hexdigest() == EXPECTED_SCHEMA_EXPORT_SHA256


def test_r131_router_modules_register_only_when_explicitly_called() -> None:
    router_root = WORKSPACE / "redagent_platform" / "api" / "routers"
    for router_path in router_root.glob("*.py"):
        module = ast.parse(router_path.read_text(encoding="utf-8"))
        top_level_router_construction = [
            node
            for node in module.body
            if isinstance(node, ast.Assign | ast.AnnAssign | ast.Expr)
            and any(
                isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == "APIRouter"
                for item in ast.walk(node)
            )
        ]
        assert top_level_router_construction == [], router_path.name

    assert not (router_root.parent / "_route_support.py").exists()
    owner_modules = (
        "contracts.py",
        "router_primitives.py",
        "static_assets.py",
        "openapi_compatibility.py",
        "workbench_fixtures.py",
    )
    for owner_name in owner_modules:
        owner_module = ast.parse((router_root.parent / owner_name).read_text(encoding="utf-8"))
        owner_functions = {
            node.name for node in owner_module.body if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert not {name for name in owner_functions if name.startswith("_public_")}, owner_name
