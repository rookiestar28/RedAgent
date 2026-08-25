from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.api.app import create_app
from redagent_platform.api_differential_service.compiler import compile_differential_plan
from redagent_platform.api_differential_service.contracts import (
    ApiDifferentialAuthorization,
    ApiDifferentialProfileId,
    IdentityRelation,
    IdentityState,
    OperationRisk,
    certified_profiles,
)
from redagent_platform.api_differential_service.minimization import minimize_replay
from redagent_platform.api_differential_service.oracle import (
    DifferentialObservation,
    evaluate_authorization_differential,
)
from redagent_platform.api_differential_service.specification import validate_and_snapshot_spec


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def test_api_differential_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schemas = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]
    properties = schemas["ApiDifferentialDashboardData"]["properties"]
    assert {"target_options", "runner_options", "job_options"} <= set(properties)
    assert set(schemas["ApiDifferentialTargetOptionData"]["properties"]) == {
        "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
    }
    assert set(schemas["ApiDifferentialRunnerOptionData"]["properties"]) == {
        "runner_id", "environment", "network_plane", "required_policy_revision", "registration_state", "expires_at",
    }
    assert set(schemas["ApiDifferentialJobOptionData"]["properties"]) == {
        "job_id", "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
    }
    assert "policy_revision" in schemas["ApiDifferentialPlanData"]["properties"]


def spec() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "RedAgent R106 Fixture", "version": "1.0.0"},
        "servers": [{"url": "http://redagent-r106-gateway:8080"}],
        "components": {
            "securitySchemes": {"fixtureBearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "Document": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "owner_id", "title"],
                    "properties": {
                        "id": {"type": "string", "maxLength": 64},
                        "owner_id": {"type": "string", "maxLength": 64},
                        "title": {"type": "string", "maxLength": 100},
                    },
                }
            },
        },
        "security": [{"fixtureBearer": []}],
        "paths": {
            "/documents": {
                "post": {
                    "operationId": "createDocument",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "additionalProperties": False, "required": ["title"],
                        "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 100}},
                    }}}},
                    "responses": {"201": {"description": "created"}, "400": {"description": "invalid"}},
                }
            },
            "/documents/{documentId}": {
                "get": {
                    "operationId": "getDocument",
                    "parameters": [{
                        "name": "documentId", "in": "path", "required": True,
                        "schema": {"type": "string", "maxLength": 64},
                    }],
                    "responses": {
                        "200": {"description": "document", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Document"}}}},
                        "403": {"description": "forbidden"},
                        "404": {"description": "not found"},
                    },
                },
                "delete": {
                    "operationId": "deleteDocument",
                    "parameters": [{
                        "name": "documentId", "in": "path", "required": True,
                        "schema": {"type": "string", "maxLength": 64},
                    }],
                    "responses": {"204": {"description": "deleted"}, "403": {"description": "forbidden"}, "404": {"description": "not found"}},
                },
            },
            "/documents/{documentId}/transfer": {
                "post": {
                    "operationId": "transferDocument",
                    "parameters": [{
                        "name": "documentId", "in": "path", "required": True,
                        "schema": {"type": "string", "maxLength": 64},
                    }],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {
                        "type": "object", "additionalProperties": False, "required": ["new_owner_id"],
                        "properties": {"new_owner_id": {"type": "string", "maxLength": 64}},
                    }}}},
                    "responses": {"200": {"description": "transferred"}, "403": {"description": "forbidden"}, "404": {"description": "not found"}},
                }
            },
            "/profiles/{profileId}": {
                "get": {
                    "operationId": "getProfile",
                    "parameters": [{
                        "name": "profileId", "in": "path", "required": True,
                        "schema": {"type": "string", "maxLength": 64},
                    }],
                    "responses": {"200": {"description": "profile"}, "403": {"description": "forbidden"}, "404": {"description": "not found"}},
                }
            },
            "/admin/audit": {
                "get": {
                    "operationId": "getAudit",
                    "responses": {"200": {"description": "audit"}, "403": {"description": "forbidden"}},
                }
            },
        },
    }


def authorization() -> ApiDifferentialAuthorization:
    return ApiDifferentialAuthorization(
        tenant_id="tenant-r106",
        policy_decision_id="decision-r106",
        policy_revision="r099-v1",
        roe_version_id="roe-r106",
        approved_profile_ids=(ApiDifferentialProfileId.STANDARD,),
        approved_spec_sha256="a" * 64,
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )


def test_certified_profile_is_closed_and_bounded() -> None:
    profiles = certified_profiles()
    assert set(profiles) == {ApiDifferentialProfileId.STANDARD}
    profile = profiles[ApiDifferentialProfileId.STANDARD]
    assert profile.engine_version == "4.22.4"
    assert profile.phases == ("examples", "coverage", "fuzzing", "stateful")
    assert profile.unexpected_methods_allowed is False
    assert profile.callback_allowed is False and profile.external_refs_allowed is False
    assert profile.max_requests <= 80 and profile.concurrency == 1


def test_spec_snapshot_accepts_exact_internal_contract_and_rejects_network_expansion() -> None:
    snapshot = validate_and_snapshot_spec(spec())
    assert snapshot.operation_ids == (
        "createDocument", "deleteDocument", "getAudit", "getDocument", "getProfile", "transferDocument",
    )
    assert snapshot.server == "http://redagent-r106-gateway:8080"
    assert len(snapshot.spec_sha256) == 64

    for mutation, reason in (
        (("servers", [{"url": "https://public.example"}]), "api_spec_server_forbidden"),
        (("webhooks", {"event": {}}), "api_spec_callback_forbidden"),
    ):
        changed = deepcopy(spec())
        changed[mutation[0]] = mutation[1]
        with pytest.raises(ValueError, match=reason):
            validate_and_snapshot_spec(changed)

    external = deepcopy(spec())
    external["components"] = {"schemas": {"Document": {"$ref": "https://public.example/schema.json"}}}
    with pytest.raises(ValueError, match="api_spec_external_reference_forbidden"):
        validate_and_snapshot_spec(external)

    callback = deepcopy(spec())
    paths = callback["paths"]
    assert isinstance(paths, dict)
    operation = paths["/documents/{documentId}"]["get"]
    operation["callbacks"] = {"notify": {"{$request.body#/url}": {}}}
    with pytest.raises(ValueError, match="api_spec_callback_forbidden"):
        validate_and_snapshot_spec(callback)


def test_compiler_emits_identity_handles_and_no_transport_or_secret_passthrough() -> None:
    snapshot = validate_and_snapshot_spec(spec())
    auth = authorization()
    auth = ApiDifferentialAuthorization(**{**auth.__dict__, "approved_spec_sha256": snapshot.spec_sha256})
    plan = compile_differential_plan(
        profile_id=ApiDifferentialProfileId.STANDARD,
        snapshot=snapshot,
        authorization=auth,
        identity_handles={
            IdentityState.OWNER: "identity-owner",
            IdentityState.PEER: "identity-peer",
            IdentityState.TENANT_ADMIN: "identity-admin",
            IdentityState.OTHER_TENANT: "identity-other-tenant",
            IdentityState.EXPIRED: "identity-expired",
            IdentityState.REVOKED: "identity-revoked",
        },
        seed=10620260711,
        now=NOW,
    )
    assert plan.seed == 10620260711 and len(plan.plan_sha256) == 64
    assert {case.operation_id for case in plan.cases} == {
        "createDocument", "deleteDocument", "getAudit", "getDocument", "getProfile", "transferDocument",
    }
    assert all(case.gateway_origin == "http://redagent-r106-gateway:8080" for case in plan.cases)
    serialized = repr(plan)
    assert "Authorization" not in serialized and "Bearer " not in serialized
    assert "https://" not in serialized and "curl" not in serialized
    assert all(case.risk in set(OperationRisk) for case in plan.cases)


def test_oracle_distinguishes_bola_bfla_valid_negative_and_filtered_success() -> None:
    bola = evaluate_authorization_differential(DifferentialObservation(
        case_id="case-bola", operation_id="getDocument", relation=IdentityRelation.CROSS_OWNER,
        privileged_status=200, lower_status=200,
        privileged_properties=("id", "owner_id", "title"),
        lower_properties=("id", "owner_id", "title"),
        expected_lower_outcomes=("403", "404"), protected_properties=("owner_id", "title"),
        resource_lineage_sha256="b" * 64,
    ))
    assert bola.finding_type == "bola" and bola.violated is True

    bfla = evaluate_authorization_differential(DifferentialObservation(
        case_id="case-bfla", operation_id="getAudit", relation=IdentityRelation.LOWER_ROLE,
        privileged_status=200, lower_status=200, privileged_properties=(), lower_properties=(),
        expected_lower_outcomes=("403",), protected_properties=(), resource_lineage_sha256="c" * 64,
    ))
    assert bfla.finding_type == "bfla" and bfla.violated is True

    bopla = evaluate_authorization_differential(DifferentialObservation(
        case_id="case-bopla", operation_id="getProfile", relation=IdentityRelation.PROPERTY_RESTRICTED,
        privileged_status=200, lower_status=200,
        privileged_properties=("id", "display_name", "internal_note"),
        lower_properties=("id", "display_name", "internal_note"),
        expected_lower_outcomes=("200_filtered", "403", "404"), protected_properties=("internal_note",),
        resource_lineage_sha256="9" * 64,
    ))
    assert bopla.finding_type == "bopla" and bopla.violated is True

    denied = evaluate_authorization_differential(DifferentialObservation(
        case_id="case-denied", operation_id="getDocument", relation=IdentityRelation.CROSS_TENANT,
        privileged_status=200, lower_status=404, privileged_properties=("id",), lower_properties=(),
        expected_lower_outcomes=("403", "404"), protected_properties=("owner_id",),
        resource_lineage_sha256="d" * 64,
    ))
    assert denied.violated is False and denied.reason == "authorized_negative"

    filtered = evaluate_authorization_differential(DifferentialObservation(
        case_id="case-filtered", operation_id="getDocument", relation=IdentityRelation.CROSS_OWNER,
        privileged_status=200, lower_status=200,
        privileged_properties=("id", "owner_id", "title"), lower_properties=("id",),
        expected_lower_outcomes=("403", "404", "200_filtered"), protected_properties=("owner_id", "title"),
        resource_lineage_sha256="e" * 64,
    ))
    assert filtered.violated is False and filtered.reason == "authorized_filtered_success"


def test_minimizer_never_changes_security_semantics() -> None:
    replay = minimize_replay(
        case_id="case-bola", operation_id="getDocument",
        relation=IdentityRelation.CROSS_OWNER,
        privileged_identity_handle="identity-owner", lower_identity_handle="identity-peer",
        resource_lineage_sha256="f" * 64,
        violated_predicate="cross_owner_read",
        sequence_steps=("create-document", "read-owner", "unrelated-list", "read-peer"),
        required_steps=("create-document", "read-peer"),
        public_values={"documentId": "document-000000000000000001", "unused": "remove-me"},
        required_value_names=("documentId",), seed=10620260711,
    )
    assert replay.sequence_steps == ("create-document", "read-peer")
    assert replay.public_values == (("documentId", "d"),)
    assert replay.relation is IdentityRelation.CROSS_OWNER
    assert replay.privileged_identity_handle == "identity-owner"
    assert replay.lower_identity_handle == "identity-peer"
    assert replay.resource_lineage_sha256 == "f" * 64
