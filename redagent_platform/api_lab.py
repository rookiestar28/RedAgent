"""OpenAPI metadata import and lab-only API security case contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from redagent_platform.domain import EvidenceKind, TargetType, TestMode
from redagent_platform.evidence_chain import EvidenceRecord, RedactionStatus
from redagent_platform.findings import EvidenceLink
from redagent_platform.lab_harness import LAB_ONLY_LABEL, LabTargetRegistration


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class OwaspApiTop10Category(str, Enum):
    API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION = "API1:2023 Broken Object Level Authorization"
    API2_BROKEN_AUTHENTICATION = "API2:2023 Broken Authentication"
    API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION = "API3:2023 Broken Object Property Level Authorization"
    API4_UNRESTRICTED_RESOURCE_CONSUMPTION = "API4:2023 Unrestricted Resource Consumption"
    API5_BROKEN_FUNCTION_LEVEL_AUTHORIZATION = "API5:2023 Broken Function Level Authorization"


class ApiLabCaseType(str, Enum):
    AUTHORIZATION_DIFFERENTIAL = "authorization_differential"
    OBJECT_PROPERTY = "object_property"
    UNAUTHENTICATED_ACCESS = "unauthenticated_access"
    RESOURCE_CONSUMPTION_REVIEW = "resource_consumption_review"


@dataclass(frozen=True, kw_only=True)
class AuthRequirement:
    scheme_name: str
    scheme_type: str
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ApiParameter:
    name: str
    location: str
    required: bool
    schema_type: str | None = None


@dataclass(frozen=True, kw_only=True)
class ApiOperation:
    path: str
    method: HttpMethod
    operation_id: str
    auth_requirements: tuple[AuthRequirement, ...]
    parameters: tuple[ApiParameter, ...]
    response_classes: tuple[str, ...]
    request_body_content_types: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class OpenApiDocument:
    id: str
    title: str
    version: str
    source_reference: str
    operations: tuple[ApiOperation, ...]


@dataclass(frozen=True, kw_only=True)
class ApiLabCase:
    case_id: str
    case_type: ApiLabCaseType
    owasp_category: OwaspApiTop10Category
    path: str
    method: HttpMethod
    operation_id: str
    lab_target_id: str
    mode: TestMode = TestMode.LAB_ONLY_RUN
    lab_only: bool = True
    execution_enabled: bool = False
    active_enterprise_enabled: bool = False


@dataclass(frozen=True, kw_only=True)
class ApiLabResult:
    result_id: str
    case_id: str
    endpoint_path: str
    method: HttpMethod
    operation_id: str
    evidence_links: tuple[EvidenceLink, ...]
    status: str = "needs_review"


_ALLOWED_METHODS = {method.value.lower(): method for method in HttpMethod}
_SAFE_ID = re.compile(r"[^a-zA-Z0-9_.:-]+")


def import_openapi_document(
    *,
    document_id: str,
    source_reference: str,
    spec: Mapping[str, object],
) -> OpenApiDocument:
    """Import OpenAPI metadata from an already parsed mapping."""
    _require_non_empty("document_id", document_id)
    _require_non_empty("source_reference", source_reference)
    openapi_version = spec.get("openapi")
    if not isinstance(openapi_version, str) or not openapi_version.startswith("3."):
        raise ValueError("unsupported_or_missing_openapi_version")
    info = _require_mapping(spec.get("info"), "missing_info")
    title = _require_string(info.get("title"), "missing_info_title")
    version = _require_string(info.get("version"), "missing_info_version")
    paths = _require_mapping(spec.get("paths"), "missing_paths")
    if not paths:
        raise ValueError("missing_paths")
    security_schemes = _extract_security_schemes(spec)
    global_security = spec.get("security")
    operations: list[ApiOperation] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise ValueError("invalid_openapi_path")
        if not isinstance(path_item, Mapping):
            raise ValueError("invalid_path_item")
        path_parameters = _extract_parameters(path_item.get("parameters", ()))
        for raw_method, operation in path_item.items():
            method = _ALLOWED_METHODS.get(str(raw_method).lower())
            if method is None:
                continue
            operation_map = _require_mapping(operation, "invalid_operation")
            operation_id = _operation_id(raw_path, method, operation_map)
            parameters = path_parameters + _extract_parameters(operation_map.get("parameters", ()))
            auth_requirements = _extract_auth_requirements(
                operation_map.get("security", global_security),
                security_schemes,
            )
            responses = _extract_response_classes(operation_map.get("responses"))
            request_bodies = _extract_request_body_content_types(operation_map.get("requestBody"))
            operations.append(
                ApiOperation(
                    path=raw_path,
                    method=method,
                    operation_id=operation_id,
                    auth_requirements=auth_requirements,
                    parameters=parameters,
                    response_classes=responses,
                    request_body_content_types=request_bodies,
                )
            )
    if not operations:
        raise ValueError("missing_operations")
    return OpenApiDocument(
        id=document_id.strip(),
        title=title,
        version=version,
        source_reference=source_reference.strip(),
        operations=tuple(operations),
    )


def generate_lab_api_cases(document: OpenApiDocument, registration: LabTargetRegistration) -> tuple[ApiLabCase, ...]:
    """Generate disabled lab-only API case metadata for an approved lab target."""
    _validate_lab_registration(registration)
    cases: list[ApiLabCase] = []
    for operation in document.operations:
        has_path_parameter = any(parameter.location == "path" for parameter in operation.parameters)
        if has_path_parameter and operation.auth_requirements:
            cases.append(
                _case(
                    document,
                    registration,
                    operation,
                    ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL,
                    OwaspApiTop10Category.API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                )
            )
        if operation.request_body_content_types:
            cases.append(
                _case(
                    document,
                    registration,
                    operation,
                    ApiLabCaseType.OBJECT_PROPERTY,
                    OwaspApiTop10Category.API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION,
                )
            )
        if not operation.auth_requirements:
            cases.append(
                _case(
                    document,
                    registration,
                    operation,
                    ApiLabCaseType.UNAUTHENTICATED_ACCESS,
                    OwaspApiTop10Category.API2_BROKEN_AUTHENTICATION,
                )
            )
    return tuple(cases)


def build_api_lab_result(
    *,
    result_id: str,
    case: ApiLabCase,
    evidence_records: tuple[EvidenceRecord, ...],
) -> ApiLabResult:
    _require_non_empty("result_id", result_id)
    if not evidence_records:
        raise ValueError("missing_evidence_records")
    links = tuple(
        EvidenceLink(
            evidence_id=record.id,
            integrity_hash=record.integrity_hash,
            redaction_status=record.redaction_status,
            contains_sensitive_payload=record.redaction_status is RedactionStatus.REDACTED,
        )
        for record in evidence_records
    )
    return ApiLabResult(
        result_id=result_id.strip(),
        case_id=case.case_id,
        endpoint_path=case.path,
        method=case.method,
        operation_id=case.operation_id,
        evidence_links=links,
    )


def _case(
    document: OpenApiDocument,
    registration: LabTargetRegistration,
    operation: ApiOperation,
    case_type: ApiLabCaseType,
    category: OwaspApiTop10Category,
) -> ApiLabCase:
    return ApiLabCase(
        case_id=f"{document.id}:{operation.operation_id}:{case_type.value}",
        case_type=case_type,
        owasp_category=category,
        path=operation.path,
        method=operation.method,
        operation_id=operation.operation_id,
        lab_target_id=registration.target_id,
    )


def _validate_lab_registration(registration: LabTargetRegistration) -> None:
    if LAB_ONLY_LABEL not in registration.labels:
        raise ValueError("lab_only_label_required")
    if registration.inventory_target.target_type is not TargetType.LAB_TARGET:
        raise ValueError("lab_target_required")
    if registration.inventory_target.allowed_modes != (TestMode.LAB_ONLY_RUN,):
        raise ValueError("lab_only_mode_required")


def _extract_security_schemes(spec: Mapping[str, object]) -> Mapping[str, str]:
    components = spec.get("components")
    if not isinstance(components, Mapping):
        return {}
    schemes = components.get("securitySchemes")
    if not isinstance(schemes, Mapping):
        return {}
    result: dict[str, str] = {}
    for name, definition in schemes.items():
        if isinstance(name, str) and isinstance(definition, Mapping):
            scheme_type = definition.get("type")
            result[name] = scheme_type if isinstance(scheme_type, str) else "unknown"
    return result


def _extract_auth_requirements(value: object, security_schemes: Mapping[str, str]) -> tuple[AuthRequirement, ...]:
    if value is None or value == []:
        return ()
    if not isinstance(value, tuple | list):
        raise ValueError("invalid_security_requirement")
    requirements: list[AuthRequirement] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("invalid_security_requirement")
        for scheme_name, scopes in item.items():
            if not isinstance(scheme_name, str):
                raise ValueError("invalid_security_scheme_name")
            scope_values = tuple(str(scope) for scope in scopes) if isinstance(scopes, tuple | list) else ()
            requirements.append(
                AuthRequirement(
                    scheme_name=scheme_name,
                    scheme_type=security_schemes.get(scheme_name, "unknown"),
                    scopes=scope_values,
                )
            )
    return tuple(requirements)


def _extract_parameters(value: object) -> tuple[ApiParameter, ...]:
    if value is None:
        return ()
    if not isinstance(value, tuple | list):
        raise ValueError("invalid_parameters")
    parameters: list[ApiParameter] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("invalid_parameter")
        name = _require_string(item.get("name"), "missing_parameter_name")
        location = _require_string(item.get("in"), "missing_parameter_location")
        required = bool(item.get("required", location == "path"))
        schema = item.get("schema")
        schema_type = schema.get("type") if isinstance(schema, Mapping) and isinstance(schema.get("type"), str) else None
        parameters.append(ApiParameter(name=name, location=location, required=required, schema_type=schema_type))
    return tuple(parameters)


def _extract_response_classes(value: object) -> tuple[str, ...]:
    responses = _require_mapping(value, "missing_responses")
    if not responses:
        raise ValueError("missing_responses")
    classes: set[str] = set()
    for code in responses:
        code_text = str(code)
        if len(code_text) == 3 and code_text[0].isdigit():
            classes.add(f"{code_text[0]}xx")
        elif code_text == "default":
            classes.add("default")
        else:
            raise ValueError("invalid_response_code")
    return tuple(sorted(classes))


def _extract_request_body_content_types(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    body = _require_mapping(value, "invalid_request_body")
    content = body.get("content")
    if not isinstance(content, Mapping):
        return ()
    return tuple(sorted(str(content_type) for content_type in content if isinstance(content_type, str)))


def _operation_id(path: str, method: HttpMethod, operation: Mapping[str, object]) -> str:
    provided = operation.get("operationId")
    if isinstance(provided, str) and provided.strip():
        return provided.strip()
    derived = _SAFE_ID.sub("_", f"{method.value.lower()}_{path.strip('/')}")
    return derived.strip("_") or f"{method.value.lower()}_root"


def _require_mapping(value: object, error_code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(error_code)
    return value


def _require_string(value: object, error_code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(error_code)
    return value.strip()


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
