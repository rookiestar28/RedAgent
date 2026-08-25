"""No-CLI R106 worker: bounded Schemathesis generation plus fixed authorization matrix."""

from __future__ import annotations

from copy import deepcopy
from http.client import HTTPConnection
import json
from pathlib import Path
import time
from urllib.parse import quote

from hypothesis import find, settings
import schemathesis
from schemathesis.core import NOT_SET


PLAN = Path("/run/redagent/plan.json")
SPEC = Path("/run/redagent/openapi.json")
OUTPUT = Path("/work/result.json")
GATEWAY = "redagent-r106-gateway"


def main() -> None:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    if plan.get("schema") != "redagent.r106-worker-plan/v1" or plan.get("seed") != 10620260711:
        raise RuntimeError("r106_worker_plan_invalid")
    generator_spec = deepcopy(spec)
    generator_spec.pop("security", None)
    generator_spec.get("components", {}).pop("securitySchemes", None)
    schema = schemathesis.openapi.from_dict(generator_spec)
    baseline: list[dict[str, object]] = []
    created: list[str] = []
    for operation in plan["operations"]:
        api_operation = schema[operation["path_template"]][operation["method"]]
        case = find(
            api_operation.as_strategy(generation_mode=schemathesis.GenerationMode.POSITIVE),
            lambda _: True,
            settings=settings(max_examples=20, derandomize=True, database=None),
        )
        if case.headers or case.cookies:
            raise RuntimeError("r106_generated_transport_material_forbidden")
        path = operation["path_template"]
        for name, value in (case.path_parameters or {}).items():
            path = path.replace("{" + name + "}", quote(str(value), safe=""))
        body = None if case.body is NOT_SET else case.body
        response = call(operation["operation_id"], operation["method"], operation["path_template"], path,
                        "identity-owner", body=body, idempotency=f"baseline-{operation['operation_id']}")
        baseline.append({"operation_id": operation["operation_id"], "status": response["status"]})
        if operation["operation_id"] == "createDocument" and response["status"] == 201:
            resource_id = response["body"].get("id")
            if isinstance(resource_id, str):
                created.append(resource_id)
    for resource_id in reversed(created):
        call("deleteDocument", "DELETE", "/documents/{documentId}", f"/documents/{resource_id}", "identity-owner")

    observations = [
        compare("bola", "getDocument", "/documents/{documentId}", "/documents/document-owner-a",
                "identity-owner", "identity-peer", ("owner_id", "title")),
        compare("valid_negative", "getDocument", "/documents/{documentId}", "/documents/document-safe-a",
                "identity-owner", "identity-peer", ("owner_id", "title")),
        compare("cross_tenant", "getDocument", "/documents/{documentId}", "/documents/document-owner-a",
                "identity-owner", "identity-other-tenant", ("owner_id", "title")),
        compare("bfla", "getAudit", "/admin/audit", "/admin/audit",
                "identity-admin", "identity-peer", ()),
        compare("bopla", "getProfile", "/profiles/{profileId}", "/profiles/user-a",
                "identity-owner", "identity-peer", ("internal_note",)),
        compare("expired", "getDocument", "/documents/{documentId}", "/documents/document-owner-a",
                "identity-owner", "identity-expired", ("owner_id", "title")),
        compare("revoked", "getDocument", "/documents/{documentId}", "/documents/document-owner-a",
                "identity-owner", "identity-revoked", ("owner_id", "title")),
        compare("anonymous", "getDocument", "/documents/{documentId}", "/documents/document-owner-a",
                "identity-owner", "identity-anonymous", ("owner_id", "title")),
    ]
    created_response = call(
        "createDocument", "POST", "/documents", "/documents", "identity-owner",
        body={"title": "R106 stateful document"}, idempotency="stateful-create-document",
    )
    resource_id = created_response["body"].get("id") if created_response["status"] == 201 else None
    if not isinstance(resource_id, str):
        raise RuntimeError("r106_stateful_create_failed")
    read_response = call(
        "getDocument", "GET", "/documents/{documentId}", f"/documents/{resource_id}", "identity-owner",
    )
    delete_response = call(
        "deleteDocument", "DELETE", "/documents/{documentId}", f"/documents/{resource_id}", "identity-owner",
    )
    reset_response = call(
        "getDocument", "GET", "/documents/{documentId}", f"/documents/{resource_id}", "identity-owner",
    )
    transfer_create = call(
        "createDocument", "POST", "/documents", "/documents", "identity-owner",
        body={"title": "R106 ownership transition"}, idempotency="ownership-transition-create",
    )
    transfer_id = transfer_create["body"].get("id") if transfer_create["status"] == 201 else None
    if not isinstance(transfer_id, str):
        raise RuntimeError("r106_ownership_transition_create_failed")
    transfer_response = call(
        "transferDocument", "POST", "/documents/{documentId}/transfer",
        f"/documents/{transfer_id}/transfer", "identity-owner", body={"new_owner_id": "user-b"},
    )
    former_owner_read = call(
        "getDocument", "GET", "/documents/{documentId}", f"/documents/{transfer_id}", "identity-owner",
    )
    new_owner_read = call(
        "getDocument", "GET", "/documents/{documentId}", f"/documents/{transfer_id}", "identity-peer",
    )
    transfer_cleanup = call(
        "deleteDocument", "DELETE", "/documents/{documentId}", f"/documents/{transfer_id}", "identity-peer",
    )
    result = {
        "schema": "redagent.r106-worker-result/v1", "engine_version": schemathesis.__version__,
        "baseline": baseline, "observations": observations,
        "stateful": {
            "create_status": created_response["status"], "read_status": read_response["status"],
            "delete_status": delete_response["status"], "reset_status": reset_response["status"],
            "resource_id_sha256": __import__("hashlib").sha256(resource_id.encode()).hexdigest(),
        },
        "ownership_transition": {
            "create_status": transfer_create["status"], "transfer_status": transfer_response["status"],
            "former_owner_status": former_owner_read["status"], "new_owner_status": new_owner_read["status"],
            "cleanup_status": transfer_cleanup["status"],
        },
        "credential_material_present": False,
    }
    OUTPUT.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def compare(
    label: str, operation_id: str, path_template: str, path: str,
    privileged: str, lower: str, protected: tuple[str, ...],
) -> dict[str, object]:
    high = call(operation_id, "GET", path_template, path, privileged)
    low = call(operation_id, "GET", path_template, path, lower)
    return {
        "label": label, "operation_id": operation_id,
        "privileged_status": high["status"], "lower_status": low["status"],
        "privileged_properties": sorted(high["body"]), "lower_properties": sorted(low["body"]),
        "protected_properties": list(protected),
    }


def call(
    operation_id: str, method: str, path_template: str, path: str,
    identity_handle: str, *, body: object | None = None, idempotency: str = "",
) -> dict[str, object]:
    time.sleep(0.55)
    encoded = b"" if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    headers = {
        "X-R106-Operation-ID": operation_id, "X-R106-Path-Template": path_template,
        "X-R106-Identity-Handle": identity_handle,
    }
    if idempotency:
        headers["X-R106-Idempotency-Key"] = idempotency
    if encoded:
        headers["Content-Type"] = "application/json"; headers["Content-Length"] = str(len(encoded))
    connection = HTTPConnection(GATEWAY, 8080, timeout=5)
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse(); raw = response.read(64 * 1024 + 1); status = response.status
    connection.close()
    if len(raw) > 64 * 1024:
        raise RuntimeError("r106_response_too_large")
    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        value = {}
    if not isinstance(value, dict):
        value = {}
    return {"status": status, "body": value}


if __name__ == "__main__":
    main()
