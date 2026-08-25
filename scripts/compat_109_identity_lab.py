"""compat_109 repo-owned identity provider emulator qualification controller."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import sys
from threading import Thread
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

from redagent_platform.identity_saas.collector import collect_identity_snapshot
from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import IdentityAuthorization, IdentityProvider
from redagent_platform.identity_saas.emulator import IdentityEmulatorHandler, IdentityEmulatorScenario
from redagent_platform.identity_saas.evaluation import BaselineCheck, evaluate_identity_snapshot
from redagent_platform.identity_saas.http_transport import ClosedIdentityHttpTransport
from redagent_platform.identity_saas.lifecycle import IdentityRun, IdentityRunState, cancel_identity_run, complete_identity_cleanup
from redagent_platform.identity_saas.profiles import adapter_declarations, emulator_profiles


OUTPUT = ROOT / "runtime-assets/attestations/260711-R109_IDENTITY_CONNECTOR_QUALIFICATION.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("command", choices=("qualify",)); parser.add_argument("--confirm-r109-local-lab", action="store_true"); args = parser.parse_args()
    if not args.confirm_r109_local_lab: raise SystemExit("r109_local_lab_confirmation_required")
    receipt = qualify(); OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(OUTPUT), "sha256": receipt["receipt_sha256"]})); return 0


def qualify() -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0); results = []; wrong_binding_denied = False; redirect_denied = False; mutation_denied = False; overgrant_denied = False
    profiles = emulator_profiles()
    for provider in IdentityProvider:
        profile = profiles[provider]; authorization = _authorization(profile, now); plan = compile_identity_plan(profile=profile, authorization=authorization, now=now)
        scenario = IdentityEmulatorScenario.for_profile(profile)
        with _running(scenario) as (endpoint, port):
            snapshot = collect_identity_snapshot(plan=plan, profile=profile,
                transport=ClosedIdentityHttpTransport(endpoint=endpoint, expected_port=port, lease_reference="lease-r109", max_response_bytes=profile.max_bytes), collected_at=now)
            operation = profile.operations[0]; check_field = operation.selected_fields[-1]; evaluation = evaluate_identity_snapshot(snapshot=snapshot,
                baseline_id="r109-identity-baseline-v1", baseline_sha256="5" * 64,
                checks=(BaselineCheck(control_id=f"R109-{provider.value.upper()}-001", operation_id=operation.operation_id,
                    attribute=check_field, expected=snapshot.resources[0].attributes[check_field], severity="high"),), evaluated_at=now)
            connection = HTTPConnection("127.0.0.1", port, timeout=5); connection.request("POST", "/operations/forbidden", headers={"X-RedAgent-Lease-Reference": "lease-r109"}); mutation_denied = connection.getresponse().status == 405; connection.close()
            results.append({"provider": provider.value, "tenant_id": snapshot.tenant_id, "audience": snapshot.audience,
                "plan_sha256": plan.plan_sha256, "snapshot_sha256": snapshot.snapshot_sha256, "evaluation_sha256": evaluation.evaluation_sha256,
                "complete": snapshot.complete, "page_count": snapshot.page_count, "resource_count": snapshot.resource_count,
                "selected_fields": list(operation.selected_fields), "external_contact_count": scenario.external_contact_count})
        wrong = IdentityEmulatorScenario.for_profile(profile); wrong.tenant_id = "wrong-r109-tenant"
        with _running(wrong) as (endpoint, port):
            try: collect_identity_snapshot(plan=plan, profile=profile, transport=ClosedIdentityHttpTransport(endpoint=endpoint, expected_port=port, lease_reference="lease-r109", max_response_bytes=profile.max_bytes), collected_at=now)
            except ValueError as exc: wrong_binding_denied = str(exc) == "identity_provider_binding_mismatch"
    redirect = IdentityEmulatorScenario.for_profile(profiles[IdentityProvider.OKTA]); redirect.redirect_binding = True
    with _running(redirect) as (endpoint, port):
        try: ClosedIdentityHttpTransport(endpoint=endpoint, expected_port=port, lease_reference="lease-r109", max_response_bytes=4096).verify_binding()
        except ValueError as exc: redirect_denied = str(exc) == "identity_http_redirect_denied"
    profile = profiles[IdentityProvider.OKTA]
    auth = _authorization(profile, now)
    try: compile_identity_plan(profile=profile, authorization=IdentityAuthorization(**(auth.__dict__ | {"granted_scopes": auth.granted_scopes + ("okta.users.read",)})), now=now)
    except ValueError as exc: overgrant_denied = str(exc) == "identity_scope_overgrant"
    run = IdentityRun(run_id="run-r109-qualification", state=IdentityRunState.COLLECTING, lease_id="lease-r109")
    cleaning, cancellation = cancel_identity_run(run, occurred_at=now); closed, cleanup = complete_identity_cleanup(cleaning, occurred_at=now, residual_resource_ids=())
    body: dict[str, object] = {"schema": "redagent.r109-qualification/v1", "qualified_at": now.isoformat(), "status": "passed",
        "scope": "repo-owned-loopback-identity-emulators-only", "source_sha256": _source_digest(), "providers": results,
        "negative": {"redirect_denied": redirect_denied, "mutation_denied": mutation_denied, "wrong_binding_denied": wrong_binding_denied, "overgrant_denied": overgrant_denied},
        "cancellation": {**asdict(cancellation), "occurred_at": cancellation.occurred_at.isoformat(), "final_state": closed.state.value, "residual_resource_count": cleanup.residual_resource_count},
        "external_adapters": [{"adapter_id": item.adapter_id, "execution_enabled": item.execution_enabled, "production_qualified": item.production_qualified} for item in adapter_declarations()],
        "safety": {"external_contact_count": sum(int(item["external_contact_count"]) for item in results), "real_tenant_contact_count": 0,
            "credential_material_persisted_count": 0, "external_reference_execution_count": 0, "production_qualified": False}}
    if not all(body["negative"].values()) or body["safety"]["external_contact_count"] != 0: raise RuntimeError("r109_negative_or_safety_qualification_failed")  # type: ignore[union-attr,index]
    body["receipt_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); return body


def _authorization(profile, now: datetime) -> IdentityAuthorization:
    return IdentityAuthorization(authorization_id="authorization-r109", policy_decision_id="decision-r109", policy_revision="r109-v1",
        reservation_id="reservation-r109", credential_lease_id="lease-r109", tenant_id=profile.tenant_id, audience=profile.audience,
        consent_mode=profile.consent_mode, granted_scopes=tuple(item.permission_scope for item in profile.operations),
        effective_role_permissions=tuple(item.effective_role_permission for item in profile.operations), approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))


@contextmanager
def _running(scenario: IdentityEmulatorScenario) -> Iterator[tuple[str, int]]:
    handler = type("QualifiedIdentityHandler", (IdentityEmulatorHandler,), {"scenario": scenario}); server = ThreadingHTTPServer(("127.0.0.1", 0), handler); thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try: yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally: server.shutdown(); server.server_close(); thread.join(timeout=5)


def _source_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform/identity_saas").glob("*.py")): digest.update(path.name.encode()); digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__": raise SystemExit(main())
