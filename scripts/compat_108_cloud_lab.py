"""compat_108 repo-owned provider-emulator and offline-check qualification controller."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, replace
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.cloud_connectors.checks import SnapshotCheck, evaluate_snapshot
from redagent_platform.cloud_connectors.collector import collect_snapshot
from redagent_platform.cloud_connectors.compiler import compile_collection_plan
from redagent_platform.cloud_connectors.contracts import CollectionAuthorization, ProviderIdentity, ProviderKind
from redagent_platform.cloud_connectors.emulator import EmulatorHandler, EmulatorScenario
from redagent_platform.cloud_connectors.evidence import project_snapshot_evidence
from redagent_platform.cloud_connectors.http_transport import ClosedHttpCollectionTransport
from redagent_platform.cloud_connectors.lifecycle import CloudRun, CloudRunState, cancel_run, complete_cleanup
from redagent_platform.cloud_connectors.offline import (
    OfflineArtifactBinding, OfflineCheck, OfflineCheckKind, OfflineInput,
    evaluate_offline, offline_input_digest,
)
from redagent_platform.cloud_connectors.profiles import adapter_declarations, emulator_profiles


OUTPUT = ROOT / "runtime-assets" / "attestations" / "260711-R108_CLOUD_CONNECTOR_QUALIFICATION.json"
CONFIRMATION = "--confirm-r108-local-lab"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("qualify",))
    parser.add_argument(CONFIRMATION, action="store_true")
    args = parser.parse_args()
    if not args.confirm_r108_local_lab:
        raise SystemExit("r108_local_lab_confirmation_required")
    receipt = qualify()
    OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(OUTPUT), "sha256": receipt["receipt_sha256"]}))
    return 0


def qualify() -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    provider_results: list[dict[str, object]] = []
    redirect_denied = False
    mutation_denied = False
    identity_denied = False
    overgrant_denied = False
    profiles = emulator_profiles()
    for provider in ProviderKind:
        profile = profiles[provider]
        permissions = tuple(item.action for item in profile.operations)
        authorization = CollectionAuthorization(
            tenant_id="tenant-r108", policy_decision_id="decision-r108",
            policy_revision="r099-v1", reservation_id="reservation-r108",
            credential_lease_id="lease-r108", profile_id=profile.profile_id,
            effective_permissions=permissions, approved_permissions=permissions,
            approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10),
        )
        plan = compile_collection_plan(profile=profile, authorization=authorization, now=now)
        scenario = EmulatorScenario.for_profile(profile)
        with _running_emulator(scenario) as (endpoint, port):
            transport = ClosedHttpCollectionTransport(
                endpoint=endpoint, expected_port=port, lease_reference="lease-r108",
                max_response_bytes=plan.max_response_bytes,
            )
            snapshot = collect_snapshot(plan=plan, transport=transport, collected_at=now)
            attribute = "read_only_root_filesystem" if provider is ProviderKind.KUBERNETES else "encryption_enabled"
            evaluation = evaluate_snapshot(
                snapshot=snapshot, control_pack_id="r108-cloud-baseline-v1",
                control_pack_sha256="3" * 64,
                checks=(SnapshotCheck(
                    check_id=f"R108-{provider.value.upper()}-001",
                    operation_id=profile.operations[0].operation_id,
                    attribute=attribute, expected=True, severity="high",
                ),), evaluated_at=now,
            )
            evidence = project_snapshot_evidence(snapshot=snapshot, evaluation=evaluation)
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("POST", "/operations/forbidden", headers={"X-RedAgent-Lease-Reference": "lease-r108"})
            mutation_denied = connection.getresponse().status == 405
            connection.close()
            provider_results.append({
                "provider": provider.value, "identity": evidence.identity,
                "plan_sha256": plan.plan_sha256, "snapshot_sha256": snapshot.snapshot_sha256,
                "evidence_sha256": evidence.content_sha256, "complete": snapshot.complete,
                "page_count": snapshot.page_count, "resource_count": snapshot.resource_count,
                "result_count": len(evaluation.results), "request_count": scenario.request_count,
                "external_contact_count": scenario.external_contact_count,
                "mutation_attempt_count": scenario.mutation_attempt_count,
            })
        wrong_scenario = EmulatorScenario.for_profile(profile)
        wrong_scenario.profile = replace(
            profile,
            expected_identity=ProviderIdentity(provider=provider, tenant=f"wrong-{profile.expected_identity.tenant}"),
        )
        with _running_emulator(wrong_scenario) as (endpoint, port):
            try:
                collect_snapshot(
                    plan=plan,
                    transport=ClosedHttpCollectionTransport(
                        endpoint=endpoint, expected_port=port, lease_reference="lease-r108",
                        max_response_bytes=plan.max_response_bytes,
                    ), collected_at=now,
                )
            except ValueError as exc:
                identity_denied = str(exc) == "cloud_provider_identity_mismatch"

    redirect_scenario = EmulatorScenario.for_profile(profiles[ProviderKind.AWS], redirect_identity=True)
    with _running_emulator(redirect_scenario) as (endpoint, port):
        try:
            ClosedHttpCollectionTransport(
                endpoint=endpoint, expected_port=port, lease_reference="lease-r108", max_response_bytes=4096,
            ).verify_identity()
        except ValueError as exc:
            redirect_denied = str(exc) == "cloud_http_redirect_denied"

    aws = profiles[ProviderKind.AWS]
    permissions = tuple(item.action for item in aws.operations)
    try:
        compile_collection_plan(
            profile=aws,
            authorization=CollectionAuthorization(
                tenant_id="tenant-r108", policy_decision_id="decision-r108",
                policy_revision="r099-v1", reservation_id="reservation-r108",
                credential_lease_id="lease-r108", profile_id=aws.profile_id,
                effective_permissions=permissions + ("iam:GetRole",), approved_permissions=permissions,
                approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10),
            ), now=now,
        )
    except ValueError as exc:
        overgrant_denied = str(exc) == "cloud_permission_overgrant"

    offline_results = [_qualify_offline(kind, now) for kind in OfflineCheckKind]
    run = CloudRun(run_id="run-r108-qualification", state=CloudRunState.COLLECTING, lease_id="lease-r108")
    cancelling, cancel_receipt = cancel_run(run, occurred_at=now)
    closed, cleanup = complete_cleanup(cancelling, occurred_at=now, residual_resource_ids=())
    declarations = adapter_declarations()
    source_sha = _source_digest()
    body: dict[str, object] = {
        "schema": "redagent.r108-qualification/v1", "qualified_at": now.isoformat(),
        "status": "passed", "scope": "repo-owned-loopback-emulators-and-offline-fixtures-only",
        "source_sha256": source_sha, "providers": provider_results, "offline": offline_results,
        "negative": {
            "redirect_denied": redirect_denied, "mutation_denied": mutation_denied,
            "wrong_identity_denied": identity_denied, "overgrant_denied": overgrant_denied,
        },
        "cancellation": {
            **asdict(cancel_receipt), "occurred_at": cancel_receipt.occurred_at.isoformat(),
            "final_state": closed.state.value, "residual_resource_count": cleanup.residual_resource_count,
        },
        "external_adapters": [
            {"adapter_id": item.adapter_id, "execution_enabled": item.execution_enabled,
             "production_qualified": item.production_qualified}
            for item in declarations
        ],
        "safety": {
            "external_contact_count": sum(int(item["external_contact_count"]) for item in provider_results),
            "real_cloud_contact_count": 0, "real_cluster_contact_count": 0,
            "external_reference_execution_count": 0, "production_qualified": False,
        },
    }
    if not all(body["negative"].values()):  # type: ignore[union-attr]
        raise RuntimeError("r108_negative_qualification_failed")
    if body["safety"]["external_contact_count"] != 0:  # type: ignore[index]
        raise RuntimeError("r108_external_contact_detected")
    body["receipt_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return body


def _qualify_offline(kind: OfflineCheckKind, now: datetime) -> dict[str, object]:
    attribute = {OfflineCheckKind.IAC: "read_only_root_filesystem", OfflineCheckKind.IMAGE: "signed", OfflineCheckKind.FILESYSTEM: "world_writable"}[kind]
    expected = False if kind is OfflineCheckKind.FILESYSTEM else True
    files = ({
        "path": f"fixtures/{kind.value}.json", "size": 128,
        "resources": [{"resource_id": f"{kind.value}:resource-1", attribute: expected}],
    },)
    input_sha = offline_input_digest(kind=kind, files=files)
    result = evaluate_offline(
        binding=OfflineArtifactBinding(
            engine_id="redagent-offline-v1", engine_sha256="1" * 64,
            policy_pack_id="r108-baseline-v1", policy_sha256="2" * 64,
            database_id="r108-synthetic-db-v1", database_sha256="3" * 64,
            network_allowed=False, subprocess_allowed=False, repository_config_allowed=False,
            external_modules_allowed=False, max_files=8, max_bytes=4096, max_results=16,
        ),
        input_data=OfflineInput(input_id=f"r108-{kind.value}-fixture", kind=kind, input_sha256=input_sha, files=files),
        checks=(OfflineCheck(check_id=f"R108-{kind.value.upper()}-001", kind=kind, attribute=attribute, expected=expected, severity="high"),),
        evaluated_at=now,
    )
    return {"kind": kind.value, "input_sha256": input_sha, "result_sha256": result.result_sha256, "result_count": len(result.results), "network_allowed": False, "subprocess_allowed": False}


@contextmanager
def _running_emulator(scenario: EmulatorScenario) -> Iterator[tuple[str, int]]:
    handler = type("QualifiedEmulatorHandler", (EmulatorHandler,), {"scenario": scenario})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _source_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform" / "cloud_connectors").glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
