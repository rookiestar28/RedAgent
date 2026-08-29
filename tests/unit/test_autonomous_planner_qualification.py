from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

import pytest

from redagent_platform.validation.autonomous_planner_qualification import (
    ABORTED,
    AUTONOMOUS_PLANNER_QUALIFIED,
    EXPECTED_FORMAL_ENVIRONMENT,
    MATRIX_SCHEMA_V2,
    MATRIX_SCHEMA_V3,
    NOT_QUALIFIED,
    PINS_SCHEMA,
    PROJECTION_SCHEMA,
    PROJECTION_SCHEMA_V2,
    PROJECTION_SCHEMA_V3,
    QualificationError,
    build_bundle,
    build_event_chain,
    canonical_bytes,
    canonical_sha256,
    compute_disposition,
    create_stage_result,
    decode_json_bytes,
    load_matrix,
    parse_matrix,
    parse_projection,
    verify_bundle,
    verify_preflight,
)


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "config/validation/autonomous-planner-qualification-v1.json"
MATRIX_V2_PATH = ROOT / "config/validation/autonomous-planner-qualification-v2.json"
MATRIX_V3_PATH = ROOT / "config/validation/autonomous-planner-qualification-v3.json"
MATRIX_V4_PATH = ROOT / "config/validation/autonomous-planner-qualification-v4.json"
MATRIX_V5_PATH = ROOT / "config/validation/autonomous-planner-qualification-v5.json"
MATRIX_V6_PATH = ROOT / "config/validation/autonomous-planner-qualification-v6.json"
MATRIX_SCHEMA_V4 = "redagent.autonomous-planner-qualification-matrix/v4"
MATRIX_SCHEMA_V5 = "redagent.autonomous-planner-qualification-matrix/v5"
MATRIX_SCHEMA_V6 = "redagent.autonomous-planner-qualification-matrix/v6"
PROJECTION_SCHEMA_V4 = "redagent.autonomous-planner-qualification-projection/v4"
PROJECTION_SCHEMA_V5 = "redagent.autonomous-planner-qualification-projection/v5"
PROJECTION_SCHEMA_V6 = "redagent.autonomous-planner-qualification-projection/v6"
ZERO_SHA = "0" * 64
V5_DEFAULT_VOLUMES = (
    ("redagent-local-postgres-data", "redagent_postgres_data"),
    ("redagent-local-keycloak-data", "redagent_keycloak_data"),
    ("redagent-local-temporal-data", "redagent_temporal_data"),
    ("redagent-local-rustfs-data", "redagent_rustfs_data"),
)


def _projection_payload(matrix) -> dict[str, object]:
    is_v2 = matrix.schema_version == MATRIX_SCHEMA_V2
    is_v3 = matrix.schema_version == MATRIX_SCHEMA_V3
    is_v4 = matrix.schema_version == MATRIX_SCHEMA_V4
    is_v5 = matrix.schema_version == MATRIX_SCHEMA_V5
    is_v6 = matrix.schema_version == MATRIX_SCHEMA_V6
    has_runtime_binding = is_v2 or is_v3 or is_v4 or is_v5 or is_v6
    body: dict[str, object] = {
        "schema_version": (
            PROJECTION_SCHEMA_V6
            if is_v6
            else PROJECTION_SCHEMA_V5
            if is_v5
            else PROJECTION_SCHEMA_V4
            if is_v4
            else PROJECTION_SCHEMA_V3
            if is_v3
            else PROJECTION_SCHEMA_V2
            if is_v2
            else PROJECTION_SCHEMA
        ),
        "attempt_id": (
            "autonomous-planner-20260830-attempt-06"
            if is_v6
            else "autonomous-planner-20260830-attempt-05"
            if is_v5
            else "autonomous-planner-20260830-attempt-04"
            if is_v4
            else "r165-20260829-attempt-03"
            if is_v3
            else "r164-formal-attempt-2"
            if is_v2
            else "r163-formal-attempt-1"
        ),
        "candidate_commit": "1" * 40,
        "candidate_tree": "2" * 40,
        "candidate_parent_commit": matrix.candidate_parent_commit,
        "matrix_sha256": matrix.matrix_sha256,
        "source_sha256": {path: hashlib.sha256(path.encode("utf-8")).hexdigest() for path in matrix.source_paths},
        "environment": {
            "platform": "windows",
            "architecture": "amd64",
            "python_version": "3.11.9",
            "node_version": "22.14.0",
        },
        "private_manifest_sha256": "3" * 64,
        "operator_identity_sha256": "4" * 64,
        "reviewer_identity_sha256": "5" * 64,
        "trust_anchor_sha256": "6" * 64,
        "runner_ids": [stage.runner_id for stage in matrix.stages],
        "target_hosts": list(matrix.allowed_target_hosts),
        "formal_environment": dict(matrix.formal_environment),
        "max_concurrency": 1,
        "scorer_sha256": matrix.scorer_sha256,
        "retained_artifacts": list(matrix.retained_artifacts),
        "residual_ports": [] if has_runtime_binding else [43161, 43162, 43163, 43164],
        "residual_process_markers": ["redagent-opa", "redagent-openbao", "redagent-stack"],
    }
    if has_runtime_binding:
        body["runner_environment"] = {
            runner_id: dict(environment) for runner_id, environment in matrix.runner_environment.items()
        }
        body["formal_runtime_paths"] = dict(matrix.formal_runtime_paths)
    return {**body, "projection_sha256": canonical_sha256(body)}


def _projection(matrix):
    return parse_projection(_projection_payload(matrix), matrix)


def _v5_matrix(*, cleanup_paths: tuple[str, ...] | None = None):
    matrix = load_matrix(MATRIX_V4_PATH)
    return replace(
        matrix,
        schema_version=MATRIX_SCHEMA_V5,
        cleanup_paths=cleanup_paths or matrix.cleanup_paths,
        formal_runtime_paths={
            "home": ".tmp/apq-05/runtime/h",
            "pre_commit_home": ".tmp/apq-05/runtime/p",
            "temp": ".tmp/apq-05/runtime/t",
        },
    )


def _bind_cli_artifact_paths(cli, monkeypatch, output_root: Path) -> None:
    replacements = {
        "OUTPUT_ROOT": output_root,
        "RUNTIME_ROOT": output_root / "runtime",
        "STAGE_LOG_ROOT": output_root / "stages",
        "PREFLIGHT_PATH": output_root / "preflight.json",
        "STAGE_RESULTS_PATH": output_root / "stage-results.json",
        "EVENTS_PATH": output_root / "events.jsonl",
        "BUNDLE_PATH": output_root / "qualification-bundle.json",
        "FORCED_G2_RETAINED": output_root / "forced-g2-verification.json",
        "RUNTIME_COORDINATE_SNAPSHOT": output_root / "runtime-coordinate-snapshot.json",
    }
    for name, value in replacements.items():
        monkeypatch.setattr(cli, name, value)


def _optional_file_snapshot(path: Path) -> tuple[bool, bytes | None]:
    return path.exists(), path.read_bytes() if path.is_file() else None


def _v5_volume_inspect_rows(
    *,
    missing: str | None = None,
    project_override: str | None = None,
    driver_override: str | None = None,
) -> str:
    rows = []
    for name, volume_key in V5_DEFAULT_VOLUMES:
        if name == missing:
            continue
        rows.append(
            "\t".join(
                (
                    name,
                    driver_override or "local",
                    project_override or "redagent-local",
                    volume_key,
                )
            )
        )
    return "".join(f"{row}\n" for row in rows)


def _preflight(matrix, projection) -> dict[str, object]:
    return verify_preflight(
        matrix,
        projection,
        observed_commit=projection.candidate_commit,
        observed_tree=projection.candidate_tree,
        observed_parent=projection.candidate_parent_commit,
        observed_branch="dev",
        worktree_clean=True,
        observed_source_sha256=projection.source_sha256,
        observed_environment={
            "platform": projection.platform,
            "architecture": projection.architecture,
            "python_version": projection.python_version,
            "node_version": projection.node_version,
        },
    )


def _stage_log_payloads(matrix) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for stage in matrix.stages:
        payloads[f"stages/{stage.stage_id}.stdout.log"] = f"{stage.stage_id}: passed\n".encode()
        payloads[f"stages/{stage.stage_id}.stderr.log"] = b""
        for artifact in stage.expected_artifacts:
            payloads[artifact] = b'{"fixture":"retained"}\n'
    payloads["forced-g2-verification.json"] = b'{"aggregate_result":"passed"}\n'
    return payloads


def _passed_stage_results(matrix, payloads: dict[str, bytes]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for stage in matrix.stages:
        stdout_path = f"stages/{stage.stage_id}.stdout.log"
        stderr_path = f"stages/{stage.stage_id}.stderr.log"
        results.append(
            create_stage_result(
                stage,
                status="passed",
                exit_code=0,
                passed_count=stage.expected_pass_count,
                skipped_count=stage.allowed_skip_count,
                stdout_sha256=hashlib.sha256(payloads[stdout_path]).hexdigest(),
                stderr_sha256=hashlib.sha256(payloads[stderr_path]).hexdigest(),
                artifact_sha256={path: hashlib.sha256(payloads[path]).hexdigest() for path in stage.expected_artifacts},
                unapproved_assessment_contacts=0,
                cleanup_complete=True,
                detail="all_fixed_runner_contracts_passed",
            )
        )
    return results


def _events(matrix, projection, preflight, stage_results, result):
    inputs = [
        ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
        ("attempt_started", {"attempt_id": projection.attempt_id}),
    ]
    inputs.extend(
        (
            "stage_completed",
            {
                "stage_id": stage.stage_id,
                "stage_result_sha256": stage_result["stage_result_sha256"],
            },
        )
        for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
    )
    inputs.append(("attempt_terminal", {"result_sha256": result["result_sha256"]}))
    return build_event_chain(inputs, expected_stage_ids=[stage.stage_id for stage in matrix.stages])


def _accepted_ceremony():
    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    payloads = _stage_log_payloads(matrix)
    stage_results = _passed_stage_results(matrix, payloads)
    result = compute_disposition(matrix, stage_results, protocol_drift=False, artifacts_complete=True)
    events = _events(matrix, projection, preflight, stage_results, result)
    payloads.update(
        {
            "preflight.json": canonical_bytes(preflight) + b"\n",
            "stage-results.json": canonical_bytes(stage_results) + b"\n",
            "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in events),
        }
    )
    artifact_sha256 = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(payloads.items())}
    bundle = build_bundle(
        matrix,
        projection,
        preflight,
        stage_results,
        artifact_sha256,
        events,
        protocol_drift=False,
    )
    pin_body = {
        "schema_version": PINS_SCHEMA,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "private_manifest_sha256": projection.private_manifest_sha256,
        "trust_anchor_sha256": projection.trust_anchor_sha256,
    }
    pins = {**pin_body, "pins_sha256": canonical_sha256(pin_body)}
    return matrix, projection, preflight, payloads, stage_results, events, bundle, pins


def _accepted_ceremony_for(matrix_path: Path):
    matrix = load_matrix(matrix_path)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    payloads = _stage_log_payloads(matrix)
    stage_results = _passed_stage_results(matrix, payloads)
    result = compute_disposition(matrix, stage_results, protocol_drift=False, artifacts_complete=True)
    events = _events(matrix, projection, preflight, stage_results, result)
    payloads.update(
        {
            "preflight.json": canonical_bytes(preflight) + b"\n",
            "stage-results.json": canonical_bytes(stage_results) + b"\n",
            "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in events),
        }
    )
    artifact_sha256 = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(payloads.items())}
    bundle = build_bundle(
        matrix,
        projection,
        preflight,
        stage_results,
        artifact_sha256,
        events,
        protocol_drift=False,
    )
    return matrix, projection, events, bundle


def _rehash_projection(payload: dict[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "projection_sha256"}
    payload["projection_sha256"] = canonical_sha256(body)


def test_matrix_is_source_pinned_closed_and_complete() -> None:
    matrix = load_matrix(MATRIX_PATH)

    assert matrix.max_concurrency == 1
    assert matrix.required_score_basis_points == 10_000
    assert matrix.conditional_allowlist == ()
    assert matrix.allowed_target_hosts == ("127.0.0.1", "::1", "localhost")
    assert dict(matrix.formal_environment) == EXPECTED_FORMAL_ENVIRONMENT
    assert matrix.validation_dependency_runner_ids == ("windows-full-gate",)
    assert len(matrix.accepted_predecessors) == 8
    assert len(matrix.stages) == 7
    assert matrix.retained_artifacts == tuple(sorted(matrix.retained_artifacts))


def test_v2_matrix_is_fresh_closed_and_binds_runner_and_runtime_environments() -> None:
    matrix = load_matrix(MATRIX_V2_PATH)

    assert matrix.schema_version == MATRIX_SCHEMA_V2
    expected_parent = "07255fae5ae9f899a79e0c5b9cbe33c863c056e8"  # pragma: allowlist secret
    assert matrix.candidate_parent_commit == expected_parent
    assert len(matrix.stages) == 8
    assert [stage.stage_id for stage in matrix.stages][3:6] == [
        "windows-full-gate",
        "runtime-coordinate-snapshot",
        "owned-runtime-cleanup",
    ]
    assert dict(matrix.runner_environment["pytest-authority-to-terminal"]) == {
        "REDAGENT_R159_LIVE_QUALIFICATION": "owned-loopback-zap-v1"
    }
    assert all(
        not environment
        for runner_id, environment in matrix.runner_environment.items()
        if runner_id != "pytest-authority-to-terminal"
    )
    assert set(matrix.formal_runtime_paths) == {"home", "pre_commit_home", "temp"}
    assert all(
        path.startswith(".tmp/autonomous-planner-qualification-attempt-02/runtime/")
        for path in (*matrix.formal_runtime_paths.values(), *matrix.cleanup_paths)
    )
    assert matrix.stages[0].expected_pass_count == 262
    assert all(stage.allowed_skip_count == 0 for stage in matrix.stages)
    assert "runtime-coordinate-snapshot.json" in matrix.retained_artifacts

    _matrix, _projection_value, events, bundle = _accepted_ceremony_for(MATRIX_V2_PATH)
    assert len(events) == len(matrix.stages) + 3
    assert bundle["result"]["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED


def test_v3_matrix_adds_owned_provisioning_and_uses_only_product_semantic_authority() -> None:
    matrix = load_matrix(MATRIX_V3_PATH)

    assert matrix.schema_version == MATRIX_SCHEMA_V3
    expected_parent = "302bcab86aad22e4d48bcc1fe0a0fa429667cd77"  # pragma: allowlist secret
    assert matrix.candidate_parent_commit == expected_parent
    assert len(matrix.stages) == 9
    assert [stage.stage_id for stage in matrix.stages][3:7] == [
        "windows-full-gate",
        "owned-runtime-provision",
        "runtime-coordinate-snapshot",
        "owned-runtime-cleanup",
    ]
    assert dict(matrix.runner_environment["pytest-authority-to-terminal"]) == {
        "REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION": "owned-loopback-zap-v1"
    }
    assert all(
        not environment
        for runner_id, environment in matrix.runner_environment.items()
        if runner_id != "pytest-authority-to-terminal"
    )
    assert set(matrix.formal_runtime_paths) == {"home", "pre_commit_home", "temp"}
    assert all(
        path.startswith(".tmp/autonomous-planner-qualification-attempt-03/runtime/")
        for path in (*matrix.formal_runtime_paths.values(), *matrix.cleanup_paths)
    )
    stages = {stage.result_kind: stage for stage in matrix.stages}
    assert matrix.stages[0].expected_pass_count == 266
    assert stages["provision"].expected_pass_count == 3
    assert all(stage.allowed_skip_count == 0 for stage in matrix.stages)
    assert "config/validation/autonomous-planner-qualification-v3.json" in matrix.source_paths

    _matrix, _projection_value, events, bundle = _accepted_ceremony_for(MATRIX_V3_PATH)
    assert len(events) == len(matrix.stages) + 3
    assert bundle["result"]["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED


def test_v4_matrix_uses_only_the_short_windows_safe_runtime_and_preserves_v3_lifecycle() -> None:
    matrix = load_matrix(MATRIX_V4_PATH)

    assert matrix.schema_version == MATRIX_SCHEMA_V4
    expected_parent = "4a9887119258fbc10d6cca28ced7014e1a7089f1"  # pragma: allowlist secret
    assert matrix.candidate_parent_commit == expected_parent
    assert len(matrix.stages) == 9
    assert [stage.stage_id for stage in matrix.stages][3:7] == [
        "windows-full-gate",
        "owned-runtime-provision",
        "runtime-coordinate-snapshot",
        "owned-runtime-cleanup",
    ]
    assert dict(matrix.runner_environment["pytest-authority-to-terminal"]) == {
        "REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION": "owned-loopback-zap-v1"
    }
    assert dict(matrix.formal_runtime_paths) == {
        "home": ".tmp/apq-04/runtime/h",
        "pre_commit_home": ".tmp/apq-04/runtime/p",
        "temp": ".tmp/apq-04/runtime/t",
    }
    assert all(path.startswith(".tmp/apq-04/runtime/") for path in matrix.cleanup_paths)
    assert "config/validation/autonomous-planner-qualification-v4.json" in matrix.source_paths
    assert matrix.stages[0].expected_pass_count == 281
    assert all(stage.allowed_skip_count == 0 for stage in matrix.stages)

    _matrix, _projection_value, events, bundle = _accepted_ceremony_for(MATRIX_V4_PATH)
    assert len(events) == len(matrix.stages) + 3
    assert bundle["result"]["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED


def test_v5_matrix_is_fresh_and_preserves_the_closed_nine_stage_authority() -> None:
    matrix = load_matrix(MATRIX_V5_PATH)

    assert matrix.schema_version == MATRIX_SCHEMA_V5
    assert matrix.candidate_parent_commit == "aa351e0b64aa7a0a2e58b03e4d896c9802e4d195"  # pragma: allowlist secret
    assert len(matrix.stages) == 9
    assert [stage.stage_id for stage in matrix.stages][3:7] == [
        "windows-full-gate",
        "owned-runtime-provision",
        "runtime-coordinate-snapshot",
        "owned-runtime-cleanup",
    ]
    assert dict(matrix.formal_runtime_paths) == {
        "home": ".tmp/apq-05/runtime/h",
        "pre_commit_home": ".tmp/apq-05/runtime/p",
        "temp": ".tmp/apq-05/runtime/t",
    }
    assert all(path.startswith(".tmp/apq-05/runtime/") for path in matrix.cleanup_paths)
    assert "config/validation/autonomous-planner-qualification-v5.json" in matrix.source_paths
    assert matrix.stages[0].expected_pass_count == 311
    assert all(stage.allowed_skip_count == 0 for stage in matrix.stages)

    _matrix, _projection_value, events, bundle = _accepted_ceremony_for(MATRIX_V5_PATH)
    assert len(events) == len(matrix.stages) + 3
    assert bundle["result"]["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED


def test_v6_matrix_is_fresh_and_preserves_v5_and_the_closed_nine_stage_authority() -> None:
    matrix = load_matrix(MATRIX_V6_PATH)

    assert matrix.schema_version == MATRIX_SCHEMA_V6
    assert matrix.candidate_parent_commit == "3baad647775fdbf302b405a951b0315beb029891"  # pragma: allowlist secret
    assert len(matrix.stages) == 9
    assert dict(matrix.formal_runtime_paths) == {
        "home": ".tmp/apq-06/runtime/h",
        "pre_commit_home": ".tmp/apq-06/runtime/p",
        "temp": ".tmp/apq-06/runtime/t",
    }
    assert all(path.startswith(".tmp/apq-06/runtime/") for path in matrix.cleanup_paths)
    assert "config/validation/autonomous-planner-qualification-v5.json" in matrix.source_paths
    assert "config/validation/autonomous-planner-qualification-v6.json" in matrix.source_paths
    assert len(matrix.source_paths) == 44
    assert matrix.stages[0].expected_pass_count == 316
    assert all(stage.allowed_skip_count == 0 for stage in matrix.stages)

    _matrix, _projection_value, events, bundle = _accepted_ceremony_for(MATRIX_V6_PATH)
    assert len(events) == len(matrix.stages) + 3
    assert bundle["result"]["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED


def test_coherently_rehashed_matrix_drift_still_fails_the_trusted_digest() -> None:
    for path in (
        MATRIX_PATH,
        MATRIX_V2_PATH,
        MATRIX_V3_PATH,
        MATRIX_V4_PATH,
        MATRIX_V5_PATH,
        MATRIX_V6_PATH,
    ):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["max_concurrency"] = 2
        body = {key: value for key, value in payload.items() if key != "matrix_sha256"}
        payload["matrix_sha256"] = canonical_sha256(body)

        with pytest.raises(QualificationError, match="trusted matrix digest mismatch"):
            parse_matrix(payload)


def test_json_decoder_rejects_duplicates_bom_empty_and_unbounded_nesting() -> None:
    with pytest.raises(QualificationError, match="duplicate JSON field"):
        decode_json_bytes(b'{"field":1,"field":2}', label="fixture", maximum_bytes=100)
    with pytest.raises(QualificationError, match="byte contract"):
        decode_json_bytes(b"", label="fixture", maximum_bytes=100)
    with pytest.raises(QualificationError, match="byte contract"):
        decode_json_bytes(b"\xef\xbb\xbf{}", label="fixture", maximum_bytes=100)
    nested = b"[" * 18 + b"0" + b"]" * 18
    with pytest.raises(QualificationError, match="nesting"):
        decode_json_bytes(nested, label="fixture", maximum_bytes=100)


def test_projection_denies_target_runner_identity_and_candidate_lineage_drift() -> None:
    matrix = load_matrix(MATRIX_PATH)
    payload = _projection_payload(matrix)

    cases = (
        ("target_hosts", ["example.com"]),
        ("runner_ids", [stage.runner_id for stage in reversed(matrix.stages)]),
        ("candidate_parent_commit", "f" * 40),
        ("reviewer_identity_sha256", payload["operator_identity_sha256"]),
        (
            "formal_environment",
            {**dict(matrix.formal_environment), "REDAGENT_OPA_HOST_PORT": "9999"},
        ),
    )
    for field, value in cases:
        mutated = deepcopy(payload)
        mutated[field] = value
        _rehash_projection(mutated)
        with pytest.raises(QualificationError):
            parse_projection(mutated, matrix)


@pytest.mark.parametrize(
    "matrix_path",
    [MATRIX_V2_PATH, MATRIX_V3_PATH, MATRIX_V4_PATH, MATRIX_V5_PATH, MATRIX_V6_PATH],
)
def test_runtime_bound_projection_denies_runner_runtime_and_snapshot_input_drift(
    matrix_path: Path,
) -> None:
    matrix = load_matrix(matrix_path)
    payload = _projection_payload(matrix)
    authority_key = next(iter(matrix.runner_environment["pytest-authority-to-terminal"]))
    cases = (
        (
            "runner_environment",
            {**payload["runner_environment"], "windows-full-gate": {authority_key: "owned-loopback-zap-v1"}},
        ),
        (
            "formal_runtime_paths",
            {**payload["formal_runtime_paths"], "temp": "../outside"},
        ),
        ("residual_ports", [58191]),
    )
    for field, value in cases:
        mutated = deepcopy(payload)
        mutated[field] = value
        _rehash_projection(mutated)
        with pytest.raises(QualificationError):
            parse_projection(mutated, matrix)


def test_preflight_requires_exact_clean_direct_successor_on_windows_dev() -> None:
    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)

    assert preflight["branch"] == "dev"
    assert preflight["worktree_clean"] is True
    assert preflight["formal_run_authority"] is False
    assert preflight["remote_authority"] is False
    with pytest.raises(QualificationError, match="exact clean candidate preflight failed"):
        verify_preflight(
            matrix,
            projection,
            observed_commit=projection.candidate_commit,
            observed_tree=projection.candidate_tree,
            observed_parent=projection.candidate_parent_commit,
            observed_branch="main",
            worktree_clean=True,
            observed_source_sha256=projection.source_sha256,
            observed_environment={
                "platform": projection.platform,
                "architecture": projection.architecture,
                "python_version": projection.python_version,
                "node_version": projection.node_version,
            },
        )


def test_disposition_is_all_or_nothing_and_never_grants_authority() -> None:
    matrix, _projection_value, _preflight_value, payloads, stage_results, *_rest = _accepted_ceremony()
    accepted = compute_disposition(matrix, stage_results, protocol_drift=False)

    assert accepted["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED
    assert accepted["score_basis_points"] == 10_000
    assert accepted["execution_authority"] is False
    assert accepted["remote_authority"] is False
    failed_results = deepcopy(stage_results)
    stage = matrix.stages[0]
    stdout_path = f"stages/{stage.stage_id}.stdout.log"
    stderr_path = f"stages/{stage.stage_id}.stderr.log"
    failed_results[0] = create_stage_result(
        stage,
        status="failed",
        exit_code=1,
        passed_count=stage.expected_pass_count,
        skipped_count=0,
        stdout_sha256=hashlib.sha256(payloads[stdout_path]).hexdigest(),
        stderr_sha256=hashlib.sha256(payloads[stderr_path]).hexdigest(),
        artifact_sha256={},
        unapproved_assessment_contacts=0,
        cleanup_complete=False,
        detail="mandatory_fixed_runner_or_result_contract_failed",
    )
    assert compute_disposition(matrix, failed_results, protocol_drift=False)["disposition"] == NOT_QUALIFIED
    assert compute_disposition(matrix, [], protocol_drift=True)["disposition"] == ABORTED


def test_accepted_bundle_verifies_offline_against_exact_payloads_and_pins() -> None:
    matrix, projection, _preflight_value, payloads, _stage_results, _events_value, bundle, pins = _accepted_ceremony()

    verified = verify_bundle(matrix, projection, bundle, pins, payloads)

    assert verified["verified"] is True
    assert verified["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED
    assert verified["execution_authority"] is False
    assert verified["release_authority"] is False
    assert verified["ga_authority"] is False


def test_offline_verifier_rejects_artifact_bytes_or_pin_tamper() -> None:
    matrix, projection, _preflight_value, payloads, _stage_results, _events_value, bundle, pins = _accepted_ceremony()
    tampered_payloads = dict(payloads)
    tampered_payloads["preflight.json"] += b" "
    with pytest.raises(QualificationError, match="offline artifact digest mismatch"):
        verify_bundle(matrix, projection, bundle, pins, tampered_payloads)

    tampered_pins = dict(pins)
    tampered_pins["candidate_tree"] = "f" * 40
    with pytest.raises(QualificationError, match="pins digest mismatch"):
        verify_bundle(matrix, projection, bundle, tampered_pins, payloads)


def test_bundle_builder_rejects_cross_attempt_log_event_and_preflight_splicing() -> None:
    matrix, projection, preflight, payloads, stage_results, events, _bundle, _pins = _accepted_ceremony()
    artifact_sha256 = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(payloads.items())}

    spliced_results = deepcopy(stage_results)
    body = {key: value for key, value in spliced_results[0].items() if key != "stage_result_sha256"}
    body["stdout_sha256"] = ZERO_SHA
    spliced_results[0] = {**body, "stage_result_sha256": canonical_sha256(body)}
    result = compute_disposition(matrix, spliced_results, protocol_drift=False)
    spliced_events = _events(matrix, projection, preflight, spliced_results, result)
    spliced_payloads = dict(payloads)
    spliced_payloads["stage-results.json"] = canonical_bytes(spliced_results) + b"\n"
    spliced_payloads["events.jsonl"] = b"".join(canonical_bytes(event) + b"\n" for event in spliced_events)
    spliced_digests = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(spliced_payloads.items())}
    with pytest.raises(QualificationError, match="stdout binding mismatch"):
        build_bundle(
            matrix,
            projection,
            preflight,
            spliced_results,
            spliced_digests,
            spliced_events,
            protocol_drift=False,
        )

    wrong_events = build_event_chain(
        [
            ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
            ("attempt_started", {"attempt_id": "another-attempt"}),
            *(
                (
                    "stage_completed",
                    {
                        "stage_id": stage.stage_id,
                        "stage_result_sha256": stage_result["stage_result_sha256"],
                    },
                )
                for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
            ),
            (
                "attempt_terminal",
                {"result_sha256": compute_disposition(matrix, stage_results, protocol_drift=False)["result_sha256"]},
            ),
        ],
        expected_stage_ids=[stage.stage_id for stage in matrix.stages],
    )
    wrong_payloads = dict(payloads)
    wrong_payloads["events.jsonl"] = b"".join(canonical_bytes(event) + b"\n" for event in wrong_events)
    wrong_digests = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(wrong_payloads.items())}
    with pytest.raises(QualificationError, match="event payload binding mismatch"):
        build_bundle(
            matrix,
            projection,
            preflight,
            stage_results,
            wrong_digests,
            wrong_events,
            protocol_drift=False,
        )

    spliced_preflight = dict(preflight)
    preflight_body = {key: value for key, value in spliced_preflight.items() if key != "preflight_sha256"}
    preflight_body["remote_authority"] = True
    spliced_preflight = {**preflight_body, "preflight_sha256": canonical_sha256(preflight_body)}
    with pytest.raises(QualificationError, match="authority binding mismatch"):
        build_bundle(
            matrix,
            projection,
            spliced_preflight,
            stage_results,
            artifact_sha256,
            events,
            protocol_drift=False,
        )


def test_event_chain_rejects_missing_reordered_or_tampered_lifecycle() -> None:
    matrix, projection, preflight, _payloads, stage_results, events, _bundle, _pins = _accepted_ceremony()
    result = compute_disposition(matrix, stage_results, protocol_drift=False)
    with pytest.raises(QualificationError, match="formal event lifecycle invalid"):
        build_event_chain(
            [
                ("attempt_started", {"attempt_id": projection.attempt_id}),
                ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
                *((events[index]["kind"], events[index]["payload"]) for index in range(2, len(events) - 1)),
                ("attempt_terminal", {"result_sha256": result["result_sha256"]}),
            ],
            expected_stage_ids=[stage.stage_id for stage in matrix.stages],
        )


def test_cli_surface_has_only_fixed_commands_and_no_operator_target_input() -> None:
    from scripts import autonomous_planner_qualification as cli

    assert cli.MATRIX_PATH.name == "autonomous-planner-qualification-v6.json"
    assert cli.OUTPUT_ROOT.relative_to(cli.ROOT).as_posix() == ".tmp/apq-06"
    assert cli.build_parser().parse_args(["preflight"]).command == "preflight"
    assert cli.build_parser().parse_args(["run"]).command == "run"
    assert cli.build_parser().parse_args(["verify"]).command == "verify"
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run", "--target", "https://example.com"])
    commands = cli._runner_commands("pytest-authority-to-terminal", "1" * 40, "2" * 40)
    assert commands[0][1:3] == ("-m", "pytest")
    assert (
        "--deselect=tests/unit/test_planner_evidence.py::test_file_symlink_artifact_fails_before_parsing" in commands[0]
    )
    assert all("http://" not in argument and "https://" not in argument for command in commands for argument in command)
    with pytest.raises(QualificationError, match="unknown qualification runner"):
        cli._runner_commands("operator-selected", "1" * 40, "2" * 40)

    cleanup = cli._runner_commands("owned-runtime-cleanup", "1" * 40, "2" * 40)
    assert [Path(command[1]).name for command in cleanup] == [
        "openbao_conformance.py",
        "opa_conformance.py",
        "redagent_local_stack.py",
    ]
    provision = cli._runner_commands("owned-runtime-provision", "1" * 40, "2" * 40)
    assert [Path(command[1]).name for command in provision] == [
        "redagent_local_stack.py",
        "openbao_conformance.py",
        "opa_conformance.py",
    ]
    assert [command[2] for command in provision] == ["start", "provision", "provision"]


def test_cli_real_input_loader_binds_the_exact_current_matrix(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    workspace = tmp_path / "workspace"
    matrix_path = workspace / "config/validation/autonomous-planner-qualification-v6.json"
    matrix_path.parent.mkdir(parents=True)
    shutil.copyfile(MATRIX_V6_PATH, matrix_path)
    matrix = load_matrix(matrix_path)
    projection = _projection_payload(matrix)
    output_root = workspace / ".tmp/apq-06"
    output_root.mkdir(parents=True)
    projection_path = output_root / "execution-projection.json"
    projection_path.write_text(json.dumps(projection), encoding="utf-8")
    pins_body = {
        "schema_version": PINS_SCHEMA,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection["projection_sha256"],
        "candidate_commit": projection["candidate_commit"],
        "candidate_tree": projection["candidate_tree"],
        "private_manifest_sha256": projection["private_manifest_sha256"],
        "trust_anchor_sha256": projection["trust_anchor_sha256"],
    }
    pins_path = output_root / "verification-pins.json"
    pins_path.write_text(
        json.dumps({**pins_body, "pins_sha256": canonical_sha256(pins_body)}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "ROOT", workspace)
    monkeypatch.setattr(cli, "MATRIX_PATH", matrix_path)
    monkeypatch.setattr(cli, "PROJECTION_PATH", projection_path)
    monkeypatch.setattr(cli, "PINS_PATH", pins_path)

    loaded_matrix, loaded_projection, loaded_pins = cli._load_inputs()

    assert loaded_matrix.schema_version == MATRIX_SCHEMA_V6
    assert loaded_projection.projection_sha256 == projection["projection_sha256"]
    assert loaded_pins["pins_sha256"] == canonical_sha256(pins_body)


def test_v4_full_gate_stage_appends_fixed_transition_resets_without_changing_v3(monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    monkeypatch.setattr(cli, "_tool", lambda name: name)
    v4 = load_matrix(MATRIX_V4_PATH)
    v4_projection = _projection(v4)
    v4_stage = next(stage for stage in v4.stages if stage.runner_id == "windows-full-gate")
    commands = cli._stage_commands(v4_stage, v4, v4_projection)

    assert len(commands) == 5
    assert Path(commands[0][3]).name == "run_full_tests_windows.ps1"
    assert Path(commands[1][1]).name == "run_validation_gate.py"
    assert [Path(command[1]).name for command in commands[2:]] == [
        "openbao_conformance.py",
        "opa_conformance.py",
        "redagent_local_stack.py",
    ]
    assert [command[2] for command in commands[2:]] == ["reset", "reset", "reset"]

    v3 = load_matrix(MATRIX_V3_PATH)
    v3_projection = _projection(v3)
    v3_stage = next(stage for stage in v3.stages if stage.runner_id == "windows-full-gate")
    assert len(cli._stage_commands(v3_stage, v3, v3_projection)) == 2


@pytest.mark.parametrize("matrix_path", [MATRIX_V5_PATH, MATRIX_V6_PATH])
def test_v5_v6_full_gate_stage_preserves_the_v4_fixed_transition_commands(
    matrix_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    monkeypatch.setattr(cli, "_tool", lambda name: name)
    matrix = load_matrix(matrix_path)
    projection = _projection(matrix)
    stage = next(stage for stage in matrix.stages if stage.runner_id == "windows-full-gate")
    commands = cli._stage_commands(stage, matrix, projection)

    assert len(commands) == 5
    assert Path(commands[0][3]).name == "run_full_tests_windows.ps1"
    assert Path(commands[1][1]).name == "run_validation_gate.py"
    assert [Path(command[1]).name for command in commands[2:]] == [
        "openbao_conformance.py",
        "opa_conformance.py",
        "redagent_local_stack.py",
    ]
    assert [command[2] for command in commands[2:]] == ["reset", "reset", "reset"]


def test_v4_full_gate_transition_failure_aborts_before_stage_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    projection = _projection(matrix)
    stage = next(stage for stage in matrix.stages if stage.runner_id == "windows-full-gate")
    historical_retained = cli.FORCED_G2_RETAINED
    historical_snapshot = _optional_file_snapshot(historical_retained)
    _bind_cli_artifact_paths(cli, monkeypatch, tmp_path / "apq-04-test")
    monkeypatch.setattr(cli, "_stage_commands", lambda *_args: (("fixed", "command"),))

    def successful_commands(_commands, observed_stage, _matrix):
        stdout_path, stderr_path = cli._stage_log_paths(observed_stage)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text("fixed commands passed\n", encoding="utf-8")
        stderr_path.write_bytes(b"")
        return 1, False

    monkeypatch.setattr(cli, "_run_processes", successful_commands)
    transition_calls: list[str] = []

    def fail_transition(_matrix, _stdout_path):
        transition_calls.append("transition")
        raise QualificationError("formal Full Gate transition readiness failed")

    monkeypatch.setattr(cli, "_complete_v4_full_gate_transition", fail_transition)

    with pytest.raises(QualificationError, match="transition readiness failed"):
        cli._execute_stage(stage, matrix, projection)
    assert transition_calls == ["transition"]
    assert _optional_file_snapshot(historical_retained) == historical_snapshot


def test_v4_start_readiness_rejects_persisted_owned_state(tmp_path: Path, monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    (tmp_path / ".local/redagent").mkdir(parents=True)
    monkeypatch.setattr(cli, "ROOT", tmp_path)

    with pytest.raises(QualificationError, match="formal start owned state is present"):
        cli._assert_formal_start_ready(matrix)


def test_v4_start_readiness_rejects_any_declared_listener(tmp_path: Path, monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_port_closed", lambda port: port != 55472)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, **_kwargs: cli.subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    with pytest.raises(QualificationError, match="formal start declared port is open"):
        cli._assert_formal_start_ready(matrix)


@pytest.mark.parametrize("inventory", ["container", "network", "volume"])
def test_v4_start_readiness_rejects_exact_owned_docker_markers(
    inventory: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_port_closed", lambda _port: True)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    marker = f"{cli._workspace_compose_project('redagent-opa')}-opa-1"

    def docker(command, **_kwargs):
        observed_inventory = (
            "container"
            if command[1:3] == ("ps", "-a")
            else "network"
            if command[1:3] == ("network", "ls")
            else "volume"
        )
        selected = inventory == observed_inventory
        return cli.subprocess.CompletedProcess(
            command,
            0,
            stdout=f"{marker}\n" if selected else "",
            stderr="",
        )

    monkeypatch.setattr(cli.subprocess, "run", docker)
    with pytest.raises(QualificationError, match="formal start owned Docker resource is present"):
        cli._assert_formal_start_ready(matrix)


@pytest.mark.parametrize("failure", ["exit", "malformed"])
def test_v4_start_readiness_fails_closed_on_untrusted_docker_inventory(
    failure: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_port_closed", lambda _port: True)
    monkeypatch.setattr(cli, "_tool", lambda name: name)

    def docker(command, **_kwargs):
        if failure == "exit":
            return cli.subprocess.CompletedProcess(command, 1, stdout="", stderr="unavailable")
        return cli.subprocess.CompletedProcess(command, 0, stdout="invalid docker name\n", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", docker)
    with pytest.raises(QualificationError, match="formal start Docker inventory invalid"):
        cli._assert_formal_start_ready(matrix)


def test_v4_start_readiness_ignores_other_workspace_resources_and_checks_six_ports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    probed: list[int] = []

    def closed(port: int) -> bool:
        probed.append(port)
        return True

    monkeypatch.setattr(cli, "_port_closed", closed)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, **_kwargs: cli.subprocess.CompletedProcess(
            command,
            0,
            stdout="redagent-opa-ffffffffffffffff-opa-1\nunrelated_default\n",
            stderr="",
        ),
    )

    cli._assert_formal_start_ready(matrix)
    assert sorted(probed) == [55472, 57273, 58090, 58191, 58200, 59010]


def test_v5_start_readiness_denies_exact_default_project_without_deleting_it(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_port_closed", lambda _port: True)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    commands: list[tuple[str, ...]] = []

    def docker(command, **_kwargs):
        commands.append(tuple(command))
        is_volume_inventory = command[1:3] == ("volume", "ls")
        return cli.subprocess.CompletedProcess(
            command,
            0,
            stdout="redagent-local-postgres-data\n" if is_volume_inventory else "",
            stderr="",
        )

    monkeypatch.setattr(cli.subprocess, "run", docker)
    with pytest.raises(QualificationError, match="formal start owned Docker resource is present"):
        cli._assert_formal_start_ready(matrix)
    assert all(command[1:3] != ("volume", "rm") for command in commands)


def test_v5_post_gate_volume_cleanup_prevalidates_all_four_then_removes_exact_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    remaining = {name for name, _volume_key in V5_DEFAULT_VOLUMES} | {"other-workspace-data"}
    commands: list[tuple[str, ...]] = []

    def docker(command, **_kwargs):
        command = tuple(command)
        commands.append(command)
        if command[1:4] == ("volume", "inspect", "--format"):
            return cli.subprocess.CompletedProcess(
                command,
                0,
                stdout=_v5_volume_inspect_rows(),
                stderr="",
            )
        if command[1:3] == ("ps", "-a"):
            return cli.subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[1:3] == ("volume", "rm"):
            name = command[3]
            assert name in remaining
            remaining.remove(name)
            return cli.subprocess.CompletedProcess(command, 0, stdout=f"{name}\n", stderr="")
        if command[1:4] == ("volume", "ls", "--format"):
            return cli.subprocess.CompletedProcess(
                command,
                0,
                stdout="".join(f"{name}\n" for name in sorted(remaining)),
                stderr="",
            )
        raise AssertionError(f"unexpected Docker command: {command}")

    monkeypatch.setattr(cli.subprocess, "run", docker)
    assert cli._remove_v5_default_full_gate_volumes(matrix) == 4
    removed = [command[3] for command in commands if command[1:3] == ("volume", "rm")]
    assert removed == [name for name, _volume_key in V5_DEFAULT_VOLUMES]
    first_remove = next(index for index, command in enumerate(commands) if command[1:3] == ("volume", "rm"))
    assert sum(command[1:3] == ("ps", "-a") for command in commands[:first_remove]) == 4
    assert remaining == {"other-workspace-data"}


def test_v5_post_gate_volume_cleanup_accepts_complete_all_absent_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    commands: list[tuple[str, ...]] = []

    def docker(command, **_kwargs):
        command = tuple(command)
        commands.append(command)
        if command[1:4] == ("volume", "ls", "--format"):
            return cli.subprocess.CompletedProcess(command, 0, stdout="other-workspace-data\n", stderr="")
        raise AssertionError(f"all-absent state must not inspect or remove: {command}")

    monkeypatch.setattr(cli.subprocess, "run", docker)
    assert cli._remove_v5_default_full_gate_volumes(matrix) == 0
    assert commands == [("docker", "volume", "ls", "--format", "{{.Name}}")]


@pytest.mark.parametrize("drift", ["missing", "malformed", "project", "driver", "attached", "unavailable"])
def test_v5_post_gate_volume_cleanup_aborts_before_any_removal_on_inventory_drift(
    drift: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_tool", lambda name: name)
    commands: list[tuple[str, ...]] = []

    def docker(command, **_kwargs):
        command = tuple(command)
        commands.append(command)
        if command[1:4] == ("volume", "ls", "--format"):
            if drift == "unavailable":
                return cli.subprocess.CompletedProcess(command, 1, stdout="", stderr="")
            names = [name for name, _volume_key in V5_DEFAULT_VOLUMES]
            if drift == "missing":
                names.pop()
            return cli.subprocess.CompletedProcess(
                command,
                0,
                stdout="".join(f"{name}\n" for name in names),
                stderr="",
            )
        if command[1:4] == ("volume", "inspect", "--format"):
            if drift == "malformed":
                stdout = "not-a-bounded-volume-row\n"
            else:
                stdout = _v5_volume_inspect_rows(
                    missing=V5_DEFAULT_VOLUMES[-1][0] if drift == "missing" else None,
                    project_override="other-project" if drift == "project" else None,
                    driver_override="other-driver" if drift == "driver" else None,
                )
            return cli.subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")
        if command[1:3] == ("ps", "-a"):
            attached = drift == "attached" and f"volume={V5_DEFAULT_VOLUMES[0][0]}" in command
            return cli.subprocess.CompletedProcess(command, 0, stdout=("a" * 64 + "\n") if attached else "", stderr="")
        if command[1:3] == ("volume", "rm"):
            raise AssertionError("volume removal must not start after ownership drift")
        raise AssertionError(f"unexpected Docker command: {command}")

    monkeypatch.setattr(cli.subprocess, "run", docker)
    with pytest.raises(QualificationError, match="default Full Gate volume"):
        cli._remove_v5_default_full_gate_volumes(matrix)
    assert all(command[1:3] != ("volume", "rm") for command in commands)


def test_v5_empty_state_root_cleanup_accepts_absent_or_exact_empty_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    assert cli._remove_v5_empty_state_root(matrix) == 0

    state_root = tmp_path / ".local/redagent"
    state_root.mkdir(parents=True)
    assert cli._remove_v5_empty_state_root(matrix) == 1
    assert not state_root.exists()


@pytest.mark.parametrize("drift", ["schema", "path", "file", "nonempty", "reparse"])
def test_v5_empty_state_root_cleanup_denies_ambiguous_state(
    drift: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    state_root = tmp_path / ".local/redagent"
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    if drift == "schema":
        matrix = replace(matrix, schema_version=MATRIX_SCHEMA_V4)
    elif drift == "path":
        matrix = replace(
            matrix,
            formal_environment={**matrix.formal_environment, "REDAGENT_STATE_DIR": ".local/other"},
        )
    elif drift == "file":
        state_root.parent.mkdir(parents=True)
        state_root.write_text("not a directory\n", encoding="utf-8")
    else:
        state_root.mkdir(parents=True)
        if drift == "nonempty":
            (state_root / "ambiguous").write_text("must remain\n", encoding="utf-8")
        else:
            monkeypatch.setattr(cli, "is_link_or_reparse", lambda path: path == state_root)

    with pytest.raises(QualificationError):
        cli._remove_v5_empty_state_root(matrix)
    if drift == "nonempty":
        assert (state_root / "ambiguous").read_text(encoding="utf-8") == "must remain\n"


def test_v5_full_gate_transition_orders_tree_then_volume_cleanup_before_readiness(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    stdout_path = tmp_path / "full-gate.stdout.log"
    stdout_path.write_bytes(b"gate passed\n")
    calls: list[str] = []
    monkeypatch.setattr(cli, "_remove_owned_zap_qualification_state", lambda: calls.append("zap") or 2)
    monkeypatch.setattr(cli, "_remove_item_runtime_paths", lambda _matrix: calls.append("runtime"))
    monkeypatch.setattr(cli, "_remove_v5_empty_state_root", lambda _matrix: calls.append("state-root") or 1)
    monkeypatch.setattr(
        cli,
        "_remove_v5_default_full_gate_volumes",
        lambda _matrix: calls.append("volumes") or 4,
    )
    monkeypatch.setattr(cli, "_assert_formal_start_ready", lambda _matrix: calls.append("ready"))

    cli._complete_v5_full_gate_transition(matrix, stdout_path)

    assert calls == ["zap", "runtime", "state-root", "volumes", "ready"]
    transition = json.loads(stdout_path.read_text(encoding="utf-8").splitlines()[-1])
    assert transition == {
        "formal_full_gate_transition_ready": True,
        "removed_default_full_gate_volumes": 4,
        "removed_empty_state_root": 1,
        "removed_qualification_receipts": 2,
    }


def test_v5_full_gate_transition_failure_aborts_before_stage_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = _v5_matrix()
    projection = _projection(load_matrix(MATRIX_V4_PATH))
    stage = next(stage for stage in matrix.stages if stage.runner_id == "windows-full-gate")
    historical_retained = cli.FORCED_G2_RETAINED
    historical_snapshot = _optional_file_snapshot(historical_retained)
    _bind_cli_artifact_paths(cli, monkeypatch, tmp_path / "apq-05-test")
    monkeypatch.setattr(cli, "_stage_commands", lambda *_args: (("fixed", "command"),))

    def successful_commands(_commands, observed_stage, _matrix):
        stdout_path, stderr_path = cli._stage_log_paths(observed_stage)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text("fixed commands passed\n", encoding="utf-8")
        stderr_path.write_bytes(b"")
        return 1, False

    monkeypatch.setattr(cli, "_run_processes", successful_commands)
    transition_calls: list[str] = []

    def fail_transition(_matrix, _stdout_path):
        transition_calls.append("transition")
        raise QualificationError("V5 formal Full Gate transition readiness failed")

    monkeypatch.setattr(cli, "_complete_v5_full_gate_transition", fail_transition, raising=False)
    with pytest.raises(QualificationError, match="V5 formal Full Gate transition readiness failed"):
        cli._execute_stage(stage, matrix, projection)
    assert transition_calls == ["transition"]
    assert _optional_file_snapshot(historical_retained) == historical_snapshot


@pytest.mark.parametrize("command_name", ["preflight", "run"])
def test_v4_preflight_and_initial_run_check_readiness_before_observation(
    command_name: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    projection = _projection(matrix)
    output_root = tmp_path / ".tmp/apq-04"
    replacements = {
        "OUTPUT_ROOT": output_root,
        "RUNTIME_ROOT": output_root / "runtime",
        "STAGE_LOG_ROOT": output_root / "stages",
        "PREFLIGHT_PATH": output_root / "preflight.json",
        "STAGE_RESULTS_PATH": output_root / "stage-results.json",
        "EVENTS_PATH": output_root / "events.jsonl",
        "BUNDLE_PATH": output_root / "qualification-bundle.json",
        "FORCED_G2_RETAINED": output_root / "forced-g2-verification.json",
        "RUNTIME_COORDINATE_SNAPSHOT": output_root / "runtime-coordinate-snapshot.json",
    }
    for name, value in replacements.items():
        monkeypatch.setattr(cli, name, value)
    monkeypatch.setattr(cli, "_load_inputs", lambda: (matrix, projection, {}))
    calls: list[str] = []
    monkeypatch.setattr(cli, "_assert_formal_start_ready", lambda _matrix: calls.append("ready"))

    def stop_after_observation(*_args):
        calls.append("observe")
        raise QualificationError("stop before formal start")

    monkeypatch.setattr(cli, "_observe_preflight", stop_after_observation)

    with pytest.raises(QualificationError, match="stop before formal start"):
        getattr(cli, f"{command_name}_command")()
    assert calls == ["ready", "observe"]


def test_count_parser_is_capture_safe_for_every_output_kind() -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V4_PATH)
    stages = {stage.result_kind: stage for stage in matrix.stages}

    assert cli._parse_counts(stages["pytest"], "301 passed", None) == (301, 0)
    assert cli._parse_counts(stages["pytest"], "300 passed, 1 skipped", None) == (300, 1)
    assert cli._parse_counts(stages["vitest"], "Tests  11 passed", None) == (11, 0)
    assert cli._parse_counts(stages["playwright"], "8 passed (22.1s)", None) == (8, 0)
    assert cli._parse_counts(
        stages["forced-g2"],
        "ignored",
        {"stages": [{"status": "passed"}] * 22},
    ) == (22, 0)
    assert cli._parse_counts(stages["cleanup"], '{"ok": true}\n' * 4, None) == (4, 0)
    assert cli._parse_counts(stages["provision"], '{"ok": true}\n' * 3, None) == (3, 0)
    residual = '{"passed_check_count":9}'
    assert cli._parse_counts(stages["residual"], residual, None) == (9, 0)
    snapshot = '{"passed_check_count":1}'
    assert cli._parse_counts(stages["runtime-snapshot"], snapshot, None) == (1, 0)
    with pytest.raises(QualificationError, match="success-count evidence missing"):
        cli._parse_counts(stages["playwright"], "all good", None)


def test_formal_children_receive_only_the_source_pinned_redagent_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V2_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "STAGE_LOG_ROOT", tmp_path / "stages")
    monkeypatch.setenv("REDAGENT_COMPOSE_PROJECT_NAME", "ambient-project-must-not-survive")
    monkeypatch.setenv("RedAgent_Unexpected_Override", "must-not-survive")
    monkeypatch.setenv("PYTHONPATH", "poisoned")
    monkeypatch.setenv("PYTHONHOME", "poisoned")
    monkeypatch.setenv("PYTHONSAFEPATH", "1")
    captured: dict[str, object] = {}

    def fixed_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fixed_run)
    completed_count, launch_aborted = cli._run_processes(
        (("fixed-tool", "fixed-argument"),),
        matrix.stages[0],
        matrix,
    )

    assert completed_count == 1
    assert launch_aborted is False
    environment = captured["environment"]
    assert isinstance(environment, dict)
    observed = {key: value for key, value in environment.items() if key.upper().startswith("REDAGENT_")}
    assert observed == {
        **EXPECTED_FORMAL_ENVIRONMENT,
        "REDAGENT_R159_LIVE_QUALIFICATION": "owned-loopback-zap-v1",
    }
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "PYTHONSAFEPATH" not in environment
    assert "PYTHONPATH" not in environment
    assert "PYTHONHOME" not in environment
    runtime_root = tmp_path / ".tmp/autonomous-planner-qualification-attempt-02/runtime"
    assert Path(environment["TEMP"]).is_relative_to(runtime_root)
    assert environment["TMP"] == environment["TEMP"] == environment["TMPDIR"]
    assert Path(environment["PRE_COMMIT_HOME"]).is_relative_to(runtime_root)
    assert Path(environment["HOME"]).is_relative_to(runtime_root)

    captured.clear()
    completed_count, launch_aborted = cli._run_processes(
        (("fixed-tool", "fixed-argument"),),
        matrix.stages[1],
        matrix,
    )
    assert completed_count == 1
    assert launch_aborted is False
    second_environment = captured["environment"]
    assert isinstance(second_environment, dict)
    assert "REDAGENT_R159_LIVE_QUALIFICATION" not in second_environment


@pytest.mark.parametrize(
    "matrix_path",
    [MATRIX_V3_PATH, MATRIX_V4_PATH, MATRIX_V5_PATH, MATRIX_V6_PATH],
)
def test_product_semantic_formal_children_bind_authority_only_on_the_authority_runner(
    matrix_path: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(matrix_path)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("REDAGENT_R159_LIVE_QUALIFICATION", "must-not-survive")
    monkeypatch.setenv("REDAGENT_UNDECLARED", "must-not-survive")

    authority = cli._fixed_child_environment(matrix, matrix.stages[0])
    observed = {key: value for key, value in authority.items() if key.upper().startswith("REDAGENT_")}
    assert observed == {
        **EXPECTED_FORMAL_ENVIRONMENT,
        "REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION": "owned-loopback-zap-v1",
    }

    component = cli._fixed_child_environment(matrix, matrix.stages[1])
    assert "REDAGENT_AUTONOMOUS_PLANNER_LIVE_QUALIFICATION" not in component
    assert "REDAGENT_R159_LIVE_QUALIFICATION" not in component
    assert "REDAGENT_UNDECLARED" not in component


def test_fixed_child_environment_supports_nested_repository_imports_and_strips_poison(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V2_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("PYTHONPATH", "Z:/ambient-poison")
    monkeypatch.setenv("PYTHONSAFEPATH", "1")
    monkeypatch.setenv("REDAGENT_UNDECLARED", "must-not-survive")
    environment = cli._fixed_child_environment(matrix, matrix.stages[0])
    completed = cli.subprocess.run(
        (
            str(Path(cli.sys.executable).resolve()),
            "-c",
            "import redagent_platform; import scripts.autonomous_planner_qualification",
        ),
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert "PYTHONSAFEPATH" not in environment
    assert "PYTHONPATH" not in environment
    assert "REDAGENT_UNDECLARED" not in environment


def test_runtime_coordinate_snapshot_fails_closed_when_opa_coordinate_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    runtime = tmp_path / ".local/redagent/runtime"
    runtime.mkdir(parents=True)
    (runtime / "local-stack.env").write_text(
        "\n".join(
            (
                "REDAGENT_COMPOSE_PROJECT_NAME=redagent-planner-local",  # pragma: allowlist secret
                "REDAGENT_BIND_HOST=127.0.0.1",
                "REDAGENT_POSTGRES_PORT=55433",
                "REDAGENT_KEYCLOAK_PORT=58081",
                "REDAGENT_TEMPORAL_PORT=57234",
                "REDAGENT_RUSTFS_PORT=59001",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(
        cli,
        "RUNTIME_COORDINATE_SNAPSHOT",
        tmp_path / ".tmp/autonomous-planner-qualification-attempt-03/runtime-coordinate-snapshot.json",
    )

    with pytest.raises(QualificationError, match="qualification fixed file is unavailable"):
        cli._capture_runtime_coordinate_snapshot()


def test_runtime_coordinate_snapshot_is_closed_secret_free_and_workspace_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    runtime = tmp_path / ".local/redagent/runtime"
    opa = tmp_path / ".local/redagent/opa"
    runtime.mkdir(parents=True)
    opa.mkdir(parents=True)
    runtime_env = runtime / "local-stack.env"
    runtime_env.write_text(
        "\n".join(
            (
                "REDAGENT_COMPOSE_PROJECT_NAME=redagent-r164-local",  # pragma: allowlist secret
                "REDAGENT_BIND_HOST=127.0.0.1",
                "REDAGENT_POSTGRES_PORT=55433",
                "REDAGENT_KEYCLOAK_PORT=58081",
                "REDAGENT_TEMPORAL_PORT=57234",
                "REDAGENT_RUSTFS_PORT=59001",
                "AWS_SECRET_ACCESS_KEY=must-never-be-retained",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (opa / "opa-endpoint.json").write_text('{"port":58182}\n', encoding="utf-8")
    retained = tmp_path / ".tmp/autonomous-planner-qualification-attempt-02/runtime-coordinate-snapshot.json"
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "RUNTIME_COORDINATE_SNAPSHOT", retained)

    snapshot = cli._capture_runtime_coordinate_snapshot()

    encoded = canonical_bytes(snapshot)
    assert b"must-never-be-retained" not in encoded
    assert snapshot["local_stack"]["project_name"] == "redagent-r164-local"
    assert snapshot["ports"] == [55433, 57234, 58081, 58182, 58200, 59001]
    assert snapshot["opa"]["project_name"].startswith("redagent-opa-")
    assert snapshot["openbao"]["project_name"].startswith("redagent-openbao-")
    assert retained.read_bytes() == canonical_bytes(snapshot) + b"\n"

    runtime_env.write_text(runtime_env.read_text(encoding="utf-8") + "REDAGENT_POSTGRES_PORT=55434\n")
    retained.unlink()
    with pytest.raises(QualificationError, match="duplicate"):
        cli._capture_runtime_coordinate_snapshot()

    monkeypatch.setattr(
        cli,
        "is_link_or_reparse",
        lambda path: path.name == "local-stack.env",
    )
    with pytest.raises(QualificationError, match="link or reparse"):
        cli._capture_runtime_coordinate_snapshot()


def test_residual_report_uses_only_retained_actual_ports_and_owned_resource_markers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_V2_PATH)
    projection = _projection(matrix)
    runtime = tmp_path / ".local/redagent/runtime"
    opa = tmp_path / ".local/redagent/opa"
    runtime.mkdir(parents=True)
    opa.mkdir(parents=True)
    (runtime / "local-stack.env").write_text(
        "\n".join(
            (
                "REDAGENT_COMPOSE_PROJECT_NAME=redagent-r164-local",  # pragma: allowlist secret
                "REDAGENT_BIND_HOST=127.0.0.1",
                "REDAGENT_POSTGRES_PORT=55433",
                "REDAGENT_KEYCLOAK_PORT=58081",
                "REDAGENT_TEMPORAL_PORT=57234",
                "REDAGENT_RUSTFS_PORT=59001",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    (opa / "opa-endpoint.json").write_text('{"port":58182}\n', encoding="utf-8")
    retained = tmp_path / ".tmp/autonomous-planner-qualification-attempt-02/runtime-coordinate-snapshot.json"
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "OUTPUT_ROOT", retained.parent)
    monkeypatch.setattr(cli, "RUNTIME_COORDINATE_SNAPSHOT", retained)
    snapshot = cli._capture_runtime_coordinate_snapshot()
    monkeypatch.setattr(
        cli,
        "_git",
        lambda *args: {
            ("rev-parse", "HEAD"): projection.candidate_commit,
            ("rev-parse", "HEAD^{tree}"): projection.candidate_tree,
            ("status", "--porcelain", "--untracked-files=all"): "",
        }[args],
    )
    monkeypatch.setattr(cli, "_source_digests", lambda _matrix: dict(projection.source_sha256))
    probed: list[int] = []

    def closed(port: int) -> bool:
        probed.append(port)
        return True

    monkeypatch.setattr(cli, "_port_closed", closed)
    monkeypatch.setattr(cli, "_tool", lambda name: name)

    def docker(command, **_kwargs):
        assert command[1:3] in (("ps", "-a"), ("network", "ls"))
        return cli.subprocess.CompletedProcess(command, 0, stdout="unrelated-resource\n", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", docker)
    report = cli._residual_report(matrix, projection)

    assert report["cleanup_complete"] is True
    assert report["passed_check_count"] == report["required_check_count"] == 9
    assert sorted(probed) == snapshot["ports"]


def test_cli_atomic_writer_never_replaces_a_named_artifact(tmp_path: Path, monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    artifact = tmp_path / ".tmp/autonomous-planner-qualification/preflight.json"

    cli._atomic_write(artifact, b"first\n")

    with pytest.raises(QualificationError, match="output already exists"):
        cli._atomic_write(artifact, b"replacement\n")
    assert artifact.read_bytes() == b"first\n"


def test_declared_item_runtime_paths_are_removed_without_touching_other_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    output_root = tmp_path / ".tmp/autonomous-planner-qualification"
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "OUTPUT_ROOT", output_root)
    monkeypatch.setattr(cli, "RUNTIME_ROOT", output_root / "runtime")
    monkeypatch.setattr(cli, "STAGE_LOG_ROOT", output_root / "stages")
    for relative in matrix.cleanup_paths:
        owned_path = tmp_path / Path(relative)
        owned_path.mkdir(parents=True, exist_ok=True)
        (owned_path / "item-owned.txt").write_text("fixture", encoding="utf-8")
    unrelated = output_root / "preflight.json"
    unrelated.parent.mkdir(parents=True, exist_ok=True)
    unrelated.write_text("retained", encoding="utf-8")
    cli._remove_item_runtime_paths(matrix)
    assert all(not (tmp_path / Path(relative)).exists() for relative in matrix.cleanup_paths)
    assert unrelated.read_text(encoding="utf-8") == "retained"

    invocation_id = "invocation-planner-0123456789ab"
    digest = hashlib.sha256(invocation_id.encode("utf-8")).hexdigest()
    zap_runtime = tmp_path / ".local/redagent/r123-zap"
    run_root = zap_runtime / digest[:24]
    run_root.mkdir(parents=True)
    (run_root / "zap-report.json").write_text("fixture", encoding="utf-8")
    receipt = zap_runtime / f"receipt-{digest}.json"
    receipt.write_text(json.dumps({"invocation_id": invocation_id}), encoding="utf-8")
    unrelated_receipt = zap_runtime / "unrelated.keep"
    unrelated_receipt.write_text("preserve", encoding="utf-8")

    assert cli._remove_owned_zap_qualification_state() == 1
    assert not run_root.exists()
    assert not receipt.exists()
    assert unrelated_receipt.read_text(encoding="utf-8") == "preserve"


@pytest.mark.skipif(os.name != "nt", reason="Windows read-only deletion contract")
def test_v5_cleanup_clears_readonly_regular_file_only_inside_declared_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    relative = ".tmp/r167-v5-cleanup/runtime/t"
    cleanup_root = tmp_path / Path(relative)
    readonly_object = cleanup_root / ".git/objects/aa/0123456789abcdef"
    unrelated = tmp_path / ".tmp/r167-v5-cleanup/retained.txt"
    readonly_object.parent.mkdir(parents=True)
    readonly_object.write_bytes(b"synthetic-read-only-git-object\n")
    unrelated.write_text("retained", encoding="utf-8")
    os.chmod(readonly_object, stat.S_IREAD)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    matrix = _v5_matrix(cleanup_paths=(relative,))

    try:
        cli._remove_item_runtime_paths(matrix)
        assert not cleanup_root.exists()
        assert unrelated.read_text(encoding="utf-8") == "retained"
    finally:
        if readonly_object.exists():
            os.chmod(readonly_object, stat.S_IWRITE)
        if cleanup_root.exists():
            shutil.rmtree(cleanup_root)


def test_v4_cleanup_keeps_plain_rmtree_behavior(tmp_path: Path, monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    relative = ".tmp/r167-v4-compat/runtime/t"
    cleanup_root = tmp_path / Path(relative)
    cleanup_root.mkdir(parents=True)
    (cleanup_root / "fixture.txt").write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    matrix = replace(load_matrix(MATRIX_V4_PATH), cleanup_paths=(relative,))
    real_rmtree = cli.shutil.rmtree
    calls: list[dict[str, object]] = []

    def observed_rmtree(path, *args, **kwargs):
        calls.append(dict(kwargs))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(cli.shutil, "rmtree", observed_rmtree)
    cli._remove_item_runtime_paths(matrix)
    assert calls == [{}]


@pytest.mark.parametrize(
    "drift",
    ["escape", "function", "exception", "writable", "nonregular", "reparse", "nonwindows"],
)
def test_v5_cleanup_refuses_every_callback_or_ownership_drift(
    drift: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    relative = ".tmp/r167-v5-denial/runtime/t"
    cleanup_root = tmp_path / Path(relative)
    owned = cleanup_root / ".git/objects/aa/owned"
    outside = tmp_path / ".tmp/r167-v5-denial/outside"
    owned.parent.mkdir(parents=True)
    owned.write_bytes(b"owned\n")
    outside.write_bytes(b"outside\n")
    os.chmod(owned, stat.S_IREAD)
    os.chmod(outside, stat.S_IREAD)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    matrix = _v5_matrix(cleanup_paths=(relative,))
    if drift == "reparse":
        monkeypatch.setattr(cli, "is_link_or_reparse", lambda path: Path(path) == owned.parent)
    if drift == "nonwindows":
        monkeypatch.setattr(cli.platform, "system", lambda: "Linux")

    def denied_rmtree(_path, *, onerror=None):
        assert onerror is not None
        failed = outside if drift == "escape" else owned.parent if drift == "nonregular" else owned
        function = os.rmdir if drift == "function" else os.unlink
        error: BaseException = OSError("unexpected") if drift == "exception" else PermissionError(13, "denied")
        if drift == "writable":
            os.chmod(owned, stat.S_IWRITE)
        onerror(function, str(failed), (type(error), error, None))

    monkeypatch.setattr(cli.shutil, "rmtree", denied_rmtree)
    try:
        with pytest.raises(QualificationError, match="V5 cleanup"):
            cli._remove_item_runtime_paths(matrix)
        assert outside.exists()
    finally:
        for path in (owned, outside):
            if path.exists():
                os.chmod(path, stat.S_IWRITE)


def test_unexpected_formal_stage_exception_is_retained_as_terminal_aborted_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    output_root = tmp_path / ".tmp/autonomous-planner-qualification"
    replacements = {
        "ROOT": tmp_path,
        "OUTPUT_ROOT": output_root,
        "RUNTIME_ROOT": output_root / "runtime",
        "STAGE_LOG_ROOT": output_root / "stages",
        "PREFLIGHT_PATH": output_root / "preflight.json",
        "STAGE_RESULTS_PATH": output_root / "stage-results.json",
        "EVENTS_PATH": output_root / "events.jsonl",
        "BUNDLE_PATH": output_root / "qualification-bundle.json",
        "FORCED_G2_RETAINED": output_root / "forced-g2-verification.json",
        "RUNTIME_COORDINATE_SNAPSHOT": output_root / "runtime-coordinate-snapshot.json",
    }
    for name, value in replacements.items():
        monkeypatch.setattr(cli, name, value)
    cli._atomic_write(cli.PREFLIGHT_PATH, canonical_bytes(preflight) + b"\n")
    monkeypatch.setattr(cli, "_load_inputs", lambda: (matrix, projection, {}))
    monkeypatch.setattr(cli, "_observe_preflight", lambda *_args: preflight)

    def unavailable(*_args):
        raise IndexError("unexpected controller defect")

    monkeypatch.setattr(cli, "_execute_stage", unavailable)

    assert cli.run_command() == 1
    stage_results = json.loads(cli.STAGE_RESULTS_PATH.read_text(encoding="utf-8"))
    bundle = json.loads(cli.BUNDLE_PATH.read_text(encoding="utf-8"))
    assert len(stage_results) == len(matrix.stages)
    assert all(result["status"] == "aborted" for result in stage_results)
    assert bundle["result"]["disposition"] == ABORTED
    assert bundle["result"]["protocol_drift"] is True
    assert len(bundle["events"]) == len(matrix.stages) + 3


def test_terminal_writer_failure_exits_without_fabricating_a_bundle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    output_root = tmp_path / ".tmp/autonomous-planner-qualification"
    replacements = {
        "ROOT": tmp_path,
        "OUTPUT_ROOT": output_root,
        "RUNTIME_ROOT": output_root / "runtime",
        "STAGE_LOG_ROOT": output_root / "stages",
        "PREFLIGHT_PATH": output_root / "preflight.json",
        "STAGE_RESULTS_PATH": output_root / "stage-results.json",
        "EVENTS_PATH": output_root / "events.jsonl",
        "BUNDLE_PATH": output_root / "qualification-bundle.json",
        "FORCED_G2_RETAINED": output_root / "forced-g2-verification.json",
        "RUNTIME_COORDINATE_SNAPSHOT": output_root / "runtime-coordinate-snapshot.json",
    }
    for name, value in replacements.items():
        monkeypatch.setattr(cli, name, value)
    cli._atomic_write(cli.PREFLIGHT_PATH, canonical_bytes(preflight) + b"\n")
    monkeypatch.setattr(cli, "_load_inputs", lambda: (matrix, projection, {}))
    monkeypatch.setattr(cli, "_observe_preflight", lambda *_args: preflight)
    monkeypatch.setattr(cli, "_execute_stage", lambda *_args: (_ for _ in ()).throw(IndexError("defect")))
    original_write = cli._atomic_write

    def fail_stage_results(path: Path, payload: bytes) -> None:
        if path == cli.STAGE_RESULTS_PATH:
            raise OSError("simulated immutable writer failure")
        original_write(path, payload)

    monkeypatch.setattr(cli, "_atomic_write", fail_stage_results)

    with pytest.raises(OSError, match="writer failure"):
        cli.run_command()
    assert not cli.BUNDLE_PATH.exists()
