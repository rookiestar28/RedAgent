from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from redagent_platform.validation import (
    ChangeRequest,
    ReceiptVerificationError,
    StageResult,
    build_verification_receipt,
    classify_change,
    current_configuration_digests,
    verify_verification_receipt,
)
from redagent_platform.validation.stages import STAGE_REGISTRY_REVISION, stage_ids_for_gate


BASE = "a" * 40
HEAD = "b" * 40
EXPECTED_ENVIRONMENT = {"python": "3.13.9", "platform": "windows-x64"}


def _receipt() -> dict[str, object]:
    decision = classify_change(
        ChangeRequest(
            base_revision=BASE,
            head_revision=HEAD,
            changed_paths=("docs/guide.md",),
        )
    )
    return build_verification_receipt(
        decision=decision,
        base_revision=BASE,
        source_revision=HEAD,
        force_full=False,
        stage_results=(
            StageResult(
                stage_id="changed-file-hooks",
                status="passed",
                exit_code=0,
                duration_ms=12,
                argv=("python", "-m", "pre_commit", "run", "--files", "docs/guide.md"),
                started_at="2026-07-14T00:00:00Z",
                ended_at="2026-07-14T00:00:01Z",
            ),
        ),
        environment={"python": "3.13.9", "platform": "windows-x64"},
        artifact_digests={},
    )


def _rebind(receipt: dict[str, object]) -> None:
    content = dict(receipt)
    content.pop("receipt_digest", None)
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["receipt_digest"] = hashlib.sha256(encoded).hexdigest()


def _rebind_decision_and_receipt(receipt: dict[str, object]) -> None:
    decision = dict(receipt["decision"])
    decision.pop("decision_digest", None)
    receipt["decision"]["decision_digest"] = hashlib.sha256(
        json.dumps(decision, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _rebind(receipt)


def _current_authoritative_kwargs(receipt: dict[str, object]) -> dict[str, object]:
    del receipt
    return {
        "expected_source_revision": HEAD,
        "expected_base_revision": BASE,
        "expected_configuration_digests": current_configuration_digests(),
        "expected_artifact_digests": {},
        "expected_changed_paths": ("docs/guide.md",),
        "expected_force_full": False,
        "expected_gate": "G0",
        "expected_ci_context": "local",
        "expected_validation_mode": "risk_proportional",
        "expected_environment": EXPECTED_ENVIRONMENT,
    }


def _verify(
    receipt: dict[str, object],
    **overrides: object,
) -> None:
    expected = _current_authoritative_kwargs(receipt)
    expected.update(overrides)
    verify_verification_receipt(receipt, **expected)


def test_authoritative_verifier_contract_requires_every_external_binding() -> None:
    parameters = inspect.signature(verify_verification_receipt).parameters
    required = {
        "expected_source_revision",
        "expected_base_revision",
        "expected_configuration_digests",
        "expected_artifact_digests",
        "expected_changed_paths",
        "expected_force_full",
        "expected_gate",
        "expected_ci_context",
        "expected_validation_mode",
        "expected_environment",
    }

    assert required <= set(parameters)
    assert all(parameters[name].default is inspect.Parameter.empty for name in required)


def test_configuration_digest_binds_the_authoritative_validation_lease() -> None:
    digests = current_configuration_digests()

    assert set(digests) >= {"validation_lease", "validation_runner", "legacy_runner"}
    assert len(digests["validation_lease"]) == 64


@pytest.mark.parametrize(
    ("mode", "attributes"),
    [
        (stat.S_IFLNK | 0o777, 0),
        (stat.S_IFREG | 0o644, 0x00000400),
    ],
)
def test_configuration_digest_refuses_a_linklike_source_before_opening(
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
    attributes: int,
) -> None:
    """Receipt binding must not follow a redirected authoritative source."""

    import redagent_platform.validation.receipt as receipt_module

    root = Path(receipt_module.__file__).absolute().parents[2]
    source = root / "package.json"
    original_lstat = Path.lstat

    def linklike_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if path == source:
            return SimpleNamespace(
                st_mode=mode,
                st_size=metadata.st_size,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_file_attributes=attributes,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", linklike_lstat)

    with pytest.raises(ReceiptVerificationError, match="link or reparse"):
        receipt_module.current_configuration_digests()


def test_configuration_digest_refuses_a_reparse_parent_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every path component must remain inside the source checkout."""

    import redagent_platform.validation.receipt as receipt_module

    root = Path(receipt_module.__file__).absolute().parents[2]
    redirected_parent = root / "redagent_platform"
    original_lstat = Path.lstat

    def reparse_parent_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if path == redirected_parent:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755,
                st_size=metadata.st_size,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_file_attributes=0x00000400,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", reparse_parent_lstat)

    with pytest.raises(ReceiptVerificationError, match="link or reparse"):
        receipt_module.current_configuration_digests()


@pytest.mark.parametrize("unsafe_mode", [stat.S_IFIFO, stat.S_IFCHR])
def test_configuration_digest_refuses_nonregular_sources_before_opening(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_mode: int,
) -> None:
    """FIFOs and device-like paths must be rejected without a blocking read."""

    import redagent_platform.validation.receipt as receipt_module

    root = Path(receipt_module.__file__).absolute().parents[2]
    source = root / "package.json"
    original_lstat = Path.lstat

    def unsafe_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if path == source:
            return SimpleNamespace(
                st_mode=unsafe_mode | 0o644,
                st_size=metadata.st_size,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_file_attributes=0,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", unsafe_lstat)

    with pytest.raises(ReceiptVerificationError, match="regular file"):
        receipt_module.current_configuration_digests()


def test_configuration_digest_refuses_an_oversized_source_before_opening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fixed authority manifest cannot turn a bounded hash into an unbounded read."""

    import redagent_platform.validation.receipt as receipt_module

    root = Path(receipt_module.__file__).absolute().parents[2]
    source = root / "package.json"
    original_lstat = Path.lstat

    def oversized_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if path == source:
            return SimpleNamespace(
                st_mode=stat.S_IFREG | 0o644,
                st_size=2 * 1024 * 1024,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_file_attributes=0,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", oversized_lstat)

    with pytest.raises(ReceiptVerificationError, match="size limit"):
        receipt_module.current_configuration_digests()


def test_configuration_digest_checks_deadline_between_bounded_file_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deadline must stop configuration hashing after a single bounded chunk."""

    import redagent_platform.validation.receipt as receipt_module

    clock = {"now": 0.0}
    original_read = os.read
    chunk_sizes: list[int] = []

    def expire_after_first_chunk(descriptor: int, size: int) -> bytes:
        chunk_sizes.append(size)
        result = original_read(descriptor, size)
        clock["now"] = 1.0
        return result

    monkeypatch.setattr(receipt_module, "os", os, raising=False)
    monkeypatch.setattr(os, "read", expire_after_first_chunk)
    monkeypatch.setattr(receipt_module.time, "monotonic", lambda: clock["now"])

    with pytest.raises(ReceiptVerificationError, match="deadline exhausted"):
        receipt_module.current_configuration_digests(deadline_monotonic=1.0)

    assert chunk_sizes
    assert all(0 < size <= 64 * 1024 for size in chunk_sizes)


def test_configuration_digest_preserves_normal_source_digest_with_bounded_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bounded reader must retain the exact normal-source digest."""

    import redagent_platform.validation.receipt as receipt_module

    root = Path(receipt_module.__file__).absolute().parents[2]
    expected = hashlib.sha256((root / "package-lock.json").read_bytes()).hexdigest()
    original_read = receipt_module.os.read
    chunk_sizes: list[int] = []

    def record_chunk_size(descriptor: int, size: int) -> bytes:
        chunk_sizes.append(size)
        return original_read(descriptor, size)

    monkeypatch.setattr(receipt_module.os, "read", record_chunk_size)

    assert receipt_module.current_configuration_digests()["package_lock"] == expected
    assert chunk_sizes
    assert all(0 < size <= 64 * 1024 for size in chunk_sizes)


def test_authoritative_verifier_rejects_impossible_legacy_mode_combination() -> None:
    receipt = _receipt()
    receipt["validation_mode"] = "legacy_full"
    _rebind(receipt)
    expected = _current_authoritative_kwargs(receipt)
    expected["expected_validation_mode"] = "legacy_full"

    with pytest.raises(ReceiptVerificationError, match="legacy"):
        verify_verification_receipt(receipt, **expected)


def test_authoritative_verifier_rejects_rebound_environment_claim() -> None:
    receipt = _receipt()
    receipt["environment"]["python"] = "9.9.9"
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match="environment"):
        verify_verification_receipt(receipt, **_current_authoritative_kwargs(receipt))


@pytest.mark.parametrize(
    "path",
    [
        "docs/api_key=LEAKED123.txt",  # pragma: allowlist secret
        "docs/AWS_SECRET_ACCESS_KEY=LEAKED123.txt",  # pragma: allowlist secret
        "docs/AWS_ACCESS_KEY_ID=LEAKED123.txt",  # pragma: allowlist secret
        "docs/PRIVATE_KEY=LEAKED123.txt",  # pragma: allowlist secret
        "docs/AUTHORIZATION=Bearer-LEAKED123.txt",  # pragma: allowlist secret
    ],
)
def test_builder_rejects_secret_like_values_embedded_in_changed_paths(path: str) -> None:
    decision = classify_change(
        ChangeRequest(base_revision=BASE, head_revision=HEAD, changed_paths=(path,))
    )
    result = StageResult(
        stage_id="changed-file-hooks",
        status="passed",
        exit_code=0,
        duration_ms=1,
        argv=("python", "-m", "pre_commit", "run", "--files", path),
        started_at="2026-07-14T00:00:00Z",
        ended_at="2026-07-14T00:00:00.001000Z",
    )

    with pytest.raises(ReceiptVerificationError, match="forbidden"):
        build_verification_receipt(
            decision=decision,
            base_revision=BASE,
            source_revision=HEAD,
            force_full=False,
            stage_results=(result,),
            environment={"python": "3.13.9", "platform": "windows-x64"},
            artifact_digests={},
        )


def test_receipt_is_bounded_canonical_secret_free_and_source_bound() -> None:
    receipt = _receipt()
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")

    assert len(encoded) <= 1024 * 1024
    assert receipt["schema_version"] == "2"
    assert "receipt_digest" in receipt
    assert len(receipt["decision"]["changed_path_digest"]) == 64
    assert receipt["decision"]["changed_path_count"] == 1
    assert "normalized_paths" not in receipt["decision"]
    assert receipt["stage_registry_revision"] == STAGE_REGISTRY_REVISION
    assert receipt["configuration_digests"] == current_configuration_digests()
    assert receipt["stages"][0]["started_at"] == "2026-07-14T00:00:00Z"
    assert receipt["stages"][0]["ended_at"] == "2026-07-14T00:00:01Z"
    assert "secret" not in encoded.decode("utf-8").lower()
    _verify(receipt)


def test_large_g2_decision_evidence_is_minimized_but_binds_all_paths() -> None:
    paths = tuple(f"docs/generated-{index:03d}.md" for index in range(501))
    decision = classify_change(ChangeRequest(BASE, HEAD, paths))

    assert decision.selected_gate == "G2"
    assert len(decision.normalized_paths) == 501
    assert decision.changed_path_count == 501
    assert len(decision.changed_path_digest) == 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt.update({"source_revision": "d" * 40}),
        lambda receipt: receipt.update({"unknown": True}),
        lambda receipt: receipt["stages"].append(deepcopy(receipt["stages"][0])),
        lambda receipt: receipt["stages"][0].update({"status": "running"}),
        lambda receipt: receipt.update({"api_token": "do-not-record"}),
    ],
)
def test_verifier_rejects_tamper_unknown_fields_duplicates_nonterminal_and_secret_keys(
    mutation: object,
) -> None:
    receipt = _receipt()
    mutation(receipt)

    with pytest.raises(ReceiptVerificationError):
        _verify(receipt)


def test_verifier_rejects_replay_against_another_source() -> None:
    with pytest.raises(ReceiptVerificationError, match="source revision"):
        _verify(_receipt(), expected_source_revision="e" * 40)


def test_verifier_rejects_oversized_receipt_before_parsing_nested_content() -> None:
    receipt = _receipt()
    receipt["environment"] = {"platform": "x" * (1024 * 1024)}

    with pytest.raises(ReceiptVerificationError, match="size"):
        _verify(receipt)


def test_builder_rejects_missing_required_terminal_stage() -> None:
    decision = classify_change(
        ChangeRequest(
            base_revision=BASE,
            head_revision=HEAD,
            changed_paths=("frontend/src/App.tsx",),
        )
    )

    with pytest.raises(ReceiptVerificationError, match="required stage"):
        build_verification_receipt(
            decision=decision,
            base_revision=BASE,
            source_revision=HEAD,
            force_full=False,
            stage_results=(
                StageResult(
                    "changed-file-hooks",
                    "passed",
                    0,
                    1,
                    ("python", "-m", "pre_commit", "run", "--files", "frontend/src/App.tsx"),
                    "2026-07-14T00:00:00Z",
                    "2026-07-14T00:00:01Z",
                ),
            ),
            environment={"python": "3.13.9"},
            artifact_digests={},
        )


def test_verifier_rejects_rebound_receipt_with_invalid_decision_digest() -> None:
    receipt = _receipt()
    receipt["decision"]["selected_gate"] = "G2"
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match="decision digest"):
        _verify(receipt)


@pytest.mark.parametrize(
    ("field", "expected", "message"),
    [
        (
            "configuration_digests",
            current_configuration_digests(),
            "configuration digest",
        ),
        ("artifact_digests", {}, "artifact digest"),
    ],
)
def test_verifier_rejects_rebound_current_file_digest_claims(
    field: str,
    expected: dict[str, str],
    message: str,
) -> None:
    receipt = _receipt()
    receipt[field][next(iter(expected), "frontend_index")] = "f" * 64
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match=message):
        _verify(receipt, **{f"expected_{field}": expected})


def test_verifier_rejects_fully_rebound_semantic_gate_and_stage_forgery() -> None:
    receipt = _receipt()
    required, skipped = stage_ids_for_gate("G1", ("backend",))
    receipt["decision"].update(
        {
            "selected_gate": "G1",
            "planes": ["backend"],
            "reasons": ["mapped_plane_suite"],
            "required_stage_ids": list(required),
            "skipped_stage_ids": list(skipped),
        }
    )
    receipt["stages"] = [
        {
            "stage_id": stage_id,
            "status": "passed",
            "exit_code": 0,
            "duration_ms": 1,
            "argv": ["python", "-V"],
            "started_at": "2026-07-14T00:00:00Z",
            "ended_at": "2026-07-14T00:00:01Z",
        }
        for stage_id in required
    ]
    _rebind_decision_and_receipt(receipt)

    with pytest.raises(ReceiptVerificationError, match="semantic classifier"):
        _verify(receipt, expected_gate="G1")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt["decision"].update({"unknown_nested": True}),
        lambda receipt: receipt["environment"].update({"unknown_nested": "value"}),
        lambda receipt: receipt["environment"].update({"platform": "x" * 257}),
    ],
)
def test_verifier_rejects_rebound_unknown_or_unbounded_nested_fields(mutation: object) -> None:
    receipt = _receipt()
    mutation(receipt)
    _rebind_decision_and_receipt(receipt)

    with pytest.raises(ReceiptVerificationError):
        _verify(receipt)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("exit_code", 1, "status and exit code"),
        ("ended_at", "2026-07-13T23:59:59Z", "timing"),
    ],
)
def test_verifier_rejects_rebound_inconsistent_stage_terminal_evidence(
    field: str,
    value: object,
    message: str,
) -> None:
    receipt = _receipt()
    receipt["stages"][0][field] = value
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match=message):
        _verify(receipt)


@pytest.mark.parametrize("exit_code", [False, 0.0, "1", [], 2**40])
def test_verifier_rejects_non_integer_or_unbounded_exit_codes(exit_code: object) -> None:
    receipt = _receipt()
    receipt["stages"][0]["exit_code"] = exit_code
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match="exit code"):
        _verify(receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform", "password=hunter2"),
        ("python", "token=unsafe"),
        ("node", "AWS_SECRET_ACCESS_KEY=unsafe"),
        ("platform", "windows x64"),
    ],
)
def test_verifier_rejects_secret_bearing_or_malformed_environment_values(
    field: str,
    value: str,
) -> None:
    receipt = _receipt()
    receipt["environment"][field] = value
    _rebind(receipt)

    with pytest.raises(ReceiptVerificationError, match="environment"):
        _verify(receipt)


def test_authority_manifest_hashes_locks_workflows_core_and_executed_scripts() -> None:
    assert set(current_configuration_digests()) == {
        "agent_skills_script",
        "classifier",
        "config_loader",
        "dependency_bootstrap_script",
        "dev_lock",
        "gate_deadline",
        "gate_workflow",
        "gate_runtime",
        "linux_wrapper",
        "legacy_runner",
        "local_stack_script",
        "openbao_script",
        "opa_script",
        "package_lock",
        "package_manifest",
        "path_mapping",
        "pre_commit_config",
        "receipt_verifier",
        "runtime_lock",
        "secure_sdlc_script",
        "stage_registry",
        "stage_runner",
        "validation_lease",
        "validation_runner",
        "validation_workflow",
        "venv_boundary_script",
        "venv_preparation_script",
        "posix_venv_layout_script",
        "windows_wrapper",
    }


def test_verifier_binds_trusted_force_gate_event_and_mode_context() -> None:
    receipt = _receipt()

    _verify(receipt)
    with pytest.raises(ReceiptVerificationError, match="force_full"):
        _verify(receipt, expected_force_full=True)
    with pytest.raises(ReceiptVerificationError, match="decision gate"):
        _verify(receipt, expected_gate="G2")
    with pytest.raises(ReceiptVerificationError, match="CI context"):
        _verify(receipt, expected_ci_context="push")
    with pytest.raises(ReceiptVerificationError, match="validation mode"):
        _verify(receipt, expected_validation_mode="legacy_full")
