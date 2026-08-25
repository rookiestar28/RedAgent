from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/compat_105_nuclei.py"


def test_controller_is_confirmation_gated_and_has_no_target_template_or_flag_input() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--confirm-r105-local-lab" in source
    assert 'choices=("build", "qualify", "cleanup")' in source
    for unsafe in ("--target", "--template", "--url", "--flags", "--workflow", "--payload"):
        assert unsafe not in source


def test_controller_uses_exact_owned_resources_and_hardened_worker_boundary() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    requalification_source = (ROOT / "scripts/compat_105_requalify.py").read_text(encoding="utf-8")
    for value in (
        "redagent-r105-worker", "redagent-r105-gateway", "redagent-r105-target",
        "redagent-r105-worker-gateway", "redagent-r105-gateway-target",
        "redagent.owner=r105", "--read-only", "--cap-drop", "ALL",
        "no-new-privileges", "--pids-limit", "--memory", "--cpus", "--internal",
    ):
        assert value in source
    assert "PortBindings" in source and "ownership_mismatch" in source
    assert "SOURCE_DATE_EPOCH=1787529600" in requalification_source


def test_controller_uses_v2_candidate_authority_normalizes_then_erases_raw_output() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "redagent.r105-runtime-lock/v2" in source
    assert "_candidate_bundle" in source
    assert "candidate_sha256" in source
    assert "compile_nuclei_plan" in source
    assert "normalize_nuclei_jsonl" in source
    assert 'results_path.unlink(missing_ok=True)' in source
    assert '"external_target_contacts": 0' in source
    assert '"cleanup_residual_resource_count": 0' in source
    assert "-disable-unsigned-templates" in source
    assert "payload-tampered.yaml" in source
    assert '"SIGTERM"' in source and '"docker", "kill"' in source
