from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/run_compat_124_local_golden_windows.ps1"


def test_public_golden_wrapper_uses_only_public_safe_preflights_and_seven_steps() -> None:
    source = WRAPPER.read_text(encoding="utf-8")

    assert "$referenceRoot = Join-Path $workspace \"reference\"" in source
    assert "if (Test-Path -LiteralPath $referenceRoot)" in source
    assert "scripts/validate_public_release.py" in source
    assert "validate_compat_124_raw_id_inventory.py" not in source

    steps = re.findall(r'Invoke-R124GoldenStep "([a-z0-9_]+)"', source)
    assert steps == [
        "public_boundary_inventory",
        "r124_postgres_core",
        "canonical_evidence_finding_retest",
        "temporal_api_worker_boundary",
        "r123_temporal_campaign_boundary",
        "real_owned_loopback_adapters",
        "r124_browser_golden",
    ]
    assert "$results.Count -eq 7" in source
    assert '$env:REDAGENT_R123_LIVE_QUALIFICATION = "owned-loopback-v2"' in source
    assert 'target_scope = "repository-owned-loopback-only"' in source
    assert "external_reference_executed = $false" in source
    assert "public_or_third_party_target_contacted = $false" in source
    assert "secret_values_recorded = $false" in source
