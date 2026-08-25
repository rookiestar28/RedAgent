from __future__ import annotations

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/r116-release.yml"


def test_release_workflow_pins_actions_and_uses_minimal_job_permissions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    uses = re.findall(r"^\s*uses:\s*([^\s]+)$", text, flags=re.MULTILINE)

    assert uses
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value) for value in uses)
    assert document["permissions"] == {"contents": "read"}
    assert document["jobs"]["validate"]["permissions"] == {"contents": "read"}
    assert document["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    assert document["jobs"]["publish"]["environment"] == "r116-release"


def test_release_workflow_requires_gate_digest_provenance_sbom_and_keyless_signing() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "scripts/run_full_tests_linux.sh" in text
    assert "persist-credentials: false" in text
    assert "provenance: mode=max" in text
    assert "format: cyclonedx-json" in text
    assert "severity-cutoff: high" in text
    assert "fail-build: true" in text
    assert "cosign sign --yes" in text
    assert "cosign attest --yes --type cyclonedx" in text
    assert "subject-digest: ${{ steps.build.outputs.digest }}" in text
    assert "if: startsWith(github.ref, 'refs/tags/v')" in text
    assert "pull_request_target" not in text
