from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_qualification_controller_requires_literal_local_confirmation_and_closed_scope() -> None:
    source = (ROOT / "scripts/compat_108_cloud_lab.py").read_text(encoding="utf-8")
    assert "--confirm-r108-local-lab" in source
    assert 'ThreadingHTTPServer(("127.0.0.1", 0)' in source
    assert "real_cloud_contact_count\": 0" in source
    assert "external_reference_execution_count\": 0" in source
    assert "production_qualified\": False" in source
