from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_r105_fixture_and_gateway_images_are_pinned_nonroot_and_dependency_free() -> None:
    for relative in ("containers/r105-target/Dockerfile", "containers/r105-gateway/Dockerfile"):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert source.startswith(
            "FROM docker.io/library/python@sha256:53739acebd52a300f19f52d93f2a6165f63300689bdf6f8af2bff0d63780e5e6"
        )
        assert "USER 65532:65532" in source
        assert " apk " not in source and "pip " not in source
        assert "http://" not in source and "https://" not in source


def test_r105_gateway_is_an_exact_get_only_no_redirect_boundary() -> None:
    source = (ROOT / "containers/r105-gateway/gateway_server.py").read_text(encoding="utf-8")
    assert 'UPSTREAM_HOST = "redagent-r105-target"' in source
    assert 'parsed.path != "/nuclei/missing-header"' in source
    assert "NoRedirect" in source
    assert "socket.gethostbyname(UPSTREAM_HOST)" in source
    assert "nuclei_gateway_resolution_denied" in source
    assert "nuclei_gateway_request_quota_exceeded" in source
    assert "nuclei_gateway_data_quota_exceeded" in source
    assert "do_POST = _deny_method" in source
    assert "do_CONNECT = _deny_method" in source


def test_r105_fixture_is_benign_and_deliberately_omits_only_certified_header() -> None:
    source = (ROOT / "containers/r105-target/fixture_server.py").read_text(encoding="utf-8")
    assert 'parsed.path != "/nuclei/missing-header"' in source
    assert "X-Content-Type-Options" not in source
    assert "subprocess" not in source and "socket" not in source
    assert "do_POST = _deny_method" in source
