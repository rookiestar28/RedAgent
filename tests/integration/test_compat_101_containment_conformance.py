from __future__ import annotations

import shutil

import pytest

from scripts import containment_conformance


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is required for compat_101 containment conformance")
def test_real_container_network_cooperative_and_forced_containment() -> None:
    result = containment_conformance.conformance()
    assert result["network_internal"] is True
    assert result["network_disconnected"] is True
    assert result["cooperative_stop"] is True
    assert result["cooperative_cleanup"] is True
    assert result["forced_kill"] is True
    assert result["forced_container_not_running"] is True
    assert result["container_removed"] is True
    assert result["network_removed"] is True
