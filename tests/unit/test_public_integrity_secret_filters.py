from pathlib import Path
import re

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
PUBLIC_SHA256 = "22d4d5579902d134dede626d0fdfb95891abc7578e13dea9cb23775498c4cf51"


def _patterns():
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hook = next(hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "detect-secrets")
    return [re.compile(hook["args"][index + 1]) for index, arg in enumerate(hook["args"]) if arg == "--exclude-lines"]


@pytest.mark.parametrize("line", [
    f'"checksumValue": "{PUBLIC_SHA256}"',
    f'"packageVerificationCodeValue": "{PUBLIC_SHA256[:40]}"',
    f'"UID": "{PUBLIC_SHA256[:16]}"',
    f'"UID": "{PUBLIC_SHA256[:15]}"',
    f'"relatedSpdxElement": "SPDXRef-OperatingSystem-{PUBLIC_SHA256[:16]}"',
    f'"spdxElementId": "SPDXRef-ContainerImage-{PUBLIC_SHA256[:16]}"',
    f'"SPDXID": "SPDXRef-OperatingSystem-{PUBLIC_SHA256[:16]}"',
    f'"containers/r104-zap/Dockerfile-v3": "{PUBLIC_SHA256}"',
    f'"org.opencontainers.image.revision": "{PUBLIC_SHA256[:40]}"',
])
def test_public_integrity_fields_are_explicitly_classified(line):
    assert any(pattern.search(line) for pattern in _patterns())


@pytest.mark.parametrize("line", [
    f'"api_token": "{PUBLIC_SHA256}"',
    f'"password": "{PUBLIC_SHA256[:16]}"',
    f'"UID": "{PUBLIC_SHA256}"',
    '"checksumValue": "synthetic-credential-not-a-checksum"',
    f'"credentials/private.key": "{PUBLIC_SHA256}"',
    f'"checksumValue": "{PUBLIC_SHA256}", "token": "synthetic-token"',
])
def test_integrity_classification_keeps_credentials_and_nonconforming_values_visible(line):
    assert not any(pattern.search(line) for pattern in _patterns())
