from dataclasses import asdict, replace
import json

import pytest

from redagent_platform.runner_service.campaign_result import NormalizedAdapterFindingV1
from redagent_platform.zap_service.campaign_transport import ZapDockerTransport, _receipt_path as zap_receipt_path
from redagent_platform.nuclei_service.campaign_transport import NucleiDockerTransport, _receipt_path as nuclei_receipt_path
from tests.unit.test_compat_123_product_adapters import _zap_receipt, _nuclei_receipt, NOW
from tests.unit.test_compat_123_product_adapters import _request
from redagent_platform.zap_service.campaign_adapter import _validate_runtime as validate_zap
from redagent_platform.nuclei_service.campaign_adapter import _validate_runtime as validate_nuclei


def _finding():
    return NormalizedAdapterFindingV1(source_record_id="record-1", tool="zap",
        tool_version="2.17.0", rule_id="10021", rule_version="v1", database_version="v1",
        title="Synthetic missing header", resource_identity="owned-loopback:fixture",
        location="/passive/missing-header", severity="low", confidence="confirmed",
        taxonomy_ids=("cwe-693",), control_ids=("header-policy",))


@pytest.mark.parametrize("transport_class,factory,path_builder", [
    (ZapDockerTransport, _zap_receipt, zap_receipt_path),
    (NucleiDockerTransport, _nuclei_receipt, nuclei_receipt_path),
])
def test_nonempty_owned_receipt_json_roundtrip_preserves_canonical_finding(tmp_path, transport_class, factory, path_builder):
    transport = transport_class(tmp_path)
    receipt = replace(factory(), normalized_findings=(_finding(),), observed_at=NOW)
    transport._write_receipt(receipt)
    assert transport._lookup(receipt.invocation_id) == receipt


@pytest.mark.parametrize("transport_class,factory,validator,key", [
    (ZapDockerTransport, _zap_receipt, validate_zap, "zap-controlled-runtime@3"),
    (NucleiDockerTransport, _nuclei_receipt, validate_nuclei, "nuclei-trusted-runtime@3"),
])
@pytest.mark.parametrize("tampered", [False, True])
def test_nonempty_persisted_receipt_passes_adapter_exact_report_guard(tmp_path, transport_class, factory, validator, key, tampered):
    transport = transport_class(tmp_path)
    request = _request(key)
    finding = _finding()
    payload = {"schema": "redagent.r123-result/v1", "adapter_id": request.adapter_id,
               "output_complete": True, "findings": [asdict(finding)]}
    overrides = {"normalized_findings": (finding,), "report_safe_payload": payload}
    if key.startswith("nuclei"):
        overrides["result_count"] = 1
    receipt = replace(factory(), **overrides)
    transport._write_receipt(receipt)
    restored = transport._lookup(receipt.invocation_id)
    assert restored is not None
    if tampered:
        restored.report_safe_payload["findings"][0]["title"] = "Different evidence finding"
        with pytest.raises(ValueError, match="report_safe_payload_invalid"):
            validator(restored, request=request)
    else:
        assert validator(restored, request=request) is restored


@pytest.mark.parametrize("transport_class,factory,path_builder", [
    (ZapDockerTransport, _zap_receipt, zap_receipt_path),
    (NucleiDockerTransport, _nuclei_receipt, nuclei_receipt_path),
])
@pytest.mark.parametrize("field,value", [
    ("taxonomy_ids", "cwe-693"), ("control_ids", {"id": "header-policy"}),
    ("taxonomy_ids", ["cwe-693", "cwe-693"]), ("control_ids", [123]),
    ("control_ids", ["not valid"]),
])
def test_owned_receipt_lookup_rejects_noncanonical_identifier_arrays(tmp_path, transport_class, factory, path_builder, field, value):
    transport = transport_class(tmp_path)
    receipt = replace(factory(), normalized_findings=(_finding(),), observed_at=NOW)
    transport._write_receipt(receipt)
    path = path_builder(transport._runtime, receipt.invocation_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["normalized_findings"][0][field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        transport._lookup(receipt.invocation_id)
