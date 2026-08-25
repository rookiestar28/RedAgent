from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "runner_classes",
    "runner_registrations",
    "runner_identities",
    "execution_capability_manifests",
    "artifact_verification_receipts",
    "runner_job_manifests",
    "runner_pull_leases",
    "runner_lifecycle_events",
    "runner_execution_receipts",
)


def _source() -> str:
    return (ROOT / "migrations" / "versions" / "0007_r100_ephemeral_runners.py").read_text(encoding="utf-8")


def test_revision_0007_owns_runner_identity_capability_manifest_lease_and_receipt_truth() -> None:
    source = _source()
    assert 'revision = "0007_r100_ephemeral_runners"' in source
    assert 'down_revision = "0006_r099_policy_distribution"' in source
    for table in TABLES:
        assert f'"{table}"' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE \"{table}\" ENABLE ROW LEVEL SECURITY' in source
    assert 'ALTER TABLE \"{table}\" FORCE ROW LEVEL SECURITY' in source
    assert 'CREATE POLICY \"{table}_tenant_isolation\"' in source


def test_revision_stores_closed_metadata_without_keys_tokens_credentials_or_arbitrary_execution_content() -> None:
    source = _source().lower()
    for forbidden in (
        '"private_key"', '"certificate_pem"', '"lease_token"', '"credential_material"',
        '"provider_response"', '"stdout"', '"stderr"', '"command"', '"argv"',
        '"shell"', '"environment_map"', '"environment_variables"', '"mounts"',
        '"runtime_flags"', '"target_response"',
    ):
        assert forbidden not in source


def test_revision_has_exact_registration_capability_artifact_manifest_claim_and_event_uniqueness() -> None:
    source = _source()
    for name in (
        "uq_runner_classes_tenant_class_revision",
        "uq_runner_registrations_tenant_runner_generation",
        "uq_runner_identities_tenant_fingerprint",
        "uq_execution_capabilities_tenant_capability_revision",
        "uq_artifact_verification_tenant_image_digest",
        "uq_runner_manifests_tenant_job_request",
        "uq_runner_pull_leases_tenant_manifest",
        "uq_runner_lifecycle_events_tenant_event",
        "uq_runner_execution_receipts_tenant_execution",
    ):
        assert name in source


def test_revision_downgrade_drops_all_nine_tables_in_dependency_safe_reverse_order() -> None:
    source = _source()
    downgrade = source.split("def downgrade() -> None:", maxsplit=1)[1]
    positions = [downgrade.index(f'op.drop_table("{table}")') for table in reversed(TABLES)]
    assert positions == sorted(positions)
    assert downgrade.count("op.drop_table(") == len(TABLES)
