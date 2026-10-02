from __future__ import annotations

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


def test_r098_secret_tables_remain_tenant_owned_after_revision_0008() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0033_bounded_child_replanning"
    for name in (
        "secret_references", "secret_workload_clients", "secret_lease_operations",
        "secret_leases", "secret_lease_events",
    ):
        table = metadata.tables[name]
        assert {"tenant_id", "version", "created_at", "updated_at"} <= set(table.c.keys())
    forbidden = {"secret_value", "password", "client_token", "secret_id", "unwrap_token", "provider_response"}
    assert all(not (forbidden & set(metadata.tables[name].c.keys())) for name in metadata.tables if name.startswith("secret_"))
