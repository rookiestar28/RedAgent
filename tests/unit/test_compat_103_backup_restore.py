from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_backup_restore_is_disposable_fixed_owned_and_never_overwrites_primary() -> None:
    source = (ROOT / "scripts/compat_103_backup_restore.py").read_text(encoding="utf-8")
    assert 'POSTGRES = "redagent-local-postgres-1"' in source
    assert "com.docker.compose.project" in source
    assert "r103_source_" in source and "r103_restore_" in source
    assert '"pg_dump"' in source and '"pg_restore"' in source
    assert '"--exit-on-error"' in source
    assert "source_inventory != restored_inventory" in source
    assert 'primary.set(database=source)' in source
    assert 'set(database=restored)' not in source
