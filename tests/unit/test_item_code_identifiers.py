from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.item_code_identifiers import ItemCodeIdentifierError, run_item_code_identifier_gate


ROOT = Path(__file__).resolve().parents[2]


def test_product_tree_has_no_item_code_identifiers_or_module_names() -> None:
    run_item_code_identifier_gate(ROOT)


def test_gate_rejects_item_coded_module_filename(tmp_path: Path) -> None:
    product = tmp_path / "redagent_platform"
    product.mkdir()
    item_code = "r" + "999"
    (product / f"{item_code}_leak.py").write_text("VALUE = 1\n", encoding="utf-8")

    with pytest.raises(ItemCodeIdentifierError, match="item-coded module filename"):
        run_item_code_identifier_gate(tmp_path)


def test_gate_rejects_item_coded_definition(tmp_path: Path) -> None:
    product = tmp_path / "redagent_platform"
    product.mkdir()
    item_code = "R" + "999"
    (product / "leak.py").write_text(f"class {item_code}Leak:\n    pass\n", encoding="utf-8")

    with pytest.raises(ItemCodeIdentifierError, match="item-coded product identifier"):
        run_item_code_identifier_gate(tmp_path)


def test_standing_gate_tooling_is_pinned() -> None:
    hooks = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    rule = (ROOT / "config/validation/ast-grep/no-item-code-python-definitions.yml").read_text(
        encoding="utf-8"
    )
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

    assert "python scripts/item_code_identifiers.py" in hooks
    assert "ast-grep scan --config sgconfig.yml redagent_platform" in hooks
    assert "severity: error" in rule
    assert r"(?i).*r\d{3}.*" in rule
    assert package["devDependencies"]["@ast-grep/cli"] == "0.45.0"
