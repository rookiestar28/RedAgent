"""Reject roadmap-style item codes in product Python identifiers and filenames."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
ITEM_CODE = re.compile(r"r\d{3}", re.IGNORECASE)
ITEM_CODE_MODULE = re.compile(r"^r\d{3}_", re.IGNORECASE)


class ItemCodeIdentifierError(RuntimeError):
    """Raised when product code exposes an internal item-code identifier."""


def _definition_offenders(product_root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted(product_root.rglob("*.py")):
        relative = path.relative_to(product_root.parent).as_posix()
        if ITEM_CODE_MODULE.match(path.name):
            offenders.append(f"{relative}: item-coded module filename")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise ItemCodeIdentifierError(f"cannot inspect Python source: {relative}") from exc
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and ITEM_CODE.search(node.name):
                offenders.append(f"{relative}:{node.lineno}: {node.name}")
    return offenders


def run_item_code_identifier_gate(repository_root: Path) -> None:
    product_root = repository_root / "redagent_platform"
    if not product_root.is_dir():
        raise ItemCodeIdentifierError("redagent_platform source root is missing")
    offenders = _definition_offenders(product_root)
    if offenders:
        preview = "; ".join(offenders[:10])
        raise ItemCodeIdentifierError(f"item-coded product identifier or filename detected: {preview}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        run_item_code_identifier_gate(args.repository_root)
    except ItemCodeIdentifierError as exc:
        print(f"item-code identifier validation failed: {exc}")
        return 1
    print("item-code identifier gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
