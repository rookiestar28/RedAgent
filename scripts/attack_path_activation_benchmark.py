from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.validation.attack_path_benchmark import (  # noqa: E402
    BenchmarkError,
    decode_json_bytes,
    load_corpus,
    run_benchmark,
    verify_receipt,
)


CORPUS = ROOT / "config/validation/attack-path-activation-benchmark-v1.json"
OUTPUT_ROOT = ROOT / ".tmp/attack-path-activation-benchmark"
RECEIPT = OUTPUT_ROOT / "receipt.json"


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _assert_safe_fixed_path(path: Path, expected: Path, *, must_exist: bool) -> None:
    if path.absolute() != expected.absolute():
        raise BenchmarkError("benchmark path is not the fixed repository path")
    lexical_root = ROOT.absolute()
    try:
        relative = path.absolute().relative_to(lexical_root)
    except ValueError as exc:
        raise BenchmarkError("benchmark path escaped repository root") from exc
    current = lexical_root
    if _is_link_or_reparse(current):
        raise BenchmarkError("benchmark path traverses a link or reparse point")
    for component in relative.parts:
        current /= component
        if current.exists() and _is_link_or_reparse(current):
            raise BenchmarkError("benchmark path traverses a link or reparse point")
    if must_exist and not path.is_file():
        raise BenchmarkError("benchmark fixed input is unavailable")
    if path.exists() and not path.is_file():
        raise BenchmarkError("benchmark fixed path is not a regular file")


def _write_receipt(value: dict[str, object]) -> None:
    _assert_safe_fixed_path(RECEIPT, ROOT / ".tmp/attack-path-activation-benchmark/receipt.json", must_exist=False)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    _assert_safe_fixed_path(RECEIPT, ROOT / ".tmp/attack-path-activation-benchmark/receipt.json", must_exist=False)
    temporary = RECEIPT.with_suffix(".json.tmp")
    _assert_safe_fixed_path(
        temporary,
        ROOT / ".tmp/attack-path-activation-benchmark/receipt.json.tmp",
        must_exist=False,
    )
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, RECEIPT)
    except BaseException:
        if temporary.is_file() and not _is_link_or_reparse(temporary):
            temporary.unlink()
        raise


def _load_receipt() -> object:
    _assert_safe_fixed_path(RECEIPT, ROOT / ".tmp/attack-path-activation-benchmark/receipt.json", must_exist=True)
    return decode_json_bytes(
        RECEIPT.read_bytes(), label="benchmark receipt", maximum_bytes=512 * 1024
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "verify"))
    args = parser.parse_args()
    try:
        _assert_safe_fixed_path(CORPUS, ROOT / "config/validation/attack-path-activation-benchmark-v1.json", must_exist=True)
        corpus = load_corpus(CORPUS)
        if args.command == "run":
            receipt = run_benchmark(corpus)
            _write_receipt(receipt)
        else:
            receipt = verify_receipt(corpus, _load_receipt())
    except (BenchmarkError, OSError) as exc:
        print(f"attack-path activation benchmark: FAIL: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "decision": receipt["decision"],
                "receipt_sha256": receipt["receipt_sha256"],
                "execution_authority": False,
                "release_approval": False,
                "ga_authority": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
