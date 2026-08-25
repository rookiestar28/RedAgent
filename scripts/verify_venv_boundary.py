from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig


ROOT = Path(__file__).resolve().parents[1]


def _is_linklike(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return True
    is_junction = getattr(path, "is_junction", lambda: False)
    reparse = bool(getattr(metadata, "st_file_attributes", 0) & 0x00000400)
    return path.is_symlink() or bool(is_junction()) or reparse


def attest(expected_value: str) -> None:
    try:
        expected = Path(expected_value).resolve(strict=True)
        repository = ROOT.resolve(strict=True)
        actual = Path(sys.prefix).resolve(strict=True)
        base = Path(sys.base_prefix).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("venv boundary path cannot be resolved") from exc
    if expected != repository and repository not in expected.parents:
        raise RuntimeError("venv boundary escaped the repository")
    if actual != expected or base == actual:
        raise RuntimeError("venv boundary does not match the active project environment")

    scripts = expected / ("Scripts" if os.name == "nt" else "bin")
    configuration = expected / "pyvenv.cfg"
    executable_parent = Path(sys.executable).absolute().parent
    if _is_linklike(expected) or _is_linklike(scripts) or _is_linklike(configuration):
        raise RuntimeError("venv boundary contains a symlink, junction, or reparse point")
    if not scripts.is_dir() or not stat.S_ISREG(configuration.lstat().st_mode):
        raise RuntimeError("venv boundary is incomplete")
    if configuration.stat().st_size > 16384:
        raise RuntimeError("venv boundary pyvenv.cfg exceeds the bounded size")
    settings = [
        line
        for line in configuration.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\s*include-system-site-packages\s*=", line, re.IGNORECASE)
    ]
    if len(settings) != 1 or not re.match(
        r"^\s*include-system-site-packages\s*=\s*false\s*$",
        settings[0],
        re.IGNORECASE,
    ):
        raise RuntimeError(
            "venv boundary requires include-system-site-packages = false exactly once"
        )
    if executable_parent.resolve(strict=True) != scripts.resolve(strict=True):
        raise RuntimeError("venv boundary interpreter is not under the expected scripts directory")

    destinations = sysconfig.get_paths()
    for key in ("purelib", "platlib"):
        raw_destination = Path(destinations[key]).absolute()
        try:
            destination = raw_destination.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(f"venv boundary {key} destination is missing") from exc
        if expected != destination and expected not in destination.parents:
            raise RuntimeError(f"venv boundary {key} destination escaped the environment")
        current = expected
        for part in raw_destination.relative_to(expected).parts:
            current = current / part
            if _is_linklike(current):
                raise RuntimeError(
                    f"venv boundary {key} site-packages path contains a link or reparse point"
                )
        if not destination.is_dir():
            raise RuntimeError(f"venv boundary {key} site-packages destination is not a directory")


def main() -> int:
    parser = argparse.ArgumentParser(description="Attest a repo-local virtual environment boundary")
    parser.add_argument("--expected", required=True)
    args = parser.parse_args()
    try:
        attest(args.expected)
    except RuntimeError as exc:
        print(f"venv boundary validation failed: {exc}", file=sys.stderr)
        return 1
    print("venv_boundary_ok=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
