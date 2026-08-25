import json
from pathlib import Path

from scripts import validate_secure_sdlc


def test_secure_sdlc_validator_passes_current_repo() -> None:
    result = validate_secure_sdlc.validate(validate_secure_sdlc.repo_root())

    assert result.ok, result.errors
    assert result.sbom_path.exists()


def test_secure_sdlc_validator_detects_missing_policy_terms(tmp_path: Path) -> None:
    policy = tmp_path / "policy.md"
    policy.write_text("Dependency Policy\n", encoding="utf-8")

    errors = validate_secure_sdlc.require_terms(
        policy,
        {
            "dependency policy": "Dependency Policy",
            "secret scanning": "Secret Scanning",
        },
    )

    assert errors == [f"{policy} does not contain required section/topic: Secret Scanning"]


def test_sbom_generation_includes_node_and_python_components(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "redagent"},
                    "node_modules/example": {
                        "version": "1.0.0",
                        "license": "MIT",
                        "dev": True,
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "requirements-dev.txt").write_text("pytest>=8.0,<9.0\n", encoding="utf-8")

    sbom = validate_secure_sdlc.build_sbom(tmp_path)

    assert sbom["components"]["node"][0]["name"] == "example"
    assert sbom["components"]["python"][0]["name"] == "pytest"


def test_sbom_generation_includes_digest_pinned_container_components(tmp_path: Path) -> None:
    lock = {
        "images": [
            {
                "service": "postgres",
                "registry": "docker.io/library/postgres",
                "tag": "18.3",
                "index_digest": "sha256:" + "a" * 64,
                "platform_digest": "sha256:" + "b" * 64,
                "platform": "linux/amd64",
                "license_security_status": "reviewed",
            }
        ]
    }
    lock_path = tmp_path / "config" / "local-stack-images.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    components = validate_secure_sdlc.container_lock_components(lock_path)

    assert components == [
        {
            "name": "docker.io/library/postgres",
            "version": "18.3",
            "index_digest": "sha256:" + "a" * 64,
            "platform_digest": "sha256:" + "b" * 64,
            "platform": "linux/amd64",
            "license": "reviewed",
            "scope": "local-runtime",
        }
    ]


def test_sbom_generation_combines_runtime_and_development_python_locks(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {}}), encoding="utf-8")
    (tmp_path / "requirements-runtime.lock").write_text("fastapi==0.139.0\n", encoding="utf-8")
    (tmp_path / "requirements-dev.lock").write_text("pytest==8.4.2\n", encoding="utf-8")

    sbom = validate_secure_sdlc.build_sbom(tmp_path)

    assert {component["name"] for component in sbom["components"]["python"]} == {"fastapi", "pytest"}
    assert {
        component["name"]: component["scope"] for component in sbom["components"]["python"]
    } == {"fastapi": "runtime", "pytest": "development"}


def test_package_lock_license_review_flags_missing_license(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "redagent"},
                    "node_modules/no-license": {"version": "1.0.0", "dev": True},
                }
            }
        ),
        encoding="utf-8",
    )

    components = validate_secure_sdlc.package_lock_components(lockfile)

    assert components == [
        {
            "name": "no-license",
            "version": "1.0.0",
            "license": "",
            "scope": "development",
        }
    ]


def test_runtime_dependency_review_populates_sbom_license_and_detects_version_drift(tmp_path: Path) -> None:
    lock = tmp_path / "requirements-runtime.lock"
    lock.write_text("fastapi==0.139.0\n", encoding="utf-8")
    review_path = tmp_path / "python-runtime-dependencies.json"
    review_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "review_date": "2026-07-10",
                "source": "https://pypi.org/pypi/<package>/<version>/json",
                "packages": [
                    {
                        "name": "fastapi",
                        "version": "0.139.0",
                        "license": "MIT",
                        "yanked": False,
                        "known_vulnerabilities": 0,
                        "status": "reviewed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    reviews = validate_secure_sdlc.runtime_dependency_reviews(review_path)
    components = validate_secure_sdlc.requirement_components(lock, scope="runtime", reviews=reviews)

    assert components[0]["license"] == "MIT"
    assert validate_secure_sdlc.validate_runtime_dependency_reviews(lock, review_path) == []
    payload = json.loads(review_path.read_text(encoding="utf-8"))
    payload["packages"][0]["version"] = "0.138.0"
    review_path.write_text(json.dumps(payload), encoding="utf-8")
    assert "Runtime dependency review mismatch: fastapi==0.139.0" in validate_secure_sdlc.validate_runtime_dependency_reviews(lock, review_path)


def test_full_gate_wrappers_delegate_and_registry_preserves_supply_chain_intent() -> None:
    root = validate_secure_sdlc.repo_root()
    windows = (root / "scripts/run_full_tests_windows.ps1").read_text(encoding="utf-8")
    linux = (root / "scripts/run_full_tests_linux.sh").read_text(encoding="utf-8")
    registry = json.loads(
        (root / "config/validation/r118-stage-registry.json").read_text(encoding="utf-8")
    )["stages"]

    assert "function Assert-NativeSuccess" in windows
    assert "scripts/run_validation_gate.py" in windows
    assert "scripts/run_validation_gate.py" in linux
    assert sum(stage["id"] == "secure-sdlc" for stage in registry) == 1
    audits = [stage for stage in registry if stage["id"] == "frontend-audit"]
    assert len(audits) == 1
    assert audits[0]["argv"][:2] == ["npm", "audit"]


def test_sbom_includes_reviewed_r102_collector_digest() -> None:
    sbom = validate_secure_sdlc.build_sbom(validate_secure_sdlc.repo_root())
    collector = next(
        component for component in sbom["components"]["containers"]
        if component["name"] == "docker.io/otel/opentelemetry-collector-contrib"
    )
    assert collector["version"] == "0.153.0"
    assert collector["index_digest"].startswith("sha256:")
    assert collector["platform_digest"].startswith("sha256:")


def test_sbom_includes_reviewed_r103_safe_lab_base_digest() -> None:
    sbom = validate_secure_sdlc.build_sbom(validate_secure_sdlc.repo_root())
    lab = next(
        component for component in sbom["components"]["containers"]
        if component["scope"] == "r103-safe-local-lab-qualification"
    )
    assert lab["name"] == "docker.io/library/python"
    assert lab["version"] == "3.13.9-alpine3.22"
    assert lab["index_digest"].startswith("sha256:")
    assert lab["platform_digest"].startswith("sha256:")
