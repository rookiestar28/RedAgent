"""Validate the secure SDLC and supply-chain baseline."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_POLICY_TERMS = {
    "dependency policy": "Dependency Policy",
    "sbom generation": "SBOM Generation",
    "vulnerability scanning": "Vulnerability Scanning",
    "secret scanning": "Secret Scanning",
    "license review": "License Review",
    "build artifact": "Build Artifact",
}

REQUIRED_CODING_TERMS = {
    "authentication": "Authentication",
    "authorization": "Authorization",
    "input validation": "Input Validation",
    "output encoding": "Output Encoding",
    "credential material": "Credential Material",
    "logging": "Logging",
    "error handling": "Error Handling",
    "data retention": "Data Retention",
    "dangerous tool execution": "Dangerous Tool Execution",
    "threat-model": "Threat-Model",
}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...]
    sbom_path: Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require_terms(path: Path, terms: dict[str, str]) -> list[str]:
    if not path.exists():
        return [f"Missing required file: {path}"]
    text = read_text(path).lower()
    return [
        f"{path} does not contain required section/topic: {label}"
        for needle, label in terms.items()
        if needle not in text
    ]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def package_lock_components(lockfile: Path) -> list[dict[str, str]]:
    lock = load_json(lockfile)
    packages = lock.get("packages", {})
    components: list[dict[str, str]] = []
    for package_path, metadata in sorted(packages.items()):
        if package_path == "":
            continue
        name = package_path.removeprefix("node_modules/")
        components.append(
            {
                "name": name,
                "version": str(metadata.get("version", "")),
                "license": str(metadata.get("license", "")),
                "scope": "development" if metadata.get("dev") else "runtime",
            }
        )
    return components


def _canonical_package_name(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def runtime_dependency_reviews(path: Path) -> dict[str, dict[str, Any]]:
    payload = load_json(path)
    packages = payload.get("packages", []) if isinstance(payload, dict) else []
    if not isinstance(packages, list):
        return {}
    return {
        _canonical_package_name(str(package.get("name", ""))): package
        for package in packages
        if isinstance(package, dict) and package.get("name")
    }


def requirement_components(
    requirements: Path,
    *,
    scope: str = "development",
    reviews: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    components: list[dict[str, str]] = []
    for raw_line in requirements.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name = line
        for separator in ("==", ">=", "<=", "~=", ">", "<"):
            if separator in line:
                name = line.split(separator, 1)[0]
                break
        components.append(
            {
                "name": name.strip(),
                "version": line,
                "license": str((reviews or {}).get(_canonical_package_name(name), {}).get("license", "review-required")),
                "scope": scope,
            }
        )
    return components


def validate_runtime_dependency_reviews(lockfile: Path, review_path: Path) -> list[str]:
    if not review_path.exists():
        return ["config/python-runtime-dependencies.json is required for runtime dependency review"]
    try:
        payload = load_json(review_path)
    except (OSError, json.JSONDecodeError):
        return ["Runtime dependency review manifest is invalid JSON"]
    errors: list[str] = []
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        errors.append("Runtime dependency review schema must be 1.0")
    if not str(payload.get("review_date", "")).strip():
        errors.append("Runtime dependency review date is required")
    if not str(payload.get("source", "")).startswith("https://pypi.org/"):
        errors.append("Runtime dependency review source must be official PyPI")
    packages = payload.get("packages", []) if isinstance(payload, dict) else []
    if not isinstance(packages, list):
        return errors + ["Runtime dependency review packages must be an array"]
    reviews: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            errors.append("Runtime dependency review entry must be an object")
            continue
        name = _canonical_package_name(str(package.get("name", "")))
        if not name:
            errors.append("Runtime dependency review package name is required")
            continue
        if name in reviews:
            errors.append(f"Duplicate runtime dependency review: {name}")
        reviews[name] = package
        if not str(package.get("license", "")).strip():
            errors.append(f"Runtime dependency license missing: {name}")
        if package.get("yanked") is not False:
            errors.append(f"Runtime dependency release is yanked or unverified: {name}")
        if package.get("known_vulnerabilities") != 0:
            errors.append(f"Runtime dependency vulnerability review failed: {name}")
        if package.get("status") != "reviewed":
            errors.append(f"Runtime dependency review status invalid: {name}")
    locked: dict[str, str] = {}
    for raw_line in lockfile.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            locked[_canonical_package_name(name)] = version
    for name, version in sorted(locked.items()):
        reviewed = reviews.get(name)
        if reviewed is None or str(reviewed.get("version", "")) != version:
            errors.append(f"Runtime dependency review mismatch: {name}=={version}")
    for name in sorted(set(reviews) - set(locked)):
        errors.append(f"Runtime dependency review not present in lock: {name}")
    return errors


def validate_node_dependency_reviews(manifest_path: Path, review_path: Path) -> list[str]:
    if not review_path.exists():
        return ["config/node-runtime-dependencies.json is required for direct Node dependency review"]
    try:
        manifest = load_json(manifest_path)
        payload = load_json(review_path)
    except (OSError, json.JSONDecodeError):
        return ["Direct Node dependency review manifest is invalid JSON"]
    errors: list[str] = []
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        errors.append("Direct Node dependency review schema must be 1.0")
    if not str(payload.get("review_date", "")).strip():
        errors.append("Direct Node dependency review date is required")
    if not str(payload.get("source", "")).startswith("https://registry.npmjs.org/"):
        errors.append("Direct Node dependency review source must be official npm registry")
    direct: dict[str, str] = {}
    for group in ("dependencies", "devDependencies"):
        values = manifest.get(group, {}) if isinstance(manifest, dict) else {}
        if not isinstance(values, dict):
            errors.append(f"package.json {group} must be an object")
            continue
        for name, version in values.items():
            normalized = str(version)
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", normalized):
                errors.append(f"Direct Node dependency must be exactly pinned: {name}@{normalized}")
            direct[str(name)] = normalized
    packages = payload.get("packages", []) if isinstance(payload, dict) else []
    if not isinstance(packages, list):
        return errors + ["Direct Node dependency review packages must be an array"]
    reviews: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            errors.append("Direct Node dependency review entry must be an object")
            continue
        name = str(package.get("name", ""))
        if not name:
            errors.append("Direct Node dependency review package name is required")
            continue
        if name in reviews:
            errors.append(f"Duplicate direct Node dependency review: {name}")
        reviews[name] = package
        if not str(package.get("license", "")).strip():
            errors.append(f"Direct Node dependency license missing: {name}")
        if package.get("known_vulnerabilities") != 0:
            errors.append(f"Direct Node dependency vulnerability review failed: {name}")
        if package.get("status") != "reviewed":
            errors.append(f"Direct Node dependency review status invalid: {name}")
    for name, version in sorted(direct.items()):
        reviewed = reviews.get(name)
        if reviewed is None or str(reviewed.get("version", "")) != version:
            errors.append(f"Direct Node dependency review mismatch: {name}@{version}")
    for name in sorted(set(reviews) - set(direct)):
        errors.append(f"Direct Node dependency review not present in package.json: {name}")
    return errors


def container_lock_components(lockfile: Path) -> list[dict[str, str]]:
    lock = load_json(lockfile)
    return [
        {
            "name": str(image.get("registry", "")),
            "version": str(image.get("tag", "")),
            "index_digest": str(image.get("index_digest", "")),
            "platform_digest": str(image.get("platform_digest", "")),
            "platform": str(image.get("platform", "")),
            "license": str(image.get("license_security_status", "")),
            "scope": "local-runtime",
        }
        for image in lock.get("images", [])
        if isinstance(image, dict)
    ]


def single_container_lock_component(lockfile: Path) -> dict[str, str]:
    image = load_json(lockfile)
    return {
        "name": str(image.get("registry", "")),
        "version": str(image.get("tag", "")),
        "index_digest": str(image.get("index_digest", "")),
        "platform_digest": str(image.get("platform_digest", "")),
        "platform": str(image.get("platform", "")),
        "license": str(image.get("license_security_status", "")),
        "scope": str(image.get("purpose", "local-conformance-only")),
    }


def build_sbom(root: Path) -> dict[str, Any]:
    node_components = package_lock_components(root / "package-lock.json")
    runtime_lock = root / "requirements-runtime.lock"
    dev_lock = root / "requirements-dev.lock"
    review_path = root / "config" / "python-runtime-dependencies.json"
    try:
        reviews = runtime_dependency_reviews(review_path) if review_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        reviews = {}
    python_components = []
    if runtime_lock.exists():
        python_components.extend(requirement_components(runtime_lock, scope="runtime", reviews=reviews))
    python_components.extend(
        requirement_components(
            dev_lock if dev_lock.exists() else root / "requirements-dev.txt",
            scope="development",
        )
    )
    container_lock = root / "config" / "local-stack-images.json"
    container_components = container_lock_components(container_lock) if container_lock.exists() else []
    openbao_lock = root / "config" / "openbao-conformance-image.json"
    if openbao_lock.exists():
        container_components.append(single_container_lock_component(openbao_lock))
    opa_lock = root / "config" / "opa-conformance-image.json"
    if opa_lock.exists():
        container_components.append(single_container_lock_component(opa_lock))
    opa_bundle_server_lock = root / "config" / "opa-bundle-server-image.json"
    if opa_bundle_server_lock.exists():
        container_components.append(single_container_lock_component(opa_bundle_server_lock))
    runner_lock = root / "config" / "runner-conformance-image.json"
    if runner_lock.exists():
        container_components.append(single_container_lock_component(runner_lock))
    lab_lock = root / "config" / "lab-conformance-image.json"
    if lab_lock.exists():
        container_components.append(single_container_lock_component(lab_lock))
    otel_lock = root / "config" / "otel-collector-conformance-image.json"
    if otel_lock.exists():
        container_components.append(single_container_lock_component(otel_lock))
    return {
        "schema": "redagent-sbom/v1",
        "generated_by": "scripts/validate_secure_sdlc.py",
        "artifact_policy": "local-only ignored .tmp artifact",
        "components": {
            "node": node_components,
            "python": python_components,
            "containers": container_components,
        },
    }


def write_sbom(root: Path, sbom: dict[str, Any]) -> Path:
    output_dir = root / ".tmp" / "sbom"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "redagent-sbom.json"
    output_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path


def validate(root: Path) -> ValidationResult:
    errors: list[str] = []
    policy = root / "docs" / "security" / "SECURE_SDLC_AND_SUPPLY_CHAIN_POLICY.md"
    coding = root / "docs" / "security" / "SECURE_CODING_STANDARD.md"
    pre_commit = root / ".pre-commit-config.yaml"
    windows_gate = root / "scripts" / "run_full_tests_windows.ps1"
    linux_gate = root / "scripts" / "run_full_tests_linux.sh"
    validation_registry = root / "config" / "validation" / "r118-stage-registry.json"

    errors.extend(require_terms(policy, REQUIRED_POLICY_TERMS))
    errors.extend(require_terms(coding, REQUIRED_CODING_TERMS))

    pre_commit_text = read_text(pre_commit) if pre_commit.exists() else ""
    if "detect-secrets" not in pre_commit_text:
        errors.append(".pre-commit-config.yaml must include detect-secrets")

    for gate in (windows_gate, linux_gate):
        if not gate.exists():
            errors.append(f"Missing full-gate script: {gate}")
            continue
        gate_text = read_text(gate)
        if "scripts/run_validation_gate.py" not in gate_text:
            errors.append(f"{gate} must delegate to scripts/run_validation_gate.py")

    if not validation_registry.exists():
        errors.append(f"Missing validation stage registry: {validation_registry}")
    else:
        try:
            registry_payload = json.loads(validation_registry.read_text(encoding="utf-8"))
            registry_stages = registry_payload["stages"]
        except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            errors.append(f"Invalid validation stage registry: {exc}")
        else:
            secure_stages = [stage for stage in registry_stages if stage.get("id") == "secure-sdlc"]
            audit_stages = [stage for stage in registry_stages if stage.get("id") == "frontend-audit"]
            if len(secure_stages) != 1 or secure_stages[0].get("argv") != [
                "python",
                "scripts/validate_secure_sdlc.py",
            ]:
                errors.append("Validation registry must run the secure-SDLC validator exactly once")
            if len(audit_stages) != 1 or audit_stages[0].get("argv", [])[:2] != ["npm", "audit"]:
                errors.append("Validation registry must run npm audit exactly once")

    lockfile = root / "package-lock.json"
    if not lockfile.exists():
        errors.append("package-lock.json is required for Node dependency review")
    else:
        for component in package_lock_components(lockfile):
            if not component["license"]:
                errors.append(f"Missing license metadata for Node component: {component['name']}")
    errors.extend(
        validate_node_dependency_reviews(
            root / "package.json",
            root / "config" / "node-runtime-dependencies.json",
        )
    )

    for lock_name in ("requirements-runtime.lock", "requirements-dev.lock"):
        python_lock = root / lock_name
        if not python_lock.exists():
            errors.append(f"{lock_name} is required for reproducible Python dependencies")
        elif any("==" not in component["version"] for component in requirement_components(python_lock)):
            errors.append(f"{lock_name} entries must be exactly pinned")

    runtime_lock = root / "requirements-runtime.lock"
    if runtime_lock.exists():
        errors.extend(
            validate_runtime_dependency_reviews(
                runtime_lock,
                root / "config" / "python-runtime-dependencies.json",
            )
        )

    container_lock = root / "config" / "local-stack-images.json"
    if not container_lock.exists():
        errors.append("config/local-stack-images.json is required for container dependency review")
    else:
        containers = container_lock_components(container_lock)
        if {component["name"] for component in containers} != {
            "docker.io/library/postgres",
            "quay.io/keycloak/keycloak",
            "docker.io/temporalio/temporal",
            "docker.io/rustfs/rustfs",
        }:
            errors.append("Container SBOM must contain the reviewed postgres, keycloak, temporal, and rustfs images")
        for component in containers:
            for field in ("index_digest", "platform_digest"):
                value = component[field]
                if not value.startswith("sha256:") or len(value) != 71:
                    errors.append(f"Container image {component['name']} has invalid {field}")
    openbao_lock = root / "config" / "openbao-conformance-image.json"
    if not openbao_lock.exists():
        errors.append("config/openbao-conformance-image.json is required for R098 container review")
    else:
        openbao = single_container_lock_component(openbao_lock)
        if openbao["name"] != "ghcr.io/openbao/openbao" or openbao["version"] != "2.5.5":
            errors.append("OpenBao conformance image review must pin the supported 2.5.5 release")
        for field in ("index_digest", "platform_digest"):
            value = openbao[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {openbao['name']} has invalid {field}")
    opa_lock = root / "config" / "opa-conformance-image.json"
    if not opa_lock.exists():
        errors.append("config/opa-conformance-image.json is required for R099 container review")
    else:
        opa = single_container_lock_component(opa_lock)
        if opa["name"] != "docker.io/openpolicyagent/opa" or opa["version"] != "1.18.2-static":
            errors.append("OPA conformance image review must pin the supported 1.18.2-static release")
        for field in ("index_digest", "platform_digest"):
            value = opa[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {opa['name']} has invalid {field}")
    opa_bundle_server_lock = root / "config" / "opa-bundle-server-image.json"
    if not opa_bundle_server_lock.exists():
        errors.append("config/opa-bundle-server-image.json is required for R099 bundle-server review")
    else:
        bundle_server = single_container_lock_component(opa_bundle_server_lock)
        if bundle_server["name"] != "docker.io/library/python" or bundle_server["version"] != "3.13-alpine":
            errors.append("R099 bundle server must pin the reviewed Python 3.13 Alpine image")
        for field in ("index_digest", "platform_digest"):
            value = bundle_server[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {bundle_server['name']} has invalid {field}")
    runner_lock = root / "config" / "runner-conformance-image.json"
    if not runner_lock.exists():
        errors.append("config/runner-conformance-image.json is required for R100 container review")
    else:
        runner = single_container_lock_component(runner_lock)
        if runner["name"] != "docker.io/library/python" or runner["version"] != "3.13.9-alpine3.22":
            errors.append("R100 synthetic runner base must pin the reviewed Python 3.13.9 Alpine image")
        for field in ("index_digest", "platform_digest"):
            value = runner[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {runner['name']} has invalid {field}")
    lab_lock = root / "config" / "lab-conformance-image.json"
    if not lab_lock.exists():
        errors.append("config/lab-conformance-image.json is required for R103 container review")
    else:
        lab = single_container_lock_component(lab_lock)
        if lab["name"] != "docker.io/library/python" or lab["version"] != "3.13.9-alpine3.22":
            errors.append("R103 safe lab base must pin the reviewed Python 3.13.9 Alpine image")
        for field in ("index_digest", "platform_digest"):
            value = lab[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {lab['name']} has invalid {field}")
    otel_lock = root / "config" / "otel-collector-conformance-image.json"
    if not otel_lock.exists():
        errors.append("config/otel-collector-conformance-image.json is required for R102 container review")
    else:
        otel = single_container_lock_component(otel_lock)
        if otel["name"] != "docker.io/otel/opentelemetry-collector-contrib" or otel["version"] != "0.153.0":
            errors.append("R102 Collector review must pin the supported 0.153.0 contrib release")
        for field in ("index_digest", "platform_digest"):
            value = otel[field]
            if not value.startswith("sha256:") or len(value) != 71:
                errors.append(f"Container image {otel['name']} has invalid {field}")
    sbom = build_sbom(root)
    sbom_path = write_sbom(root, sbom)
    if not sbom["components"]["node"] and not sbom["components"]["python"]:
        errors.append("SBOM must contain at least one dependency component")

    return ValidationResult(ok=not errors, errors=tuple(errors), sbom_path=sbom_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print JSON validation result.")
    args = parser.parse_args()

    result = validate(repo_root())
    payload = {
        "ok": result.ok,
        "errors": list(result.errors),
        "sbom_path": str(result.sbom_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"secure_sdlc_ok={str(result.ok).lower()}")
        print(f"sbom_path={result.sbom_path}")
        for error in result.errors:
            print(f"ERROR: {error}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
