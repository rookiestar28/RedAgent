from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from redagent_platform.runner_service.config import RunnerIdentityConfigError, load_runner_identity_settings
from redagent_platform.runner_service.contracts import RunnerRegistration
from redagent_platform.runner_service.identity import (
    authorize_peer_identity,
    build_runner_ssl_context,
    build_server_ssl_context,
    load_peer_identity,
)


NOW = datetime(2026, 7, 10, 15, 0, tzinfo=timezone.utc)


def _issue(
    *,
    issuer_key: rsa.RSAPrivateKey,
    issuer_cert: x509.Certificate,
    common_name: str,
    uri: str | None = None,
    dns: str | None = None,
    client: bool = False,
    server: bool = False,
    not_before: datetime = NOW - timedelta(minutes=1),
    not_after: datetime = NOW + timedelta(days=1),
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names: list[x509.GeneralName] = []
    if uri:
        names.append(x509.UniformResourceIdentifier(uri))
    if dns:
        names.extend((x509.DNSName(dns), x509.IPAddress(ip_address("127.0.0.1"))))
    usages = []
    if client:
        usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if server:
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage(usages), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
    )
    return key, builder.sign(issuer_key, hashes.SHA256())


def _ca(
    common_name: str = "RedAgent compat_100 test CA",
    *,
    not_before: datetime = NOW - timedelta(minutes=5),
    not_after: datetime = NOW + timedelta(days=1),
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _write(path: Path, value: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pki(tmp_path: Path) -> dict[str, Path | x509.Certificate]:
    # IMPORTANT: OpenSSL validates against wall-clock time, while semantic identity tests use frozen NOW.
    runtime_not_after = datetime.now(timezone.utc) + timedelta(days=1)
    ca_key, ca_cert = _ca(not_before=NOW - timedelta(days=1), not_after=runtime_not_after)
    server_key, server_cert = _issue(issuer_key=ca_key, issuer_cert=ca_cert, common_name="localhost", dns="localhost",
        server=True, not_before=NOW - timedelta(days=1), not_after=runtime_not_after)
    runner_key, runner_cert = _issue(
        issuer_key=ca_key,
        issuer_cert=ca_cert,
        common_name="runner-local-1",
        uri="spiffe://redagent.test/runner/runner-local-1",
        client=True,
        not_before=NOW - timedelta(days=1),
        not_after=runtime_not_after,
    )
    return {
        "ca": _write(tmp_path / "pki" / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM)),
        "server_cert": _write(tmp_path / "pki" / "server.pem", server_cert.public_bytes(serialization.Encoding.PEM)),
        "server_key": _write(tmp_path / "pki" / "server-key.pem", _pem_key(server_key)),
        "runner_cert": _write(tmp_path / "pki" / "runner.pem", runner_cert.public_bytes(serialization.Encoding.PEM)),
        "runner_key": _write(tmp_path / "pki" / "runner-key.pem", _pem_key(runner_key)),
        "ca_cert": ca_cert,
        "runner_cert_object": runner_cert,
    }


def _registration(identity, **overrides: object) -> RunnerRegistration:
    values: dict[str, object] = {
        "runner_id": "runner-local-1",
        "tenant_id": "tenant-a",
        "environment": "local-conformance",
        "runner_class_id": "synthetic-standard",
        "network_plane": "isolated-none",
        "spiffe_id": identity.spiffe_id,
        "certificate_fingerprint": identity.certificate_fingerprint,
        "certificate_serial": identity.certificate_serial,
        "adapter_allowlist": ("synthetic-conformance:1.0.0",),
        "image_allowlist": ("sha256:" + "a" * 64,),
        "required_policy_revision": "r099-v1",
        "generation": 1,
        "registered_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
        "revoked_at": None,
    }
    values.update(overrides)
    return RunnerRegistration(**values)  # type: ignore[arg-type]


def test_local_identity_config_requires_loopback_workspace_files_and_no_inline_pem(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    env = {
        "REDAGENT_RUNNER_IDENTITY_PROFILE": "local-conformance",
        "REDAGENT_RUNNER_TRUST_DOMAIN": "redagent.test",
        "REDAGENT_RUNNER_BIND_HOST": "127.0.0.1",
        "REDAGENT_RUNNER_SERVER_NAME": "localhost",
        "REDAGENT_RUNNER_CA_FILE": str(pki["ca"]),
        "REDAGENT_RUNNER_SERVER_CERT_FILE": str(pki["server_cert"]),
        "REDAGENT_RUNNER_SERVER_KEY_FILE": str(pki["server_key"]),  # pragma: allowlist secret
    }
    settings = load_runner_identity_settings(tmp_path, env=env)
    assert settings.profile == "local-conformance" and settings.bind_host == "127.0.0.1"
    with pytest.raises(RunnerIdentityConfigError, match="runner_identity_local_loopback_required"):
        load_runner_identity_settings(tmp_path, env={**env, "REDAGENT_RUNNER_BIND_HOST": "0.0.0.0"})
    with pytest.raises(RunnerIdentityConfigError, match="runner_identity_inline_material_forbidden"):
        load_runner_identity_settings(tmp_path, env={**env, "REDAGENT_RUNNER_SERVER_KEY_PEM": "synthetic"})  # pragma: allowlist secret


def test_production_identity_config_rejects_test_domain_loopback_and_incomplete_files(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    base = {
        "REDAGENT_RUNNER_IDENTITY_PROFILE": "production",
        "REDAGENT_RUNNER_TRUST_DOMAIN": "redagent.test",
        "REDAGENT_RUNNER_BIND_HOST": "127.0.0.1",
        "REDAGENT_RUNNER_SERVER_NAME": "localhost",
        "REDAGENT_RUNNER_CA_FILE": str(pki["ca"]),
        "REDAGENT_RUNNER_SERVER_CERT_FILE": str(pki["server_cert"]),
        "REDAGENT_RUNNER_SERVER_KEY_FILE": str(pki["server_key"]),  # pragma: allowlist secret
    }
    with pytest.raises(RunnerIdentityConfigError, match="runner_identity_production_test_domain_forbidden"):
        load_runner_identity_settings(tmp_path, env=base)
    with pytest.raises(RunnerIdentityConfigError, match="runner_identity_configuration_incomplete"):
        load_runner_identity_settings(tmp_path, env={"REDAGENT_RUNNER_IDENTITY_PROFILE": "local-conformance"})


def test_peer_certificate_requires_current_ca_signed_client_svid_with_exact_uri(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    identity = load_peer_identity(Path(pki["runner_cert"]).read_bytes(), Path(pki["ca"]).read_bytes(), trust_domain="redagent.test", now=NOW)
    assert identity.runner_id == "runner-local-1"
    assert identity.spiffe_id == "spiffe://redagent.test/runner/runner-local-1"
    assert len(identity.certificate_fingerprint) == 64


def test_peer_certificate_rejects_wrong_ca_expiry_wrong_trust_domain_and_missing_client_eku(tmp_path: Path) -> None:
    ca_key, ca_cert = _ca()
    valid_key, valid = _issue(
        issuer_key=ca_key, issuer_cert=ca_cert, common_name="runner-local-1",
        uri="spiffe://redagent.test/runner/runner-local-1", client=True,
    )
    del valid_key
    rogue_key, rogue_ca = _ca("rogue")
    wrong_eku_key, wrong_eku = _issue(
        issuer_key=ca_key, issuer_cert=ca_cert, common_name="runner-local-1",
        uri="spiffe://redagent.test/runner/runner-local-1", server=True,
    )
    del wrong_eku_key, rogue_key
    expired_key, expired = _issue(
        issuer_key=ca_key, issuer_cert=ca_cert, common_name="runner-local-1",
        uri="spiffe://redagent.test/runner/runner-local-1", client=True,
        not_before=NOW - timedelta(minutes=10), not_after=NOW - timedelta(minutes=1),
    )
    del expired_key
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    cases = (
        (valid, rogue_ca.public_bytes(serialization.Encoding.PEM), "runner_identity_chain_invalid"),
        (valid, ca_pem, "runner_identity_trust_domain_mismatch", "other.test"),
        (wrong_eku, ca_pem, "runner_identity_client_eku_required"),
        (expired, ca_pem, "runner_identity_expired"),
    )
    for case in cases:
        cert, authority, reason, *domain = case
        with pytest.raises(ValueError, match=reason):
            load_peer_identity(cert.public_bytes(serialization.Encoding.PEM), authority, trust_domain=domain[0] if domain else "redagent.test", now=NOW)


def test_certificate_authentication_never_replaces_current_registration_authorization(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    identity = load_peer_identity(Path(pki["runner_cert"]).read_bytes(), Path(pki["ca"]).read_bytes(), trust_domain="redagent.test", now=NOW)
    authorized = authorize_peer_identity(
        identity, _registration(identity), environment="local-conformance",
        runner_class_id="synthetic-standard", policy_revision="r099-v1", generation=1, now=NOW,
    )
    assert authorized.runner_id == "runner-local-1"
    failures = (
        (_registration(identity, revoked_at=NOW), "runner_registration_revoked"),
        (_registration(identity, certificate_fingerprint="f" * 64), "runner_identity_registration_mismatch"),
        (_registration(identity), "runner_environment_mismatch", {"environment": "production"}),
        (_registration(identity), "runner_generation_mismatch", {"generation": 2}),
        (_registration(identity), "runner_policy_revision_mismatch", {"policy_revision": "r100-v2"}),
    )
    for registration, reason, *kwargs in failures:
        arguments = {
            "environment": "local-conformance", "runner_class_id": "synthetic-standard",
            "policy_revision": "r099-v1", "generation": 1, "now": NOW,
        }
        arguments.update(kwargs[0] if kwargs else {})
        with pytest.raises(ValueError, match=reason):
            authorize_peer_identity(identity, registration, **arguments)


def _handshake(server_context: ssl.SSLContext, client_context: ssl.SSLContext) -> tuple[bytes | None, list[BaseException]]:
    errors: list[BaseException] = []
    received: list[bytes] = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection, server_context.wrap_socket(connection, server_side=True) as secured:
                received.append(secured.getpeercert(binary_form=True) or b"")
                secured.sendall(b"ok")
        except BaseException as exc:  # transport evidence is returned to the asserting thread
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    response: bytes | None = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            with client_context.wrap_socket(connection, server_hostname="localhost") as secured:
                response = secured.recv(2)
    except BaseException as exc:
        errors.append(exc)
    thread.join(timeout=3)
    return (received[0] if received else response), errors


def test_real_tls_context_requires_mutual_certificate_and_exposes_exact_peer_der(tmp_path: Path) -> None:
    pki = _pki(tmp_path)
    server = build_server_ssl_context(Path(pki["ca"]), Path(pki["server_cert"]), Path(pki["server_key"]))
    runner = build_runner_ssl_context(Path(pki["ca"]), Path(pki["runner_cert"]), Path(pki["runner_key"]))
    peer_der, errors = _handshake(server, runner)
    assert not errors and peer_der
    identity = load_peer_identity(peer_der, Path(pki["ca"]).read_bytes(), trust_domain="redagent.test", now=NOW)
    assert identity.runner_id == "runner-local-1"

    no_certificate = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(pki["ca"]))
    no_certificate.minimum_version = ssl.TLSVersion.TLSv1_3
    _, denied_errors = _handshake(server, no_certificate)
    assert denied_errors and any(isinstance(error, ssl.SSLError) for error in denied_errors)
