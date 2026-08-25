"""X.509-SVID parsing, current registration authorization, and TLS contexts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from redagent_platform.runner_service.contracts import RunnerRegistration


_TRUST_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_RUNNER_SVID = re.compile(r"^spiffe://(?P<domain>[a-z0-9.-]+)/runner/(?P<runner>[A-Za-z0-9][A-Za-z0-9._:-]{0,99})$")


@dataclass(frozen=True, slots=True)
class PeerCertificateIdentity:
    runner_id: str
    spiffe_id: str
    certificate_fingerprint: str
    certificate_serial: str
    not_before: datetime
    not_after: datetime


def load_peer_identity(
    certificate_bytes: bytes,
    authority_bytes: bytes,
    *,
    trust_domain: str,
    now: datetime,
) -> PeerCertificateIdentity:
    _aware(now)
    if not _TRUST_DOMAIN.fullmatch(trust_domain):
        raise ValueError("runner_identity_trust_domain_invalid")
    certificate = _load_certificate(certificate_bytes)
    authority = _load_certificate(authority_bytes)
    _validate_authority(authority, now)
    try:
        certificate.verify_directly_issued_by(authority)
    except (ValueError, TypeError) as exc:
        raise ValueError("runner_identity_chain_invalid") from exc
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError("runner_identity_expired")
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("runner_identity_required_extension_missing") from exc
    if constraints.ca:
        raise ValueError("runner_identity_leaf_ca_forbidden")
    if not usage.digital_signature:
        raise ValueError("runner_identity_digital_signature_required")
    if ExtendedKeyUsageOID.CLIENT_AUTH not in extended:
        raise ValueError("runner_identity_client_eku_required")
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or len(tuple(san)) != 1:
        raise ValueError("runner_identity_single_uri_required")
    match = _RUNNER_SVID.fullmatch(uris[0])
    if match is None:
        raise ValueError("runner_identity_spiffe_id_invalid")
    if match.group("domain") != trust_domain:
        raise ValueError("runner_identity_trust_domain_mismatch")
    return PeerCertificateIdentity(
        runner_id=match.group("runner"),
        spiffe_id=uris[0],
        certificate_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        certificate_serial=str(certificate.serial_number),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
    )


def authorize_peer_identity(
    identity: PeerCertificateIdentity,
    registration: RunnerRegistration,
    *,
    environment: str,
    runner_class_id: str,
    policy_revision: str,
    generation: int,
    now: datetime,
) -> RunnerRegistration:
    _aware(now)
    if not identity.not_before <= now < identity.not_after:
        raise ValueError("runner_identity_expired")
    if registration.revoked_at is not None and registration.revoked_at <= now:
        raise ValueError("runner_registration_revoked")
    if not registration.registered_at <= now < registration.expires_at:
        raise ValueError("runner_registration_expired")
    if (
        identity.runner_id != registration.runner_id
        or identity.spiffe_id != registration.spiffe_id
        or identity.certificate_fingerprint != registration.certificate_fingerprint
        or identity.certificate_serial != registration.certificate_serial
    ):
        raise ValueError("runner_identity_registration_mismatch")
    if registration.environment != environment:
        raise ValueError("runner_environment_mismatch")
    if registration.runner_class_id != runner_class_id:
        raise ValueError("runner_class_mismatch")
    if registration.required_policy_revision != policy_revision:
        raise ValueError("runner_policy_revision_mismatch")
    if registration.generation != generation:
        raise ValueError("runner_generation_mismatch")
    return registration


def build_server_ssl_context(ca_file: Path, certificate_file: Path, key_file: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(certificate_file), str(key_file))
    context.load_verify_locations(cafile=str(ca_file))
    context.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context


def build_runner_ssl_context(ca_file: Path, certificate_file: Path, key_file: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(certificate_file), str(key_file))
    return context


def _load_certificate(value: bytes) -> x509.Certificate:
    if not isinstance(value, bytes) or not value:
        raise ValueError("runner_identity_certificate_invalid")
    try:
        if value.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(value)
        return x509.load_der_x509_certificate(value)
    except ValueError as exc:
        raise ValueError("runner_identity_certificate_invalid") from exc


def _validate_authority(authority: x509.Certificate, now: datetime) -> None:
    if not authority.not_valid_before_utc <= now < authority.not_valid_after_utc:
        raise ValueError("runner_identity_authority_expired")
    try:
        constraints = authority.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = authority.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("runner_identity_authority_invalid") from exc
    if not constraints.ca or not usage.key_cert_sign:
        raise ValueError("runner_identity_authority_invalid")


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
