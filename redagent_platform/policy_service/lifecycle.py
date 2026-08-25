"""Pure fail-closed policy bundle activation rules for compat_099 transactions."""

from __future__ import annotations

from dataclasses import dataclass
import re


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class PolicyLifecycleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BundleRevision:
    """Immutable metadata for a repository-reviewed snapshot bundle."""

    revision: str
    source_sha256: str
    artifact_sha256: str
    artifact_size: int
    manifest_roots: tuple[str, ...]
    rego_version: int
    signing_key_id: str
    signing_scope: str
    signing_algorithm: str
    author_user_id: str
    reviewer_user_id: str
    test_evidence_sha256: str
    conformance_sha256: str
    coverage_basis_points: int
    signature_verified: bool
    status: str

    def __post_init__(self) -> None:
        for value in (
            self.revision, self.signing_key_id, self.signing_scope,
            self.author_user_id, self.reviewer_user_id,
        ):
            _identifier(value)
        for value in (
            self.source_sha256, self.artifact_sha256,
            self.test_evidence_sha256, self.conformance_sha256,
        ):
            if not isinstance(value, str) or not _HASH.fullmatch(value):
                raise PolicyLifecycleError("policy_bundle_hash_invalid")
        if self.author_user_id == self.reviewer_user_id:
            raise PolicyLifecycleError("policy_bundle_review_separation_required")
        if self.manifest_roots != ("redagent", "system") or self.rego_version != 1:
            raise PolicyLifecycleError("policy_bundle_manifest_invalid")
        if self.signing_algorithm != "RS256" or not self.signature_verified:
            raise PolicyLifecycleError("policy_bundle_signature_invalid")
        if (
            isinstance(self.artifact_size, bool)
            or not 1 <= self.artifact_size <= 4 * 1024 * 1024
        ):
            raise PolicyLifecycleError("policy_bundle_size_invalid")
        if (
            isinstance(self.coverage_basis_points, bool)
            or not 8_000 <= self.coverage_basis_points <= 10_000
        ):
            raise PolicyLifecycleError("policy_bundle_coverage_invalid")
        if self.status != "accepted":
            raise PolicyLifecycleError("policy_bundle_not_accepted")


@dataclass(frozen=True, slots=True)
class BundleAcknowledgement:
    agent_id: str
    active_revision: str
    artifact_sha256: str
    bundle_state: str
    status_fresh: bool

    def __post_init__(self) -> None:
        _identifier(self.agent_id)
        _identifier(self.active_revision)
        if not _HASH.fullmatch(self.artifact_sha256):
            raise PolicyLifecycleError("policy_bundle_hash_invalid")
        if self.bundle_state != "OK" or self.status_fresh is not True:
            raise PolicyLifecycleError("policy_bundle_agent_not_ready")


@dataclass(frozen=True, slots=True)
class BundleActivation:
    required_revision: str
    previous_revision: str
    artifact_sha256: str
    acknowledged_agents: tuple[str, ...]
    rollback: bool


def activate_bundle(
    candidate: BundleRevision,
    *,
    required_agents: tuple[str, ...],
    acknowledgements: tuple[BundleAcknowledgement, ...],
    current_revision: str,
    rollback: bool = False,
) -> BundleActivation:
    """Return activation metadata only after exact all-agent convergence.

    The caller persists this result together with audit/outbox state in one
    database transaction. This function never accepts policy source or bytes.
    """

    if not isinstance(candidate, BundleRevision):
        raise PolicyLifecycleError("policy_bundle_candidate_invalid")
    _identifier(current_revision)
    if not isinstance(rollback, bool):
        raise PolicyLifecycleError("policy_bundle_rollback_invalid")
    if (
        not isinstance(required_agents, tuple)
        or not required_agents
        or len(required_agents) > 64
        or len(set(required_agents)) != len(required_agents)
    ):
        raise PolicyLifecycleError("policy_bundle_required_agents_invalid")
    for agent_id in required_agents:
        _identifier(agent_id)
    if (
        not isinstance(acknowledgements, tuple)
        or len(acknowledgements) != len(required_agents)
        or len({item.agent_id for item in acknowledgements}) != len(acknowledgements)
        or {item.agent_id for item in acknowledgements} != set(required_agents)
    ):
        raise PolicyLifecycleError("policy_bundle_agent_convergence_required")
    for acknowledgement in acknowledgements:
        if (
            acknowledgement.active_revision != candidate.revision
            or acknowledgement.artifact_sha256 != candidate.artifact_sha256
        ):
            raise PolicyLifecycleError("policy_bundle_agent_revision_mismatch")
    if candidate.revision == current_revision:
        raise PolicyLifecycleError("policy_bundle_revision_already_required")
    return BundleActivation(
        required_revision=candidate.revision,
        previous_revision=current_revision,
        artifact_sha256=candidate.artifact_sha256,
        acknowledged_agents=tuple(sorted(required_agents)),
        rollback=rollback,
    )


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise PolicyLifecycleError("policy_bundle_identifier_invalid")
