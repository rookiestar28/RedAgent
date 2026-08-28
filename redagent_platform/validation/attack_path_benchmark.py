"""Deterministic, execution-free activation benchmark for bounded attack paths."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Sequence


CORPUS_SCHEMA = "redagent.attack-path-activation-benchmark/v1"
THRESHOLD_SCHEMA = "redagent.attack-path-activation-threshold/v1"
CERTIFICATION_SCHEMA = "redagent.attack-path-plan-certification/v1"
RECEIPT_SCHEMA = "redagent.attack-path-activation-receipt/v1"
ACTIVATE_BOUNDED_ATTACK_PATH_PLANNING = "ACTIVATE_BOUNDED_ATTACK_PATH_PLANNING"
INSUFFICIENT_CURRENT_NEED = "INSUFFICIENT_CURRENT_NEED"
MAX_CORPUS_BYTES = 256 * 1024
DEPTH_TWO_BOUND = 2
EXPECTED_CAPABILITY_IDS = (
    "artifact-posture",
    "nuclei-trusted-runtime",
    "zap-controlled-runtime",
)
EXPECTED_OBJECTIVE_KINDS = (
    "http_posture",
    "repository_snapshot_posture",
    "security_header_assertion",
)
EXPECTED_OPERATOR_BINDINGS = {
    "artifact-posture:repository-snapshot-posture": (
        "artifact-posture",
        "repository_snapshot_posture",
        1,
    ),
    "nuclei-trusted-runtime:http-posture": (
        "nuclei-trusted-runtime",
        "http_posture",
        2,
    ),
    "nuclei-trusted-runtime:security-header-assertion": (
        "nuclei-trusted-runtime",
        "security_header_assertion",
        2,
    ),
    "zap-controlled-runtime:http-posture": (
        "zap-controlled-runtime",
        "http_posture",
        2,
    ),
    "zap-controlled-runtime:security-header-assertion": (
        "zap-controlled-runtime",
        "security_header_assertion",
        2,
    ),
}
EXPECTED_THRESHOLDS = {
    "schema_version": THRESHOLD_SCHEMA,
    "coverage_fraction_min_basis_points": 1_000,
    "coverage_case_min": 2,
    "quality_gap_fraction_min_basis_points": 1_000,
    "quality_gap_case_min": 2,
    "quality_case_score_max_basis_points": 8_000,
    "quality_mean_score_max_exclusive_basis_points": 9_000,
    "realism_positive_case_min": 1,
}
PROVENANCE_CLASSES = frozenset(
    {"synthetic_owned_loopback", "authorized_history_derived"}
)
_TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:[-_.:][a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BenchmarkError(ValueError):
    """Raised when benchmark input, certification, or authority is invalid."""


@dataclass(frozen=True)
class Operator:
    operator_id: str
    capability_id: str
    objective_kind: str
    preconditions: tuple[str, ...]
    effects: tuple[str, ...]
    risk_cost: int


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    objective_kind: str
    provenance: str
    initial_facts: tuple[str, ...]
    goal_facts: tuple[str, ...]


@dataclass(frozen=True)
class BenchmarkCorpus:
    schema_version: str
    corpus_sha256: str
    capability_ids: tuple[str, ...]
    objective_kinds: tuple[str, ...]
    operators: tuple[Operator, ...]
    cases: tuple[BenchmarkCase, ...]
    thresholds: Mapping[str, object]


@dataclass(frozen=True)
class PlanCertification:
    operator_ids: tuple[str, ...]
    length: int
    cost: int
    final_facts: tuple[str, ...]
    certification_sha256: str


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 of the canonical UTF-8 JSON representation."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_mapping(
    value: object, *, label: str, fields: frozenset[str]
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BenchmarkError(f"{label} fields invalid")
    if not all(isinstance(key, str) for key in value):
        raise BenchmarkError(f"{label} fields invalid")
    return value


def _strict_int(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BenchmarkError(f"{label} invalid")
    return value


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise BenchmarkError(f"{label} invalid")
    return value


def _token_tuple(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise BenchmarkError(f"{label} invalid")
    items = tuple(_token(item, label=label) for item in value)
    if (not allow_empty and not items) or items != tuple(sorted(set(items))):
        raise BenchmarkError(f"{label} must be sorted and unique")
    return items


def _parse_operator(value: object) -> Operator:
    item = _strict_mapping(
        value,
        label="operator",
        fields=frozenset(
            {
                "operator_id",
                "capability_id",
                "objective_kind",
                "preconditions",
                "effects",
                "risk_cost",
            }
        ),
    )
    operator_id = _token(item["operator_id"], label="operator id")
    capability_id = _token(item["capability_id"], label="operator capability")
    objective_kind = _token(item["objective_kind"], label="operator objective")
    expected = EXPECTED_OPERATOR_BINDINGS.get(operator_id)
    if expected is None:
        raise BenchmarkError("operator id invalid")
    if objective_kind not in EXPECTED_OBJECTIVE_KINDS:
        raise BenchmarkError("operator objective invalid")
    risk_cost = _strict_int(item["risk_cost"], label="operator risk cost", minimum=1)
    if (capability_id, objective_kind, risk_cost) != expected:
        raise BenchmarkError("operator binding invalid")
    preconditions = _token_tuple(item["preconditions"], label="operator preconditions")
    effects = _token_tuple(item["effects"], label="operator effects")
    if set(preconditions) & set(effects):
        raise BenchmarkError("operator precondition effect overlap")
    return Operator(
        operator_id=operator_id,
        capability_id=capability_id,
        objective_kind=objective_kind,
        preconditions=preconditions,
        effects=effects,
        risk_cost=risk_cost,
    )


def _parse_case(value: object) -> BenchmarkCase:
    item = _strict_mapping(
        value,
        label="case",
        fields=frozenset(
            {"case_id", "objective_kind", "provenance", "initial_facts", "goal_facts"}
        ),
    )
    case_id = _token(item["case_id"], label="case id")
    objective_kind = _token(item["objective_kind"], label="case objective")
    if objective_kind not in EXPECTED_OBJECTIVE_KINDS:
        raise BenchmarkError("case objective invalid")
    provenance = _token(item["provenance"], label="case provenance")
    if provenance not in PROVENANCE_CLASSES:
        raise BenchmarkError("case provenance invalid")
    initial_facts = _token_tuple(
        item["initial_facts"], label="case initial facts", allow_empty=True
    )
    goal_facts = _token_tuple(item["goal_facts"], label="case goal facts")
    return BenchmarkCase(
        case_id=case_id,
        objective_kind=objective_kind,
        provenance=provenance,
        initial_facts=initial_facts,
        goal_facts=goal_facts,
    )


def _corpus_body(payload: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != "corpus_sha256"}


def parse_corpus(payload: object) -> BenchmarkCorpus:
    """Parse and validate the complete frozen benchmark contract."""
    value = _strict_mapping(
        payload,
        label="corpus",
        fields=frozenset(
            {
                "schema_version",
                "thresholds",
                "capability_ids",
                "operators",
                "cases",
                "corpus_sha256",
            }
        ),
    )
    if value["schema_version"] != CORPUS_SCHEMA:
        raise BenchmarkError("corpus schema invalid")
    digest = value["corpus_sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise BenchmarkError("corpus digest invalid")
    # IMPORTANT: authenticate the complete frozen body before interpreting nested semantics.
    if canonical_sha256(_corpus_body(value)) != digest:
        raise BenchmarkError("corpus digest mismatch")
    thresholds = _strict_mapping(
        value["thresholds"],
        label="threshold",
        fields=frozenset(EXPECTED_THRESHOLDS),
    )
    for key, expected in EXPECTED_THRESHOLDS.items():
        actual = thresholds[key]
        if isinstance(expected, int):
            _strict_int(actual, label="threshold contract")
        if actual != expected:
            raise BenchmarkError("threshold contract invalid")
    if value["capability_ids"] != list(EXPECTED_CAPABILITY_IDS):
        raise BenchmarkError("capability contract invalid")
    capability_ids = EXPECTED_CAPABILITY_IDS
    if not isinstance(value["operators"], list):
        raise BenchmarkError("operators invalid")
    operators = tuple(_parse_operator(item) for item in value["operators"])
    operator_ids = tuple(item.operator_id for item in operators)
    if operator_ids != tuple(sorted(EXPECTED_OPERATOR_BINDINGS)):
        raise BenchmarkError("operators must match the sorted closed binding set")
    if not isinstance(value["cases"], list):
        raise BenchmarkError("cases invalid")
    cases = tuple(_parse_case(item) for item in value["cases"])
    case_ids = tuple(item.case_id for item in cases)
    if len(cases) != 12 or case_ids != tuple(sorted(set(case_ids))):
        raise BenchmarkError("cases must be sorted, unique, and contain twelve entries")
    objective_kinds = tuple(sorted({item.objective_kind for item in cases}))
    if objective_kinds != EXPECTED_OBJECTIVE_KINDS:
        raise BenchmarkError("case objective coverage invalid")
    fact_universe = {
        fact
        for item in operators
        for fact in (*item.preconditions, *item.effects)
    }
    for case in cases:
        if not set((*case.initial_facts, *case.goal_facts)).issubset(fact_universe):
            raise BenchmarkError("case fact outside closed operator domain")
    return BenchmarkCorpus(
        schema_version=CORPUS_SCHEMA,
        corpus_sha256=digest,
        capability_ids=capability_ids,
        objective_kinds=objective_kinds,
        operators=operators,
        cases=cases,
        thresholds=dict(thresholds),
    )


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError("duplicate JSON field")
        result[key] = value
    return result


def decode_json_bytes(payload: bytes, *, label: str, maximum_bytes: int) -> object:
    """Decode one bounded canonical-input JSON document and reject duplicate keys."""
    if (
        not payload
        or len(payload) > maximum_bytes
        or payload.startswith(b"\xef\xbb\xbf")
    ):
        raise BenchmarkError(f"{label} byte contract invalid")
    try:
        return json.loads(
            payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"{label} JSON invalid") from exc


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def load_corpus(path: Path) -> BenchmarkCorpus:
    """Load a bounded regular corpus without following a link/reparse endpoint."""
    if _is_link_or_reparse(path) or not path.is_file():
        raise BenchmarkError("corpus path must be a regular non-link file")
    payload = path.read_bytes()
    decoded = decode_json_bytes(
        payload, label="corpus", maximum_bytes=MAX_CORPUS_BYTES
    )
    return parse_corpus(decoded)


def _operator_map(corpus: BenchmarkCorpus) -> dict[str, Operator]:
    return {item.operator_id: item for item in corpus.operators}


def validate_plan(
    corpus: BenchmarkCorpus,
    case: BenchmarkCase,
    operator_ids: tuple[str, ...],
) -> PlanCertification:
    """Independently replay a proposed plan without calling the oracle transition path."""
    if len(operator_ids) != len(set(operator_ids)):
        raise BenchmarkError("plan operator repeated")
    operators = _operator_map(corpus)
    state = set(case.initial_facts)
    cost = 0
    for operator_id in operator_ids:
        operator = operators.get(operator_id)
        if operator is None:
            raise BenchmarkError("plan operator unknown")
        if operator.objective_kind != case.objective_kind:
            raise BenchmarkError("plan operator objective mismatch")
        if not set(operator.preconditions).issubset(state):
            raise BenchmarkError("plan precondition unsatisfied")
        state.update(operator.effects)
        cost += operator.risk_cost
    if not set(case.goal_facts).issubset(state):
        raise BenchmarkError("plan goal unsatisfied")
    final_facts = tuple(sorted(state))
    body = {
        "schema_version": CERTIFICATION_SCHEMA,
        "case_id": case.case_id,
        "objective_kind": case.objective_kind,
        "operator_ids": list(operator_ids),
        "initial_facts": list(case.initial_facts),
        "goal_facts": list(case.goal_facts),
        "final_facts": list(final_facts),
        "length": len(operator_ids),
        "risk_cost": cost,
        "valid": True,
    }
    return PlanCertification(
        operator_ids=operator_ids,
        length=len(operator_ids),
        cost=cost,
        final_facts=final_facts,
        certification_sha256=canonical_sha256(body),
    )


def _oracle_apply(state: frozenset[str], operator: Operator) -> frozenset[str] | None:
    """Oracle-only transition path; the independent validator does not call this helper."""
    if not set(operator.preconditions).issubset(state):
        return None
    return state.union(operator.effects)


def _find_plan(
    corpus: BenchmarkCorpus,
    case: BenchmarkCase,
    *,
    rank_by: str,
    max_depth: int | None = None,
) -> tuple[str, ...] | None:
    candidates = tuple(
        item for item in corpus.operators if item.objective_kind == case.objective_kind
    )
    limit = len(candidates) if max_depth is None else min(max_depth, len(candidates))
    solutions: list[tuple[tuple[object, ...], tuple[str, ...]]] = []
    for length in range(limit + 1):
        for sequence in permutations(candidates, length):
            state = frozenset(case.initial_facts)
            valid = True
            for operator in sequence:
                next_state = _oracle_apply(state, operator)
                if next_state is None:
                    valid = False
                    break
                state = next_state
            if not valid or not set(case.goal_facts).issubset(state):
                continue
            operator_ids = tuple(item.operator_id for item in sequence)
            cost = sum(item.risk_cost for item in sequence)
            if rank_by == "length":
                rank: tuple[object, ...] = (length, cost, operator_ids)
            elif rank_by == "cost":
                rank = (cost, length, operator_ids)
            else:
                raise BenchmarkError("oracle rank mode invalid")
            solutions.append((rank, operator_ids))
    if not solutions:
        return None
    return min(solutions, key=lambda item: item[0])[1]


def decide_activation(
    *,
    coverage_signal: bool,
    quality_signal: bool,
    positive_case_provenances: tuple[str, ...],
) -> str:
    """Apply the predeclared realism gate to already-computed mechanical signals."""
    if any(item not in PROVENANCE_CLASSES for item in positive_case_provenances):
        raise BenchmarkError("positive case provenance invalid")
    if (coverage_signal or quality_signal) and not positive_case_provenances:
        raise BenchmarkError("positive signal case evidence missing")
    realism_gate = "authorized_history_derived" in positive_case_provenances
    if realism_gate and (coverage_signal or quality_signal):
        return ACTIVATE_BOUNDED_ATTACK_PATH_PLANNING
    return INSUFFICIENT_CURRENT_NEED


def run_benchmark(corpus: BenchmarkCorpus) -> dict[str, object]:
    """Evaluate every frozen case and emit one canonical authority-false receipt."""
    certifications: list[dict[str, object]] = []
    coverage_case_ids: list[str] = []
    quality_gap_case_ids: list[str] = []
    quality_scores: list[int] = []
    positive_provenances: list[str] = []
    case_by_id = {item.case_id: item for item in corpus.cases}
    for case in corpus.cases:
        optimal_length_plan = _find_plan(corpus, case, rank_by="length")
        optimal_cost_plan = _find_plan(corpus, case, rank_by="cost")
        depth_two_plan = _find_plan(
            corpus, case, rank_by="cost", max_depth=DEPTH_TWO_BOUND
        )
        if optimal_length_plan is None or optimal_cost_plan is None:
            raise BenchmarkError("corpus case is not solvable")
        optimal_length_cert = validate_plan(corpus, case, optimal_length_plan)
        optimal_cost_cert = validate_plan(corpus, case, optimal_cost_plan)
        if optimal_length_cert.length >= 3:
            coverage_case_ids.append(case.case_id)
        depth_two_cert: PlanCertification | None = None
        quality_basis_points: int | None = None
        if depth_two_plan is not None:
            depth_two_cert = validate_plan(corpus, case, depth_two_plan)
            if depth_two_cert.cost == 0:
                if optimal_cost_cert.cost != 0:
                    raise BenchmarkError("zero-cost quality relation invalid")
                quality_basis_points = 10_000
            else:
                quality_basis_points = (
                    optimal_cost_cert.cost * 10_000 // depth_two_cert.cost
                )
            if not 0 <= quality_basis_points <= 10_000:
                raise BenchmarkError("quality score invalid")
            quality_scores.append(quality_basis_points)
            if (
                quality_basis_points
                <= EXPECTED_THRESHOLDS["quality_case_score_max_basis_points"]
            ):
                quality_gap_case_ids.append(case.case_id)
        result: dict[str, object] = {
            "case_id": case.case_id,
            "objective_kind": case.objective_kind,
            "provenance": case.provenance,
            "optimal_length_plan": list(optimal_length_plan),
            "optimal_length": optimal_length_cert.length,
            "optimal_length_cost": optimal_length_cert.cost,
            "optimal_length_certification_sha256": optimal_length_cert.certification_sha256,
            "optimal_cost_plan": list(optimal_cost_plan),
            "optimal_cost": optimal_cost_cert.cost,
            "optimal_cost_certification_sha256": optimal_cost_cert.certification_sha256,
            "depth_two_solved": depth_two_cert is not None,
            "depth_two_plan": list(depth_two_plan) if depth_two_plan is not None else None,
            "depth_two_cost": depth_two_cert.cost if depth_two_cert is not None else None,
            "depth_two_certification_sha256": (
                depth_two_cert.certification_sha256 if depth_two_cert is not None else None
            ),
            "quality_score_basis_points": quality_basis_points,
        }
        result["case_certification_sha256"] = canonical_sha256(result)
        certifications.append(result)
    total = len(corpus.cases)
    coverage_fraction = len(coverage_case_ids) * 10_000 // total
    quality_eligible = len(quality_scores)
    quality_gap_fraction = (
        len(quality_gap_case_ids) * 10_000 // quality_eligible
        if quality_eligible
        else 0
    )
    quality_mean = sum(quality_scores) // quality_eligible if quality_eligible else 0
    coverage_signal = (
        len(coverage_case_ids) >= EXPECTED_THRESHOLDS["coverage_case_min"]
        and coverage_fraction
        >= EXPECTED_THRESHOLDS["coverage_fraction_min_basis_points"]
    )
    quality_signal = (
        len(quality_gap_case_ids) >= EXPECTED_THRESHOLDS["quality_gap_case_min"]
        and quality_gap_fraction
        >= EXPECTED_THRESHOLDS["quality_gap_fraction_min_basis_points"]
        and quality_mean
        < EXPECTED_THRESHOLDS["quality_mean_score_max_exclusive_basis_points"]
    )
    positive_ids = set(coverage_case_ids) | set(quality_gap_case_ids)
    positive_provenances.extend(case_by_id[item].provenance for item in sorted(positive_ids))
    decision = decide_activation(
        coverage_signal=coverage_signal,
        quality_signal=quality_signal,
        positive_case_provenances=tuple(positive_provenances),
    )
    provenance_values = {item.provenance for item in corpus.cases}
    provenance_profile = (
        "synthetic_owned_loopback_only"
        if provenance_values == {"synthetic_owned_loopback"}
        else "mixed_with_authorized_history"
    )
    body: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA,
        "benchmark_role": "activation-only",
        "corpus_sha256": corpus.corpus_sha256,
        "threshold_schema": THRESHOLD_SCHEMA,
        "thresholds_sha256": canonical_sha256(dict(corpus.thresholds)),
        "current_depth_bound": DEPTH_TWO_BOUND,
        "case_count": total,
        "coverage_case_count": len(coverage_case_ids),
        "coverage_case_ids": coverage_case_ids,
        "coverage_fraction_basis_points": coverage_fraction,
        "coverage_signal": coverage_signal,
        "quality_eligible_case_count": quality_eligible,
        "quality_gap_case_count": len(quality_gap_case_ids),
        "quality_gap_case_ids": quality_gap_case_ids,
        "quality_gap_fraction_basis_points": quality_gap_fraction,
        "quality_mean_basis_points": quality_mean,
        "quality_signal": quality_signal,
        "realism_positive_case_count": sum(
            item == "authorized_history_derived" for item in positive_provenances
        ),
        "realism_gate_passed": "authorized_history_derived" in positive_provenances,
        "provenance_profile": provenance_profile,
        "provenance_counts": {
            item: sum(case.provenance == item for case in corpus.cases)
            for item in sorted(PROVENANCE_CLASSES)
        },
        "decision": decision,
        "case_certifications": certifications,
        "execution_authority": False,
        "release_approval": False,
        "production_release_authority": False,
        "go_authority": False,
        "ga_authority": False,
    }
    return {**body, "receipt_sha256": canonical_sha256(body)}


def verify_receipt(
    corpus: BenchmarkCorpus, receipt: object
) -> dict[str, object]:
    """Recompute and byte-logically compare a receipt without trusting receipt fields."""
    if not isinstance(receipt, Mapping) or not all(
        isinstance(key, str) for key in receipt
    ):
        raise BenchmarkError("receipt object invalid")
    expected = run_benchmark(corpus)
    if dict(receipt) != expected:
        raise BenchmarkError("receipt verification failed")
    return expected
