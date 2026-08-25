"""Value-discarding compat_112 synthetic submission classifier."""

from enum import Enum
import hmac


class SubmissionCategory(str, Enum):
    SYNTHETIC_ACCEPTED = "synthetic_accepted"
    EMPTY = "empty"
    REJECTED_REAL_OR_UNKNOWN = "rejected_real_or_unknown"


def classify_submission(value: str) -> SubmissionCategory:
    if not isinstance(value, str):
        raise ValueError("human_submission_type_invalid")
    if value == "":
        return SubmissionCategory.EMPTY
    # CRITICAL: compare in memory and return only a closed category; never persist, hash, echo, or log the value.
    if hmac.compare_digest(value, "REDAGENT-R112-SYNTHETIC-ONLY"):
        return SubmissionCategory.SYNTHETIC_ACCEPTED
    return SubmissionCategory.REJECTED_REAL_OR_UNKNOWN
