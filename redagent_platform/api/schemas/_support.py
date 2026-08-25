"""Primitive imports and constants shared by public API schema modules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


OPAQUE_ID = r"^[A-Za-z0-9._:-]+$"


__all__ = (
    "Any",
    "BaseModel",
    "ConfigDict",
    "datetime",
    "Field",
    "Literal",
    "model_validator",
    "OPAQUE_ID",
    "timedelta",
    "timezone",
)
