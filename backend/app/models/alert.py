"""Validated, data-only Alert contracts for the v0.4 domain boundary."""

from __future__ import annotations

import re
from collections.abc import Generator
from copy import deepcopy
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .detection import DetectionMatch

_ALERT_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_Timestamp = Annotated[datetime, Field(strict=True)]


class AlertState(StrEnum):
    """The complete v0.4 Alert lifecycle state set."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class AlertSeverity(StrEnum):
    """Security significance, separate from handling urgency."""

    UNASSIGNED = "unassigned"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertPriority(StrEnum):
    """Operational handling urgency, separate from security significance."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class Alert(BaseModel):
    """One immutable Alert value with independently owned detection evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    alert_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    source_match: DetectionMatch = Field(repr=False)
    created_at: _Timestamp
    state: AlertState = AlertState.NEW
    state_changed_at: _Timestamp
    severity: AlertSeverity = AlertSeverity.UNASSIGNED
    priority: AlertPriority = AlertPriority.NORMAL
    updated_at: _Timestamp

    @field_validator("alert_id")
    @classmethod
    def validate_alert_id(cls, value: str) -> str:
        if not _ALERT_ID.fullmatch(value):
            raise ValueError("alert_id must be an ASCII lowercase slug")
        return value

    @field_validator("source_match", mode="before")
    @classmethod
    def own_validated_match(cls, value: object) -> DetectionMatch:
        if not isinstance(value, DetectionMatch):
            raise ValueError("source_match must be a validated DetectionMatch")
        try:
            # Revalidate a deep copy: an existing Pydantic instance may have had nested data mutated.
            data = deepcopy(value.model_dump(mode="python", exclude_unset=True))
            return DetectionMatch.model_validate(data)
        except (TypeError, ValueError, ValidationError):
            raise ValueError("source_match must be a valid true DetectionMatch") from None

    @field_validator("created_at", "state_changed_at", "updated_at", mode="before")
    @classmethod
    def require_aware_utc_instant(cls, value: object) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("alert timestamps must be timezone-aware datetime values")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_timestamp_order(self) -> Self:
        if not self.created_at <= self.state_changed_at <= self.updated_at:
            raise ValueError(
                "alert timestamps must satisfy created_at <= state_changed_at <= updated_at"
            )
        return self

    def __getattribute__(self, name: str) -> Any:
        value = super().__getattribute__(name)
        if name == "source_match":
            # The stored Pydantic graph contains mutable lists and dictionaries.
            return deepcopy(value)
        return value

    def __iter__(self) -> Generator[tuple[str, Any], None, None]:
        # Pydantic's default iteration otherwise yields the raw field reference.
        for name, value in super().__iter__():
            yield name, deepcopy(value) if name == "source_match" else value
