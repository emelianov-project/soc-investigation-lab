"""Shared validation for operations that update Alert values."""

from datetime import UTC, datetime
from typing import Any

from app.models import Alert

_ALERT_TIMESTAMPS = ("created_at", "state_changed_at", "updated_at")


def normalize_change_time(value: datetime) -> datetime | None:
    try:
        return Alert.require_aware_utc_instant(value)
    except Exception:
        # A caller-provided tzinfo can raise during offset lookup or conversion.
        return None


def validate_alert_fields(fields: dict[str, Any]) -> Alert | None:
    try:
        return Alert.model_validate(fields, strict=True)
    except Exception:
        # Operation-specific errors must not carry validation or evidence details.
        return None


def read_alert_snapshot(alert: object) -> tuple[Alert, dict[str, Any]] | None:
    if not isinstance(alert, Alert):
        return None

    try:
        # Pydantic iteration hides underscore-prefixed keys injected via model_copy.
        if vars(alert).keys() != Alert.model_fields.keys():
            return None
        # Iteration detaches evidence. Reject noncanonical timestamps before the
        # model can normalize values that bypassed validation via model_copy.
        fields = dict(alert)
        if fields.keys() != Alert.model_fields.keys() or not all(
            isinstance(value, datetime) and value.tzinfo is UTC
            for value in (fields[name] for name in _ALERT_TIMESTAMPS)
        ):
            return None
    except Exception:
        return None

    current = validate_alert_fields(fields)
    if current is None:
        return None
    return current, fields
