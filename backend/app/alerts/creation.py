"""Construct validated Alert values from existing detection evidence."""

from datetime import datetime

from pydantic import ValidationError

from app.models import Alert, AlertPriority, AlertSeverity, AlertState, DetectionMatch

_PUBLIC_FIELDS = {
    "source_match": "match",
    "alert_id": "alert_id",
    "created_at": "created_at",
    "state_changed_at": "created_at",
    "updated_at": "created_at",
}


class AlertCreationError(ValueError):
    """A creation input failed validation, with no evidence in the diagnostics."""

    def __init__(self, field: str | None = None) -> None:
        self.field = field
        self.reason = f"invalid_{field}" if field is not None else "invalid_input"
        super().__init__(self.reason)


def create_alert(
    match: DetectionMatch,
    alert_id: str,
    created_at: datetime,
    *,
    severity: AlertSeverity = AlertSeverity.UNASSIGNED,
    priority: AlertPriority = AlertPriority.NORMAL,
) -> Alert:
    """Create a NEW Alert from a TRUE match using an explicit ID and instant."""
    if not isinstance(severity, AlertSeverity):
        raise AlertCreationError("severity")
    if not isinstance(priority, AlertPriority):
        raise AlertCreationError("priority")

    try:
        return Alert(
            alert_id=alert_id,
            source_match=match,
            created_at=created_at,
            state=AlertState.NEW,
            state_changed_at=created_at,
            severity=severity,
            priority=priority,
            updated_at=created_at,
        )
    except ValidationError as error:
        location = error.errors(include_url=False, include_context=False, include_input=False)[0][
            "loc"
        ]
        field = (
            _PUBLIC_FIELDS.get(location[0]) if location and isinstance(location[0], str) else None
        )
    except (TypeError, ValueError, OverflowError):
        field = None

    # Raise outside the handlers so the public error does not retain the validation exception.
    raise AlertCreationError(field) from None
