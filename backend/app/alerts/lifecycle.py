"""Explicit state transitions for immutable Alert values."""

from datetime import datetime

from app.models import Alert, AlertState

from ._validation import normalize_change_time, read_alert_snapshot, validate_alert_fields


class AlertTransitionError(ValueError):
    """A lifecycle request failed with a safe reason and field name."""

    def __init__(self, reason: str, field: str) -> None:
        self.reason = reason
        self.field = field
        super().__init__(f"{reason}: {field}")


def acknowledge_alert(alert: Alert, at: datetime) -> Alert:
    """Acknowledge a NEW Alert or validate an ACKNOWLEDGED no-op."""
    return _transition(alert, at, AlertState.NEW, AlertState.ACKNOWLEDGED)


def close_alert(alert: Alert, at: datetime) -> Alert:
    """Close an ACKNOWLEDGED Alert or validate a CLOSED no-op."""
    return _transition(alert, at, AlertState.ACKNOWLEDGED, AlertState.CLOSED)


def _transition(
    alert: Alert, at: datetime, source_state: AlertState, target_state: AlertState
) -> Alert:
    snapshot = read_alert_snapshot(alert)
    if snapshot is None:
        raise AlertTransitionError("invalid_alert", "alert") from None
    current, fields = snapshot

    instant = normalize_change_time(at)
    if instant is None:
        raise AlertTransitionError("invalid_at", "at") from None
    if instant < current.updated_at:
        raise AlertTransitionError("out_of_order_at", "at")
    if current.state is target_state:
        return current
    if current.state is not source_state:
        raise AlertTransitionError("forbidden_transition", "state")

    fields.update(state=target_state, state_changed_at=instant, updated_at=instant)
    updated = validate_alert_fields(fields)
    if updated is None:
        raise AlertTransitionError("invalid_alert", "alert") from None
    return updated
