"""Explicit state transitions for immutable Alert values."""

from datetime import UTC, datetime

from app.models import Alert, AlertState

_ALERT_TIMESTAMPS = ("created_at", "state_changed_at", "updated_at")


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


def _normalize_at(at: datetime) -> datetime:
    try:
        return Alert.require_aware_utc_instant(at)
    except Exception:
        # A caller-provided tzinfo can raise during offset lookup or conversion.
        pass
    raise AlertTransitionError("invalid_at", "at") from None


def _transition(
    alert: Alert, at: datetime, source_state: AlertState, target_state: AlertState
) -> Alert:
    if not isinstance(alert, Alert):
        raise AlertTransitionError("invalid_alert", "alert")

    current: Alert | None = None
    try:
        # Iteration supplies a detached match. Check canonical timestamps before
        # validation can normalize a snapshot that bypassed the model.
        fields = dict(alert)
        if fields.keys() == Alert.model_fields.keys() and all(
            isinstance(value, datetime) and value.tzinfo is UTC
            for value in (fields[name] for name in _ALERT_TIMESTAMPS)
        ):
            current = Alert.model_validate(fields, strict=True)
    except Exception:
        # Invalid evidence may fail during copying as well as validation.
        pass
    if current is None:
        raise AlertTransitionError("invalid_alert", "alert") from None

    instant = _normalize_at(at)
    if instant < current.updated_at:
        raise AlertTransitionError("out_of_order_at", "at")
    if current.state is target_state:
        return current
    if current.state is not source_state:
        raise AlertTransitionError("forbidden_transition", "state")

    fields.update(state=target_state, state_changed_at=instant, updated_at=instant)
    try:
        return Alert.model_validate(fields, strict=True)
    except Exception:
        pass
    raise AlertTransitionError("invalid_alert", "alert") from None
