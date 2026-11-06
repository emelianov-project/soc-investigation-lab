"""Independent severity and priority updates for active Alerts."""

from datetime import datetime
from typing import Literal

from app.models import Alert, AlertPriority, AlertSeverity, AlertState

from ._validation import normalize_change_time, read_alert_snapshot, validate_alert_fields


class AlertPolicyError(ValueError):
    """A policy update failed with a safe reason and field name."""

    def __init__(self, reason: str, field: str) -> None:
        self.reason = reason
        self.field = field
        super().__init__(f"{reason}: {field}")


def set_severity(alert: Alert, value: AlertSeverity, changed_at: datetime) -> Alert:
    """Assign security significance to an active Alert."""
    return _set_policy(alert, "severity", value, changed_at)


def set_priority(alert: Alert, value: AlertPriority, changed_at: datetime) -> Alert:
    """Assign operational urgency to an active Alert."""
    return _set_policy(alert, "priority", value, changed_at)


def _set_policy(
    alert: Alert,
    field: Literal["severity", "priority"],
    value: AlertSeverity | AlertPriority,
    changed_at: datetime,
) -> Alert:
    snapshot = read_alert_snapshot(alert)
    if snapshot is None:
        raise AlertPolicyError("invalid_alert", "alert") from None
    current, fields = snapshot

    previous = current.severity if field == "severity" else current.priority
    if type(value) is not type(previous):
        raise AlertPolicyError("invalid_value", field) from None

    instant = normalize_change_time(changed_at)
    if instant is None:
        raise AlertPolicyError("invalid_changed_at", "changed_at") from None
    if instant < current.updated_at:
        raise AlertPolicyError("out_of_order_changed_at", "changed_at") from None
    if current.state is AlertState.CLOSED:
        raise AlertPolicyError("closed_alert", "state") from None
    if value is previous:
        return current

    fields[field] = value
    fields["updated_at"] = instant
    updated = validate_alert_fields(fields)
    if updated is None:
        raise AlertPolicyError("invalid_alert", "alert") from None
    return updated
