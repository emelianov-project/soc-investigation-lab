"""Read-only filtering and ordering for analyst Alert queues."""

from collections.abc import Collection, Mapping
from datetime import datetime
from enum import StrEnum
from itertools import islice

from app.models import Alert, AlertPriority, AlertSeverity, AlertState

from ._validation import read_alert_snapshot

_ACTIVE_STATES = frozenset({AlertState.NEW, AlertState.ACKNOWLEDGED})
_PRIORITY_RANK = {
    AlertPriority.URGENT: 0,
    AlertPriority.HIGH: 1,
    AlertPriority.NORMAL: 2,
    AlertPriority.LOW: 3,
}
_SEVERITY_RANK = {
    AlertSeverity.CRITICAL: 0,
    AlertSeverity.HIGH: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.LOW: 3,
    AlertSeverity.INFORMATIONAL: 4,
    AlertSeverity.UNASSIGNED: 5,
}


class AlertQueueError(ValueError):
    """The queue request failed with a safe reason and field name."""

    def __init__(self, reason: str, field: str) -> None:
        self.reason = reason
        self.field = field
        super().__init__(f"{reason}: {field}")


def list_alerts(
    alerts: Collection[Alert],
    *,
    states: set[AlertState] | frozenset[AlertState] | None = None,
    severities: set[AlertSeverity] | frozenset[AlertSeverity] | None = None,
    priorities: set[AlertPriority] | frozenset[AlertPriority] | None = None,
) -> tuple[Alert, ...]:
    """Validate a finite collection and return detached Alerts in queue order.

    Filters accept nonempty built-in sets or frozensets of the matching enum.
    Omit states to select active Alerts. Omit other filters for no restriction.
    """
    validated: list[Alert] = []
    seen_ids: set[str] = set()
    for entry in _snapshot_collection(alerts):
        snapshot = read_alert_snapshot(entry)
        if snapshot is None:
            raise AlertQueueError("invalid_alert", "alerts") from None
        alert, _ = snapshot
        if alert.alert_id in seen_ids:
            raise AlertQueueError("duplicate_alert_id", "alert_id") from None
        seen_ids.add(alert.alert_id)
        validated.append(alert)

    selected_states = _read_filter(states, AlertState, "states") or _ACTIVE_STATES
    selected_severities = _read_filter(severities, AlertSeverity, "severities")
    selected_priorities = _read_filter(priorities, AlertPriority, "priorities")
    matching = (
        alert
        for alert in validated
        if alert.state in selected_states
        and (selected_severities is None or alert.severity in selected_severities)
        and (selected_priorities is None or alert.priority in selected_priorities)
    )
    return tuple(sorted(matching, key=_queue_key))


def _snapshot_collection(alerts: object) -> tuple[object, ...]:
    if not isinstance(alerts, Collection) or isinstance(
        alerts, (Mapping, str, bytes, bytearray, memoryview)
    ):
        raise AlertQueueError("invalid_collection", "alerts") from None
    try:
        size = len(alerts)
        # One lookahead catches overlong iterators without draining a stream.
        entries = tuple(islice(alerts, size + 1))
    except Exception:
        pass
    else:
        if len(entries) == size:
            return entries
    raise AlertQueueError("invalid_collection", "alerts") from None


def _read_filter[E: StrEnum](
    values: set[E] | frozenset[E] | None, enum_type: type[E], field: str
) -> frozenset[E] | None:
    if values is None:
        return None
    if type(values) not in (set, frozenset):
        raise AlertQueueError("invalid_filter", field) from None
    selected = frozenset(values)
    if not selected or any(type(value) is not enum_type for value in selected):
        raise AlertQueueError("invalid_filter", field) from None
    return selected


def _queue_key(alert: Alert) -> tuple[int, int, datetime, str]:
    return (
        _PRIORITY_RANK[alert.priority],
        _SEVERITY_RANK[alert.severity],
        alert.created_at,
        alert.alert_id,
    )
