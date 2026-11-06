"""Tests for the stateless analyst Alert queue."""

import warnings
from collections.abc import Collection, Iterator
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from itertools import permutations
from traceback import format_exception
from typing import Any, cast

import pytest
from app.alerts import (
    AlertQueueError,
    acknowledge_alert,
    close_alert,
    create_alert,
    list_alerts,
)
from app.models import (
    Alert,
    AlertPriority,
    AlertSeverity,
    AlertState,
    ConditionOutcome,
    ConditionTrace,
    DetectionMatch,
    DetectionOperator,
    EventCategory,
    EventSource,
    NetworkContext,
    NormalizedEvent,
)

START = datetime(2026, 10, 1, 12, tzinfo=UTC)
HOST = "queue-fixture.example.com"
SOURCE_VALUE = "queue-fixture-source"
EXPECTED = "queue-fixture-expected"
ACTUAL = f"{EXPECTED}-actual"


@pytest.fixture
def match() -> DetectionMatch:
    event = NormalizedEvent(
        source=EventSource.SYSMON,
        provider="Microsoft-Windows-Sysmon",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        timestamp=START,
        computer=HOST,
        category=EventCategory.NETWORK,
        context=NetworkContext(
            source_ip=IPv4Address("192.0.2.10"),
            source_port=49152,
            destination_ip=IPv4Address("198.51.100.20"),
            destination_port=443,
        ),
        source_data={"ExampleField": SOURCE_VALUE, "TraceField": ACTUAL},
    )
    return DetectionMatch(
        rule_id="example-network-rule",
        rule_version=1,
        rule_title="Example network match",
        event=event,
        root_outcome=ConditionOutcome.TRUE,
        trace=ConditionTrace(
            location="$",
            kind="leaf",
            outcome=ConditionOutcome.TRUE,
            field="source_data.TraceField",
            op=DetectionOperator.CONTAINS,
            expected=EXPECTED,
            actual=ACTUAL,
        ),
    )


def _alert(
    match: DetectionMatch,
    alert_id: str = "example-alert",
    *,
    state: AlertState = AlertState.NEW,
    severity: AlertSeverity = AlertSeverity.UNASSIGNED,
    priority: AlertPriority = AlertPriority.NORMAL,
    created_at: datetime = START,
) -> Alert:
    alert = create_alert(match, alert_id, created_at, severity=severity, priority=priority)
    if state is AlertState.NEW:
        return alert
    acknowledged = acknowledge_alert(alert, created_at)
    if state is AlertState.ACKNOWLEDGED:
        return acknowledged
    return close_alert(acknowledged, created_at)


def test_empty_collection() -> None:
    assert list_alerts(()) == ()
    assert list_alerts([], states={AlertState.CLOSED}) == ()


def test_default_and_explicit_state_selection(match: DetectionMatch) -> None:
    new = _alert(match, "a-new")
    acknowledged = _alert(match, "b-acknowledged", state=AlertState.ACKNOWLEDGED)
    closed = _alert(match, "c-closed", state=AlertState.CLOSED)
    alerts = [closed, acknowledged, new]

    assert list_alerts(alerts) == (new, acknowledged)
    assert list_alerts(alerts, states=set(AlertState)) == (new, acknowledged, closed)
    for alert in alerts:
        assert list_alerts(alerts, states=frozenset({alert.state})) == (alert,)


@pytest.mark.parametrize("severity", list(AlertSeverity))
def test_every_severity_filter(match: DetectionMatch, severity: AlertSeverity) -> None:
    alerts = {value: _alert(match, value.value, severity=value) for value in AlertSeverity}
    assert list_alerts(alerts.values(), severities={severity}) == (alerts[severity],)


@pytest.mark.parametrize("priority", list(AlertPriority))
def test_every_priority_filter(match: DetectionMatch, priority: AlertPriority) -> None:
    alerts = {value: _alert(match, value.value, priority=value) for value in AlertPriority}
    assert list_alerts(alerts.values(), priorities={priority}) == (alerts[priority],)


def test_filters_union_within_dimensions_and_intersect_across_them(match: DetectionMatch) -> None:
    first = _alert(match, "first", severity=AlertSeverity.HIGH, priority=AlertPriority.URGENT)
    second = _alert(
        match,
        "second",
        state=AlertState.ACKNOWLEDGED,
        severity=AlertSeverity.LOW,
        priority=AlertPriority.HIGH,
    )
    wrong_state = _alert(
        match,
        "wrong-state",
        state=AlertState.CLOSED,
        severity=AlertSeverity.HIGH,
        priority=AlertPriority.HIGH,
    )
    wrong_severity = _alert(match, "wrong-severity", priority=AlertPriority.HIGH)
    wrong_priority = _alert(match, "wrong-priority", severity=AlertSeverity.LOW)
    alerts = (wrong_state, second, wrong_severity, first, wrong_priority)
    assert list_alerts(
        alerts,
        states={AlertState.NEW, AlertState.ACKNOWLEDGED},
        severities={AlertSeverity.HIGH, AlertSeverity.LOW},
        priorities=frozenset({AlertPriority.HIGH, AlertPriority.URGENT}),
    ) == (first, second)
    assert list_alerts(alerts, severities={AlertSeverity.MEDIUM}) == ()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("states", set()),
        ("severities", frozenset()),
        ("priorities", set()),
        ("states", "new"),
        ("states", [AlertState.NEW]),
        ("states", {AlertSeverity.HIGH}),
        ("states", {AlertState.NEW, AlertPriority.LOW}),
        ("severities", {"high"}),
        ("severities", {AlertPriority.HIGH}),
        ("severities", {AlertSeverity.HIGH, AlertPriority.LOW}),
        ("priorities", {AlertSeverity.LOW}),
        ("priorities", {AlertPriority.HIGH, "urgent"}),
        ("priorities", {"high": AlertPriority.HIGH}),
        ("priorities", 1),
    ],
)
def test_invalid_filter_fails_even_on_empty_input(field: str, value: object) -> None:
    with pytest.raises(AlertQueueError) as error:
        list_alerts((), **cast(dict[str, Any], {field: value}))
    assert (error.value.reason, error.value.field) == ("invalid_filter", field)


def test_priority_precedes_severity_age_and_id(match: DetectionMatch) -> None:
    urgent = _alert(
        match,
        "z-urgent",
        priority=AlertPriority.URGENT,
        created_at=START + timedelta(hours=3),
    )
    high = _alert(
        match,
        "y-high",
        priority=AlertPriority.HIGH,
        severity=AlertSeverity.INFORMATIONAL,
        created_at=START + timedelta(hours=2),
    )
    normal = _alert(
        match, "b-normal", severity=AlertSeverity.HIGH, created_at=START + timedelta(hours=1)
    )
    low = _alert(match, "a-low", priority=AlertPriority.LOW, severity=AlertSeverity.CRITICAL)
    expected = (urgent, high, normal, low)
    for alerts in permutations(expected):
        assert list_alerts(alerts) == expected


def test_severity_order_and_unassigned_last_within_priority(match: DetectionMatch) -> None:
    expected = (
        AlertSeverity.CRITICAL,
        AlertSeverity.HIGH,
        AlertSeverity.MEDIUM,
        AlertSeverity.LOW,
        AlertSeverity.INFORMATIONAL,
        AlertSeverity.UNASSIGNED,
    )
    alerts = [
        _alert(
            match,
            f"severity-{5 - index}",
            severity=severity,
            created_at=START + timedelta(hours=5 - index),
        )
        for index, severity in enumerate(expected)
    ]
    assert tuple(alert.severity for alert in list_alerts(alerts[::-1])) == expected


def test_utc_oldest_first_then_ascii_id(match: DetectionMatch) -> None:
    offset = timezone(timedelta(hours=5, minutes=30))
    oldest = _alert(match, "z-oldest", created_at=(START - timedelta(minutes=1)).astimezone(offset))
    first_tie = _alert(match, "a-2", created_at=START.astimezone(offset))
    second_tie = _alert(match, "a-a")
    newer = _alert(match, "a-newer", created_at=START + timedelta(minutes=1))
    expected = (oldest, first_tie, second_tie, newer)

    assert list_alerts(expected[::-1]) == expected
    assert all(alert.created_at.tzinfo is UTC for alert in expected)


@pytest.mark.parametrize("identical", [True, False])
@pytest.mark.parametrize("state", [AlertState.NEW, AlertState.CLOSED])
def test_duplicate_ids_fail_before_filtering(
    match: DetectionMatch, identical: bool, state: AlertState
) -> None:
    first = _alert(match, state=state)
    match.event.source_data["ExampleField"] = "different-evidence"
    duplicate = first if identical else _alert(match, state=state)
    if not identical:
        assert duplicate.source_match != first.source_match

    for filters in ({}, {"severities": {AlertSeverity.CRITICAL}}):
        with pytest.raises(AlertQueueError) as error:
            list_alerts((first, duplicate), **cast(dict[str, Any], filters))
        assert (error.value.reason, error.value.field) == ("duplicate_alert_id", "alert_id")
        assert first.alert_id not in str(error.value)


@pytest.mark.parametrize(
    "mutation",
    [
        {"alert_id": "invalid id"},
        {"state": "closed"},
        {"severity": "high"},
        {"priority": AlertSeverity.HIGH},
        {"created_at": START.replace(tzinfo=None)},
        {"state_changed_at": START + timedelta(hours=1)},
        {"updated_at": START.isoformat()},
        {"updated_at": START.astimezone(timezone(timedelta(hours=1)))},
        {"source_match": None},
        {"unexpected": True},
        {"_unexpected": True},
    ],
)
def test_invalid_snapshot_fails_even_when_filtered_out(
    match: DetectionMatch, mutation: dict[str, object]
) -> None:
    valid = _alert(match, "visible")
    closed = _alert(match, "closed", state=AlertState.CLOSED)
    invalid = closed.model_copy(update=mutation)
    original = valid.model_dump()
    with pytest.raises(AlertQueueError) as error:
        list_alerts([valid, invalid])
    assert (error.value.reason, error.value.field) == ("invalid_alert", "alerts")
    assert valid.model_dump() == original


@pytest.mark.parametrize("invalid", [None, 1, {}, "", b"", bytearray(), memoryview(b"")])
def test_malformed_collections_are_rejected(invalid: object) -> None:
    with pytest.raises(AlertQueueError) as error:
        list_alerts(cast(Collection[Alert], invalid))
    assert (error.value.reason, error.value.field) == ("invalid_collection", "alerts")


def test_unsized_iterators_are_rejected_without_consuming_them(match: DetectionMatch) -> None:
    original = _alert(match)
    stream = iter([original])
    with pytest.raises(AlertQueueError) as error:
        list_alerts(cast(Collection[Alert], stream))
    assert error.value.reason == "invalid_collection"
    assert next(stream) is original


@pytest.mark.parametrize("invalid", [None, {}, "example-alert", 1])
def test_non_alert_elements_fail_a_mixed_collection(match: DetectionMatch, invalid: object) -> None:
    with pytest.raises(AlertQueueError) as error:
        list_alerts([_alert(match), cast(Alert, invalid)])
    assert (error.value.reason, error.value.field) == ("invalid_alert", "alerts")


class _CountedCollection(Collection[Alert]):
    def __init__(self, values: tuple[Alert, ...], size: int) -> None:
        self.values = values
        self.size = size
        self.iterations = 0

    def __iter__(self) -> Iterator[Alert]:
        self.iterations += 1
        return iter(self.values)

    def __len__(self) -> int:
        return self.size

    def __contains__(self, value: object) -> bool:
        return value in self.values


class _BrokenCollection(_CountedCollection):
    def __iter__(self) -> Iterator[Alert]:
        yield from self.values
        raise ValueError(SOURCE_VALUE)


def test_collection_is_snapshotted_once(match: DetectionMatch) -> None:
    original = _alert(match)
    alerts = _CountedCollection((original,), 1)
    assert list_alerts(alerts) == (original,)
    assert alerts.iterations == 1


@pytest.mark.parametrize("reported_size", [0, 2])
def test_inconsistent_collection_sizes_fail(match: DetectionMatch, reported_size: int) -> None:
    alerts = _CountedCollection((_alert(match),), reported_size)
    with pytest.raises(AlertQueueError) as error:
        list_alerts(alerts)
    assert error.value.reason == "invalid_collection"


def test_collection_iteration_error_is_sanitized(match: DetectionMatch) -> None:
    alerts = _BrokenCollection((_alert(match),), 1)
    with pytest.raises(AlertQueueError) as error:
        list_alerts(alerts)
    failure = error.value
    assert (failure.reason, failure.field) == ("invalid_collection", "alerts")
    assert failure.__cause__ is failure.__context__ is None
    assert SOURCE_VALUE not in "".join(format_exception(failure))


def test_results_preserve_detached_typed_evidence_and_leave_inputs_untouched(
    match: DetectionMatch,
) -> None:
    original = _alert(match).model_copy(update={"source_match": match})
    other = _alert(match, "another-alert", priority=AlertPriority.URGENT)
    before = original.model_dump()
    alerts = [original, other]

    sorted_other, selected = list_alerts(alerts)
    assert sorted_other == other
    assert selected is not original
    assert alerts[0] is original and alerts[1] is other
    assert original.model_dump() == before

    match.event.source_data.clear()
    match.trace.actual = "changed-original"
    exposed = selected.source_match
    exposed.event.source_data.clear()
    exposed.trace.expected = "changed-copy"

    assert selected.model_dump() == before
    evidence = selected.source_match
    assert isinstance(evidence.event.context, NetworkContext)
    assert isinstance(evidence.event.context.source_ip, IPv4Address)


def test_invalid_evidence_diagnostics_are_safe_and_failure_is_atomic(
    match: DetectionMatch,
) -> None:
    valid = _alert(match)
    invalid_evidence = match.model_copy(update={"root_outcome": ACTUAL})
    invalid = _alert(match, "closed", state=AlertState.CLOSED).model_copy(
        update={"source_match": invalid_evidence}
    )
    before = valid.model_dump()
    alerts = [valid, invalid]
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertQueueError) as error:
            list_alerts(alerts)

    failure = error.value
    assert (failure.reason, failure.field) == ("invalid_alert", "alerts")
    assert failure.__cause__ is failure.__context__ is None
    assert emitted == []
    diagnostics = [str(failure), repr(failure), repr(vars(failure)), *format_exception(failure)]
    for private_value in (HOST, SOURCE_VALUE, EXPECTED, ACTUAL, "ValidationError"):
        assert all(private_value not in diagnostic for diagnostic in diagnostics)
    assert alerts[0] is valid and alerts[1] is invalid
    assert valid.model_dump() == before
    assert list_alerts([valid]) == (valid,)
