"""Tests for validated Alert lifecycle transitions."""

import warnings
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from ipaddress import IPv4Address
from traceback import format_exception
from typing import cast

import pytest
from app.alerts import AlertTransitionError, acknowledge_alert, close_alert, create_alert
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
LATER = START + timedelta(hours=1)
HOST = "lifecycle-fixture.example.com"
SOURCE_VALUE = "lifecycle-fixture-source"
EXPECTED = "lifecycle-fixture-expected"
ACTUAL = f"{EXPECTED}-actual"


@pytest.fixture
def new_alert() -> Alert:
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
    trace = ConditionTrace(
        location="$",
        kind="leaf",
        outcome=ConditionOutcome.TRUE,
        field="source_data.TraceField",
        op=DetectionOperator.CONTAINS,
        expected=EXPECTED,
        actual=ACTUAL,
    )
    match = DetectionMatch(
        rule_id="example-network-rule",
        rule_version=1,
        rule_title="Example network match",
        event=event,
        root_outcome=ConditionOutcome.TRUE,
        trace=trace,
    )
    return create_alert(
        match,
        "example-alert",
        START,
        severity=AlertSeverity.HIGH,
        priority=AlertPriority.LOW,
    )


def test_real_transitions_preserve_original_and_evidence(new_alert: Alert) -> None:
    original = new_alert.model_dump()
    acknowledged = acknowledge_alert(new_alert, LATER)
    closed_at = LATER + timedelta(hours=1)
    closed = close_alert(acknowledged, closed_at)

    assert new_alert.model_dump() == original
    assert acknowledged is not new_alert
    assert acknowledged.model_dump() == original | {
        "state": AlertState.ACKNOWLEDGED,
        "state_changed_at": LATER,
        "updated_at": LATER,
    }
    assert closed is not acknowledged
    assert closed.model_dump() == original | {
        "state": AlertState.CLOSED,
        "state_changed_at": closed_at,
        "updated_at": closed_at,
    }
    evidence = closed.source_match
    assert isinstance(evidence.event.context, NetworkContext)
    assert isinstance(evidence.event.context.source_ip, IPv4Address)
    assert evidence.trace.expected == EXPECTED
    assert evidence.trace.actual == ACTUAL


def test_equal_time_and_offset_transitions_are_deterministic(new_alert: Alert) -> None:
    offset = timezone(timedelta(hours=5, minutes=30))
    acknowledged = acknowledge_alert(new_alert, START.astimezone(offset))
    assert acknowledged == acknowledge_alert(new_alert, START)
    assert acknowledged.state is AlertState.ACKNOWLEDGED
    assert acknowledged.state_changed_at == acknowledged.updated_at == START
    assert acknowledged.updated_at.tzinfo is UTC

    closed = close_alert(acknowledged, START.astimezone(offset))
    assert closed == close_alert(acknowledged, START)
    assert closed.state is AlertState.CLOSED
    assert closed.state_changed_at == closed.updated_at == START
    assert closed.state_changed_at.tzinfo is UTC


@pytest.mark.parametrize("operation", [acknowledge_alert, close_alert])
def test_idempotent_calls_preserve_value_and_validate_time(
    new_alert: Alert, operation: Callable[[Alert, datetime], Alert]
) -> None:
    acknowledged = acknowledge_alert(new_alert, LATER)
    current = acknowledged if operation is acknowledge_alert else close_alert(acknowledged, LATER)
    future = LATER + timedelta(hours=1)

    assert operation(current, future).model_dump() == current.model_dump()
    assert operation(current, LATER) == current
    with pytest.raises(AlertTransitionError) as error:
        operation(current, START.astimezone(timezone(timedelta(hours=9))))
    assert (error.value.reason, error.value.field) == ("out_of_order_at", "at")
    with pytest.raises(AlertTransitionError) as error:
        operation(current, future.replace(tzinfo=None))
    assert (error.value.reason, error.value.field) == ("invalid_at", "at")


def test_direct_closure_and_reopening_fail_atomically(new_alert: Alert) -> None:
    original = new_alert.model_dump()
    with pytest.raises(AlertTransitionError) as direct:
        close_alert(new_alert, LATER)
    assert (direct.value.reason, direct.value.field) == ("forbidden_transition", "state")
    assert new_alert.model_dump() == original

    closed = close_alert(acknowledge_alert(new_alert, LATER), LATER)
    before = closed.model_dump()
    with pytest.raises(AlertTransitionError) as reopen:
        acknowledge_alert(closed, LATER)
    assert (reopen.value.reason, reopen.value.field) == ("forbidden_transition", "state")
    assert closed.model_dump() == before


def test_backdated_real_transition_is_rejected(new_alert: Alert) -> None:
    acknowledged = acknowledge_alert(new_alert, LATER)
    before = acknowledged.model_dump()
    with pytest.raises(AlertTransitionError) as error:
        close_alert(acknowledged, START.astimezone(timezone(timedelta(hours=3))))
    assert error.value.reason == "out_of_order_at"
    assert acknowledged.model_dump() == before
    assert close_alert(acknowledged, LATER).state is AlertState.CLOSED


class _TestZone(tzinfo):
    def __init__(self, offset: timedelta | None) -> None:
        self._offset = offset

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return self._offset

    def dst(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> None:
        return None


@pytest.mark.parametrize(
    "invalid",
    [
        START.replace(tzinfo=None),
        START.isoformat(),
        1,
        None,
        START.replace(tzinfo=_TestZone(None)),
        START.replace(tzinfo=_TestZone(timedelta(hours=24))),
        datetime.min.replace(tzinfo=timezone(timedelta(hours=1))),
        datetime.max.replace(tzinfo=timezone(timedelta(hours=-1))),
    ],
)
def test_invalid_at_is_controlled(new_alert: Alert, invalid: object) -> None:
    with pytest.raises(AlertTransitionError) as error:
        acknowledge_alert(new_alert, cast(datetime, invalid))
    assert (error.value.reason, error.value.field) == ("invalid_at", "at")
    assert error.value.__cause__ is error.value.__context__ is None


@pytest.mark.parametrize("invalid", [None, {}, "example-alert", 1])
def test_non_alert_inputs_are_rejected(invalid: object) -> None:
    with pytest.raises(AlertTransitionError) as error:
        acknowledge_alert(cast(Alert, invalid), START)
    assert (error.value.reason, error.value.field) == ("invalid_alert", "alert")


@pytest.mark.parametrize(
    "mutation",
    [
        {"alert_id": "invalid id"},
        {"state": "acknowledged"},
        {"severity": "high"},
        {"priority": "low"},
        {"updated_at": START.isoformat()},
        {"updated_at": START.astimezone(timezone(timedelta(hours=1)))},
        {"state_changed_at": LATER},
        {"created_at": LATER},
        {"source_match": None},
        {"unexpected": True},
    ],
)
def test_invalid_snapshots_fail_before_transitions_or_no_ops(
    new_alert: Alert, mutation: dict[str, object]
) -> None:
    acknowledged = acknowledge_alert(new_alert, START)
    invalid = acknowledged.model_copy(update=mutation)
    for operation in (acknowledge_alert, close_alert):
        with pytest.raises(AlertTransitionError) as error:
            operation(invalid, LATER)
        assert (error.value.reason, error.value.field) == ("invalid_alert", "alert")


def test_transition_and_no_op_keep_independent_evidence(new_alert: Alert) -> None:
    acknowledged = acknowledge_alert(new_alert, LATER)
    detached = acknowledged.source_match
    copied = acknowledged.model_copy(update={"source_match": detached})
    no_op = acknowledge_alert(copied, LATER)
    closed = close_alert(copied, LATER)
    assert no_op == acknowledged

    detached.event.source_data.clear()
    detached.trace.actual = "changed-original"
    exposed = closed.source_match
    exposed.event.source_data.clear()
    exposed.trace.expected = "changed-copy"

    expected = new_alert.source_match.model_dump()
    assert acknowledged.source_match.model_dump() == expected
    assert no_op.source_match.model_dump() == expected
    assert closed.source_match.model_dump() == expected


def test_invalid_evidence_error_contains_only_safe_diagnostics(new_alert: Alert) -> None:
    invalid_match = new_alert.source_match.model_copy(update={"root_outcome": ACTUAL})
    invalid = new_alert.model_copy(update={"source_match": invalid_match})
    before = new_alert.model_dump()
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertTransitionError) as error:
            acknowledge_alert(invalid, START)

    failure = error.value
    assert (failure.reason, failure.field) == ("invalid_alert", "alert")
    assert failure.__cause__ is failure.__context__ is None
    assert emitted == []
    diagnostics = [str(failure), repr(failure), repr(vars(failure)), *format_exception(failure)]
    for private_value in (HOST, SOURCE_VALUE, EXPECTED, ACTUAL, "ValidationError"):
        assert all(private_value not in diagnostic for diagnostic in diagnostics)
    assert new_alert.model_dump() == before
    assert acknowledge_alert(new_alert, START).state is AlertState.ACKNOWLEDGED
