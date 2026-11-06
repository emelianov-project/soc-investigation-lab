"""Tests for explicit severity and priority updates."""

import warnings
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from ipaddress import IPv4Address
from traceback import format_exception
from typing import Literal, cast

import pytest
from app.alerts import (
    AlertPolicyError,
    acknowledge_alert,
    close_alert,
    create_alert,
    set_priority,
    set_severity,
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
LATER = START + timedelta(hours=1)
CHANGE = LATER + timedelta(hours=1)
HOST = "policy-fixture.example.com"
SOURCE_VALUE = "policy-fixture-source"
EXPECTED = "policy-fixture-expected"
ACTUAL = f"{EXPECTED}-actual"

type PolicyField = Literal["severity", "priority"]


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
    return create_alert(
        DetectionMatch(
            rule_id="example-network-rule",
            rule_version=1,
            rule_title="Example network match",
            event=event,
            root_outcome=ConditionOutcome.TRUE,
            trace=trace,
        ),
        "example-alert",
        START,
        severity=AlertSeverity.HIGH,
        priority=AlertPriority.LOW,
    )


@pytest.fixture(params=[AlertState.NEW, AlertState.ACKNOWLEDGED])
def active_alert(request: pytest.FixtureRequest, new_alert: Alert) -> Alert:
    if request.param is AlertState.ACKNOWLEDGED:
        return acknowledge_alert(new_alert, LATER)
    return new_alert


def _assign(field: PolicyField, alert: Alert, value: object, changed_at: object) -> Alert:
    instant = cast(datetime, changed_at)
    if field == "severity":
        return set_severity(alert, cast(AlertSeverity, value), instant)
    return set_priority(alert, cast(AlertPriority, value), instant)


@pytest.mark.parametrize("value", list(AlertSeverity))
def test_all_severities_on_active_alerts(active_alert: Alert, value: AlertSeverity) -> None:
    original = active_alert.model_dump()
    updated = set_severity(active_alert, value, CHANGE)
    expected_time = active_alert.updated_at if value is active_alert.severity else CHANGE
    assert updated.model_dump() == original | {"severity": value, "updated_at": expected_time}
    assert updated.severity is value
    assert updated.priority is active_alert.priority
    assert active_alert.model_dump() == original


@pytest.mark.parametrize("value", list(AlertPriority))
def test_all_priorities_on_active_alerts(active_alert: Alert, value: AlertPriority) -> None:
    original = active_alert.model_dump()
    updated = set_priority(active_alert, value, CHANGE)
    expected_time = active_alert.updated_at if value is active_alert.priority else CHANGE
    assert updated.model_dump() == original | {"priority": value, "updated_at": expected_time}
    assert updated.priority is value
    assert updated.severity is active_alert.severity
    assert active_alert.model_dump() == original


@pytest.mark.parametrize("field", ["severity", "priority"])
def test_equal_time_and_offset_updates_are_deterministic(
    new_alert: Alert, field: PolicyField
) -> None:
    active = acknowledge_alert(new_alert, LATER)
    value = AlertSeverity.CRITICAL if field == "severity" else AlertPriority.URGENT
    offset_time = LATER.astimezone(timezone(timedelta(hours=5, minutes=30)))
    updated = _assign(field, active, value, offset_time)

    assert updated is not active
    assert updated == _assign(field, active, value, LATER)
    assert updated.updated_at == LATER
    assert updated.updated_at.tzinfo is UTC
    assert updated.state_changed_at == LATER


@pytest.mark.parametrize("field", ["severity", "priority"])
def test_same_value_is_a_validated_no_op(active_alert: Alert, field: PolicyField) -> None:
    value = active_alert.severity if field == "severity" else active_alert.priority
    assert _assign(field, active_alert, value, CHANGE) == active_alert
    assert _assign(field, active_alert, value, active_alert.updated_at) == active_alert
    with pytest.raises(AlertPolicyError) as error:
        _assign(field, active_alert, value, CHANGE.replace(tzinfo=None))
    assert (error.value.reason, error.value.field) == ("invalid_changed_at", "changed_at")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", AlertSeverity.HIGH),
        ("severity", AlertSeverity.LOW),
        ("priority", AlertPriority.LOW),
        ("priority", AlertPriority.URGENT),
    ],
)
def test_closed_alert_rejects_every_assignment(
    new_alert: Alert, field: PolicyField, value: AlertSeverity | AlertPriority
) -> None:
    closed = close_alert(acknowledge_alert(new_alert, LATER), LATER)
    original = closed.model_dump()
    with pytest.raises(AlertPolicyError) as error:
        _assign(field, closed, value, CHANGE)
    assert (error.value.reason, error.value.field) == ("closed_alert", "state")
    assert closed.model_dump() == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", AlertSeverity.CRITICAL),
        ("severity", AlertSeverity.LOW),
        ("priority", AlertPriority.LOW),
        ("priority", AlertPriority.URGENT),
    ],
)
def test_backdated_changes_and_no_ops_are_rejected(
    new_alert: Alert, field: PolicyField, value: AlertSeverity | AlertPriority
) -> None:
    alert = set_severity(acknowledge_alert(new_alert, LATER), AlertSeverity.CRITICAL, CHANGE)
    original = alert.model_dump()
    with pytest.raises(AlertPolicyError) as error:
        _assign(field, alert, value, LATER.astimezone(timezone(timedelta(hours=9))))
    assert (error.value.reason, error.value.field) == ("out_of_order_changed_at", "changed_at")
    assert alert.model_dump() == original


class _InvalidZone(tzinfo):
    def utcoffset(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=24)

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
        START.replace(tzinfo=_InvalidZone()),
        datetime.min.replace(tzinfo=timezone(timedelta(hours=1))),
        datetime.max.replace(tzinfo=timezone(timedelta(hours=-1))),
    ],
)
def test_invalid_change_time_is_controlled(new_alert: Alert, invalid: object) -> None:
    with pytest.raises(AlertPolicyError) as error:
        set_priority(new_alert, AlertPriority.NORMAL, cast(datetime, invalid))
    assert (error.value.reason, error.value.field) == ("invalid_changed_at", "changed_at")
    assert error.value.__cause__ is error.value.__context__ is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "high"),
        ("severity", AlertPriority.HIGH),
        ("severity", None),
        ("priority", "low"),
        ("priority", AlertSeverity.LOW),
        ("priority", 1),
    ],
)
def test_policy_values_require_the_exact_enum(
    new_alert: Alert, field: PolicyField, value: object
) -> None:
    with pytest.raises(AlertPolicyError) as error:
        _assign(field, new_alert, value, CHANGE)
    assert (error.value.reason, error.value.field) == ("invalid_value", field)


@pytest.mark.parametrize("invalid", [None, {}, "example-alert", 1])
def test_non_alert_inputs_are_rejected(invalid: object) -> None:
    with pytest.raises(AlertPolicyError) as error:
        set_severity(cast(Alert, invalid), AlertSeverity.HIGH, CHANGE)
    assert (error.value.reason, error.value.field) == ("invalid_alert", "alert")


@pytest.mark.parametrize(
    ("field", "value"),
    [("severity", AlertSeverity.HIGH), ("priority", AlertPriority.LOW)],
)
@pytest.mark.parametrize(
    "mutation",
    [
        {"alert_id": "invalid id"},
        {"state": "new"},
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
def test_full_snapshot_is_validated_even_for_no_ops(
    new_alert: Alert,
    mutation: dict[str, object],
    field: PolicyField,
    value: AlertSeverity | AlertPriority,
) -> None:
    invalid = new_alert.model_copy(update=mutation)
    with pytest.raises(AlertPolicyError) as error:
        _assign(field, invalid, value, CHANGE)
    assert (error.value.reason, error.value.field) == ("invalid_alert", "alert")


def test_real_update_and_no_op_return_detached_typed_evidence(new_alert: Alert) -> None:
    match = new_alert.source_match
    before = match.model_dump()
    copied = new_alert.model_copy(update={"source_match": match})
    updated = set_severity(copied, AlertSeverity.CRITICAL, CHANGE)
    no_op = set_priority(copied, AlertPriority.LOW, CHANGE)
    assert copied.source_match.model_dump() == before

    match.event.source_data.clear()
    match.trace.actual = "changed-original"
    exposed = updated.source_match
    exposed.event.source_data.clear()
    exposed.trace.expected = "changed-copy"

    assert new_alert.source_match.model_dump() == before
    assert no_op.source_match.model_dump() == before
    evidence = updated.source_match
    assert evidence.model_dump() == before
    assert isinstance(evidence.event.context, NetworkContext)
    assert isinstance(evidence.event.context.source_ip, IPv4Address)


def test_invalid_evidence_diagnostics_are_safe_and_failure_is_atomic(new_alert: Alert) -> None:
    invalid_match = new_alert.source_match.model_copy(update={"root_outcome": ACTUAL})
    invalid = new_alert.model_copy(update={"source_match": invalid_match})
    before = new_alert.model_dump()
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertPolicyError) as error:
            set_priority(invalid, AlertPriority.URGENT, CHANGE)

    failure = error.value
    assert (failure.reason, failure.field) == ("invalid_alert", "alert")
    assert failure.__cause__ is failure.__context__ is None
    assert emitted == []
    diagnostics = [str(failure), repr(failure), repr(vars(failure)), *format_exception(failure)]
    for private_value in (HOST, SOURCE_VALUE, EXPECTED, ACTUAL, "ValidationError"):
        assert all(private_value not in diagnostic for diagnostic in diagnostics)
    assert new_alert.model_dump() == before
    assert invalid.source_match.root_outcome == ACTUAL
    assert set_priority(new_alert, AlertPriority.URGENT, CHANGE).priority is AlertPriority.URGENT
