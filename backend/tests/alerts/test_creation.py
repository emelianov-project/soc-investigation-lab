"""Tests for the public deterministic Alert creation boundary."""

import warnings
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from traceback import format_exception
from typing import cast

import pytest
from app.alerts import AlertCreationError, create_alert
from app.models import (
    AlertPriority,
    AlertSeverity,
    AlertState,
    ConditionOutcome,
    ConditionTrace,
    DetectionMatch,
    EventCategory,
    EventSource,
    NetworkContext,
    NormalizedEvent,
)

INSTANT = datetime(2026, 10, 1, 12, tzinfo=UTC)
ALERT_ID = "example-alert-1"
HOST = "fixture-host.example.com"
SOURCE_VALUE = "fixture-source-value"
EXPECTED = "fixture-expected"
ACTUAL = "fixture-expected-actual"


@pytest.fixture
def match() -> DetectionMatch:
    event = NormalizedEvent(
        source=EventSource.SYSMON,
        provider="Microsoft-Windows-Sysmon",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        timestamp=INSTANT,
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
    leaves = [
        ("context.source_ip", "ip_in_cidr", "192.0.2.0/24", IPv4Address("192.0.2.10")),
        ("timestamp", "equals", INSTANT.isoformat(), INSTANT),
        ("source_data.TraceField", "contains", EXPECTED, ACTUAL),
    ]
    trace = ConditionTrace.model_validate(
        {
            "location": "$",
            "kind": "all",
            "outcome": ConditionOutcome.TRUE,
            "children": [
                {
                    "location": f"$.all[{index}]",
                    "kind": "leaf",
                    "outcome": ConditionOutcome.TRUE,
                    "field": field,
                    "op": op,
                    "expected": expected,
                    "actual": actual,
                }
                for index, (field, op, expected, actual) in enumerate(leaves)
            ],
        }
    )
    return DetectionMatch(
        rule_id="example-network-rule",
        rule_version=2,
        rule_title="Example network match",
        event=event,
        root_outcome=ConditionOutcome.TRUE,
        trace=trace,
    )


def test_defaults_and_complete_typed_evidence(match: DetectionMatch) -> None:
    alert = create_alert(match, ALERT_ID, INSTANT)

    assert alert.alert_id == ALERT_ID
    assert alert.state is AlertState.NEW
    assert alert.severity is AlertSeverity.UNASSIGNED
    assert alert.priority is AlertPriority.NORMAL
    assert alert.created_at == alert.state_changed_at == alert.updated_at == INSTANT
    evidence = alert.source_match
    assert evidence.model_dump(exclude_unset=True) == match.model_dump(exclude_unset=True)
    assert isinstance(evidence.event.context, NetworkContext)
    assert isinstance(evidence.event.context.source_ip, IPv4Address)
    assert isinstance(evidence.trace.children[0].actual, IPv4Address)
    assert isinstance(evidence.trace.children[1].actual, datetime)


@pytest.mark.parametrize("severity", list(AlertSeverity))
@pytest.mark.parametrize("priority", list(AlertPriority))
def test_explicit_policy_values_are_independent(
    match: DetectionMatch, severity: AlertSeverity, priority: AlertPriority
) -> None:
    alert = create_alert(match, ALERT_ID, INSTANT, severity=severity, priority=priority)
    assert alert.severity is severity
    assert alert.priority is priority


def test_offset_time_is_normalized_and_creation_is_repeatable(match: DetectionMatch) -> None:
    offset_time = INSTANT.astimezone(timezone(timedelta(hours=5, minutes=30)))
    first = create_alert(match, ALERT_ID, offset_time)
    second = create_alert(match, ALERT_ID, INSTANT)
    assert first == second
    assert first is not second
    assert first.created_at == first.state_changed_at == first.updated_at == INSTANT
    assert all(
        value.tzinfo is UTC
        for value in (first.created_at, first.state_changed_at, first.updated_at)
    )
    assert create_alert(match, "another-alert", INSTANT) != first


@pytest.mark.parametrize("bad_id", ["", "UPPER", "café", "a--b", "a b", "a" * 129, 42, None])
def test_invalid_id(match: DetectionMatch, bad_id: object) -> None:
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, cast(str, bad_id), INSTANT)
    assert error.value.field == "alert_id"
    assert error.value.reason == "invalid_alert_id"


@pytest.mark.parametrize("bad_time", [datetime(2026, 10, 1), "2026-10-01T12:00:00Z", 1, None])
def test_invalid_timestamp(match: DetectionMatch, bad_time: object) -> None:
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, cast(datetime, bad_time))
    assert error.value.field == "created_at"
    assert error.value.reason == "invalid_created_at"


def test_utc_conversion_overflow_is_a_controlled_failure(match: DetectionMatch) -> None:
    out_of_range = datetime.min.replace(tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, out_of_range)
    assert error.value.reason == "invalid_input"
    assert error.value.__context__ is None


@pytest.mark.parametrize("bad_severity", ["critical", b"critical", "severe", AlertPriority.HIGH])
def test_severity_requires_its_typed_enum(match: DetectionMatch, bad_severity: object) -> None:
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, INSTANT, severity=cast(AlertSeverity, bad_severity))
    assert error.value.field == "severity"
    assert error.value.reason == "invalid_severity"


@pytest.mark.parametrize("bad_priority", ["urgent", "critical", 1, AlertSeverity.HIGH])
def test_priority_requires_its_typed_enum(match: DetectionMatch, bad_priority: object) -> None:
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, INSTANT, priority=cast(AlertPriority, bad_priority))
    assert error.value.field == "priority"
    assert error.value.reason == "invalid_priority"


def test_wrong_match_type(match: DetectionMatch) -> None:
    with pytest.raises(AlertCreationError) as error:
        create_alert(cast(DetectionMatch, match.event), ALERT_ID, INSTANT)
    assert error.value.reason == "invalid_match"


@pytest.mark.parametrize("outcome", [ConditionOutcome.FALSE, ConditionOutcome.UNKNOWN, "true"])
def test_invalid_match_outcome(match: DetectionMatch, outcome: object) -> None:
    invalid = match.model_copy(update={"root_outcome": outcome})
    with pytest.raises(AlertCreationError) as error:
        create_alert(invalid, ALERT_ID, INSTANT)
    assert error.value.reason == "invalid_match"


def test_invalid_trace(match: DetectionMatch) -> None:
    match.trace.children.clear()
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, INSTANT)
    assert error.value.reason == "invalid_match"


def test_mutated_ip_is_rejected_even_if_it_could_be_parsed(match: DetectionMatch) -> None:
    context = match.event.context.model_copy(update={"source_ip": "192.0.2.10"})
    match.event = match.event.model_copy(update={"context": context})
    with pytest.raises(AlertCreationError) as error:
        create_alert(match, ALERT_ID, INSTANT)
    assert error.value.reason == "invalid_match"


def test_evidence_is_unchanged_and_detached_in_both_directions(match: DetectionMatch) -> None:
    before = match.model_dump()
    alert = create_alert(match, ALERT_ID, INSTANT)
    assert match.model_dump() == before

    match.event.source_data["ExampleField"] = "changed-original"
    match.trace.children[2].actual = "changed-original"
    exposed = alert.source_match
    exposed.event.source_data.clear()
    exposed.trace.children.reverse()
    assert alert.source_match.model_dump() == before


def test_validation_failure_has_safe_diagnostics_and_no_partial_result(
    match: DetectionMatch,
) -> None:
    before = match.model_dump()
    invalid = match.model_copy(update={"root_outcome": ACTUAL})
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AlertCreationError) as error:
            create_alert(invalid, ALERT_ID, INSTANT)

    failure = error.value
    assert failure.reason == "invalid_match"
    assert failure.field == "match"
    assert failure.__cause__ is failure.__context__ is None
    assert emitted == []
    diagnostics = [str(failure), repr(failure), repr(vars(failure)), *format_exception(failure)]
    for value in (HOST, SOURCE_VALUE, EXPECTED, ACTUAL, "ValidationError"):
        assert all(value not in diagnostic for diagnostic in diagnostics)
    assert match.model_dump() == before
    assert create_alert(match, ALERT_ID, INSTANT).source_match.model_dump() == before
