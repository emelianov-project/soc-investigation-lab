"""Focused contracts for Alert values and detached detection evidence."""

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address
from typing import Any

import pytest
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
from pydantic import ValidationError

CREATED = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def match() -> DetectionMatch:
    """Build synthetic, typed event and ordered trace evidence."""
    event = NormalizedEvent(
        source=EventSource.SYSMON,
        provider="Microsoft-Windows-Sysmon",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        timestamp=CREATED,
        computer="host.example.com",
        category=EventCategory.NETWORK,
        context=NetworkContext(
            source_ip=IPv4Address("192.0.2.10"),
            source_port=49152,
            destination_ip=IPv4Address("198.51.100.20"),
            destination_port=443,
        ),
        source_data={"ExampleField": "synthetic-value"},
    )
    trace = ConditionTrace(
        location="$",
        kind="all",
        outcome=ConditionOutcome.TRUE,
        children=[
            ConditionTrace(
                location="$.all[0]",
                kind="leaf",
                outcome=ConditionOutcome.TRUE,
                field="event_id",
                op=DetectionOperator.EQUALS,
                expected=3,
                actual=3,
            ),
            ConditionTrace(
                location="$.all[1]",
                kind="leaf",
                outcome=ConditionOutcome.TRUE,
                field="context.source_ip",
                op=DetectionOperator.IP_IN_CIDR,
                expected="192.0.2.0/24",
                actual=IPv4Address("192.0.2.10"),
            ),
        ],
    )
    return DetectionMatch(
        rule_id="example-network-rule",
        rule_version=2,
        rule_title="Synthetic network match",
        event=event,
        root_outcome=ConditionOutcome.TRUE,
        trace=trace,
    )


def alert(**changes: Any) -> Alert:
    """Construct a model snapshot with explicit time inputs."""
    values: dict[str, Any] = {
        "alert_id": "example-alert-1",
        "source_match": match(),
        "created_at": CREATED,
        "state_changed_at": CREATED,
        "updated_at": CREATED,
    }
    values.update(changes)
    return Alert.model_validate(values)


def test_public_model_defaults_and_complete_typed_evidence() -> None:
    selected = alert()
    evidence = selected.source_match

    assert selected.alert_id == "example-alert-1"
    assert selected.state is AlertState.NEW
    assert selected.severity is AlertSeverity.UNASSIGNED
    assert selected.priority is AlertPriority.NORMAL
    assert selected.created_at == selected.state_changed_at == selected.updated_at == CREATED
    assert isinstance(evidence, DetectionMatch)
    assert evidence.rule_id == "example-network-rule"
    assert evidence.rule_version == 2
    assert evidence.rule_title == "Synthetic network match"
    assert evidence.root_outcome is ConditionOutcome.TRUE
    assert isinstance(evidence.event, NormalizedEvent)
    assert isinstance(evidence.event.context, NetworkContext)
    assert isinstance(evidence.event.context.source_ip, IPv4Address)
    assert evidence.trace.kind == "all"
    assert [child.location for child in evidence.trace.children] == ["$.all[0]", "$.all[1]"]
    assert isinstance(evidence.trace.children[1].actual, IPv4Address)
    assert evidence.model_dump() == match().model_dump()
    assert "source_match" not in repr(selected)


@pytest.mark.parametrize("state", list(AlertState))
def test_all_states_are_supported_as_snapshots(state: AlertState) -> None:
    assert alert(state=state).state is state


@pytest.mark.parametrize("severity", list(AlertSeverity))
def test_all_severities_are_supported(severity: AlertSeverity) -> None:
    assert alert(severity=severity).severity is severity


@pytest.mark.parametrize("priority", list(AlertPriority))
def test_all_priorities_are_supported(priority: AlertPriority) -> None:
    assert alert(priority=priority).priority is priority


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "Upper",
        "two_words",
        "-start",
        "end-",
        "two--hyphens",
        "has space",
        "café",
        "a" * 129,
        42,
        True,
    ],
)
def test_alert_id_rejects_invalid_or_coerced_values(bad_id: object) -> None:
    with pytest.raises(ValidationError):
        alert(alert_id=bad_id)


def test_alert_id_accepts_maximum_length() -> None:
    assert alert(alert_id="a" * 128).alert_id == "a" * 128


@pytest.mark.parametrize(
    "missing", ["alert_id", "source_match", "created_at", "state_changed_at", "updated_at"]
)
def test_required_fields_cannot_be_omitted(missing: str) -> None:
    data = alert().model_dump()
    del data[missing]
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        alert(unexpected="not part of the contract")


@pytest.mark.parametrize(
    ("field", "value"),
    [("state", "in_progress"), ("severity", "severe"), ("priority", "critical")],
)
def test_invalid_enum_values_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        alert(**{field: value})


@pytest.mark.parametrize("field", ["created_at", "state_changed_at", "updated_at"])
@pytest.mark.parametrize("bad_time", ["2026-10-01T12:00:00Z", 1, datetime(2026, 10, 1, 12, 0)])
def test_timestamps_require_explicit_aware_datetime(field: str, bad_time: object) -> None:
    with pytest.raises(ValidationError):
        alert(**{field: bad_time})


def test_timestamps_normalize_offsets_to_utc_instants() -> None:
    offset = timezone(timedelta(hours=3))
    selected = alert(
        created_at=datetime(2026, 10, 1, 15, 0, tzinfo=offset),
        state_changed_at=datetime(2026, 10, 1, 15, 1, tzinfo=offset),
        updated_at=datetime(2026, 10, 1, 12, 2, tzinfo=UTC),
    )
    assert selected.created_at == CREATED
    assert selected.state_changed_at == CREATED + timedelta(minutes=1)
    assert selected.updated_at == CREATED + timedelta(minutes=2)
    assert selected.created_at.tzinfo is UTC
    assert selected.state_changed_at.tzinfo is UTC
    assert selected.updated_at.tzinfo is UTC


@pytest.mark.parametrize(
    "changes",
    [
        {"state_changed_at": CREATED - timedelta(seconds=1)},
        {"updated_at": CREATED - timedelta(seconds=1)},
        {
            "state_changed_at": CREATED + timedelta(seconds=2),
            "updated_at": CREATED + timedelta(seconds=1),
        },
    ],
)
def test_timestamp_order_is_enforced(changes: dict[str, datetime]) -> None:
    with pytest.raises(ValidationError):
        alert(**changes)


def test_invalid_or_incomplete_match_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError):
        alert(source_match={"rule_id": "incomplete"})
    invalid = match().model_copy(update={"root_outcome": ConditionOutcome.FALSE})
    with pytest.raises(ValidationError, match="valid true DetectionMatch"):
        alert(source_match=invalid)
    invalid_trace = match()
    invalid_trace.trace.children.clear()
    with pytest.raises(ValidationError, match="valid true DetectionMatch"):
        alert(source_match=invalid_trace)


def test_absent_and_redacted_trace_shapes_remain_lossless() -> None:
    original = match()
    original.trace = ConditionTrace(
        location="$",
        kind="any",
        outcome=ConditionOutcome.TRUE,
        children=[
            ConditionTrace(
                location="$.any[0]",
                kind="leaf",
                outcome=ConditionOutcome.TRUE,
                field="event_id",
                op=DetectionOperator.EQUALS,
                expected=3,
                actual=3,
            ),
            ConditionTrace(
                location="$.any[1]",
                kind="leaf",
                outcome=ConditionOutcome.UNKNOWN,
                field="source_data.ExampleField",
                op=DetectionOperator.EQUALS,
                expected="synthetic-value",
                absence="missing",
            ),
        ],
    )
    preserved = alert(source_match=original).source_match.trace.children[1]
    assert preserved.absence == "missing"
    assert "actual" not in preserved.model_fields_set

    original.trace = ConditionTrace(
        location="$",
        kind="leaf",
        outcome=ConditionOutcome.TRUE,
        field="source_data.ExampleField",
        op=DetectionOperator.EQUALS,
        expected="synthetic-value",
        redacted=True,
        redaction_marker="[redacted]",
    )
    preserved = alert(source_match=original).source_match.trace
    assert preserved.redacted is True
    assert preserved.redaction_marker == "[redacted]"
    assert "actual" not in preserved.model_fields_set


def test_invalid_evidence_error_does_not_echo_event_content() -> None:
    invalid = match().model_copy(update={"root_outcome": ConditionOutcome.FALSE})
    with pytest.raises(ValidationError) as error:
        alert(source_match=invalid)
    assert "synthetic-value" not in str(error.value)
    assert "host.example.com" not in str(error.value)


def test_caller_owned_nested_mutation_cannot_change_alert_evidence() -> None:
    original = match()
    selected = alert(source_match=original)
    before = selected.source_match.model_dump()

    original.rule_title = "changed"
    original.event.source_data["ExampleField"] = "changed"
    assert isinstance(original.event.context, NetworkContext)
    original.event.context.source_port = 9
    original.trace.children[0].actual = 9
    original.trace.children.reverse()

    assert selected.source_match.model_dump() == before


def test_exposed_evidence_is_a_defensive_copy_at_every_nested_level() -> None:
    selected = alert()
    before = selected.source_match.model_dump()
    exposed = selected.source_match

    exposed.rule_title = "changed"
    exposed.event.source_data["ExampleField"] = "changed"
    assert isinstance(exposed.event.context, NetworkContext)
    exposed.event.context.source_port = 9
    exposed.trace.children[0].actual = 9
    exposed.trace.children.reverse()

    assert selected.source_match.model_dump() == before
    assert selected.source_match is not selected.source_match


def test_iteration_and_dump_do_not_expose_mutable_evidence_aliases() -> None:
    selected = alert()
    before = selected.source_match.model_dump()

    iterated = dict(selected)["source_match"]
    assert isinstance(iterated, DetectionMatch)
    iterated.event.source_data["ExampleField"] = "changed"
    dumped = selected.model_dump()
    dumped["source_match"]["event"]["source_data"]["ExampleField"] = "changed"

    assert selected.source_match.model_dump() == before


def test_alert_fields_cannot_be_assigned() -> None:
    selected = alert()
    with pytest.raises(ValidationError):
        selected.alert_id = "other"
    with pytest.raises(ValidationError):
        selected.source_match = match()
    with pytest.raises(ValidationError):
        selected.state = AlertState.CLOSED


def test_repeated_construction_is_deterministic_and_value_equal() -> None:
    first = alert()
    second = alert()
    assert first == second
    assert first.source_match is not second.source_match
    assert first.model_dump() == second.model_dump()
